const PAID_EXIT_PAYMENT_OUTBOX_BATCH: usize = 16;

struct QueuedPaidExitPayment {
    id: String,
    envelope: StreamingRoutePaymentEnvelope,
}

fn paid_exit_payment_outbox_directory(config_path: &Path) -> PathBuf {
    paid_route_store_file_path(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("paid-exit-payment-outbox")
}

#[cfg(unix)]
fn preferred_paid_exit_outbox_owner(
    store: Option<(u32, u32)>,
    config: Option<(u32, u32)>,
    outbox: Option<(u32, u32)>,
    parent: Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    [store, config, outbox, parent]
        .into_iter()
        .flatten()
        .find(|(uid, _)| *uid != 0)
}

#[cfg(unix)]
fn repair_paid_exit_outbox_handle(
    file: &fs::File,
    path: &Path,
    owner: Option<(u32, u32)>,
    mode: u32,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if let Some((uid, gid)) = owner
        && (metadata.uid(), metadata.gid()) != (uid, gid)
    {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))
            .with_context(|| format!("failed to set ownership on {}", path.display()))?;
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to protect {}", path.display()))
}

#[cfg(unix)]
fn prepare_paid_exit_payment_outbox(config_path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    let directory = paid_exit_payment_outbox_directory(config_path);
    let owner = |path: &Path| {
        fs::metadata(path)
            .ok()
            .map(|metadata| (metadata.uid(), metadata.gid()))
    };
    let preferred_owner = preferred_paid_exit_outbox_owner(
        owner(&paid_route_store_file_path(config_path)),
        owner(config_path),
        owner(&directory),
        owner(directory.parent().unwrap_or_else(|| Path::new("."))),
    );
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(anyhow!("refusing outbox symlink {}", directory.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let handle = options
        .open(&directory)
        .with_context(|| format!("failed to open {}", directory.display()))?;
    repair_paid_exit_outbox_handle(&handle, &directory, preferred_owner, 0o700)?;
    Ok(directory)
}

#[cfg(not(unix))]
fn prepare_paid_exit_payment_outbox(config_path: &Path) -> Result<PathBuf> {
    let directory = paid_exit_payment_outbox_directory(config_path);
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

fn queue_paid_exit_payment_bytes(config_path: &Path, id: &str, bytes: &[u8]) -> Result<bool> {
    let directory = prepare_paid_exit_payment_outbox(config_path)?;
    let destination = directory.join(format!("{id}.json"));
    let existed = match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_file() => true,
        Ok(_) => return Err(anyhow!("refusing outbox symlink {}", destination.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    write_private_file_preserving_user_owner(&destination, bytes)
        .with_context(|| format!("failed to queue {}", destination.display()))?;
    Ok(!existed)
}

fn queue_paid_exit_payment(
    app: &AppConfig,
    config_path: &Path,
    envelope: &StreamingRoutePaymentEnvelope,
) -> Result<bool> {
    use sha2::{Digest, Sha256};

    let buyer = normalize_nostr_pubkey(&envelope.buyer)
        .context("invalid paid route payment buyer")?;
    if buyer != app.nostr_keys()?.public_key().to_hex() {
        return Err(anyhow!(
            "paid route payment buyer does not match local FIPS identity"
        ));
    }
    let seller = normalize_nostr_pubkey(&envelope.seller)
        .context("invalid paid route payment seller")?;
    let closes_historical_channel = matches!(
        &envelope.payload,
        StreamingRoutePaymentPayload::CooperativeClose(_)
    );
    if !closes_historical_channel
        && app.public_paid_exit_node_pubkey_hex().as_deref() != Some(&seller)
    {
        return Err(anyhow!(
            "paid route payment seller is not the selected public exit"
        ));
    }
    let bytes = serde_json::to_vec(envelope)
        .context("failed to encode paid route payment envelope")?;
    let id = hex::encode(Sha256::digest(&bytes));
    let frame = nostr_vpn_core::fips_control::FipsControlFrame::PaidRoutePayment {
        id: id.clone(),
        envelope: envelope.clone(),
    };
    nostr_vpn_core::fips_control::encode_fips_control_frame(&frame)
        .context("paid route payment does not fit the FIPS control envelope")?;
    queue_paid_exit_payment_bytes(config_path, &id, &bytes)
}

fn load_paid_exit_payment_outbox(config_path: &Path) -> Vec<QueuedPaidExitPayment> {
    let directory = match prepare_paid_exit_payment_outbox(config_path) {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("paid-exit: failed to prepare payment outbox: {error}");
            return Vec::new();
        }
    };
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            eprintln!(
                "paid-exit: failed to scan payment outbox {}: {error}",
                directory.display()
            );
            return Vec::new();
        }
    };
    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.truncate(PAID_EXIT_PAYMENT_OUTBOX_BATCH);
    paths
        .into_iter()
        .filter_map(|path| match fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("failed to decode {}", path.display()))
            }) {
            Ok(envelope) => {
                let id = path.file_stem()?.to_str()?.to_string();
                if !valid_paid_exit_payment_id(&id) {
                    let _ = fs::remove_file(path);
                    return None;
                }
                Some(QueuedPaidExitPayment { id, envelope })
            }
            Err(error) => {
                eprintln!("paid-exit: discarding invalid payment outbox entry: {error}");
                let _ = fs::remove_file(path);
                None
            }
        })
        .collect()
}

#[derive(Default)]
struct PaidExitPaymentOutboxFlushResult {
    queued: usize,
    errors: usize,
}

async fn flush_paid_exit_payment_outbox(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    config_path: &Path,
) -> PaidExitPaymentOutboxFlushResult {
    let mut result = PaidExitPaymentOutboxFlushResult::default();
    for queued in load_paid_exit_payment_outbox(config_path) {
        let seller = queued.envelope.seller.clone();
        match runtime
            .enqueue_paid_route_payment(&seller, queued.id, queued.envelope)
        {
            Ok(()) => result.queued += 1,
            Err(error) => {
                result.errors += 1;
                eprintln!("paid-exit: direct FIPS payment queue failed: {error}");
            }
        }
    }
    result
}

fn acknowledge_paid_exit_payment(
    config_path: &Path,
    seller_pubkey: &str,
    id: &str,
) -> Result<bool> {
    if !valid_paid_exit_payment_id(id) {
        return Err(anyhow!("invalid paid route payment acknowledgment id"));
    }
    let path = paid_exit_payment_outbox_directory(config_path).join(format!("{id}.json"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let envelope: StreamingRoutePaymentEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    if normalize_nostr_pubkey(&envelope.seller).ok().as_deref() != Some(seller_pubkey) {
        return Err(anyhow!(
            "paid route payment acknowledgment source does not match seller"
        ));
    }
    // A payment acknowledgment proves only that the seller persisted the
    // payment. Routing is admitted separately by PaidRouteSessionOpenAck after
    // the seller has authenticated and bound the buyer's tunnel IP.
    fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(true)
}

fn valid_paid_exit_payment_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(test, unix))]
mod payment_outbox_owner_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    #[test]
    fn owner_selection_skips_root_created_state() {
        assert_eq!(
            preferred_paid_exit_outbox_owner(
                Some((0, 0)),
                Some((501, 20)),
                Some((0, 0)),
                Some((501, 20))
            ),
            Some((501, 20))
        );
        assert_eq!(
            preferred_paid_exit_outbox_owner(
                Some((502, 20)),
                Some((501, 20)),
                Some((0, 0)),
                None
            ),
            Some((502, 20))
        );
    }

    #[test]
    fn outbox_preserves_owner_modes_and_rejects_symlinks() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nvpn-outbox-owner-{nonce}"));
        fs::create_dir(&root).expect("create root");
        let config = root.join("config.toml");
        let store = paid_route_store_file_path(&config);
        fs::write(&config, b"config").expect("write config");
        fs::write(&store, b"{}").expect("write store");
        let id = "a".repeat(64);
        assert!(queue_paid_exit_payment_bytes(&config, &id, b"{}").expect("queue"));
        let directory = paid_exit_payment_outbox_directory(&config);
        let entry = directory.join(format!("{id}.json"));
        let expected = fs::metadata(&store).expect("store metadata");
        for (path, mode) in [(&directory, 0o700), (&entry, 0o600)] {
            let metadata = fs::metadata(path).expect("outbox metadata");
            assert_eq!((metadata.uid(), metadata.gid()), (expected.uid(), expected.gid()));
            assert_eq!(metadata.permissions().mode() & 0o777, mode);
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).expect("weaken dir");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o666)).expect("weaken entry");
        assert!(!queue_paid_exit_payment_bytes(&config, &id, b"{}").expect("repair"));
        assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&entry).unwrap().permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(&directory).expect("remove outbox");
        let redirect = root.join("redirect");
        fs::create_dir(&redirect).expect("create redirect");
        symlink(&redirect, &directory).expect("symlink outbox");
        assert!(queue_paid_exit_payment_bytes(&config, &id, b"{}").is_err());
        assert_eq!(fs::read_dir(&redirect).expect("read redirect").count(), 0);
        fs::remove_dir_all(root).expect("remove root");
    }
}
