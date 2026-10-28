struct QueuedPaidExitPayment {
    id: String,
    envelope: StreamingRoutePaymentEnvelope,
}

// Refund lifetime ends by the 12h cutoff plus 24h reclaim; a week bounds dead-seller retries.
const PAYMENT_OUTBOX_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

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
    #[cfg(not(target_os = "macos"))]
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

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
            #[cfg(target_os = "macos")]
            let created = fs::create_dir_all(&directory);
            #[cfg(not(target_os = "macos"))]
            let created = fs::DirBuilder::new().mode(0o700).create(&directory);
            match created {
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

    let buyer =
        normalize_nostr_pubkey(&envelope.buyer).context("invalid paid route payment buyer")?;
    if buyer != app.nostr_keys()?.public_key().to_hex() {
        return Err(anyhow!(
            "paid route payment buyer does not match local FIPS identity"
        ));
    }
    let seller =
        normalize_nostr_pubkey(&envelope.seller).context("invalid paid route payment seller")?;
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
    let bytes =
        serde_json::to_vec(envelope).context("failed to encode paid route payment envelope")?;
    let id = hex::encode(Sha256::digest(&bytes));
    let frame = nostr_vpn_core::fips_control::FipsControlFrame::PaidRoutePayment {
        id: id.clone(),
        envelope: envelope.clone(),
    };
    nostr_vpn_core::fips_control::encode_fips_control_frame(&frame)
        .context("paid route payment does not fit the FIPS control envelope")?;
    queue_paid_exit_payment_bytes(config_path, &id, &bytes)
}

fn paid_exit_outbox_entry_expired(path: &Path, now_unix: u64) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .is_some_and(|modified| {
            modified
                .as_secs()
                .saturating_add(PAYMENT_OUTBOX_RETENTION_SECS)
                <= now_unix
        })
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
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let paths = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    let mut pending: Vec<QueuedPaidExitPayment> = paths
        .into_iter()
        .filter_map(|path| {
            if paid_exit_outbox_entry_expired(&path, now_unix) {
                let _ = fs::remove_file(path);
                return None;
            }
            match fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("failed to decode {}", path.display()))
                }) {
                Ok(envelope) => {
                    let id = path.file_stem()?.to_str()?.to_string();
                    if !valid_paid_exit_payment_id(&id)
                        || nostr_vpn_core::paid_route_store::paid_route_payment_id(&envelope)
                            .is_ok_and(|expected| expected != id)
                    {
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
            }
        })
        .collect();
    // A balance update is cumulative. Recover legacy backlogs as well as new
    // queues, retaining the strongest durable update for each exact binding.
    // Funding and cooperative close records keep only their newest retry.
    let binding = |envelope: &StreamingRoutePaymentEnvelope| {
        (
            envelope.version,
            envelope.service_id.clone(),
            envelope.lease_id.clone(),
            envelope.buyer.clone(),
            envelope.seller.clone(),
            envelope.channel_id().to_owned(),
        )
    };
    let mut newest = std::collections::HashMap::new();
    let mut strongest = std::collections::HashMap::new();
    let mut newest_retry = std::collections::HashMap::new();
    for queued in &pending {
        let key = binding(&queued.envelope);
        let sent_at = newest.entry(key.clone()).or_insert(0);
        *sent_at = (*sent_at).max(queued.envelope.sent_at_unix);
        let retry = (queued.envelope.sent_at_unix, queued.id.clone());
        let record = newest_retry
            .entry((key.clone(), std::mem::discriminant(&queued.envelope.payload)))
            .or_insert_with(|| retry.clone());
        if retry > *record {
            *record = retry;
        }
        let StreamingRoutePaymentPayload::BalanceUpdate(update) = &queued.envelope.payload else {
            continue;
        };
        let candidate = (update.paid_msat, update.payment.balance, queued.id.clone());
        let current = strongest.entry(key).or_insert_with(|| candidate.clone());
        if candidate > *current {
            *current = candidate;
        }
    }
    let remove_superseded = |queued: &QueuedPaidExitPayment| {
        let path = directory.join(format!("{}.json", queued.id));
        if let Err(error) = fs::remove_file(path) {
            eprintln!("paid-exit: failed to remove superseded payment: {error}");
        }
    };
    pending.retain(|queued| {
        let key = binding(&queued.envelope);
        let StreamingRoutePaymentPayload::BalanceUpdate(update) = &queued.envelope.payload else {
            let (_, id) = &newest_retry[&(key, std::mem::discriminant(&queued.envelope.payload))];
            if id != &queued.id {
                remove_superseded(queued);
                return false;
            }
            return true;
        };
        let (paid_msat, balance, id) = &strongest[&key];
        if id != &queued.id && *paid_msat >= update.paid_msat && *balance >= update.payment.balance
        {
            remove_superseded(queued);
            return false;
        }
        true
    });
    // The transport owns its bounded queue. Never hide fresh channels behind
    // a fixed prefix of old hashes when it applies backpressure.
    let phase = |envelope: &StreamingRoutePaymentEnvelope| match &envelope.payload {
        StreamingRoutePaymentPayload::ChannelOpen(_) => 0,
        StreamingRoutePaymentPayload::BalanceUpdate(_) => 1,
        _ => 2,
    };
    pending.sort_by_key(|queued| {
        (
            std::cmp::Reverse(newest[&binding(&queued.envelope)]),
            binding(&queued.envelope),
            phase(&queued.envelope),
            queued.id.clone(),
        )
    });
    pending
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
        match runtime.enqueue_paid_route_payment(&seller, queued.id, queued.envelope) {
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
    // Payment ACKs cover a persisted cumulative balance. Routing admission
    // still requires a separate, authenticated session-open acknowledgment.
    nostr_vpn_core::paid_route_store::acknowledge_paid_route_payment_outbox(
        config_path,
        seller_pubkey,
        id,
    )
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
            preferred_paid_exit_outbox_owner(Some((502, 20)), Some((501, 20)), Some((0, 0)), None),
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
            assert_eq!(
                (metadata.uid(), metadata.gid()),
                (expected.uid(), expected.gid())
            );
            assert_eq!(metadata.permissions().mode() & 0o777, mode);
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).expect("weaken dir");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o666)).expect("weaken entry");
        assert!(!queue_paid_exit_payment_bytes(&config, &id, b"{}").expect("repair"));
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&entry).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(&directory).expect("remove outbox");
        let redirect = root.join("redirect");
        fs::create_dir(&redirect).expect("create redirect");
        symlink(&redirect, &directory).expect("symlink outbox");
        assert!(queue_paid_exit_payment_bytes(&config, &id, b"{}").is_err());
        assert_eq!(fs::read_dir(&redirect).expect("read redirect").count(), 0);
        fs::remove_dir_all(root).expect("remove root");
    }
}

#[cfg(test)]
#[path = "payment_outbox_tests.rs"]
mod payment_outbox_tests;
