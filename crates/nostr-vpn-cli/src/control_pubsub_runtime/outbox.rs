fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub fn control_pubsub_store_file_path(config_path: &Path) -> PathBuf {
    nostr_vpn_core::control_pubsub::control_pubsub_store_path(config_path)
}

fn control_pubsub_outbox_directory_from_store_path(store_path: &Path) -> PathBuf {
    store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("control-pubsub-outbox")
}

pub fn control_pubsub_outbox_directory(config_path: &Path) -> PathBuf {
    control_pubsub_outbox_directory_from_store_path(&control_pubsub_store_file_path(config_path))
}

pub fn queue_control_pubsub_event(config_path: &Path, event: &Event) -> Result<bool> {
    validate_control_pubsub_event(event)?;
    let bytes = serde_json::to_vec(event).context("failed to encode control pubsub event")?;

    let directory = control_pubsub_outbox_directory(config_path);
    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let destination = directory.join(format!("{}.json", event.id.to_hex()));
    if destination.exists() {
        return Ok(false);
    }
    nostr_vpn_core::config::write_private_file_preserving_user_owner(&destination, &bytes)
        .with_context(|| format!("failed to queue {}", destination.display()))?;
    Ok(true)
}

fn validate_control_pubsub_event(event: &Event) -> Result<()> {
    event
        .verify()
        .map_err(|error| anyhow!("invalid signed control pubsub event: {error}"))?;
    let kind = u16::from(event.kind);
    let update_events = configured_update_events()?;
    if !is_control_event(event, &update_events) {
        anyhow::bail!("unsupported control pubsub event kind or filter {kind}");
    }
    let bytes = serde_json::to_vec(event).context("failed to encode control pubsub event")?;
    if bytes.len() > CONTROL_PUBSUB_MAX_EVENT_BYTES {
        anyhow::bail!(
            "control pubsub event is {} bytes, maximum is {}",
            bytes.len(),
            CONTROL_PUBSUB_MAX_EVENT_BYTES
        );
    }
    Ok(())
}

fn control_pubsub_outbox_event_paths(directory: &Path) -> Vec<PathBuf> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            tracing::warn!(%error, path = %directory.display(), "failed to scan control pubsub outbox");
            return Vec::new();
        }
    };
    let mut paths = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.truncate(OUTBOX_BATCH);
    paths
}

#[cfg(any(feature = "paid-exit", test))]
pub fn load_control_pubsub_events(config_path: &Path) -> Result<Vec<Event>> {
    let update_events = configured_update_events()?;
    Ok(ControlEventStore::load(
        Some(control_pubsub_store_file_path(config_path)),
        update_events,
    )?
    .snapshot())
}
