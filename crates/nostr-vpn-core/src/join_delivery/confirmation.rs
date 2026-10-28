// Keep confirmation independently of the retry payload: expiry is not an ACK.
// These local records contain no request secret and do not grant membership.
#[derive(Serialize, Deserialize)]
struct PendingJoinConfirmation {
    network_id: String,
    recipient: String,
    event_id: String,
    signed_at: u64,
}

impl PendingJoinConfirmation {
    fn from_queued(queued: &QueuedJoinRoster) -> Result<Self> {
        Ok(Self {
            network_id: queued.join_roster.signed_roster.network_id()?,
            recipient: queued.recipient_npub.clone(),
            event_id: queued.join_roster.signed_roster.artifact_hash(),
            signed_at: queued.join_roster.signed_roster.signed_at(),
        })
    }

    fn path(&self, directory: &Path) -> PathBuf {
        directory.join(format!("{}-{}.pending", self.recipient, self.event_id))
    }
}

fn record_pending_join_confirmation(directory: &Path, queued: &QueuedJoinRoster) -> Result<()> {
    let confirmation = PendingJoinConfirmation::from_queued(queued)?;
    let path = confirmation.path(directory);
    if path.exists() {
        return Ok(());
    }
    let temporary = path.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        confirmation.event_id
    ));
    write_private_file(&temporary, &serde_json::to_vec(&confirmation)?)?;
    fs::rename(&temporary, &path).with_context(|| format!("failed to save {}", path.display()))
}

/// Return local approvals still lacking a durable application receipt, even
/// after their bounded delivery retry window has ended.
pub fn pending_join_confirmations(
    config_path: &Path,
    network_id: &str,
) -> std::collections::HashSet<String> {
    read_pending_confirmations(&join_roster_outbox_directory(config_path))
        .into_iter()
        .map(|(_, confirmation)| confirmation)
        .filter(|confirmation| confirmation.network_id == network_id)
        .map(|confirmation| confirmation.recipient)
        .collect()
}

fn read_pending_confirmations(directory: &Path) -> Vec<(PathBuf, PendingJoinConfirmation)> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pending")
        })
        .filter_map(|path| {
            let bytes = fs::read(&path).ok()?;
            let confirmation = serde_json::from_slice(&bytes).ok()?;
            Some((path, confirmation))
        })
        .collect()
}

/// Call only after the authenticated, matching roster application receipt.
/// A late receipt for an older approval must not confirm a newer request.
pub fn complete_join_roster_delivery(path: &Path, queued: &QueuedJoinRoster) -> Result<()> {
    // The sender retains this exact approval while waiting. Its retry payload
    // may already have expired when the application receipt arrives.
    let delivered = PendingJoinConfirmation::from_queued(queued)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    // Each approval has an immutable, distinct path. A concurrent new approval
    // cannot be deleted by a late receipt for an older roster.
    for (confirmation_path, pending) in read_pending_confirmations(directory) {
        if pending.network_id == delivered.network_id
            && pending.recipient == delivered.recipient
            && (pending.event_id == delivered.event_id || pending.signed_at < delivered.signed_at)
        {
            remove_confirmation_file(&confirmation_path)?;
        }
    }
    remove_confirmation_file(path)
}

fn remove_confirmation_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to consume confirmed join roster"),
    }
}

/// An expired approval can never deliver, so drop the retry payload and its
/// pending marker together; otherwise the UI shows "approval pending" forever.
pub fn expire_join_roster(path: &Path, queued: &QueuedJoinRoster) -> Result<()> {
    remove_confirmation_file(path)?;
    let confirmation = PendingJoinConfirmation::from_queued(queued)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    remove_confirmation_file(&confirmation.path(directory))
}
