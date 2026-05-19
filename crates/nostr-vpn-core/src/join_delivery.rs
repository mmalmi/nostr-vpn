use std::fs;
use std::io::ErrorKind;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::normalize_nostr_pubkey;
use crate::fips_control::JoinRosterControl;

include!("join_delivery/confirmation.rs");

const JOIN_ROSTER_OUTBOX_VERSION: u8 = 1;
const MAX_QUEUED_JOIN_ROSTERS: usize = 8;
pub const JOIN_ROSTER_OUTBOX_TTL_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedJoinRoster {
    pub version: u8,
    pub recipient_npub: String,
    pub join_roster: JoinRosterControl,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub last_attempt_at: u64,
}

pub fn join_roster_delivery_expired(queued: &QueuedJoinRoster, now: u64) -> bool {
    now.saturating_sub(queued.join_roster.signed_roster.signed_at()) > JOIN_ROSTER_OUTBOX_TTL_SECS
}

pub fn join_roster_outbox_directory(config_path: &Path) -> PathBuf {
    let mut directory_name = config_path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "config.toml".into());
    directory_name.push(".join-roster-outbox");
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(directory_name)
}

pub fn queue_join_roster(
    config_path: &Path,
    recipient_npub: &str,
    join_roster: &JoinRosterControl,
) -> Result<PathBuf> {
    let recipient_npub =
        normalize_nostr_pubkey(recipient_npub).context("invalid join roster recipient")?;
    join_roster
        .signed_roster
        .verify()
        .context("invalid signed join roster")?;
    let queued = QueuedJoinRoster {
        version: JOIN_ROSTER_OUTBOX_VERSION,
        recipient_npub: recipient_npub.clone(),
        join_roster: join_roster.clone(),
        attempts: 0,
        last_attempt_at: 0,
    };
    let directory = join_roster_outbox_directory(config_path);
    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let event_id = queued.join_roster.signed_roster.event.id.to_hex();
    let destination = directory.join(format!("{recipient_npub}-{event_id}.json"));
    if destination.exists() {
        record_pending_join_confirmation(&directory, &queued)?;
        return Ok(destination);
    }
    let temporary = directory.join(format!(
        ".{recipient_npub}-{}-{event_id}.tmp",
        std::process::id()
    ));
    let bytes = serde_json::to_vec(&queued).context("failed to encode queued join roster")?;
    write_private_file(&temporary, &bytes)?;
    // Persist the pending state before the daemon can see and deliver the
    // payload. Otherwise a fast receipt can arrive before its pending marker.
    if let Err(error) = record_pending_join_confirmation(&directory, &queued) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("failed to queue {}", destination.display()));
    }
    Ok(destination)
}

pub fn record_join_roster_attempt(
    path: &Path,
    queued: &mut QueuedJoinRoster,
    attempted_at: u64,
) -> Result<()> {
    queued.attempts = queued.attempts.saturating_add(1);
    queued.last_attempt_at = attempted_at;
    let bytes = serde_json::to_vec(queued).context("failed to encode queued join roster")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("join-roster.json");
    let temporary = parent.join(format!(
        ".{file_name}-{}-{}.tmp",
        std::process::id(),
        queued.attempts
    ));
    write_private_file(&temporary, &bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("failed to update {}", path.display()));
    }
    Ok(())
}

pub fn load_join_rosters(config_path: &Path) -> Vec<(PathBuf, QueuedJoinRoster)> {
    let directory = join_roster_outbox_directory(config_path);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            eprintln!("failed to scan {}: {error}", directory.display());
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
    paths.truncate(MAX_QUEUED_JOIN_ROSTERS);
    paths
        .into_iter()
        .filter_map(|path| {
            match fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))
                .and_then(|bytes| {
                    serde_json::from_slice::<QueuedJoinRoster>(&bytes)
                        .with_context(|| format!("failed to decode {}", path.display()))
                }) {
                Ok(queued)
                    if queued.version == JOIN_ROSTER_OUTBOX_VERSION
                        && queued.join_roster.signed_roster.verify().is_ok()
                        && !queued.join_roster.request_secret.is_empty() =>
                {
                    Some((path, queued))
                }
                Ok(_) => {
                    eprintln!(
                        "discarding unsupported queued join roster {}",
                        path.display()
                    );
                    let _ = fs::remove_file(path);
                    None
                }
                Err(error) => {
                    eprintln!("discarding invalid queued join roster: {error:#}");
                    let _ = fs::remove_file(path);
                    None
                }
            }
        })
        .collect()
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nostr_sdk::Keys;

    use super::*;
    use crate::fips_control::{JoinRosterControl, NetworkRoster, SignedRoster};

    #[test]
    fn outbox_stores_exactly_one_signed_roster() {
        let admin = Keys::generate();
        let recipient = Keys::generate().public_key().to_hex();
        let roster = SignedRoster::sign(
            "network",
            NetworkRoster {
                network_name: "Home".to_string(),
                devices: vec![recipient.clone()],
                admins: vec![admin.public_key().to_hex()],
                aliases: Default::default(),
                signed_at: 100,
            },
            &admin,
        )
        .expect("sign roster");
        let join_roster =
            JoinRosterControl::new(roster.clone(), "request-secret").expect("join control");
        let config_path = std::env::temp_dir().join(format!(
            "nvpn-join-roster-{}-{}.toml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));

        let path =
            queue_join_roster(&config_path, &recipient, &join_roster).expect("queue signed roster");
        let queued = load_join_rosters(&config_path);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].1.join_roster.signed_roster, roster);
        assert_eq!(queued[0].1.join_roster.request_secret, "request-secret");
        assert_eq!(queued[0].1.recipient_npub, recipient);
        assert_eq!(queued[0].1.attempts, 0);
        assert!(!join_roster_delivery_expired(
            &queued[0].1,
            100 + JOIN_ROSTER_OUTBOX_TTL_SECS
        ));
        assert!(join_roster_delivery_expired(
            &queued[0].1,
            101 + JOIN_ROSTER_OUTBOX_TTL_SECS
        ));

        let mut delivery = queued[0].1.clone();
        record_join_roster_attempt(&path, &mut delivery, 123).expect("record send attempt");
        let reloaded = load_join_rosters(&config_path);
        assert_eq!(reloaded[0].1.attempts, 1);
        assert_eq!(reloaded[0].1.last_attempt_at, 123);

        // A later approval can be queued while the old receipt is in flight.
        let mut newer_roster = roster.roster().expect("roster");
        newer_roster.signed_at = 124;
        let newer = JoinRosterControl::new(
            SignedRoster::sign("network", newer_roster, &admin).expect("new signature"),
            "new-request-secret",
        )
        .expect("new approval");
        let newer_path = queue_join_roster(&config_path, &recipient, &newer).expect("queue newer");
        assert!(pending_join_confirmations(&config_path, "network").contains(&recipient));
        assert!(pending_join_confirmations(&config_path, "other-network").is_empty());

        complete_join_roster_delivery(&path, &queued[0].1).expect("confirm queued roster");
        assert!(
            pending_join_confirmations(&config_path, "network").contains(&recipient),
            "an old receipt must not confirm the new request"
        );
        let expired_path = queue_join_roster(&config_path, &recipient, &join_roster)
            .expect("queue older approval again");
        fs::remove_file(expired_path).expect("expire retry payload without confirming");
        let newer_delivery = load_join_rosters(&config_path).remove(0).1;
        complete_join_roster_delivery(&newer_path, &newer_delivery).expect("confirm newer roster");
        complete_join_roster_delivery(&newer_path, &newer_delivery)
            .expect("duplicate receipt is harmless");
        assert!(pending_join_confirmations(&config_path, "network").is_empty());
        fs::remove_dir(join_roster_outbox_directory(&config_path)).expect("remove outbox");
    }
}
