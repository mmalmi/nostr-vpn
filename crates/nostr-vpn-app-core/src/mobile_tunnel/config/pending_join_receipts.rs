const PENDING_JOIN_ROSTER_RECEIPTS_VERSION: u8 = 1;
const MAX_PENDING_JOIN_ROSTER_RECEIPTS: usize = 32;
const MAX_PENDING_JOIN_ROSTER_RECEIPTS_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingJoinRosterReceipt {
    destination: PeerIdentity,
    committed: bool,
    failed_attempts: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPendingJoinRosterReceipt {
    roster_event_id: String,
    destination_npub: String,
    committed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPendingJoinRosterReceipts {
    version: u8,
    receipts: Vec<PersistedPendingJoinRosterReceipt>,
}

#[derive(Debug)]
struct PendingJoinRosterReceiptQueue {
    path: Option<PathBuf>,
    applying: Mutex<()>,
    receipts: Mutex<HashMap<String, PendingJoinRosterReceipt>>,
    changed: tokio::sync::Notify,
}

type PendingJoinRosterReceipts = Arc<PendingJoinRosterReceiptQueue>;

impl Default for PendingJoinRosterReceiptQueue {
    fn default() -> Self {
        Self {
            path: None,
            applying: Mutex::new(()),
            receipts: Mutex::new(HashMap::new()),
            changed: tokio::sync::Notify::new(),
        }
    }
}

impl PendingJoinRosterReceiptQueue {
    #[cfg(any(test, target_os = "android"))]
    fn has_pending_receipts(&self) -> bool {
        // Config-file observers can request a restart before apply has queued
        // its receipt. Keep the live carrier through that gap and until ACK.
        let Ok(_applying) = self.applying.try_lock() else {
            return true;
        };
        self.receipts
            .lock()
            .map_or(true, |receipts| !receipts.is_empty())
    }

    fn load(path: Option<PathBuf>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: Some(path),
                    ..Self::default()
                });
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", path.display()));
            }
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            > MAX_PENDING_JOIN_ROSTER_RECEIPTS_BYTES
        {
            return Err(anyhow!(
                "mobile pending join receipt sidecar {} exceeds {} bytes",
                path.display(),
                MAX_PENDING_JOIN_ROSTER_RECEIPTS_BYTES
            ));
        }
        let persisted: PersistedPendingJoinRosterReceipts = serde_json::from_slice(&bytes)
            .with_context(|| {
                format!(
                    "failed to decode mobile pending join receipt sidecar {}",
                    path.display()
                )
            })?;
        if persisted.version != PENDING_JOIN_ROSTER_RECEIPTS_VERSION {
            return Err(anyhow!(
                "unsupported mobile pending join receipt sidecar version {}",
                persisted.version
            ));
        }
        if persisted.receipts.len() > MAX_PENDING_JOIN_ROSTER_RECEIPTS {
            return Err(anyhow!(
                "mobile pending join receipt sidecar has {} entries; maximum is {}",
                persisted.receipts.len(),
                MAX_PENDING_JOIN_ROSTER_RECEIPTS
            ));
        }
        let mut receipts = HashMap::with_capacity(persisted.receipts.len());
        for persisted_receipt in persisted.receipts {
            let roster_event_id = persisted_receipt.roster_event_id.trim().to_ascii_lowercase();
            if roster_event_id.is_empty() || roster_event_id.len() > 256 {
                return Err(anyhow!(
                    "invalid roster event id in mobile pending join receipt sidecar"
                ));
            }
            let destination =
                PeerIdentity::from_npub(&persisted_receipt.destination_npub).with_context(|| {
                    format!(
                        "invalid destination for pending join receipt {roster_event_id}"
                    )
                })?;
            if receipts
                .insert(
                    roster_event_id.clone(),
                    PendingJoinRosterReceipt {
                        destination,
                        committed: persisted_receipt.committed,
                        failed_attempts: 0,
                    },
                )
                .is_some()
            {
                return Err(anyhow!(
                    "duplicate pending join receipt {roster_event_id} in sidecar"
                ));
            }
        }
        Ok(Self {
            path: Some(path),
            applying: Mutex::new(()),
            receipts: Mutex::new(receipts),
            changed: tokio::sync::Notify::new(),
        })
    }

    fn enqueue(
        &self,
        roster_event_id: String,
        destination: PeerIdentity,
        committed: bool,
    ) -> Result<()> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| anyhow!("mobile pending join receipt lock poisoned"))?;
        let mut updated = receipts.clone();
        updated
            .entry(roster_event_id)
            .and_modify(|receipt| {
                receipt.committed |= committed;
            })
            .or_insert(PendingJoinRosterReceipt {
                destination,
                committed,
                failed_attempts: 0,
            });
        if updated != *receipts {
            self.persist(&updated)?;
            *receipts = updated;
        }
        drop(receipts);
        if committed {
            self.changed.notify_one();
        }
        Ok(())
    }

    fn mark_committed(&self) -> Result<usize> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| anyhow!("mobile pending join receipt lock poisoned"))?;
        let mut updated = receipts.clone();
        let mut changed = 0;
        for receipt in updated.values_mut() {
            if !receipt.committed {
                receipt.committed = true;
                changed += 1;
            }
        }
        if changed != 0 {
            self.persist(&updated)?;
            *receipts = updated;
        }
        drop(receipts);
        if changed != 0 {
            self.changed.notify_one();
        }
        Ok(changed)
    }

    fn committed_snapshot(&self) -> Result<Vec<(String, PeerIdentity)>> {
        self.receipts
            .lock()
            .map_err(|_| anyhow!("mobile pending join receipt lock poisoned"))
            .map(|receipts| {
                receipts
                    .iter()
                    .filter(|(_, receipt)| receipt.committed)
                    .map(|(event_id, receipt)| (event_id.clone(), receipt.destination))
                    .collect()
            })
    }

    fn record_failed_attempt(
        &self,
        roster_event_id: &str,
        destination: PeerIdentity,
    ) -> Result<()> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| anyhow!("mobile pending join receipt lock poisoned"))?;
        if let Some(receipt) = receipts.get_mut(roster_event_id)
            && receipt.destination == destination
        {
            receipt.failed_attempts = receipt.failed_attempts.saturating_add(1);
        }
        Ok(())
    }

    fn remove_delivered(
        &self,
        roster_event_id: &str,
        destination: PeerIdentity,
    ) -> Result<bool> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| anyhow!("mobile pending join receipt lock poisoned"))?;
        if receipts
            .get(roster_event_id)
            .is_some_and(|receipt| receipt.destination == destination)
        {
            let mut updated = receipts.clone();
            updated.remove(roster_event_id);
            self.persist(&updated)?;
            *receipts = updated;
            return Ok(true);
        }
        Ok(false)
    }

    fn persist(&self, receipts: &HashMap<String, PendingJoinRosterReceipt>) -> Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if receipts.is_empty() {
            match fs::remove_file(path) {
                Ok(()) => sync_pending_join_receipt_parent(path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to remove {}", path.display()));
                }
            }
            return Ok(());
        }
        if receipts.len() > MAX_PENDING_JOIN_ROSTER_RECEIPTS {
            return Err(anyhow!(
                "mobile pending join receipt queue has {} entries; maximum is {}",
                receipts.len(),
                MAX_PENDING_JOIN_ROSTER_RECEIPTS
            ));
        }
        let mut persisted_receipts = receipts
            .iter()
            .map(
                |(roster_event_id, receipt)| PersistedPendingJoinRosterReceipt {
                    roster_event_id: roster_event_id.clone(),
                    destination_npub: receipt.destination.npub(),
                    committed: receipt.committed,
                },
            )
            .collect::<Vec<_>>();
        persisted_receipts.sort_by(|left, right| {
            left.roster_event_id.cmp(&right.roster_event_id)
        });
        let bytes = serde_json::to_vec(&PersistedPendingJoinRosterReceipts {
            version: PENDING_JOIN_ROSTER_RECEIPTS_VERSION,
            receipts: persisted_receipts,
        })
        .context("failed to encode mobile pending join receipt sidecar")?;
        write_pending_join_receipts_atomically(path, &bytes)
    }
}

fn write_pending_join_receipts_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pending-join-roster-receipts.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut temporary = None;
    let mut file = None;
    for attempt in 0..128u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(created) => {
                temporary = Some(candidate);
                file = Some(created);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create sidecar beside {}", path.display()));
            }
        }
    }
    let temporary = temporary.ok_or_else(|| {
        anyhow!(
            "failed to allocate temporary pending join receipt sidecar beside {}",
            path.display()
        )
    })?;
    let mut file = file.expect("pending join receipt temp file accompanies its path");
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to write sidecar {}", temporary.display()));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| {
            format!(
                "failed to atomically replace pending join receipt sidecar {}",
                path.display()
            )
        });
    }
    sync_pending_join_receipt_parent(path)
}

#[cfg(unix)]
fn sync_pending_join_receipt_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync sidecar directory {}", parent.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_pending_join_receipt_parent(_: &Path) -> Result<()> {
    Ok(())
}
