//! Completed inbox receipts outlive the live protocol journal. Each record has a
//! bounded independent read; pagination never parses an entire user's history.
#[cfg(unix)]
use super::unix_storage::visit_names;
#[cfg(windows)]
use super::windows_storage::visit_names;
use super::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

const MAX_RECEIPT_BYTES: u64 = 128 * 1024;
const PAGE_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxPage {
    pub transfers: Vec<TransferState>,
    pub next_cursor: Option<String>,
}

fn directory(config: &Path) -> PathBuf {
    state_dir(config).join("inbox-history")
}

fn validate(config: &Path, id: &str, state: &TransferState) -> Result<()> {
    ensure!(valid_id(id) && state.id == id, "Invalid inbox receipt ID");
    ensure!(
        !state.is_sender && state.status == "completed",
        "Inbox receipt is not a received transfer"
    );
    ensure!(
        !state.files.is_empty() && state.files.len() <= 32,
        "Invalid inbox receipt files"
    );
    let inbox = state_dir(config).join("inbox");
    let mut total = 0_u64;
    for file in &state.files {
        ensure!(
            fips_file_transfer::wire::valid_filename(&file.name)
                && file.size_bytes <= MAX_FILE_BYTES,
            "Invalid inbox file details"
        );
        let path = Path::new(
            file.local_path
                .as_deref()
                .context("Inbox file has no saved location")?,
        );
        let relative = path
            .strip_prefix(&inbox)
            .context("Inbox file is outside received files")?;
        ensure!(
            relative.components().count() == 2
                && relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "Invalid inbox file location"
        );
        total = total
            .checked_add(file.size_bytes)
            .context("Invalid inbox byte count")?;
    }
    ensure!(
        total == state.total_bytes && state.transferred_bytes == total,
        "Invalid completed inbox byte count"
    );
    Ok(())
}

pub fn save(config: &Path, state: &TransferState) -> Result<()> {
    validate(config, &state.id, state)?;
    let bytes = serde_json::to_vec(state)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "Inbox receipt is too large"
    );
    owned_dir(config, &state_dir(config))?;
    owned_dir(config, &directory(config))?;
    write_atomic(
        config,
        &directory(config).join(format!("{}.json", state.id)),
        &bytes,
    )
}

pub fn read(config: &Path, id: &str) -> Result<Option<TransferState>> {
    ensure!(valid_id(id), "Invalid inbox receipt ID");
    let path = directory(config).join(format!("{id}.json"));
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let state: TransferState =
        serde_json::from_slice(&bounded_read(config, &path, MAX_RECEIPT_BYTES)?)
            .context("Could not read inbox receipt")?;
    validate(config, id, &state)?;
    Ok(Some(state))
}

/// The cursor is an exclusive opaque transfer ID, with descending byte ordering.
/// Keep only 65 filename candidates in memory and parse at most 64 receipts.
pub fn page(config: &Path, before: Option<&str>) -> Result<InboxPage> {
    if let Some(cursor) = before {
        ensure!(valid_id(cursor), "Invalid inbox cursor");
    }
    let folder = directory(config);
    match fs::symlink_metadata(&folder) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InboxPage {
                transfers: vec![],
                next_cursor: None,
            });
        }
        Err(error) => return Err(error.into()),
    }
    // Enumerate through a pinned directory, so an exchanged ancestor cannot
    // redirect even filename discovery. Receipts are independently reopened.
    let mut candidates = BinaryHeap::<Reverse<String>>::new();
    visit_names(config, &folder, |name| {
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            return;
        };
        if !valid_id(id) || before.is_some_and(|cursor| id >= cursor) {
            return;
        }
        if candidates.len() < PAGE_SIZE + 1 {
            candidates.push(Reverse(id.into()));
        } else if candidates
            .peek()
            .is_some_and(|smallest| id > smallest.0.as_str())
        {
            candidates.pop();
            candidates.push(Reverse(id.into()));
        }
    })?;
    let mut ids = candidates.into_iter().map(|id| id.0).collect::<Vec<_>>();
    ids.sort_unstable_by(|a, b| b.cmp(a));
    let next_cursor = if ids.len() > PAGE_SIZE {
        ids.get(PAGE_SIZE - 1).cloned()
    } else {
        None
    };
    let mut transfers = Vec::with_capacity(PAGE_SIZE);
    for id in ids.into_iter().take(PAGE_SIZE) {
        match read(config, &id) {
            Ok(Some(state)) => transfers.push(state),
            Ok(None) => {}
            Err(error) => tracing::warn!(%id,%error,"invalid inbox receipt skipped"),
        }
    }
    Ok(InboxPage {
        transfers,
        next_cursor,
    })
}
