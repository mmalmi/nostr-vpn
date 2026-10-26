//! Local file-transfer control shared by desktop daemons and mobile VPN runtimes.
//! Bytes stay in owned files; command JSON carries only staged source references.
#[cfg(windows)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub mod inbox;
mod runtime;
#[cfg(unix)]
mod unix_destination;
#[cfg(unix)]
mod unix_storage;
#[cfg(windows)]
mod windows_storage;
pub use runtime::FileTransferService;
#[cfg(unix)]
use unix_storage::{create_owned, open_owned, owned_dir, remove as remove_owned, write_atomic};
#[cfg(windows)]
use windows_storage::{create_owned, open_owned, owned_dir, remove as remove_owned, write_atomic};

pub const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024 * 1024;
const MAX_COMMAND_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PENDING_COMMANDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileState {
    pub name: String,
    pub size_bytes: u64,
    pub local_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferState {
    pub id: String,
    pub peer_npub: String,
    pub peer_name: String,
    pub is_sender: bool,
    pub files: Vec<FileState>,
    pub status: String,
    pub transferred_bytes: u64,
    pub total_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileCommand {
    Send { npub: String, paths: Vec<String> },
    Accept { id: String },
    Decline { id: String },
    Cancel { id: String },
    Resume { id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedCommand {
    id: String,
    command: FileCommand,
}

pub fn state_dir(config: &Path) -> PathBuf {
    config
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("file-transfers")
}

pub fn outbox_dir(config: &Path) -> PathBuf {
    config
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("file-transfer-outbox")
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn valid_filename(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
    !value.is_empty()
        && value.len() <= 240
        && value != "."
        && value != ".."
        && !reserved
        && !value.ends_with(['.', ' '])
        && !value
            .chars()
            .any(|c| c.is_control() || "/\\<>:\"|?*".contains(c))
}

fn export_names(files: &[fips_file_transfer::ManifestFile]) -> Vec<String> {
    let reserved = files
        .iter()
        .map(|file| file.filename.to_lowercase())
        .collect::<std::collections::HashSet<_>>();
    let mut assigned = std::collections::HashSet::new();
    files
        .iter()
        .map(|file| {
            let trimmed = file.filename.trim_end_matches(['.', ' ']);
            let base = if trimmed.is_empty() {
                "file".to_owned()
            } else if !valid_filename(trimmed) {
                format!("_{trimmed}")
            } else {
                trimmed.to_owned()
            };
            let mut name = base.clone();
            let mut suffix = 2;
            while assigned.contains(&name.to_lowercase())
                || (name != file.filename && reserved.contains(&name.to_lowercase()))
            {
                name = format!("{suffix}-{base}");
                suffix += 1;
            }
            assigned.insert(name.to_lowercase());
            name
        })
        .collect()
}

pub fn validate_recipient(config: &Path, recipient: &str) -> Result<()> {
    let app = crate::config::AppConfig::load(config)?;
    let recipient = crate::config::normalize_nostr_pubkey(recipient)?;
    ensure!(
        authorized_peers(&app)?.contains_key(&recipient),
        "This device is not in an enabled private network"
    );
    Ok(())
}

fn authorized_peers(
    app: &crate::config::AppConfig,
) -> Result<std::collections::HashMap<String, String>> {
    let mut peers = std::collections::HashMap::new();
    let own = app.own_nostr_pubkey_hex()?;
    for network in app.networks.iter().filter(|network| {
        network.enabled
            && !network.local_identity_confirmation_pending
            && !network.removed_devices.contains(&own)
    }) {
        for member in network.devices.iter().chain(&network.admins) {
            if let Ok(hex) = crate::config::normalize_nostr_pubkey(member) {
                if hex != own && !network.removed_devices.contains(&hex) {
                    peers.insert(hex.clone(), app.peer_alias(&hex).unwrap_or_default());
                }
            }
        }
    }
    Ok(peers)
}

/// Queue an already staged file operation. The running endpoint owns execution.
pub fn enqueue(config: &Path, command: FileCommand) -> Result<String> {
    match &command {
        FileCommand::Send { npub, paths } => {
            validate_recipient(config, npub)?;
            ensure!(
                !paths.is_empty() && paths.len() <= 32,
                "Choose between 1 and 32 files"
            );
            for path in paths {
                open_staged(config, Path::new(path))?;
            }
        }
        FileCommand::Accept { id }
        | FileCommand::Decline { id }
        | FileCommand::Cancel { id }
        | FileCommand::Resume { id } => {
            ensure!(valid_id(id), "Invalid transfer ID");
        }
    }
    let directory = state_dir(config).join("commands");
    owned_dir(config, &state_dir(config))?;
    owned_dir(config, &directory)?;
    ensure!(
        fs::read_dir(&directory)?.take(MAX_PENDING_COMMANDS).count() < MAX_PENDING_COMMANDS,
        "File transfers are busy. Try again shortly."
    );
    let id = uuid::Uuid::new_v4().simple().to_string();
    let bytes = serde_json::to_vec(&QueuedCommand {
        id: id.clone(),
        command,
    })?;
    ensure!(
        bytes.len() as u64 <= MAX_COMMAND_BYTES,
        "File command is too large"
    );
    write_atomic(config, &directory.join(format!("{id}.json")), &bytes)?;
    Ok(id)
}

pub fn read_state(config: &Path) -> Result<Vec<TransferState>> {
    let path = state_dir(config).join("state.json");
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let bytes = bounded_read(config, &path, MAX_STATE_BYTES)?;
    serde_json::from_slice(&bytes).context("Could not read file transfers")
}

/// Stage a user-selected source without loading the file into memory.
pub fn stage_source(config: &Path, source: &Path) -> Result<PathBuf> {
    let name = source
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid filename")?;
    ensure!(valid_filename(name), "Unsupported filename");
    let mut input = File::open(source).context("Could not open selected file")?;
    let metadata = input.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE_BYTES,
        "Invalid selected file"
    );
    let batch = outbox_dir(config).join(uuid::Uuid::new_v4().simple().to_string());
    owned_dir(config, &outbox_dir(config))?;
    owned_dir(config, &batch)?;
    let target = batch.join(name);
    let result = (|| -> Result<()> {
        let mut output = create_owned(config, &target)?;
        let count = std::io::copy(&mut (&mut input).take(MAX_FILE_BYTES + 1), &mut output)?;
        ensure!(
            count == metadata.len(),
            "Selected file changed while preparing it"
        );
        output.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = remove_owned(&target, false);
        let _ = remove_owned(&batch, true);
        return Err(error);
    }
    Ok(target)
}

pub fn create_upload(config: &Path, name: &str) -> Result<(PathBuf, File)> {
    ensure!(valid_filename(name), "Invalid filename");
    owned_dir(config, &outbox_dir(config))?;
    let batch = outbox_dir(config).join(uuid::Uuid::new_v4().simple().to_string());
    owned_dir(config, &batch)?;
    let path = batch.join(name);
    let output = create_owned(config, &path)?;
    Ok((path, output))
}

pub fn completed_file(config: &Path, id: &str, index: usize) -> Result<(FileState, File)> {
    ensure!(valid_id(id), "Invalid transfer ID");
    let state = match inbox::read(config, id)? {
        Some(state) => state,
        None => read_state(config)?
            .into_iter()
            .find(|state| state.id == id)
            .context("File transfer not found")?,
    };
    ensure!(
        !state.is_sender && state.status == "completed",
        "File is not ready"
    );
    let file = state.files.get(index).cloned().context("File not found")?;
    let path = Path::new(file.local_path.as_deref().context("File is not saved")?);
    let root = state_dir(config).join("inbox");
    let relative = path.strip_prefix(root).context("Invalid saved file")?;
    ensure!(
        relative.components().count() == 2
            && relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "Invalid saved file"
    );
    let handle = open_owned(config, path)?;
    ensure!(
        handle.metadata()?.is_file() && handle.metadata()?.len() == file.size_bytes,
        "Saved file has changed"
    );
    Ok((file, handle))
}

fn open_staged(config: &Path, path: &Path) -> Result<File> {
    let root = outbox_dir(config);
    let relative = path
        .strip_prefix(&root)
        .context("Select a staged file to send")?;
    let parts: Vec<_> = relative.components().collect();
    ensure!(
        parts.len() == 2
            && parts
                .iter()
                .all(|part| matches!(part, Component::Normal(_))),
        "Invalid staged file path"
    );
    let batch = parts[0]
        .as_os_str()
        .to_str()
        .context("Invalid staging folder")?;
    ensure!(valid_id(batch), "Invalid staging folder");
    ensure!(
        valid_filename(parts[1].as_os_str().to_str().context("Invalid filename")?),
        "Invalid filename"
    );
    for directory in [&root, &root.join(batch)] {
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "Invalid staging folder"
        );
        check_owner(config, &fs::symlink_metadata(directory)?)?;
    }
    let file = open_owned(config, path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE_BYTES,
        "Invalid staged file"
    );
    Ok(file)
}

fn bounded_read(config: &Path, path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = open_owned(config, path)?;
    ensure!(
        file.metadata()?.len() <= max,
        "File transfer record is too large"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= max,
        "File transfer record is too large"
    );
    Ok(bytes)
}

#[cfg(unix)]
fn owner_metadata(config: &Path) -> Result<fs::Metadata> {
    #[cfg(unix)]
    {
        Ok(
            unix_storage::directory(config.parent().context("Config directory is missing")?)?
                .metadata()?,
        )
    }
    #[cfg(not(unix))]
    fs::metadata(config.parent().context("Config directory is missing")?).map_err(Into::into)
}

fn check_owner(config: &Path, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == owner_metadata(config)?.uid(),
            "File is not owned by this app's user"
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "File transfer storage must not be writable by other users"
        );
    }
    #[cfg(not(unix))]
    let _ = (config, metadata);
    Ok(())
}

/// Remove only a validated staged source; directory traversal never follows links.
pub fn discard_staged(config: &Path, path: &Path) -> Result<()> {
    open_staged(config, path)?;
    remove_owned(path, false)?;
    if let Some(parent) = path.parent() {
        let _ = remove_owned(parent, true);
    }
    Ok(())
}
