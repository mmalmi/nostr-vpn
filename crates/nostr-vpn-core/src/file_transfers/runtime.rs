use super::*;
use crate::config::{AppConfig, normalize_nostr_pubkey};
use fips_core::{FipsEndpoint, PeerIdentity};
use fips_file_transfer::{TransferFile, TransferSender, TransferStatus};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// Lifetime is tied to the canonical VPN endpoint. Dropping it pauses transfers.
pub struct FileTransferService {
    task: JoinHandle<()>,
}
impl Drop for FileTransferService {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl FileTransferService {
    pub fn start(endpoint: Arc<FipsEndpoint>, config: PathBuf) -> Self {
        let task = tokio::spawn(async move {
            let result: Result<()> = async {
                owned_dir(&config, &state_dir(&config))?;
                for name in ["commands", "inbox", "sources"] {
                    owned_dir(&config, &state_dir(&config).join(name))?;
                }
                let (events, event_rx) = flume::bounded(128);
                let (sender, engine) =
                    fips_file_transfer::start(endpoint, private_store(&config)?, events)
                        .await
                        .map_err(anyhow::Error::msg)?;
                let _engine = EngineGuard(engine);
                sender
                    .set_source_opener(Arc::new(StagedSource(config.clone())))
                    .map_err(anyhow::Error::msg)?;
                run(config.clone(), sender, event_rx).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, "file transfer service stopped");
                let mut state = failed_state("service".into(), error.to_string());
                state.status = "unavailable".into();
                let mut previous = read_state(&config).unwrap_or_default();
                previous.retain(|state| state.id != "service");
                for transfer in &mut previous {
                    if matches!(
                        transfer.status.as_str(),
                        "preparing" | "connecting" | "transferring"
                    ) {
                        transfer.status = "paused".into();
                    }
                }
                previous.push(state);
                if let Ok(bytes) = serde_json::to_vec(&previous) {
                    let _ = write_atomic(&config, &state_dir(&config).join("state.json"), &bytes);
                }
            }
        });
        Self { task }
    }

    /// Mobile runtimes already own a list of cancellable tasks.
    pub fn into_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let _service = self;
            std::future::pending::<()>().await;
        })
    }
}
struct EngineGuard(JoinHandle<()>);
impl Drop for EngineGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct StagedSource(PathBuf);
impl fips_file_transfer::Source for StagedSource {
    fn open(&self, path: &Path) -> fips_file_transfer::Result<File> {
        open_staged(&self.0, path).map_err(|error| error.to_string())
    }
}

#[cfg(windows)]
fn private_store(config: &Path) -> Result<PathBuf> {
    windows_storage::private_store(config)
}

#[cfg(unix)]
fn private_store(config: &Path) -> Result<PathBuf> {
    if rustix::process::geteuid().is_root() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        #[cfg(target_os = "macos")]
        let base = Path::new("/Library/Application Support/nvpn/file-transfers");
        #[cfg(not(target_os = "macos"))]
        let base = Path::new("/var/lib/nvpn/file-transfers");
        let absolute = std::path::absolute(config)?;
        let root = base.join(format!(
            "{:x}",
            Sha256::digest(absolute.as_os_str().as_bytes())
        ));
        // Validate protected ancestors before creating each descendant. No
        // user-writable path may redirect privileged transfer journals/parts.
        let mut ancestor = PathBuf::from("/");
        for part in root.components().skip(1) {
            ancestor.push(part);
            match fs::symlink_metadata(&ancestor) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() && ancestor == Path::new("/var") {
                        ancestor = ancestor.canonicalize()?;
                    }
                    let metadata = fs::symlink_metadata(&ancestor)?;
                    ensure!(
                        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                        "File transfer storage has an untrusted ancestor"
                    );
                    #[cfg(target_os = "macos")]
                    crate::macos_file_io::reject_write_acl(&unix_storage::directory(&ancestor)?)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&ancestor)?;
                    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
                    #[cfg(target_os = "macos")]
                    crate::macos_file_io::clear_inherited_acl(&unix_storage::directory(
                        &ancestor,
                    )?)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        return Ok(ancestor);
    }
    let directory = state_dir(config).join("engine");
    owned_dir(config, &directory)?;
    Ok(directory)
}

async fn run(
    config: PathBuf,
    sender: TransferSender,
    events: flume::Receiver<fips_file_transfer::TransferEvent>,
) -> Result<()> {
    let mut timer = tokio::time::interval(Duration::from_millis(500));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut aliases = HashMap::new();
    let mut allowed = HashSet::new();
    let mut revision = None;
    let mut failures = Vec::new();
    let mut action_errors = HashMap::new();
    let mut last_state = Vec::new();
    // Migrate old received rows once; protocol receipt expiry does not remove
    // the separately paged app inbox or its saved files.
    for state in read_state(&config)?
        .into_iter()
        .filter(|state| !state.is_sender && state.status == "completed")
    {
        if inbox::read(&config, &state.id)?.is_none() {
            inbox::save(&config, &state)?;
        }
    }
    let mut received = inbox::page(&config, None)?.transfers;
    let mut archived: HashMap<String, TransferState> = HashMap::new();
    let mut preparing: Option<Preparing> = None;
    let mut registering: HashMap<String, Registration> = HashMap::new();
    let mut stopping: HashMap<PathBuf, PendingStop> = HashMap::new();
    let active = sender
        .snapshots()
        .into_iter()
        .filter(|state| !state.status.terminal())
        .map(|state| state.id)
        .collect::<HashSet<_>>();
    let mut pending_cleanup = fs::read_dir(state_dir(&config).join("sources"))?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|id| id.to_str())
                .map(str::to_owned)
        })
        .filter(|id| {
            valid_id(id)
                && !active.contains(id)
                && !state_dir(&config)
                    .join("commands")
                    .join(format!("{id}.json"))
                    .exists()
        })
        .collect::<HashSet<_>>();
    loop {
        let event = tokio::select! {
            _ = timer.tick() => None,
            result = events.recv_async() => { match result {
                Ok(event) => Some(event),
                Err(_) => return Err(anyhow::anyhow!("File transfer connection stopped")),
            } },
        };
        if let Some(event) = event {
            match event {
                fips_file_transfer::TransferEvent::Failed {
                    transfer_id, error, ..
                } => {
                    if sender
                        .snapshots()
                        .iter()
                        .any(|state| state.id == transfer_id)
                    {
                        action_errors.insert(transfer_id, error);
                    } else {
                        if let Some(registration) = registering.remove(&transfer_id) {
                            remove_owned(&registration.command_path, false)?;
                        }
                        pending_cleanup.insert(transfer_id.clone());
                        failures.retain(|state: &TransferState| state.id != transfer_id);
                        failures.push(failed_state(transfer_id, error));
                        if failures.len() > 32 {
                            failures.remove(0);
                        }
                    }
                }
                fips_file_transfer::TransferEvent::Progress { transfer_id, .. }
                | fips_file_transfer::TransferEvent::Completed { transfer_id, .. } => {
                    action_errors.remove(&transfer_id);
                }
                _ => {}
            }
            // Drain progress notifications cheaply; file-system
            // polling and UI snapshots run at most twice per second.
            continue;
        }
        let modified = fs::metadata(&config).and_then(|m| m.modified()).ok();
        if revision != modified || revision.is_none() {
            match AppConfig::load(&config) {
                Ok(app) => {
                    aliases = authorized_peers(&app)?;
                    allowed = aliases.keys().cloned().collect();
                    revision = modified;
                }
                Err(error) => {
                    allowed.clear();
                    tracing::warn!(%error, "file transfer membership unavailable");
                }
            }
            sender
                .set_allowed_peers(allowed.iter().filter_map(|hex| peer(hex).ok()).collect())
                .map_err(anyhow::Error::msg)?;
            for snapshot in sender.snapshots() {
                let local_save = !snapshot.is_sender && !snapshot.local_paths.is_empty();
                if !local_save && !allowed.contains(&snapshot.peer) && !snapshot.status.terminal() {
                    let _ = sender.restrict_offer(&snapshot.id, Vec::new());
                    let _ = sender.cancel(&snapshot.id);
                }
            }
        }
        for snapshot in sender.snapshots() {
            if let Some(registration) = registering.remove(&snapshot.id) {
                remove_owned(&registration.command_path, false)?;
            }
        }
        if preparing
            .as_ref()
            .is_some_and(|job| !allowed.contains(&job.peer))
        {
            let mut job = preparing.take().expect("checked preparation");
            job.cancelled.store(true, Ordering::Relaxed);
            job.state.status = "cancelled".into();
            job.state.error = Some("Device is no longer authorized".into());
            remove_owned(&job.command_path, false)?;
            pending_cleanup.insert(job.state.id.clone());
            failures.push(job.state.clone());
        }
        let mut commands = command_paths(&config)?
            .into_iter()
            .map(|path| {
                let record = read_command(&config, &path);
                (path, record)
            })
            .collect::<Vec<_>>();
        // Offline cancellation must win over a queued send on reconnect,
        // regardless of the random command IDs' lexical order.
        commands.sort_by_key(|(_, record)| {
            !record.as_ref().is_ok_and(|record| {
                matches!(
                    record.command,
                    FileCommand::Cancel { .. } | FileCommand::Decline { .. }
                )
            })
        });
        let mut cancelled_queued = HashSet::new();
        for (path, record) in commands {
            if record
                .as_ref()
                .is_ok_and(|record| cancelled_queued.contains(&record.id))
            {
                continue;
            }
            let result = match record {
                Ok(record) if valid_id(&record.id) => {
                    let id = record.id.clone();
                    if let FileCommand::Send { npub, paths } = &record.command {
                        if sender.snapshots().iter().any(|snapshot| snapshot.id == id) {
                            registering.remove(&id);
                            remove_owned(&path, false)?;
                            continue;
                        }
                        if preparing.is_some() || registering.contains_key(&id) {
                            continue;
                        }
                        match Preparing::start(
                            &config,
                            &allowed,
                            &aliases,
                            id.clone(),
                            npub,
                            paths.clone(),
                            path.clone(),
                        ) {
                            Ok(job) => {
                                preparing = Some(job);
                                continue;
                            }
                            Err(error) => {
                                for source in paths {
                                    let _ = discard_staged(&config, Path::new(source));
                                }
                                failures.push(failed_state(id, error.to_string()));
                                remove_owned(&path, false)?;
                                continue;
                            }
                        }
                    }
                    if let FileCommand::Cancel { id: target } = &record.command {
                        if preparing
                            .as_ref()
                            .is_some_and(|job| job.state.id == *target)
                        {
                            let mut job = preparing.take().expect("checked preparation");
                            job.cancelled.store(true, Ordering::Relaxed);
                            job.state.status = "cancelled".into();
                            remove_owned(&job.command_path, false)?;
                            pending_cleanup.insert(target.clone());
                            cancelled_queued.insert(target.clone());
                            failures.push(job.state.clone());
                            remove_owned(&path, false)?;
                            continue;
                        }
                    }
                    if let FileCommand::Cancel { id: target } = &record.command {
                        if !registering.contains_key(target)
                            && !sender
                                .snapshots()
                                .iter()
                                .any(|snapshot| snapshot.id == *target)
                        {
                            if let Some(state) = cancel_queued_send(&config, target)? {
                                cancelled_queued.insert(target.clone());
                                pending_cleanup.insert(target.clone());
                                failures.push(state);
                                remove_owned(&path, false)?;
                                continue;
                            }
                        }
                    }
                    let stop_target = match &record.command {
                        FileCommand::Cancel { id } | FileCommand::Decline { id } => Some(id),
                        _ => None,
                    };
                    if let Some(target) = stop_target {
                        let snapshot = sender
                            .snapshots()
                            .into_iter()
                            .find(|state| state.id == *target);
                        if snapshot
                            .as_ref()
                            .is_some_and(|state| state.status.terminal())
                            || (snapshot.is_none() && !registering.contains_key(target))
                        {
                            stopping.remove(&path);
                            remove_owned(&path, false)?;
                            continue;
                        }
                        if stopping
                            .get(&path)
                            .is_some_and(|attempt| Instant::now() < attempt.retry_at)
                        {
                            continue;
                        }
                    }
                    let retain_until_stopped = stop_target.is_some();
                    let result = execute(&config, &sender, &allowed, record);
                    if result.is_ok() && retain_until_stopped {
                        // Enqueueing into the engine is not durable acknowledgement.
                        // Keep this intent across VPN shutdown until a terminal
                        // snapshot proves the transfer can no longer restart.
                        // Async storage failures may leave no acknowledgement;
                        // retry idempotently with bounded exponential backoff.
                        let attempts = stopping
                            .get(&path)
                            .map_or(1, |attempt| (attempt.attempts + 1).min(6));
                        stopping.insert(
                            path.clone(),
                            PendingStop {
                                attempts,
                                retry_at: Instant::now()
                                    + Duration::from_secs((1_u64 << attempts).min(60)),
                            },
                        );
                        continue;
                    }
                    if let Err(error) = &result {
                        failures.retain(|state: &TransferState| state.id != id);
                        failures.push(TransferState {
                            id,
                            peer_npub: String::new(),
                            peer_name: String::new(),
                            is_sender: true,
                            files: Vec::new(),
                            status: "failed".into(),
                            transferred_bytes: 0,
                            total_bytes: 0,
                            error: Some(error.to_string()),
                        });
                        if failures.len() > 32 {
                            failures.remove(0);
                        }
                    }
                    result
                }
                _ => Err(anyhow::anyhow!("Invalid file command")),
            };
            if let Err(error) = result {
                tracing::warn!(%error, "file transfer action failed");
            }
            // This exact queue entry is consumed once; transfer IDs are persistent.
            remove_owned(&path, false)?;
        }
        if preparing
            .as_ref()
            .is_some_and(|job| job.task.as_ref().is_some_and(JoinHandle::is_finished))
        {
            let mut job = preparing.take().expect("checked preparation");
            let result = job
                .task
                .take()
                .expect("preparation task")
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
                .and_then(|files| finish_offer(&sender, &allowed, &job.state.id, &job.peer, files));
            if let Err(error) = result {
                job.state.status = "failed".into();
                job.state.error = Some(error.to_string());
                pending_cleanup.insert(job.state.id.clone());
                failures.push(job.state.clone());
                remove_owned(&job.command_path, false)?;
            } else {
                job.state.status = "connecting".into();
                registering.insert(
                    job.state.id.clone(),
                    Registration {
                        command_path: job.command_path.clone(),
                        state: job.state.clone(),
                    },
                );
            }
        }
        let mut states = sender
            .snapshots()
            .into_iter()
            .map(|snapshot| {
                let status = match snapshot.status {
                    TransferStatus::Offered => "offered",
                    TransferStatus::Connecting => "connecting",
                    TransferStatus::Transferring => "transferring",
                    TransferStatus::Paused => "paused",
                    TransferStatus::Completed => "completed",
                    TransferStatus::Declined => "declined",
                    TransferStatus::Cancelled => "cancelled",
                    TransferStatus::Failed => "failed",
                };
                let error = snapshot
                    .error
                    .or_else(|| action_errors.get(&snapshot.id).cloned());
                TransferState {
                    id: snapshot.id,
                    peer_npub: npub(&snapshot.peer).unwrap_or_default(),
                    peer_name: aliases.get(&snapshot.peer).cloned().unwrap_or_default(),
                    is_sender: snapshot.is_sender,
                    files: snapshot
                        .files
                        .into_iter()
                        .enumerate()
                        .map(|(index, file)| FileState {
                            name: file.filename,
                            size_bytes: file.size_bytes,
                            local_path: snapshot.local_paths.get(index).cloned(),
                        })
                        .collect(),
                    status: status.into(),
                    transferred_bytes: snapshot.transferred_bytes,
                    total_bytes: snapshot.total_bytes,
                    error,
                }
            })
            .collect::<Vec<_>>();
        for state in &states {
            if state.is_sender
                && matches!(
                    state.status.as_str(),
                    "completed" | "cancelled" | "declined" | "failed"
                )
            {
                pending_cleanup.insert(state.id.clone());
            }
        }
        let mut inbox_changed = false;
        for state in states
            .iter()
            .filter(|state| !state.is_sender && state.status == "completed")
        {
            if archived.get(&state.id) != Some(state) {
                inbox::save(&config, state)?;
                archived.insert(state.id.clone(), state.clone());
                inbox_changed = true;
            }
        }
        if inbox_changed {
            received = inbox::page(&config, None)?.transfers;
        }
        let present = states
            .iter()
            .map(|state| state.id.clone())
            .collect::<HashSet<_>>();
        for id in &present {
            if let Some(registration) = registering.remove(id) {
                remove_owned(&registration.command_path, false)?;
            }
        }
        action_errors.retain(|id, _| present.contains(id));
        archived.retain(|id, _| present.contains(id));
        // Completed records are durable in the inbox; bound the live projection.
        states.retain(|state| state.is_sender || state.status != "completed");
        let live = states
            .iter()
            .map(|state| state.id.clone())
            .collect::<HashSet<_>>();
        states.extend(
            received
                .iter()
                .filter(|state| !live.contains(&state.id))
                .cloned(),
        );
        states.extend(failures.iter().cloned());
        states.extend(
            registering
                .values()
                .map(|registration| registration.state.clone()),
        );
        if let Some(job) = &preparing {
            let mut state = job.state.clone();
            state.transferred_bytes = job.progress.load(Ordering::Relaxed);
            states.push(state);
        }
        if failures.len() > 32 {
            failures.drain(..failures.len() - 32);
        }
        pending_cleanup.retain(|id| !cleanup_sources(&config, id));
        bound_states(&mut states);
        if states != last_state {
            write_atomic(
                &config,
                &state_dir(&config).join("state.json"),
                &serde_json::to_vec(&states)?,
            )?;
            last_state = states;
        }
    }
}

fn cancel_queued_send(config: &Path, id: &str) -> Result<Option<TransferState>> {
    ensure!(valid_id(id), "Invalid transfer ID");
    let path = state_dir(config)
        .join("commands")
        .join(format!("{id}.json"));
    if !path.try_exists()? {
        return Ok(None);
    }
    let command = read_command(config, &path)?;
    let FileCommand::Send { npub, paths } = command.command else {
        return Ok(None);
    };
    // Cancellation still works if the user removed a staged source while offline.
    let mut state = queued_state(config, id, &npub, &paths)
        .unwrap_or_else(|_| failed_state(id.into(), String::new()));
    // Retain a cleanup receipt until all source handles close, including Windows.
    write_atomic(
        config,
        &state_dir(config).join("sources").join(format!("{id}.json")),
        &serde_json::to_vec(&paths)?,
    )?;
    remove_owned(&path, false)?;
    state.status = "cancelled".into();
    state.error = None;
    Ok(Some(state))
}

fn execute(
    config: &Path,
    sender: &TransferSender,
    allowed: &HashSet<String>,
    record: QueuedCommand,
) -> Result<()> {
    match record.command {
        FileCommand::Send { .. } => anyhow::bail!("File preparation has not finished"),
        FileCommand::Accept { id } | FileCommand::Resume { id } => {
            let snapshot = sender
                .snapshots()
                .into_iter()
                .find(|snapshot| snapshot.id == id)
                .context("File transfer not found")?;
            let local_save = !snapshot.is_sender && !snapshot.local_paths.is_empty();
            ensure!(
                local_save || allowed.contains(&snapshot.peer),
                "Device is no longer authorized"
            );
            if snapshot.is_sender {
                return sender.resume_offer(&id).map_err(anyhow::Error::msg);
            }
            #[cfg(unix)]
            let destination = Arc::new(unix_destination::InboxDestination::new(config));
            #[cfg(windows)]
            let destination = windows_storage::destination(config);
            sender
                .resume(&id, destination)
                .map_err(anyhow::Error::msg)?;
        }
        FileCommand::Decline { id } => sender.decline_incoming(&id).map_err(anyhow::Error::msg)?,
        FileCommand::Cancel { id } => sender.cancel(&id).map_err(anyhow::Error::msg)?,
    }
    Ok(())
}

struct Registration {
    command_path: PathBuf,
    state: TransferState,
}

struct PendingStop {
    attempts: u32,
    retry_at: Instant,
}

struct Preparing {
    task: Option<JoinHandle<Result<Vec<TransferFile>>>>,
    cancelled: Arc<AtomicBool>,
    progress: Arc<AtomicU64>,
    command_path: PathBuf,
    peer: String,
    state: TransferState,
}

impl Preparing {
    fn start(
        config: &Path,
        allowed: &HashSet<String>,
        aliases: &HashMap<String, String>,
        id: String,
        recipient: &str,
        paths: Vec<String>,
        command_path: PathBuf,
    ) -> Result<Self> {
        let hex = normalize_nostr_pubkey(recipient)?;
        ensure!(
            allowed.contains(&hex),
            "This device is not in an enabled private network"
        );
        ensure!(
            !paths.is_empty() && paths.len() <= 32,
            "Choose between 1 and 32 files"
        );
        let mut files = Vec::new();
        for path in &paths {
            let path = Path::new(path);
            files.push(FileState {
                name: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("Invalid filename")?
                    .to_owned(),
                size_bytes: open_staged(config, path)?.metadata()?.len(),
                local_path: None,
            });
        }
        let total_bytes = files.iter().map(|file| file.size_bytes).sum();
        write_atomic(
            config,
            &state_dir(config).join("sources").join(format!("{id}.json")),
            &serde_json::to_vec(&paths)?,
        )?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = cancelled.clone();
        let progress = Arc::new(AtomicU64::new(0));
        let prepared = progress.clone();
        let config = config.to_owned();
        let task =
            tokio::task::spawn_blocking(move || prepare(&config, paths, &cancellation, &prepared));
        Ok(Self {
            task: Some(task),
            cancelled,
            progress,
            command_path,
            peer: hex.clone(),
            state: TransferState {
                id,
                peer_npub: npub(&hex)?,
                peer_name: aliases.get(&hex).cloned().unwrap_or_default(),
                is_sender: true,
                files,
                status: "preparing".into(),
                transferred_bytes: 0,
                total_bytes,
                error: None,
            },
        })
    }
}
impl Drop for Preparing {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

fn finish_offer(
    sender: &TransferSender,
    allowed: &HashSet<String>,
    id: &str,
    recipient: &str,
    files: Vec<TransferFile>,
) -> Result<()> {
    ensure!(
        allowed.contains(recipient),
        "Device is no longer authorized"
    );
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    sender
        .send_offer(id.to_owned(), token, peer(recipient)?, files)
        .map_err(anyhow::Error::msg)
}

fn failed_state(id: String, error: String) -> TransferState {
    TransferState {
        id,
        peer_npub: String::new(),
        peer_name: String::new(),
        is_sender: true,
        files: Vec::new(),
        status: "failed".into(),
        transferred_bytes: 0,
        total_bytes: 0,
        error: Some(error),
    }
}

fn prepare(
    config: &Path,
    paths: Vec<String>,
    cancelled: &AtomicBool,
    progress: &AtomicU64,
) -> Result<Vec<TransferFile>> {
    ensure!(
        !paths.is_empty() && paths.len() <= 32,
        "Choose between 1 and 32 files"
    );
    paths
        .into_iter()
        .map(|path| {
            let path = PathBuf::from(path);
            let mut file = open_staged(config, &path)?;
            let size_bytes = file.metadata()?.len();
            let mut hash = Sha256::new();
            let mut count = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                ensure!(
                    !cancelled.load(Ordering::Relaxed),
                    "File transfer cancelled"
                );
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                count += length as u64;
                ensure!(count <= size_bytes, "Selected file changed");
                hash.update(&buffer[..length]);
                progress.fetch_add(length as u64, Ordering::Relaxed);
            }
            ensure!(count == size_bytes, "Selected file changed");
            Ok(TransferFile {
                filename: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("Invalid filename")?
                    .into(),
                size_bytes,
                sha256: format!("{:x}", hash.finalize()),
                path,
            })
        })
        .collect()
}

fn cleanup_sources(config: &Path, id: &str) -> bool {
    if !valid_id(id) {
        return true;
    }
    let record = state_dir(config).join("sources").join(format!("{id}.json"));
    let Ok(bytes) = bounded_read(config, &record, MAX_COMMAND_BYTES) else {
        return fs::symlink_metadata(&record)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    };
    let Ok(paths) = serde_json::from_slice::<Vec<PathBuf>>(&bytes) else {
        return false;
    };
    let mut complete = true;
    for path in paths.into_iter().take(32) {
        if fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        if open_staged(config, &path).is_ok() {
            if remove_owned(&path, false).is_err() {
                complete = false;
                continue;
            }
            if let Some(parent) = path.parent() {
                let _ = remove_owned(parent, true);
            }
        } else {
            complete = false;
        }
    }
    // Windows readers may still hold a cancelled source. Keep the journal
    // until a later pass can remove every owned source after those handles close.
    complete && remove_owned(&record, false).is_ok()
}

fn npub(hex: &str) -> Result<String> {
    Ok(PublicKey::from_hex(hex)?.to_bech32()?)
}
fn peer(hex: &str) -> Result<PeerIdentity> {
    PeerIdentity::from_npub(&npub(hex)?).map_err(Into::into)
}
