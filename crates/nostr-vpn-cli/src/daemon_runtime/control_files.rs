pub(crate) fn daemon_pid_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.pid")
}

#[cfg(unix)]
pub(crate) fn production_unix_daemon_instance_lock_file_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    let runtime_dir = Path::new("/run/nvpn");
    #[cfg(not(target_os = "linux"))]
    let runtime_dir = Path::new("/var/run/nvpn");

    runtime_dir.join("to.nostrvpn.nvpn.daemon.instance.lock")
}

pub(crate) fn validate_daemon_instance_id(value: &str) -> Result<&str> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        });
    if !valid {
        return Err(anyhow!(
            "daemon instance must match [a-z0-9][a-z0-9_-]{{0,63}}"
        ));
    }
    Ok(value)
}

pub(crate) fn daemon_instance_lock_file_path_for_instance(
    _config_path: &Path,
    daemon_instance: Option<&str>,
) -> Result<PathBuf> {
    let daemon_instance = daemon_instance.map(validate_daemon_instance_id).transpose()?;

    #[cfg(test)]
    {
        let base = std::env::temp_dir()
            .join(format!(
                "to.nostrvpn.nvpn.daemon-instance-test-{}",
                std::process::id()
            ));
        let runtime_dir = daemon_instance.map_or(base.clone(), |id| base.join(id));
        Ok(runtime_dir.join("daemon.instance.lock"))
    }

    #[cfg(all(not(test), unix))]
    {
        if let Some(id) = daemon_instance {
            #[cfg(target_os = "linux")]
            let runtime_dir = PathBuf::from(format!("/run/nvpn-{id}"));
            #[cfg(not(target_os = "linux"))]
            let runtime_dir = PathBuf::from(format!("/var/run/nvpn-{id}"));
            return Ok(runtime_dir.join("to.nostrvpn.nvpn.daemon.instance.lock"));
        }
        Ok(production_unix_daemon_instance_lock_file_path())
    }

    #[cfg(all(not(test), windows))]
    {
        if daemon_instance.is_some() {
            return Err(anyhow!(
                "explicit daemon instances are supported only by Unix system services"
            ));
        }
        let root = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "PROGRAMDATA is unavailable; refusing to use a per-user daemon instance lock"
                )
            })?;
        Ok(root
            .join("nVPN")
            .join("to.nostrvpn.nvpn.daemon.instance.lock"))
    }

    #[cfg(all(not(test), not(any(unix, windows))))]
    {
        Err(anyhow!(
            "daemon instance locking is unsupported on this platform"
        ))
    }
}

#[cfg(test)]
pub(crate) fn daemon_instance_lock_file_path(config_path: &Path) -> Result<PathBuf> {
    daemon_instance_lock_file_path_for_instance(config_path, None)
}

pub(crate) struct DaemonInstanceLock {
    _file: fs::File,
}

pub(crate) fn acquire_daemon_instance_lock(config_path: &Path) -> Result<DaemonInstanceLock> {
    acquire_daemon_instance_lock_for_daemon(config_path, None)
}

pub(crate) fn acquire_daemon_instance_lock_for_daemon(
    config_path: &Path,
    daemon_instance: Option<&str>,
) -> Result<DaemonInstanceLock> {
    let lock_path = daemon_instance_lock_file_path_for_instance(config_path, daemon_instance)?;

    #[cfg(unix)]
    {
        #[cfg(test)]
        let expected_uid = unsafe { libc::geteuid() };
        #[cfg(not(test))]
        let expected_uid = daemon_instance.map_or(0, |_| unsafe { libc::geteuid() });
        if daemon_instance.is_some() && !lock_path.parent().is_some_and(Path::is_dir) {
            return Err(anyhow!(
                "isolated daemon runtime directory is unavailable: {}",
                lock_path.parent().map_or_else(
                    || Path::new("<missing>").display().to_string(),
                    |path| path.display().to_string()
                )
            ));
        }
        return acquire_unix_daemon_instance_lock_at(&lock_path, expected_uid);
    }

    #[cfg(windows)]
    {
        return acquire_windows_daemon_instance_lock_at(&lock_path);
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "daemon instance locking is unsupported on this platform"
    ))
}

#[cfg(unix)]
pub(crate) fn acquire_unix_daemon_instance_lock_at(
    lock_path: &Path,
    expected_uid: u32,
) -> Result<DaemonInstanceLock> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let parent = lock_path.parent().ok_or_else(|| {
        anyhow!(
            "daemon instance lock has no runtime directory: {}",
            lock_path.display()
        )
    })?;
    match fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to create protected {}", parent.display()));
                }
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", parent.display()));
        }
    }
    validate_unix_daemon_lock_parent(parent, expected_uid)?;

    match fs::symlink_metadata(lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(anyhow!(
                "refusing daemon instance lock symlink {}",
                lock_path.display()
            ));
        }
        Ok(metadata) => validate_unix_daemon_lock_file(lock_path, &metadata, expected_uid)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!(
                "daemon already running or protected instance lock {} is unavailable: {}",
                lock_path.display(),
                error
            ));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", lock_path.display()));
        }
    }

    let mut options = runtime_open_options_no_follow();
    options.create(true).read(true).write(true).mode(0o600);
    let file = options.open(lock_path).map_err(|error| {
        anyhow!(
            "daemon already running or protected instance lock {} is unavailable: {}",
            lock_path.display(),
            error
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open lock {}", lock_path.display()))?;
    validate_unix_daemon_lock_file(lock_path, &metadata, expected_uid)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!(
                "failed to protect daemon instance lock {}",
                lock_path.display()
            )
        })?;

    use std::os::fd::AsRawFd as _;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(anyhow!(
            "another nvpn daemon is already running: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(DaemonInstanceLock { _file: file })
}

#[cfg(unix)]
fn validate_unix_daemon_lock_parent(parent: &Path, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect {}", parent.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || mode & 0o022 != 0
    {
        return Err(anyhow!(
            "daemon instance lock runtime directory {} is not protected \
             (expected directory owner uid {expected_uid} without group/other write; \
             found uid {} mode {:03o})",
            parent.display(),
            metadata.uid(),
            mode
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_daemon_lock_file(
    lock_path: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || mode & 0o077 != 0
    {
        return Err(anyhow!(
            "daemon instance lock {} is not protected \
             (expected regular single-link file owner uid {expected_uid} without group/other access; \
             found uid {} mode {:03o} links {})",
            lock_path.display(),
            metadata.uid(),
            mode,
            metadata.nlink()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn acquire_windows_daemon_instance_lock_at(lock_path: &Path) -> Result<DaemonInstanceLock> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut options = runtime_open_options_no_follow();
    options.create(true).read(true).write(true);

    use std::os::windows::fs::OpenOptionsExt;
    // A zero share mode makes opening the same lock file fail until the
    // first daemon drops its handle.
    options.share_mode(0);

    let file = options.open(&lock_path).map_err(|error| {
        anyhow!(
            "daemon already running or instance lock {} is unavailable: {}",
            lock_path.display(),
            error
        )
    })?;

    Ok(DaemonInstanceLock { _file: file })
}

pub(crate) fn visible_daemon_state_for_status(
    running: bool,
    state: Option<&DaemonRuntimeState>,
) -> Option<DaemonRuntimeState> {
    if running { state.cloned() } else { None }
}

pub(crate) fn daemon_log_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.log")
}

fn runtime_open_options_no_follow() -> OpenOptions {
    #[cfg(unix)]
    let mut options = OpenOptions::new();
    #[cfg(not(unix))]
    let options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

pub(crate) fn redirect_stdio_to_daemon_log(config_path: &Path) -> Result<()> {
    let log_path = daemon_log_file_path(config_path);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log_file = open_daemon_log_file(&log_path)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = log_file.as_raw_fd();
        unsafe {
            if libc::dup2(fd, libc::STDOUT_FILENO) < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to redirect stdout to daemon log");
            }
            if libc::dup2(fd, libc::STDERR_FILENO) < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to redirect stderr to daemon log");
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows Service Manager doesn't allocate a console for services, so
        // stdout/stderr go nowhere by default. Point both at the daemon log
        // via SetStdHandle. Anything tracing-subscriber and eprintln! emit
        // ends up in the same file as macOS/Linux daemons.
        use std::os::windows::io::AsRawHandle;
        let handle = log_file.as_raw_handle();
        unsafe {
            // STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
            // SetStdHandle from kernel32; signature: BOOL SetStdHandle(DWORD nStdHandle, HANDLE hHandle)
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn SetStdHandle(nStdHandle: u32, hHandle: *mut std::ffi::c_void) -> i32;
            }
            const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
            const STD_ERROR_HANDLE: u32 = (-12i32) as u32;
            if SetStdHandle(STD_OUTPUT_HANDLE, handle as *mut _) == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to redirect stdout to daemon log");
            }
            if SetStdHandle(STD_ERROR_HANDLE, handle as *mut _) == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to redirect stderr to daemon log");
            }
        }
        // Keep the file alive for the lifetime of the daemon process — the
        // OS holds the handle, but dropping our File would close it.
        std::mem::forget(log_file);
    }

    Ok(())
}

pub(crate) fn compact_daemon_log_if_needed(config_path: &Path) -> Result<bool> {
    compact_log_file_if_needed(
        &daemon_log_file_path(config_path),
        DAEMON_LOG_MAX_BYTES,
        DAEMON_LOG_RETAIN_BYTES,
    )
}

pub(crate) fn daemon_log_compact_check_due(last_checked: &mut Instant) -> bool {
    if last_checked.elapsed() < Duration::from_secs(DAEMON_LOG_COMPACT_CHECK_SECS) {
        return false;
    }
    *last_checked = Instant::now();
    true
}

pub(crate) fn compact_log_file_if_needed(
    path: &Path,
    max_bytes: u64,
    retain_bytes: u64,
) -> Result<bool> {
    if max_bytes == 0 || retain_bytes == 0 || retain_bytes >= max_bytes {
        return Ok(false);
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(anyhow!(
            "refusing to compact non-regular daemon log {}",
            path.display()
        ));
    }
    let mut read_options = runtime_open_options_no_follow();
    let mut file = read_options
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let original_len = validate_daemon_runtime_file(&file, path)?.len();
    if original_len <= max_bytes {
        return Ok(false);
    }

    let retain_start = original_len.saturating_sub(retain_bytes);
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(retain_start))
        .with_context(|| format!("failed to seek {}", path.display()))?;
    let mut retained = Vec::with_capacity(retain_bytes as usize);
    std::io::Read::read_to_end(
        &mut std::io::Read::take(&mut file, retain_bytes),
        &mut retained,
    )
        .with_context(|| format!("failed to read {}", path.display()))?;
    if let Some(newline) = retained.iter().position(|byte| *byte == b'\n') {
        retained.drain(..=newline);
    }

    let header = format!(
        "[nvpn] daemon log compacted at {}; retained {} bytes from {} bytes\n",
        unix_timestamp(),
        retained.len(),
        original_len
    );
    // Keep the validated handle: the config owner can replace the path while
    // the elevated daemon is retaining the old log tail.
    file.set_len(0)
        .with_context(|| format!("failed to compact {}", path.display()))?;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0))
        .with_context(|| format!("failed to rewind {}", path.display()))?;
    std::io::Write::write_all(&mut file, header.as_bytes())
        .with_context(|| format!("failed to write compaction header to {}", path.display()))?;
    std::io::Write::write_all(&mut file, &retained)
        .with_context(|| format!("failed to write retained log tail to {}", path.display()))?;
    std::io::Write::flush(&mut file)
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(true)
}

pub(crate) fn daemon_state_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.state.json")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn daemon_network_cleanup_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    #[cfg(target_os = "linux")]
    return parent
        .join(".nvpn-network-cleanup")
        .join("daemon.cleanup.json");

    #[cfg(not(target_os = "linux"))]
    parent.join("daemon.cleanup.json")
}

pub(crate) fn daemon_control_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.control")
}

pub(crate) fn daemon_control_ready_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.control.ready")
}

pub(crate) fn daemon_control_result_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.control.result.json")
}

pub(crate) fn daemon_staged_config_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("config.pending.toml")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DaemonControlResult {
    request: String,
    ok: bool,
    error: Option<String>,
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn ensure_no_other_daemon_processes_for_config(
    config_path: &Path,
    current_pid: u32,
) -> Result<()> {
    let daemon_pids = daemon_candidate_pids(config_path, current_pid)?;

    if let Some(existing_pid) = daemon_pids.first().copied() {
        return Err(anyhow!("daemon already running with pid {}", existing_pid));
    }

    Ok(())
}

pub(crate) fn write_daemon_control_request(
    config_path: &Path,
    request: DaemonControlRequest,
) -> Result<()> {
    let control_file = daemon_control_file_path(config_path);
    if let Some(parent) = control_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_runtime_file_atomically(&control_file, format!("{}\n", request.as_str()).as_bytes()).with_context(|| {
        format!(
            "failed to write daemon control request {}",
            control_file.display()
        )
    })?;
    if let Err(error) = persist_desired_daemon_vpn_enabled_for_request(config_path, request) {
        eprintln!(
            "daemon: failed to persist desired VPN state in {}: {}",
            config_path.display(),
            error
        );
    }
    project_daemon_vpn_enabled_request(config_path, request);
    Ok(())
}

pub(crate) fn persist_desired_daemon_vpn_enabled_for_request(
    config_path: &Path,
    request: DaemonControlRequest,
) -> Result<Option<bool>> {
    let vpn_enabled = match request {
        DaemonControlRequest::Pause => false,
        DaemonControlRequest::Resume => true,
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => return Ok(None),
    };

    persist_desired_daemon_vpn_enabled(config_path, vpn_enabled)?;
    Ok(Some(vpn_enabled))
}

pub(crate) fn persist_desired_daemon_vpn_enabled(
    config_path: &Path,
    vpn_enabled: bool,
) -> Result<bool> {
    let mut app = load_or_default_config(config_path)?;
    persist_desired_daemon_vpn_enabled_in_config(&mut app, config_path, vpn_enabled)
}

pub(crate) fn persist_desired_daemon_vpn_enabled_in_config(
    app: &mut AppConfig,
    config_path: &Path,
    vpn_enabled: bool,
) -> Result<bool> {
    if app.autoconnect == vpn_enabled {
        return Ok(false);
    }

    app.autoconnect = vpn_enabled;
    app.ensure_defaults();
    maybe_autoconfigure_node(app);
    app.save(config_path)?;
    Ok(true)
}

fn project_daemon_vpn_enabled_request(config_path: &Path, request: DaemonControlRequest) {
    let Some(vpn_enabled) = (match request {
        DaemonControlRequest::Pause => Some(false),
        DaemonControlRequest::Resume => Some(true),
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => None,
    }) else {
        return;
    };

    let state_file = daemon_state_file_path(config_path);
    let Ok(Some(mut state)) = read_daemon_state(&state_file) else {
        return;
    };

    state.updated_at = unix_timestamp();
    state.vpn_enabled = vpn_enabled;
    state.vpn_status = match (vpn_enabled, state.vpn_active) {
        (true, true) if state.vpn_status == "Turning VPN off" || state.vpn_status == "Paused" => {
            "VPN on".to_string()
        }
        (true, true) => state.vpn_status,
        (true, false) => "Turning VPN on".to_string(),
        (false, true) => "Turning VPN off".to_string(),
        (false, false) => "Paused".to_string(),
    };

    if let Err(error) = write_daemon_state(&state_file, &state) {
        eprintln!(
            "daemon: failed to project VPN control state {}: {}",
            state_file.display(),
            error
        );
    }
}

pub(crate) fn clear_daemon_control_result(config_path: &Path) {
    let _ = fs::remove_file(daemon_control_result_file_path(config_path));
}

pub(crate) fn clear_daemon_control_ready(config_path: &Path) {
    let _ = fs::remove_file(daemon_control_ready_file_path(config_path));
}

pub(crate) fn write_daemon_control_ready(config_path: &Path, pid: u32) -> Result<()> {
    let ready_file = daemon_control_ready_file_path(config_path);
    if let Some(parent) = ready_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_runtime_file_atomically(&ready_file, format!("{pid}\n").as_bytes())
        .with_context(|| format!("failed to write {}", ready_file.display()))?;
    Ok(())
}

pub(crate) fn daemon_control_ready_for_pid(config_path: &Path, pid: u32) -> bool {
    fs::read_to_string(daemon_control_ready_file_path(config_path))
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        == Some(pid)
}

pub(crate) fn wait_for_daemon_control_ready(
    config_path: &Path,
    pid: u32,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if daemon_control_ready_for_pid(config_path, pid) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }

    Err(anyhow!(
        "daemon process {pid} did not become ready for control requests within {}s",
        timeout.as_secs()
    ))
}

pub(crate) fn write_daemon_control_result(
    config_path: &Path,
    request: DaemonControlRequest,
    result: Result<()>,
) -> Result<()> {
    let result_file = daemon_control_result_file_path(config_path);
    if let Some(parent) = result_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let payload = match result {
        Ok(()) => DaemonControlResult {
            request: request.as_str().to_string(),
            ok: true,
            error: None,
        },
        Err(error) => DaemonControlResult {
            request: request.as_str().to_string(),
            ok: false,
            error: Some(format!("{error:#}")),
        },
    };
    let raw = serde_json::to_vec_pretty(&payload)?;
    write_runtime_file_atomically(&result_file, &raw)
        .with_context(|| format!("failed to write {}", result_file.display()))?;
    Ok(())
}

pub(crate) fn read_daemon_control_result(
    config_path: &Path,
) -> Result<Option<DaemonControlResult>> {
    let result_file = daemon_control_result_file_path(config_path);
    if !result_file.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&result_file)
        .with_context(|| format!("failed to read {}", result_file.display()))?;
    let parsed = serde_json::from_str::<DaemonControlResult>(&raw)
        .with_context(|| format!("failed to parse {}", result_file.display()))?;
    Ok(Some(parsed))
}

pub(crate) fn wait_for_daemon_control_result(
    config_path: &Path,
    request: DaemonControlRequest,
    timeout: Duration,
) -> Result<()> {
    let result_file = daemon_control_result_file_path(config_path);
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Some(result) = read_daemon_control_result(config_path)?
            && result.request == request.as_str()
        {
            let _ = fs::remove_file(&result_file);
            return if result.ok {
                Ok(())
            } else {
                Err(anyhow!(
                    "{}",
                    result
                        .error
                        .unwrap_or_else(|| "daemon control request failed".to_string())
                ))
            };
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(anyhow!(
        "daemon did not report result for {} within {}s; background service may be busy or stuck. try again, or restart/reinstall the app/service if it keeps happening",
        request.as_str(),
        timeout.as_secs()
    ))
}

pub(crate) fn stage_daemon_config_apply(config_path: &Path, source_path: &Path) -> Result<()> {
    let staged_path = daemon_staged_config_file_path(config_path);
    if let Some(parent) = staged_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut config = AppConfig::load(source_path)
        .with_context(|| format!("failed to load source config {}", source_path.display()))?;
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    config
        .save(&staged_path)
        .with_context(|| format!("failed to stage config {}", staged_path.display()))?;
    set_private_cache_file_permissions(&staged_path)?;
    Ok(())
}

pub(crate) fn update_daemon_config_from_staged_request(config_path: &Path) -> Result<bool> {
    let staged_path = daemon_staged_config_file_path(config_path);
    if !staged_path.exists() {
        return Ok(false);
    }

    let result = apply_config_file(&staged_path, config_path);
    let _ = fs::remove_file(&staged_path);
    let _ = AppConfig::delete_persisted_secrets_for_path(&staged_path);
    result?;
    Ok(true)
}

pub(crate) fn request_daemon_stop(config_path: &Path) -> Result<()> {
    write_daemon_control_request(config_path, DaemonControlRequest::Stop)
}

pub(crate) fn request_daemon_reload(config_path: &Path) -> Result<()> {
    write_daemon_control_request(config_path, DaemonControlRequest::Reload)
}

pub(crate) fn apply_config_via_running_daemon(
    source_path: &Path,
    config_path: &Path,
) -> Result<()> {
    let status = daemon_status(config_path)?;
    if !status.running {
        #[cfg(target_os = "windows")]
        {
            let service_status = service_management::windows_query_service_status(false)?;
            if windows_should_apply_config_via_service(&service_status) {
                apply_config_file(source_path, config_path)?;
                service_management::windows_start_service_and_wait(true, Duration::from_secs(10))?;
                return Ok(());
            }
        }

        return Err(anyhow!("daemon: not running"));
    }
    // A service process is visible to launchd/process scans before its config,
    // tunnel, and control loop are initialized. Waiting for this pid-specific
    // marker prevents a startup request from being mistaken for stale state
    // and deleted by daemon initialization.
    crate::wait_for_running_daemon_control_ready(config_path, &status)?;

    clear_daemon_control_result(config_path);
    stage_daemon_config_apply(config_path, source_path)?;
    request_daemon_reload(config_path)?;
    wait_for_daemon_control_ack(
        config_path,
        crate::daemon_control_ack_timeout(DaemonControlRequest::Reload),
    )?;
    wait_for_daemon_control_result(
        config_path,
        DaemonControlRequest::Reload,
        crate::daemon_control_result_timeout(DaemonControlRequest::Reload),
    )
}

pub(crate) fn wait_for_daemon_control_ack(config_path: &Path, timeout: Duration) -> Result<()> {
    let control_file = daemon_control_file_path(config_path);
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !control_file.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(anyhow!(
        "daemon did not acknowledge control request within {}s; background service may be busy or stuck. try again, or restart/reinstall the app/service if it keeps happening",
        timeout.as_secs()
    ))
}

#[cfg(test)]
pub(crate) fn wait_for_daemon_vpn_enabled(
    config_path: &Path,
    expected_enabled: bool,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(status) = daemon_status(config_path) {
            let current_state = status.state.as_ref();
            let current_enabled = current_state
                .map(|state| state.vpn_enabled)
                .unwrap_or(status.running);
            let resumed_waiting_for_participants = expected_enabled
                && current_state
                    .is_some_and(|state| state.vpn_status == WAITING_FOR_PARTICIPANTS_STATUS);
            if current_enabled == expected_enabled || resumed_waiting_for_participants {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let verb = if expected_enabled { "resume" } else { "pause" };
    Err(anyhow!(
        "daemon acknowledged control request but did not {verb} within {}s; background service may be busy or stuck. try again, or restart/reinstall the app/service if it keeps happening",
        timeout.as_secs()
    ))
}

pub(crate) fn take_daemon_control_request(config_path: &Path) -> Option<DaemonControlRequest> {
    let control_file = daemon_control_file_path(config_path);
    let raw = match fs::read_to_string(&control_file) {
        Ok(raw) => raw,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "daemon: failed to read control request {}: {}",
                    control_file.display(),
                    error
                );
            }
            return None;
        }
    };

    let _ = fs::remove_file(&control_file);
    DaemonControlRequest::parse(&raw)
}

pub(crate) fn read_daemon_pid_record(path: &Path) -> Result<Option<DaemonPidRecord>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon pid file {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonPidRecord>(&raw)
        .with_context(|| format!("failed to parse daemon pid file {}", path.display()))?;
    Ok(Some(parsed))
}

pub(crate) fn write_daemon_pid_record(path: &Path, record: &DaemonPidRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(record)?;
    write_runtime_file_atomically(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon pid file {}", path.display()))?;
    Ok(())
}

pub(crate) fn read_daemon_state(path: &Path) -> Result<Option<DaemonRuntimeState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read(path)
        .with_context(|| format!("failed to read daemon state file {}", path.display()))?;
    match serde_json::from_slice::<DaemonRuntimeState>(&raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(parse_error) => {
            let trimmed = trim_runtime_json_padding(&raw);
            if trimmed.len() != raw.len()
                && !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_slice::<DaemonRuntimeState>(trimmed)
            {
                if let Err(error) = write_runtime_file_atomically(path, trimmed) {
                    eprintln!(
                        "daemon: parsed padded state file {} but failed to rewrite clean copy: {}",
                        path.display(),
                        error
                    );
                }
                return Ok(Some(parsed));
            }

            quarantine_corrupt_runtime_file(path, "daemon state", &parse_error);
            Ok(None)
        }
    }
}

pub(crate) fn write_daemon_state(path: &Path, state: &DaemonRuntimeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    write_runtime_file_atomically(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon state file {}", path.display()))?;
    Ok(())
}
