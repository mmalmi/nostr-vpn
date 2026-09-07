pub(crate) fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    write_runtime_file_atomically_with_mode(path, contents, 0o644)
}

pub(crate) fn write_private_runtime_file_atomically(
    path: &Path,
    contents: &[u8],
) -> Result<()> {
    write_runtime_file_atomically_with_mode(path, contents, 0o600)
}

fn write_runtime_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    unix_mode: u32,
) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime file has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("runtime");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut temp_file = None;
    let mut temp_path = None;
    for attempt in 0..128u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(unix_mode);
        }
        #[cfg(not(unix))]
        let _ = unix_mode;
        match options.open(&candidate) {
            Ok(file) => {
                temp_file = Some(file);
                temp_path = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create temp runtime file {}", candidate.display())
                });
            }
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        anyhow!(
            "failed to allocate temp runtime file for {}",
            path.display()
        )
    })?;
    let mut file = temp_file.expect("temp file set with temp path");
    if let Err(error) = file.write_all(contents) {
        let _ = fs::remove_file(&temp_path);
        return Err(error)
            .with_context(|| format!("failed to write temp runtime file {}", temp_path.display()));
    }
    #[cfg(unix)]
    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(unix_mode)) {
        let _ = fs::remove_file(&temp_path);
        return Err(error).with_context(|| {
            format!(
                "failed to set temp runtime file permissions on {}",
                temp_path.display()
            )
        });
    }
    // These files are runtime status/control files. Keeping the replace atomic
    // matters for readers, but forcing every status update to durable storage
    // adds visible latency on macOS and is not needed for crash recovery.
    drop(file);
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

pub(crate) fn trim_runtime_json_padding(raw: &[u8]) -> &[u8] {
    let start = raw
        .iter()
        .position(|byte| *byte != 0 && !byte.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| *byte != 0 && !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &raw[start..end]
}

pub(crate) fn quarantine_corrupt_runtime_file(
    path: &Path,
    label: &str,
    parse_error: &serde_json::Error,
) {
    let Some(parent) = path.parent() else {
        eprintln!(
            "daemon: ignoring corrupt {label} file {}: {}",
            path.display(),
            parse_error
        );
        return;
    };
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("runtime");
    let quarantined = parent.join(format!(
        "{file_name}.corrupt-{}-{}",
        std::process::id(),
        unix_timestamp()
    ));

    match fs::rename(path, &quarantined) {
        Ok(()) => eprintln!(
            "daemon: ignoring corrupt {label} file {}: {}; moved aside to {}",
            path.display(),
            parse_error,
            quarantined.display()
        ),
        Err(rename_error) => eprintln!(
            "daemon: ignoring corrupt {label} file {}: {}; failed to move aside: {}",
            path.display(),
            parse_error,
            rename_error
        ),
    }
}

pub(crate) fn spawn_daemon_process(args: &ConnectArgs, config_path: &Path) -> Result<u32> {
    if let Some(existing_pid) = daemon_candidate_pids(config_path, std::process::id())?
        .into_iter()
        .next()
    {
        return Err(anyhow!("daemon already running with pid {}", existing_pid));
    }

    let log_file_path = daemon_log_file_path(config_path);
    if let Some(parent) = log_file_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    #[cfg(windows)]
    {
        // Windows append-only handles cannot truncate. Keep the separate write
        // handle used by the Windows launcher, validating it before mutation.
        let truncate_log = runtime_open_options_no_follow()
            .create(true)
            .write(true)
            .open(&log_file_path)
            .with_context(|| format!("failed to open {}", log_file_path.display()))?;
        validate_daemon_runtime_file(&truncate_log, &log_file_path)?;
        truncate_log
            .set_len(0)
            .with_context(|| format!("failed to truncate {}", log_file_path.display()))?;
    }
    let log_file = open_daemon_log_file(&log_file_path)?;
    #[cfg(not(windows))]
    log_file
        .set_len(0)
        .with_context(|| format!("failed to truncate {}", log_file_path.display()))?;
    let stderr_log = log_file
        .try_clone()
        .context("failed to clone daemon log file handle")?;

    let mut command = ProcessCommand::new(
        std::env::current_exe().context("failed to resolve current executable")?,
    );
    command
        .arg("daemon")
        .arg("--config")
        .arg(config_path)
        .arg("--iface")
        .arg(&args.iface)
        .arg("--mesh-refresh-interval-secs")
        .arg(args.mesh_refresh_interval_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_log));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{
            HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        };
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        // Rust supplies the daemon's explicit null/log handles below, but
        // CreateProcess can otherwise inherit the launcher's PowerShell/SSH
        // pipe handles too. Those leaked handles keep the remote shell open.
        for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = unsafe { GetStdHandle(stream) };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                unsafe {
                    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }

        // OpenSSH runs commands in a Windows job and waits for descendants.
        // Break the daemon out of that job as well as redirecting stdio, so
        // `nvpn start --daemon` can actually return to PowerShell/SSH.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        command.creation_flags(
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
        );
    }

    if let Some(network_id) = &args.network_id {
        command.arg("--network-id").arg(network_id);
    }
    for device in &args.devices {
        command.arg("--device").arg(device);
    }

    let mut child = command
        .spawn()
        .context("failed to spawn daemonized connect process")?;
    let pid = child.id();

    // Wait briefly to catch startup failures that occur after initial bootstrapping
    // (for example: missing tunnel permissions or resolver install errors).
    for _ in 0..25 {
        if let Some(status) = child
            .try_wait()
            .context("failed to verify daemon process state")?
        {
            let log_tail = read_daemon_log_tail(&log_file_path, 20);
            return if log_tail.is_empty() {
                Err(anyhow!(
                    "daemon process exited during startup with status {status}"
                ))
            } else {
                Err(anyhow!(
                    "daemon process exited during startup with status {status}\nlog tail:\n{log_tail}"
                ))
            };
        }
        thread::sleep(Duration::from_millis(100));
    }

    let record = DaemonPidRecord {
        pid,
        config_path: config_path.display().to_string(),
        started_at: unix_timestamp(),
    };
    let pid_file = daemon_pid_file_path(config_path);
    write_daemon_pid_record(&pid_file, &record)?;
    Ok(pid)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn stop_existing_daemons_before_service_install(config_path: &Path) -> Result<()> {
    stop_daemon(StopArgs {
        config: Some(config_path.to_path_buf()),
        timeout_secs: 5,
        force: true,
    })
}
