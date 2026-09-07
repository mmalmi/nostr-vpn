pub(crate) fn set_daemon_cleanup_file_permissions(path: &Path) -> Result<()> {
    // Cleanup snapshots may contain WireGuard private and preshared keys.
    set_runtime_file_permissions(path, 0o600)
}

pub(crate) fn set_private_cache_file_permissions(path: &Path) -> Result<()> {
    set_runtime_file_permissions(path, 0o600)
}

fn set_runtime_file_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let file = runtime_open_options_no_follow()
            .read(true)
            .open(path)
            .with_context(|| format!("failed to open runtime file {}", path.display()))?;
        validate_daemon_runtime_file(&file, path)?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to protect runtime file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

pub(crate) fn validate_daemon_runtime_file(file: &fs::File, path: &Path) -> Result<fs::Metadata> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open runtime file {}", path.display()))?;
    #[cfg(unix)]
    let single_link = {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    };
    #[cfg(not(unix))]
    let single_link = true;
    if !metadata.is_file() || !single_link {
        return Err(anyhow!(
            "refusing runtime file {}: expected a regular file with one link",
            path.display()
        ));
    }
    Ok(metadata)
}

pub(crate) fn open_daemon_log_file(path: &Path) -> Result<fs::File> {
    let mut options = runtime_open_options_no_follow();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open daemon log {}", path.display()))?;
    // Validate before chmod, truncation, or handing the file to a child. A
    // hard link must never turn the daemon into an arbitrary-file writer.
    validate_daemon_runtime_file(&file, path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to protect daemon log {}", path.display()))?;
    Ok(file)
}

pub(crate) fn set_daemon_cleanup_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("failed to open daemon cleanup directory {}", path.display()))?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to protect daemon cleanup directory {}", path.display()))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    Ok(())
}

pub(crate) fn executable_fingerprint(path: &Path) -> Result<ExecutableFingerprint> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat executable {}", path.display()))?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_nanos());
    Ok(ExecutableFingerprint {
        len: metadata.len(),
        modified_unix_nanos,
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn current_executable_fingerprint() -> Result<(PathBuf, ExecutableFingerprint)> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let executable = fs::canonicalize(&executable)
        .with_context(|| format!("failed to canonicalize {}", executable.display()))?;
    let fingerprint = executable_fingerprint(&executable)?;
    Ok((executable, fingerprint))
}

pub(crate) fn service_supervisor_restart_due(
    executable: &Path,
    launched_fingerprint: &ExecutableFingerprint,
) -> Result<bool> {
    Ok(executable_fingerprint(executable)? != *launched_fingerprint)
}

#[cfg(unix)]
pub(crate) fn send_signal(pid: u32, signal: &str) -> Result<()> {
    if cfg!(not(unix)) {
        return Err(anyhow!("daemon signal control is only supported on unix"));
    }

    let output = ProcessCommand::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .output()
        .with_context(|| format!("failed to execute kill {signal} {pid}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "kill {signal} {pid} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_taskkill_pid(pid: u32) -> Result<()> {
    let output = ProcessCommand::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()
        .with_context(|| format!("failed to execute taskkill /PID {pid} /F"))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim())
        .trim()
        .to_string();
    let lower = details.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("no running instance") {
        return Ok(());
    }

    Err(anyhow!(
        "taskkill /PID {pid} /F failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(any(unix, test))]
pub(crate) fn kill_error_requires_control_fallback(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("operation not permitted") || lower.contains("permission denied")
}

fn ping_wait_arg_from_secs(timeout_secs: u64) -> String {
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        timeout_secs.saturating_mul(1000).to_string()
    } else {
        timeout_secs.to_string()
    }
}

pub(crate) fn run_ping(target: &str, count: u32, timeout_secs: u64) -> Result<()> {
    let mut command = ProcessCommand::new("ping");
    if cfg!(target_os = "windows") {
        command
            .arg("-n")
            .arg(count.to_string())
            .arg("-w")
            .arg(ping_wait_arg_from_secs(timeout_secs))
            .arg(target);
    } else {
        command
            .arg("-c")
            .arg(count.to_string())
            .arg("-W")
            .arg(ping_wait_arg_from_secs(timeout_secs))
            .arg(target);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to execute ping for {target}"))?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        return Err(anyhow!("ping failed for {target}"));
    }

    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod ping_command_tests {
    use super::ping_wait_arg_from_secs;

    #[test]
    fn timeout_seconds_are_converted_to_macos_ping_milliseconds() {
        assert_eq!(ping_wait_arg_from_secs(2), "2000");
    }
}

pub(crate) fn resolve_ping_target(target: &str, peers: &[PeerAnnouncement]) -> Option<String> {
    if target.parse::<IpAddr>().is_ok() {
        return Some(target.to_string());
    }

    peers.iter().find_map(|peer| {
        let tunnel_ip = strip_cidr(&peer.tunnel_ip);
        if peer.node_id == target || peer.tunnel_ip == target || tunnel_ip == target {
            Some(tunnel_ip.to_string())
        } else {
            None
        }
    })
}
