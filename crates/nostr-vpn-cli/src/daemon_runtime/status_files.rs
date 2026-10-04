pub(crate) fn read_daemon_pid_record(path: &Path) -> Result<Option<DaemonPidRecord>> {
    let Some(raw) = read_daemon_status_file(path)? else {
        return Ok(None);
    };
    let parsed = serde_json::from_slice::<DaemonPidRecord>(&raw)
        .with_context(|| format!("failed to parse daemon pid file {}", path.display()))?;
    Ok(Some(parsed))
}

pub(crate) fn write_daemon_pid_record(path: &Path, record: &DaemonPidRecord) -> Result<()> {
    let raw = serde_json::to_string_pretty(record)?;
    write_daemon_status_file(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon pid file {}", path.display()))?;
    Ok(())
}

pub(crate) fn read_daemon_state(path: &Path) -> Result<Option<DaemonRuntimeState>> {
    let Some(raw) = read_daemon_status_file(path)? else {
        return Ok(None);
    };
    match serde_json::from_slice::<DaemonRuntimeState>(&raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(parse_error) => {
            let trimmed = trim_runtime_json_padding(&raw);
            if trimmed.len() != raw.len()
                && !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_slice::<DaemonRuntimeState>(trimmed)
            {
                if daemon_status_writable()
                    && let Err(error) = write_daemon_status_file(path, trimmed)
                {
                    eprintln!(
                        "daemon: parsed padded state file {} but failed to rewrite clean copy: {}",
                        path.display(),
                        error
                    );
                }
                return Ok(Some(parsed));
            }

            if daemon_status_writable() {
                quarantine_corrupt_runtime_file(path, "daemon state", &parse_error);
            }
            Ok(None)
        }
    }
}

pub(crate) fn write_daemon_state(path: &Path, state: &DaemonRuntimeState) -> Result<()> {
    let raw = serde_json::to_string_pretty(state)?;
    write_daemon_status_file(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon state file {}", path.display()))?;
    Ok(())
}

fn daemon_status_writable() -> bool {
    #[cfg(target_os = "macos")]
    return unsafe { libc::geteuid() } == 0;
    #[cfg(not(target_os = "macos"))]
    true
}

fn read_daemon_status_file(path: &Path) -> Result<Option<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    return crate::macos_privileged_files::read_runtime_state(path);
    #[cfg(not(target_os = "macos"))]
    match fs::read(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read daemon status {}", path.display())),
    }
}

fn write_daemon_status_file(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    return crate::macos_privileged_files::write_runtime_state(path, contents);
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        write_runtime_file_atomically(path, contents)
    }
}
