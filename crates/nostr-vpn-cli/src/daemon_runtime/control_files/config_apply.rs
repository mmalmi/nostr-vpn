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
    #[cfg(not(target_os = "macos"))]
    set_private_cache_file_permissions(&staged_path)?;
    Ok(())
}

pub(crate) fn update_daemon_config_from_staged_request(config_path: &Path) -> Result<bool> {
    let staged_path = daemon_staged_config_file_path(config_path);
    if !staged_path.exists() {
        return Ok(false);
    }
    validate_staged_daemon_config_file(&staged_path, config_path)?;

    let result = apply_config_file(&staged_path, config_path);
    let _ = fs::remove_file(&staged_path);
    let _ = AppConfig::delete_persisted_secrets_for_path(&staged_path);
    result?;
    Ok(true)
}

/// The staged config is user-directory state applied by a possibly-root
/// daemon, so it must satisfy the daemon instance-lock file discipline
/// (regular single-link file, owned by the config owner) before the daemon
/// parses it.
#[cfg(unix)]
fn validate_staged_daemon_config_file(staged_path: &Path, config_path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let config_directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    let expected_uid = fs::symlink_metadata(config_directory)
        .with_context(|| format!("failed to inspect {}", config_directory.display()))?
        .uid();
    let file = runtime_open_options_no_follow()
        .read(true)
        .open(staged_path)
        .map_err(|error| {
            anyhow!(
                "refusing staged daemon config {}: {error}",
                staged_path.display()
            )
        })?;
    let metadata = validate_daemon_runtime_file(&file, staged_path)?;
    if metadata.uid() != expected_uid {
        return Err(anyhow!(
            "refusing staged daemon config {} owned by uid {} (expected config owner uid {expected_uid})",
            staged_path.display(),
            metadata.uid()
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to protect staged daemon config {}",
                    staged_path.display()
                )
            })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_staged_daemon_config_file(_staged_path: &Path, _config_path: &Path) -> Result<()> {
    Ok(())
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
