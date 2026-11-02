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
    let Some(mut staged_file) = open_trusted_daemon_request_file(&staged_path)? else {
        return Ok(false);
    };

    // The trust checks validated this handle; apply the bytes read from it.
    // Reopening the staged path would let a replacement behind that path after
    // validation swap in contents that were never validated.
    let result = (|| {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut staged_file, &mut raw).with_context(|| {
            format!("failed to read staged config {}", staged_path.display())
        })?;
        apply_config_bytes(&raw, &staged_path, config_path)
    })();
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
