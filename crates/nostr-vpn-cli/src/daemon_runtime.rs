use super::*;

pub(crate) fn daemon_pid_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.pid")
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

pub(crate) fn daemon_state_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.state.json")
}

pub(crate) fn daemon_network_cleanup_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.cleanup.json")
}

pub(crate) fn daemon_control_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.control")
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

pub(crate) fn daemon_peer_cache_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.mesh-cache.json")
}

pub(crate) fn relay_operator_log_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("relay.operator.log")
}

pub(crate) fn relay_operator_state_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("relay.operator.json")
}

const LOCAL_NAT_ASSIST_PORT: u16 = 3478;

pub(crate) fn relay_operator_binary_path() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    #[cfg(target_os = "windows")]
    let candidate = current_exe.with_file_name("nvpn-udp-relay.exe");
    #[cfg(not(target_os = "windows"))]
    let candidate = current_exe.with_file_name("nvpn-udp-relay");

    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(anyhow!(
            "relay operator binary not found at {}",
            candidate.display()
        ))
    }
}

pub(crate) fn relay_operator_advertise_host(
    app: &AppConfig,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
) -> Option<String> {
    public_signal_endpoint
        .and_then(|value| relay_operator_host_from_endpoint(&value.endpoint))
        .or_else(|| relay_operator_host_from_endpoint(&app.node.endpoint))
}

pub(crate) fn relay_operator_host_from_endpoint(endpoint: &str) -> Option<String> {
    let addr = endpoint.trim().parse::<SocketAddr>().ok()?;
    relay_operator_ip_is_viable(addr.ip()).then(|| addr.ip().to_string())
}

pub(crate) fn relay_operator_ip_is_viable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}

pub(crate) fn stop_local_relay_operator(
    process: &mut Option<LocalRelayOperatorProcess>,
    runtime: &mut LocalRelayOperatorRuntime,
    relay_status: impl Into<String>,
    nat_assist_status: impl Into<String>,
) {
    if let Some(mut process) = process.take() {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
    runtime.running = false;
    runtime.pid = None;
    runtime.status = relay_status.into();
    runtime.nat_assist_running = false;
    runtime.nat_assist_status = nat_assist_status.into();
}

pub(crate) fn sync_local_relay_operator(
    config_path: &Path,
    app: &AppConfig,
    relays: &[String],
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    process: &mut Option<LocalRelayOperatorProcess>,
    runtime: &mut LocalRelayOperatorRuntime,
) -> Result<()> {
    if let Some(process_state) = process.as_mut()
        && let Some(status) = process_state
            .child
            .try_wait()
            .context("failed to poll relay operator child")?
    {
        *process = None;
        runtime.running = false;
        runtime.pid = None;
        runtime.status = if app.relay_for_others {
            format!("Relay operator exited ({status})")
        } else {
            "Relay operator disabled".to_string()
        };
        runtime.nat_assist_running = false;
        runtime.nat_assist_status = if app.provide_nat_assist {
            format!("NAT assist exited ({status})")
        } else {
            "NAT assist disabled".to_string()
        };
    }

    if !app.relay_for_others && !app.provide_nat_assist {
        stop_local_relay_operator(
            process,
            runtime,
            "Relay operator disabled",
            "NAT assist disabled",
        );
        return Ok(());
    }

    if relays.is_empty() {
        stop_local_relay_operator(
            process,
            runtime,
            if app.relay_for_others {
                "Add at least one Nostr relay to relay for others"
            } else {
                "Relay operator disabled"
            },
            if app.provide_nat_assist {
                "Add at least one Nostr relay to provide NAT assist"
            } else {
                "NAT assist disabled"
            },
        );
        return Ok(());
    }

    let Some(advertise_host) = relay_operator_advertise_host(app, public_signal_endpoint) else {
        stop_local_relay_operator(
            process,
            runtime,
            if app.relay_for_others {
                "Waiting for a public relay ingress address"
            } else {
                "Relay operator disabled"
            },
            if app.provide_nat_assist {
                "Waiting for a public NAT-assist address"
            } else {
                "NAT assist disabled"
            },
        );
        return Ok(());
    };

    if process.as_ref().is_some_and(|process_state| {
        process_state.advertise_host != advertise_host
            || process_state.relays != relays
            || process_state.secret_key != app.nostr.secret_key
            || process_state.relay_enabled != app.relay_for_others
            || process_state.nat_assist_enabled != app.provide_nat_assist
    }) {
        stop_local_relay_operator(
            process,
            runtime,
            "Restarting relay operator",
            "Restarting NAT assist",
        );
    }

    if let Some(process_state) = process.as_ref() {
        runtime.running = process_state.relay_enabled;
        runtime.pid = process_state.relay_enabled.then_some(process_state.pid);
        runtime.status = if process_state.relay_enabled {
            format!(
                "Relaying for others on {} (pid {})",
                process_state.advertise_host, process_state.pid
            )
        } else {
            "Relay operator disabled".to_string()
        };
        runtime.nat_assist_running = process_state.nat_assist_enabled;
        runtime.nat_assist_status = if process_state.nat_assist_enabled {
            format!(
                "Providing NAT assist on {}:{} (pid {})",
                process_state.advertise_host, LOCAL_NAT_ASSIST_PORT, process_state.pid
            )
        } else {
            "NAT assist disabled".to_string()
        };
        return Ok(());
    }

    let binary = match relay_operator_binary_path() {
        Ok(path) => path,
        Err(error) => {
            runtime.running = false;
            runtime.pid = None;
            runtime.status = if app.relay_for_others {
                format!("Relay operator unavailable ({error})")
            } else {
                "Relay operator disabled".to_string()
            };
            runtime.nat_assist_running = false;
            runtime.nat_assist_status = if app.provide_nat_assist {
                format!("NAT assist unavailable ({error})")
            } else {
                "NAT assist disabled".to_string()
            };
            return Ok(());
        }
    };

    let log_path = relay_operator_log_file_path(config_path);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let _ = set_daemon_runtime_file_permissions(&log_path);
    let stderr_log = log_file
        .try_clone()
        .context("failed to clone relay operator log file handle")?;

    let mut command = ProcessCommand::new(&binary);
    command
        .arg("--secret-key")
        .arg(&app.nostr.secret_key)
        .arg("--advertise-host")
        .arg(&advertise_host)
        .arg("--state-file")
        .arg(relay_operator_state_file_path(config_path))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_log));

    if !app.relay_for_others {
        command.arg("--disable-relay");
    }
    if app.provide_nat_assist {
        command
            .arg("--enable-nat-assist")
            .arg("--nat-assist-port")
            .arg(LOCAL_NAT_ASSIST_PORT.to_string());
    }

    for relay in relays {
        command.arg("--relay").arg(relay);
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            runtime.running = false;
            runtime.pid = None;
            runtime.status = if app.relay_for_others {
                format!("Relay operator failed to start ({error})")
            } else {
                "Relay operator disabled".to_string()
            };
            runtime.nat_assist_running = false;
            runtime.nat_assist_status = if app.provide_nat_assist {
                format!("NAT assist failed to start ({error})")
            } else {
                "NAT assist disabled".to_string()
            };
            return Ok(());
        }
    };
    let pid = child.id();
    *process = Some(LocalRelayOperatorProcess {
        child,
        pid,
        advertise_host: advertise_host.clone(),
        relays: relays.to_vec(),
        secret_key: app.nostr.secret_key.clone(),
        relay_enabled: app.relay_for_others,
        nat_assist_enabled: app.provide_nat_assist,
    });
    runtime.running = app.relay_for_others;
    runtime.pid = app.relay_for_others.then_some(pid);
    runtime.status = if app.relay_for_others {
        format!("Relaying for others on {advertise_host} (pid {pid})")
    } else {
        "Relay operator disabled".to_string()
    };
    runtime.nat_assist_running = app.provide_nat_assist;
    runtime.nat_assist_status = if app.provide_nat_assist {
        format!("Providing NAT assist on {advertise_host}:{LOCAL_NAT_ASSIST_PORT} (pid {pid})")
    } else {
        "NAT assist disabled".to_string()
    };
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DaemonControlResult {
    request: String,
    ok: bool,
    error: Option<String>,
}

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
    fs::write(&control_file, format!("{}\n", request.as_str())).with_context(|| {
        format!(
            "failed to write daemon control request {}",
            control_file.display()
        )
    })?;
    set_daemon_runtime_file_permissions(&control_file)?;
    Ok(())
}

pub(crate) fn clear_daemon_control_result(config_path: &Path) {
    let _ = fs::remove_file(daemon_control_result_file_path(config_path));
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
            error: Some(error.to_string()),
        },
    };
    let raw = serde_json::to_vec_pretty(&payload)?;
    write_runtime_file_atomically(&result_file, &raw)
        .with_context(|| format!("failed to write {}", result_file.display()))?;
    set_daemon_runtime_file_permissions(&result_file)?;
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
    let raw = fs::read(source_path)
        .with_context(|| format!("failed to read source config {}", source_path.display()))?;
    write_runtime_file_atomically(&staged_path, &raw)
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
            let service_status = service_management::windows_query_service_status()?;
            if windows_should_apply_config_via_service(&service_status) {
                apply_config_file(source_path, config_path)?;
                service_management::windows_start_service_and_wait(true, Duration::from_secs(10))?;
                return Ok(());
            }
        }

        return Err(anyhow!("daemon: not running"));
    }

    clear_daemon_control_result(config_path);
    stage_daemon_config_apply(config_path, source_path)?;
    request_daemon_reload(config_path)?;
    wait_for_daemon_control_ack(config_path, Duration::from_secs(3))?;
    wait_for_daemon_control_result(
        config_path,
        DaemonControlRequest::Reload,
        Duration::from_secs(3),
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

pub(crate) fn wait_for_daemon_session_active(
    config_path: &Path,
    expected_active: bool,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(status) = daemon_status(config_path) {
            let current_state = status.state.as_ref();
            let current_active = current_state
                .map(|state| state.session_active)
                .unwrap_or(status.running);
            let resumed_waiting_for_participants = expected_active
                && current_state
                    .is_some_and(|state| state.session_status == WAITING_FOR_PARTICIPANTS_STATUS);
            if current_active == expected_active || resumed_waiting_for_participants {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let verb = if expected_active { "resume" } else { "pause" };
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
    set_daemon_runtime_file_permissions(path)?;
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
                } else {
                    let _ = set_daemon_runtime_file_permissions(path);
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
    set_daemon_runtime_file_permissions(path)?;
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn read_daemon_network_cleanup_state(
    path: &Path,
) -> Result<Option<MacosNetworkCleanupState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read(path)
        .with_context(|| format!("failed to read daemon cleanup file {}", path.display()))?;
    match serde_json::from_slice::<MacosNetworkCleanupState>(&raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(parse_error) => {
            let trimmed = trim_runtime_json_padding(&raw);
            if trimmed.len() != raw.len()
                && !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_slice::<MacosNetworkCleanupState>(trimmed)
            {
                if let Err(error) = write_runtime_file_atomically(path, trimmed) {
                    eprintln!(
                        "daemon: parsed padded cleanup file {} but failed to rewrite clean copy: {}",
                        path.display(),
                        error
                    );
                } else {
                    let _ = set_daemon_runtime_file_permissions(path);
                }
                return Ok(Some(parsed));
            }

            quarantine_corrupt_runtime_file(path, "daemon cleanup", &parse_error);
            Ok(None)
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn write_daemon_network_cleanup_state(
    path: &Path,
    state: &MacosNetworkCleanupState,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    write_runtime_file_atomically(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon cleanup file {}", path.display()))?;
    set_daemon_runtime_file_permissions(path)?;
    Ok(())
}

pub(crate) fn remove_runtime_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

pub(crate) fn persist_daemon_network_cleanup_state(
    config_path: &Path,
    tunnel_runtime: &CliTunnelRuntime,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let path = daemon_network_cleanup_file_path(config_path);
        if let Some(state) = tunnel_runtime.macos_network_cleanup_state() {
            write_daemon_network_cleanup_state(&path, &state)?;
        } else {
            remove_runtime_file_if_exists(&path)?;
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (config_path, tunnel_runtime);
    }

    Ok(())
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_route_delete_error_is_absent(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not in table")
        || lower.contains("no such process")
        || lower.contains("no such route")
}

#[cfg(target_os = "macos")]
pub(crate) fn repair_legacy_macos_network_state(config_path: &Path) -> Result<bool> {
    let app = load_or_default_config(config_path)?;
    let mut repaired = false;

    if let Ok(tunnel_ip) = strip_cidr(&app.node.tunnel_ip).parse::<Ipv4Addr>() {
        let default_routes = macos_default_routes()?;
        let underlay_default = macos_underlay_default_route_from_routes(&default_routes);
        let mut tunnel_default_ifaces = Vec::new();

        for route in default_routes {
            if !route.interface.starts_with("utun") {
                continue;
            }

            match macos_iface_has_ipv4_address(&route.interface, tunnel_ip) {
                Ok(true) => tunnel_default_ifaces.push(route.interface),
                Ok(false) => {}
                Err(error) => {
                    eprintln!(
                        "repair-network: failed to inspect macOS interface {}: {}",
                        route.interface, error
                    );
                }
            }
        }

        if let Some(underlay_default) = underlay_default {
            for iface in tunnel_default_ifaces {
                match delete_macos_default_route_for_interface(&iface) {
                    Ok(()) => repaired = true,
                    Err(error) if macos_route_delete_error_is_absent(&error.to_string()) => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to remove legacy macOS default route on {iface}")
                        });
                    }
                }
            }

            if repaired {
                restore_macos_default_route(&underlay_default)
                    .context("failed to restore legacy macOS default route")?;
            }
        }
    }

    let route_families =
        linux_exit_node_default_route_families(&runtime_effective_advertised_routes(&app));
    if route_families.ipv4 {
        if let Err(error) = cleanup_macos_pf_nat() {
            eprintln!("repair-network: failed to clear legacy macOS PF NAT rules: {error}");
        } else {
            repaired = true;
        }

        match read_macos_ip_forward() {
            Ok(true) => {
                write_macos_ip_forward(false)
                    .context("failed to restore legacy macOS IPv4 forwarding state")?;
                repaired = true;
            }
            Ok(false) => {}
            Err(error) => {
                return Err(error).context("failed to read legacy macOS IPv4 forwarding state");
            }
        }
    }

    Ok(repaired)
}

pub(crate) fn repair_saved_network_state(config_path: &Path) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let path = daemon_network_cleanup_file_path(config_path);
        let Some(state) = read_daemon_network_cleanup_state(&path)? else {
            return repair_legacy_macos_network_state(config_path);
        };

        let mut failures = Vec::new();
        for route in &state.endpoint_bypass_routes {
            if let Err(error) = delete_macos_endpoint_bypass_route(route)
                && !macos_route_delete_error_is_absent(&error.to_string())
            {
                failures.push(format!("remove bypass route {route}: {error}"));
            }
        }

        if let Some(route) = state.original_default_route.as_ref() {
            if route.interface != state.iface
                && let Err(error) = delete_macos_default_route_for_interface(&state.iface)
                && !macos_route_delete_error_is_absent(&error.to_string())
            {
                failures.push(format!(
                    "remove default route on {}: {}",
                    state.iface, error
                ));
            }
            if let Err(error) = restore_macos_default_route(route) {
                failures.push(format!("restore default route: {error}"));
            }
        } else if !state.iface.trim().is_empty()
            && let Err(error) = delete_macos_default_route_for_interface(&state.iface)
            && !macos_route_delete_error_is_absent(&error.to_string())
        {
            failures.push(format!(
                "remove default route on {}: {}",
                state.iface, error
            ));
        }

        if state.pf_was_enabled.is_some() {
            if let Err(error) = cleanup_macos_pf_nat() {
                failures.push(format!("remove PF NAT rules: {error}"));
            }
            if state.pf_was_enabled == Some(false)
                && let Err(error) = run_checked(ProcessCommand::new("pfctl").arg("-d"))
            {
                failures.push(format!("restore PF enabled state: {error}"));
            }
        }

        if let Some(previous) = state.ipv4_forward_was_enabled
            && let Err(error) = write_macos_ip_forward(previous)
        {
            failures.push(format!("restore IPv4 forwarding: {error}"));
        }

        if !failures.is_empty() {
            return Err(anyhow!(failures.join("; ")))
                .with_context(|| format!("failed to repair {}", path.display()));
        }

        remove_runtime_file_if_exists(&path)?;
        return Ok(true);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = config_path;
        Ok(false)
    }
}

pub(crate) fn read_daemon_peer_cache(path: &Path) -> Result<Option<DaemonPeerCacheState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon peer cache {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonPeerCacheState>(&raw)
        .with_context(|| format!("failed to parse daemon peer cache {}", path.display()))?;
    Ok(Some(parsed))
}

pub(crate) fn write_daemon_peer_cache(path: &Path, state: &DaemonPeerCacheState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(path, raw)
        .with_context(|| format!("failed to write daemon peer cache {}", path.display()))?;
    set_private_cache_file_permissions(path)?;
    Ok(())
}

pub(crate) fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime file has no parent: {}", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("runtime"),
        std::process::id(),
        unix_timestamp()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temp runtime file {}", temp_path.display()))?;
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
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_file_path)
        .with_context(|| format!("failed to open {}", log_file_path.display()))?;
    let _ = set_daemon_runtime_file_permissions(&log_file_path);
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
        .arg("--announce-interval-secs")
        .arg(args.announce_interval_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_log));

    if let Some(network_id) = &args.network_id {
        command.arg("--network-id").arg(network_id);
    }
    for participant in &args.participants {
        command.arg("--participant").arg(participant);
    }
    for relay in &args.relay {
        command.arg("--relay").arg(relay);
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

pub(crate) fn read_daemon_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(raw) = fs::read_to_string(path) else {
        return String::new();
    };

    let mut lines = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() > max_lines {
        lines.drain(0..(lines.len() - max_lines));
    }
    lines.join("\n")
}

#[cfg(unix)]
pub(crate) fn is_process_running(pid: u32) -> bool {
    ProcessCommand::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("pid=")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
        .unwrap_or(false)
}

#[cfg(windows)]
pub(crate) fn is_process_running(pid: u32) -> bool {
    let output = ProcessCommand::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    tasklist_pids_from_output(&String::from_utf8_lossy(&output.stdout)).contains(&pid)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_process_running(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, config_path: &Path) -> bool {
    if !is_process_running(pid) {
        return false;
    }

    let output = ProcessCommand::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("command=")
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    daemon_command_matches_config(&String::from_utf8_lossy(&output.stdout), config_path)
}

#[cfg(windows)]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, _config_path: &Path) -> bool {
    is_process_running(pid)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn daemon_pid_record_counts_as_running(_pid: u32, _config_path: &Path) -> bool {
    false
}

#[cfg(unix)]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let output = ProcessCommand::new("ps")
        .arg("ax")
        .arg("-o")
        .arg("pid=,command=")
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    daemon_pids_from_ps_output(&String::from_utf8_lossy(&output.stdout), config_path)
}

#[cfg(windows)]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let output = ProcessCommand::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_Process -Filter \"Name LIKE 'nvpn%.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    daemon_pids_from_windows_cim_json(&String::from_utf8_lossy(&output.stdout), config_path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn find_daemon_pids_by_config(_config_path: &Path) -> Vec<u32> {
    Vec::new()
}

#[cfg(any(unix, test))]
pub(crate) fn daemon_pids_from_ps_output(ps_output: &str, config_path: &Path) -> Vec<u32> {
    let mut pids = Vec::new();

    for line in ps_output.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let Some(pid_text) = parts.next() else {
            continue;
        };
        let Some(command) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        if daemon_command_matches_config(command, config_path) {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn tasklist_pids_from_output(tasklist_output: &str) -> Vec<u32> {
    let trimmed = tasklist_output.trim();
    if trimmed.is_empty()
        || trimmed
            .to_ascii_lowercase()
            .contains("no tasks are running which match")
    {
        return Vec::new();
    }

    let mut pids = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if !(line.starts_with('"') && line.ends_with('"')) {
            continue;
        }
        let inner = &line[1..line.len().saturating_sub(1)];
        let mut fields = inner.split("\",\"");
        let _image_name = fields.next();
        let Some(pid_text) = fields.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        pids.push(pid);
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(windows)]
pub(crate) fn windows_nvpn_pids() -> Vec<u32> {
    let output = ProcessCommand::new("tasklist")
        .args(["/FI", "IMAGENAME eq nvpn.exe", "/FO", "CSV", "/NH"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    tasklist_pids_from_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn recent_windows_daemon_pid_candidate(
    state: Option<&DaemonRuntimeState>,
    current_pid: u32,
    nvpn_pids: &[u32],
    now: u64,
) -> Option<u32> {
    let state = state?;
    if now.saturating_sub(state.updated_at) > WINDOWS_DAEMON_STATE_FRESHNESS_SECS {
        return None;
    }

    let mut other_pids = nvpn_pids
        .iter()
        .copied()
        .filter(|pid| *pid != current_pid)
        .collect::<Vec<_>>();
    other_pids.sort_unstable();
    other_pids.dedup();
    if other_pids.len() == 1 {
        Some(other_pids[0])
    } else {
        None
    }
}

pub(crate) fn daemon_candidate_pids(config_path: &Path, current_pid: u32) -> Result<Vec<u32>> {
    let mut daemon_pids = find_daemon_pids_by_config(config_path);

    let pid_file = daemon_pid_file_path(config_path);
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && record.pid != current_pid
        && daemon_pid_record_counts_as_running(record.pid, config_path)
        && !daemon_pids.contains(&record.pid)
    {
        daemon_pids.push(record.pid);
    }

    #[cfg(windows)]
    {
        let state = read_daemon_state(&daemon_state_file_path(config_path))?;
        if let Some(pid) = recent_windows_daemon_pid_candidate(
            state.as_ref(),
            current_pid,
            &windows_nvpn_pids(),
            unix_timestamp(),
        ) && !daemon_pids.contains(&pid)
        {
            daemon_pids.push(pid);
        }
    }

    daemon_pids.retain(|pid| *pid != current_pid);
    daemon_pids.sort_unstable();
    daemon_pids.dedup();
    Ok(daemon_pids)
}

pub(crate) fn daemon_command_matches_config(command: &str, config_path: &Path) -> bool {
    let config_text = config_path.display().to_string();
    command.contains(" daemon ")
        && command.contains("--config")
        && command.contains(config_text.as_str())
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn daemon_pids_from_windows_cim_json(cim_json: &str, config_path: &Path) -> Vec<u32> {
    let trimmed = cim_json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let entries = match parsed {
        serde_json::Value::Array(entries) => entries,
        serde_json::Value::Object(entry) => vec![serde_json::Value::Object(entry)],
        _ => return Vec::new(),
    };

    let mut pids = Vec::new();
    for entry in entries {
        let Some(command) = entry.get("CommandLine").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(pid) = entry
            .get("ProcessId")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            continue;
        };

        if daemon_command_matches_config(command, config_path) {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

pub(crate) fn set_daemon_runtime_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Daemon runtime files must stay readable by the desktop app even when
        // the daemon was started with elevated privileges.
        let permissions = fs::Permissions::from_mode(0o644);
        fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "failed to set daemon runtime file permissions on {}",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}

pub(crate) fn set_private_cache_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set daemon peer cache file permissions on {}",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
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

pub(crate) fn run_ping(target: &str, count: u32, timeout_secs: u64) -> Result<()> {
    let mut command = ProcessCommand::new("ping");
    if cfg!(target_os = "windows") {
        command
            .arg("-n")
            .arg(count.to_string())
            .arg("-w")
            .arg((timeout_secs.saturating_mul(1000)).to_string())
            .arg(target);
    } else {
        command
            .arg("-c")
            .arg(count.to_string())
            .arg("-W")
            .arg(timeout_secs.to_string())
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
