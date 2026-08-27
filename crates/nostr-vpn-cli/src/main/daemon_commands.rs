#[cfg(any(target_os = "macos", test))]
fn macos_effective_uid() -> u32 {
    #[cfg(test)]
    {
        let override_uid = TEST_MACOS_EUID_OVERRIDE.load(Ordering::Relaxed);
        if override_uid != TEST_MACOS_EUID_SENTINEL {
            return override_uid;
        }
    }

    #[cfg(target_os = "macos")]
    {
        unsafe { libc::geteuid() as u32 }
    }

    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn ensure_macos_connect_privileges(config_path: &Path) -> Result<()> {
    if macos_effective_uid() == 0 {
        return Ok(());
    }

    Err(anyhow!(
        "macOS tunnel setup requires admin privileges (did you run with sudo?); run `sudo nvpn start --connect --config {}` for a one-off session or `sudo nvpn service install --config {}` to use the launchd service",
        config_path.display(),
        config_path.display()
    ))
}

#[cfg(test)]
mod daemon_commands_tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn macos_connect_privilege_preflight_requires_admin_when_euid_is_not_root() {
        let _guard = super::TEST_MACOS_EUID_OVERRIDE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("macos euid test lock");
        super::TEST_MACOS_EUID_OVERRIDE.store(501, Ordering::Relaxed);

        let error = super::ensure_macos_connect_privileges(Path::new("/tmp/nvpn.toml"))
            .expect_err("non-root macOS preflight should fail");
        let message = error.to_string();
        assert!(message.contains("admin privileges"));
        assert!(message.contains("did you run with sudo?"));
        assert!(message.contains("sudo nvpn start --connect"));
        assert!(message.contains("sudo nvpn service install"));

        super::TEST_MACOS_EUID_OVERRIDE
            .store(super::TEST_MACOS_EUID_SENTINEL, Ordering::Relaxed);
    }

    #[test]
    fn macos_connect_privilege_preflight_allows_root() {
        let _guard = super::TEST_MACOS_EUID_OVERRIDE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("macos euid test lock");
        super::TEST_MACOS_EUID_OVERRIDE.store(0, Ordering::Relaxed);

        super::ensure_macos_connect_privileges(Path::new("/tmp/nvpn.toml"))
            .expect("root macOS preflight should pass");

        super::TEST_MACOS_EUID_OVERRIDE
            .store(super::TEST_MACOS_EUID_SENTINEL, Ordering::Relaxed);
    }

    #[test]
    fn daemon_status_does_not_repair_network_state_when_daemon_is_stopped() {
        let _guard = super::TEST_REPAIR_SAVED_NETWORK_STATE_CALLS_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("repair call test lock");
        super::TEST_REPAIR_SAVED_NETWORK_STATE_CALLS.store(0, Ordering::Relaxed);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-daemon-status-pure-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "").expect("write config placeholder");

        let status = super::daemon_status(&config_path).expect("daemon status should succeed");
        assert!(!status.running);
        assert_eq!(
            super::TEST_REPAIR_SAVED_NETWORK_STATE_CALLS.load(Ordering::Relaxed),
            0
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

async fn start_session(args: StartArgs) -> Result<()> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let (app, _network_id) = load_config_with_overrides(
        &config_path,
        args.network_id.clone(),
        args.devices.clone(),
        ConfigLoadMode::Persist,
    )?;
    if args.connect {
        persist_desired_daemon_vpn_enabled(&config_path, true)?;
    } else if args.no_connect {
        persist_desired_daemon_vpn_enabled(&config_path, false)?;
    }

    let should_connect = if args.connect {
        true
    } else if args.no_connect {
        false
    } else {
        app.autoconnect
    };

    if !should_connect {
        println!(
            "start: autoconnect is disabled; not starting a session (pass --connect to override)"
        );
        return Ok(());
    }

    let connect_args = ConnectArgs {
        config: Some(config_path.clone()),
        network_id: args.network_id,
        devices: args.devices,
        iface: args.iface,
        mesh_refresh_interval_secs: args.mesh_refresh_interval_secs,
    };

    if args.daemon {
        let status = daemon_status(&config_path)?;
        if status.running {
            return Err(anyhow!(
                "daemon already running with pid {}",
                status.pid.unwrap_or_default()
            ));
        }

        let pid = spawn_daemon_process(&connect_args, &config_path)?;
        println!("daemon started: pid {pid}");
        println!("pid_file: {}", status.pid_file.display());
        println!("log_file: {}", status.log_file.display());
        return Ok(());
    }

    connect_vpn(connect_args).await
}

fn stop_daemon(args: StopArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    let current_pid = std::process::id();
    let daemon_pids = daemon_candidate_pids(&config_path, current_pid)?;

    if daemon_pids.is_empty() {
        return finish_stop_daemon(&config_path, &status, false);
    }

    #[cfg(target_os = "windows")]
    let requested_control_stop = {
        request_daemon_stop(&config_path)?;
        true
    };

    #[cfg(not(target_os = "windows"))]
    let mut requested_control_stop = false;

    #[cfg(not(target_os = "windows"))]
    for pid in &daemon_pids {
        match send_signal(*pid, "-TERM") {
            Ok(()) => {}
            Err(error) if kill_error_requires_control_fallback(&error.to_string()) => {
                if !requested_control_stop {
                    request_daemon_stop(&config_path)?;
                    requested_control_stop = true;
                }
            }
            Err(error) => return Err(error),
        }
    }

    let timeout = Duration::from_secs(args.timeout_secs.max(1));
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if daemon_candidate_pids(&config_path, current_pid)?.is_empty() {
            return finish_stop_daemon(&config_path, &status, true);
        }
        thread::sleep(Duration::from_millis(120));
    }

    if args.force {
        for pid in daemon_candidate_pids(&config_path, current_pid)? {
            #[cfg(target_os = "windows")]
            windows_taskkill_pid(pid)?;

            #[cfg(not(target_os = "windows"))]
            if let Err(error) = send_signal(pid, "-KILL")
                && !kill_error_requires_control_fallback(&error.to_string())
            {
                return Err(error);
            }
        }
        thread::sleep(Duration::from_millis(120));
    }

    if requested_control_stop {
        #[cfg(not(target_os = "windows"))]
        request_daemon_stop(&config_path)?;
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            if daemon_candidate_pids(&config_path, current_pid)?.is_empty() {
                return finish_stop_daemon(&config_path, &status, true);
            }
            thread::sleep(Duration::from_millis(120));
        }
    }

    let remaining = daemon_candidate_pids(&config_path, current_pid)?;
    if !remaining.is_empty() {
        let hint = stop_daemon_remaining_hint(&config_path, &remaining, requested_control_stop);
        return Err(anyhow!(
            "failed to stop daemon(s) for {}; remaining pid(s): {}; {hint}",
            config_path.display(),
            remaining
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    finish_stop_daemon(&config_path, &status, true)
}

fn stop_daemon_remaining_hint(
    _config_path: &Path,
    _remaining: &[u32],
    requested_control_stop: bool,
) -> String {
    #[cfg(target_os = "macos")]
    if let Ok(service_status) = service_management::query_service_status(_config_path)
        && let Some(hint) = macos_stop_daemon_hint_from_service_status(&service_status, _remaining)
    {
        return hint;
    }

    if requested_control_stop {
        "daemon ignored local stop request; likely an older daemon binary is still running. perform one elevated stop (e.g. sudo nvpn stop --force --config <config>) to migrate".to_string()
    } else {
        "try --force".to_string()
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_stop_daemon_hint_from_service_status(
    service_status: &ServiceStatusView,
    remaining: &[u32],
) -> Option<String> {
    if !(service_status.supported
        && service_status.installed
        && service_status.loaded
        && service_status.running)
    {
        return None;
    }

    let pid = service_status.pid?;
    if !remaining.contains(&pid) {
        return None;
    }

    Some(format!(
        "daemon is managed by launchd service {}; it may be getting restarted automatically. use sudo nvpn service disable --config <config> to stop it completely, or sudo nvpn service enable --config <config> to restart it onto the current binary",
        service_status.label
    ))
}

fn finish_stop_daemon(config_path: &Path, status: &DaemonStatus, was_running: bool) -> Result<()> {
    let repaired = repair_saved_network_state(config_path);
    let _ = fs::remove_file(&status.pid_file);
    let _ = fs::remove_file(daemon_control_file_path(config_path));

    match repaired {
        Ok(true) if was_running => {
            transition_daemon_state_after_network_repair(config_path)?;
            println!("daemon stopped; repaired network state");
        }
        Ok(true) => {
            transition_daemon_state_after_network_repair(config_path)?;
            println!("daemon: not running; repaired network state");
        }
        Ok(false) if was_running => println!("daemon stopped"),
        Ok(false) => println!("daemon: not running"),
        Err(error) => {
            return Err(anyhow!(
                "{} but failed to repair network state: {error}",
                if was_running {
                    "daemon stopped"
                } else {
                    "daemon is not running"
                }
            ));
        }
    }

    Ok(())
}

fn repair_network(args: RepairNetworkArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    if let Some(pid) = daemon_candidate_pids(&config_path, std::process::id())?
        .into_iter()
        .next()
    {
        return Err(anyhow!(
            "daemon is still running with pid {pid}; stop it before repairing network state"
        ));
    }

    if repair_saved_network_state(&config_path)? {
        transition_daemon_state_after_network_repair(&config_path)?;
        println!("network state repaired");
    } else {
        println!("network state already clean");
    }
    Ok(())
}

fn reload_daemon(args: ReloadArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    if !status.running {
        println!("daemon: not running");
        return Ok(());
    }

    wait_for_running_daemon_control_ready(&config_path, &status)?;
    clear_daemon_control_result(&config_path);
    request_daemon_reload(&config_path)?;
    wait_for_daemon_control_ack(
        &config_path,
        daemon_control_ack_timeout(DaemonControlRequest::Reload),
    )?;
    wait_for_daemon_control_result(
        &config_path,
        DaemonControlRequest::Reload,
        daemon_control_result_timeout(DaemonControlRequest::Reload),
    )?;
    println!("daemon reloaded");
    Ok(())
}

pub(crate) fn daemon_control_ack_timeout(request: DaemonControlRequest) -> Duration {
    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(15);
        }
    }

    // Daemon polls the control file inside its 1s state_interval tick, but
    // each tick can stall on FIPS event drain + tunnel reconfig + route
    // refresh. 3s was empirically too short — leave headroom for a busy node.
    Duration::from_secs(10)
}

pub(crate) fn daemon_control_result_timeout(request: DaemonControlRequest) -> Duration {
    #[cfg(target_os = "windows")]
    if matches!(request, DaemonControlRequest::Reload) {
        // A reload is complete only after native WireGuard, routes, and DNS
        // have applied. Cold DnsClient PowerShell gets 10s and the handshake
        // watchdog gets 10s; leave bounded route/cleanup room while keeping a
        // stuck transition below a minute.
        return Duration::from_secs(45);
    }

    if matches!(request, DaemonControlRequest::Reload) {
        // Reload completion includes tunnel, route, DNS, and paid-exit
        // upstream transitions. A live Direct-to-WireGuard seller handoff can
        // legitimately take more than 15s while the old path is removed and
        // the replacement handshake is proven. Keep the deadline bounded,
        // but do not roll a successfully applying configuration back early.
        return Duration::from_secs(30);
    }

    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(30);
        }
    }

    Duration::from_secs(15)
}

pub(crate) fn daemon_control_startup_ready_timeout() -> Duration {
    // SCM/launchd can report the process before FIPS, tunnel, and control-loop
    // initialization completes. This is a readiness deadline, not a sleep:
    // the PID-specific marker returns immediately in the usual case.
    Duration::from_secs(30)
}

pub(crate) fn wait_for_running_daemon_control_ready(
    config_path: &Path,
    status: &DaemonStatus,
) -> Result<()> {
    let pid = status
        .pid
        .ok_or_else(|| anyhow!("daemon: running process has no pid"))?;
    wait_for_daemon_control_ready(config_path, pid, daemon_control_startup_ready_timeout())
}

#[cfg(test)]
pub(crate) fn daemon_control_vpn_transition_timeout(request: DaemonControlRequest) -> Duration {
    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(30);
        }

        #[cfg(not(target_os = "macos"))]
        {
            return Duration::from_secs(2);
        }
    }

    Duration::ZERO
}

fn control_daemon(args: ControlArgs, request: DaemonControlRequest) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    if !status.running {
        persist_desired_daemon_vpn_enabled_for_request(&config_path, request)?;
        println!("daemon: not running");
        return Ok(());
    }

    wait_for_running_daemon_control_ready(&config_path, &status)?;
    write_daemon_control_request(&config_path, request)?;
    match request {
        DaemonControlRequest::Pause | DaemonControlRequest::Resume => {}
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => {
            wait_for_daemon_control_ack(&config_path, daemon_control_ack_timeout(request))?;
        }
    }

    match request {
        DaemonControlRequest::Pause => println!("daemon pause requested"),
        DaemonControlRequest::Resume => println!("daemon resume requested"),
        DaemonControlRequest::Reload => println!("daemon reload requested"),
        DaemonControlRequest::Stop => println!("daemon stop requested"),
    }
    Ok(())
}

pub(crate) fn daemon_status(config_path: &Path) -> Result<DaemonStatus> {
    let pid_file = daemon_pid_file_path(config_path);
    let log_file = daemon_log_file_path(config_path);
    let state_file = daemon_state_file_path(config_path);
    let pid_record = read_daemon_pid_record(&pid_file)?;
    let pid_from_record = pid_record.as_ref().map(|record| record.pid);
    let running_pid = daemon_candidate_pids(config_path, std::process::id())?
        .into_iter()
        .next();

    let pid = running_pid.or(pid_from_record);
    let state = read_daemon_state(&state_file)?;
    let running = running_pid.is_some() || daemon_state_file_counts_as_running(state.as_ref());

    if let Some(pid) = running_pid
        && pid_from_record != Some(pid)
    {
        let refreshed = DaemonPidRecord {
            pid,
            config_path: config_path.display().to_string(),
            started_at: unix_timestamp(),
        };
        let _ = write_daemon_pid_record(&pid_file, &refreshed);
    }

    Ok(DaemonStatus {
        running,
        pid,
        pid_file,
        log_file,
        state_file,
        state,
    })
}

fn daemon_state_file_counts_as_running(state: Option<&DaemonRuntimeState>) -> bool {
    if !daemon_state_file_status_mode_enabled() {
        return false;
    }
    let Some(state) = state else {
        return false;
    };
    daemon_state_is_fresh(state, unix_timestamp(), daemon_state_running_max_age_secs())
}

fn daemon_state_file_status_mode_enabled() -> bool {
    std::env::var(DAEMON_STATUS_MODE_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                DAEMON_STATUS_MODE_STATE_FILE | "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn daemon_state_running_max_age_secs() -> u64 {
    std::env::var(DAEMON_STATE_RUNNING_MAX_AGE_SECS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DAEMON_STATE_RUNNING_MAX_AGE_SECS)
}

fn daemon_state_is_fresh(state: &DaemonRuntimeState, now: u64, max_age_secs: u64) -> bool {
    if state.updated_at == 0 {
        return false;
    }
    if state.updated_at > now {
        return state.updated_at - now <= DAEMON_STATE_RUNNING_MAX_FUTURE_SKEW_SECS;
    }
    now - state.updated_at <= max_age_secs
}

fn daemon_status_json_value(status: &DaemonStatus) -> serde_json::Value {
    json!({
        "running": status.running,
        "pid": status.pid,
        "pid_file": status.pid_file,
        "log_file": status.log_file,
        "state_file": status.state_file,
        "state": visible_daemon_state_for_status(status.running, status.state.as_ref()),
    })
}

fn status_endpoint(app: &AppConfig, daemon: &DaemonStatus) -> String {
    daemon
        .state
        .as_ref()
        .map(|state| state.advertised_endpoint.trim().to_string())
        .unwrap_or_else(|| app.node.endpoint.clone())
}

fn status_listen_port(app: &AppConfig, daemon: &DaemonStatus) -> u16 {
    daemon
        .state
        .as_ref()
        .map(|state| state.listen_port)
        .unwrap_or(app.node.listen_port)
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn expected_peer_count(config: &AppConfig) -> usize {
    let participants = config.participant_pubkeys_hex();
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let expected = participants
        .iter()
        .filter(|participant| own_pubkey.as_deref() != Some(participant.as_str()))
        .count();

    #[cfg(feature = "paid-exit")]
    let expected = {
        let mut expected = expected;
        if let Some(public_paid_exit) = config.public_paid_exit_node_pubkey_hex()
            && own_pubkey.as_deref() != Some(public_paid_exit.as_str())
            && !participants
                .iter()
                .any(|participant| participant == &public_paid_exit)
        {
            expected = expected.saturating_add(1);
        }
        expected
    };

    expected
}

fn format_probe_state(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Available => "available",
        ProbeState::Unavailable => "unavailable",
        ProbeState::Unsupported => "unsupported",
        ProbeState::Error => "error",
        ProbeState::Unknown => "unknown",
    }
}
