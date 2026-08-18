#[derive(Clone, Copy)]
pub(crate) struct DaemonRuntimeStateInput<'a> {
    pub(crate) app: &'a AppConfig,
    pub(crate) vpn_enabled: bool,
    pub(crate) vpn_active: bool,
    pub(crate) expected_peers: usize,
    pub(crate) tunnel_runtime: &'a CliTunnelRuntime,
    pub(crate) fips_peer_statuses: &'a [MeshPeerStatus],
    pub(crate) fips_relay_statuses: &'a [DaemonRelayState],
    pub(crate) fips_endpoint_peers: &'a [DaemonFipsEndpointPeerState],
    pub(crate) advertised_routes_by_participant: &'a HashMap<String, Vec<String>>,
    pub(crate) vpn_status: &'a str,
    pub(crate) network: &'a NetworkSummary,
    pub(crate) port_mapping: &'a PortMappingStatus,
}

type OpenFileDescriptorTypes = std::collections::BTreeMap<String, u64>;
type OpenFileDescriptorSnapshot = (u64, OpenFileDescriptorTypes);

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn increment_fd_type(types: &mut OpenFileDescriptorTypes, fd_type: &str) {
    *types.entry(fd_type.to_string()).or_default() += 1;
}

#[cfg(target_os = "linux")]
fn open_file_descriptor_snapshot() -> Option<OpenFileDescriptorSnapshot> {
    let entries = fs::read_dir("/proc/self/fd").ok()?;
    let mut count = 0_u64;
    let mut types = std::collections::BTreeMap::new();
    for entry in entries.flatten() {
        count += 1;
        let fd_type = match fs::read_link(entry.path()) {
            Ok(target) => {
                let target = target.to_string_lossy();
                if target.starts_with("socket:[") {
                    "socket"
                } else if target.starts_with("pipe:[") {
                    "pipe"
                } else if target.starts_with("anon_inode:[eventpoll]")
                    || target.starts_with("anon_inode:[eventfd]")
                {
                    "event"
                } else if target.starts_with("anon_inode:") {
                    "other"
                } else {
                    "file"
                }
            }
            Err(_) => "other",
        };
        increment_fd_type(&mut types, fd_type);
    }
    Some((count, types))
}

#[cfg(target_os = "macos")]
fn open_file_descriptor_snapshot() -> Option<OpenFileDescriptorSnapshot> {
    let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
    let capacity = usize::try_from(unsafe { libc::getdtablesize() }).ok()?;
    let buffer_size = capacity
        .checked_mul(entry_size)
        .map(|size| size.min(i32::MAX as usize))?;
    let mut buffer = vec![0_u8; buffer_size];
    let bytes = unsafe {
        libc::proc_pidinfo(
            std::process::id() as i32,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast(),
            buffer_size as i32,
        )
    };
    (bytes >= 0).then_some(())?;
    let count = bytes as usize / entry_size;
    let mut types = std::collections::BTreeMap::new();
    for index in 0..count {
        let info = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(index * entry_size)
                    .cast::<libc::proc_fdinfo>(),
            )
        };
        let fd_type = match info.proc_fdtype as i32 {
            libc::PROX_FDTYPE_SOCKET => "socket",
            libc::PROX_FDTYPE_PIPE => "pipe",
            libc::PROX_FDTYPE_VNODE => "file",
            libc::PROX_FDTYPE_KQUEUE | libc::PROX_FDTYPE_FSEVENTS => "event",
            _ => "other",
        };
        increment_fd_type(&mut types, fd_type);
    }
    Some((count as u64, types))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_file_descriptor_snapshot() -> Option<OpenFileDescriptorSnapshot> {
    None
}

#[cfg(unix)]
fn open_file_descriptor_soft_limit() -> Option<u64> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return None;
    }
    let current = unsafe { limit.assume_init() }.rlim_cur;
    (current != libc::RLIM_INFINITY).then_some(current)
}

#[cfg(not(unix))]
fn open_file_descriptor_soft_limit() -> Option<u64> {
    None
}

fn persist_daemon_startup_failure_state(
    state_file: &Path,
    input: DaemonRuntimeStateInput<'_>,
) {
    let state = build_daemon_runtime_state(input);
    if let Err(error) = write_daemon_state(state_file, &state) {
        eprintln!("daemon: failed to persist startup failure state: {error}");
    }
}

fn remove_current_daemon_pid_record(pid_file: &Path) {
    let current_pid = std::process::id();
    match read_daemon_pid_record(pid_file) {
        Ok(Some(record)) if record.pid == current_pid => {
            let _ = fs::remove_file(pid_file);
        }
        Ok(_) => {}
        Err(error) => eprintln!(
            "daemon: failed to inspect pid file {} before cleanup: {error}",
            pid_file.display()
        ),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_service_dispatcher(args: DaemonArgs) -> Result<()> {
    WINDOWS_SERVICE_DAEMON_ARGS
        .set(args)
        .map_err(|_| anyhow!("windows service daemon arguments already initialized"))?;
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_windows_service_main)
        .context("failed to start Windows service dispatcher")
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service() {
        eprintln!("windows service failed: {error:?}");
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_service() -> Result<()> {
    let args = WINDOWS_SERVICE_DAEMON_ARGS
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("windows service launched without daemon arguments"))?;
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let status_handle_cell = std::sync::Arc::new(OnceLock::new());
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, {
        let config_path = config_path.clone();
        let status_handle_cell = std::sync::Arc::clone(&status_handle_cell);
        move |control_event| match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(status_handle) = status_handle_cell.get()
                    && let Err(error) = set_windows_service_status(
                        status_handle,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::Win32(0),
                        1,
                        WINDOWS_SERVICE_STOP_TIMEOUT,
                    )
                {
                    eprintln!("windows service failed to report stop pending: {error}");
                }
                if let Err(error) = request_daemon_stop(&config_path) {
                    eprintln!("windows service failed to request daemon stop: {error}");
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .context("failed to register Windows service control handler")?;
    status_handle_cell
        .set(status_handle)
        .map_err(|_| anyhow!("windows service status handle already initialized"))?;

    set_windows_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        1,
        Duration::from_secs(10),
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for Windows service")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        0,
        Duration::default(),
    )?;

    let result = runtime.block_on(daemon_vpn(args));
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    set_windows_service_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        0,
        Duration::default(),
    )?;
    result
}

#[cfg(target_os = "windows")]
pub(crate) fn set_windows_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> Result<()> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint,
            wait_hint,
            process_id: None,
        })
        .with_context(|| format!("failed to update Windows service status to {state:?}"))
}

pub(crate) fn daemon_peer_state_from_fips_status(
    network_id: &str,
    participant: &str,
    status: Option<&MeshPeerStatus>,
    advertised_routes: Vec<String>,
    now: u64,
    vpn_active: bool,
) -> DaemonPeerState {
    let last_seen_at =
        status.and_then(|status| credible_daemon_peer_timestamp(now, status.last_seen_at));
    let last_control_seen_at = status
        .and_then(|status| credible_daemon_peer_timestamp(now, status.last_control_seen_at));
    let last_data_seen_at =
        status.and_then(|status| credible_daemon_peer_timestamp(now, status.last_data_seen_at));
    let reachable = vpn_active && status.is_some_and(|status| status.connected);
    let fips_transport_addr = status.and_then(|status| status.transport_addr.clone());
    DaemonPeerState {
        participant_pubkey: participant.to_string(),
        node_id: String::new(),
        tunnel_ip: derive_mesh_tunnel_ip(network_id, participant).unwrap_or_default(),
        endpoint: "fips".to_string(),
        runtime_endpoint: fips_transport_addr
            .clone()
            .or_else(|| reachable.then(|| "fips".to_string())),
        fips_endpoint_npub: status
            .map(|status| status.endpoint_npub.clone())
            .unwrap_or_default(),
        fips_transport_addr: fips_transport_addr.unwrap_or_default(),
        fips_transport_type: status
            .and_then(|status| status.transport_type.clone())
            .unwrap_or_default(),
        fips_srtt_ms: status.and_then(|status| status.srtt_ms),
        fips_srtt_age_ms: status.and_then(|status| status.srtt_age_ms),
        fips_packets_sent: status.map(|status| status.link_packets_sent).unwrap_or(0),
        fips_packets_recv: status.map(|status| status.link_packets_recv).unwrap_or(0),
        fips_bytes_sent: status.map(|status| status.link_bytes_sent).unwrap_or(0),
        fips_bytes_recv: status.map(|status| status.link_bytes_recv).unwrap_or(0),
        fips_rekey_in_progress: status.is_some_and(|status| status.rekey_in_progress),
        fips_rekey_draining: status.is_some_and(|status| status.rekey_draining),
        fips_current_k_bit: status.and_then(|status| status.current_k_bit),
        fips_last_outbound_route: status
            .and_then(|status| status.last_outbound_route.clone())
            .unwrap_or_default(),
        direct_probe_pending: status.is_some_and(|status| status.direct_probe_pending),
        direct_probe_after_ms: status.and_then(|status| status.direct_probe_after_ms),
        direct_probe_retry_count: status
            .map(|status| status.direct_probe_retry_count)
            .unwrap_or(0),
        direct_probe_auto_reconnect: status
            .is_some_and(|status| status.direct_probe_auto_reconnect),
        direct_probe_expires_at_ms: status.and_then(|status| status.direct_probe_expires_at_ms),
        fips_nostr_traversal_failures: status
            .map(|status| status.nostr_traversal_consecutive_failures)
            .unwrap_or(0),
        fips_nostr_traversal_in_cooldown: status
            .is_some_and(|status| status.nostr_traversal_in_cooldown),
        fips_nostr_traversal_cooldown_until_ms: status
            .and_then(|status| status.nostr_traversal_cooldown_until_ms),
        fips_nostr_traversal_last_observed_skew_ms: status
            .and_then(|status| status.nostr_traversal_last_observed_skew_ms),
        tx_bytes: status.map(|status| status.tx_bytes).unwrap_or(0),
        rx_bytes: status.map(|status| status.rx_bytes).unwrap_or(0),
        public_key: String::new(),
        advertised_routes,
        last_mesh_seen_at: last_seen_at.unwrap_or(0),
        last_fips_seen_at: last_seen_at,
        last_fips_control_seen_at: last_control_seen_at,
        last_fips_data_seen_at: last_data_seen_at,
        reachable,
        last_handshake_at: last_seen_at,
        error: if reachable {
            None
        } else {
            status
                .and_then(|status| status.error.clone())
                .or_else(|| Some("fips link pending".to_string()))
        },
    }
}

pub(crate) fn build_daemon_runtime_state(input: DaemonRuntimeStateInput<'_>) -> DaemonRuntimeState {
    let DaemonRuntimeStateInput {
        app,
        vpn_enabled,
        vpn_active,
        expected_peers,
        tunnel_runtime,
        fips_peer_statuses,
        fips_relay_statuses,
        fips_endpoint_peers,
        advertised_routes_by_participant,
        vpn_status,
        network,
        port_mapping,
    } = input;

    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let now = unix_timestamp();
    let listen_port = tunnel_runtime.listen_port().unwrap_or_default();
    let local_endpoint = tunnel_runtime
        .listen_port()
        .map(|port| local_signal_endpoint(app, port))
        .unwrap_or_default();
    // Daemon no longer pre-discovers a public endpoint; fips-core advertises
    // its own (and falls back to udp:nat traversal when behind NAT). The
    // advertised_endpoint we surface in state.json is the local-network
    // endpoint, used by other peers on the same LAN.
    let advertised_endpoint = local_endpoint.clone();
    let mut peers = Vec::new();

    let participant_pubkeys_list = app.participant_pubkeys_hex();
    let participant_pubkeys = participant_pubkeys_list
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    let fips_status_by_pubkey = fips_peer_statuses
        .iter()
        .map(|status| (status.pubkey.as_str(), status))
        .collect::<HashMap<_, _>>();
    let network_id = app.effective_network_id();
    for participant in &participant_pubkeys_list {
        if Some(participant.as_str()) == own_pubkey.as_deref() {
            continue;
        }
        let status = if vpn_active {
            fips_status_by_pubkey.get(participant.as_str()).copied()
        } else {
            None
        };
        peers.push(daemon_peer_state_from_fips_status(
            &network_id,
            participant,
            status,
            advertised_routes_by_participant
                .get(participant)
                .cloned()
                .unwrap_or_default(),
            now,
            vpn_active,
        ));
    }

    let connected_peer_count = if !vpn_active {
        0
    } else {
        fips_peer_statuses
            .iter()
            .filter(|status| Some(status.pubkey.as_str()) != own_pubkey.as_deref())
            .filter(|status| participant_pubkeys.contains(&status.pubkey))
            .filter(|status| status.connected)
            .count()
    };
    let fips_direct_roster_peer_count = if !vpn_active {
        0
    } else {
        fips_peer_statuses
            .iter()
            .filter(|status| Some(status.pubkey.as_str()) != own_pubkey.as_deref())
            .filter(|status| participant_pubkeys.contains(&status.pubkey))
            .filter(|status| status.connected)
            .filter(|status| {
                status
                    .transport_addr
                    .as_deref()
                    .is_some_and(|addr| !addr.trim().is_empty())
            })
            .count()
    };
    // Pre-pairing nodes have no active roster yet, but their FIPS transport is
    // already running so an admin can deliver the first signed roster. Keep
    // those non-roster links visible while VPN service is enabled.
    let fips_other_peer_count = if !vpn_enabled {
        0
    } else {
        fips_peer_statuses
            .iter()
            .filter(|status| Some(status.pubkey.as_str()) != own_pubkey.as_deref())
            .filter(|status| !participant_pubkeys.contains(&status.pubkey))
            .filter(|status| status.connected)
            .count()
    };
    let mesh_ready = vpn_active;
    let health = build_health_issues(app, vpn_active, mesh_ready, network, port_mapping, &peers);
    let (open_file_descriptor_count, open_file_descriptor_types) =
        open_file_descriptor_snapshot().unzip();
    DaemonRuntimeState {
        updated_at: now,
        open_file_descriptor_count,
        open_file_descriptor_types,
        open_file_descriptor_soft_limit: open_file_descriptor_soft_limit(),
        binary_version: PRODUCT_VERSION.to_string(),
        fips_core_version: fips_core_build_version(),
        local_endpoint,
        advertised_endpoint,
        listen_port,
        paid_exit_seller_ready: tunnel_runtime.paid_exit_seller_ready,
        wireguard_exit_ready: tunnel_runtime.wireguard_exit_ready,
        vpn_enabled,
        vpn_active,
        vpn_status: vpn_status.to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count,
        fips_direct_roster_peer_count,
        fips_other_peer_count,
        mesh_ready,
        health,
        network: network.clone(),
        port_mapping: port_mapping.clone(),
        relays: fips_relay_statuses.to_vec(),
        fips_endpoint_peers: fips_endpoint_peers.to_vec(),
        peers,
    }
}

pub(crate) fn persist_daemon_runtime_state(
    path: &Path,
    input: DaemonRuntimeStateInput<'_>,
) -> Result<()> {
    write_daemon_state(path, &build_daemon_runtime_state(input))
}

pub(crate) fn persist_daemon_runtime_and_cleanup_state(
    state_file: &Path,
    config_path: &Path,
    input: DaemonRuntimeStateInput<'_>,
) -> bool {
    let persisted = match persist_daemon_runtime_state(state_file, input) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("daemon: failed to persist runtime state: {error}");
            false
        }
    };
    if let Err(error) = persist_daemon_network_cleanup_state(config_path, input.tunnel_runtime) {
        eprintln!("daemon: failed to persist network cleanup state: {error}");
    }
    persisted
}

pub(crate) async fn persist_daemon_runtime_and_cleanup_state_async(
    state_file: &Path,
    config_path: &Path,
    input: DaemonRuntimeStateInput<'_>,
) -> bool {
    let state_file = state_file.to_path_buf();
    let config_path = config_path.to_path_buf();
    let app = input.app.clone();
    let vpn_enabled = input.vpn_enabled;
    let vpn_active = input.vpn_active;
    let expected_peers = input.expected_peers;
    let tunnel_runtime = input.tunnel_runtime.clone();
    let fips_peer_statuses = input.fips_peer_statuses.to_vec();
    let fips_relay_statuses = input.fips_relay_statuses.to_vec();
    let fips_endpoint_peers = input.fips_endpoint_peers.to_vec();
    let advertised_routes_by_participant = input.advertised_routes_by_participant.clone();
    let vpn_status = input.vpn_status.to_string();
    let network = input.network.clone();
    let port_mapping = input.port_mapping.clone();

    match tokio::task::spawn_blocking(move || {
        persist_daemon_runtime_and_cleanup_state(
            &state_file,
            &config_path,
            DaemonRuntimeStateInput {
                app: &app,
                vpn_enabled,
                vpn_active,
                expected_peers,
                tunnel_runtime: &tunnel_runtime,
                fips_peer_statuses: &fips_peer_statuses,
                fips_relay_statuses: &fips_relay_statuses,
                fips_endpoint_peers: &fips_endpoint_peers,
                advertised_routes_by_participant: &advertised_routes_by_participant,
                vpn_status: &vpn_status,
                network: &network,
                port_mapping: &port_mapping,
            },
        )
    })
    .await
    {
        Ok(persisted) => persisted,
        Err(error) => {
            eprintln!("daemon: runtime state persistence task failed: {error}");
            false
        }
    }
}

pub(crate) fn disconnected_daemon_runtime_state(
    expected_peers: usize,
    network: &NetworkSummary,
) -> DaemonRuntimeState {
    let (open_file_descriptor_count, open_file_descriptor_types) =
        open_file_descriptor_snapshot().unzip();
    DaemonRuntimeState {
        updated_at: unix_timestamp(),
        open_file_descriptor_count,
        open_file_descriptor_types,
        open_file_descriptor_soft_limit: open_file_descriptor_soft_limit(),
        binary_version: PRODUCT_VERSION.to_string(),
        fips_core_version: fips_core_build_version(),
        local_endpoint: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        paid_exit_seller_ready: false,
        wireguard_exit_ready: false,
        vpn_enabled: false,
        vpn_active: false,
        vpn_status: "Disconnected".to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count: 0,
        fips_direct_roster_peer_count: 0,
        fips_other_peer_count: 0,
        mesh_ready: false,
        health: Vec::new(),
        network: network.clone(),
        port_mapping: PortMappingStatus::default(),
        relays: Vec::new(),
        fips_endpoint_peers: Vec::new(),
        peers: Vec::new(),
    }
}

pub(crate) fn cleanup_failed_daemon_runtime_state(
    expected_peers: usize,
    network: &NetworkSummary,
    failures: &[String],
) -> DaemonRuntimeState {
    let mut state = disconnected_daemon_runtime_state(expected_peers, network);
    state.vpn_status = "Cleanup failed".to_string();
    state.health.push(HealthIssue::new(
        "network_cleanup_failed",
        HealthSeverity::Critical,
        "Network cleanup failed",
        format!(
            "{} Run `nvpn repair-network` before reconnecting.",
            failures.join("; ")
        ),
    ));
    state
}

pub(crate) fn transition_daemon_state_after_network_repair(config_path: &Path) -> Result<()> {
    let state_file = daemon_state_file_path(config_path);
    let previous = read_daemon_state(&state_file)?;
    let expected_peers = previous
        .as_ref()
        .map_or(0, |state| state.expected_peer_count);
    let network = previous
        .as_ref()
        .map_or_else(NetworkSummary::default, |state| state.network.clone());
    write_daemon_state(
        &state_file,
        &disconnected_daemon_runtime_state(expected_peers, &network),
    )
    .context("failed to record repaired disconnected daemon state")
}
