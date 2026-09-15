use super::*;

pub(super) struct DaemonVpnStartup {
    pub(super) config_path: PathBuf,
    pub(super) _instance_lock: DaemonInstanceLock,
    pub(super) pid_file: PathBuf,
    pub(super) network_override: Option<String>,
    pub(super) participants_override: Vec<String>,
    pub(super) app: AppConfig,
    pub(super) network_id: String,
    pub(super) own_pubkey: Option<String>,
    pub(super) expected_peers: usize,
    pub(super) state_file: PathBuf,
    pub(super) recent_peers_path: PathBuf,
    pub(super) recent_peers: nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    pub(super) fips_join_request_sends: HashMap<String, u64>,
    pub(super) pending_fips_roster_recipients: HashSet<String>,
    pub(super) fips_roster_sync_state: FipsRosterSyncState,
    pub(super) last_fips_stale_participant_restart_at: Option<u64>,
    pub(super) fips_pending_roster_restart_state: FipsPendingRosterRestartState,
    pub(super) iface: String,
    pub(super) ethernet_underlay: Option<crate::fips_private_mesh::FipsEthernetUnderlayConfig>,
    pub(super) tunnel_runtime: CliTunnelRuntime,
    pub(super) network_snapshot: crate::diagnostics::NetworkSnapshot,
    pub(super) network_changed_at: Option<u64>,
    pub(super) captive_portal: Option<bool>,
    pub(super) timeout: Duration,
    pub(super) port_mapping_runtime: PortMappingRuntime,
    pub(super) vpn_enabled: bool,
    pub(super) fips_tunnel_runtime: Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    pub(super) last_fips_endpoint_peer_signature: EndpointPeerSignature,
}

pub(super) fn daemon_service_supervisor_requests_restart(
    executable: Option<&(PathBuf, ExecutableFingerprint)>,
) -> bool {
    let Some((executable, launched_fingerprint)) = executable else {
        return false;
    };
    match service_supervisor_restart_due(executable, launched_fingerprint) {
        Ok(true) => {
            eprintln!(
                "daemon: service executable changed on disk; exiting so the supervisor restarts the updated binary"
            );
            true
        }
        Ok(false) => false,
        Err(error) => {
            eprintln!("daemon: failed to check service executable fingerprint: {error}");
            false
        }
    }
}

pub(super) async fn initialize_daemon_vpn(args: &DaemonArgs) -> Result<DaemonVpnStartup> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }
    let ethernet_underlay = match (
        args.fips_ethernet_interface.as_deref(),
        args.fips_ethernet_discovery_scope.as_deref(),
    ) {
        (Some(interface), Some(scope)) => Some(
            crate::fips_private_mesh::FipsEthernetUnderlayConfig::parse(interface, scope)?,
        ),
        (None, None) => None,
        _ => {
            return Err(anyhow!(
                "--fips-ethernet-interface and --fips-ethernet-discovery-scope must be provided together"
            ));
        }
    };

    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let instance_lock =
        acquire_daemon_instance_lock_for_daemon(&config_path, args.daemon_instance.as_deref())?;
    if args.service
        && let Err(error) = redirect_stdio_to_daemon_log(&config_path)
    {
        eprintln!("daemon: failed to redirect service log: {error}");
    }
    if let Err(error) = compact_daemon_log_if_needed(&config_path) {
        eprintln!("daemon: failed to compact service log: {error}");
    }
    #[cfg(any(target_os = "macos", test))]
    crate::ensure_macos_connect_privileges(&config_path)?;
    #[cfg(not(target_os = "windows"))]
    ensure_no_other_daemon_processes_for_config(&config_path, std::process::id())?;
    clear_daemon_control_ready(&config_path);
    if repair_saved_network_state(&config_path)
        .context("daemon startup refused while saved network cleanup remains incomplete")?
    {
        transition_daemon_state_after_network_repair(&config_path)?;
    }
    let pid_file = daemon_pid_file_path(&config_path);
    if let Err(error) = write_daemon_pid_record(
        &pid_file,
        &DaemonPidRecord {
            pid: std::process::id(),
            config_path: config_path.display().to_string(),
            started_at: unix_timestamp(),
        },
    ) {
        eprintln!(
            "daemon: failed to write pid file {}: {error}",
            pid_file.display()
        );
    }
    let network_override = args.network_id.clone();
    let participants_override = args.devices.clone();
    let (mut app, network_id) = load_config_with_overrides(
        &config_path,
        network_override.clone(),
        participants_override.clone(),
        ConfigLoadMode::Persist,
    )?;
    if !args.fips_websocket_seed_urls.is_empty() {
        app.fips_websocket_seed_urls = args.fips_websocket_seed_urls.clone();
    }
    if let Some(bind_addr) = args.fips_websocket_bind.as_deref() {
        app.fips_websocket_bind_addr = bind_addr.trim().to_string();
    }
    if let Some(public_url) = args.fips_websocket_public_url.as_deref() {
        app.fips_websocket_public_url = public_url.to_string();
    }
    app.ensure_defaults();
    #[cfg(unix)]
    app.clear_pending_nostr_join_request();
    if app.ensure_pending_nostr_join_request(unix_timestamp())? {
        // Desktop Unix keeps this request only in the daemon's in-memory `app`;
        // AppConfig::save strips it from disk and deletes any legacy secret.
        app.save(&config_path)?;
    }
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let recent_peers_local_npub = own_pubkey
        .as_deref()
        .map(nostr_vpn_core::config::npub_for_pubkey_hex)
        .ok_or_else(|| anyhow!("could not derive local npub for recent peers cache"))?;
    let recent_peers_scope = nostr_vpn_core::recent_peers::recent_peers_scope(&network_id);
    let expected_peers = expected_peer_count(&app);
    let state_file = daemon_state_file_path(&config_path);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    let recent_peers_path = crate::recent_peers_store::recent_peers_file_path(&config_path);
    let recent_peers = match crate::recent_peers_store::load_recent_peers(
        &recent_peers_path,
        &recent_peers_local_npub,
        &recent_peers_scope,
        unix_timestamp(),
    ) {
        Ok(state) => state,
        Err(error) => {
            eprintln!(
                "daemon: failed to load recent peers cache {}: {error}",
                recent_peers_path.display()
            );
            nostr_vpn_core::recent_peers::RecentPeerEndpoints::new(
                &recent_peers_local_npub,
                &recent_peers_scope,
            )?
        }
    };
    let fips_join_request_sends = HashMap::new();
    let pending_fips_roster_recipients = HashSet::new();
    let fips_roster_sync_state = FipsRosterSyncState::default();
    let last_fips_stale_participant_restart_at = None;
    let fips_pending_roster_restart_state = FipsPendingRosterRestartState::default();
    let iface = args.iface.clone();
    let mut tunnel_runtime = CliTunnelRuntime::new(iface.clone());
    let network_snapshot = capture_network_snapshot();
    let network_changed_at = Some(unix_timestamp());
    let timeout = network_probe_timeout(&app);
    // A guest with only a raw Ethernet underlay has no Internet route until
    // FIPS starts. Probing now only waits for DNS timeouts and delays the mesh.
    let captive_portal = if network_snapshot.default_interface.is_some() {
        detect_captive_portal(timeout).await
    } else {
        None
    };
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let vpn_enabled = daemon_start_vpn_enabled(&app, args.paused);
    let (fips_tunnel_runtime, last_fips_endpoint_peer_signature) =
        if fips_private_runtime_active_for_config(&app, &config_path, vpn_enabled, expected_peers)?
        {
            let mut config = match fips_tunnel_config_from_app(FipsTunnelConfigInput {
                app: &app,
                config_path: &config_path,
                network_id: &network_id,
                iface: iface.clone(),
                underlay_interface: network_snapshot.default_interface.as_deref(),
                underlay_interface_mtu: network_snapshot.default_interface_mtu,
                own_pubkey: own_pubkey.as_deref(),
                recent_peers: Some(&recent_peers),
                live_peer_endpoints: &[],
                ethernet_underlay: ethernet_underlay.as_ref(),
            }) {
                Ok(config) => config,
                Err(error) => {
                    let network = network_snapshot.summary(network_changed_at, captive_portal);
                    let port_mapping = port_mapping_runtime.status();
                    let advertised_routes = HashMap::new();
                    let vpn_status = format!("FIPS private mesh config failed ({error})");
                    persist_daemon_startup_failure_state(
                        &state_file,
                        DaemonRuntimeStateInput {
                            app: &app,
                            vpn_enabled,
                            vpn_active: false,
                            expected_peers,
                            tunnel_runtime: &tunnel_runtime,
                            fips_peer_statuses: &[],
                            fips_relay_statuses: &[],
                            fips_endpoint_peers: &[],
                            advertised_routes_by_participant: &advertised_routes,
                            vpn_status: &vpn_status,
                            network: &network,
                            port_mapping: &port_mapping,
                        },
                    );
                    return Err(error);
                }
            };
            if !vpn_enabled {
                config.disable_client_dataplane();
            }
            let seeded_endpoint_count = config
                .endpoint_peers
                .iter()
                .flat_map(|peer| peer.addresses.iter())
                .filter(|addr| addr.seen_at_ms.is_some())
                .count();
            let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);
            let endpoint_peer_states =
                daemon_endpoint_peer_states_from_signature(&endpoint_peer_signature);
            let runtime = match start_fips_private_tunnel_runtime(&config_path, config).await {
                Ok(runtime) => runtime,
                Err(error) => {
                    let network = network_snapshot.summary(network_changed_at, captive_portal);
                    let port_mapping = port_mapping_runtime.status();
                    let advertised_routes = HashMap::new();
                    let vpn_status = format!("FIPS private mesh startup failed ({error})");
                    persist_daemon_startup_failure_state(
                        &state_file,
                        DaemonRuntimeStateInput {
                            app: &app,
                            vpn_enabled,
                            vpn_active: false,
                            expected_peers,
                            tunnel_runtime: &tunnel_runtime,
                            fips_peer_statuses: &[],
                            fips_relay_statuses: &[],
                            fips_endpoint_peers: &endpoint_peer_states,
                            advertised_routes_by_participant: &advertised_routes,
                            vpn_status: &vpn_status,
                            network: &network,
                            port_mapping: &port_mapping,
                        },
                    );
                    return Err(error);
                }
            };
            eprintln!(
                "daemon: FIPS private mesh on {} (seeded {} recently-connected peer endpoint(s))",
                runtime.iface(),
                seeded_endpoint_count,
            );
            (Some(runtime), endpoint_peer_signature)
        } else {
            (None, Vec::new())
        };

    tunnel_runtime.sync_fips_state(fips_tunnel_runtime.as_ref());
    if daemon_vpn_active(vpn_enabled, expected_peers)
        && let Some(listen_port) = tunnel_runtime.active_listen_port
    {
        refresh_port_mapping(
            &app,
            &network_snapshot,
            listen_port,
            &mut port_mapping_runtime,
        )
        .await;
    }

    Ok(DaemonVpnStartup {
        config_path,
        _instance_lock: instance_lock,
        pid_file,
        network_override,
        participants_override,
        app,
        network_id,
        own_pubkey,
        expected_peers,
        state_file,
        recent_peers_path,
        recent_peers,
        fips_join_request_sends,
        pending_fips_roster_recipients,
        fips_roster_sync_state,
        last_fips_stale_participant_restart_at,
        fips_pending_roster_restart_state,
        iface,
        ethernet_underlay,
        tunnel_runtime,
        network_snapshot,
        network_changed_at,
        captive_portal,
        timeout,
        port_mapping_runtime,
        vpn_enabled,
        fips_tunnel_runtime,
        last_fips_endpoint_peer_signature,
    })
}

pub(super) fn daemon_refresh_intervals(
    args: &DaemonArgs,
) -> (tokio::time::Interval, tokio::time::Interval) {
    let mesh_refresh_interval = Duration::from_secs(args.mesh_refresh_interval_secs.max(5));
    let mut announce_interval = tokio::time::interval(mesh_refresh_interval);
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut recent_peer_refresh_interval = tokio::time::interval(mesh_refresh_interval);
    recent_peer_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    (announce_interval, recent_peer_refresh_interval)
}

pub(super) struct DaemonVpnLoopState {
    pub(super) vpn_status: String,
    pub(super) last_log_compact_check: Instant,
    pub(super) last_state_persisted_at: Instant,
    pub(super) daemon_state_persist_interval: Duration,
    pub(super) platform_network_event_pending: bool,
    pub(super) platform_network_settle_rechecks_remaining: u8,
    pub(super) supervised_service_executable: Option<(PathBuf, ExecutableFingerprint)>,
}

pub(super) async fn initialize_daemon_vpn_loop(
    _args: &DaemonArgs,
    startup: &DaemonVpnStartup,
) -> Result<DaemonVpnLoopState> {
    let vpn_status = if !daemon_vpn_active(startup.vpn_enabled, startup.expected_peers) {
        daemon_vpn_idle_status(
            startup.vpn_enabled,
            startup.expected_peers,
            startup.app.join_requests_enabled(),
        )
        .to_string()
    } else {
        "VPN on".to_string()
    };
    let last_log_compact_check = Instant::now();
    let fips_peer_statuses = startup
        .fips_tunnel_runtime
        .as_ref()
        .map(|runtime| runtime.peer_statuses())
        .unwrap_or_default();
    let fips_relay_statuses = current_fips_relay_statuses!(&startup.fips_tunnel_runtime).await;
    let fips_endpoint_peer_states =
        current_fips_endpoint_peer_states!(&startup.last_fips_endpoint_peer_signature);
    let fips_advertised_routes =
        current_fips_advertised_routes!(startup.fips_tunnel_runtime, &startup.app);
    let network = startup
        .network_snapshot
        .summary(startup.network_changed_at, startup.captive_portal);
    let port_mapping = startup.port_mapping_runtime.status();
    write_daemon_state(
        &startup.state_file,
        &build_daemon_runtime_state(DaemonRuntimeStateInput {
            app: &startup.app,
            vpn_enabled: startup.vpn_enabled,
            vpn_active: daemon_vpn_active(startup.vpn_enabled, startup.expected_peers),
            expected_peers: startup.expected_peers,
            tunnel_runtime: &startup.tunnel_runtime,
            fips_peer_statuses: &fips_peer_statuses,
            fips_relay_statuses: &fips_relay_statuses,
            fips_endpoint_peers: &fips_endpoint_peer_states,
            advertised_routes_by_participant: &fips_advertised_routes,
            vpn_status: &vpn_status,
            network: &network,
            port_mapping: &port_mapping,
        }),
    )?;
    let last_state_persisted_at = Instant::now();
    let daemon_state_persist_interval = Duration::from_secs(DAEMON_STATE_PERSIST_INTERVAL_SECS);
    let platform_network_event_pending = false;
    let platform_network_settle_rechecks_remaining = 0;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let supervised_service_executable = if _args.service {
        Some(current_executable_fingerprint()?)
    } else {
        None
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let supervised_service_executable: Option<(PathBuf, ExecutableFingerprint)> = None;

    Ok(DaemonVpnLoopState {
        vpn_status,
        last_log_compact_check,
        last_state_persisted_at,
        daemon_state_persist_interval,
        platform_network_event_pending,
        platform_network_settle_rechecks_remaining,
        supervised_service_executable,
    })
}
