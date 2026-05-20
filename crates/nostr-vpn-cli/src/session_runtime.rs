use super::*;

const DAEMON_STATE_PERSIST_INTERVAL_SECS: u64 = 5;

#[cfg(feature = "embedded-fips")]
macro_rules! current_fips_peer_statuses {
    ($runtime:expr) => {
        $runtime
            .as_ref()
            .map(|runtime| runtime.peer_statuses())
            .unwrap_or_default()
    };
}

#[cfg(not(feature = "embedded-fips"))]
macro_rules! current_fips_peer_statuses {
    ($runtime:expr) => {
        Vec::<MeshPeerStatus>::new()
    };
}

#[cfg(feature = "embedded-fips")]
async fn current_fips_relay_statuses(
    runtime: &Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
) -> Vec<DaemonRelayState> {
    let Some(runtime) = runtime.as_ref() else {
        return Vec::new();
    };
    match runtime.relay_statuses().await {
        Ok(relays) => relays
            .into_iter()
            .map(|relay| DaemonRelayState {
                url: relay.url,
                status: relay.status,
            })
            .collect(),
        Err(error) => {
            eprintln!("fips: relay status snapshot failed: {error}");
            Vec::new()
        }
    }
}

#[cfg(not(feature = "embedded-fips"))]
async fn current_fips_relay_statuses<T>(_runtime: &Option<T>) -> Vec<DaemonRelayState> {
    Vec::new()
}

#[cfg(feature = "embedded-fips")]
macro_rules! current_fips_advertised_routes {
    ($runtime:expr, $app:expr) => {
        $runtime
            .as_ref()
            .map(|runtime| {
                let mut map = std::collections::HashMap::<String, Vec<String>>::new();
                for participant in $app.participant_pubkeys_hex() {
                    let routes = runtime.peer_advertised_routes(&participant);
                    if !routes.is_empty() {
                        map.insert(participant, routes);
                    }
                }
                map
            })
            .unwrap_or_default()
    };
}

#[cfg(not(feature = "embedded-fips"))]
macro_rules! current_fips_advertised_routes {
    ($runtime:expr, $app:expr) => {
        std::collections::HashMap::<String, Vec<String>>::new()
    };
}

#[cfg(feature = "embedded-fips")]
fn fips_peer_count(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_statuses: &[MeshPeerStatus],
) -> usize {
    let participant_pubkeys = app
        .participant_pubkeys_hex()
        .into_iter()
        .collect::<HashSet<_>>();
    peer_statuses
        .iter()
        .filter(|status| Some(status.pubkey.as_str()) != own_pubkey)
        .filter(|status| participant_pubkeys.contains(&status.pubkey))
        .filter(|status| status.connected)
        .count()
}

#[cfg(feature = "embedded-fips")]
fn maybe_log_fips_mesh_count(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_statuses: &[MeshPeerStatus],
    expected_peers: usize,
    last_mesh_count: &mut usize,
) {
    let connected = fips_peer_count(app, own_pubkey, peer_statuses);
    if connected != *last_mesh_count {
        println!("mesh: {connected}/{expected_peers} peers connected");
        *last_mesh_count = connected;
    }
}

#[cfg(feature = "embedded-fips")]
async fn flush_pending_fips_roster_recipients(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    pending_recipients: &mut HashSet<String>,
) {
    if pending_recipients.is_empty() {
        return;
    }
    match publish_fips_active_network_roster(runtime, app, pending_recipients).await {
        Ok(_) => {}
        Err(error) => eprintln!("fips: queued roster publish failed: {error}"),
    }
}

#[cfg(feature = "embedded-fips")]
type EndpointPeerSignature = Vec<(String, Vec<String>)>;

#[cfg(feature = "embedded-fips")]
struct RecentPeerRefresh<'a> {
    recent_peers: &'a mut nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    recent_peers_path: &'a std::path::Path,
    last_endpoint_peer_signature: &'a mut EndpointPeerSignature,
}

#[cfg(feature = "embedded-fips")]
fn endpoint_peer_signature(
    endpoint_peers: &[crate::fips_private_mesh::FipsEndpointPeerTransportConfig],
) -> EndpointPeerSignature {
    endpoint_peers
        .iter()
        .map(|peer| {
            let mut addresses = peer
                .addresses
                .iter()
                .map(|hint| hint.addr.clone())
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            (peer.npub.clone(), addresses)
        })
        .collect()
}

/// Snapshot the runtime's authenticated peer transport addresses, update
/// the on-disk recent-peers cache, and hand fips the refreshed peer hint
/// list via `update_peers` so new direct candidates race the existing ones
/// in the next dial cycle without restarting the endpoint. Public (non-LAN)
/// endpoints get rotated into the cache, including authenticated non-roster
/// transit peers; mesh-carried live hints can include LAN endpoints but stay
/// in memory only.
#[cfg(feature = "embedded-fips")]
async fn update_recent_peers_from_runtime(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &nostr_vpn_core::config::AppConfig,
    network_id: &str,
    own_pubkey: Option<&str>,
    refresh: RecentPeerRefresh<'_>,
    now: u64,
) {
    let snapshot = match runtime.authenticated_peer_transport_addrs().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("fips: peer endpoint snapshot failed: {error}");
            Vec::new()
        }
    };
    let mut changed = false;
    for (participant, addr) in snapshot {
        if refresh.recent_peers.note_success(&participant, &addr, now) {
            changed = true;
        }
    }
    if refresh
        .recent_peers
        .prune_stale(now, crate::recent_peers_store::RECENT_PEERS_TTL_SECS)
    {
        changed = true;
    }
    if changed
        && let Err(error) = crate::recent_peers_store::write_recent_peers(
            refresh.recent_peers_path,
            refresh.recent_peers,
        )
    {
        eprintln!(
            "daemon: failed to write recent peers cache {}: {error}",
            refresh.recent_peers_path.display()
        );
    }
    let live_peer_endpoints = runtime.peer_endpoint_hints();
    match crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app(
        app,
        network_id,
        runtime.iface().to_string(),
        own_pubkey,
        Some(refresh.recent_peers),
        &live_peer_endpoints,
    ) {
        Ok(refreshed) => {
            let signature = endpoint_peer_signature(&refreshed.endpoint_peers);
            if signature == *refresh.last_endpoint_peer_signature {
                return;
            }
            if let Err(error) = runtime.update_peers(&refreshed.endpoint_peers).await {
                eprintln!("fips: update_peers (cache refresh) failed: {error}");
            } else {
                *refresh.last_endpoint_peer_signature = signature;
            }
        }
        Err(error) => {
            eprintln!("fips: rebuilding peer hint list failed: {error}");
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn reset_tunnel_runtime_after_macos_underlay_repair(
    tunnel_runtime: &mut CliTunnelRuntime,
) {
    tunnel_runtime.stop();
}

#[cfg(not(any(target_os = "macos", test)))]
pub(crate) fn reset_tunnel_runtime_after_macos_underlay_repair(
    _tunnel_runtime: &mut CliTunnelRuntime,
) {
}

fn prefer_nonself_tunnel_snapshot(
    tunnel_runtime: &CliTunnelRuntime,
    previous: &crate::diagnostics::NetworkSnapshot,
    latest: crate::diagnostics::NetworkSnapshot,
) -> crate::diagnostics::NetworkSnapshot {
    let latest = crate::diagnostics::prefer_nonempty_network_snapshot(previous, latest);
    match latest.default_interface.as_deref() {
        Some(iface) if tunnel_runtime.owns_interface(iface) => previous.clone(),
        _ => latest,
    }
}

async fn capture_network_snapshot_for_daemon() -> crate::diagnostics::NetworkSnapshot {
    match tokio::task::spawn_blocking(capture_network_snapshot).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("daemon: network snapshot task failed: {error}");
            crate::diagnostics::NetworkSnapshot::default()
        }
    }
}

#[cfg(target_os = "macos")]
async fn ensure_macos_underlay_default_route_for_daemon() -> Result<bool> {
    tokio::task::spawn_blocking(crate::macos_network::ensure_macos_underlay_default_route)
        .await
        .context("macOS underlay route check task failed")?
}

pub(crate) async fn connect_vpn(args: ConnectArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.unwrap_or_else(default_config_path);
    #[cfg(any(target_os = "macos", test))]
    crate::ensure_macos_connect_privileges(&config_path)?;
    #[cfg(target_os = "macos")]
    if let Err(error) = repair_saved_network_state(&config_path) {
        eprintln!("connect: failed to repair saved macOS network state: {error}");
    }
    #[cfg(target_os = "macos")]
    match crate::macos_network::ensure_macos_underlay_default_route() {
        Ok(true) => eprintln!("connect: restored missing macOS underlay default route"),
        Ok(false) => {}
        Err(error) => eprintln!("connect: failed to ensure macOS underlay default route: {error}"),
    }
    let (app, network_id) =
        load_config_with_overrides(&config_path, args.network_id, args.participants)?;
    let configured_participants = app.participant_pubkeys_hex();
    if configured_participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running connect"
        ));
    }
    #[cfg(not(feature = "embedded-fips"))]
    {
        return Err(anyhow!(
            "embedded FIPS private mesh requires building nvpn with the embedded-fips feature"
        ));
    }

    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let expected_peers = expected_peer_count(&app);
    let iface = args.iface.clone();
    let network_snapshot = capture_network_snapshot();
    let mut port_mapping_runtime = PortMappingRuntime::default();
    refresh_port_mapping(
        &app,
        &network_snapshot,
        app.node.listen_port,
        &mut port_mapping_runtime,
    )
    .await;
    #[cfg(feature = "embedded-fips")]
    crate::fips_private_mesh::purge_legacy_fips_endpoint_cache(&config_path);
    #[cfg(feature = "embedded-fips")]
    let mut fips_tunnel_runtime = {
        let config = fips_tunnel_config_from_app(
            &app,
            &network_id,
            iface.clone(),
            own_pubkey.as_deref(),
            None,
            &[],
        )?;
        let runtime = crate::fips_private_mesh::FipsPrivateTunnelRuntime::start(config).await?;
        println!("connect: FIPS private mesh on {}", runtime.iface());
        Some(runtime)
    };
    // Foreground `nvpn connect` does not consume FIPS roster events nor the
    // daemon control channel, so the MagicDNS records can't change during
    // its lifetime — the underscore prefix keeps the responder alive until
    // session shutdown without triggering an unused-binding warning.
    let _magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);

    println!(
        "connect: network {network_id} using FIPS private mesh; waiting for {expected_peers} configured peer(s)"
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.mesh_refresh_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    #[cfg(feature = "embedded-fips")]
    let mut pending_fips_roster_recipients: HashSet<String> = HashSet::new();

    let mut last_mesh_count = 0_usize;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tunnel_heartbeat_interval.tick() => {
                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_mut() {
                    let now = unix_timestamp();
                    if let Err(error) = runtime.ping_peers(&network_id, now).await {
                        eprintln!("fips: peer ping failed: {error}");
                    }
                    if let Err(error) = runtime.refresh_link_statuses().await {
                        eprintln!("fips: peer link snapshot failed: {error}");
                    }
                    flush_pending_fips_roster_recipients(
                        runtime,
                        &app,
                        &mut pending_fips_roster_recipients,
                    )
                    .await;
                    let _ = runtime.drain_events();
                    if let Err(error) = runtime.refresh_peer_dependent_routes().await {
                        eprintln!("fips: peer route refresh failed: {error}");
                    }
                    maybe_log_fips_mesh_count(
                        &app,
                        own_pubkey.as_deref(),
                        &runtime.peer_statuses(),
                        expected_peers,
                        &mut last_mesh_count,
                    );
                }
            }
            _ = announce_interval.tick() => {
                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                    if let Err(error) = publish_fips_active_network_roster(
                        runtime,
                        &app,
                        &mut pending_fips_roster_recipients,
                    ).await {
                        eprintln!("fips: roster publish failed: {error}");
                    }
                    if let Err(error) = broadcast_local_fips_capabilities(runtime, &app).await {
                        eprintln!("fips: capabilities broadcast failed: {error}");
                    }
                }
            }
        }
    }

    port_mapping_runtime.stop().await;
    #[cfg(feature = "embedded-fips")]
    if let Some(runtime) = fips_tunnel_runtime
        && let Err(error) = runtime.stop().await
    {
        eprintln!("connect: failed to stop FIPS private mesh: {error}");
    }
    println!("connect: disconnected");

    Ok(())
}

pub(crate) async fn daemon_vpn(args: DaemonArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.clone().unwrap_or_else(default_config_path);
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
    ensure_no_other_daemon_processes_for_config(&config_path, std::process::id())?;
    #[cfg(target_os = "macos")]
    if let Err(error) = repair_saved_network_state(&config_path) {
        eprintln!("daemon: failed to repair saved macOS network state: {error}");
    }
    #[cfg(target_os = "macos")]
    match crate::macos_network::ensure_macos_underlay_default_route() {
        Ok(true) => eprintln!("daemon: restored missing macOS underlay default route"),
        Ok(false) => {}
        Err(error) => eprintln!("daemon: failed to ensure macOS underlay default route: {error}"),
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
    let participants_override = args.participants.clone();
    let (mut app, mut network_id) = load_config_with_overrides(
        &config_path,
        network_override.clone(),
        participants_override.clone(),
    )?;
    let mut own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut expected_peers = expected_peer_count(&app);
    #[cfg(not(feature = "embedded-fips"))]
    {
        return Err(anyhow!(
            "embedded FIPS private mesh requires building nvpn with the embedded-fips feature"
        ));
    }
    let state_file = daemon_state_file_path(&config_path);
    #[cfg(feature = "embedded-fips")]
    crate::fips_private_mesh::purge_legacy_fips_endpoint_cache(&config_path);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    #[cfg(feature = "embedded-fips")]
    let recent_peers_path = crate::recent_peers_store::recent_peers_file_path(&config_path);
    #[cfg(feature = "embedded-fips")]
    let mut recent_peers =
        match crate::recent_peers_store::load_recent_peers(&recent_peers_path, unix_timestamp()) {
            Ok(state) => state,
            Err(error) => {
                eprintln!(
                    "daemon: failed to load recent peers cache {}: {error}",
                    recent_peers_path.display()
                );
                nostr_vpn_core::recent_peers::RecentPeerEndpoints::default()
            }
        };
    #[cfg(feature = "embedded-fips")]
    let mut fips_join_request_sends: HashMap<String, u64> = HashMap::new();
    #[cfg(feature = "embedded-fips")]
    let mut pending_fips_roster_recipients: HashSet<String> = HashSet::new();
    let iface = args.iface.clone();
    let mut tunnel_runtime = CliTunnelRuntime::new(iface.clone());
    let mut network_snapshot = capture_network_snapshot();
    let mut network_changed_at = Some(unix_timestamp());
    let timeout = network_probe_timeout(&app);
    let mut captive_portal = detect_captive_portal(timeout).await;
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let mut vpn_enabled = !args.paused;
    if daemon_vpn_active(vpn_enabled, expected_peers) {
        refresh_port_mapping(
            &app,
            &network_snapshot,
            app.node.listen_port,
            &mut port_mapping_runtime,
        )
        .await;
    }
    #[cfg(feature = "embedded-fips")]
    let (mut fips_tunnel_runtime, mut last_fips_endpoint_peer_signature) =
        if fips_private_runtime_active(&app, vpn_enabled, expected_peers) {
            let seeded_endpoint_count = recent_peers
                .as_static_peer_endpoints_with_seen_at()
                .iter()
                .map(|(_, eps)| eps.len())
                .sum::<usize>();
            let config = fips_tunnel_config_from_app(
                &app,
                &network_id,
                iface.clone(),
                own_pubkey.as_deref(),
                Some(&recent_peers),
                &[],
            )?;
            let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);
            let runtime = crate::fips_private_mesh::FipsPrivateTunnelRuntime::start(config).await?;
            eprintln!(
                "daemon: FIPS private mesh on {} (seeded {} recently-connected peer endpoint(s))",
                runtime.iface(),
                seeded_endpoint_count,
            );
            (Some(runtime), endpoint_peer_signature)
        } else {
            (None, Vec::new())
        };
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);

    let mesh_refresh_interval = Duration::from_secs(args.mesh_refresh_interval_secs.max(5));
    let mut announce_interval = tokio::time::interval(mesh_refresh_interval);
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut recent_peer_refresh_interval = tokio::time::interval(mesh_refresh_interval);
    recent_peer_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut state_interval = tokio::time::interval(Duration::from_secs(1));
    state_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut network_interval = tokio::time::interval(Duration::from_secs(5));
    network_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    #[cfg(unix)]
    let mut terminate_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
    #[cfg(unix)]
    let terminate_wait = async move {
        let _ = terminate_signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate_wait = std::future::pending::<()>();
    tokio::pin!(terminate_wait);

    let mut vpn_status = if !daemon_vpn_active(vpn_enabled, expected_peers) {
        daemon_vpn_idle_status(vpn_enabled, expected_peers, app.join_requests_enabled()).to_string()
    } else {
        "VPN on".to_string()
    };
    let mut last_network_check_at = WallTimeJumpObserver::new(unix_timestamp());
    let mut last_log_compact_check = Instant::now();
    #[cfg(feature = "embedded-fips")]
    let fips_peer_statuses = fips_tunnel_runtime
        .as_ref()
        .map(|runtime| runtime.peer_statuses())
        .unwrap_or_default();
    #[cfg(not(feature = "embedded-fips"))]
    let fips_peer_statuses = Vec::new();
    let fips_relay_statuses = current_fips_relay_statuses(&fips_tunnel_runtime).await;
    let fips_advertised_routes = current_fips_advertised_routes!(fips_tunnel_runtime, &app);
    write_daemon_state(
        &state_file,
        &build_daemon_runtime_state(
            &app,
            vpn_enabled,
            daemon_vpn_active(vpn_enabled, expected_peers),
            expected_peers,
            &tunnel_runtime,
            &fips_peer_statuses,
            &fips_relay_statuses,
            &fips_advertised_routes,
            &vpn_status,
            &network_snapshot.summary(network_changed_at, captive_portal),
            &port_mapping_runtime.status(),
        ),
    )?;
    let mut last_state_persisted_at = Instant::now();
    let daemon_state_persist_interval = Duration::from_secs(DAEMON_STATE_PERSIST_INTERVAL_SECS);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let supervised_service_executable = if args.service {
        Some(current_executable_fingerprint()?)
    } else {
        None
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let supervised_service_executable: Option<(PathBuf, ExecutableFingerprint)> = None;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = &mut terminate_wait => {
                break;
            }
            _ = announce_interval.tick() => {
                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                    if let Err(error) = publish_fips_active_network_roster(
                        runtime,
                        &app,
                        &mut pending_fips_roster_recipients,
                    ).await {
                        eprintln!("fips: roster publish failed: {error}");
                    }
                    if let Err(error) = broadcast_local_fips_capabilities(runtime, &app).await {
                        eprintln!("fips: capabilities broadcast failed: {error}");
                    }
                }
            }
            _ = recent_peer_refresh_interval.tick() => {
                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                    update_recent_peers_from_runtime(
                        runtime,
                        &app,
                        &network_id,
                        own_pubkey.as_deref(),
                        RecentPeerRefresh {
                            recent_peers: &mut recent_peers,
                            recent_peers_path: &recent_peers_path,
                            last_endpoint_peer_signature: &mut last_fips_endpoint_peer_signature,
                        },
                        unix_timestamp(),
                    )
                    .await;
                }
            }
            _ = tunnel_heartbeat_interval.tick() => {
                if !daemon_vpn_active(vpn_enabled, expected_peers) {
                    #[cfg(feature = "embedded-fips")]
                    if fips_private_runtime_active(&app, vpn_enabled, expected_peers)
                        && let Some(runtime) = fips_tunnel_runtime.as_ref()
                    {
                        let now = unix_timestamp();
                        if let Err(error) = runtime.ping_peers(&network_id, now).await {
                            eprintln!("fips: peer ping failed: {error}");
                        }
                        if let Err(error) = runtime.refresh_link_statuses().await {
                            eprintln!("fips: peer link snapshot failed: {error}");
                        }
                        flush_pending_fips_roster_recipients(
                            runtime,
                            &app,
                            &mut pending_fips_roster_recipients,
                        )
                        .await;
                        if let Err(error) = send_pending_fips_join_requests(
                            runtime,
                            &app,
                            &mut fips_join_request_sends,
                            now,
                        )
                        .await
                        {
                            eprintln!("fips: join request send failed: {error}");
                        }
                    }
                    continue;
                }

                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                    let now = unix_timestamp();
                    if let Err(error) = runtime.ping_peers(&network_id, now).await {
                        eprintln!("fips: peer ping failed: {error}");
                    }
                    if let Err(error) = runtime.refresh_link_statuses().await {
                        eprintln!("fips: peer link snapshot failed: {error}");
                    }
                    flush_pending_fips_roster_recipients(
                        runtime,
                        &app,
                        &mut pending_fips_roster_recipients,
                    )
                    .await;
                    if let Err(error) = send_pending_fips_join_requests(
                        runtime,
                        &app,
                        &mut fips_join_request_sends,
                        now,
                    )
                    .await
                    {
                        eprintln!("fips: join request send failed: {error}");
                    }
                }
            }
            _ = network_interval.tick() => {
                let now = unix_timestamp();
                let resumed_after_sleep = observe_wall_time_jump(
                    &mut last_network_check_at,
                    now,
                    Instant::now(),
                    MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
                );
                if resumed_after_sleep {
                    eprintln!("daemon: sleep/wake detected; refreshing FIPS endpoint state");
                }
                #[cfg(target_os = "macos")]
                let underlay_repaired =
                    match ensure_macos_underlay_default_route_for_daemon().await {
                        Ok(true) => {
                            eprintln!("daemon: restored missing macOS underlay default route");
                            true
                        }
                        Ok(false) => false,
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to ensure macOS underlay default route: {error}"
                            );
                            false
                        }
                    };
                #[cfg(not(target_os = "macos"))]
                let underlay_repaired = false;
                let latest_snapshot = prefer_nonself_tunnel_snapshot(
                    &tunnel_runtime,
                    &network_snapshot,
                    capture_network_snapshot_for_daemon().await,
                );
                let runtime_listen_port =
                    tunnel_runtime.active_listen_port.unwrap_or(app.node.listen_port);
                let vpn_active = daemon_vpn_active(vpn_enabled, expected_peers);
                let network_changed = latest_snapshot.changed_since(&network_snapshot);
                let endpoint_changed = if network_changed {
                    network_snapshot = latest_snapshot.clone();
                    network_changed_at = Some(unix_timestamp());
                    captive_portal = detect_captive_portal(timeout).await;
                    if vpn_active {
                        refresh_port_mapping(
                            &app,
                            &network_snapshot,
                            runtime_listen_port,
                            &mut port_mapping_runtime,
                        )
                        .await;
                        true
                    } else {
                        port_mapping_runtime.stop().await;
                        false
                    }
                } else if resumed_after_sleep {
                    network_changed_at = Some(now);
                    if vpn_active {
                        refresh_port_mapping(
                            &app,
                            &network_snapshot,
                            runtime_listen_port,
                            &mut port_mapping_runtime,
                        )
                        .await;
                        true
                    } else {
                        port_mapping_runtime.stop().await;
                        false
                    }
                } else if vpn_active {
                    match port_mapping_runtime
                        .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                        .await
                    {
                        Ok(changed) => changed,
                        Err(error) => {
                            eprintln!("daemon: port mapping renew failed: {error}");
                            false
                        }
                    }
                } else {
                    false
                };

                if !network_changed && !endpoint_changed && !underlay_repaired && !resumed_after_sleep {
                    continue;
                }

                if network_changed || underlay_repaired || resumed_after_sleep {
                    if network_changed {
                        network_snapshot = latest_snapshot;
                        network_changed_at = Some(unix_timestamp());
                        eprintln!("daemon: network change detected; refreshing FIPS endpoint state");
                    } else if resumed_after_sleep {
                        network_snapshot = latest_snapshot;
                        network_changed_at = Some(now);
                        eprintln!("daemon: sleep/wake detected; refreshing FIPS endpoint state");
                    } else {
                        network_snapshot = latest_snapshot;
                        eprintln!("daemon: refreshing tunnel after macOS underlay repair");
                    }
                    if underlay_repaired {
                        reset_tunnel_runtime_after_macos_underlay_repair(&mut tunnel_runtime);
                    }
                    #[cfg(feature = "embedded-fips")]
                    if let Some(runtime) = fips_tunnel_runtime.as_mut()
                        && let Err(error) = refresh_fips_tunnel_config(
                            runtime,
                            &app,
                            &network_id,
                            own_pubkey.as_deref(),
                        )
                        .await
                    {
                        vpn_status = format!("Network change refresh failed ({error})");
                    } else {
                        vpn_status = if daemon_vpn_active(vpn_enabled, expected_peers) {
                            "Connected (network refresh)".to_string()
                        } else {
                            daemon_vpn_idle_status(
                                vpn_enabled,
                                expected_peers,
                                app.join_requests_enabled(),
                            )
                            .to_string()
                        };
                    }
                    #[cfg(feature = "embedded-fips")]
                    if let Some(runtime) = fips_tunnel_runtime.as_ref()
                        && let Err(error) = broadcast_local_fips_capabilities(runtime, &app).await
                    {
                        eprintln!("fips: capabilities broadcast failed after network refresh: {error}");
                    }
                }
            }
            _ = state_interval.tick() => {
                if daemon_log_compact_check_due(&mut last_log_compact_check)
                    && let Err(error) = compact_daemon_log_if_needed(&config_path)
                {
                    eprintln!("daemon: failed to compact service log: {error}");
                }
                #[cfg(feature = "embedded-fips")]
                if let Some(runtime) = fips_tunnel_runtime.as_mut() {
                    match drain_fips_mesh_events(
                        runtime,
                        &mut app,
                        &config_path,
                        &mut vpn_status,
                    )
                    .await
                    {
                        Ok(true) => {
                            let reload = build_daemon_reload_config(
                                app.clone(),
                                app.effective_network_id(),
                            );
                            app = reload.app;
                            network_id = reload.network_id;
                            expected_peers = reload.expected_peers;
                            own_pubkey = reload.own_pubkey;

                            fips_join_request_sends.clear();
                            if let Err(error) = refresh_fips_tunnel_config(
                                runtime,
                                &app,
                                &network_id,
                                own_pubkey.as_deref(),
                            )
                            .await
                            {
                                vpn_status =
                                    format!("Roster applied, but FIPS reload failed ({error})");
                            }
                            if let Some(rt) = magic_dns_runtime.as_ref() {
                                rt.refresh_records(&app);
                            }
                        }
                        Ok(false) => {}
                        Err(error) => {
                            vpn_status = format!("FIPS event handling failed ({error})");
                        }
                    }
                    if let Err(error) = runtime.refresh_peer_dependent_routes().await {
                        vpn_status = format!("FIPS route refresh failed ({error})");
                    }
                }

                if let Some(request) = take_daemon_control_request(&config_path) {
                    let publish_fips_roster_after_control =
                        matches!(request, DaemonControlRequest::Reload | DaemonControlRequest::Resume);
                    let control_result = match request {
                        DaemonControlRequest::Stop => break,
                        DaemonControlRequest::Pause => {
                            vpn_enabled = false;
                            let join_requests_active = app.join_requests_enabled();
                            port_mapping_runtime.stop().await;
                            vpn_status = daemon_vpn_idle_status(
                                vpn_enabled,
                                expected_peers,
                                join_requests_active,
                            )
                            .to_string();
                            Ok(())
                        }
                        DaemonControlRequest::Resume => {
                            if !vpn_enabled {
                                vpn_enabled = true;
                                if daemon_vpn_active(vpn_enabled, expected_peers) {
                                    let runtime_listen_port = tunnel_runtime
                                        .active_listen_port
                                        .unwrap_or(app.node.listen_port);
                                    refresh_port_mapping(
                                        &app,
                                        &network_snapshot,
                                        runtime_listen_port,
                                        &mut port_mapping_runtime,
                                    )
                                    .await;
                                    vpn_status = "VPN on".to_string();
                                } else {
                                    port_mapping_runtime.stop().await;
                                    vpn_status = daemon_vpn_idle_status(
                                        vpn_enabled,
                                        expected_peers,
                                        app.join_requests_enabled(),
                                    )
                                    .to_string();
                                }
                            }
                            Ok(())
                        }
                        DaemonControlRequest::Reload => {
                            match update_daemon_config_from_staged_request(&config_path) {
                                Ok(staged_config_applied) => {
                                    match load_config_with_overrides(
                                        &config_path,
                                        network_override.clone(),
                                        participants_override.clone(),
                                    ) {
                                        Ok((reloaded_app, reloaded_network_id)) => {
                                            let reload = build_daemon_reload_config(
                                                reloaded_app,
                                                reloaded_network_id,
                                            );
                                            app = reload.app;
                                            network_id = reload.network_id;
                                            expected_peers = reload.expected_peers;
                                            own_pubkey = reload.own_pubkey;
                                            if let Some(rt) = magic_dns_runtime.as_ref() {
                                                rt.refresh_records(&app);
                                            }

                                            let join_requests_active = app.join_requests_enabled();
                                            let vpn_active =
                                                daemon_vpn_active(vpn_enabled, expected_peers);
                                            vpn_status = if vpn_active {
                                                "Config reloaded".to_string()
                                            } else if vpn_enabled {
                                                daemon_vpn_idle_status(
                                                    vpn_enabled,
                                                    expected_peers,
                                                    join_requests_active,
                                                )
                                                .to_string()
                                            } else {
                                                "Config reloaded (paused)".to_string()
                                            };

                                            if vpn_active {
                                                let runtime_listen_port = tunnel_runtime
                                                    .active_listen_port
                                                    .unwrap_or(app.node.listen_port);
                                                refresh_port_mapping(
                                                    &app,
                                                    &network_snapshot,
                                                    runtime_listen_port,
                                                    &mut port_mapping_runtime,
                                                )
                                                .await;
                                            }
                                            Ok(())
                                        }
                                        Err(error) => {
                                            vpn_status = if staged_config_applied {
                                                format!("Config apply failed (reload: {error})")
                                            } else {
                                                format!("Config reload failed ({error})")
                                            };
                                            Err(error)
                                        }
                                    }
                                }
                                Err(error) => {
                                    vpn_status = format!("Config apply failed ({error})");
                                    Err(error)
                                }
                            }
                        }
                    };
                    let _ = write_daemon_control_result(&config_path, request, control_result);
                    #[cfg(feature = "embedded-fips")]
                    let pre_sync_fips_roster_recipients = if publish_fips_roster_after_control {
                        fips_tunnel_runtime
                            .as_ref()
                            .map(|runtime| runtime.peer_pubkeys())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    #[cfg(feature = "embedded-fips")]
                    if publish_fips_roster_after_control
                        && let Some(runtime) = fips_tunnel_runtime.as_ref()
                        && let Err(error) = publish_fips_active_network_roster_to(
                            runtime,
                            &app,
                            &pre_sync_fips_roster_recipients,
                            &mut pending_fips_roster_recipients,
                        )
                        .await
                    {
                        eprintln!(
                            "fips: roster publish failed before peer-set refresh: {error}"
                        );
                    }
                    #[cfg(feature = "embedded-fips")]
                    if let Err(error) = sync_fips_private_runtime(
                        &mut fips_tunnel_runtime,
                        &app,
                        &network_id,
                        &iface,
                        own_pubkey.as_deref(),
                        vpn_enabled,
                        expected_peers,
                    )
                    .await
                    {
                        vpn_status = format!("FIPS private mesh update failed ({error})");
                    }
                    #[cfg(feature = "embedded-fips")]
                    if publish_fips_roster_after_control
                        && let Some(runtime) = fips_tunnel_runtime.as_ref()
                    {
                        if let Err(error) = publish_fips_active_network_roster(
                            runtime,
                            &app,
                            &mut pending_fips_roster_recipients,
                        )
                        .await
                        {
                            eprintln!(
                                "fips: roster publish failed after control request: {error}"
                            );
                        }
                        if let Err(error) = broadcast_local_fips_capabilities(runtime, &app).await {
                            eprintln!(
                                "fips: capabilities broadcast failed after control request: {error}"
                            );
                        }
                    }
                    match persist_daemon_runtime_state(
                        &state_file,
                        &app,
                        vpn_enabled,
                        expected_peers,
                        &tunnel_runtime,
                        &current_fips_peer_statuses!(fips_tunnel_runtime),
                        &current_fips_relay_statuses(&fips_tunnel_runtime).await,
                        &current_fips_advertised_routes!(fips_tunnel_runtime, &app),
                        &vpn_status,
                        &network_snapshot.summary(network_changed_at, captive_portal),
                        &port_mapping_runtime.status(),
                    ) {
                        Ok(()) => last_state_persisted_at = Instant::now(),
                        Err(error) => {
                            eprintln!("daemon: failed to persist runtime state: {error}");
                        }
                    }
                    if let Err(error) =
                        persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                    {
                        eprintln!("daemon: failed to persist network cleanup state: {error}");
                    }
                }
                if let Some((executable, launched_fingerprint)) =
                    supervised_service_executable.as_ref()
                {
                    match service_supervisor_restart_due(executable, launched_fingerprint) {
                        Ok(true) => {
                            eprintln!(
                                "daemon: service executable changed on disk; exiting so the supervisor restarts the updated binary"
                            );
                            break;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to check service executable fingerprint: {error}"
                            );
                        }
                    }
                }
                if last_state_persisted_at.elapsed() >= daemon_state_persist_interval {
                    let fips_peer_statuses = current_fips_peer_statuses!(fips_tunnel_runtime);
                    let fips_relay_statuses =
                        current_fips_relay_statuses(&fips_tunnel_runtime).await;
                    let fips_advertised_routes =
                        current_fips_advertised_routes!(fips_tunnel_runtime, &app);
                    match persist_daemon_runtime_state(
                        &state_file,
                        &app,
                        vpn_enabled,
                        expected_peers,
                        &tunnel_runtime,
                        &fips_peer_statuses,
                        &fips_relay_statuses,
                        &fips_advertised_routes,
                        &vpn_status,
                        &network_snapshot.summary(network_changed_at, captive_portal),
                        &port_mapping_runtime.status(),
                    ) {
                        Ok(()) => last_state_persisted_at = Instant::now(),
                        Err(error) => {
                            eprintln!("daemon: failed to persist runtime state: {error}");
                        }
                    }
                    if let Err(error) =
                        persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                    {
                        eprintln!("daemon: failed to persist network cleanup state: {error}");
                    }
                }
            }
        }
    }

    port_mapping_runtime.stop().await;
    #[cfg(feature = "embedded-fips")]
    if let Some(runtime) = fips_tunnel_runtime
        && let Err(error) = runtime.stop().await
    {
        eprintln!("daemon: failed to stop FIPS private mesh: {error}");
    }
    tunnel_runtime.stop();
    if let Err(error) = persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime) {
        eprintln!("daemon: failed to clear network cleanup state: {error}");
    }

    let final_state = DaemonRuntimeState {
        updated_at: unix_timestamp(),
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        vpn_enabled: false,
        vpn_active: false,
        vpn_status: "Disconnected".to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count: 0,
        mesh_ready: false,
        health: Vec::new(),
        network: network_snapshot.summary(network_changed_at, captive_portal),
        port_mapping: PortMappingStatus::default(),
        relays: Vec::new(),
        peers: Vec::new(),
    };
    let _ = write_daemon_state(&state_file, &final_state);
    remove_current_daemon_pid_record(&pid_file);

    Ok(())
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
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, {
        let config_path = config_path.clone();
        move |control_event| match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = request_daemon_stop(&config_path);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .context("failed to register Windows service control handler")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
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
    wait_hint: Duration,
) -> Result<()> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
        .with_context(|| format!("failed to update Windows service status to {state:?}"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_daemon_runtime_state(
    app: &AppConfig,
    vpn_enabled: bool,
    vpn_active: bool,
    expected_peers: usize,
    tunnel_runtime: &CliTunnelRuntime,
    fips_peer_statuses: &[MeshPeerStatus],
    fips_relay_statuses: &[DaemonRelayState],
    advertised_routes_by_participant: &HashMap<String, Vec<String>>,
    vpn_status: &str,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
) -> DaemonRuntimeState {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let now = unix_timestamp();
    let listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    let local_endpoint = local_signal_endpoint(app, listen_port);
    // Daemon no longer pre-discovers a public endpoint; fips-core advertises
    // its own (and falls back to udp:nat traversal when behind NAT). The
    // advertised_endpoint we surface in state.json is the local-network
    // endpoint, used by other peers on the same LAN.
    let advertised_endpoint = local_endpoint.clone();
    let mut peers = Vec::new();

    let fips_status_by_pubkey = fips_peer_statuses
        .iter()
        .map(|status| (status.pubkey.as_str(), status))
        .collect::<HashMap<_, _>>();
    let network_id = app.effective_network_id();
    for participant in &app.participant_pubkeys_hex() {
        if Some(participant.as_str()) == own_pubkey.as_deref() {
            continue;
        }
        let status = if vpn_active {
            fips_status_by_pubkey.get(participant.as_str()).copied()
        } else {
            None
        };
        let last_seen_at = status.and_then(|status| status.last_seen_at);
        let reachable = vpn_active && status.is_some_and(|status| status.connected);
        let fips_transport_addr = status.and_then(|status| status.transport_addr.clone());
        let tunnel_ip = derive_mesh_tunnel_ip(&network_id, participant).unwrap_or_default();
        peers.push(DaemonPeerState {
            participant_pubkey: participant.clone(),
            node_id: String::new(),
            tunnel_ip,
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
            fips_packets_sent: status.map(|status| status.link_packets_sent).unwrap_or(0),
            fips_packets_recv: status.map(|status| status.link_packets_recv).unwrap_or(0),
            fips_bytes_sent: status.map(|status| status.link_bytes_sent).unwrap_or(0),
            fips_bytes_recv: status.map(|status| status.link_bytes_recv).unwrap_or(0),
            tx_bytes: status.map(|status| status.tx_bytes).unwrap_or(0),
            rx_bytes: status.map(|status| status.rx_bytes).unwrap_or(0),
            public_key: String::new(),
            advertised_routes: advertised_routes_by_participant
                .get(participant)
                .cloned()
                .unwrap_or_default(),
            last_mesh_seen_at: last_seen_at.unwrap_or(0),
            last_fips_seen_at: last_seen_at,
            reachable,
            last_handshake_at: last_seen_at,
            error: if reachable {
                None
            } else {
                status
                    .and_then(|status| status.error.clone())
                    .or_else(|| Some("fips link pending".to_string()))
            },
        });
    }

    let connected_peer_count = if !vpn_active {
        0
    } else {
        let participant_pubkeys = app
            .participant_pubkeys_hex()
            .into_iter()
            .collect::<HashSet<_>>();
        fips_peer_statuses
            .iter()
            .filter(|status| Some(status.pubkey.as_str()) != own_pubkey.as_deref())
            .filter(|status| participant_pubkeys.contains(&status.pubkey))
            .filter(|status| status.connected)
            .count()
    };
    let mesh_ready = vpn_active;
    let health = build_health_issues(app, vpn_active, mesh_ready, network, port_mapping, &peers);
    DaemonRuntimeState {
        updated_at: now,
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint,
        advertised_endpoint,
        listen_port,
        vpn_enabled,
        vpn_active,
        vpn_status: vpn_status.to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        health,
        network: network.clone(),
        port_mapping: port_mapping.clone(),
        relays: fips_relay_statuses.to_vec(),
        peers,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_daemon_runtime_state(
    path: &Path,
    app: &AppConfig,
    vpn_enabled: bool,
    expected_peers: usize,
    tunnel_runtime: &CliTunnelRuntime,
    fips_peer_statuses: &[MeshPeerStatus],
    fips_relay_statuses: &[DaemonRelayState],
    advertised_routes_by_participant: &HashMap<String, Vec<String>>,
    vpn_status: &str,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
) -> Result<()> {
    write_daemon_state(
        path,
        &build_daemon_runtime_state(
            app,
            vpn_enabled,
            daemon_vpn_active(vpn_enabled, expected_peers),
            expected_peers,
            tunnel_runtime,
            fips_peer_statuses,
            fips_relay_statuses,
            advertised_routes_by_participant,
            vpn_status,
            network,
            port_mapping,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn prefer_nonself_tunnel_snapshot_ignores_tunnel_default_interface() {
        let tunnel_runtime = CliTunnelRuntime::new("utun100");
        let previous = crate::diagnostics::NetworkSnapshot {
            default_interface: Some("eth0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 64, 2)),
            primary_ipv6: None,
            gateway_ipv4: Some(Ipv4Addr::new(192, 168, 64, 1)),
            gateway_ipv6: None,
        };
        let latest = crate::diagnostics::NetworkSnapshot {
            default_interface: Some("utun100".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(10, 44, 210, 253)),
            primary_ipv6: None,
            gateway_ipv4: None,
            gateway_ipv6: None,
        };

        let preferred = prefer_nonself_tunnel_snapshot(&tunnel_runtime, &previous, latest);

        assert_eq!(preferred.default_interface.as_deref(), Some("eth0"));
        assert_eq!(preferred.primary_ipv4, Some(Ipv4Addr::new(192, 168, 64, 2)));
    }
}
