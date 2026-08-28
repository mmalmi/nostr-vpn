include!("runtime_helpers/tunnel_runtime.rs");

fn parse_exit_node_arg(value: &str) -> Result<Option<String>> {
    let value = value.trim();
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "off" | "none" | "disable" | "disabled" | "clear"
        )
    {
        return Ok(None);
    }

    normalize_nostr_pubkey(value).map(Some)
}

fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn route_is_host_route(route: &str) -> bool {
    let Some((host, bits)) = route.split_once('/') else {
        return true;
    };
    let Ok(bits) = bits.parse::<u8>() else {
        return false;
    };

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => bits == 32,
        Ok(IpAddr::V6(_)) => bits == 128,
        Err(_) => false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn route_targets_require_endpoint_bypass(route_targets: &[String]) -> bool {
    route_targets
        .iter()
        .any(|route| !route_is_host_route(route))
}

fn daemon_vpn_active(vpn_enabled: bool, expected_peers: usize) -> bool {
    vpn_enabled && expected_peers > 0
}

fn daemon_start_vpn_enabled(app: &AppConfig, paused: bool) -> bool {
    app.autoconnect && !paused
}

fn fips_host_runtime_active(app: &AppConfig) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        app.fips_host_tunnel_enabled
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = app;
        false
    }
}

fn fips_private_runtime_active(app: &AppConfig, vpn_enabled: bool, expected_peers: usize) -> bool {
    daemon_vpn_active(vpn_enabled, expected_peers)
        || fips_host_runtime_active(app)
        || paid_exit_fips_runtime_active(app)
        || app.join_requests_enabled()
        || app
            .active_network_opt()
            .and_then(|network| network.outbound_join_request.as_ref())
            .is_some()
        || app.pending_nostr_join_request.is_some()
        || app.has_fips_static_peer_endpoints()
}

fn fips_private_runtime_active_for_config(
    app: &AppConfig,
    config_path: &Path,
    vpn_enabled: bool,
    expected_peers: usize,
) -> Result<bool> {
    Ok(fips_private_runtime_active(app, vpn_enabled, expected_peers)
        || !load_pending_fips_control_recipients(config_path)?.is_empty())
}

pub(crate) fn paid_exit_fips_runtime_active(app: &AppConfig) -> bool {
    #[cfg(feature = "paid-exit")]
    {
        app.paid_exit.enabled
            || app.internet_source == nostr_vpn_core::config::InternetSource::PaidAutomatic
            || app.public_paid_exit_node_pubkey_hex().is_some()
            || app.connect_to_non_roster_fips_peers
    }
    #[cfg(not(feature = "paid-exit"))]
    {
        let _ = app;
        false
    }
}

fn daemon_vpn_idle_status(
    vpn_enabled: bool,
    expected_peers: usize,
    join_requests_active: bool,
) -> &'static str {
    if vpn_enabled && expected_peers == 0 {
        WAITING_FOR_PARTICIPANTS_STATUS
    } else if join_requests_active {
        LISTENING_FOR_JOIN_REQUESTS_STATUS
    } else {
        "Paused"
    }
}

#[derive(Clone, Copy, Debug)]
struct WallTimeJumpObserver {
    wall_observed_at: u64,
    monotonic_observed_at: Instant,
}

impl WallTimeJumpObserver {
    fn new(wall_observed_at: u64) -> Self {
        Self {
            wall_observed_at,
            monotonic_observed_at: Instant::now(),
        }
    }
}

fn wall_time_jump_detected(
    previous_wall_observed_at: u64,
    now_wall: u64,
    monotonic_elapsed_secs: u64,
    threshold_secs: u64,
) -> bool {
    if previous_wall_observed_at == 0 || threshold_secs == 0 {
        return false;
    }

    if now_wall < previous_wall_observed_at {
        return true;
    }

    let wall_elapsed_secs = now_wall.saturating_sub(previous_wall_observed_at);
    wall_elapsed_secs >= threshold_secs
        && wall_elapsed_secs.saturating_sub(monotonic_elapsed_secs) >= threshold_secs
}

fn observe_wall_time_jump(
    last_observed_at: &mut WallTimeJumpObserver,
    now_wall: u64,
    threshold_secs: u64,
) -> bool {
    let monotonic_elapsed_secs = last_observed_at.monotonic_observed_at.elapsed().as_secs();
    let jumped = wall_time_jump_detected(
        last_observed_at.wall_observed_at,
        now_wall,
        monotonic_elapsed_secs,
        threshold_secs,
    );
    last_observed_at.wall_observed_at = now_wall;
    last_observed_at.monotonic_observed_at = Instant::now();
    jumped
}

struct InboundJoinRequest<'a> {
    sender_pubkey: &'a str,
    requested_at: u64,
    request: &'a MeshJoinRequest,
}

fn persist_inbound_join_request(
    app: &mut AppConfig,
    config_path: &Path,
    inbound: InboundJoinRequest<'_>,
    vpn_status: &mut String,
) {
    match app.record_inbound_join_request(
        &inbound.request.network_id,
        &inbound.request.join_secret,
        inbound.sender_pubkey,
        &inbound.request.requester_node_name,
        inbound.requested_at,
    ) {
        Ok(Some(network_name)) => {
            if let Err(error) = app.save(config_path) {
                *vpn_status = format!("Failed to persist join request: {error}");
            } else {
                *vpn_status = format!("Join request received for {network_name}.");
            }
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!(
                "daemon: ignoring invalid join request from {}: {error}",
                inbound.sender_pubkey
            );
        }
    }
}

fn persist_shared_network_roster(
    app: &mut AppConfig,
    config_path: &Path,
    signed_roster: Option<&SignedRoster>,
    vpn_status: &mut String,
) -> Result<Option<String>> {
    let signed_roster =
        signed_roster.ok_or_else(|| anyhow!("FIPS roster frame is missing signed roster event"))?;
    let changed = app.apply_verified_admin_signed_shared_roster(signed_roster)?;
    let apply_network_id = signed_roster.network_id()?;
    if signed_roster_is_current_for_app(app, &apply_network_id, signed_roster) {
        upsert_signed_roster(
            &signed_rosters_file_path(config_path),
            signed_roster.clone(),
        )?;
    }
    if !changed {
        return Ok(None);
    }

    maybe_autoconfigure_node(app);
    app.save(config_path)?;
    let network_name = app
        .networks
        .iter()
        .find(|network| {
            normalize_runtime_network_id(&network.network_id)
                == normalize_runtime_network_id(&apply_network_id)
        })
        .map(|network| network.name.clone())
        .unwrap_or_else(|| apply_network_id.to_string());
    *vpn_status = format!("Roster updated for {network_name}.");
    Ok(Some(network_name))
}

fn endpoint_hint_refresh_participant(
    active_network_id: Option<&str>,
    roster_participants: &HashSet<String>,
    sender_pubkey: &str,
    network_id: &str,
    capabilities: &PeerCapabilities,
) -> Option<String> {
    let network_matches =
        active_network_id.is_some_and(|active| active == normalize_runtime_network_id(network_id));
    (network_matches
        && roster_participants.contains(sender_pubkey)
        && !capabilities.endpoint_hints.is_empty())
    .then(|| sender_pubkey.to_string())
}
#[derive(Debug, Default)]
struct DrainedFipsMeshEvents {
    roster_changed: bool,
    endpoint_hint_participants: Vec<String>,
    #[cfg(feature = "paid-exit")]
    paid_route_session_opens: Vec<(String, PaidRouteSessionOpen)>,
    #[cfg(feature = "paid-exit")]
    paid_route_session_open_acks: Vec<(String, String)>,
    #[cfg(feature = "paid-exit")]
    paid_route_payments: Vec<(String, String, StreamingRoutePaymentEnvelope)>,
    #[cfg(feature = "paid-exit")]
    paid_route_payment_acks: Vec<(String, String)>,
}
async fn drain_fips_mesh_events(
    runtime: &mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    vpn_status: &mut String,
) -> Result<DrainedFipsMeshEvents> {
    let mut drained = DrainedFipsMeshEvents::default();
    let active_network_id = app
        .active_network_opt()
        .map(|network| normalize_runtime_network_id(&network.network_id));
    let roster_participants = desired_fips_endpoint_hint_recipients(app);
    for event in runtime.drain_events() {
        match event {
            crate::fips_private_mesh::FipsPrivateMeshEvent::Packet(packet) => {
                let _ = packet;
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::Presence {
                participant_pubkey,
                last_seen_at,
            } => {
                let _ = (participant_pubkey, last_seen_at);
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::JoinRequest {
                sender_pubkey,
                requested_at,
                request,
            } => {
                persist_inbound_join_request(
                    app,
                    config_path,
                    InboundJoinRequest {
                        sender_pubkey: &sender_pubkey,
                        requested_at,
                        request: &request,
                    },
                    vpn_status,
                );
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::JoinRoster {
                sender_pubkey,
                control,
            } => {
                let roster_event_id = control.signed_roster.artifact_hash();
                let durably_applied = match persist_join_roster(
                    app,
                    config_path,
                    &control,
                    vpn_status,
                ) {
                    Ok(Some(_)) => {
                        drained.roster_changed = true;
                        true
                    }
                    Ok(None) => match join_roster_is_durably_persisted(config_path, &control) {
                        Ok(persisted) => persisted,
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to verify persisted FIPS join roster from {sender_pubkey}: {error}"
                            );
                            false
                        }
                    },
                    Err(error) => {
                        eprintln!(
                            "daemon: ignoring invalid FIPS join roster from {sender_pubkey}: {error}"
                        );
                        false
                    }
                };
                if durably_applied
                    && let Err(error) = runtime
                        .send_join_roster_ack(&sender_pubkey, roster_event_id)
                        .await
                {
                    eprintln!(
                        "daemon: failed to deliver FIPS join roster receipt for {sender_pubkey}: {error}"
                    );
                }
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::Roster {
                sender_pubkey,
                signed_roster,
                ..
            } => match persist_shared_network_roster(
                app,
                config_path,
                signed_roster.as_deref(),
                vpn_status,
            ) {
                Ok(Some(_)) => drained.roster_changed = true,
                Ok(None) => {}
                Err(error) => {
                    eprintln!("daemon: ignoring invalid FIPS roster from {sender_pubkey}: {error}");
                }
            },
            crate::fips_private_mesh::FipsPrivateMeshEvent::Capabilities {
                sender_pubkey,
                network_id,
                capabilities,
            } => {
                // The FIPS receive path records capabilities before queuing
                // this event. Apply fresh direct endpoint hints promptly so
                // peers that roam between LAN/NAT paths do not stay on stale
                // direct-probe state until the generic liveness repair fires.
                if let Some(participant) = endpoint_hint_refresh_participant(
                    active_network_id.as_deref(),
                    &roster_participants,
                    &sender_pubkey,
                    &network_id,
                    &capabilities,
                ) {
                    drained.endpoint_hint_participants.push(participant);
                }
            }
            #[cfg(feature = "paid-exit")]
            crate::fips_private_mesh::FipsPrivateMeshEvent::PaidRouteSessionOpen {
                sender_pubkey,
                open,
            } => drained.paid_route_session_opens.push((sender_pubkey, open)),
            #[cfg(feature = "paid-exit")]
            crate::fips_private_mesh::FipsPrivateMeshEvent::PaidRouteSessionOpenAck {
                sender_pubkey,
                lease_id,
            } => drained
                .paid_route_session_open_acks
                .push((sender_pubkey, lease_id)),
            #[cfg(feature = "paid-exit")]
            crate::fips_private_mesh::FipsPrivateMeshEvent::PaidRoutePayment {
                sender_pubkey,
                id,
                envelope,
            } => drained
                .paid_route_payments
                .push((sender_pubkey, id, *envelope)),
            #[cfg(feature = "paid-exit")]
            crate::fips_private_mesh::FipsPrivateMeshEvent::PaidRoutePaymentAck {
                sender_pubkey,
                id,
            } => drained.paid_route_payment_acks.push((sender_pubkey, id)),
        }
    }
    drained.endpoint_hint_participants.sort();
    drained.endpoint_hint_participants.dedup();
    Ok(drained)
}
async fn refresh_fips_tunnel_config(
    runtime: &mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    network_id: &str,
    underlay_interface: Option<&str>,
    underlay_interface_mtu: Option<u32>,
    own_pubkey: Option<&str>,
) -> Result<()> {
    let ethernet_underlay = runtime.ethernet_underlay().cloned();
    let live_peer_endpoints = runtime.peer_endpoint_hints();
    let mut config = fips_tunnel_config_from_app_async(FipsTunnelConfigInput {
        app,
        config_path,
        network_id,
        iface: runtime.iface().to_string(),
        underlay_interface,
        underlay_interface_mtu,
        own_pubkey,
        recent_peers: None,
        live_peer_endpoints: &live_peer_endpoints,
        ethernet_underlay: ethernet_underlay.as_ref(),
    })
    .await?;
    if !runtime.client_dataplane_enabled() {
        config.disable_client_dataplane();
    }
    apply_fips_private_tunnel_runtime_config(config_path, runtime, config).await
}

pub(crate) struct FipsTunnelConfigInput<'a> {
    pub(crate) app: &'a AppConfig,
    pub(crate) config_path: &'a Path,
    pub(crate) network_id: &'a str,
    pub(crate) iface: String,
    pub(crate) underlay_interface: Option<&'a str>,
    pub(crate) underlay_interface_mtu: Option<u32>,
    pub(crate) own_pubkey: Option<&'a str>,
    pub(crate) recent_peers: Option<&'a nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
    pub(crate) live_peer_endpoints: &'a [(String, Vec<(String, u64)>)],
    pub(crate) ethernet_underlay:
        Option<&'a crate::fips_private_mesh::FipsEthernetUnderlayConfig>,
}

fn fips_tunnel_config_from_app(
    input: FipsTunnelConfigInput<'_>,
) -> Result<crate::fips_private_mesh::FipsPrivateTunnelConfig> {
    let FipsTunnelConfigInput {
        app,
        config_path,
        network_id,
        iface,
        underlay_interface,
        underlay_interface_mtu,
        own_pubkey,
        recent_peers,
        live_peer_endpoints,
        ethernet_underlay,
    } = input;

    let pending_control_recipients = load_pending_fips_control_recipients(config_path)?;
    let control_recipient_pubkeys = pending_control_recipients
        .iter()
        .map(|(_, recipient)| recipient.as_str())
        .collect::<Vec<_>>();
    let mut config =
        crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app_with_control_recipients(
        app,
        network_id,
        iface,
        own_pubkey,
        recent_peers,
        live_peer_endpoints,
        &control_recipient_pubkeys,
    )?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        config.underlay_interface = underlay_interface.map(str::to_owned);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = underlay_interface;
    config.ethernet_underlay = ethernet_underlay.cloned();
    for (kind, recipient) in pending_control_recipients {
        match crate::fips_private_mesh::prioritize_fips_control_recipient(
            config.endpoint_peers.clone(),
            &recipient,
        ) {
            Ok(peers) => config.endpoint_peers = peers,
            Err(error) => {
                eprintln!("ignoring invalid pending {kind} recipient: {error}");
            }
        }
    }
    config.control_pubsub_store_path =
        crate::control_pubsub_runtime::control_pubsub_store_file_path(config_path);
    config.clamp_mesh_mtu_to_underlay_interface_mtu(underlay_interface_mtu);
    #[cfg(feature = "paid-exit")]
    {
        config.paid_exit = app.paid_exit.clone();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            config.local_exit_forwarding_routes = runtime_local_exit_forwarding_routes(app);
        }
        config.paid_route_store_path = paid_route_store_file_path(config_path);
        if let Some(seller_pubkey) = app.public_paid_exit_node_pubkey_hex() {
            let store = load_paid_route_store(&config.paid_route_store_path)?;
            config.require_public_paid_exit_admission(
                store.buyer_has_seller_admission(&seller_pubkey, unix_timestamp())?,
            );
        }
        config.paid_route_wallet_data_dir = paid_exit_wallet_data_dir(config_path);
        config.paid_route_payment_relays = paid_exit_relay_urls(app, &[]);
        config.paid_route_admissions = fips_paid_route_admissions_from_store(app, config_path)?;
        config.endpoint_peers =
            crate::fips_private_mesh::fips_endpoint_peers_with_paid_route_admissions(
                config.endpoint_peers,
                &config.paid_route_admissions,
            );
        config.paid_route_accounting_peers =
            fips_paid_route_accounting_peers(app, &config.paid_route_admissions);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if app.paid_exit.enabled {
            eprintln!(
                "paid-exit: fips routes advertised={:?} local_forwarding={:?}",
                config.local_advertised_routes, config.local_exit_forwarding_routes
            );
        }
    }
    #[cfg(not(feature = "paid-exit"))]
    let _ = config_path;
    // Daemon no longer pre-discovers a public endpoint. fips-core's
    // build_overlay_advert performs its own STUN observation and advertises
    // <reflexive_ip>:<listen_port> directly; if that's wrong (e.g. symmetric
    // NAT), peers fall back to udp:nat traversal via Nostr signaling. Use
    // any operator-configured endpoint as a hint when set.
    let configured = endpoint_with_listen_port(&app.node.endpoint, config.listen_port);
    config.advertised_endpoint = if endpoint_is_local_only(&configured) {
        String::new()
    } else {
        configured
    };
    Ok(config)
}

#[cfg(feature = "paid-exit")]
fn fips_paid_route_accounting_peers(
    app: &AppConfig,
    admissions: &[FipsPaidRouteAdmission],
) -> Vec<crate::fips_private_mesh::FipsPaidRouteAccountingPeer> {
    let mut peers: Vec<crate::fips_private_mesh::FipsPaidRouteAccountingPeer> = app
        .public_paid_exit_node_pubkey_hex()
        .into_iter()
        .filter_map(|participant_pubkey| {
            crate::fips_private_mesh::FipsPaidRouteAccountingPeer::parse(
                &participant_pubkey,
                crate::fips_private_mesh::FipsPaidRouteAccountingRole::LocalBuyer,
            )
        })
        .collect();
    peers.extend(admissions.iter().filter_map(|admission| {
        crate::fips_private_mesh::FipsPaidRouteAccountingPeer::parse(
            &admission.participant_pubkey,
            crate::fips_private_mesh::FipsPaidRouteAccountingRole::LocalSeller,
        )
    }));
    peers.sort_by(|left, right| {
        left.participant_pubkey
            .cmp(&right.participant_pubkey)
            .then_with(|| role_sort_key(left.role).cmp(&role_sort_key(right.role)))
    });
    peers.dedup_by(|left, right| left.participant_pubkey == right.participant_pubkey);
    peers
}

#[cfg(feature = "paid-exit")]
fn role_sort_key(role: crate::fips_private_mesh::FipsPaidRouteAccountingRole) -> u8 {
    match role {
        crate::fips_private_mesh::FipsPaidRouteAccountingRole::LocalBuyer => 0,
        crate::fips_private_mesh::FipsPaidRouteAccountingRole::LocalSeller => 1,
    }
}
async fn fips_tunnel_config_from_app_async(
    input: FipsTunnelConfigInput<'_>,
) -> Result<crate::fips_private_mesh::FipsPrivateTunnelConfig> {
    let app = input.app.clone();
    let config_path = input.config_path.to_path_buf();
    let network_id = input.network_id.to_string();
    let iface = input.iface;
    let underlay_interface = input.underlay_interface.map(ToOwned::to_owned);
    let underlay_interface_mtu = input.underlay_interface_mtu;
    let own_pubkey = input.own_pubkey.map(ToOwned::to_owned);
    let recent_peers = input.recent_peers.cloned();
    let live_peer_endpoints = input.live_peer_endpoints.to_vec();
    let ethernet_underlay = input.ethernet_underlay.cloned();

    tokio::task::spawn_blocking(move || {
        fips_tunnel_config_from_app(FipsTunnelConfigInput {
            app: &app,
            config_path: &config_path,
            network_id: &network_id,
            iface,
            underlay_interface: underlay_interface.as_deref(),
            underlay_interface_mtu,
            own_pubkey: own_pubkey.as_deref(),
            recent_peers: recent_peers.as_ref(),
            live_peer_endpoints: &live_peer_endpoints,
            ethernet_underlay: ethernet_underlay.as_ref(),
        })
    })
    .await
    .context("FIPS tunnel config task failed")?
}

#[cfg(feature = "paid-exit")]
fn fips_paid_route_admissions_from_store(
    app: &AppConfig,
    config_path: &Path,
) -> Result<Vec<FipsPaidRouteAdmission>> {
    if !app.paid_exit.enabled {
        return Ok(Vec::new());
    }
    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    Ok(store
        .seller_admissions(&app.paid_exit, unix_timestamp())
        .into_iter()
        .filter_map(|admission| {
            if let Err(error) = app.validate_paid_exit_seller_buyer(&admission.buyer_pubkey) {
                eprintln!(
                    "paid-exit: withholding seller admission for {}: {error}",
                    admission.buyer_pubkey
                );
                return None;
            }
            Some(crate::fips_private_mesh::fips_paid_route_admission_from_seller_admission(
                admission,
            ))
        })
        .collect())
}
struct SyncFipsPrivateRuntimeContext<'a> {
    app: &'a AppConfig,
    config_path: &'a Path,
    network_id: &'a str,
    iface: &'a str,
    underlay_interface: Option<&'a str>,
    underlay_interface_mtu: Option<u32>,
    own_pubkey: Option<&'a str>,
    recent_peers: Option<&'a nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
    ethernet_underlay: Option<&'a crate::fips_private_mesh::FipsEthernetUnderlayConfig>,
    vpn_enabled: bool,
    expected_peers: usize,
}
async fn sync_fips_private_runtime(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: SyncFipsPrivateRuntimeContext<'_>,
) -> Result<bool> {
    if !fips_private_runtime_active_for_config(
        context.app,
        context.config_path,
        context.vpn_enabled,
        context.expected_peers,
    )? {
        let runtime_replaced = runtime.is_some();
        if let Some(runtime) = runtime.take() {
            stop_fips_private_tunnel_runtime(context.config_path, runtime).await?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !context.app.fips_host_tunnel_enabled {
            crate::fips_host_tunnel::FipsHostTunnelRuntime::cleanup_disabled_artifacts();
        }
        return Ok(runtime_replaced);
    }

    let config_iface = runtime
        .as_ref()
        .map(|runtime| runtime.iface().to_string())
        .unwrap_or_else(|| context.iface.to_string());
    let live_peer_endpoints = runtime
        .as_ref()
        .map(|runtime| runtime.peer_endpoint_hints())
        .unwrap_or_default();
    let ethernet_underlay = runtime
        .as_ref()
        .and_then(crate::fips_private_mesh::FipsPrivateTunnelRuntime::ethernet_underlay)
        .or(context.ethernet_underlay);
    let mut config = fips_tunnel_config_from_app_async(FipsTunnelConfigInput {
        app: context.app,
        config_path: context.config_path,
        network_id: context.network_id,
        iface: config_iface,
        underlay_interface: context.underlay_interface,
        underlay_interface_mtu: context.underlay_interface_mtu,
        own_pubkey: context.own_pubkey,
        // Preserve authenticated non-roster hints across config and link
        // refreshes. The bounded live admission deduction is intentionally
        // restart-neutral, but these hints still carry the working transit
        // path and should not disappear during an ordinary reload.
        recent_peers: context.recent_peers,
        live_peer_endpoints: &live_peer_endpoints,
        ethernet_underlay,
    })
    .await?;
    if !context.vpn_enabled {
        config.disable_client_dataplane();
    }

    let restart = runtime
        .as_ref()
        .is_some_and(|existing| existing.requires_endpoint_restart(&config));
    if restart {
        if let Some(existing) = runtime.take() {
            stop_fips_private_tunnel_runtime(context.config_path, existing).await?;
        }
        let started = start_fips_private_tunnel_runtime(context.config_path, config).await?;
        eprintln!("daemon: restarted FIPS private mesh on {}", started.iface());
        *runtime = Some(started);
        Ok(true)
    } else if let Some(existing) = runtime.as_mut() {
        apply_fips_private_tunnel_runtime_config(context.config_path, existing, config).await?;
        Ok(false)
    } else {
        let started = start_fips_private_tunnel_runtime(context.config_path, config).await?;
        eprintln!("daemon: FIPS private mesh on {}", started.iface());
        *runtime = Some(started);
        Ok(true)
    }
}
async fn send_pending_fips_join_requests(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    sent_cache: &mut HashMap<String, u64>,
    now: u64,
) -> Result<usize> {
    let Some(network) = app.active_network_opt() else {
        return Ok(0);
    };
    let Some(pending) = network.outbound_join_request.as_ref() else {
        return Ok(0);
    };
    let recipients = pending_fips_join_request_recipients(app);
    if recipients.is_empty() {
        return Ok(0);
    }
    let request = MeshJoinRequest {
        network_id: normalize_runtime_network_id(&network.network_id),
        join_secret: network.join_secret.clone(),
        requester_node_name: app.node_name.trim().to_string(),
    };

    let mut sent = 0usize;
    for recipient in recipients {
        let fingerprint = format!(
            "{}:{recipient}:{}",
            request.network_id, pending.requested_at
        );
        if sent_cache
            .get(&fingerprint)
            .is_some_and(|last_sent| now.saturating_sub(*last_sent) < FIPS_JOIN_REQUEST_RETRY_SECS)
        {
            continue;
        }
        runtime
            .send_join_request(&recipient, pending.requested_at, request.clone())
            .await?;
        sent_cache.insert(fingerprint, now);
        sent += 1;
    }
    Ok(sent)
}

fn pending_fips_join_request_recipients(app: &AppConfig) -> Vec<String> {
    let Some(network) = app.active_network_opt() else {
        return Vec::new();
    };
    let Some(pending) = network.outbound_join_request.as_ref() else {
        return Vec::new();
    };
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut recipients = if network
        .admins
        .iter()
        .any(|admin| admin == &pending.recipient)
    {
        vec![pending.recipient.clone()]
    } else {
        network.admins.clone()
    };
    recipients.retain(|recipient| own_pubkey.as_deref() != Some(recipient.as_str()));
    recipients.sort();
    recipients.dedup();
    recipients
}
fn publish_fips_active_network_roster(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    pending_recipients: &mut HashSet<String>,
) -> Result<usize> {
    publish_fips_active_network_roster_to(runtime, app, config_path, &[], pending_recipients)
}
async fn broadcast_local_fips_capabilities(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
) -> Result<usize> {
    let Some(network) = app.active_network_opt() else {
        return Ok(0);
    };
    let advertised_routes = runtime_effective_advertised_routes(app);
    let local_ipv4_candidates = runtime_signal_ipv4_candidates_async(&app.node.tunnel_ip).await;
    let local_advertised_endpoints = match runtime.local_advertised_endpoints().await {
        Ok(endpoints) => endpoints,
        Err(error) => {
            eprintln!("fips: local advertised endpoint snapshot failed: {error}");
            Vec::new()
        }
    };
    let endpoint_hints =
        local_fips_endpoint_hints(app, local_ipv4_candidates, &local_advertised_endpoints);
    let desired_hint_recipients = desired_fips_endpoint_hint_recipients(app);
    let signed_at = unix_timestamp();
    let mut sent = 0usize;

    for participant in runtime.peer_pubkeys() {
        let capabilities = PeerCapabilities {
            advertised_routes: advertised_routes.clone(),
            endpoint_hints: if desired_hint_recipients.contains(&participant) {
                endpoint_hints.clone()
            } else {
                Vec::new()
            },
            dataplane_features: local_fips_dataplane_features(),
            signed_at,
        };
        if runtime
            .enqueue_capabilities(&participant, &network.id, capabilities)
            .is_ok()
        {
            sent += 1;
        }
    }

    Ok(sent)
}
include!("runtime_helpers/endpoint_hints.rs");
fn local_advertised_udp_endpoint_hint_addr(endpoint: &OverlayEndpointAdvert) -> Option<String> {
    if endpoint.transport != OverlayTransportKind::Udp {
        return None;
    }
    let hint = PeerEndpointHint::udp(endpoint.addr.trim());
    nostr_vpn_core::fips_control::peer_endpoint_hint_addr(&hint)
}
fn runtime_signal_ipv4_candidates(
    detected_ipv4: Option<Ipv4Addr>,
    tunnel_ip: &str,
) -> Vec<Ipv4Addr> {
    let tunnel_ipv4 = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok();
    let mut ips = Vec::new();
    if let Some(ip) = runtime_signal_ipv4(detected_ipv4, tunnel_ip)
        && ipv4_is_lan_endpoint_hint(ip)
    {
        ips.push(ip);
    }
    for iface in netdev::get_interfaces() {
        if iface.is_loopback() {
            continue;
        }
        for net in &iface.ipv4 {
            let ip = net.addr();
            if Some(ip) == tunnel_ipv4
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || !ipv4_is_lan_endpoint_hint(ip)
            {
                continue;
            }
            ips.push(ip);
        }
    }
    ips.sort();
    ips.dedup();
    ips
}
async fn runtime_signal_ipv4_candidates_async(tunnel_ip: &str) -> Vec<Ipv4Addr> {
    let tunnel_ip = tunnel_ip.to_string();
    match tokio::task::spawn_blocking(move || {
        runtime_signal_ipv4_candidates(detect_runtime_primary_ipv4(), &tunnel_ip)
    })
    .await
    {
        Ok(ips) => ips,
        Err(error) => {
            eprintln!("fips: local IPv4 candidate discovery task failed: {error}");
            Vec::new()
        }
    }
}
fn endpoint_is_gossipable_direct_hint(endpoint: &str, allow_local: bool) -> bool {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        if parsed.port() == 0 || endpoint_hint_ip_is_unusable(parsed.ip()) {
            return false;
        }
        return allow_local || !endpoint_is_local_only(&parsed.to_string());
    }

    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return false;
    };
    let host = host.trim();
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 || host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if host.contains(':') {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && endpoint_hint_ip_is_unusable(ip)
    {
        return false;
    }
    allow_local || !endpoint_is_local_only(trimmed)
}
fn endpoint_uses_tunnel_ip(endpoint: &str, tunnel_ip: &str) -> bool {
    let Ok(tunnel_ip) = strip_cidr(tunnel_ip).parse::<IpAddr>() else {
        return false;
    };
    endpoint_addr_ip(endpoint).is_some_and(|ip| ip == tunnel_ip)
}
fn endpoint_addr_ip(endpoint: &str) -> Option<IpAddr> {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return Some(parsed.ip());
    }

    let (host, _) = trimmed.rsplit_once(':')?;
    host.trim().parse::<IpAddr>().ok()
}
fn endpoint_hint_ip_is_unusable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ipv4_is_cgnat(ip)
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}
fn ipv4_is_lan_endpoint_hint(ip: Ipv4Addr) -> bool {
    ip.is_private()
}
fn ipv4_is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}
fn desired_fips_endpoint_hint_recipients(app: &AppConfig) -> HashSet<String> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| own_pubkey.as_deref() != Some(participant.as_str()))
        .collect()
}
