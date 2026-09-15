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
    join_roster_deliveries: Vec<tokio::task::JoinHandle<bool>>,
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
        finish_join_roster_deliveries_before_runtime_sync(
            context.join_roster_deliveries,
            runtime_replaced,
        )
        .await;
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
    finish_join_roster_deliveries_before_runtime_sync(context.join_roster_deliveries, restart)
        .await;
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

async fn fips_relay_statuses_from_runtime(
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
macro_rules! current_fips_relay_statuses {
    ($runtime:expr) => {
        fips_relay_statuses_from_runtime($runtime)
    };
}
pub(crate) const FIPS_STALE_PARTICIPANT_RESTART_COOLDOWN_SECS: u64 = 60;
pub(crate) const FIPS_PENDING_ROSTER_RESTART_GRACE_SECS: u64 = 45;
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
fn fips_peer_count(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_statuses: &[MeshPeerStatus],
) -> usize {
    let participant_pubkeys_list = app.participant_pubkeys_hex();
    let participant_pubkeys = participant_pubkeys_list
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    peer_statuses
        .iter()
        .filter(|status| Some(status.pubkey.as_str()) != own_pubkey)
        .filter(|status| participant_pubkeys.contains(&status.pubkey))
        .filter(|status| status.connected)
        .count()
}
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

fn credible_daemon_peer_timestamp(now: u64, timestamp: Option<u64>) -> Option<u64> {
    let timestamp = timestamp?;
    if timestamp > now && timestamp - now > DAEMON_PEER_MAX_FUTURE_SKEW_SECS {
        return None;
    }
    Some(timestamp)
}
fn flush_pending_fips_roster_recipients(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    pending_recipients: &mut HashSet<String>,
) {
    if pending_recipients.is_empty() {
        return;
    }
    match publish_fips_active_network_roster(runtime, app, config_path, pending_recipients) {
        Ok(_) => {}
        Err(error) => eprintln!("fips: queued roster publish failed: {error}"),
    }
}
pub(crate) type EndpointPeerSignature =
    Vec<(String, bool, bool, Vec<(String, Option<u64>, u8)>)>;
type RecentPeerRefreshSignature = (
    Vec<(String, Vec<String>)>,
    Vec<(String, Vec<String>)>,
);
const RECENT_PEER_CACHE_TIMESTAMP_FLUSH_SECS: u64 = 5 * 60;
struct RecentPeerRefresh<'a> {
    recent_peers: &'a mut nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    recent_peers_path: &'a std::path::Path,
    last_endpoint_peer_signature: &'a mut EndpointPeerSignature,
    last_refresh_signature: &'a mut Option<RecentPeerRefreshSignature>,
    last_cache_persisted_at: &'a mut u64,
    force_rebuild: bool,
}
struct FipsRestartContext<'a> {
    app: &'a nostr_vpn_core::config::AppConfig,
    config_path: &'a std::path::Path,
    network_id: &'a str,
    fallback_iface: &'a str,
    underlay_interface: Option<&'a str>,
    underlay_interface_mtu: Option<u32>,
    own_pubkey: Option<&'a str>,
    recent_peers: Option<&'a nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
    ethernet_underlay: Option<&'a crate::fips_private_mesh::FipsEthernetUnderlayConfig>,
    client_dataplane_enabled: bool,
    last_endpoint_peer_signature: &'a mut EndpointPeerSignature,
}
struct FipsLinkRefreshCompletion<'a> {
    runtime: Option<&'a crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    app: &'a nostr_vpn_core::config::AppConfig,
    network_id: &'a str,
    own_pubkey: Option<&'a str>,
    recent_peers: &'a mut nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    recent_peers_path: &'a std::path::Path,
    last_endpoint_peer_signature: &'a mut EndpointPeerSignature,
    last_refresh_signature: &'a mut Option<RecentPeerRefreshSignature>,
    last_cache_persisted_at: &'a mut u64,
    vpn_enabled: bool,
    expected_peers: usize,
    now: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FipsLinkEventRefresh {
    None,
    RestartEndpoint,
    RebindUnderlayAndRefreshPaths,
    ReconcileNetworkState,
    UpdatePeersAndRefreshPaths,
}
impl FipsLinkEventRefresh {
    const fn explicitly_refreshes_peer_paths(self) -> bool {
        matches!(self, Self::UpdatePeersAndRefreshPaths)
    }
}
#[derive(Debug, Default)]
pub(crate) struct FipsPendingRosterRestartState {
    pending_since: Option<u64>,
    last_restart_at: Option<u64>,
}
pub(crate) fn fips_link_event_refresh(
    _platform_network_event: bool,
    network_changed: bool,
    network_state_drift: bool,
    endpoint_changed: bool,
    resumed_after_sleep: bool,
) -> FipsLinkEventRefresh {
    if resumed_after_sleep {
        FipsLinkEventRefresh::RestartEndpoint
    } else if network_changed {
        // Preserve established FIPS sessions across ordinary address/route
        // handoffs, but replace the configured UDP sockets whose kernel source
        // address belonged to the previous network. The runtime's config
        // comparison below still replaces the endpoint when its physical
        // interface, bind, MTU, or transport configuration actually changed.
        FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
    } else if network_state_drift {
        FipsLinkEventRefresh::ReconcileNetworkState
    } else if endpoint_changed {
        FipsLinkEventRefresh::UpdatePeersAndRefreshPaths
    } else {
        // Route notifications wake the network snapshot comparison. They are
        // not evidence by themselves that authenticated peer paths changed.
        FipsLinkEventRefresh::None
    }
}

pub(crate) fn fips_stale_participant_restart_due(
    last_restart_at: &mut Option<u64>,
    now: u64,
) -> bool {
    let due = last_restart_at.is_none_or(|last_restart_at| {
        now < last_restart_at
            || now.saturating_sub(last_restart_at)
                >= FIPS_STALE_PARTICIPANT_RESTART_COOLDOWN_SECS
    });
    if due {
        *last_restart_at = Some(now);
    }
    due
}

include!("fips_status_helpers/stale_participant_recovery.rs");

pub(crate) fn fips_endpoint_control_requires_runtime_replacement(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<fips_endpoint::FipsEndpointError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    fips_endpoint::FipsEndpointError::Closed
                        | fips_endpoint::FipsEndpointError::Timeout { .. }
                )
            })
    })
}

fn fips_pending_roster_links_detected(
    peer_statuses: &[MeshPeerStatus],
    relay_statuses: &[DaemonRelayState],
    roster_pubkeys: &HashSet<String>,
    expected_peers: usize,
) -> bool {
    if expected_peers == 0
        || roster_pubkeys.is_empty()
        || !relay_statuses
            .iter()
            .any(|relay| relay.status.eq_ignore_ascii_case("connected"))
    {
        return false;
    }
    if peer_statuses
        .iter()
        .any(|status| roster_pubkeys.contains(&status.pubkey) && status.connected)
    {
        return false;
    }
    let pending = peer_statuses
        .iter()
        .filter(|status| {
            roster_pubkeys.contains(&status.pubkey)
                && !status.connected
                && status.last_seen_at.is_none()
                && status.error.as_deref() == Some("fips link pending")
        })
        .count();
    pending >= expected_peers
}
pub(crate) fn fips_pending_roster_restart_due(
    peer_statuses: &[MeshPeerStatus],
    relay_statuses: &[DaemonRelayState],
    roster_pubkeys: &HashSet<String>,
    expected_peers: usize,
    state: &mut FipsPendingRosterRestartState,
    now: u64,
) -> bool {
    if !fips_pending_roster_links_detected(
        peer_statuses,
        relay_statuses,
        roster_pubkeys,
        expected_peers,
    ) {
        state.pending_since = None;
        return false;
    }
    let pending_since = match state.pending_since {
        Some(pending_since) if now >= pending_since => pending_since,
        _ => {
            state.pending_since = Some(now);
            return false;
        }
    };
    if now.saturating_sub(pending_since) < FIPS_PENDING_ROSTER_RESTART_GRACE_SECS {
        return false;
    }
    if !fips_stale_participant_restart_due(&mut state.last_restart_at, now) {
        return false;
    }
    state.pending_since = None;
    true
}
fn endpoint_peer_signature(
    endpoint_peers: &[crate::fips_private_mesh::FipsEndpointPeerTransportConfig],
) -> EndpointPeerSignature {
    endpoint_peers
        .iter()
        .map(|peer| {
            let mut addresses = peer
                .addresses
                .iter()
                .map(|hint| (hint.addr.clone(), hint.seen_at_ms, hint.priority))
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            (
                peer.npub.clone(),
                peer.auto_reconnect,
                peer.discovery_fallback_transit,
                addresses,
            )
        })
        .collect()
}
pub(crate) fn daemon_endpoint_peer_states_from_signature(
    signature: &EndpointPeerSignature,
) -> Vec<DaemonFipsEndpointPeerState> {
    signature
        .iter()
        .map(
            |(npub, auto_reconnect, discovery_fallback_transit, addresses)| {
                DaemonFipsEndpointPeerState {
                    npub: npub.clone(),
                    addresses: addresses
                        .iter()
                        .map(|(addr, seen_at_ms, priority)| DaemonFipsEndpointPeerAddressState {
                            addr: addr.clone(),
                            seen_at_ms: *seen_at_ms,
                            priority: *priority,
                        })
                        .collect(),
                    auto_reconnect: *auto_reconnect,
                    discovery_fallback_transit: *discovery_fallback_transit,
                }
            },
        )
        .collect()
}
fn endpoint_peers_for_participant_refresh(
    endpoint_peers: &[crate::fips_private_mesh::FipsEndpointPeerTransportConfig],
    participants: &[String],
) -> Vec<crate::fips_private_mesh::FipsEndpointPeerTransportConfig> {
    if participants.is_empty() {
        return Vec::new();
    }

    let participant_keys = participants
        .iter()
        .filter_map(|participant| {
            nostr_sdk::prelude::PublicKey::parse(participant.trim())
                .ok()
                .map(|key| *key.as_bytes())
        })
        .collect::<std::collections::HashSet<_>>();
    if participant_keys.is_empty() {
        return Vec::new();
    }

    endpoint_peers
        .iter()
        .filter(|peer| {
            nostr_sdk::prelude::PublicKey::parse(peer.npub.trim())
                .ok()
                .is_some_and(|key| participant_keys.contains(key.as_bytes()))
        })
        .cloned()
        .collect()
}

/// Snapshot the runtime's authenticated FIPS peers, update
/// the on-disk recent-peers cache, and hand fips the refreshed peer hint
/// list via `update_peers` so reusable authenticated UDP candidates can race
/// existing configured routes without restarting the endpoint.
async fn update_recent_peers_from_runtime(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &nostr_vpn_core::config::AppConfig,
    network_id: &str,
    own_pubkey: Option<&str>,
    refresh: RecentPeerRefresh<'_>,
    now: u64,
) {
    let snapshot = match runtime.authenticated_endpoint_peers().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("fips: peer endpoint snapshot failed: {error}");
            Vec::new()
        }
    };
    let recent_topology_before = refresh.recent_peers.as_static_peer_endpoints();
    let mut changed = false;
    for peer in snapshot {
        match refresh
            .recent_peers
            .observe_authenticated_peer(&peer, now)
        {
            Ok(true) => changed = true,
            Ok(false) => {}
            Err(error) => {
                eprintln!("fips: ignoring invalid authenticated peer {}: {error}", peer.npub);
            }
        }
    }
    if refresh
        .recent_peers
        .prune_stale(now, crate::recent_peers_store::RECENT_PEERS_TTL_SECS)
    {
        changed = true;
    }
    let recent_topology_after = refresh.recent_peers.as_static_peer_endpoints();
    let topology_changed = recent_topology_before != recent_topology_after;
    let cache_timestamp_flush_due = changed
        && now.saturating_sub(*refresh.last_cache_persisted_at)
            >= RECENT_PEER_CACHE_TIMESTAMP_FLUSH_SECS;
    if (topology_changed || cache_timestamp_flush_due)
        && let Err(error) = crate::recent_peers_store::write_recent_peers(
            refresh.recent_peers_path,
            refresh.recent_peers,
        )
    {
        eprintln!(
            "daemon: failed to write recent peers cache {}: {error}",
            refresh.recent_peers_path.display()
        );
    } else if topology_changed || cache_timestamp_flush_due {
        *refresh.last_cache_persisted_at = now;
    }
    let live_peer_endpoints = runtime.peer_endpoint_hints();
    let input_signature = recent_peer_refresh_signature(refresh.recent_peers, &live_peer_endpoints);
    if !refresh.force_rebuild
        && refresh.last_refresh_signature.as_ref() == Some(&input_signature)
    {
        return;
    }
    let refreshed = {
        let app = app.clone();
        let network_id = network_id.to_string();
        let iface = runtime.iface().to_string();
        let own_pubkey = own_pubkey.map(ToOwned::to_owned);
        let recent_peers = refresh.recent_peers.clone();
        tokio::task::spawn_blocking(move || {
            crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app(
                &app,
                &network_id,
                iface,
                own_pubkey.as_deref(),
                Some(&recent_peers),
                &live_peer_endpoints,
            )
        })
        .await
    };
    match refreshed {
        Ok(Ok(refreshed)) => {
            let signature = endpoint_peer_signature(&refreshed.endpoint_peers);
            if signature == *refresh.last_endpoint_peer_signature {
                *refresh.last_refresh_signature = Some(input_signature);
                return;
            }
            if let Err(error) = runtime.update_peers(&refreshed.endpoint_peers).await {
                eprintln!("fips: update_peers (cache refresh) failed: {error}");
            } else {
                *refresh.last_endpoint_peer_signature = signature;
                *refresh.last_refresh_signature = Some(input_signature);
            }
        }
        Ok(Err(error)) => {
            eprintln!("fips: rebuilding peer hint list failed: {error}");
        }
        Err(error) => {
            eprintln!("fips: peer hint rebuild task failed: {error}");
        }
    }
}

fn recent_peer_refresh_signature(
    recent_peers: &nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    live_peer_endpoints: &[(String, Vec<(String, u64)>)],
) -> RecentPeerRefreshSignature {
    let mut live = live_peer_endpoints
        .iter()
        .filter_map(|(participant, endpoints)| {
            let mut addresses = endpoints
                .iter()
                .map(|(address, _)| address.clone())
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            (!addresses.is_empty()).then(|| (participant.clone(), addresses))
        })
        .collect::<Vec<_>>();
    live.sort();
    live.dedup();
    (recent_peers.as_static_peer_endpoints(), live)
}

async fn rebind_fips_tunnel_runtime_underlay_after_link_event(
    runtime: &Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    underlay_interface: Option<&str>,
    reason: &str,
) -> Result<()> {
    let Some(runtime) = runtime.as_ref() else {
        return Ok(());
    };
    let rebound = runtime
        .rebind_network_transports(underlay_interface.map(ToOwned::to_owned))
        .await?;
    eprintln!(
        "daemon: FIPS underlay carrier(s) rebound on {} after {reason} ({rebound}); refreshed_unix_ms={}",
        runtime.iface(),
        daemon_wall_clock_unix_milliseconds()
    );
    Ok(())
}

async fn fips_tunnel_config_for_link_event(
    input: FipsTunnelConfigInput<'_>,
) -> Result<crate::fips_private_mesh::FipsPrivateTunnelConfig> {
    tokio::time::timeout(
        Duration::from_millis(FIPS_LINK_EVENT_CONFIG_BUILD_TIMEOUT_MILLIS),
        fips_tunnel_config_from_app_async(input),
    )
    .await
    .context("FIPS tunnel config build timed out during link recovery")?
}

async fn refresh_fips_tunnel_runtime_after_link_event(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: FipsRestartContext<'_>,
    reason: &str,
    refresh: FipsLinkEventRefresh,
) -> Result<()> {
    let config_iface = runtime
        .as_ref()
        .map(|runtime| runtime.iface().to_string())
        .unwrap_or_else(|| context.fallback_iface.to_string());
    // Do not carry learned endpoint hints across link changes. They may belong
    // to a previous underlay or NAT mapping.
    let live_peer_endpoints = Vec::new();
    let mut config = fips_tunnel_config_for_link_event(
        FipsTunnelConfigInput {
            app: context.app,
            config_path: context.config_path,
            network_id: context.network_id,
            iface: config_iface,
            underlay_interface: context.underlay_interface,
            underlay_interface_mtu: context.underlay_interface_mtu,
            own_pubkey: context.own_pubkey,
            recent_peers: context.recent_peers,
            live_peer_endpoints: &live_peer_endpoints,
            ethernet_underlay: context.ethernet_underlay,
        },
    )
    .await?;
    if !context.client_dataplane_enabled {
        config.disable_client_dataplane();
    }
    let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);
    let endpoint_peers = config.endpoint_peers.clone();
    if matches!(refresh, FipsLinkEventRefresh::RestartEndpoint)
        || runtime
            .as_ref()
            .is_some_and(|existing| existing.requires_endpoint_restart(&config))
    {
        if let Some(existing) = runtime.take() {
            stop_fips_private_tunnel_runtime(context.config_path, existing).await?;
        }
        let started = start_fips_private_tunnel_runtime(context.config_path, config).await?;
        eprintln!(
            "daemon: restarted FIPS private mesh on {} after {reason}",
            started.iface()
        );
        *runtime = Some(started);
    } else if let Some(existing) = runtime.as_mut() {
        if matches!(
            refresh,
            FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
                | FipsLinkEventRefresh::ReconcileNetworkState
        ) {
            // Apply the canonical route, DNS, and runtime config for both
            // accepted carrier changes and same-carrier route drift.
            #[cfg(target_os = "macos")]
            if matches!(refresh, FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths) {
                existing
                    .rebind_macos_wg_upstream_after_link_event(&config)
                    .await?;
            }
            apply_fips_private_tunnel_runtime_config(context.config_path, existing, config).await?;
        } else if matches!(
            refresh,
            FipsLinkEventRefresh::UpdatePeersAndRefreshPaths
        ) {
            existing.update_peers(&endpoint_peers).await?;
        }
        if matches!(refresh, FipsLinkEventRefresh::ReconcileNetworkState) {
            eprintln!(
                "daemon: reconciled FIPS network state on {} after {reason}; refreshed_unix_ms={}",
                existing.iface(),
                daemon_wall_clock_unix_milliseconds(),
            );
        } else if refresh.explicitly_refreshes_peer_paths() {
            let refreshed = existing.refresh_peer_paths(&endpoint_peers).await?;
            eprintln!(
                "daemon: refreshed FIPS private mesh paths on {} after {reason} ({refreshed} direct probe(s) started); refreshed_unix_ms={}",
                existing.iface(),
                daemon_wall_clock_unix_milliseconds(),
            );
        } else if matches!(refresh, FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths) {
            // The rebind already invalidated affected paths and scheduled
            // reprobes after FIPS's underlay/roam guard. An immediate second
            // refresh races that guard and can delay authenticated payload.
            eprintln!(
                "daemon: FIPS private mesh path reprobe owned by carrier rebind on {} after {reason}",
                existing.iface(),
            );
        }
    } else {
        let started = start_fips_private_tunnel_runtime(context.config_path, config).await?;
        eprintln!("daemon: FIPS private mesh on {} after {reason}", started.iface());
        *runtime = Some(started);
    }
    *context.last_endpoint_peer_signature = endpoint_peer_signature;
    Ok(())
}

async fn complete_fips_link_event_refresh(context: FipsLinkRefreshCompletion<'_>) -> String {
    if let Some(runtime) = context.runtime {
        if let Err(error) = runtime.ping_peers(context.network_id, context.now).await {
            eprintln!("fips: peer ping failed after network refresh: {error}");
        }
        if let Err(error) = runtime.refresh_link_statuses().await {
            eprintln!("fips: peer link snapshot failed after network refresh: {error}");
        }
        update_recent_peers_from_runtime(
            runtime,
            context.app,
            context.network_id,
            context.own_pubkey,
            RecentPeerRefresh {
                recent_peers: context.recent_peers,
                recent_peers_path: context.recent_peers_path,
                last_endpoint_peer_signature: context.last_endpoint_peer_signature,
                last_refresh_signature: context.last_refresh_signature,
                last_cache_persisted_at: context.last_cache_persisted_at,
                force_rebuild: true,
            },
            context.now,
        )
        .await;
        if let Err(error) = broadcast_local_fips_capabilities(runtime, context.app).await {
            eprintln!("fips: capabilities broadcast failed after network refresh: {error}");
        }
    }
    if daemon_vpn_active(context.vpn_enabled, context.expected_peers) {
        "Connected (network refresh)".to_string()
    } else {
        daemon_vpn_idle_status(
            context.vpn_enabled,
            context.expected_peers,
            context.app.join_requests_enabled(),
        )
        .to_string()
    }
}

async fn rebuild_fips_tunnel_runtime_after_control_failure(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: FipsRestartContext<'_>,
    reason: &str,
) -> Result<()> {
    let config_iface = runtime
        .as_ref()
        .map(|runtime| runtime.iface().to_string())
        .unwrap_or_else(|| context.fallback_iface.to_string());
    let live_peer_endpoints = runtime
        .as_ref()
        .map(|runtime| runtime.peer_endpoint_hints())
        .unwrap_or_default();
    let config = fips_tunnel_config_from_app_async(FipsTunnelConfigInput {
        app: context.app,
        config_path: context.config_path,
        network_id: context.network_id,
        iface: config_iface,
        underlay_interface: context.underlay_interface,
        underlay_interface_mtu: context.underlay_interface_mtu,
        own_pubkey: context.own_pubkey,
        recent_peers: context.recent_peers,
        live_peer_endpoints: &live_peer_endpoints,
        ethernet_underlay: context.ethernet_underlay,
    })
    .await?;
    let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);

    if let Some(existing) = runtime.take() {
        stop_fips_private_tunnel_runtime(context.config_path, existing)
            .await
            .context("refusing to rebuild FIPS after incomplete prior cleanup")?;
    }
    let started = start_fips_private_tunnel_runtime(context.config_path, config).await?;
    eprintln!(
        "daemon: rebuilt FIPS private mesh on {} after {reason}",
        started.iface()
    );
    *runtime = Some(started);
    *context.last_endpoint_peer_signature = endpoint_peer_signature;
    Ok(())
}
async fn refresh_fips_tunnel_runtime_peer_paths(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: FipsRestartContext<'_>,
    stale_participants: &[String],
) -> Result<bool> {
    let Some(current) = runtime.as_ref() else {
        return Ok(false);
    };
    refresh_fips_tunnel_runtime_peer_paths_in_place(
        current,
        context,
        stale_participants,
        "stale participant liveness",
    )
    .await?;
    Ok(false)
}
async fn refresh_fips_tunnel_runtime_peer_paths_in_place(
    current: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    context: FipsRestartContext<'_>,
    participants: &[String],
    reason: &str,
) -> Result<()> {
    let live_peer_endpoints = current.peer_endpoint_hints();
    let mut config = fips_tunnel_config_from_app_async(
        FipsTunnelConfigInput {
            app: context.app,
            config_path: context.config_path,
            network_id: context.network_id,
            iface: current.iface().to_string(),
            underlay_interface: context.underlay_interface,
            underlay_interface_mtu: context.underlay_interface_mtu,
            own_pubkey: context.own_pubkey,
            recent_peers: context.recent_peers,
            live_peer_endpoints: &live_peer_endpoints,
            ethernet_underlay: context.ethernet_underlay,
        },
    )
    .await?;
    if !context.client_dataplane_enabled {
        config.disable_client_dataplane();
    }
    let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);
    let outcome = current.update_peers(&config.endpoint_peers).await?;
    let refresh_endpoint_peers =
        endpoint_peers_for_participant_refresh(&config.endpoint_peers, participants);
    if refresh_endpoint_peers.is_empty() {
        eprintln!(
            "daemon: no matching FIPS endpoint peer paths for {} participant(s) after {reason}",
            participants.len()
        );
        *context.last_endpoint_peer_signature = endpoint_peer_signature;
        return Ok(());
    }
    let refreshed = current.refresh_peer_paths(&refresh_endpoint_peers).await?;
    *context.last_endpoint_peer_signature = endpoint_peer_signature;
    eprintln!(
        "daemon: refreshed FIPS endpoint peer paths in place after {reason} (targets={} added={} updated={} unchanged={} removed={} direct_refreshes={})",
        refresh_endpoint_peers.len(),
        outcome.added,
        outcome.updated,
        outcome.unchanged,
        outcome.removed,
        refreshed
    );
    Ok(())
}
async fn restart_fips_tunnel_runtime_after_pending_roster_links(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: FipsRestartContext<'_>,
    expected_peers: usize,
    state: &mut FipsPendingRosterRestartState,
    now: u64,
) -> Result<bool> {
    let Some(current) = runtime.as_ref() else {
        return Ok(false);
    };
    let peer_statuses = current.peer_statuses();
    let relay_statuses = match current.relay_statuses().await {
        Ok(relays) => relays
            .into_iter()
            .map(|relay| DaemonRelayState {
                url: relay.url,
                status: relay.status,
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            eprintln!("fips: relay status snapshot failed during pending roster recovery: {error}");
            Vec::new()
        }
    };
    if !fips_pending_roster_restart_due(
        &peer_statuses,
        &relay_statuses,
        &fips_roster_pubkeys(context.app, context.own_pubkey),
        expected_peers,
        state,
        now,
    ) {
        return Ok(false);
    }
    eprintln!(
        "daemon: refreshing FIPS private mesh paths after all {expected_peers} roster link(s) stayed pending with relay discovery connected"
    );
    refresh_fips_tunnel_runtime_after_link_event(
        runtime,
        context,
        "all FIPS roster links pending",
        FipsLinkEventRefresh::UpdatePeersAndRefreshPaths,
    )
    .await?;
    Ok(true)
}
fn fips_roster_pubkeys(app: &AppConfig, own_pubkey: Option<&str>) -> HashSet<String> {
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .collect()
}

fn prefer_nonself_tunnel_snapshot(
    tunnel_runtime: &CliTunnelRuntime,
    wireguard_exit_interface: Option<&str>,
    wireguard_exit_ipv4: Option<Ipv4Addr>,
    previous: &crate::diagnostics::NetworkSnapshot,
    latest: crate::diagnostics::NetworkSnapshot,
) -> crate::diagnostics::NetworkSnapshot {
    let latest = crate::diagnostics::prefer_nonempty_network_snapshot(previous, latest);
    if latest.default_interface.is_some()
        && latest.default_interface == previous.default_interface
        && previous.primary_ipv4.is_some()
        && latest.primary_ipv4.is_none()
        && latest.gateway_ipv4.is_none()
    {
        return previous.clone();
    }
    match latest.default_interface.as_deref() {
        Some(iface)
            if tunnel_runtime.owns_interface(iface)
                || wireguard_exit_interface.is_some_and(|managed| managed == iface)
                || wireguard_exit_ipv4.is_some_and(|managed| latest.primary_ipv4 == Some(managed)) =>
        {
            previous.clone()
        }
        _ => latest,
    }
}

async fn capture_network_snapshot_for_daemon(
    tunnel_interface: &str,
    wireguard_exit_interface: Option<&str>,
    default_route_hints: Vec<String>,
) -> crate::diagnostics::NetworkSnapshotSample {
    let mut excluded_interfaces = vec![tunnel_interface.to_string()];
    if let Some(interface) = wireguard_exit_interface {
        excluded_interfaces.push(interface.to_string());
    }
    match tokio::task::spawn_blocking(move || {
        let excluded_interfaces = excluded_interfaces
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        crate::diagnostics::capture_network_snapshot_sample_excluding_interfaces(
            &excluded_interfaces,
            &default_route_hints,
        )
    })
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("daemon: network snapshot task failed: {error}");
            let snapshot = crate::diagnostics::NetworkSnapshot::default();
            crate::diagnostics::NetworkSnapshotSample {
                diagnostic: "selected=none reason=snapshot-task-failed".to_string(),
                snapshot,
                live_unmanaged_ipv4_default_present: false,
            }
        }
    }
}

fn spawn_platform_network_change_monitor() -> Option<tokio::sync::mpsc::Receiver<()>> {
    #[cfg(target_os = "linux")]
    {
        crate::linux_network::spawn_linux_route_change_monitor()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos_network::spawn_macos_route_change_monitor()
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows_network::spawn_windows_route_change_monitor()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

async fn recv_platform_network_change(
    rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
) -> Option<()> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn drain_platform_network_changes(rx: &mut Option<tokio::sync::mpsc::Receiver<()>>) {
    let Some(rx) = rx.as_mut() else {
        return;
    };
    while rx.try_recv().is_ok() {}
}

pub(crate) fn drain_platform_network_changes_for_sample(
    rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
    event_driven_sample: bool,
) {
    // Discard notifications already represented by an event-owned
    // kernel-state sample so a storm cannot starve its absolute deadline.
    if event_driven_sample {
        drain_platform_network_changes(rx);
    }
}

fn log_event_driven_network_sample(
    event_driven_sample: bool,
    sampled_network: &crate::diagnostics::NetworkSnapshotSample,
    last_diagnostic: &mut String,
) {
    if event_driven_sample && sampled_network.diagnostic != *last_diagnostic {
        eprintln!(
            "daemon: physical route sample: {}; sampled_unix_ms={}",
            sampled_network.diagnostic,
            daemon_wall_clock_unix_milliseconds()
        );
        sampled_network.diagnostic.clone_into(last_diagnostic);
    }
}
