use super::*;

pub(super) struct FipsHeartbeatContext<'a> {
    pub(super) runtime: &'a mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    pub(super) app: &'a AppConfig,
    pub(super) config_path: &'a Path,
    pub(super) network_id: &'a str,
    pub(super) fallback_iface: &'a str,
    pub(super) underlay_interface: Option<&'a str>,
    pub(super) underlay_interface_mtu: Option<u32>,
    pub(super) own_pubkey: Option<&'a str>,
    pub(super) recent_peers: &'a nostr_vpn_core::recent_peers::RecentPeerEndpoints,
    pub(super) ethernet_underlay: Option<&'a crate::fips_private_mesh::FipsEthernetUnderlayConfig>,
    pub(super) expected_peers: usize,
    pub(super) last_endpoint_peer_signature: &'a mut EndpointPeerSignature,
    pub(super) last_stale_participant_restart_at: &'a mut Option<u64>,
    pub(super) pending_roster_restart_state: &'a mut FipsPendingRosterRestartState,
    pub(super) roster_sync_state: &'a mut FipsRosterSyncState,
    pub(super) pending_roster_recipients: &'a mut HashSet<String>,
    pub(super) join_request_sends: &'a mut HashMap<String, u64>,
}

pub(super) async fn maintain_fips_heartbeat(context: FipsHeartbeatContext<'_>) {
    let FipsHeartbeatContext {
        runtime,
        app,
        config_path,
        network_id,
        fallback_iface,
        underlay_interface,
        underlay_interface_mtu,
        own_pubkey,
        recent_peers,
        ethernet_underlay,
        expected_peers,
        last_endpoint_peer_signature,
        last_stale_participant_restart_at,
        pending_roster_restart_state,
        roster_sync_state,
        pending_roster_recipients,
        join_request_sends,
    } = context;
    let now = unix_timestamp();
    let client_dataplane_enabled = runtime
        .as_ref()
        .is_some_and(crate::fips_private_mesh::FipsPrivateTunnelRuntime::client_dataplane_enabled);
    let pending_manual_join = app
        .active_network_opt()
        .is_some_and(|network| network.local_identity_confirmation_pending);

    if let Some(current) = runtime.as_ref() {
        let ping_result = if pending_manual_join {
            current.ping_pending_join_peers(network_id, now).await
        } else {
            current.ping_peers(network_id, now).await
        };
        if let Err(error) = ping_result {
            eprintln!("fips: peer ping failed: {error}");
        }
        if let Err(error) = current.refresh_link_statuses().await {
            eprintln!("fips: peer link snapshot failed: {error:#}");
            if fips_endpoint_control_requires_runtime_replacement(&error) {
                if fips_stale_participant_restart_due(last_stale_participant_restart_at, now) {
                    eprintln!(
                        "daemon: replacing unresponsive FIPS endpoint after local control timeout"
                    );
                    let recovery = rebuild_fips_tunnel_runtime_after_control_failure(
                        runtime,
                        FipsRestartContext {
                            app,
                            config_path,
                            network_id,
                            fallback_iface,
                            underlay_interface,
                            underlay_interface_mtu,
                            own_pubkey,
                            recent_peers: Some(recent_peers),
                            ethernet_underlay,
                            client_dataplane_enabled,
                            last_endpoint_peer_signature,
                        },
                        "local endpoint control timeout",
                    )
                    .await;
                    match recovery {
                        Ok(()) => {
                            *pending_roster_restart_state =
                                FipsPendingRosterRestartState::default();
                            *roster_sync_state = FipsRosterSyncState::default();
                        }
                        Err(error) => {
                            eprintln!("fips: endpoint control recovery failed: {error:#}");
                        }
                    }
                }
                return;
            }
        }
    }

    match restart_fips_tunnel_runtime_after_stale_participants(
        runtime,
        FipsRestartContext {
            app,
            config_path,
            network_id,
            fallback_iface,
            underlay_interface,
            underlay_interface_mtu,
            own_pubkey,
            recent_peers: Some(recent_peers),
            ethernet_underlay,
            client_dataplane_enabled,
            last_endpoint_peer_signature,
        },
        last_stale_participant_restart_at,
        now,
    )
    .await
    {
        Ok(true) => *roster_sync_state = FipsRosterSyncState::default(),
        Ok(false) => {}
        Err(error) => eprintln!("fips: stale participant recovery failed: {error:#}"),
    }

    match restart_fips_tunnel_runtime_after_pending_roster_links(
        runtime,
        FipsRestartContext {
            app,
            config_path,
            network_id,
            fallback_iface,
            underlay_interface,
            underlay_interface_mtu,
            own_pubkey,
            recent_peers: Some(recent_peers),
            ethernet_underlay,
            client_dataplane_enabled,
            last_endpoint_peer_signature,
        },
        expected_peers,
        pending_roster_restart_state,
        now,
    )
    .await
    {
        Ok(true) => *roster_sync_state = FipsRosterSyncState::default(),
        Ok(false) => {}
        Err(error) => eprintln!("fips: pending roster recovery failed: {error}"),
    }

    let Some(runtime) = runtime.as_ref() else {
        return;
    };
    if let Err(error) =
        sync_fips_roster_with_connected_peers(runtime, app, config_path, roster_sync_state)
    {
        eprintln!("fips: roster peer sync failed: {error}");
    }
    flush_pending_fips_roster_recipients(runtime, app, config_path, pending_roster_recipients);
    if let Err(error) = enqueue_pending_fips_join_requests(runtime, app, join_request_sends, now) {
        eprintln!("fips: join request queue failed: {error}");
    }
}
