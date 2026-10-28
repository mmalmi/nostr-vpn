use super::*;

pub(super) struct DaemonStatePersistContext<'a> {
    pub(super) state_file: &'a Path,
    pub(super) config_path: &'a Path,
    pub(super) app: &'a AppConfig,
    pub(super) vpn_enabled: bool,
    pub(super) expected_peers: usize,
    pub(super) tunnel_runtime: &'a CliTunnelRuntime,
    pub(super) fips_tunnel_runtime: &'a Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    pub(super) endpoint_peer_signature: &'a EndpointPeerSignature,
    pub(super) vpn_status: &'a str,
    pub(super) network_snapshot: &'a crate::diagnostics::NetworkSnapshot,
    pub(super) network_changed_at: Option<u64>,
    pub(super) captive_portal: Option<bool>,
    pub(super) port_mapping_runtime: &'a PortMappingRuntime,
}

pub(super) async fn persist_current_daemon_state(context: DaemonStatePersistContext<'_>) -> bool {
    if let Err(error) = persist_fips_daemon_network_cleanup_state(
        context.config_path,
        context.fips_tunnel_runtime.as_ref(),
    ) {
        eprintln!("daemon: failed to persist FIPS network cleanup ownership: {error:#}");
    }
    let fips_peer_statuses = current_fips_peer_statuses!(context.fips_tunnel_runtime);
    let fips_relay_statuses = current_fips_relay_statuses!(context.fips_tunnel_runtime).await;
    let mut fips_endpoint_peer_states =
        current_fips_endpoint_peer_states!(context.endpoint_peer_signature);
    if let Some(runtime) = context.fips_tunnel_runtime.as_ref() {
        let npubs = fips_endpoint_peer_states
            .iter()
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>();
        let mut live = runtime.configured_public_seed_link_statuses(&npubs);
        for peer in &mut fips_endpoint_peer_states {
            peer.live = live.remove(&peer.npub);
        }
    }
    let fips_advertised_routes =
        current_fips_advertised_routes!(context.fips_tunnel_runtime, context.app);
    let network = context
        .network_snapshot
        .summary(context.network_changed_at, context.captive_portal);
    let port_mapping = context.port_mapping_runtime.status();
    let mut tunnel_runtime = context.tunnel_runtime.clone();
    tunnel_runtime.sync_fips_state(context.fips_tunnel_runtime.as_ref());
    persist_daemon_runtime_and_cleanup_state_async(
        context.state_file,
        context.config_path,
        DaemonRuntimeStateInput {
            app: context.app,
            vpn_enabled: context.vpn_enabled,
            vpn_active: daemon_vpn_active(context.vpn_enabled, context.expected_peers),
            expected_peers: context.expected_peers,
            tunnel_runtime: &tunnel_runtime,
            fips_peer_statuses: &fips_peer_statuses,
            fips_relay_statuses: &fips_relay_statuses,
            fips_endpoint_peers: &fips_endpoint_peer_states,
            advertised_routes_by_participant: &fips_advertised_routes,
            vpn_status: context.vpn_status,
            network: &network,
            port_mapping: &port_mapping,
        },
    )
    .await
}
