pub(crate) fn fips_stale_participant_carrier_rebind_required(
    peer_statuses: &[MeshPeerStatus],
    stale_participants: &[String],
) -> bool {
    !stale_participants.is_empty()
        // A connected public provider also proves the shared carrier works.
        // Losing the last private-roster peer only needs that peer refreshed.
        && !peer_statuses.iter().any(|status| status.connected)
}

async fn restart_fips_tunnel_runtime_after_stale_participants(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    context: FipsRestartContext<'_>,
    last_restart_at: &mut Option<u64>,
    now: u64,
) -> Result<bool> {
    let (stale_participants, carrier_rebind_required) = runtime
        .as_ref()
        .map(|runtime| {
            let stale_participants = runtime.stale_participants_needing_path_refresh(now);
            let carrier_rebind_required = fips_stale_participant_carrier_rebind_required(
                &runtime.peer_statuses(),
                &stale_participants,
            );
            (stale_participants, carrier_rebind_required)
        })
        .unwrap_or_default();
    if stale_participants.is_empty() {
        return Ok(false);
    }
    if !fips_stale_participant_restart_due(last_restart_at, now) {
        return Ok(false);
    }
    eprintln!(
        "daemon: refreshing FIPS peer paths after {} participant(s) stopped responding while endpoint paths need refresh",
        stale_participants.len()
    );
    if carrier_rebind_required {
        rebind_fips_tunnel_runtime_underlay_after_link_event(
            runtime,
            context.underlay_interface,
            "all FIPS participant paths became stale",
        )
        .await?;
        // Carrier rebind invalidates the old NAT-dependent paths and owns the
        // ensuing retries. An immediate peer refresh would race FIPS's roam
        // guard and can postpone the first authenticated packet on the new
        // carrier.
        return Ok(false);
    }
    let refresh_result = refresh_fips_tunnel_runtime_peer_paths(
        runtime,
        FipsRestartContext {
            app: context.app,
            config_path: context.config_path,
            network_id: context.network_id,
            fallback_iface: context.fallback_iface,
            underlay_interface: context.underlay_interface,
            underlay_interface_mtu: context.underlay_interface_mtu,
            own_pubkey: context.own_pubkey,
            recent_peers: context.recent_peers,
            ethernet_underlay: context.ethernet_underlay,
            client_dataplane_enabled: context.client_dataplane_enabled,
            last_endpoint_peer_signature: &mut *context.last_endpoint_peer_signature,
        },
        &stale_participants,
    )
    .await;
    match refresh_result {
        Ok(restarted) => Ok(restarted),
        Err(error) if fips_endpoint_control_requires_runtime_replacement(&error) => {
            eprintln!(
                "daemon: replacing FIPS endpoint after stale path refresh failed: {error:#}"
            );
            rebuild_fips_tunnel_runtime_after_control_failure(
                runtime,
                context,
                "stale path refresh failure",
            )
            .await?;
            Ok(true)
        }
        Err(error) => Err(error),
    }
}
