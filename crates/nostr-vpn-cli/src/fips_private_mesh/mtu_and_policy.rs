#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MeshMtu {
    underlay_udp: u16,
    tunnel: u16,
}

fn private_mesh_mtu_from_app(app: Option<&AppConfig>) -> MeshMtu {
    let env_profile_raw = std::env::var("NVPN_MESH_MTU_PROFILE").ok();
    let env_profile = env_profile_raw.as_deref().and_then(non_empty_str);
    let env_underlay = parse_mtu_env("NVPN_MESH_UNDERLAY_UDP_MTU");
    let env_tunnel = parse_mtu_env("NVPN_MESH_TUNNEL_MTU");

    resolve_private_mesh_mtu_from_sources(app, env_profile, env_underlay, env_tunnel)
}

fn resolve_private_mesh_mtu_from_sources(
    app: Option<&AppConfig>,
    env_profile: Option<&str>,
    env_underlay: Option<u16>,
    env_tunnel: Option<u16>,
) -> MeshMtu {
    let app_profile = app.and_then(|app| non_empty_str(&app.mesh_mtu_profile));
    let app_underlay =
        app.and_then(|app| (app.mesh_underlay_udp_mtu > 0).then_some(app.mesh_underlay_udp_mtu));
    let app_tunnel = app.and_then(|app| (app.mesh_tunnel_mtu > 0).then_some(app.mesh_tunnel_mtu));

    resolve_private_mesh_mtu(
        env_profile.or(app_profile),
        env_underlay.or(app_underlay),
        env_tunnel.or(app_tunnel),
    )
}

fn resolve_private_mesh_mtu(
    profile: Option<&str>,
    underlay_override: Option<u16>,
    tunnel_override: Option<u16>,
) -> MeshMtu {
    let mut mtu = match normalized_mtu_profile(profile).as_deref() {
        Some("lan") => MeshMtu {
            underlay_udp: MESH_LAN_UNDERLAY_UDP_MTU,
            tunnel: MESH_LAN_TUNNEL_MTU,
        },
        _ => MeshMtu {
            underlay_udp: nostr_vpn_core::MESH_UNDERLAY_UDP_MTU,
            tunnel: nostr_vpn_core::MESH_TUNNEL_MTU,
        },
    };

    if let Some(underlay_udp) = clamp_mtu(underlay_override, MESH_MIN_UNDERLAY_UDP_MTU) {
        mtu.underlay_udp = underlay_udp;
        if tunnel_override.is_none() {
            mtu.tunnel = tunnel_mtu_for_underlay(underlay_udp);
        }
    }
    if let Some(tunnel) = clamp_mtu(tunnel_override, MESH_MIN_TUNNEL_MTU) {
        mtu.tunnel = tunnel;
    }

    let max_tunnel = tunnel_mtu_for_underlay(mtu.underlay_udp);
    if mtu.tunnel > max_tunnel {
        mtu.tunnel = max_tunnel;
    }
    mtu
}

fn normalized_mtu_profile(profile: Option<&str>) -> Option<String> {
    let profile = profile?.trim();
    if profile.is_empty() {
        return None;
    }
    Some(profile.to_ascii_lowercase())
}

fn parse_mtu_env(name: &str) -> Option<u16> {
    std::env::var(name).ok()?.trim().parse::<u16>().ok()
}

fn fips_nostr_discovery_policy_from_app(app: &AppConfig) -> NostrDiscoveryPolicy {
    std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY")
        .ok()
        .as_deref()
        .and_then(parse_fips_nostr_discovery_policy)
        .unwrap_or(if app.connect_to_non_roster_fips_peers
            || app.pending_nostr_join_request.is_some()
            || app.node.advertise_exit_node
            || crate::paid_exit_fips_runtime_active(app)
        {
            NostrDiscoveryPolicy::Open
        } else {
            NostrDiscoveryPolicy::ConfiguredOnly
        })
}

fn parse_fips_nostr_discovery_policy(value: &str) -> Option<NostrDiscoveryPolicy> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "disabled" | "off" | "false" | "0" => Some(NostrDiscoveryPolicy::Disabled),
        "configured_only" | "configuredonly" | "configured" => {
            Some(NostrDiscoveryPolicy::ConfiguredOnly)
        }
        "open" | "true" | "1" => Some(NostrDiscoveryPolicy::Open),
        _ => None,
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn clamp_mtu(value: Option<u16>, min: u16) -> Option<u16> {
    value.map(|mtu| mtu.clamp(min, MESH_MAX_MTU))
}

fn clamp_mesh_mtu_to_underlay_interface_mtu(
    mut mtu: MeshMtu,
    underlay_interface_mtu: Option<u32>,
) -> MeshMtu {
    let Some(interface_udp_mtu) = underlay_udp_mtu_for_interface_mtu(underlay_interface_mtu) else {
        return mtu;
    };
    let underlay_udp = interface_udp_mtu.max(MESH_MIN_UNDERLAY_UDP_MTU);
    if mtu.underlay_udp > underlay_udp {
        mtu.underlay_udp = underlay_udp;
        mtu.tunnel = mtu.tunnel.min(tunnel_mtu_for_underlay(underlay_udp));
    }
    mtu
}

fn underlay_udp_mtu_for_interface_mtu(interface_mtu: Option<u32>) -> Option<u16> {
    const IPV6_UDP_OVERHEAD: u32 = 48;
    let udp_mtu = interface_mtu?.saturating_sub(IPV6_UDP_OVERHEAD);
    (udp_mtu > 0).then_some(udp_mtu.min(MESH_MAX_MTU as u32) as u16)
}

fn tunnel_mtu_for_underlay(underlay_udp_mtu: u16) -> u16 {
    let tunnel_headroom =
        nostr_vpn_core::MESH_UNDERLAY_UDP_MTU.saturating_sub(nostr_vpn_core::MESH_TUNNEL_MTU);
    underlay_udp_mtu
        .saturating_sub(tunnel_headroom)
        .max(MESH_MIN_TUNNEL_MTU)
}

#[cfg(target_os = "linux")]
fn exit_node_ipv4_mss_clamp(tunnel_mtu: u16) -> u16 {
    tunnel_mtu.saturating_sub(40).max(536)
}
