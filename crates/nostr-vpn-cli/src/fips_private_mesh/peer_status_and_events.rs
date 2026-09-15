#[derive(Debug, Clone)]
struct PeerCapabilitiesEntry {
    capabilities: PeerCapabilities,
    received_at: u64,
}

fn fips_peer_liveness(
    last_seen_at: Option<u64>,
    link_connected: bool,
    peer_error: Option<String>,
    now: u64,
) -> (bool, Option<String>) {
    if fips_peer_presence_far_future(last_seen_at, now) {
        return (
            false,
            peer_error.or_else(|| Some("fips participant stale".to_string())),
        );
    }
    if fips_peer_presence_fresh(last_seen_at, now) {
        return (true, None);
    }
    if link_connected {
        return (true, None);
    }
    if fips_peer_presence_stale(last_seen_at, now) {
        return (
            false,
            peer_error.or_else(|| Some("fips participant stale".to_string())),
        );
    }
    (
        false,
        peer_error.or_else(|| Some("fips link pending".to_string())),
    )
}

fn fips_peer_presence_fresh(last_seen_at: Option<u64>, now: u64) -> bool {
    last_seen_at.is_some_and(|last_seen_at| {
        fips_timestamp_within_grace(now, last_seen_at, FIPS_PEER_ONLINE_GRACE_SECS)
    })
}

fn fips_peer_presence_stale(last_seen_at: Option<u64>, now: u64) -> bool {
    last_seen_at.is_some_and(|last_seen_at| !fips_peer_presence_fresh(Some(last_seen_at), now))
}

fn fips_peer_presence_far_future(last_seen_at: Option<u64>, now: u64) -> bool {
    last_seen_at.is_some_and(|last_seen_at| {
        last_seen_at > now && last_seen_at - now > FIPS_PEER_MAX_FUTURE_SKEW_SECS
    })
}

fn fips_peer_ping_interval_secs(last_seen_at: Option<u64>, link_connected: bool, now: u64) -> u64 {
    if fips_peer_presence_fresh(last_seen_at, now) {
        FIPS_PEER_ACTIVE_PING_INTERVAL_SECS
    } else if link_connected {
        FIPS_PEER_LINK_PING_INTERVAL_SECS
    } else {
        FIPS_PEER_DISCOVERY_PROBE_INTERVAL_SECS
    }
}

fn fips_peer_ping_due(
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    link_connected: bool,
    now: u64,
) -> bool {
    let interval = fips_peer_ping_interval_secs(last_seen_at, link_connected, now);
    last_ping_sent_at.is_none_or(|sent_at| fips_elapsed_at_least(now, sent_at, interval))
}

fn mesh_status_from_endpoint_peer(
    pubkey: String,
    peer: &FipsEndpointPeer,
    now: u64,
) -> MeshPeerStatus {
    let connected = peer.connected;
    MeshPeerStatus {
        pubkey,
        connected,
        endpoint_npub: normalize_fips_endpoint_npub(&peer.npub),
        transport_addr: peer.transport_addr.clone(),
        transport_type: peer.transport_type.clone(),
        srtt_ms: peer.srtt_ms,
        srtt_age_ms: peer.srtt_age_ms,
        link_packets_sent: peer.packets_sent,
        link_packets_recv: peer.packets_recv,
        link_bytes_sent: peer.bytes_sent,
        link_bytes_recv: peer.bytes_recv,
        rekey_in_progress: peer.rekey_in_progress,
        rekey_draining: peer.rekey_draining,
        current_k_bit: peer.current_k_bit,
        last_outbound_route: peer.last_outbound_route.clone(),
        direct_probe_pending: peer.direct_probe_pending,
        direct_probe_after_ms: peer.direct_probe_after_ms,
        direct_probe_retry_count: peer.direct_probe_retry_count,
        direct_probe_auto_reconnect: peer.direct_probe_auto_reconnect,
        direct_probe_expires_at_ms: peer.direct_probe_expires_at_ms,
        nostr_traversal_consecutive_failures: peer.nostr_traversal_consecutive_failures,
        nostr_traversal_in_cooldown: peer.nostr_traversal_in_cooldown,
        nostr_traversal_cooldown_until_ms: peer.nostr_traversal_cooldown_until_ms,
        nostr_traversal_last_observed_skew_ms: peer.nostr_traversal_last_observed_skew_ms,
        last_seen_at: connected.then_some(now),
        last_control_seen_at: None,
        last_data_seen_at: None,
        tx_bytes: 0,
        rx_bytes: 0,
        error: (!connected).then(|| "fips link pending".to_string()),
    }
}

fn endpoint_peer_status_pubkey(peer: &FipsEndpointPeer) -> Option<String> {
    normalize_nostr_pubkey(&peer.npub).ok()
}

fn other_endpoint_peer_statuses(
    other_link_status: &HashMap<String, FipsEndpointPeer>,
    now: u64,
) -> Vec<MeshPeerStatus> {
    let mut statuses = other_link_status
        .values()
        .filter_map(|peer| {
            endpoint_peer_status_pubkey(peer)
                .map(|pubkey| mesh_status_from_endpoint_peer(pubkey, peer, now))
        })
        .collect::<Vec<_>>();
    statuses.sort_by(|left, right| left.pubkey.cmp(&right.pubkey));
    statuses.dedup_by(|left, right| left.pubkey == right.pubkey);
    statuses
}

fn peer_endpoint_hint_addr(hint: &PeerEndpointHint) -> Option<String> {
    nostr_vpn_core::fips_control::peer_endpoint_hint_addr(hint)
}

fn endpoint_addr_ip(addr: &str) -> Option<IpAddr> {
    let (_transport, trimmed) = split_peer_transport_addr(addr);
    let trimmed = trimmed.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return Some(parsed.ip());
    }

    let (host, _) = trimmed.rsplit_once(':')?;
    host.trim().parse::<IpAddr>().ok()
}

fn endpoint_uses_tunnel_ip(addr: &str, tunnel_ips: &HashSet<IpAddr>) -> bool {
    endpoint_addr_ip(addr).is_some_and(|ip| tunnel_ips.contains(&ip))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4Subnet {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Subnet {
    fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            network: mask_ipv4(addr, prefix_len),
            prefix_len,
        }
    }

    fn contains(&self, addr: Ipv4Addr) -> bool {
        mask_ipv4(addr, self.prefix_len) == self.network
    }
}

fn mask_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    if prefix_len >= 32 {
        return addr;
    }
    Ipv4Addr::from(u32::from(addr) & (u32::MAX << (32 - u32::from(prefix_len))))
}

fn local_private_ipv4_subnets() -> Vec<Ipv4Subnet> {
    let mut subnets = local_private_ipv4_interface_subnets();
    subnets.extend(local_private_ipv4_route_subnets(&subnets));
    subnets.sort_by_key(|subnet| (u32::from(subnet.network), subnet.prefix_len));
    subnets.dedup();
    subnets
}

fn local_private_ipv4_interface_subnets() -> Vec<Ipv4Subnet> {
    let mut subnets = Vec::new();
    for iface in netdev::get_interfaces() {
        if iface.is_loopback() {
            continue;
        }
        for net in &iface.ipv4 {
            let addr = net.addr();
            if addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_multicast()
                || !(addr.is_private() || ipv4_is_cgnat_addr(addr) || addr.is_link_local())
            {
                continue;
            }
            subnets.push(Ipv4Subnet::new(addr, net.prefix_len()));
        }
    }
    subnets.sort_by_key(|subnet| (u32::from(subnet.network), subnet.prefix_len));
    subnets.dedup();
    subnets
}

#[cfg(target_os = "linux")]
fn local_private_ipv4_route_subnets(interface_subnets: &[Ipv4Subnet]) -> Vec<Ipv4Subnet> {
    let Ok(output) = ProcessCommand::new("ip")
        .arg("-4")
        .arg("route")
        .arg("show")
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    linux_private_ipv4_route_subnets_from_ip_route(&stdout, interface_subnets)
}

#[cfg(target_os = "macos")]
fn local_private_ipv4_route_subnets(interface_subnets: &[Ipv4Subnet]) -> Vec<Ipv4Subnet> {
    let Ok(output) = ProcessCommand::new("netstat")
        .arg("-rn")
        .arg("-f")
        .arg("inet")
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    macos_private_ipv4_route_subnets_from_netstat(&stdout, interface_subnets)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn local_private_ipv4_route_subnets(_interface_subnets: &[Ipv4Subnet]) -> Vec<Ipv4Subnet> {
    Vec::new()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn private_route_gateway_is_local(gateway: Ipv4Addr, interface_subnets: &[Ipv4Subnet]) -> bool {
    interface_subnets
        .iter()
        .any(|subnet| subnet.contains(gateway))
}

#[cfg(any(target_os = "linux", test))]
fn linux_private_ipv4_route_subnets_from_ip_route(
    output: &str,
    interface_subnets: &[Ipv4Subnet],
) -> Vec<Ipv4Subnet> {
    let mut subnets = Vec::new();
    for line in output.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with("default ")
            || line.starts_with("blackhole ")
            || line.starts_with("unreachable ")
            || line.starts_with("throw ")
        {
            continue;
        }
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let Some(route) = parse_ipv4_route_target(tokens[0]) else {
            continue;
        };
        if !ipv4_static_hint_requires_local_subnet(route.network) {
            continue;
        }
        let gateway = tokens
            .windows(2)
            .find(|pair| pair[0] == "via")
            .and_then(|pair| pair[1].parse::<Ipv4Addr>().ok());
        let dev = tokens
            .windows(2)
            .find(|pair| pair[0] == "dev")
            .map(|pair| pair[1]);
        if gateway.is_none() && dev.is_some_and(route_interface_is_tunnel_like) {
            continue;
        }
        if gateway.is_none_or(|gateway| private_route_gateway_is_local(gateway, interface_subnets))
        {
            subnets.push(route);
        }
    }
    subnets.sort_by_key(|subnet| (u32::from(subnet.network), subnet.prefix_len));
    subnets.dedup();
    subnets
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn route_interface_is_tunnel_like(interface: &str) -> bool {
    interface.starts_with("utun")
        || interface.starts_with("tun")
        || interface.starts_with("wg")
        || interface.starts_with("tailscale")
        || interface == "lo"
}

#[cfg(any(target_os = "macos", test))]
fn macos_private_ipv4_route_subnets_from_netstat(
    output: &str,
    interface_subnets: &[Ipv4Subnet],
) -> Vec<Ipv4Subnet> {
    let mut subnets = Vec::new();
    for line in output.lines().map(str::trim) {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 3 || tokens[0] == "default" {
            continue;
        }
        let Some(route) = parse_macos_ipv4_route_target(tokens[0]) else {
            continue;
        };
        if !ipv4_static_hint_requires_local_subnet(route.network) {
            continue;
        }
        let gateway = tokens[1].parse::<Ipv4Addr>().ok();
        let direct = tokens[1].starts_with("link#");
        if direct
            || gateway
                .is_some_and(|gateway| private_route_gateway_is_local(gateway, interface_subnets))
        {
            subnets.push(route);
        }
    }
    subnets.sort_by_key(|subnet| (u32::from(subnet.network), subnet.prefix_len));
    subnets.dedup();
    subnets
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn parse_ipv4_route_target(target: &str) -> Option<Ipv4Subnet> {
    let (addr, prefix_len) = target
        .split_once('/')
        .map(|(addr, prefix)| (addr, prefix.parse::<u8>().ok()))
        .unwrap_or((target, Some(32)));
    let prefix_len = prefix_len?;
    if prefix_len > 32 {
        return None;
    }
    Some(Ipv4Subnet::new(addr.parse().ok()?, prefix_len))
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_ipv4_route_target(target: &str) -> Option<Ipv4Subnet> {
    if target.contains('/') {
        return parse_ipv4_route_target(target);
    }
    let parts = target.split('.').collect::<Vec<_>>();
    let prefix_len = match parts.len() {
        1 => 8,
        2 => 16,
        3 => 24,
        4 => 32,
        _ => return None,
    };
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        octets[index] = part.parse::<u8>().ok()?;
    }
    Some(Ipv4Subnet::new(Ipv4Addr::from(octets), prefix_len))
}

fn ipv4_static_hint_requires_local_subnet(addr: Ipv4Addr) -> bool {
    addr.is_private() || ipv4_is_cgnat_addr(addr) || addr.is_link_local()
}

fn ipv4_is_cgnat_addr(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn static_endpoint_allowed_on_current_underlay(addr: &str, local_subnets: &[Ipv4Subnet]) -> bool {
    static_endpoint_allowed_on_current_underlay_with_route_check(
        addr,
        local_subnets,
        private_endpoint_directly_routed_on_current_underlay,
    )
}

fn static_endpoint_allowed_on_current_underlay_with_route_check(
    addr: &str,
    local_subnets: &[Ipv4Subnet],
    route_check: impl Fn(Ipv4Addr) -> bool,
) -> bool {
    match endpoint_addr_ip(addr) {
        Some(IpAddr::V4(ip)) if ipv4_static_hint_requires_local_subnet(ip) => {
            local_subnets.iter().any(|subnet| subnet.contains(ip)) && route_check(ip)
        }
        _ => true,
    }
}

#[cfg(target_os = "macos")]
fn private_endpoint_directly_routed_on_current_underlay(ip: Ipv4Addr) -> bool {
    let Ok(output) = ProcessCommand::new("route")
        .arg("-n")
        .arg("get")
        .arg(ip.to_string())
        .output()
    else {
        return true;
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    macos_route_get_has_direct_private_endpoint_route(&stdout, ip)
}

#[cfg(target_os = "linux")]
fn private_endpoint_directly_routed_on_current_underlay(ip: Ipv4Addr) -> bool {
    let Ok(output) = ProcessCommand::new("ip")
        .arg("-4")
        .arg("route")
        .arg("get")
        .arg(ip.to_string())
        .output()
    else {
        return true;
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    linux_route_get_has_direct_private_endpoint_route(&stdout)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn private_endpoint_directly_routed_on_current_underlay(_ip: Ipv4Addr) -> bool {
    true
}

#[cfg(any(target_os = "macos", test))]
fn macos_route_get_has_direct_private_endpoint_route(output: &str, ip: Ipv4Addr) -> bool {
    let mut gateway = None;
    let mut interface = None;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("gateway:") {
            gateway = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim());
        }
    }
    let Some(interface) = interface else {
        return false;
    };
    if route_interface_is_tunnel_like(interface) {
        return false;
    }
    match gateway {
        Some(gateway) if gateway.starts_with("link#") => true,
        Some(gateway) => gateway.parse::<Ipv4Addr>().is_ok_and(|gateway| gateway == ip),
        None => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_get_has_direct_private_endpoint_route(output: &str) -> bool {
    let tokens = output.split_whitespace().collect::<Vec<_>>();
    if tokens.windows(2).any(|pair| pair[0] == "via") {
        return false;
    }
    let dev = tokens
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1]);
    dev.is_some_and(|dev| !route_interface_is_tunnel_like(dev))
}

fn filter_static_tunnel_endpoints(
    groups: Vec<(String, Vec<String>)>,
    tunnel_ips: &HashSet<IpAddr>,
    local_subnets: &[Ipv4Subnet],
) -> Vec<(String, Vec<String>)> {
    filter_static_tunnel_endpoints_with_policy(groups, tunnel_ips, local_subnets, false)
}

fn filter_static_tunnel_endpoints_with_policy(
    groups: Vec<(String, Vec<String>)>,
    tunnel_ips: &HashSet<IpAddr>,
    local_subnets: &[Ipv4Subnet],
    allow_routed_private_endpoints: bool,
) -> Vec<(String, Vec<String>)> {
    filter_static_tunnel_endpoints_with_policy_and_route_check(
        groups,
        tunnel_ips,
        local_subnets,
        allow_routed_private_endpoints,
        private_endpoint_directly_routed_on_current_underlay,
    )
}

fn filter_static_tunnel_endpoints_with_policy_and_route_check<F>(
    groups: Vec<(String, Vec<String>)>,
    tunnel_ips: &HashSet<IpAddr>,
    local_subnets: &[Ipv4Subnet],
    allow_routed_private_endpoints: bool,
    route_check: F,
) -> Vec<(String, Vec<String>)>
where
    F: Fn(Ipv4Addr) -> bool + Copy,
{
    groups
        .into_iter()
        .filter_map(|(participant, addrs)| {
            let addrs = addrs
                .into_iter()
                .filter(|addr| {
                    !endpoint_uses_tunnel_ip(addr, tunnel_ips)
                        && (allow_routed_private_endpoints
                            || static_endpoint_allowed_on_current_underlay_with_route_check(
                                addr,
                                local_subnets,
                                route_check,
                            ))
                })
                .collect::<Vec<_>>();
            (!addrs.is_empty()).then_some((participant, addrs))
        })
        .collect()
}

fn filter_stamped_tunnel_endpoints(
    groups: Vec<(String, Vec<(String, u64)>)>,
    tunnel_ips: &HashSet<IpAddr>,
    local_subnets: &[Ipv4Subnet],
) -> Vec<(String, Vec<(String, u64)>)> {
    groups
        .into_iter()
        .filter_map(|(participant, addrs)| {
            let addrs = addrs
                .into_iter()
                .filter(|(addr, _)| {
                    !endpoint_uses_tunnel_ip(addr, tunnel_ips)
                        && static_endpoint_allowed_on_current_underlay(addr, local_subnets)
                })
                .collect::<Vec<_>>();
            (!addrs.is_empty()).then_some((participant, addrs))
        })
        .collect()
}

fn recent_transit_endpoint_score(addr: &str) -> u8 {
    let (transport, host_port) = split_peer_transport_addr(addr);
    let Ok(socket_addr) = host_port.parse::<SocketAddr>() else {
        return 0;
    };

    let mut score = match socket_addr.ip() {
        IpAddr::V6(_) => 3,
        IpAddr::V4(_) => 2,
    };

    score += match socket_addr.port() {
        443 | 2121 | 8443 | 51820 => 4,
        1..=32767 => 2,
        32768..=49151 => 1,
        _ => 0,
    };

    match transport.to_ascii_lowercase().as_str() {
        "tcp" | "udp" => score + 1,
        _ => score,
    }
}

fn freshest_seen_at_ms(addrs: &[(String, u64)]) -> u64 {
    addrs
        .iter()
        .map(|(_, seen_at_ms)| *seen_at_ms)
        .max()
        .unwrap_or(0)
}

fn recent_transit_group_rank(addrs: &[(String, u64)]) -> (u8, u64) {
    let best_score = addrs
        .iter()
        .map(|(addr, _)| recent_transit_endpoint_score(addr))
        .max()
        .unwrap_or(0);
    (best_score, freshest_seen_at_ms(addrs))
}

fn static_transit_group_rank(addrs: &[String]) -> u8 {
    addrs
        .iter()
        .map(|addr| recent_transit_endpoint_score(addr))
        .max()
        .unwrap_or(0)
}

fn is_public_native_bootstrap_peer(participant: &str) -> bool {
    let participant = normalize_fips_endpoint_npub(participant);
    DEFAULT_FIPS_BOOTSTRAP_PEERS
        .iter()
        .any(|(npub, _)| participant == *npub)
}

fn cap_static_non_roster_transit_endpoints(
    groups: Vec<(String, Vec<String>)>,
    roster_endpoint_npubs: &HashSet<String>,
    max_non_roster: usize,
) -> Vec<(String, Vec<String>)> {
    let mut roster = Vec::new();
    let mut non_roster = Vec::new();

    for (participant, addrs) in groups {
        if roster_endpoint_npubs.contains(&normalize_fips_endpoint_npub(&participant)) {
            roster.push((participant, addrs));
        } else {
            non_roster.push((participant, addrs));
        }
    }

    non_roster.sort_by(|left, right| {
        is_public_native_bootstrap_peer(&right.0)
            .cmp(&is_public_native_bootstrap_peer(&left.0))
            .then_with(|| {
                static_transit_group_rank(&right.1)
            .cmp(&static_transit_group_rank(&left.1))
            })
            .then_with(|| left.0.cmp(&right.0))
    });
    non_roster.truncate(max_non_roster);

    roster.extend(non_roster);
    roster
}

fn cap_recent_non_roster_transit_endpoints(
    groups: Vec<(String, Vec<(String, u64)>)>,
    roster_endpoint_npubs: &HashSet<String>,
    max_non_roster: usize,
) -> Vec<(String, Vec<(String, u64)>)> {
    let mut roster = Vec::new();
    let mut non_roster = Vec::new();

    for (participant, addrs) in groups {
        if roster_endpoint_npubs.contains(&normalize_fips_endpoint_npub(&participant)) {
            roster.push((participant, addrs));
        } else {
            non_roster.push((participant, addrs));
        }
    }

    non_roster.sort_by(|left, right| {
        recent_transit_group_rank(&right.1)
            .cmp(&recent_transit_group_rank(&left.1))
            .then_with(|| left.0.cmp(&right.0))
    });
    non_roster.truncate(max_non_roster);

    roster.extend(non_roster);
    roster
}

fn non_roster_endpoint_group_count<T>(
    groups: &[(String, Vec<T>)],
    roster_endpoint_npubs: &HashSet<String>,
) -> usize {
    groups
        .iter()
        .filter(|entry| !entry.1.is_empty())
        .map(|(participant, _)| normalize_fips_endpoint_npub(participant))
        .filter(|npub| !roster_endpoint_npubs.contains(npub))
        .collect::<HashSet<_>>()
        .len()
}

fn open_discovery_limit_after_transit_seeds(
    limit: usize,
    static_non_roster_seeds: usize,
) -> usize {
    limit.saturating_sub(static_non_roster_seeds)
}

fn fips_tunnel_endpoint_hosts(app: &AppConfig, network_id: &str) -> HashSet<IpAddr> {
    let mut hosts = HashSet::new();
    if let Ok(ip) = strip_cidr(&app.node.tunnel_ip).parse::<IpAddr>() {
        hosts.insert(ip);
    }
    for participant in app.participant_pubkeys_hex() {
        if let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &participant)
            && let Ok(ip) = strip_cidr(&tunnel_ip).parse::<IpAddr>()
        {
            hosts.insert(ip);
        }
    }
    hosts
}

#[derive(Debug, Clone)]
pub(crate) struct FipsRelayStatus {
    pub(crate) url: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone)]
pub(crate) enum FipsPrivateMeshEvent {
    Packet(FipsEndpointData),
    Presence {
        participant_pubkey: String,
        last_seen_at: u64,
    },
    JoinRequest {
        sender_pubkey: String,
        requested_at: u64,
        request: MeshJoinRequest,
    },
    JoinRoster {
        sender_pubkey: String,
        control: Box<JoinRosterControl>,
    },
    Roster {
        sender_pubkey: String,
        signed_roster: Option<Box<SignedRoster>>,
    },
    Capabilities {
        sender_pubkey: String,
        network_id: String,
        capabilities: PeerCapabilities,
        first_received: bool,
    },
    #[cfg(feature = "paid-exit")]
    PaidRouteSessionOpen {
        sender_pubkey: String,
        open: PaidRouteSessionOpen,
    },
    #[cfg(feature = "paid-exit")]
    PaidRouteSessionOpenAck {
        sender_pubkey: String,
        lease_id: String,
    },
    #[cfg(feature = "paid-exit")]
    PaidRoutePayment {
        sender_pubkey: String,
        id: String,
        envelope: Box<StreamingRoutePaymentEnvelope>,
    },
    #[cfg(feature = "paid-exit")]
    PaidRoutePaymentAck {
        sender_pubkey: String,
        id: String,
    },
}
