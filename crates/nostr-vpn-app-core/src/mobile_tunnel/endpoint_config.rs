fn mobile_endpoint_hints(config: &MobileTunnelConfig) -> Vec<PeerEndpointHint> {
    if !config.share_local_candidates {
        return Vec::new();
    }
    mobile_endpoint_hints_with_candidates(config, mobile_lan_ipv4_candidates(&config.local_address))
}

fn mobile_endpoint_hints_with_candidates(
    config: &MobileTunnelConfig,
    local_ipv4_candidates: Vec<Ipv4Addr>,
) -> Vec<PeerEndpointHint> {
    let endpoint = endpoint_with_listen_port(&config.advertised_endpoint, config.listen_port);
    let mut endpoints = Vec::new();

    if endpoint_is_gossipable_direct_hint(&endpoint)
        && !endpoint_uses_tunnel_ip(&endpoint, &config.local_address)
    {
        endpoints.push(endpoint);
    }

    let tunnel_ipv4 = parse_ipv4(&config.local_address);
    if config.listen_port != 0 {
        for ip in local_ipv4_candidates {
            if Some(ip) == tunnel_ipv4 || !ipv4_is_lan_endpoint_hint(ip) {
                continue;
            }
            endpoints.push(SocketAddrV4::new(ip, config.listen_port).to_string());
        }
    }

    endpoints.sort();
    endpoints.dedup();
    endpoints
        .into_iter()
        .map(PeerEndpointHint::udp)
        .filter(|hint| peer_endpoint_hint_addr(hint).is_some())
        .collect()
}

fn fips_peer_configs_from_mesh(
    peers: &[FipsMeshPeerConfig],
    peer_hints: &HashMap<String, Vec<FipsPeerAddressHint>>,
    bootstrap_peers: &HashMap<String, Vec<FipsPeerAddressHint>>,
    include_non_roster_transit: bool,
) -> Vec<FipsPeerConfig> {
    let mut configs = Vec::new();
    let mut included = std::collections::HashSet::new();

    for peer in peers {
        included.insert(peer.participant_pubkey.clone());
        configs.push(fips_peer_config_from_hint(
            &peer.endpoint_npub,
            peer_hints.get(&peer.participant_pubkey),
            true,
            FIPS_MOBILE_AUTO_RECONNECT,
        ));
    }

    if !include_non_roster_transit {
        return configs;
    }

    for (participant, hints) in peer_hints {
        if included.contains(participant) || hints.is_empty() {
            continue;
        }
        if let Ok(peer) = FipsMeshPeerConfig::from_participant_pubkey(participant, Vec::new()) {
            // Learned non-roster hints are authenticated overlay peers; without
            // fallback transit, they are warm sessions with little use.
            configs.push(fips_peer_config_from_hint(
                &peer.endpoint_npub,
                Some(hints),
                true,
                FIPS_MOBILE_AUTO_RECONNECT,
            ));
            included.insert(participant.clone());
        }
    }

    // Bootstrap/transit peers ferry frames as fallback transit; route targets
    // still come exclusively from the roster.
    for (participant, hints) in bootstrap_peers {
        if included.contains(participant) || hints.is_empty() {
            continue;
        }
        if let Ok(peer) = FipsMeshPeerConfig::from_participant_pubkey(participant, Vec::new()) {
            configs.push(fips_peer_config_from_hint(
                &peer.endpoint_npub,
                Some(hints),
                true,
                FIPS_MOBILE_AUTO_RECONNECT,
            ));
            included.insert(participant.clone());
        }
    }

    configs.sort_by(|left, right| left.npub.cmp(&right.npub));
    configs.dedup_by(|left, right| left.npub == right.npub);
    configs
}

fn fips_peer_config_from_hint(
    endpoint_npub: &str,
    hints: Option<&Vec<FipsPeerAddressHint>>,
    discovery_fallback_transit: bool,
    auto_reconnect: bool,
) -> FipsPeerConfig {
    let addresses = hints
        .into_iter()
        .flatten()
        .map(|hint| {
            let (transport, addr) = split_peer_transport_addr(&hint.addr);
            let priority = if hint.priority == FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY {
                mobile_fips_endpoint_hint_priority(&hint.addr, hint.priority)
            } else {
                hint.priority
            };
            let mut addr = PeerAddress::with_priority(transport, addr, priority);
            if let Some(seen_at_ms) = hint.seen_at_ms {
                addr = addr.learned().with_seen_at_ms(seen_at_ms);
            }
            addr
        })
        .collect();
    FipsPeerConfig {
        npub: endpoint_npub.to_string(),
        alias: None,
        addresses,
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect,
        discovery_fallback_transit,
    }
}

fn mobile_static_peer_hints(app: &AppConfig) -> HashMap<String, Vec<FipsPeerAddressHint>> {
    let mut hints = fips_address_hints(app.fips_static_peer_endpoints());
    for value in hints.values_mut() {
        value.sort_by(|left, right| left.addr.cmp(&right.addr));
        value.dedup_by(|left, right| left.addr == right.addr);
    }
    hints
}

/// The configured bootstrap/transit peers as address hints, dialed as fallback
/// transit (separate from learned `peer_hints`).
fn mobile_bootstrap_peer_hints(app: &AppConfig) -> HashMap<String, Vec<FipsPeerAddressHint>> {
    let mut hints = fips_address_hints(app.fips_bootstrap_peer_endpoints());
    for value in hints.values_mut() {
        value.sort_by(|left, right| left.addr.cmp(&right.addr));
        value.dedup_by(|left, right| left.addr == right.addr);
    }
    hints
}

fn fips_address_hints(
    endpoints: Vec<(String, Vec<String>)>,
) -> HashMap<String, Vec<FipsPeerAddressHint>> {
    endpoints
        .into_iter()
        .filter_map(|(participant, endpoints)| {
            let participant = normalize_nostr_pubkey(&participant).ok()?;
            let hints = endpoints
                .into_iter()
                .filter_map(|endpoint| {
                    normalize_fips_transport_address(&endpoint).map(|addr| {
                        FipsPeerAddressHint {
                            priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
                            addr,
                            seen_at_ms: None,
                        }
                    })
                })
                .collect::<Vec<_>>();
            (!hints.is_empty()).then_some((participant, hints))
        })
        .collect()
}

fn non_empty_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

pub(crate) fn fips_endpoint_config(scope: &str, mobile: &MobileTunnelConfig) -> FipsConfig {
    fips_endpoint_config_for_platform(scope, mobile, current_runtime_platform())
}

fn fips_endpoint_config_for_platform(
    scope: &str,
    mobile: &MobileTunnelConfig,
    platform: RuntimePlatform,
) -> FipsConfig {
    let mut config = FipsConfig::new();
    // A first-adjacency seed may authenticate before its tree/bloom adverts
    // have converged. Reply-learned discovery can ask that live adjacency for
    // an addressless roster peer immediately instead of recording a bloom
    // miss and suppressing the ordinary control request for the full backoff.
    config.node.routing.mode = RoutingMode::ReplyLearned;
    // The fips control socket binds a UNIX socket at
    // `/tmp/fips-control.sock` by default. Inside an iOS app extension
    // the sandbox forbids /tmp writes, which crashes the
    // PacketTunnelProvider before it can finish startTunnel. Android's
    // sandbox accepts it but we don't need control on mobile either —
    // there's no daemon to talk to.
    config.node.control.enabled = false;
    // Keep open/public discovery available but paced. Phones can easily wake
    // several stale peers at once; failed route lookups and ambient adverts
    // must back off instead of leaning on public transit nodes indefinitely.
    config.node.discovery.backoff_base_secs = FIPS_DISCOVERY_BACKOFF_BASE_SECS;
    config.node.discovery.backoff_max_secs = FIPS_DISCOVERY_BACKOFF_MAX_SECS;
    config.node.discovery.forward_min_interval_secs = FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS;
    config.node.rate_limit.handshake_resend_interval_ms = MOBILE_HANDSHAKE_RESEND_INTERVAL_MS;
    config.node.rate_limit.handshake_resend_backoff = MOBILE_HANDSHAKE_RESEND_BACKOFF;
    // Cap concurrent FIPS peers on mobile. With Open discovery the global
    // overlay can keep introducing new peers; on phones we'd rather drop
    // ambient connection attempts than burn battery talking to strangers
    // who can't put anything on our tun anyway. Desktop nodes keep fips's
    // default of 128 because they're typically on AC power and uncapped
    // bandwidth.
    config.node.limits.max_peers = MOBILE_MAX_FIPS_PEERS;
    config.node.limits.max_connections = MOBILE_MAX_FIPS_CONNECTIONS;
    config.node.limits.max_links = MOBILE_MAX_FIPS_LINKS;
    let join_request_pending = mobile_join_request_pending(mobile);
    let include_non_roster_transit = mobile.connect_to_non_roster_fips_peers
        || mobile.join_requests_enabled
        || mobile.device_approval_pending
        || join_request_pending
        || !mobile.websocket_seed_urls.is_empty()
        || !mobile.bootstrap_peers.is_empty();
    let nostr_enabled = mobile_nostr_enabled(mobile);
    config.node.discovery.nostr.enabled = nostr_enabled;
    // Publish only the generic `udp:nat` overlay advert so roster peers can
    // bootstrap encrypted traversal offers to mobile nodes. LAN addresses are
    // not placed in that public advert; when enabled, they are carried inside
    // encrypted traversal signaling/control frames.
    // A pending approval already carries the joiner's FIPS identity (the app
    // npub), so roster delivery routes by identity through configured transit.
    // Do not publish an advert merely to complete approval. Once roster peers
    // exist, adverts remain enabled to seek the preferred direct VPN path.
    config.node.discovery.nostr.advertise = nostr_enabled && !mobile.peers.is_empty();
    config.node.discovery.nostr.policy = if include_non_roster_transit {
        NostrDiscoveryPolicy::Open
    } else {
        NostrDiscoveryPolicy::ConfiguredOnly
    };
    config.node.discovery.nostr.open_discovery_max_pending =
        MOBILE_NOSTR_OPEN_DISCOVERY_MAX_PENDING;
    config.node.discovery.nostr.failure_streak_threshold = MOBILE_NOSTR_FAILURE_STREAK_THRESHOLD;
    config.node.discovery.nostr.startup_sweep_max_age_secs = FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS;
    config.node.discovery.nostr.share_local_candidates = mobile.share_local_candidates;
    // iOS requires Apple's managed multicast entitlement for raw mDNS. Our
    // packet-tunnel profiles do not carry it, so keep LAN candidates available
    // to encrypted Nostr traversal while leaving the multicast daemon closed.
    // Packet-tunnel extensions may still use ordinary local unicast traffic.
    config.node.discovery.lan.enabled = mobile.share_local_candidates
        && nostr_enabled
        && platform != RuntimePlatform::Ios;
    // Leave the relay-side `app` at fips-core's default ("fips-overlay-v1");
    // see fips_private_mesh::fips_endpoint_config for the rationale (the relay
    // `protocol` tag is publicly visible, so per-network apps would let any
    // observer count members of each private network). The mesh id is still
    // used as the LAN `discovery_scope` and inside FIPS handshake payloads.
    let _ = scope;
    if !mobile.nostr_relays.is_empty() {
        config
            .node
            .discovery
            .nostr
            .advert_relays
            .clone_from(&mobile.nostr_relays);
    }
    if !mobile.stun_servers.is_empty() {
        config
            .node
            .discovery
            .nostr
            .stun_servers
            .clone_from(&mobile.stun_servers);
    }
    if mobile.webrtc_enabled {
        configure_mobile_webrtc_transport(
            &mut config,
            nostr_enabled,
            &mobile.stun_servers,
            platform != RuntimePlatform::Ios,
        );
    }
    config.peers = fips_peer_configs_from_mesh(
        &mobile.peers,
        &mobile.peer_hints,
        &mobile.bootstrap_peers,
        include_non_roster_transit,
    );
    let needs_websocket = !mobile.websocket_seed_urls.is_empty()
        || config.peers.iter().any(|peer| {
            peer.addresses
                .iter()
                .any(|address| address.transport.eq_ignore_ascii_case("websocket"))
        });
    if needs_websocket {
        config.transports.websocket = TransportInstances::Single(WebSocketConfig {
            seed_urls: mobile.websocket_seed_urls.clone(),
            ..WebSocketConfig::default()
        });
    }
    config.transports.udp = mobile_udp_transports(mobile.listen_port, nostr_enabled);
    // Outbound TCP transport so peers reachable only over tcp:443 (UDP-blocked
    // networks) can still be dialed. bind_addr=None keeps it outbound-only.
    let needs_tcp = config.peers.iter().any(|peer| {
        peer.addresses
            .iter()
            .any(|addr| addr.transport.eq_ignore_ascii_case("tcp"))
    });
    if needs_tcp {
        // Default = outbound-only; inferred type avoids naming a possibly-second
        // fips-core's TcpConfig (see fips_private_mesh for the same rationale), so
        // we deliberately keep `Default::default()` over `TcpConfig::default()`.
        #[allow(clippy::default_trait_access)]
        {
            config.transports.tcp = TransportInstances::Single(Default::default());
        }
    }
    config
}

fn mobile_udp_transports(
    listen_port: u16,
    advertise_on_nostr: bool,
) -> TransportInstances<UdpConfig> {
    let udp = UdpConfig {
        outbound_only: Some(false),
        accept_connections: Some(true),
        advertise_on_nostr: Some(false),
        public: Some(false),
        ..UdpConfig::default()
    };
    TransportInstances::Named(HashMap::from([
        (
            MOBILE_UDP_IPV4_TRANSPORT.to_string(),
            UdpConfig {
                bind_addr: Some(format!("0.0.0.0:{listen_port}")),
                advertise_on_nostr: Some(advertise_on_nostr),
                ..udp.clone()
            },
        ),
        (
            MOBILE_UDP_IPV6_TRANSPORT.to_string(),
            UdpConfig {
                bind_addr: Some(format!("[::]:{listen_port}")),
                ..udp
            },
        ),
    ]))
}

fn mobile_join_request_pending(mobile: &MobileTunnelConfig) -> bool {
    !mobile.pending_join_request_recipient.trim().is_empty()
        && mobile.pending_join_requested_at != 0
}

fn mobile_nostr_enabled(mobile: &MobileTunnelConfig) -> bool {
    mobile.nostr_discovery_enabled
        && (mobile.join_requests_enabled
            || mobile.device_approval_pending
            || mobile_join_request_pending(mobile)
            || !mobile.peers.is_empty()
            || !mobile.peer_hints.is_empty())
}

fn native_config_path(data_dir: &str) -> PathBuf {
    let trimmed = data_dir.trim();
    if trimmed.is_empty() {
        default_config_path()
    } else {
        PathBuf::from(trimmed).join("config.toml")
    }
}

fn default_config_path() -> PathBuf {
    dirs::config_dir().map_or_else(
        || PathBuf::from("nvpn.toml"),
        |dir| dir.join("nvpn").join("config.toml"),
    )
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    let tunnel_ip = tunnel_ip.trim();
    if tunnel_ip.is_empty() {
        return "10.44.0.1/32".to_string();
    }
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn endpoint_with_listen_port(endpoint: &str, listen_port: u16) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
        if addr.port() != 0 || listen_port == 0 {
            return addr.to_string();
        }
        return match addr.ip() {
            std::net::IpAddr::V4(ip) => format!("{ip}:{listen_port}"),
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{listen_port}"),
        };
    }
    if trimmed.rsplit_once(':').is_some() || listen_port == 0 {
        return trimmed.to_string();
    }
    format!("{trimmed}:{listen_port}")
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn mobile_lan_ipv4_candidates(local_address: &str) -> Vec<Ipv4Addr> {
    let tunnel_ipv4 = parse_ipv4(local_address);
    let mut ips = Vec::new();
    if let Some(ip) = detect_runtime_primary_ipv4()
        && ipv4_is_lan_endpoint_hint(ip)
        && Some(ip) != tunnel_ipv4
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

fn endpoint_is_gossipable_direct_hint(endpoint: &str) -> bool {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return parsed.port() != 0 && !endpoint_hint_ip_is_unusable(parsed.ip());
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
    true
}

fn endpoint_hint_ip_is_unusable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn mobile_fips_endpoint_hint_priority(addr: &str, normal_priority: u8) -> u8 {
    if endpoint_addr_is_private_or_local(addr) {
        FIPS_PRIVATE_DYNAMIC_PEER_ENDPOINT_PRIORITY
    } else {
        normal_priority
    }
}

fn endpoint_addr_is_private_or_local(endpoint: &str) -> bool {
    endpoint_addr_ip(endpoint).is_some_and(endpoint_ip_is_private_or_local)
}

fn endpoint_ip_is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ipv4_is_cgnat_addr(ip)
                || ip.is_link_local()
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ipv4_is_benchmark_addr(ip)
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    }
}

fn ipv4_is_cgnat_addr(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn ipv4_is_benchmark_addr(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 198 && (18..=19).contains(&octets[1])
}

fn endpoint_uses_tunnel_ip(endpoint: &str, tunnel_ip: &str) -> bool {
    let Some(tunnel_ip) = parse_ipv4(tunnel_ip).map(IpAddr::V4) else {
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

fn wg_upstream_excluded_route_for_addr(upstream: SocketAddr) -> Option<String> {
    match upstream.ip() {
        IpAddr::V4(ip) => Some(format!("{ip}/32")),
        IpAddr::V6(_) => None,
    }
}

fn configure_mobile_webrtc_transport(
    config: &mut FipsConfig,
    nostr_enabled: bool,
    stun_servers: &[String],
    resolve_mdns_candidates: bool,
) {
    if !nostr_enabled {
        return;
    }

    #[allow(clippy::default_trait_access)]
    {
        config.transports.webrtc = TransportInstances::Single(Default::default());
    }
    let TransportInstances::Single(webrtc) = &mut config.transports.webrtc else {
        return;
    };
    webrtc.advertise_on_nostr = Some(true);
    webrtc.auto_connect = Some(true);
    webrtc.accept_connections = Some(true);
    webrtc.resolve_mdns_candidates = Some(resolve_mdns_candidates);
    if !stun_servers.is_empty() {
        webrtc.stun_servers = Some(stun_servers.to_vec());
    }
}

#[cfg(test)]
mod endpoint_config_tests {
    use super::*;
    use nostr_sdk::prelude::Keys;

    fn test_peer() -> FipsMeshPeerConfig {
        let participant = Keys::generate().public_key().to_hex();
        FipsMeshPeerConfig::from_participant_pubkey(&participant, vec!["10.44.1.2/32".to_string()])
            .expect("peer config")
    }

    #[test]
    fn mobile_endpoint_config_configures_webrtc_when_discovery_on() {
        let roster = test_peer();
        let pending = test_peer();
        let transit = test_peer();
        let mobile = MobileTunnelConfig {
            peers: vec![roster.clone()],
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            websocket_seed_urls: vec!["wss://seed.example.org/fips".to_string()],
            stun_servers: vec!["stun:stun.example.org:3478".to_string()],
            webrtc_enabled: true,
            connect_to_non_roster_fips_peers: true,
            pending_join_request_recipient: pending.participant_pubkey.clone(),
            pending_join_requested_at: 1,
            bootstrap_peers: HashMap::from([(
                transit.participant_pubkey.clone(),
                vec![FipsPeerAddressHint {
                    addr: "203.0.113.20:51820".to_string(),
                    seen_at_ms: None,
                    priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
                }],
            )]),
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        config
            .validate()
            .expect("WebRTC-enabled mobile FIPS config should validate");
        assert_eq!(config.node.routing.mode, RoutingMode::ReplyLearned);
        let TransportInstances::Single(webrtc) = &config.transports.webrtc else {
            panic!("expected one WebRTC transport");
        };
        assert_eq!(webrtc.advertise_on_nostr, Some(true));
        assert_eq!(webrtc.auto_connect, Some(true));
        assert_eq!(webrtc.accept_connections, Some(true));
        assert_eq!(webrtc.resolve_mdns_candidates, Some(true));
        assert_eq!(
            webrtc.stun_servers.as_ref().expect("stun servers"),
            &mobile.stun_servers
        );
        let TransportInstances::Single(websocket) = &config.transports.websocket else {
            panic!("expected one WebSocket transport");
        };
        assert_eq!(websocket.seed_urls, mobile.websocket_seed_urls);
    }

    #[test]
    fn ios_keeps_routable_discovery_without_opening_multicast() {
        let peer = test_peer();
        let peer_npub = peer.endpoint_npub.clone();
        let peer_pubkey = peer.participant_pubkey.clone();
        let mobile = MobileTunnelConfig {
            peers: vec![peer],
            peer_hints: HashMap::from([(
                peer_pubkey,
                vec![FipsPeerAddressHint {
                    addr: "192.168.50.24:51820".to_string(),
                    seen_at_ms: None,
                    priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
                }],
            )]),
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            websocket_seed_urls: vec!["wss://seed.example.org/fips".to_string()],
            stun_servers: vec!["stun:stun.example.org:3478".to_string()],
            share_local_candidates: true,
            nostr_discovery_enabled: true,
            webrtc_enabled: true,
            ..empty_config()
        };

        let config =
            fips_endpoint_config_for_platform("nostr-vpn:test", &mobile, RuntimePlatform::Ios);

        assert!(config.node.discovery.nostr.enabled);
        assert!(
            config.node.discovery.nostr.share_local_candidates,
            "encrypted traversal signaling should retain direct LAN candidates"
        );
        assert!(!config.node.discovery.lan.enabled);
        let TransportInstances::Single(webrtc) = &config.transports.webrtc else {
            panic!("expected one WebRTC transport");
        };
        assert_eq!(webrtc.resolve_mdns_candidates, Some(false));
        assert!(!config.transports.websocket.is_empty());
        assert!(!config.transports.udp.is_empty());
        let configured_peer = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == peer_npub)
            .expect("configured peer");
        assert!(configured_peer.addresses.iter().any(|address| {
            address.transport == "udp" && address.addr == "192.168.50.24:51820"
        }));
    }

    #[test]
    fn mobile_config_ignores_stale_join_recipient() {
        let stale = test_peer();
        let mobile = MobileTunnelConfig {
            peers: vec![test_peer()],
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            webrtc_enabled: true,
            pending_join_request_recipient: stale.participant_pubkey,
            pending_join_requested_at: 0,
            ..empty_config()
        };

        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        assert!(config.peers.iter().all(|peer| peer.npub != stale.endpoint_npub));
    }

    #[test]
    fn mobile_endpoint_config_leaves_webrtc_empty_when_discovery_off() {
        let mobile = MobileTunnelConfig {
            peers: vec![test_peer()],
            nostr_discovery_enabled: false,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(!config.node.discovery.nostr.enabled);
        assert!(config.transports.webrtc.is_empty());
        assert!(config.transports.websocket.is_empty());
    }

    #[test]
    fn pending_device_approval_opens_mobile_discovery_without_a_network() {
        let mut app = AppConfig::generated_without_networks();
        app.ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending device approval");
        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");

        let config = fips_endpoint_config("nostr-vpn:pending", &mobile);

        assert!(config.node.discovery.nostr.enabled);
        assert!(
            !config.node.discovery.nostr.advertise,
            "the approval npub must route without a FIPS advert"
        );
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(config.node.discovery.nostr.open_discovery_max_pending > 0);
    }

    #[test]
    fn mobile_endpoint_config_keeps_websocket_without_webrtc() {
        let mobile = MobileTunnelConfig {
            peers: vec![test_peer()],
            nostr_discovery_enabled: true,
            webrtc_enabled: false,
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            websocket_seed_urls: vec!["wss://seed.example.org/fips".to_string()],
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert!(config.transports.webrtc.is_empty());
        assert!(!config.transports.websocket.is_empty());
        assert!(!config.transports.udp.is_empty());
    }
}
