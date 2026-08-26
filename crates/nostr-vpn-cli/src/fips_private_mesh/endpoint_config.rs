#[derive(Debug, Clone)]
struct FipsEndpointTransportConfig {
    listen_port: u16,
    bind_interface: Option<String>,
    advertised_endpoint: String,
    advertise_public_endpoint: bool,
    /// Find/advertise peers over Nostr relays. When false, the endpoint dials
    /// only configured static/bootstrap peers and does not enable ambient
    /// relay, LAN, or same-host endpoint discovery.
    nostr_discovery_enabled: bool,
    /// Publishing is independent from consuming relay discovery. A pending
    /// join already supplied its npub to the administrator and only needs
    /// identity-routed control delivery until membership is confirmed.
    advertise_on_nostr: bool,
    webrtc_enabled: bool,
    stun_servers: Vec<String>,
    nostr_relays: Vec<String>,
    websocket: WebSocketConfig,
    share_local_candidates: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsEthernetUnderlayConfig {
    pub(crate) interface: String,
    pub(crate) discovery_scope: String,
}

impl FipsEthernetUnderlayConfig {
    pub(crate) fn parse(interface: &str, discovery_scope: &str) -> Result<Self> {
        let interface = interface.trim();
        if interface.is_empty() {
            return Err(anyhow!("--fips-ethernet-interface must not be empty"));
        }
        let discovery_scope = discovery_scope.trim();
        if discovery_scope.is_empty() {
            return Err(anyhow!(
                "--fips-ethernet-discovery-scope must not be empty"
            ));
        }
        if discovery_scope.len() > u8::MAX as usize {
            return Err(anyhow!(
                "--fips-ethernet-discovery-scope must not exceed 255 UTF-8 bytes"
            ));
        }
        Ok(Self {
            interface: interface.to_string(),
            discovery_scope: discovery_scope.to_string(),
        })
    }
}

/// Address hint carried through nvpn's intermediate config types before
/// being lowered into a fips `PeerAddress`. `seen_at_ms` is the
/// most-recent observation timestamp (Unix ms) when we have one — set for
/// recent-peers cache entries, `None` for operator-supplied static hints.
/// fips's dialer uses this field as a recency tiebreaker inside the same
/// priority tier.
const FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY: u8 = 10;
const FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY: u8 = 100;
const FIPS_PRIVATE_DYNAMIC_PEER_ENDPOINT_PRIORITY: u8 = 200;
const FIPS_WEBSOCKET_FALLBACK_ENDPOINT_PRIORITY: u8 = 200;
const FIPS_UDP_IPV4_TRANSPORT: &str = "ipv4";
const FIPS_UDP_IPV6_TRANSPORT: &str = "ipv6";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsPeerAddressHint {
    pub(crate) addr: String,
    pub(crate) seen_at_ms: Option<u64>,
    pub(crate) priority: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsEndpointPeerTransportConfig {
    pub(crate) npub: String,
    pub(crate) addresses: Vec<FipsPeerAddressHint>,
    pub(crate) connect_on_start: bool,
    pub(crate) auto_reconnect: bool,
    pub(crate) discovery_fallback_transit: bool,
}

fn endpoint_peers_with_changed_addresses(
    previous: &[FipsEndpointPeerTransportConfig],
    next: &[FipsEndpointPeerTransportConfig],
) -> Vec<FipsEndpointPeerTransportConfig> {
    next.iter()
        .filter(|peer| {
            previous
                .iter()
                .find(|candidate| candidate.npub == peer.npub)
                .is_none_or(|candidate| candidate.addresses != peer.addresses)
        })
        .cloned()
        .collect()
}

pub(crate) fn prioritize_fips_control_recipient(
    peers: Vec<FipsEndpointPeerTransportConfig>,
    recipient_pubkey: &str,
) -> Result<Vec<FipsEndpointPeerTransportConfig>> {
    let recipient_pubkey = normalize_nostr_pubkey(recipient_pubkey)
        .with_context(|| format!("invalid FIPS control recipient {recipient_pubkey}"))?;
    let recipient_npub = PublicKey::from_hex(&recipient_pubkey)?.to_bech32()?;
    Ok(prioritize_fips_control_peer(peers, &recipient_npub))
}

fn prioritize_fips_control_peer(
    mut peers: Vec<FipsEndpointPeerTransportConfig>,
    route_npub: &str,
) -> Vec<FipsEndpointPeerTransportConfig> {
    let mut route_peer = peers
        .iter()
        .position(|peer| peer.npub == route_npub)
        .map(|index| peers.remove(index))
        .unwrap_or_else(|| FipsEndpointPeerTransportConfig {
            npub: route_npub.to_string(),
            addresses: Vec::new(),
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        });
    route_peer.connect_on_start = true;
    route_peer.auto_reconnect = true;
    peers.insert(0, route_peer);
    peers
}

#[cfg(test)]
fn fips_peer_address_from_hint(hint: &FipsPeerAddressHint) -> PeerAddress {
    let (transport, addr) = split_peer_transport_addr(&hint.addr);
    fips_peer_address_from_parts(hint, transport, addr)
}

fn fips_peer_address_from_parts(
    hint: &FipsPeerAddressHint,
    transport: String,
    addr: String,
) -> PeerAddress {
    let mut peer_address = PeerAddress::with_priority(transport, addr, hint.priority);
    if let Some(seen_at_ms) = hint.seen_at_ms {
        peer_address = peer_address.learned().with_seen_at_ms(seen_at_ms);
    }
    peer_address
}

fn fips_peer_addresses_from_hint(hint: &FipsPeerAddressHint) -> Vec<PeerAddress> {
    let (transport, addr) = split_peer_transport_addr(&hint.addr);
    if transport != "udp" || addr.parse::<SocketAddr>().is_ok() {
        return vec![fips_peer_address_from_parts(hint, transport, addr)];
    }

    let Ok(resolved) = addr.to_socket_addrs() else {
        return vec![fips_peer_address_from_parts(hint, transport, addr)];
    };
    let mut seen = HashSet::new();
    let addresses = resolved
        .filter(|socket_addr| seen.insert(*socket_addr))
        .map(|socket_addr| {
            fips_peer_address_from_parts(hint, transport.clone(), socket_addr.to_string())
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        vec![fips_peer_address_from_parts(hint, transport, addr)]
    } else {
        addresses
    }
}

fn retain_enabled_peer_transport_addresses(
    peers: &mut [FipsEndpointPeerTransportConfig],
    webrtc_enabled: bool,
) {
    if webrtc_enabled {
        return;
    }
    for peer in peers {
        peer.addresses
            .retain(|hint| split_peer_transport_addr(&hint.addr).0 != "webrtc");
    }
}

fn dynamic_endpoint_priority(addr: &str) -> u8 {
    endpoint_hint_priority(addr, FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY)
}

fn endpoint_hint_priority(addr: &str, normal_priority: u8) -> u8 {
    if endpoint_addr_is_private_or_local(addr) {
        FIPS_PRIVATE_DYNAMIC_PEER_ENDPOINT_PRIORITY
    } else {
        normal_priority
    }
}

fn endpoint_addr_is_private_or_local(addr: &str) -> bool {
    endpoint_addr_ip(addr).is_some_and(endpoint_ip_is_private_or_local)
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

fn ipv4_is_benchmark_addr(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 198 && (18..=19).contains(&octets[1])
}

fn fips_endpoint_config_with_open_discovery_limit(
    peers: &[FipsEndpointPeerTransportConfig],
    transport: Option<&FipsEndpointTransportConfig>,
    mesh_mtu: MeshMtu,
    nostr_discovery_policy: NostrDiscoveryPolicy,
    open_discovery_max_pending: usize,
) -> Config {
    let mut config = Config::new();
    config.node.control.enabled = false;
    let public_websocket_listener = transport.is_some_and(|transport| {
        transport.websocket.bind_addr.is_some() && transport.websocket.public_url.is_some()
    });
    if public_websocket_listener {
        // The transport admits this many physical sockets, so the FIPS node
        // must be able to promote and retain the same bounded population.
        // Otherwise authenticated ambient peers fill the lower core default
        // and deny a fresh bootstrap client while WebSocket still has room.
        config.node.limits.max_connections = FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS;
        config.node.limits.max_peers = FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS;
        config.node.limits.max_links = FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS;
    }
    // App mesh peers may be routable only through already-connected
    // neighbors when direct NAT traversal fails. Reply-learned routing lets
    // first-contact EndpointData trigger discovery through those neighbors.
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.retry.base_interval_secs = FIPS_RECONNECT_BACKOFF_BASE_SECS;
    config.node.retry.max_backoff_secs = FIPS_RECONNECT_BACKOFF_MAX_SECS;
    config.node.heartbeat_interval_secs = FIPS_ENDPOINT_HEARTBEAT_INTERVAL_SECS;
    config.node.link_dead_timeout_secs = FIPS_ENDPOINT_LINK_DEAD_TIMEOUT_SECS;
    config.node.fast_link_dead_timeout_secs = FIPS_ENDPOINT_FAST_LINK_DEAD_TIMEOUT_SECS;
    config.node.session.idle_timeout_secs = FIPS_ENDPOINT_SESSION_IDLE_TIMEOUT_SECS;
    config.node.session.pending_packets_per_dest = FIPS_ENDPOINT_PENDING_PACKETS_PER_DEST;
    config.node.rekey.after_secs = FIPS_ENDPOINT_REKEY_AFTER_SECS;
    config.dns.enabled = false;
    // Public/open discovery can route through authenticated transit nodes. Be
    // polite to those nodes when stale roster peers or cached adverts cannot
    // be reached.
    config.node.discovery.backoff_base_secs = FIPS_DISCOVERY_BACKOFF_BASE_SECS;
    config.node.discovery.backoff_max_secs = FIPS_DISCOVERY_BACKOFF_MAX_SECS;
    config.node.discovery.forward_min_interval_secs = FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS;
    let advertise_public_endpoint = transport
        .map(|transport| transport.advertise_public_endpoint)
        .unwrap_or(false);
    // The signed Nostr peer-advert toggle. Standard nostr-pubsub is the single
    // relay provider; FIPS signs and ingests ordinary adverts but does not run
    // a second embedded relay client. When off we neither advertise nor ingest
    // peer adverts, while configured physical peers remain directly dialable.
    let nostr_discovery_enabled = transport
        .map(|transport| transport.nostr_discovery_enabled)
        .unwrap_or(true);
    // A fresh joiner already gives the administrator this endpoint's npub in
    // its signed request, so publishing an ambient advert is unnecessary.
    // Start advertising after roster membership exists so FIPS can seek a
    // preferred direct VPN path. Explicit public endpoints still advertise
    // because unknown clients must be able to discover them.
    let advertise_on_nostr = nostr_discovery_enabled
        && transport.is_some_and(|transport| transport.advertise_on_nostr)
        && (advertise_public_endpoint || !peers.is_empty());
    let nostr_enabled = nostr_discovery_enabled && (transport.is_some() || !peers.is_empty());
    config.node.discovery.nostr.enabled = nostr_enabled;
    config.node.discovery.nostr.advertise = advertise_on_nostr;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    // Open discovery by default (unless the user opts into configured-only
    // discovery) so we can FIPS-handshake with any nvpn node we see on relays,
    // not just configured roster peers. This is what lets us route app-mesh
    // traffic through transit hops that aren't in our network roster (a
    // friend-of-a-friend nvpn node can ferry our packets when direct
    // traversal fails). Security boundary: the FIPS handshake can be open; the
    // per-network data plane is NOT. `FipsMeshRuntime::receive_endpoint_data*`
    // drops every inbound packet whose source npub doesn't own the inner
    // source IP per our roster, so a non-roster transit peer can carry frames
    // but cannot inject anything that surfaces on the tun. See the
    // `inbound_endpoint_data_*` tests in `nostr-vpn-core::fips_mesh`.
    // Headless e2e meshes can force configured-only discovery to avoid
    // contending with ambient public relay traffic.
    config.node.discovery.nostr.policy = nostr_discovery_policy;
    config.node.discovery.nostr.open_discovery_max_pending = open_discovery_max_pending;
    config.node.discovery.nostr.failure_streak_threshold = FIPS_NOSTR_FAILURE_STREAK_THRESHOLD;
    config.node.discovery.nostr.extended_cooldown_secs = FIPS_NOSTR_EXTENDED_COOLDOWN_SECS;
    config.node.discovery.nostr.startup_sweep_max_age_secs = FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS;
    config.node.discovery.nostr.share_local_candidates = nostr_discovery_enabled
        && transport
            .map(|transport| transport.share_local_candidates)
            .unwrap_or(false);
    config.node.discovery.lan.enabled = nostr_discovery_enabled
        && transport
            .map(|transport| transport.share_local_candidates)
            .unwrap_or(false);
    // Leave the relay-side `app` at fips-core's default ("fips-overlay-v1").
    // We deliberately do NOT bake the per-network mesh id into it: the relay
    // `protocol` tag is publicly visible, so per-network apps would let any
    // observer count members of each private network. The builder receives a
    // hashed per-network LAN discovery scope separately; that scope is carried
    // only in mDNS TXT records on the local link, while the private data plane
    // still enforces roster ownership before packets reach the tun.
    let external_addr = transport
        .filter(|_| advertise_public_endpoint)
        .and_then(|transport| fips_udp_external_addr(&transport.advertised_endpoint));
    if let Some(transport) = transport {
        config.node.discovery.nostr.bind_interface = transport.bind_interface.clone();
        config.node.discovery.nostr.stun_servers = transport.stun_servers.clone();
        if !transport.nostr_relays.is_empty() {
            config.node.discovery.nostr.advert_relays = transport.nostr_relays.clone();
        }
        if transport.webrtc_enabled {
            configure_fips_webrtc_transport(
                &mut config,
                advertise_on_nostr,
                &transport.stun_servers,
                mesh_mtu.underlay_udp,
            );
        }
        let has_configured_websocket_fallback = peers.iter().any(|peer| {
            peer.addresses
                .iter()
                .any(|hint| split_peer_transport_addr(&hint.addr).0 == "websocket")
        });
        if !transport.websocket.seed_urls.is_empty()
            || transport.websocket.bind_addr.is_some()
            || has_configured_websocket_fallback
        {
            config.transports.websocket =
                TransportInstances::Single(transport.websocket.clone());
        }
    }
    let listen_port = transport.map_or(0, |transport| transport.listen_port);
    let advertised_family = external_addr
        .as_deref()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| addr.is_ipv6());
    let (ipv4_external_addr, ipv6_external_addr) = match advertised_family {
        Some(false) => (external_addr, None),
        Some(true) => (None, external_addr),
        None => (None, None),
    };
    let udp = UdpConfig {
        bind_interface: transport.and_then(|transport| transport.bind_interface.clone()),
        public: Some(advertise_public_endpoint),
        outbound_only: Some(transport.is_none()),
        accept_connections: Some(transport.is_some()),
        // The safe default remains IPv6-minimum sized for NAT traversal and
        // nested tunnels. Clean-LAN tests must opt into a larger paired budget
        // through config or NVPN_MESH_* env overrides.
        mtu: Some(mesh_mtu.underlay_udp),
        send_buf_size: fips_udp_send_buf_size(),
        ..UdpConfig::default()
    };
    let mut ipv4 = udp.clone();
    ipv4.bind_addr = Some(format!("0.0.0.0:{listen_port}"));
    ipv4.advertise_on_nostr = Some(advertise_on_nostr && advertised_family != Some(true));
    ipv4.external_addr = ipv4_external_addr;
    let mut ipv6 = udp;
    ipv6.bind_addr = Some(format!("[::]:{listen_port}"));
    ipv6.advertise_on_nostr = Some(advertise_on_nostr && advertised_family == Some(true));
    ipv6.external_addr = ipv6_external_addr;
    config.transports.udp = TransportInstances::Named(HashMap::from([
        (FIPS_UDP_IPV4_TRANSPORT.to_string(), ipv4),
        (FIPS_UDP_IPV6_TRANSPORT.to_string(), ipv6),
    ]));
    // Outbound TCP transport so peers reachable only over tcp:443 (e.g. on
    // networks that block UDP outright) can still be dialed. bind_addr=None keeps
    // it outbound-only — no listener.
    let needs_tcp = peers.iter().any(|peer| {
        peer.addresses
            .iter()
            .any(|hint| split_peer_transport_addr(&hint.addr).0 == "tcp")
    });
    if needs_tcp {
        // Default = outbound-only (no bind_addr). Inferred type keeps this the
        // exact `TcpConfig` of `config.transports`, which matters under the e2e's
        // [patch.crates-io] where a second fips-core version can be in the graph,
        // so we deliberately keep `Default::default()` over `TcpConfig::default()`.
        #[allow(clippy::default_trait_access)]
        {
            config.transports.tcp = TransportInstances::Single(Default::default());
        }
    }
    config.peers = peers
        .iter()
        .map(|peer| FipsPeerConfig {
            npub: peer.npub.clone(),
            alias: None,
            addresses: peer
                .addresses
                .iter()
                .flat_map(fips_peer_addresses_from_hint)
                .collect(),
            connect_policy: if peer.connect_on_start {
                ConnectPolicy::AutoConnect
            } else {
                ConnectPolicy::Manual
            },
            auto_reconnect: peer.auto_reconnect,
            discovery_fallback_transit: peer.discovery_fallback_transit,
        })
        .collect();
    config
}

fn fips_endpoint_config_for_ethernet(
    peers: &[FipsEndpointPeerTransportConfig],
    transport: Option<&FipsEndpointTransportConfig>,
    ethernet: &FipsEthernetUnderlayConfig,
    mesh_mtu: MeshMtu,
    nostr_discovery_policy: NostrDiscoveryPolicy,
    open_discovery_max_pending: usize,
) -> Config {
    let mut config = fips_endpoint_config_with_open_discovery_limit(
        peers,
        transport,
        mesh_mtu,
        nostr_discovery_policy,
        open_discovery_max_pending,
    );
    config.transports.ethernet = TransportInstances::Single(EthernetConfig {
        interface: ethernet.interface.clone(),
        discovery: Some(true),
        announce: Some(true),
        auto_connect: Some(true),
        accept_connections: Some(true),
        discovery_scope: Some(ethernet.discovery_scope.clone()),
        mtu: Some(mesh_mtu.underlay_udp),
        ..EthernetConfig::default()
    });
    config
}

fn fips_endpoint_peers_from_mesh(
    mesh_peers: &[FipsMeshPeerConfig],
    operator_static_endpoints: Vec<(String, Vec<String>)>,
    recent_peer_endpoints: Vec<(String, Vec<(String, u64)>)>,
) -> Vec<FipsEndpointPeerTransportConfig> {
    let mut peers = HashMap::<String, FipsEndpointPeerTransportConfig>::new();
    for peer in mesh_peers {
        let npub = normalize_fips_endpoint_npub(&peer.endpoint_npub);
        peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: true,
                discovery_fallback_transit: true,
            });
    }

    // Operator-configured hints have no freshness signal. If a duplicate
    // address later appears in the recent cache, keep the operator hint static.
    for (npub, addresses) in operator_static_endpoints {
        let npub = normalize_fips_endpoint_npub(&npub);
        let peer = peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: true,
                discovery_fallback_transit: true,
            });
        for raw in addresses {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let priority = if split_peer_transport_addr(trimmed).0 == "websocket" {
                FIPS_WEBSOCKET_FALLBACK_ENDPOINT_PRIORITY
            } else {
                FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY
            };
            if let Some(existing) = peer.addresses.iter_mut().find(|hint| hint.addr == trimmed) {
                existing.seen_at_ms = None;
                existing.priority = existing.priority.min(priority);
                continue;
            }
            peer.addresses.push(FipsPeerAddressHint {
                addr: trimmed.to_string(),
                seen_at_ms: None,
                priority,
            });
        }
    }

    // Recent-peers cache entries arrive with millisecond freshness so fips can
    // prefer fresher hints within the same priority tier. Authenticated
    // non-roster entries are transport-only seeds: FIPS may use them for
    // decentralized transit, while nvpn's separate route/admission tables
    // continue to restrict private-network packets to roster participants.
    for (npub, addresses) in recent_peer_endpoints {
        let npub = normalize_fips_endpoint_npub(&npub);
        let peer = peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: false,
                discovery_fallback_transit: true,
            });
        for (addr, seen_at_ms) in addresses {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Same (npub, addr) from multiple dynamic sources: keep the
            // freshest timestamp. If an operator static hint already owns this
            // socket, do not stamp it as recent; fips uses that distinction to
            // keep the configured LAN path preferred during retries.
            if let Some(existing) = peer.addresses.iter_mut().find(|hint| hint.addr == trimmed) {
                if let Some(existing_seen_at_ms) = existing.seen_at_ms {
                    let priority = dynamic_endpoint_priority(trimmed);
                    existing.seen_at_ms = Some(existing_seen_at_ms.max(seen_at_ms));
                    existing.priority = existing.priority.min(priority);
                }
                continue;
            }
            peer.addresses.push(FipsPeerAddressHint {
                addr: trimmed.to_string(),
                seen_at_ms: Some(seen_at_ms),
                priority: dynamic_endpoint_priority(trimmed),
            });
        }
    }

    let mut peers = peers.into_values().collect::<Vec<_>>();
    for peer in &mut peers {
        peer.addresses.sort_by(|a, b| a.addr.cmp(&b.addr));
        peer.addresses.dedup_by(|a, b| a.addr == b.addr);
    }
    peers.sort_by(|left, right| left.npub.cmp(&right.npub));
    peers
}

/// Keep a pair of public WebSocket listeners configured as routing peers on
/// both sides while giving exactly one side ownership of the physical dial.
/// The lexicographically greater canonical npub dials the lesser npub. This
/// avoids cross-connection replacement races without weakening either side's
/// configured-transit status or coupling identity to URL spelling.
pub(crate) fn apply_canonical_websocket_dial_direction(
    peers: &mut [FipsEndpointPeerTransportConfig],
    local_npub: &str,
    public_websocket_listener: bool,
) {
    if !public_websocket_listener {
        return;
    }
    let local_npub = normalize_fips_endpoint_npub(local_npub);
    if PublicKey::parse(&local_npub).is_err() {
        return;
    }

    for peer in peers {
        let peer_npub = normalize_fips_endpoint_npub(&peer.npub);
        if peer_npub == local_npub || PublicKey::parse(&peer_npub).is_err() {
            continue;
        }

        let mut has_configured_websocket = false;
        let mut has_other_configured_transport = false;
        for hint in &peer.addresses {
            if hint.seen_at_ms.is_some() {
                continue;
            }
            let (transport, _) = split_peer_transport_addr(&hint.addr);
            if transport == "websocket" {
                has_configured_websocket = true;
            } else {
                has_other_configured_transport = true;
            }
        }
        if !has_configured_websocket || has_other_configured_transport {
            continue;
        }

        peer.connect_on_start = peer_npub < local_npub;
    }
}

/// The WebSocket transport's legacy seed list dials independently of
/// `PeerConfig::connect_policy`. Remove only URLs belonging to a configured
/// identity whose canonical peer policy is Manual, so the transport cannot
/// recreate the cross-connection that peer arbitration intentionally avoids.
fn websocket_seed_urls_after_peer_dial_ownership(
    configured_seed_urls: &[String],
    peers: &[FipsEndpointPeerTransportConfig],
) -> Vec<String> {
    configured_seed_urls
        .iter()
        .filter(|seed_url| {
            let seed_url = seed_url.trim();
            !peers.iter().any(|peer| {
                !peer.connect_on_start
                    && peer.addresses.iter().any(|hint| {
                        hint.seen_at_ms.is_none()
                            && {
                                let (transport, addr) =
                                    split_peer_transport_addr(&hint.addr);
                                transport == "websocket" && addr.trim() == seed_url
                            }
                    })
            })
        })
        .cloned()
        .collect()
}

#[cfg(feature = "paid-exit")]
pub(crate) fn fips_endpoint_peers_with_paid_route_admissions(
    endpoint_peers: Vec<FipsEndpointPeerTransportConfig>,
    admissions: &[FipsPaidRouteAdmission],
) -> Vec<FipsEndpointPeerTransportConfig> {
    let mut peers = endpoint_peers
        .into_iter()
        .map(|mut peer| {
            peer.npub = normalize_fips_endpoint_npub(&peer.npub);
            (peer.npub.clone(), peer)
        })
        .collect::<HashMap<_, _>>();

    for admission in admissions {
        let npub = normalize_fips_endpoint_npub(&admission.participant_pubkey);
        if npub.trim().is_empty() {
            continue;
        }
        let peer = peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: true,
                discovery_fallback_transit: false,
            });
        peer.connect_on_start = true;
        peer.auto_reconnect = true;
        peer.discovery_fallback_transit = false;
    }

    let mut peers = peers.into_values().collect::<Vec<_>>();
    for peer in &mut peers {
        peer.addresses.sort_by(|a, b| a.addr.cmp(&b.addr));
        peer.addresses.dedup_by(|a, b| a.addr == b.addr);
    }
    peers.sort_by(|left, right| left.npub.cmp(&right.npub));
    peers
}

fn normalize_fips_endpoint_npub(value: &str) -> String {
    let trimmed = value.trim();
    normalize_nostr_pubkey(trimmed)
        .ok()
        .and_then(|pubkey| {
            PublicKey::from_hex(&pubkey)
                .ok()
                .and_then(|public_key| public_key.to_bech32().ok())
        })
        .unwrap_or_else(|| trimmed.to_string())
}

fn participant_pubkey_bytes(value: &str) -> Option<ParticipantPubkeyBytes> {
    PublicKey::parse(value.trim())
        .ok()
        .map(|pubkey| *pubkey.as_bytes())
}

fn fips_udp_external_addr(advertised_endpoint: &str) -> Option<String> {
    let endpoint = advertised_endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    let parsed = endpoint.parse::<SocketAddr>().ok()?;
    if endpoint_ip_is_private_or_local(parsed.ip()) {
        return None;
    }
    Some(parsed.to_string())
}

fn required_public_udp_listener_ipv6(config: &FipsPrivateTunnelConfig) -> Option<bool> {
    config.advertise_public_endpoint.then(|| {
        fips_udp_external_addr(&config.advertised_endpoint)
            .and_then(|addr| addr.parse::<SocketAddr>().ok())
            .is_some_and(|addr| addr.is_ipv6())
    })
}

fn configure_fips_webrtc_transport(
    config: &mut Config,
    ambient_discovery_enabled: bool,
    stun_servers: &[String],
    mtu: u16,
) {
    #[allow(clippy::default_trait_access)]
    {
        config.transports.webrtc = TransportInstances::Single(Default::default());
    }
    let TransportInstances::Single(webrtc) = &mut config.transports.webrtc else {
        return;
    };
    webrtc.advertise_on_nostr = Some(ambient_discovery_enabled);
    webrtc.auto_connect = Some(ambient_discovery_enabled);
    // Offers arrive through an existing authenticated FIPS session. Keep
    // inbound WebRTC available even when ambient relay discovery is disabled;
    // the node's configured/open discovery policy still decides which
    // authenticated identities may submit link negotiation.
    webrtc.accept_connections = Some(true);
    webrtc.mtu = Some(mtu);
    if !stun_servers.is_empty() {
        webrtc.stun_servers = Some(stun_servers.to_vec());
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FipsPrivateTunnelConfig {
    pub(crate) identity_nsec: String,
    pub(crate) network_id: String,
    pub(crate) iface: String,
    pub(crate) local_address: String,
    pub(crate) listen_port: u16,
    pub(crate) underlay_interface: Option<String>,
    pub(crate) advertised_endpoint: String,
    pub(crate) advertise_public_endpoint: bool,
    pub(crate) stun_servers: Vec<String>,
    pub(crate) nostr_relays: Vec<String>,
    pub(crate) nostr_pubsub: nostr_vpn_core::config::NostrPubsubConfig,
    pub(crate) control_pubsub_store_path: PathBuf,
    pub(crate) ethernet_underlay: Option<FipsEthernetUnderlayConfig>,
    pub(crate) websocket: WebSocketConfig,
    pub(crate) share_local_candidates: bool,
    pub(crate) peers: Vec<FipsMeshPeerConfig>,
    pub(crate) endpoint_peers: Vec<FipsEndpointPeerTransportConfig>,
    /// Keep the authenticated FIPS control plane alive while the local VPN is
    /// paused without installing peer/default routes or taking over DNS.
    pub(crate) client_dataplane_enabled: bool,
    pub(crate) route_targets: Vec<String>,
    /// The selected internet source owns system DNS even while its default
    /// route is pending. This keeps roster MagicDNS alive during exit setup.
    secure_dns_requested: bool,
    public_paid_exit_waiting_for_admission: bool,
    pub(crate) magic_dns_records: HashMap<String, Ipv4Addr>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fips_host: Option<FipsHostTunnelConfig>,
    pub(crate) local_advertised_routes: Vec<String>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) local_exit_forwarding_routes: Vec<String>,
    pub(crate) local_exit_seller_egress: Option<PaidExitSellerEgress>,
    pub(crate) paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    #[cfg(feature = "paid-exit")]
    pub(crate) paid_route_accounting_peers: Vec<FipsPaidRouteAccountingPeer>,
    #[cfg(feature = "paid-exit")]
    pub(crate) paid_exit: PaidExitConfig,
    #[cfg(feature = "paid-exit")]
    pub(crate) paid_route_store_path: PathBuf,
    #[cfg(feature = "paid-exit")]
    pub(crate) paid_route_wallet_data_dir: PathBuf,
    #[cfg(feature = "paid-exit")]
    pub(crate) paid_route_payment_relays: Vec<String>,
    pub(crate) exit_dns: ExitDnsConfig,
    pub(crate) wireguard_exit: WireGuardExitConfig,
    pub(crate) exit_node_leak_protection: bool,
    nostr_discovery_enabled: bool,
    advertise_on_nostr: bool,
    webrtc_enabled: bool,
    nostr_discovery_policy: NostrDiscoveryPolicy,
    open_discovery_max_pending: usize,
    mesh_mtu: MeshMtu,
    #[cfg(target_os = "linux")]
    pub(crate) control_plane_bypass_hosts: Vec<Ipv4Addr>,
}

include!("endpoint_config/tests.rs");
