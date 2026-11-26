fn routed_fips_peer(
    peer: &FipsMeshPeerRuntime,
    via_default_route: bool,
) -> Option<RoutedFipsPeer<'_>> {
    Some(RoutedFipsPeer {
        participant_pubkey: &peer.participant_pubkey_hex,
        participant_pubkey_bytes: peer.participant_pubkey.as_ref(),
        endpoint_node_addr: peer.endpoint_node_addr.as_ref()?,
        via_default_route,
    })
}

fn routed_fips_packet(peer: &FipsMeshPeerRuntime, bytes: Vec<u8>) -> Option<RoutedFipsPacket<'_>> {
    let peer = routed_fips_peer(peer, false)?;
    Some(RoutedFipsPacket {
        participant_pubkey: peer.participant_pubkey,
        participant_pubkey_bytes: peer.participant_pubkey_bytes,
        endpoint_node_addr: peer.endpoint_node_addr,
        bytes,
    })
}

fn normalize_paid_route_admissions(
    admissions: Vec<FipsPaidRouteAdmission>,
) -> HashMap<[u8; 32], FipsPaidRouteAdmission> {
    let mut by_participant = HashMap::new();
    for mut admission in admissions {
        let Some(participant_pubkey) = parse_nostr_pubkey_bytes(&admission.participant_pubkey)
        else {
            continue;
        };
        admission.participant_pubkey = hex::encode(participant_pubkey);
        let replace = by_participant
            .get(&participant_pubkey)
            .is_none_or(|existing| paid_route_admission_preferred(&admission, existing));
        if replace {
            by_participant.insert(participant_pubkey, admission);
        }
    }
    by_participant
}

fn paid_route_admission_preferred(
    candidate: &FipsPaidRouteAdmission,
    existing: &FipsPaidRouteAdmission,
) -> bool {
    match (candidate.allow_routing, existing.allow_routing) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.updated_at_unix > existing.updated_at_unix,
    }
}

fn paid_route_peers_from_admissions(
    admissions: &HashMap<[u8; 32], FipsPaidRouteAdmission>,
    require_routing: bool,
) -> Vec<FipsMeshPeerRuntime> {
    let mut peers = admissions
        .values()
        .filter_map(|admission| {
            if require_routing && !admission.allow_routing {
                return None;
            }
            let routes = admission
                .allowed_ips
                .iter()
                .filter_map(|route| IpRoute::parse(route))
                .collect::<Vec<_>>();
            if routes.is_empty() {
                return None;
            }
            let participant_pubkey = parse_nostr_pubkey_bytes(&admission.participant_pubkey)?;
            let endpoint_node_addr = endpoint_node_addr_from_pubkey_bytes(participant_pubkey);
            let endpoint_npub = npub_for_pubkey_bytes(&participant_pubkey).ok()?;
            let has_default_route = routes.iter().any(|route| route.is_default_route());
            Some(FipsMeshPeerRuntime {
                participant_pubkey: Some(participant_pubkey),
                participant_pubkey_hex: hex::encode(participant_pubkey),
                endpoint_npub: Some(endpoint_npub),
                endpoint_node_addr: Some(endpoint_node_addr),
                routes,
                has_default_route,
            })
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| {
        left.participant_pubkey_hex
            .cmp(&right.participant_pubkey_hex)
    });
    peers.dedup_by(|left, right| same_participant(left, right));
    peers
}

fn paid_route_destination_routes_from_admissions(
    admissions: &HashMap<[u8; 32], FipsPaidRouteAdmission>,
) -> HashMap<[u8; 32], Vec<IpRoute>> {
    admissions
        .iter()
        .map(|(participant, admission)| {
            let routes = admission
                .destination_allowed_ips
                .iter()
                .filter_map(|route| IpRoute::parse(route))
                .collect::<Vec<_>>();
            (*participant, routes)
        })
        .collect()
}

fn select_indexed_peer_for_ip<'a>(
    peers: &'a [FipsMeshPeerRuntime],
    exact_routes: &HashMap<IpAddr, ExactRouteMatch>,
    prefix_v4_routes: &[IndexedIpRoute],
    prefix_v6_routes: &[IndexedIpRoute],
    destination: IpAddr,
) -> PeerRouteSelection<'a> {
    if let Some(route_match) = exact_routes.get(&destination) {
        let prefix_len = if destination.is_ipv4() { 32 } else { 128 };
        return match *route_match {
            ExactRouteMatch::Peer(peer_index) => peers
                .get(peer_index)
                .map_or(PeerRouteSelection::None, |peer| PeerRouteSelection::Match {
                    peer,
                    prefix_len,
                }),
            ExactRouteMatch::Ambiguous => PeerRouteSelection::Ambiguous { prefix_len },
        };
    }

    let prefix_routes = if destination.is_ipv4() {
        prefix_v4_routes
    } else {
        prefix_v6_routes
    };
    let mut selected = PeerRouteSelection::None;

    for candidate in prefix_routes {
        if selected
            .prefix_len()
            .is_some_and(|prefix| candidate.route.prefix_len < prefix)
        {
            break;
        }
        if !candidate.route.matches(destination) {
            continue;
        }
        let Some(peer) = peers.get(candidate.peer_index) else {
            continue;
        };
        selected = selected.combine(PeerRouteSelection::Match {
            peer,
            prefix_len: candidate.route.prefix_len,
        });
    }
    selected
}

fn participant_peer_index(peers: &[FipsMeshPeerRuntime]) -> HashMap<[u8; 32], usize> {
    let mut index = HashMap::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        if let Some(participant_pubkey) = peer.participant_pubkey {
            index.entry(participant_pubkey).or_insert(peer_index);
        }
    }
    index
}

fn endpoint_node_addr_peer_index(peers: &[FipsMeshPeerRuntime]) -> HashMap<[u8; 16], usize> {
    let mut node_addrs = HashMap::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        if let Some(endpoint_node_addr) = peer.endpoint_node_addr {
            node_addrs.entry(endpoint_node_addr).or_insert(peer_index);
        }
    }
    node_addrs
}

fn exact_route_peer_index(peers: &[FipsMeshPeerRuntime]) -> HashMap<IpAddr, ExactRouteMatch> {
    let mut index = HashMap::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        for route in &peer.routes {
            let Some(exact_ip) = route.exact_ip() else {
                continue;
            };
            index
                .entry(exact_ip)
                .and_modify(|entry| {
                    if let ExactRouteMatch::Peer(existing_index) = *entry
                        && same_participant(&peers[existing_index], peer)
                    {
                        return;
                    }
                    *entry = ExactRouteMatch::Ambiguous;
                })
                .or_insert(ExactRouteMatch::Peer(peer_index));
        }
    }
    index
}

fn prefix_route_peer_indexes(
    peers: &[FipsMeshPeerRuntime],
) -> (Vec<IndexedIpRoute>, Vec<IndexedIpRoute>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        for &route in &peer.routes {
            if route.exact_ip().is_some() {
                continue;
            }
            let indexed = IndexedIpRoute { peer_index, route };
            match route.network {
                IpAddr::V4(_) => v4.push(indexed),
                IpAddr::V6(_) => v6.push(indexed),
            }
        }
    }

    sort_prefix_route_peer_index(&mut v4);
    sort_prefix_route_peer_index(&mut v6);
    (v4, v6)
}

fn sort_prefix_route_peer_index(routes: &mut [IndexedIpRoute]) {
    routes.sort_by(|left, right| {
        right
            .route
            .prefix_len
            .cmp(&left.route.prefix_len)
            .then_with(|| left.peer_index.cmp(&right.peer_index))
    });
}

fn endpoint_node_addr_from_pubkey_bytes(pubkey: [u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(pubkey);
    let mut node_addr = [0u8; 16];
    node_addr.copy_from_slice(&digest[..16]);
    node_addr
}

fn runtime_participant_pubkey(value: &str) -> (Option<[u8; 32]>, String) {
    if let Some(pubkey) = parse_nostr_pubkey_bytes(value) {
        return (Some(pubkey), hex::encode(pubkey));
    }
    (None, value.trim().to_string())
}

fn same_participant(left: &FipsMeshPeerRuntime, right: &FipsMeshPeerRuntime) -> bool {
    match (left.participant_pubkey, right.participant_pubkey) {
        (Some(left), Some(right)) => left == right,
        _ => left.participant_pubkey_hex == right.participant_pubkey_hex,
    }
}

fn parse_nostr_pubkey_bytes(value: &str) -> Option<[u8; 32]> {
    PublicKey::parse(value.trim())
        .ok()
        .map(|pubkey| *pubkey.as_bytes())
}

fn npub_for_pubkey_hex(pubkey_hex: &str) -> Result<String> {
    PublicKey::from_hex(pubkey_hex)
        .context("invalid endpoint public key")?
        .to_bech32()
        .context("failed to encode endpoint npub")
}

fn npub_for_pubkey_bytes(pubkey: &[u8; 32]) -> Result<String> {
    PublicKey::from_byte_array(*pubkey)
        .to_bech32()
        .context("failed to encode endpoint npub")
}

impl IpRoute {
    fn parse(value: &str) -> Option<Self> {
        let (addr, prefix_len) = value.trim().split_once('/')?;
        let network = addr.trim().parse::<IpAddr>().ok()?;
        let prefix_len = prefix_len.trim().parse::<u8>().ok()?;

        match network {
            IpAddr::V4(ip) if prefix_len <= 32 => Some(Self {
                network: IpAddr::V4(mask_ipv4(ip, prefix_len)),
                prefix_len,
            }),
            IpAddr::V6(ip) if prefix_len <= 128 => Some(Self {
                network: IpAddr::V6(mask_ipv6(ip, prefix_len)),
                prefix_len,
            }),
            _ => None,
        }
    }

    fn matches(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => mask_ipv4(ip, self.prefix_len) == network,
            (IpAddr::V6(network), IpAddr::V6(ip)) => mask_ipv6(ip, self.prefix_len) == network,
            _ => false,
        }
    }

    fn exact_ip(self) -> Option<IpAddr> {
        match self.network {
            IpAddr::V4(ip) if self.prefix_len == 32 => Some(IpAddr::V4(ip)),
            IpAddr::V6(ip) if self.prefix_len == 128 => Some(IpAddr::V6(ip)),
            _ => None,
        }
    }

    fn is_default_route(self) -> bool {
        matches!(
            (self.network, self.prefix_len),
            (IpAddr::V4(ip), 0) if ip == Ipv4Addr::UNSPECIFIED
        ) || matches!(
            (self.network, self.prefix_len),
            (IpAddr::V6(ip), 0) if ip == Ipv6Addr::UNSPECIFIED
        )
    }
}

pub fn packet_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            let ihl = first & 0x0f;
            if packet.len() < 20 || ihl < 5 || packet.len() < usize::from(ihl) * 4 {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
            ))
        }
        6 => {
            let mut source = [0_u8; 16];
            let mut destination = [0_u8; 16];
            source.copy_from_slice(packet.get(8..24)?);
            destination.copy_from_slice(packet.get(24..40)?);
            Some((
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
            ))
        }
        _ => None,
    }
}

fn mask_ipv4(ip: Ipv4Addr, bits: u8) -> Ipv4Addr {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_ipv6(ip: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    Ipv6Addr::from(u128::from_be_bytes(ip.octets()) & mask)
}
