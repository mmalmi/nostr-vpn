struct MobileDnsQuery<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &'a [u8],
}

enum MobileDnsPacketAction {
    Respond(Vec<u8>),
    ForwardViaExit,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MobileWireGuardDnsFlow {
    server: Ipv4Addr,
    protocol: u8,
    client_port: u16,
}

struct MobileExitDnsNat {
    local_dns_server: Ipv4Addr,
    servers: Vec<Ipv4Addr>,
    next_server: AtomicUsize,
    flows: Mutex<HashSet<MobileWireGuardDnsFlow>>,
}

impl MobileExitDnsNat {
    fn new(local_dns_server: Ipv4Addr, servers: Vec<Ipv4Addr>) -> Option<Self> {
        (!servers.is_empty()).then_some(Self {
            local_dns_server,
            servers,
            next_server: AtomicUsize::new(0),
            flows: Mutex::new(HashSet::new()),
        })
    }

    fn rewrite_query(&self, packet: &mut [u8]) -> Option<Ipv4Addr> {
        let (source, destination, source_port, destination_port, protocol) =
            ipv4_transport_endpoints(packet)?;
        let _ = source;
        if destination != self.local_dns_server || destination_port != 53 {
            return None;
        }
        let index = self.next_server.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        let server = self.servers[index];
        self.flows.lock().ok()?.insert(MobileWireGuardDnsFlow {
            server,
            protocol,
            client_port: source_port,
        });
        rewrite_ipv4_destination(packet, self.local_dns_server, server);
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(packet);
        Some(server)
    }

    fn rewrite_response(&self, packet: &mut [u8]) -> bool {
        let Some((source, _, source_port, destination_port, protocol)) =
            ipv4_transport_endpoints(packet)
        else {
            return false;
        };
        if source_port != 53 {
            return false;
        }
        let flow = MobileWireGuardDnsFlow {
            server: source,
            protocol,
            client_port: destination_port,
        };
        let matched = self.flows.lock().is_ok_and(|mut flows| {
            if protocol == 17 {
                flows.remove(&flow)
            } else {
                flows.contains(&flow)
            }
        });
        if !matched {
            return false;
        }
        rewrite_ipv4_source(packet, source, self.local_dns_server);
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(packet);
        true
    }
}

async fn mobile_dns_packet_action(
    packet: &[u8],
    app_config: &Arc<RwLock<AppConfig>>,
    secure_dns: Option<&dyn SecureDnsLookup>,
    magic_dns_server: Ipv4Addr,
    forward_public_via_wireguard: bool,
) -> Option<MobileDnsPacketAction> {
    let query = parse_mobile_magic_dns_query(packet, magic_dns_server)?;
    let response = {
        let app = app_config.read().ok()?;
        let records = build_magic_dns_records(&app);
        build_magic_dns_response_if_handled(query.payload, &records)
    };
    let response = match response {
        Some(response) => response,
        None if forward_public_via_wireguard => {
            return Some(MobileDnsPacketAction::ForwardViaExit);
        }
        None => match secure_dns {
            Some(resolver) => match resolver.resolve(query.payload).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(%error, "mobile secure DNS resolution failed closed");
                    build_servfail_response(query.payload)?
                }
            },
            None => build_magic_dns_server_failure_response(query.payload)?,
        },
    };
    build_mobile_dns_response_packet(&query, &response).map(MobileDnsPacketAction::Respond)
}

#[cfg(test)]
async fn mobile_magic_dns_response_packet(
    packet: &[u8],
    app_config: &Arc<RwLock<AppConfig>>,
    secure_dns: Option<&dyn SecureDnsLookup>,
    magic_dns_server: Ipv4Addr,
) -> Option<Vec<u8>> {
    match mobile_dns_packet_action(
        packet,
        app_config,
        secure_dns,
        magic_dns_server,
        false,
    )
    .await?
    {
        MobileDnsPacketAction::Respond(response) => Some(response),
        MobileDnsPacketAction::ForwardViaExit => None,
    }
}

fn ipv4_transport_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, u8)> {
    if packet.len() < 24 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 4 || !matches!(packet[9], 6 | 17) {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 4 || packet.len() < total_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    if fragment != 0 {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
        packet[9],
    ))
}

fn parse_mobile_magic_dns_query(
    packet: &[u8],
    magic_dns_server: Ipv4Addr,
) -> Option<MobileDnsQuery<'_>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != 17 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff;
    if fragment != 0 {
        return None;
    }
    let magic_dns_octets = magic_dns_server.octets();
    if &packet[16..20] != magic_dns_octets.as_slice() {
        return None;
    }
    let destination = magic_dns_server;
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let udp = header_len;
    let source_port = u16::from_be_bytes([packet[udp], packet[udp + 1]]);
    let destination_port = u16::from_be_bytes([packet[udp + 2], packet[udp + 3]]);
    if destination_port != 53 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([packet[udp + 4], packet[udp + 5]]));
    if udp_len < 8 || udp + udp_len > total_len {
        return None;
    }
    Some(MobileDnsQuery {
        source,
        destination,
        source_port,
        destination_port,
        payload: &packet[udp + 8..udp + udp_len],
    })
}

fn build_mobile_dns_response_packet(
    query: &MobileDnsQuery<'_>,
    dns_response: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8_usize.checked_add(dns_response.len())?;
    let total_len = 20_usize.checked_add(udp_len)?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    let total_len_u16 = u16::try_from(total_len).ok()?;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&query.destination.octets());
    packet[16..20].copy_from_slice(&query.source.octets());
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&query.destination_port.to_be_bytes());
    packet[22..24].copy_from_slice(&query.source_port.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[28..].copy_from_slice(dns_response);
    Some(packet)
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = sum.wrapping_add(u32::from(value));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded IPv4 checksum fits in u16")
}

fn ipv4_is_lan_endpoint_hint(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ipv4_is_mesh_tunnel_ip(ip)
}

fn ipv4_is_mesh_tunnel_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10 && octets[1] == 44
}

#[cfg(debug_assertions)]
pub(crate) fn mobile_debug_log(message: impl AsRef<str>) {
    let dir = std::env::temp_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("nvpn-mobile-debug.log");
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "{:?} {}", SystemTime::now(), message.as_ref());
}

#[cfg(not(debug_assertions))]
pub(crate) fn mobile_debug_log(_message: impl AsRef<str>) {}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    strip_cidr(value.trim()).parse().ok()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn empty_config() -> MobileTunnelConfig {
    MobileTunnelConfig {
        config_path: String::new(),
        app_config_toml: String::new(),
        identity_nsec: String::new(),
        node_name: String::new(),
        network_id: String::new(),
        join_secret: String::new(),
        local_address: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        mtu: DEFAULT_MOBILE_MTU,
        peers: Vec::new(),
        peer_hints: HashMap::new(),
        bootstrap_peers: HashMap::new(),
        route_targets: Vec::new(),
        nostr_relays: Vec::new(),
        websocket_seed_urls: Vec::new(),
        stun_servers: Vec::new(),
        share_local_candidates: false,
        connect_to_non_roster_fips_peers: false,
        nostr_discovery_enabled: true,
        webrtc_enabled: false,
        excluded_routes: Vec::new(),
        dns_servers: Vec::new(),
        magic_dns_server: String::new(),
        dns_match_domains: Vec::new(),
        exit_dns: ExitDnsConfig::default(),
        wireguard_exit: None,
        join_requests_enabled: false,
        device_approval_pending: false,
        local_identity_confirmation_pending: false,
        pending_join_network_id: String::new(),
        pending_join_request_recipient: String::new(),
        pending_join_secret: String::new(),
        pending_join_requested_at: 0,
        error: String::new(),
    }
}
