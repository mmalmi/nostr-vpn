use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

const MAX_TRACKED_EXIT_FLOWS: usize = 16_384;
const EXIT_TCP_IDLE: Duration = Duration::from_secs(5 * 24 * 60 * 60);
const EXIT_UDP_IDLE: Duration = Duration::from_secs(3 * 60);
const EXIT_ICMP_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct ExitFlowEntry {
    seen: Instant,
    generation: u64,
}

#[derive(Debug, Default)]
pub struct ExitFlowFilter {
    flows: HashMap<ExitFlowKey, ExitFlowEntry>,
    order: VecDeque<(ExitFlowKey, u64)>,
    next_generation: u64,
}

impl ExitFlowFilter {
    pub fn note_outbound(&mut self, peer: [u8; 16], packet: &[u8]) {
        if let Some(key) = Self::outbound_key(peer, packet) {
            self.note_outbound_key(key, Instant::now());
        }
    }

    pub fn admits_inbound(&mut self, peer: [u8; 16], packet: &[u8]) -> bool {
        Self::inbound_key(peer, packet)
            .is_some_and(|key| self.admits_inbound_key(key, Instant::now()))
    }

    pub(crate) fn outbound_key(peer: [u8; 16], packet: &[u8]) -> Option<ExitFlowKey> {
        outbound_exit_flow_key(peer, packet, false)
    }

    pub(crate) fn inbound_key(peer: [u8; 16], packet: &[u8]) -> Option<ExitFlowKey> {
        let transport = complete_ip_transport(packet)?;
        if !is_public_exit_source(transport.source_addr) {
            return None;
        }
        inbound_exit_flow_key(peer, packet, transport)
    }

    pub(crate) fn note_outbound_key(&mut self, key: ExitFlowKey, now: Instant) {
        if let Some(entry) = self.flows.get_mut(&key) {
            entry.seen = now;
            return;
        }
        while self.flows.len() >= MAX_TRACKED_EXIT_FLOWS {
            let Some((oldest, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .flows
                .get(&oldest)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.flows.remove(&oldest);
            }
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.flows.insert(
            key,
            ExitFlowEntry {
                seen: now,
                generation,
            },
        );
        self.order.push_back((key, generation));
        if self.order.len() > MAX_TRACKED_EXIT_FLOWS * 2 {
            self.order.retain(|(candidate, generation)| {
                self.flows
                    .get(candidate)
                    .is_some_and(|entry| entry.generation == *generation)
            });
        }
    }

    pub(crate) fn admits_inbound_key(&mut self, key: ExitFlowKey, now: Instant) -> bool {
        let timeout = exit_flow_timeout(key.protocol);
        let Some(entry) = self.flows.get_mut(&key) else {
            return false;
        };
        if now.saturating_duration_since(entry.seen) > timeout {
            self.flows.remove(&key);
            return false;
        }
        entry.seen = now;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ExitFlowKey {
    peer: [u8; 16],
    local_addr: IpAddressKey,
    remote_addr: IpAddressKey,
    local_port: u16,
    remote_port: u16,
    protocol: u8,
    token: u32,
}

impl ExitFlowKey {
    fn new(
        peer: [u8; 16],
        transport: ParsedTransport,
        ports: (u16, u16),
        token: u32,
        inbound: bool,
    ) -> Self {
        let (local_addr, remote_addr, local_port, remote_port) = if inbound {
            (
                transport.destination_addr,
                transport.source_addr,
                ports.1,
                ports.0,
            )
        } else {
            (
                transport.source_addr,
                transport.destination_addr,
                ports.0,
                ports.1,
            )
        };
        Self {
            peer,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            protocol: transport.protocol,
            token,
        }
    }
}

fn outbound_exit_flow_key(peer: [u8; 16], packet: &[u8], quoted: bool) -> Option<ExitFlowKey> {
    let transport = if quoted {
        parse_ip_transport(packet)?
    } else {
        complete_ip_transport(packet)?
    };
    match transport.protocol {
        protocol @ (IPPROTO_TCP | IPPROTO_UDP) => {
            let ports = if quoted {
                parse_transport_ports(packet, transport)?
            } else if protocol == IPPROTO_TCP {
                let tcp = parse_tcp_at(packet, transport)?;
                (tcp.source_port, tcp.destination_port)
            } else {
                let udp = parse_udp_at(packet, transport)?;
                (udp.source_port, udp.destination_port)
            };
            Some(ExitFlowKey::new(peer, transport, ports, 0, false))
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let icmp = packet.get(transport.header_offset..transport.payload_end)?;
            let request_type = if transport.protocol == IPPROTO_ICMP {
                8
            } else {
                128
            };
            if icmp.len() < 8 || icmp[0] != request_type || icmp[1] != 0 {
                return None;
            }
            Some(ExitFlowKey::new(
                peer,
                transport,
                (0, 0),
                u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
                false,
            ))
        }
        _ => None,
    }
}

fn inbound_exit_flow_key(
    peer: [u8; 16],
    packet: &[u8],
    transport: ParsedTransport,
) -> Option<ExitFlowKey> {
    match transport.protocol {
        protocol @ (IPPROTO_TCP | IPPROTO_UDP) => {
            let ports = if protocol == IPPROTO_TCP {
                let tcp = parse_tcp_at(packet, transport)?;
                if tcp.flags & 0x02 != 0 && tcp.flags & 0x10 == 0 {
                    return None;
                }
                (tcp.source_port, tcp.destination_port)
            } else {
                let udp = parse_udp_at(packet, transport)?;
                (udp.source_port, udp.destination_port)
            };
            Some(ExitFlowKey::new(peer, transport, ports, 0, true))
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let icmp = packet.get(transport.header_offset..transport.payload_end)?;
            if icmp.len() < 8 {
                return None;
            }
            let echo_reply = (transport.protocol == IPPROTO_ICMP && icmp[0] == 0)
                || (transport.protocol == IPPROTO_ICMPV6 && icmp[0] == 129);
            if echo_reply && icmp[1] == 0 {
                return Some(ExitFlowKey::new(
                    peer,
                    transport,
                    (0, 0),
                    u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
                    true,
                ));
            }
            let is_error = match transport.protocol {
                IPPROTO_ICMP => matches!(icmp[0], 3 | 11 | 12),
                IPPROTO_ICMPV6 => matches!(icmp[0], 1..=4),
                _ => false,
            };
            if !is_error {
                return None;
            }
            let quoted = icmp.get(8..)?;
            let key = outbound_exit_flow_key(peer, quoted, true)?;
            (key.local_addr == transport.destination_addr).then_some(key)
        }
        _ => None,
    }
}

fn exit_flow_timeout(protocol: u8) -> Duration {
    match protocol {
        IPPROTO_TCP => EXIT_TCP_IDLE,
        IPPROTO_UDP => EXIT_UDP_IDLE,
        _ => EXIT_ICMP_IDLE,
    }
}

fn complete_ip_transport(packet: &[u8]) -> Option<ParsedTransport> {
    let transport = parse_ip_transport(packet)?;
    (transport.payload_end <= packet.len() && ip_packet_len(packet)? <= packet.len())
        .then_some(transport)
}

fn ip_packet_len(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 => Some(usize::from(u16::from_be_bytes([
            *packet.get(2)?,
            *packet.get(3)?,
        ]))),
        6 => 40_usize.checked_add(usize::from(u16::from_be_bytes([
            *packet.get(4)?,
            *packet.get(5)?,
        ]))),
        _ => None,
    }
}

fn parse_transport_ports(packet: &[u8], transport: ParsedTransport) -> Option<(u16, u16)> {
    let header = packet.get(transport.header_offset..)?;
    Some((
        u16::from_be_bytes([*header.first()?, *header.get(1)?]),
        u16::from_be_bytes([*header.get(2)?, *header.get(3)?]),
    ))
}

fn is_public_exit_source(address: IpAddressKey) -> bool {
    match address {
        IpAddressKey::V4([a, b, c, _]) => {
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && matches!((b, c), (0, 0) | (168, _))))
        }
        IpAddressKey::V6(bytes) => {
            bytes != [0; 16]
                && bytes != Ipv6Addr::LOCALHOST.octets()
                && bytes[0] != 0xff
                && bytes[0] != 0xfe
                && bytes[0] & 0xfe != 0xfc
                && bytes[..12] != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        }
    }
}

pub(crate) fn is_public_exit_destination(address: IpAddr) -> bool {
    if let IpAddr::V6(ip) = address {
        let bytes = ip.octets();
        // Do not let IPv4 translation/tunneling turn a public-looking IPv6
        // destination into a private IPv4 destination at the seller's uplink.
        if bytes[..12] == [0; 12] || bytes[..6] == [0, 0x64, 0xff, 0x9b, 0, 1] {
            return false;
        }
        let embedded = if bytes[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
            Some([bytes[12], bytes[13], bytes[14], bytes[15]])
        } else if bytes[..2] == [0x20, 0x02] {
            Some([bytes[2], bytes[3], bytes[4], bytes[5]])
        } else {
            None
        };
        if embedded.is_some_and(|ip| !is_public_exit_source(IpAddressKey::V4(ip))) {
            return false;
        }
    }
    is_public_exit_source(match address {
        IpAddr::V4(ip) => IpAddressKey::V4(ip.octets()),
        IpAddr::V6(ip) => IpAddressKey::V6(ip.octets()),
    })
}
