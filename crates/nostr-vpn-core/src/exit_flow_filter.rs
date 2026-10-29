use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

const MAX_TRACKED_EXIT_FLOWS: usize = 16_384;
const EXIT_TCP_IDLE: Duration = Duration::from_secs(5 * 24 * 60 * 60);
const EXIT_UDP_IDLE: Duration = Duration::from_secs(3 * 60);
const EXIT_ICMP_IDLE: Duration = Duration::from_secs(30);
const EXIT_FLOW_REFRESH_GROUPS: usize = 3;
const NO_EXIT_FLOW_SLOT: usize = usize::MAX;

// One slab slot per tracked flow. `older` and `newer` link the slot into its
// refresh group's list: toward `older` sit flows refreshed earlier, toward
// `newer` flows refreshed later. Refresh times are only ever written from the
// monotonic clock, so every list stays sorted by last refresh and its front is
// the least recently refreshed flow of the group.
#[derive(Debug)]
struct ExitFlowNode {
    key: ExitFlowKey,
    seen: Instant,
    older: usize,
    newer: usize,
}

#[derive(Debug)]
pub struct ExitFlowFilter {
    flows: HashMap<ExitFlowKey, usize>,
    nodes: Vec<ExitFlowNode>,
    free_nodes: Vec<usize>,
    group_fronts: [usize; EXIT_FLOW_REFRESH_GROUPS],
    group_backs: [usize; EXIT_FLOW_REFRESH_GROUPS],
}

impl Default for ExitFlowFilter {
    fn default() -> Self {
        Self {
            flows: HashMap::default(),
            nodes: Vec::default(),
            free_nodes: Vec::default(),
            group_fronts: [NO_EXIT_FLOW_SLOT; EXIT_FLOW_REFRESH_GROUPS],
            group_backs: [NO_EXIT_FLOW_SLOT; EXIT_FLOW_REFRESH_GROUPS],
        }
    }
}

impl ExitFlowFilter {
    pub fn note_outbound(&mut self, peer: [u8; 16], packet: &[u8]) {
        let Some(key) = outbound_exit_flow_key(peer, packet, false) else {
            return;
        };
        let now = Instant::now();
        if let Some(&slot) = self.flows.get(&key) {
            self.refresh_flow(slot, now);
            return;
        }
        if self.flows.len() >= MAX_TRACKED_EXIT_FLOWS {
            self.evict_one_flow(now);
        }
        let slot = self.alloc_flow(key, now);
        let group = exit_flow_group(key.protocol);
        self.link_newer_end(group, slot);
        self.flows.insert(key, slot);
    }

    pub fn admits_inbound(&mut self, peer: [u8; 16], packet: &[u8]) -> bool {
        let Some(transport) = complete_ip_transport(packet) else {
            return false;
        };
        if !is_public_exit_source(transport.source_addr) {
            return false;
        }
        let Some(key) = inbound_exit_flow_key(peer, packet, transport) else {
            return false;
        };
        let timeout = exit_flow_timeout(key.protocol);
        let now = Instant::now();
        let Some(&slot) = self.flows.get(&key) else {
            return false;
        };
        if now.saturating_duration_since(self.nodes[slot].seen) > timeout {
            self.free_flow(slot);
            return false;
        }
        self.refresh_flow(slot, now);
        true
    }

    // Evict one flow in O(1): a flow past its idle timeout when any group
    // front is idle (the most idle front first), otherwise the least recently
    // refreshed flow overall. Group lists are sorted by last refresh, so the
    // three fronts are the only candidates the idle-before-active policy can
    // prefer and no scan of the tracked table is ever needed.
    fn evict_one_flow(&mut self, now: Instant) {
        let mut idle: Option<usize> = None;
        let mut least_recent: Option<usize> = None;
        for group in 0..EXIT_FLOW_REFRESH_GROUPS {
            let front = self.group_fronts[group];
            if front == NO_EXIT_FLOW_SLOT {
                continue;
            }
            let seen = self.nodes[front].seen;
            if least_recent.is_none_or(|slot| seen < self.nodes[slot].seen) {
                least_recent = Some(front);
            }
            let timeout = exit_flow_timeout(self.nodes[front].key.protocol);
            if now.saturating_duration_since(seen) > timeout
                && idle.is_none_or(|slot| seen < self.nodes[slot].seen)
            {
                idle = Some(front);
            }
        }
        if let Some(slot) = idle.or(least_recent) {
            self.free_flow(slot);
        }
    }

    // Refreshing moves the flow to the newer end of its group, keeping each
    // list ordered by last refresh.
    fn refresh_flow(&mut self, slot: usize, now: Instant) {
        self.unlink_flow(slot);
        self.nodes[slot].seen = now;
        let group = exit_flow_group(self.nodes[slot].key.protocol);
        self.link_newer_end(group, slot);
    }

    fn unlink_flow(&mut self, slot: usize) {
        let (older, newer, group) = {
            let node = &self.nodes[slot];
            (node.older, node.newer, exit_flow_group(node.key.protocol))
        };
        match older {
            NO_EXIT_FLOW_SLOT => self.group_fronts[group] = newer,
            front_older => self.nodes[front_older].newer = newer,
        }
        match newer {
            NO_EXIT_FLOW_SLOT => self.group_backs[group] = older,
            back_newer => self.nodes[back_newer].older = older,
        }
        let node = &mut self.nodes[slot];
        node.older = NO_EXIT_FLOW_SLOT;
        node.newer = NO_EXIT_FLOW_SLOT;
    }

    fn link_newer_end(&mut self, group: usize, slot: usize) {
        let older = self.group_backs[group];
        self.nodes[slot].older = older;
        if older == NO_EXIT_FLOW_SLOT {
            self.group_fronts[group] = slot;
        } else {
            self.nodes[older].newer = slot;
        }
        self.group_backs[group] = slot;
    }

    fn alloc_flow(&mut self, key: ExitFlowKey, seen: Instant) -> usize {
        let node = ExitFlowNode {
            key,
            seen,
            older: NO_EXIT_FLOW_SLOT,
            newer: NO_EXIT_FLOW_SLOT,
        };
        match self.free_nodes.pop() {
            Some(slot) => {
                self.nodes[slot] = node;
                slot
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        }
    }

    fn free_flow(&mut self, slot: usize) {
        self.unlink_flow(slot);
        let key = self.nodes[slot].key;
        self.flows.remove(&key);
        self.free_nodes.push(slot);
    }
}

// Match the grouping of exit_flow_timeout: TCP, UDP, and the shared ICMP
// idle timeout.
fn exit_flow_group(protocol: u8) -> usize {
    match protocol {
        IPPROTO_TCP => 0,
        IPPROTO_UDP => 1,
        _ => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ExitFlowKey {
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
