use crate::paid_routes::PaidRouteUsage;
use std::collections::{HashMap, VecDeque};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const IPV6_EXTENSION_HOP_BY_HOP: u8 = 0;
const IPV6_EXTENSION_ROUTING: u8 = 43;
const IPV6_EXTENSION_FRAGMENT: u8 = 44;
const IPV6_EXTENSION_AUTH: u8 = 51;
const IPV6_EXTENSION_DESTINATION: u8 = 60;
const IPV6_EXTENSION_MOBILITY: u8 = 135;
const IPV6_EXTENSION_HIP: u8 = 139;
const IPV6_EXTENSION_SHIM6: u8 = 140;
const MAX_TRACKED_TCP_FLOWS: usize = 4096;
const MAX_PENDING_TCP_PACKET_ENDS: usize = 8192;
const MAX_TRACKED_UDP_FLOWS: usize = 4096;
const UDP_FLOW_IDLE_OBSERVATIONS: u64 = 262_144;
include!("exit_flow_filter.rs");

#[derive(Debug, Default)]
pub struct PaidRouteTrafficAccountant {
    tcp_flows: HashMap<TcpFlowKey, TcpAckState>,
    flow_order: VecDeque<TcpFlowKey>,
    udp_flows: HashMap<UdpFlowKey, u64>,
    udp_flow_order: VecDeque<UdpFlowKey>,
    observation_clock: u64,
}

impl PaidRouteTrafficAccountant {
    pub fn record_outbound_packet(&mut self, packet: &[u8]) -> PaidRouteUsage {
        let now = self.next_observation();
        let len = packet.len() as u64;
        let mut delta = PaidRouteUsage {
            tx_bytes: len,
            tx_packets: 1,
            billable_bytes: len,
            ..PaidRouteUsage::default()
        };

        let Some(transport) = parse_ip_transport(packet) else {
            return delta;
        };
        match transport.protocol {
            IPPROTO_UDP => {
                if let Some(udp) = parse_udp_at(packet, transport) {
                    self.note_outbound_udp_flow(UdpFlowKey::from_outbound_udp(&udp), now);
                }
            }
            IPPROTO_TCP => {
                if let Some(tcp) = parse_tcp_at(packet, transport) {
                    let key = TcpFlowKey::from_outbound_tcp(&tcp);
                    if tcp.flags & 0x02 != 0 && !tcp.ack {
                        self.tcp_flow(key).note_buyer_syn(tcp.sequence_number);
                    }
                    if tcp.ack
                        && let Some(flow) = self.tcp_flows.get_mut(&key)
                    {
                        let acked = flow.apply_buyer_ack(tcp.ack_number);
                        delta.billable_bytes = delta.billable_bytes.saturating_add(acked.bytes);
                    }
                }
            }
            _ => {}
        }
        delta
    }

    pub fn record_inbound_packet(&mut self, packet: &[u8]) -> PaidRouteUsage {
        let now = self.next_observation();
        let len = packet.len() as u64;
        let mut delta = PaidRouteUsage {
            rx_bytes: len,
            rx_packets: 1,
            ..PaidRouteUsage::default()
        };

        let Some(transport) = parse_ip_transport(packet) else {
            return delta;
        };
        match transport.protocol {
            IPPROTO_UDP => {
                if let Some(udp) = parse_udp_at(packet, transport)
                    && self
                        .inbound_udp_matches_recent_flow(&UdpFlowKey::from_inbound_udp(&udp), now)
                {
                    delta.billable_bytes = udp.packet_len as u64;
                }
            }
            IPPROTO_TCP => {
                if let Some(tcp) = parse_tcp_at(packet, transport) {
                    let key = TcpFlowKey::from_inbound_tcp(&tcp);
                    let syn = tcp.flags & 0x02 != 0;
                    if syn {
                        self.tcp_flow(key).note_peer_syn(tcp.sequence_number);
                    }
                    if tcp.payload_len > 0 {
                        self.tcp_flow(key).note_inbound_payload(
                            tcp.sequence_number.wrapping_add(u32::from(syn)),
                            tcp.payload_len,
                        );
                    }
                }
            }
            _ => {}
        }
        delta
    }

    fn next_observation(&mut self) -> u64 {
        self.observation_clock = self.observation_clock.wrapping_add(1);
        self.observation_clock
    }

    fn tcp_flow(&mut self, key: TcpFlowKey) -> &mut TcpAckState {
        if !self.tcp_flows.contains_key(&key) {
            self.flow_order.push_back(key);
            while self.tcp_flows.len() >= MAX_TRACKED_TCP_FLOWS {
                let Some(oldest) = self.flow_order.pop_front() else {
                    break;
                };
                self.tcp_flows.remove(&oldest);
            }
        }
        self.tcp_flows.entry(key).or_default()
    }

    fn note_outbound_udp_flow(&mut self, key: UdpFlowKey, now: u64) {
        if !self.udp_flows.contains_key(&key) {
            self.udp_flow_order.push_back(key);
            while self.udp_flows.len() >= MAX_TRACKED_UDP_FLOWS {
                let Some(oldest) = self.udp_flow_order.pop_front() else {
                    break;
                };
                self.udp_flows.remove(&oldest);
            }
        }
        self.udp_flows.insert(key, now);
    }

    fn inbound_udp_matches_recent_flow(&mut self, key: &UdpFlowKey, now: u64) -> bool {
        let Some(last_seen) = self.udp_flows.get(key).copied() else {
            return false;
        };
        if now.wrapping_sub(last_seen) > UDP_FLOW_IDLE_OBSERVATIONS {
            self.udp_flows.remove(key);
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AckedTcpUsage {
    bytes: u64,
    packets: u64,
}

#[derive(Debug, Default)]
struct TcpAckState {
    buyer_syn_seq: Option<u32>,
    peer_syn_seq: Option<u32>,
    first_observed_seq: Option<u32>,
    observed_end_seq: Option<u32>,
    billed_ack_seq: Option<u32>,
    pending_packet_ends: VecDeque<u32>,
}

impl TcpAckState {
    fn note_buyer_syn(&mut self, sequence_number: u32) {
        if self.buyer_syn_seq != Some(sequence_number) {
            // A reused address/port tuple has a new sequence space. Carrying
            // its old watermark forward can bill a random ISN gap as gigabytes.
            *self = Self {
                buyer_syn_seq: Some(sequence_number),
                ..Self::default()
            };
        }
    }

    fn note_peer_syn(&mut self, sequence_number: u32) {
        if self.peer_syn_seq != Some(sequence_number) {
            *self = Self {
                buyer_syn_seq: self.buyer_syn_seq,
                peer_syn_seq: Some(sequence_number),
                ..Self::default()
            };
        }
    }

    fn note_inbound_payload(&mut self, sequence_number: u32, payload_len: usize) {
        let payload_len = payload_len.min(u32::MAX as usize) as u32;
        if payload_len == 0 {
            return;
        }
        let end_seq = sequence_number.wrapping_add(payload_len);
        match self.observed_end_seq {
            None => {
                self.first_observed_seq = Some(sequence_number);
                self.observed_end_seq = Some(end_seq);
                self.push_pending_packet_end(end_seq);
            }
            Some(observed_end) if seq_after(end_seq, observed_end) => {
                self.observed_end_seq = Some(end_seq);
                self.push_pending_packet_end(end_seq);
            }
            _ => {}
        }
    }

    fn apply_buyer_ack(&mut self, ack_seq: u32) -> AckedTcpUsage {
        let Some(observed_end) = self.observed_end_seq else {
            return AckedTcpUsage {
                bytes: 0,
                packets: 0,
            };
        };
        let base = self
            .billed_ack_seq
            .or(self.first_observed_seq)
            .unwrap_or(observed_end);
        let bill_until = if seq_after(ack_seq, observed_end) {
            observed_end
        } else {
            ack_seq
        };
        if !seq_after(bill_until, base) {
            return AckedTcpUsage {
                bytes: 0,
                packets: 0,
            };
        }

        let bytes = bill_until.wrapping_sub(base) as u64;
        let mut packets = 0u64;
        self.pending_packet_ends.retain(|end_seq| {
            if seq_leq(*end_seq, bill_until) {
                if seq_after(*end_seq, base) {
                    packets = packets.saturating_add(1);
                }
                false
            } else {
                true
            }
        });
        self.billed_ack_seq = Some(bill_until);
        AckedTcpUsage { bytes, packets }
    }

    fn push_pending_packet_end(&mut self, end_seq: u32) {
        self.pending_packet_ends.push_back(end_seq);
        while self.pending_packet_ends.len() > MAX_PENDING_TCP_PACKET_ENDS {
            self.pending_packet_ends.pop_front();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    local_addr: IpAddressKey,
    remote_addr: IpAddressKey,
    local_port: u16,
    remote_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    local_addr: IpAddressKey,
    remote_addr: IpAddressKey,
    local_port: u16,
    remote_port: u16,
}

impl UdpFlowKey {
    fn from_outbound_udp(udp: &ParsedUdpPacket) -> Self {
        Self {
            local_addr: udp.source_addr,
            remote_addr: udp.destination_addr,
            local_port: udp.source_port,
            remote_port: udp.destination_port,
        }
    }

    fn from_inbound_udp(udp: &ParsedUdpPacket) -> Self {
        Self {
            local_addr: udp.destination_addr,
            remote_addr: udp.source_addr,
            local_port: udp.destination_port,
            remote_port: udp.source_port,
        }
    }
}

impl TcpFlowKey {
    fn from_outbound_tcp(tcp: &ParsedTcpPacket) -> Self {
        Self {
            local_addr: tcp.source_addr,
            remote_addr: tcp.destination_addr,
            local_port: tcp.source_port,
            remote_port: tcp.destination_port,
        }
    }

    fn from_inbound_tcp(tcp: &ParsedTcpPacket) -> Self {
        Self {
            local_addr: tcp.destination_addr,
            remote_addr: tcp.source_addr,
            local_port: tcp.destination_port,
            remote_port: tcp.source_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpAddressKey {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Clone, Copy)]
struct ParsedTcpPacket {
    source_addr: IpAddressKey,
    destination_addr: IpAddressKey,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    ack: bool,
    flags: u8,
    payload_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct ParsedUdpPacket {
    source_addr: IpAddressKey,
    destination_addr: IpAddressKey,
    source_port: u16,
    destination_port: u16,
    packet_len: usize,
}

fn parse_ip_transport(packet: &[u8]) -> Option<ParsedTransport> {
    let version = packet.first().copied()? >> 4;
    match version {
        4 => parse_ipv4_transport(packet),
        6 => parse_ipv6_transport(packet),
        _ => None,
    }
}

fn parse_udp_at(packet: &[u8], parsed: ParsedTransport) -> Option<ParsedUdpPacket> {
    let udp = packet.get(parsed.header_offset..parsed.payload_end)?;
    if udp.len() < 8 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let packet_len = parsed.header_offset.checked_add(udp_len)?;
    Some(ParsedUdpPacket {
        source_addr: parsed.source_addr,
        destination_addr: parsed.destination_addr,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        packet_len,
    })
}

#[derive(Clone, Copy)]
struct ParsedTransport {
    source_addr: IpAddressKey,
    destination_addr: IpAddressKey,
    protocol: u8,
    header_offset: usize,
    payload_end: usize,
}

fn parse_ipv4_transport(packet: &[u8]) -> Option<ParsedTransport> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let payload_end = total_len.min(packet.len());
    if payload_end < header_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    Some(ParsedTransport {
        source_addr: IpAddressKey::V4(packet[12..16].try_into().ok()?),
        destination_addr: IpAddressKey::V4(packet[16..20].try_into().ok()?),
        protocol: packet[9],
        header_offset: header_len,
        payload_end,
    })
}

fn parse_ipv6_transport(packet: &[u8]) -> Option<ParsedTransport> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let payload_end = 40usize.saturating_add(payload_len).min(packet.len());
    if payload_end < 40 {
        return None;
    }
    let source_addr = IpAddressKey::V6(packet[8..24].try_into().ok()?);
    let destination_addr = IpAddressKey::V6(packet[24..40].try_into().ok()?);
    let mut protocol = packet[6];
    let mut offset = 40usize;

    for _ in 0..8 {
        match protocol {
            IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6 => {
                return Some(ParsedTransport {
                    source_addr,
                    destination_addr,
                    protocol,
                    header_offset: offset,
                    payload_end,
                });
            }
            IPV6_EXTENSION_HOP_BY_HOP
            | IPV6_EXTENSION_ROUTING
            | IPV6_EXTENSION_DESTINATION
            | IPV6_EXTENSION_MOBILITY
            | IPV6_EXTENSION_HIP
            | IPV6_EXTENSION_SHIM6 => {
                if offset + 2 > payload_end {
                    return None;
                }
                let next = packet[offset];
                let header_len = (usize::from(packet[offset + 1]) + 1) * 8;
                offset = offset.checked_add(header_len)?;
                if offset > payload_end {
                    return None;
                }
                protocol = next;
            }
            IPV6_EXTENSION_AUTH => {
                if offset + 2 > payload_end {
                    return None;
                }
                let next = packet[offset];
                let header_len = (usize::from(packet[offset + 1]) + 2) * 4;
                offset = offset.checked_add(header_len)?;
                if offset > payload_end {
                    return None;
                }
                protocol = next;
            }
            IPV6_EXTENSION_FRAGMENT => return None,
            _ => return None,
        }
    }
    None
}

fn parse_tcp_at(packet: &[u8], transport: ParsedTransport) -> Option<ParsedTcpPacket> {
    let tcp = packet.get(transport.header_offset..transport.payload_end)?;
    if tcp.len() < 20 {
        return None;
    }
    let header_len = usize::from(tcp[12] >> 4) * 4;
    if header_len < 20 || header_len > tcp.len() {
        return None;
    }
    Some(ParsedTcpPacket {
        source_addr: transport.source_addr,
        destination_addr: transport.destination_addr,
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence_number: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack_number: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        ack: tcp[13] & 0x10 != 0,
        flags: tcp[13],
        payload_len: tcp.len().saturating_sub(header_len),
    })
}

fn seq_after(left: u32, right: u32) -> bool {
    left != right && left.wrapping_sub(right) < 0x8000_0000
}

fn seq_before(left: u32, right: u32) -> bool {
    left != right && right.wrapping_sub(left) < 0x8000_0000
}

fn seq_leq(left: u32, right: u32) -> bool {
    left == right || seq_before(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_udp_is_billable_immediately() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let packet = ipv4_udp_packet(60);

        let delta = accountant.record_outbound_packet(&packet);

        assert_eq!(delta.tx_bytes, 60);
        assert_eq!(delta.tx_packets, 1);
        assert_eq!(delta.billable_bytes, 60);
    }

    #[test]
    fn unmatched_inbound_udp_is_observed_but_not_billable() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let packet = ipv4_udp_packet_with([198, 51, 100, 1], [10, 8, 0, 2], 53, 12345, 60);

        let delta = accountant.record_inbound_packet(&packet);

        assert_eq!(delta.rx_bytes, 60);
        assert_eq!(delta.rx_packets, 1);
        assert_eq!(delta.billable_bytes, 0);
    }

    #[test]
    fn inbound_udp_matching_buyer_flow_is_billable() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let outbound = ipv4_udp_packet_with([10, 8, 0, 2], [198, 51, 100, 1], 12345, 53, 60);
        let inbound = ipv4_udp_packet_with([198, 51, 100, 1], [10, 8, 0, 2], 53, 12345, 84);

        accountant.record_outbound_packet(&outbound);
        let delta = accountant.record_inbound_packet(&inbound);

        assert_eq!(delta.rx_bytes, 84);
        assert_eq!(delta.rx_packets, 1);
        assert_eq!(delta.billable_bytes, 84);
    }

    #[test]
    fn inbound_udp_bills_ip_udp_length_not_trailing_buffer_junk() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let outbound = ipv4_udp_packet_with([10, 8, 0, 2], [198, 51, 100, 1], 12345, 53, 60);
        let mut inbound = ipv4_udp_packet_with([198, 51, 100, 1], [10, 8, 0, 2], 53, 12345, 84);
        inbound.extend_from_slice(&[0xaa; 32]);

        accountant.record_outbound_packet(&outbound);
        let delta = accountant.record_inbound_packet(&inbound);

        assert_eq!(delta.rx_bytes, 116);
        assert_eq!(delta.rx_packets, 1);
        assert_eq!(delta.billable_bytes, 84);
    }

    #[test]
    fn inbound_udp_with_invalid_udp_length_is_not_billable() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let outbound = ipv4_udp_packet_with([10, 8, 0, 2], [198, 51, 100, 1], 12345, 53, 60);
        let mut inbound = ipv4_udp_packet_with([198, 51, 100, 1], [10, 8, 0, 2], 53, 12345, 60);
        inbound[24..26].copy_from_slice(&41u16.to_be_bytes());

        accountant.record_outbound_packet(&outbound);
        let delta = accountant.record_inbound_packet(&inbound);

        assert_eq!(delta.rx_bytes, 60);
        assert_eq!(delta.rx_packets, 1);
        assert_eq!(delta.billable_bytes, 0);
    }

    #[test]
    fn inbound_tcp_data_is_billable_only_after_buyer_ack() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let inbound = ipv4_tcp_packet(TcpPacketSpec {
            src: [203, 0, 113, 10],
            dst: [10, 8, 0, 2],
            src_port: 443,
            dst_port: 55_000,
            seq: 10_000,
            ack: 1,
            flags: 0x18,
            payload_len: 1200,
        });
        let outbound_ack = ipv4_tcp_packet(TcpPacketSpec {
            src: [10, 8, 0, 2],
            dst: [203, 0, 113, 10],
            src_port: 55_000,
            dst_port: 443,
            seq: 1,
            ack: 11_200,
            flags: 0x10,
            payload_len: 0,
        });

        let inbound_delta = accountant.record_inbound_packet(&inbound);
        assert_eq!(inbound_delta.rx_bytes, inbound.len() as u64);
        assert_eq!(inbound_delta.billable_bytes, 0);

        let outbound_delta = accountant.record_outbound_packet(&outbound_ack);
        assert_eq!(
            outbound_delta.billable_bytes,
            outbound_ack.len() as u64 + 1200
        );
    }

    #[test]
    fn retransmitted_inbound_tcp_data_is_not_double_billed() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let inbound = ipv4_tcp_packet(TcpPacketSpec {
            src: [203, 0, 113, 10],
            dst: [10, 8, 0, 2],
            src_port: 443,
            dst_port: 55_000,
            seq: 10_000,
            ack: 1,
            flags: 0x18,
            payload_len: 1000,
        });
        let outbound_ack = ipv4_tcp_packet(TcpPacketSpec {
            src: [10, 8, 0, 2],
            dst: [203, 0, 113, 10],
            src_port: 55_000,
            dst_port: 443,
            seq: 1,
            ack: 11_000,
            flags: 0x10,
            payload_len: 0,
        });

        accountant.record_inbound_packet(&inbound);
        accountant.record_inbound_packet(&inbound);
        let first_ack = accountant.record_outbound_packet(&outbound_ack);
        let duplicate_ack = accountant.record_outbound_packet(&outbound_ack);

        assert_eq!(first_ack.billable_bytes, outbound_ack.len() as u64 + 1000);
        assert_eq!(duplicate_ack.billable_bytes, outbound_ack.len() as u64);
    }

    #[test]
    fn reused_tcp_ports_never_bill_sequence_number_gaps_as_traffic() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        for (index, server_seq) in [10_000u32, 1_000_000_000, 50, u32::MAX - 500, 9_000]
            .into_iter()
            .enumerate()
        {
            let syn = TcpPacketSpec {
                src: [10, 8, 0, 2],
                dst: [203, 0, 113, 10],
                src_port: 55_000,
                dst_port: 443,
                seq: 1 + index as u32,
                ack: 0,
                flags: 0x02,
                payload_len: 0,
            };
            // Also cover a missed client SYN: the server SYN/ACK alone must
            // distinguish a new connection from the previous use of this tuple.
            if index % 2 == 0 {
                accountant.record_outbound_packet(&ipv4_tcp_packet(syn));
            }
            let syn_ack = TcpPacketSpec {
                src: syn.dst,
                dst: syn.src,
                src_port: syn.dst_port,
                dst_port: syn.src_port,
                seq: server_seq,
                ack: syn.seq + 1,
                flags: 0x12,
                payload_len: 0,
            };
            accountant.record_inbound_packet(&ipv4_tcp_packet(syn_ack));
            let data = ipv4_tcp_packet(TcpPacketSpec {
                seq: server_seq.wrapping_add(1),
                flags: 0x18,
                payload_len: 1000,
                ..syn_ack
            });
            accountant.record_inbound_packet(&data);
            let ack = ipv4_tcp_packet(TcpPacketSpec {
                seq: syn.seq + 1,
                ack: server_seq.wrapping_add(1001),
                flags: 0x10,
                ..syn
            });
            assert_eq!(
                accountant.record_outbound_packet(&ack).billable_bytes,
                ack.len() as u64 + 1000,
                "only payload from this connection is billable"
            );
            // A retransmitted handshake must not erase the paid watermark.
            accountant.record_inbound_packet(&ipv4_tcp_packet(syn_ack));
            accountant.record_inbound_packet(&data);
            assert_eq!(
                accountant.record_outbound_packet(&ack).billable_bytes,
                ack.len() as u64
            );
        }
    }

    #[test]
    fn ipv6_tcp_ack_progress_is_counted() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let inbound = ipv6_tcp_packet(TcpPacketSpecV6 {
            src: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 443,
            dst_port: 55_000,
            seq: 500,
            ack: 1,
            flags: 0x18,
            payload_len: 512,
        });
        let outbound_ack = ipv6_tcp_packet(TcpPacketSpecV6 {
            src: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            dst: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            src_port: 55_000,
            dst_port: 443,
            seq: 1,
            ack: 1012,
            flags: 0x10,
            payload_len: 0,
        });

        accountant.record_inbound_packet(&inbound);
        let delta = accountant.record_outbound_packet(&outbound_ack);

        assert_eq!(delta.billable_bytes, outbound_ack.len() as u64 + 512);
    }

    #[test]
    fn accounting_overhead_smoke() {
        let mut accountant = PaidRouteTrafficAccountant::default();
        let inbound = ipv4_tcp_packet(TcpPacketSpec {
            src: [203, 0, 113, 10],
            dst: [10, 8, 0, 2],
            src_port: 443,
            dst_port: 55_000,
            seq: 10_000,
            ack: 1,
            flags: 0x18,
            payload_len: 1200,
        });
        let outbound = ipv4_tcp_packet(TcpPacketSpec {
            src: [10, 8, 0, 2],
            dst: [203, 0, 113, 10],
            src_port: 55_000,
            dst_port: 443,
            seq: 1,
            ack: 11_200,
            flags: 0x10,
            payload_len: 0,
        });
        let start = std::time::Instant::now();
        let iterations = 200_000u32;
        for _ in 0..iterations {
            accountant.record_inbound_packet(&inbound);
            accountant.record_outbound_packet(&outbound);
        }
        let elapsed = start.elapsed();
        eprintln!(
            "paid-route accounting smoke: {} packet observations in {:?} ({:.1} ns/packet)",
            iterations * 2,
            elapsed,
            elapsed.as_nanos() as f64 / f64::from(iterations * 2)
        );
    }

    #[derive(Clone, Copy)]
    struct TcpPacketSpec {
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload_len: usize,
    }

    #[derive(Clone, Copy)]
    struct TcpPacketSpecV6 {
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload_len: usize,
    }

    fn ipv4_udp_packet(total_len: usize) -> Vec<u8> {
        ipv4_udp_packet_with([10, 8, 0, 2], [198, 51, 100, 1], 12345, 53, total_len)
    }

    fn ipv4_udp_packet_with(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        total_len: usize,
    ) -> Vec<u8> {
        let total_len = total_len.max(28);
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..26].copy_from_slice(&((total_len - 20) as u16).to_be_bytes());
        packet
    }

    fn ipv4_tcp_packet(spec: TcpPacketSpec) -> Vec<u8> {
        let total_len = 40 + spec.payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_TCP;
        packet[12..16].copy_from_slice(&spec.src);
        packet[16..20].copy_from_slice(&spec.dst);
        fill_tcp_header(
            &mut packet[20..],
            spec.src_port,
            spec.dst_port,
            spec.seq,
            spec.ack,
            spec.flags,
        );
        packet
    }

    fn ipv6_tcp_packet(spec: TcpPacketSpecV6) -> Vec<u8> {
        let payload_len = 20 + spec.payload_len;
        let total_len = 40 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = IPPROTO_TCP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&spec.src);
        packet[24..40].copy_from_slice(&spec.dst);
        fill_tcp_header(
            &mut packet[40..],
            spec.src_port,
            spec.dst_port,
            spec.seq,
            spec.ack,
            spec.flags,
        );
        packet
    }

    fn fill_tcp_header(
        tcp: &mut [u8],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) {
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
    }
}
