//! Helpers for packets that have crossed a userspace tunnel boundary.
//!
//! Linux can hand TUN readers packets whose TCP/UDP checksum still relies on
//! kernel checksum metadata. That metadata is lost when we carry the raw IP
//! bytes over FIPS, so receivers may drop otherwise valid TCP packets. Finalize
//! checksums before serializing packets onto the overlay or writing them back to
//! an OS-owned TUN.

use std::net::Ipv4Addr;

/// Build an ICMP echo reply when `packet` is an IPv4 echo request addressed to
/// this tunnel's own virtual address.
///
/// Packet-tunnel platforms do not necessarily have a kernel-owned interface
/// that answers host-directed ICMP. Handling the request at the tunnel edge
/// keeps `ping` useful without sending the request into an app packet flow.
pub fn ipv4_icmp_echo_reply(packet: &[u8], local_address: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl + 8 || total_len > packet.len() || packet[9] != 1 {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 || packet[ihl] != 8 || packet[ihl + 1] != 0 {
        return None;
    }
    if packet[16..20] != local_address.octets() {
        return None;
    }

    let mut reply = packet[..total_len].to_vec();
    let source = <[u8; 4]>::try_from(&reply[12..16]).ok()?;
    reply[12..16].copy_from_slice(&local_address.octets());
    reply[16..20].copy_from_slice(&source);
    reply[8] = 64;
    reply[ihl] = 0;

    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_checksum = finalize_sum(add_words(0, &reply[ihl..total_len]));
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    reply[10] = 0;
    reply[11] = 0;
    let header_checksum = finalize_sum(add_words(0, &reply[..ihl]));
    reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Some(reply)
}

/// Recompute TCP/UDP checksums for supported IP packets in-place.
pub fn finalize_transport_checksum(packet: &mut [u8]) {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => finalize_ipv4_transport_checksum(packet),
        Some(6) => finalize_ipv6_transport_checksum(packet),
        _ => {}
    }
}

/// Recompute IPv4 TCP/UDP checksums in-place.
///
/// This is intentionally conservative: it only touches complete, unfragmented
/// IPv4 TCP/UDP packets. IPv4 UDP packets with checksum 0 keep checksum 0,
/// which is a valid "no checksum" marker.
pub fn finalize_ipv4_transport_checksum(packet: &mut [u8]) {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return;
    }

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    let total_len_usize = usize::from(total_len);
    if total_len_usize < ihl || total_len_usize > packet.len() {
        return;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let has_more_fragments = fragment & 0x2000 != 0;
    let fragment_offset = fragment & 0x1fff;
    if has_more_fragments || fragment_offset != 0 {
        return;
    }

    let protocol = packet[9];
    let Ok(transport_len) = u16::try_from(total_len_usize - ihl) else {
        return;
    };
    let transport_len_usize = usize::from(transport_len);
    match protocol {
        6 if transport_len_usize >= 20 => {
            packet[ihl + 16] = 0;
            packet[ihl + 17] = 0;
            let checksum = ipv4_transport_checksum(packet, ihl, transport_len, protocol);
            packet[ihl + 16..ihl + 18].copy_from_slice(&checksum.to_be_bytes());
        }
        17 if transport_len_usize >= 8 => {
            let old = u16::from_be_bytes([packet[ihl + 6], packet[ihl + 7]]);
            if old == 0 {
                return;
            }
            packet[ihl + 6] = 0;
            packet[ihl + 7] = 0;
            let checksum = ipv4_transport_checksum(packet, ihl, transport_len, protocol);
            let checksum = if checksum == 0 { 0xffff } else { checksum };
            packet[ihl + 6..ihl + 8].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => {}
    }
}

/// Recompute IPv6 TCP/UDP checksums in-place.
///
/// This handles the simple packets our tunnel pipeline carries today: a fixed
/// 40-byte IPv6 header followed directly by TCP or UDP. Extension-header
/// packets are left untouched.
pub fn finalize_ipv6_transport_checksum(packet: &mut [u8]) {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    let payload_len_usize = usize::from(payload_len);
    if payload_len == 0 || 40 + payload_len_usize > packet.len() {
        return;
    }

    let protocol = packet[6];
    let checksum_offset = match protocol {
        6 if payload_len_usize >= 20 => 40 + 16,
        17 if payload_len_usize >= 8 => 40 + 6,
        _ => return,
    };

    packet[checksum_offset] = 0;
    packet[checksum_offset + 1] = 0;
    let checksum = ipv6_transport_checksum(packet, payload_len, protocol);
    let checksum = if protocol == 17 && checksum == 0 {
        0xffff
    } else {
        checksum
    };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn ipv4_transport_checksum(packet: &[u8], ihl: usize, transport_len: u16, protocol: u8) -> u16 {
    let transport_len_usize = usize::from(transport_len);
    let mut sum = 0_u32;
    sum = add_words(sum, &packet[12..16]);
    sum = add_words(sum, &packet[16..20]);
    sum += u32::from(protocol);
    sum += u32::from(transport_len);
    sum = add_words(sum, &packet[ihl..ihl + transport_len_usize]);
    finalize_sum(sum)
}

fn ipv6_transport_checksum(packet: &[u8], payload_len: u16, protocol: u8) -> u16 {
    let payload_len_usize = usize::from(payload_len);
    let mut sum = 0_u32;
    sum = add_words(sum, &packet[8..40]);
    sum += u32::from(payload_len);
    sum += u32::from(protocol);
    sum = add_words(sum, &packet[40..40 + payload_len_usize]);
    finalize_sum(sum)
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    sum
}

fn finalize_sum(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let payload = b"nvpn-ping";
        let total_len = 20 + 8 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(
            &u16::try_from(total_len)
                .expect("test packet fits u16")
                .to_be_bytes(),
        );
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20] = 8;
        packet[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&7_u16.to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let icmp_checksum = finalize_sum(add_words(0, &packet[20..]));
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        let header_checksum = finalize_sum(add_words(0, &packet[..20]));
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn replies_to_ipv4_icmp_echo_for_local_tunnel_address() {
        let source = Ipv4Addr::new(10, 44, 5, 62);
        let local = Ipv4Addr::new(10, 44, 252, 137);
        let request = icmp_echo_request(source, local);
        let reply = ipv4_icmp_echo_reply(&request, local).expect("echo reply");

        assert_eq!(&reply[12..16], &local.octets());
        assert_eq!(&reply[16..20], &source.octets());
        assert_eq!(reply[20], 0);
        assert_eq!(reply[21], 0);
        assert_eq!(finalize_sum(add_words(0, &reply[20..])), 0);
        assert_eq!(finalize_sum(add_words(0, &reply[..20])), 0);
        assert_eq!(&reply[24..], &request[24..]);
    }

    #[test]
    fn ignores_ipv4_icmp_echo_for_another_address() {
        let request = icmp_echo_request(
            Ipv4Addr::new(10, 44, 5, 62),
            Ipv4Addr::new(10, 44, 252, 137),
        );

        assert!(ipv4_icmp_echo_reply(&request, Ipv4Addr::new(10, 44, 252, 138)).is_none());
    }

    fn test_len_u16(len: usize) -> u16 {
        u16::try_from(len).expect("test packet length fits u16")
    }

    fn tcp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let total_len = 20_u16 + 20;
        let mut packet = vec![0_u8; usize::from(total_len)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..22].copy_from_slice(&443_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&45172_u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x12;
        packet[34..36].copy_from_slice(&65535_u16.to_be_bytes());
        packet[36..38].copy_from_slice(&0xa77d_u16.to_be_bytes());
        packet
    }

    fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let payload = b"hello";
        let payload_len = u16::try_from(payload.len()).expect("test payload fits u16");
        let total_len = 20 + 8 + payload_len;
        let mut packet = vec![0_u8; usize::from(total_len)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..22].copy_from_slice(&5353_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&5353_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(8_u16 + payload_len).to_be_bytes());
        packet[26..28].copy_from_slice(&0xbeef_u16.to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn ipv6_tcp_ack_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let payload_len = 20_u16;
        let mut packet = vec![0_u8; 40 + usize::from(payload_len)];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..42].copy_from_slice(&52097_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&9999_u16.to_be_bytes());
        packet[44..48].copy_from_slice(&1000_u32.to_be_bytes());
        packet[48..52].copy_from_slice(&2000_u32.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x10;
        packet[54..56].copy_from_slice(&2049_u16.to_be_bytes());
        packet[56..58].copy_from_slice(&0x8ece_u16.to_be_bytes());
        packet
    }

    fn ipv6_udp_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let payload = b"hello";
        let payload_len = 8 + u16::try_from(payload.len()).expect("test payload fits u16");
        let mut packet = vec![0_u8; 40 + usize::from(payload_len)];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..42].copy_from_slice(&40000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&5354_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&payload_len.to_be_bytes());
        packet[46..48].copy_from_slice(&0x8ece_u16.to_be_bytes());
        packet[48..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn finalizes_ipv4_tcp_checksum() {
        let mut packet = tcp_packet(
            Ipv4Addr::new(172, 66, 147, 243),
            Ipv4Addr::new(10, 44, 80, 2),
        );
        finalize_ipv4_transport_checksum(&mut packet);
        let checksum = u16::from_be_bytes([packet[36], packet[37]]);

        assert_ne!(checksum, 0xa77d);
        assert_eq!(ipv4_transport_checksum(&packet, 20, 20, 6), 0);
    }

    #[test]
    fn finalizes_ipv4_udp_checksum_when_present() {
        let mut packet = udp_packet(
            Ipv4Addr::new(10, 44, 80, 2),
            Ipv4Addr::new(10, 44, 204, 215),
        );
        finalize_ipv4_transport_checksum(&mut packet);

        assert_eq!(
            ipv4_transport_checksum(&packet, 20, test_len_u16(packet.len() - 20), 17),
            0
        );
    }

    #[test]
    fn preserves_ipv4_udp_zero_checksum() {
        let mut packet = udp_packet(
            Ipv4Addr::new(10, 44, 80, 2),
            Ipv4Addr::new(10, 44, 204, 215),
        );
        packet[26] = 0;
        packet[27] = 0;
        finalize_ipv4_transport_checksum(&mut packet);

        assert_eq!(&packet[26..28], &[0, 0]);
    }

    #[test]
    fn finalizes_ipv6_tcp_checksum() {
        let mut packet =
            ipv6_tcp_ack_packet("fd00::55".parse().unwrap(), "fd00::55".parse().unwrap());
        finalize_ipv6_transport_checksum(&mut packet);

        assert_eq!(
            ipv6_transport_checksum(&packet, test_len_u16(packet.len() - 40), 6),
            0
        );
    }

    #[test]
    fn finalizes_ipv6_udp_checksum() {
        let mut packet = ipv6_udp_packet("fd00::55".parse().unwrap(), "fd00::55".parse().unwrap());
        finalize_transport_checksum(&mut packet);

        assert_eq!(
            ipv6_transport_checksum(&packet, test_len_u16(packet.len() - 40), 17),
            0
        );
        assert_ne!(&packet[46..48], &[0, 0]);
    }
}
