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
    let icmp_checksum = !fold_checksum(checksum_sum(0, &reply[ihl..total_len]));
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    finalize_ipv4_header_checksum(&mut reply[..ihl]);
    Some(reply)
}

/// Recompute the IPv4 header checksum in-place for a header slice of at least 20 bytes.
pub fn finalize_ipv4_header_checksum(header: &mut [u8]) {
    if header.len() < 20 {
        return;
    }
    header[10] = 0;
    header[11] = 0;
    let checksum = !fold_checksum(checksum_sum(0, header));
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Compute the protocol + source/destination address portion of an IPv4 or IPv6
/// transport pseudo-header sum. Add the transport length before folding.
#[inline]
#[must_use]
pub fn pseudo_header_base_sum(protocol: u8, src: &[u8], dst: &[u8]) -> u64 {
    let sum = checksum_sum(u64::from(protocol), src);
    checksum_sum(sum, dst)
}

/// Accumulate RFC 1071 ones'-complement 16-bit big-endian words from `bytes`
/// onto `initial` using auto-vectorizable native-endian `u32` accumulation.
#[inline]
#[must_use]
pub fn checksum_sum(mut sum: u64, bytes: &[u8]) -> u64 {
    // By RFC 1071 byte-order independence, summing 16-bit words in native
    // endianness with end-around carry and converting the folded 16-bit result
    // from big-endian yields the exact big-endian 16-bit sum without per-word
    // byte swaps in the inner loop. Chunking at 32,768 words prevents u32
    // overflow (32,768 * 0xffff < 2^31).
    let (pairs, rem) = bytes.as_chunks::<2>();
    for block in pairs.chunks(32_768) {
        let mut acc = 0_u32;
        for &pair in block {
            acc += u32::from(u16::from_ne_bytes(pair));
        }
        let folded = (acc & 0xffff) + (acc >> 16);
        let folded = (folded & 0xffff) + (folded >> 16);
        let ne_16 = u16::try_from(folded).expect("folded checksum fits u16");
        sum += u64::from(u16::from_be(ne_16));
    }
    if let Some(&byte) = rem.first() {
        sum += u64::from(byte) << 8;
    }
    sum
}

/// Fold an accumulated RFC 1071 sum to a 16-bit ones'-complement sum (not inverted).
#[inline]
#[must_use]
pub fn fold_checksum(mut sum: u64) -> u16 {
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    u16::try_from(sum).expect("folded checksum fits u16")
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
    let sum = checksum_sum(
        u64::from(protocol) + u64::from(transport_len),
        &packet[12..20],
    );
    !fold_checksum(checksum_sum(sum, &packet[ihl..ihl + transport_len_usize]))
}

fn ipv6_transport_checksum(packet: &[u8], payload_len: u16, protocol: u8) -> u16 {
    let payload_len_usize = usize::from(payload_len);
    let sum = checksum_sum(u64::from(protocol) + u64::from(payload_len), &packet[8..40]);
    !fold_checksum(checksum_sum(sum, &packet[40..40 + payload_len_usize]))
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
        let icmp_checksum = !fold_checksum(checksum_sum(0, &packet[20..]));
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        finalize_ipv4_header_checksum(&mut packet[..20]);
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
        assert_eq!(!fold_checksum(checksum_sum(0, &reply[20..])), 0);
        assert_eq!(!fold_checksum(checksum_sum(0, &reply[..20])), 0);
        assert_eq!(&reply[24..], &request[24..]);
    }

    #[test]
    fn checksum_sum_matches_reference_across_lengths_and_carry_boundaries() {
        fn ref_fold(initial: u64, bytes: &[u8]) -> u16 {
            let mut sum = initial;
            let (chunks, rem) = bytes.as_chunks::<2>();
            for c in chunks {
                sum += u64::from(u16::from_be_bytes(*c));
            }
            if let Some(&b) = rem.first() {
                sum += u64::from(b) << 8;
            }
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            u16::try_from(sum).expect("fits u16")
        }

        let buf = (0..4096usize)
            .map(|i| u8::try_from((i.wrapping_mul(131) ^ (i >> 3) ^ 0x5a) & 0xff).expect("u8"))
            .collect::<Vec<_>>();
        for len in (0..=512).chain([1279, 1280, 1281, 1322, 1460, 4095, 4096]) {
            for offset in 0..8 {
                if offset + len <= buf.len() {
                    let slice = &buf[offset..offset + len];
                    assert_eq!(
                        fold_checksum(checksum_sum(0x1_2345, slice)),
                        ref_fold(0x1_2345, slice),
                        "mismatch for len={len} offset={offset}"
                    );
                }
            }
        }
        for pattern in [0x00_u8, 0xff_u8, 0x80_u8, 0x7f_u8] {
            let uniform = vec![pattern; 1501];
            for len in [0, 1, 2, 7, 8, 31, 32, 33, 63, 64, 65, 1500, 1501] {
                assert_eq!(
                    fold_checksum(checksum_sum(0xffff, &uniform[..len])),
                    ref_fold(0xffff, &uniform[..len]),
                    "mismatch for pattern={pattern:#x} len={len}"
                );
            }
        }
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
