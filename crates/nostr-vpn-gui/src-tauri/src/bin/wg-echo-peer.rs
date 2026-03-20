use std::env;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use nostr_vpn_core::crypto::{decode_private_key, decode_public_key};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let listen_port: u16 = args
        .next()
        .ok_or_else(|| anyhow!("usage: wg-echo-peer <listen-port> <local-private-key-b64> <peer-public-key-b64> <local-tunnel-ip>"))?
        .parse()
        .context("invalid listen port")?;
    let local_private_key = args
        .next()
        .ok_or_else(|| anyhow!("missing local private key"))?;
    let peer_public_key = args
        .next()
        .ok_or_else(|| anyhow!("missing peer public key"))?;
    let local_tunnel_ip: Ipv4Addr = args
        .next()
        .ok_or_else(|| anyhow!("missing local tunnel ip"))?
        .parse()
        .context("invalid local tunnel ip")?;

    let private = decode_private_key(&local_private_key).context("invalid local private key")?;
    let peer_public = decode_public_key(&peer_public_key).context("invalid peer public key")?;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, listen_port))
        .with_context(|| format!("failed to bind udp socket on port {listen_port}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .context("failed to set socket read timeout")?;

    let mut tunnel = Tunn::new(private, peer_public, None, Some(25), 1, None);
    let mut network_buf = vec![0_u8; 65_535];
    let mut read_buf = vec![0_u8; 65_535];
    let mut write_buf = vec![0_u8; 65_535];
    let mut peer_endpoint: Option<SocketAddr> = None;

    eprintln!("wg-echo-peer listening on 0.0.0.0:{listen_port} for tunnel ip {local_tunnel_ip}");

    loop {
        match socket.recv_from(&mut network_buf) {
            Ok((read, source)) => {
                peer_endpoint = Some(source);
                let result =
                    tunnel.decapsulate(Some(source.ip()), &network_buf[..read], &mut read_buf);
                process_result(
                    &socket,
                    &mut tunnel,
                    source,
                    result,
                    &mut write_buf,
                    local_tunnel_ip,
                    &mut peer_endpoint,
                )?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("udp recv failed"),
        }

        if let Some(endpoint) = peer_endpoint {
            let result = tunnel.update_timers(&mut read_buf);
            process_result(
                &socket,
                &mut tunnel,
                endpoint,
                result,
                &mut write_buf,
                local_tunnel_ip,
                &mut peer_endpoint,
            )?;
        }
    }
}

fn process_result(
    socket: &UdpSocket,
    tunnel: &mut Tunn,
    source: SocketAddr,
    initial: TunnResult<'_>,
    tunnel_buf: &mut [u8],
    local_tunnel_ip: Ipv4Addr,
    peer_endpoint: &mut Option<SocketAddr>,
) -> Result<()> {
    let mut current = initial;

    loop {
        match current {
            TunnResult::WriteToNetwork(packet) => {
                let endpoint = peer_endpoint.unwrap_or(source);
                eprintln!(
                    "wg-echo-peer sending {} bytes to {}",
                    packet.len(),
                    endpoint
                );
                socket
                    .send_to(packet, endpoint)
                    .with_context(|| format!("failed to send wireguard datagram to {endpoint}"))?;
                return Ok(());
            }
            TunnResult::WriteToTunnelV4(packet, _) => {
                eprintln!("wg-echo-peer received tunnel packet {} bytes", packet.len());
                if let Some(reply) = icmp_echo_reply(packet, local_tunnel_ip) {
                    current = tunnel.encapsulate(&reply, tunnel_buf);
                    continue;
                }
                if let Some(reply) = udp_echo_reply(packet, local_tunnel_ip) {
                    current = tunnel.encapsulate(&reply, tunnel_buf);
                    continue;
                }
                return Ok(());
            }
            TunnResult::WriteToTunnelV6(_, _) => return Ok(()),
            TunnResult::Done => return Ok(()),
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                eprintln!("wg-echo-peer connection expired; waiting for next handshake");
                return Ok(());
            }
            TunnResult::Err(error) => return Err(anyhow!("wireguard tunnel error: {error:?}")),
        }
    }
}

fn icmp_echo_reply(packet: &[u8], local_tunnel_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }

    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let total_len = total_len.min(packet.len());
    if total_len < header_len + 8 {
        return None;
    }

    let protocol = packet[9];
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if protocol != 1 || destination != local_tunnel_ip {
        return None;
    }

    let icmp_offset = header_len;
    if packet[icmp_offset] != 8 {
        return None;
    }

    let mut reply = packet[..total_len].to_vec();
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[icmp_offset] = 0;
    reply[icmp_offset + 2] = 0;
    reply[icmp_offset + 3] = 0;
    let icmp_checksum = checksum(&reply[icmp_offset..total_len]);
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = checksum(&reply[..header_len]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Some(reply)
}

fn udp_echo_reply(packet: &[u8], local_tunnel_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }

    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let total_len = total_len.min(packet.len());
    if total_len < header_len + 8 {
        return None;
    }

    if packet[9] != 17 {
        return None;
    }

    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if destination_ip != local_tunnel_ip {
        return None;
    }

    let udp_offset = header_len;
    let udp_len = u16::from_be_bytes([packet[udp_offset + 4], packet[udp_offset + 5]]) as usize;
    if udp_len < 8 || total_len < udp_offset + udp_len {
        return None;
    }

    let mut reply = packet[..total_len].to_vec();
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[udp_offset..udp_offset + 2].copy_from_slice(&packet[udp_offset + 2..udp_offset + 4]);
    reply[udp_offset + 2..udp_offset + 4].copy_from_slice(&packet[udp_offset..udp_offset + 2]);

    reply[udp_offset + 6] = 0;
    reply[udp_offset + 7] = 0;
    let udp_checksum = udp_checksum(
        destination_ip,
        source_ip,
        &reply[udp_offset..udp_offset + udp_len],
    );
    reply[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = checksum(&reply[..header_len]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    Some(reply)
}

fn udp_checksum(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + udp_packet.len() + (udp_packet.len() % 2));
    pseudo_header.extend_from_slice(&source_ip.octets());
    pseudo_header.extend_from_slice(&destination_ip.octets());
    pseudo_header.push(0);
    pseudo_header.push(17);
    pseudo_header.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(udp_packet);
    checksum(&pseudo_header)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([*byte, 0]) as u32;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::{checksum, udp_echo_reply};
    use std::net::Ipv4Addr;

    fn ipv4_udp_packet(
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let header_len = 20;
        let udp_len = 8 + payload.len();
        let total_len = header_len + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let ip_checksum = checksum(&packet[..header_len]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn udp_echo_reply_swaps_addresses_and_ports() {
        let request = ipv4_udp_packet(
            Ipv4Addr::new(10, 44, 116, 253),
            Ipv4Addr::new(10, 44, 0, 2),
            41234,
            7777,
            b"hello",
        );

        let reply = udp_echo_reply(&request, Ipv4Addr::new(10, 44, 0, 2)).expect("udp reply");

        assert_eq!(&reply[12..16], &request[16..20]);
        assert_eq!(&reply[16..20], &request[12..16]);
        assert_eq!(&reply[20..22], &request[22..24]);
        assert_eq!(&reply[22..24], &request[20..22]);
        assert_eq!(&reply[28..], b"hello");
    }
}
