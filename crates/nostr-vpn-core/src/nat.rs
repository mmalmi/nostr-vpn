use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use webrtc_stun::message::{BINDING_REQUEST, Getter, Message};
use webrtc_stun::xoraddr::XORMappedAddress;

pub const DISCOVER_REQUEST_PREFIX: &str = "NVPN_DISCOVER";
pub const ENDPOINT_RESPONSE_PREFIX: &str = "NVPN_ENDPOINT";
pub const PUNCH_REQUEST_PREFIX: &str = "NVPN_PUNCH";
pub const PUNCH_ACK_PREFIX: &str = "NVPN_ACK";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolePunchReport {
    pub packets_sent: u32,
    pub packet_received: bool,
    pub local_addr: SocketAddr,
}

pub fn discover_public_udp_endpoint(
    reflector_addr: SocketAddr,
    listen_port: u16,
    timeout: Duration,
) -> Result<String> {
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind udp discovery socket on {bind_addr}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set udp discovery read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set udp discovery write timeout")?;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let request = format!("{DISCOVER_REQUEST_PREFIX} {nonce}");

    socket
        .send_to(request.as_bytes(), reflector_addr)
        .with_context(|| format!("failed to send udp discovery probe to {reflector_addr}"))?;

    let mut buf = [0u8; 1024];
    let (read, _) = socket
        .recv_from(&mut buf)
        .context("failed to receive udp discovery response")?;

    let payload =
        std::str::from_utf8(&buf[..read]).context("udp discovery response was not utf8")?;
    parse_public_endpoint_response(payload)
}

pub fn discover_public_udp_endpoint_via_stun(
    server: &str,
    listen_port: u16,
    timeout: Duration,
) -> Result<String> {
    let server_addr = resolve_stun_server_addr(server)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind udp stun socket on {bind_addr}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set udp stun read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set udp stun write timeout")?;

    let mut request = Message::new();
    request.typ = BINDING_REQUEST;
    request
        .new_transaction_id()
        .context("failed to generate stun transaction id")?;
    request.encode();

    socket
        .send_to(&request.raw, server_addr)
        .with_context(|| format!("failed to send stun binding request to {server_addr}"))?;

    let mut buf = [0u8; 1500];
    let (read, _) = socket
        .recv_from(&mut buf)
        .context("failed to receive stun binding response")?;

    let mut response = Message::new();
    response.raw = buf[..read].to_vec();
    response
        .decode()
        .context("failed to decode stun binding response")?;

    if response.transaction_id != request.transaction_id {
        return Err(anyhow!("stun binding response transaction id mismatch"));
    }

    let mut xor_addr = XORMappedAddress::default();
    xor_addr
        .get_from(&response)
        .context("stun response missing XOR-MAPPED-ADDRESS")?;

    Ok(SocketAddr::new(xor_addr.ip, xor_addr.port).to_string())
}

pub fn hole_punch_udp(
    listen_port: u16,
    peer_endpoint: SocketAddr,
    attempts: u32,
    interval: Duration,
    recv_timeout: Duration,
) -> Result<HolePunchReport> {
    if attempts == 0 {
        return Err(anyhow!("attempts must be > 0"));
    }

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind udp hole-punch socket on {bind_addr}"))?;
    socket
        .set_read_timeout(Some(recv_timeout))
        .context("failed to set udp hole-punch read timeout")?;
    socket
        .set_write_timeout(Some(recv_timeout))
        .context("failed to set udp hole-punch write timeout")?;

    let local_addr = socket
        .local_addr()
        .context("failed to read udp hole-punch local addr")?;

    let mut packets_sent = 0u32;
    let mut packet_received = false;
    let mut recv_buf = [0u8; 256];

    for attempt in 0..attempts {
        let payload = format!("{PUNCH_REQUEST_PREFIX} {attempt}");
        socket
            .send_to(payload.as_bytes(), peer_endpoint)
            .with_context(|| format!("failed to send hole-punch packet to {peer_endpoint}"))?;
        packets_sent += 1;

        if let Ok((read, src)) = socket.recv_from(&mut recv_buf)
            && src == peer_endpoint
            && read > 0
        {
            packet_received = true;
        }

        if attempt + 1 < attempts {
            thread::sleep(interval);
        }
    }

    Ok(HolePunchReport {
        packets_sent,
        packet_received,
        local_addr,
    })
}

fn parse_public_endpoint_response(payload: &str) -> Result<String> {
    let Some(value) = payload.strip_prefix(ENDPOINT_RESPONSE_PREFIX) else {
        return Err(anyhow!(
            "invalid discovery response: expected '{ENDPOINT_RESPONSE_PREFIX} <ip:port>'"
        ));
    };

    let endpoint = value.trim();
    if endpoint.is_empty() {
        return Err(anyhow!("invalid discovery response: empty endpoint"));
    }

    let parsed: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("invalid discovery endpoint '{endpoint}'"))?;

    Ok(parsed.to_string())
}

fn resolve_stun_server_addr(server: &str) -> Result<SocketAddr> {
    let raw = server.trim();
    if raw.is_empty() {
        return Err(anyhow!("stun server address must not be empty"));
    }

    let stripped = raw
        .strip_prefix("stun://")
        .or_else(|| raw.strip_prefix("stun:"))
        .unwrap_or(raw);

    let addrs = stripped
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve stun server '{raw}'"))?;

    select_ipv4_socket_addr(addrs)
        .ok_or_else(|| anyhow!("stun server '{raw}' did not resolve to an IPv4 socket address"))
}

fn select_ipv4_socket_addr(addrs: impl IntoIterator<Item = SocketAddr>) -> Option<SocketAddr> {
    addrs.into_iter().find(SocketAddr::is_ipv4)
}

#[cfg(test)]
mod tests {
    use super::select_ipv4_socket_addr;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn selects_ipv4_address_for_ipv4_socket() {
        let addrs = [
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3478, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3478)),
        ];

        let selected = select_ipv4_socket_addr(addrs);

        assert_eq!(
            selected,
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3478)))
        );
    }

    #[test]
    fn returns_none_when_no_address_matches_socket_family() {
        let addrs = [SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            3478,
            0,
            0,
        ))];

        let selected = select_ipv4_socket_addr(addrs);

        assert_eq!(selected, None);
    }
}
