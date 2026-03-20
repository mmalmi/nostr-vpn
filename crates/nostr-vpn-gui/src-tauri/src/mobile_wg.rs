use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Result, anyhow};
use boringtun::noise::{Tunn, TunnResult};
use nostr_vpn_core::crypto::{decode_private_key, decode_public_key};

const MAX_WIREGUARD_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Route {
    network: u32,
    prefix_len: u8,
}

impl Ipv4Route {
    fn parse(value: &str) -> Option<Self> {
        let (addr, prefix_len) = value.trim().split_once('/')?;
        let prefix_len = prefix_len.parse::<u8>().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let ip = addr.parse::<Ipv4Addr>().ok()?;
        let mask = prefix_mask(prefix_len);
        Some(Self {
            network: u32::from(ip) & mask,
            prefix_len,
        })
    }

    fn matches(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & prefix_mask(self.prefix_len)) == self.network
    }
}

struct WireGuardPeerRuntime {
    participant_pubkey: String,
    endpoint: SocketAddr,
    tunnel: Tunn,
    routes: Vec<Ipv4Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireGuardPeerConfig {
    pub participant_pubkey: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutgoingDatagram {
    pub participant_pubkey: String,
    pub endpoint: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DatagramProcessingResult {
    pub outgoing: Vec<OutgoingDatagram>,
    pub tunnel_packets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerRuntimeStatus {
    pub participant_pubkey: String,
    pub endpoint: SocketAddr,
    pub last_handshake_age: Option<Duration>,
}

pub(crate) struct MobileWireGuardRuntime {
    peers: Vec<WireGuardPeerRuntime>,
}

impl MobileWireGuardRuntime {
    pub(crate) fn new(private_key: &str, peers: Vec<WireGuardPeerConfig>) -> Result<Self> {
        let private_key = decode_private_key(private_key)?;
        let mut runtimes = Vec::with_capacity(peers.len());

        for (index, peer) in peers.into_iter().enumerate() {
            let peer_public_key = decode_public_key(&peer.public_key)?;
            let routes = peer
                .allowed_ips
                .iter()
                .filter_map(|route| Ipv4Route::parse(route))
                .collect::<Vec<_>>();
            let tunnel = Tunn::new(
                private_key.clone(),
                peer_public_key,
                None,
                Some(25),
                (index as u32).saturating_add(1),
                None,
            );
            runtimes.push(WireGuardPeerRuntime {
                participant_pubkey: peer.participant_pubkey,
                endpoint: peer.endpoint,
                tunnel,
                routes,
            });
        }

        Ok(Self { peers: runtimes })
    }

    pub(crate) fn queue_tunnel_packet(&mut self, packet: &[u8]) -> Result<Vec<OutgoingDatagram>> {
        let Some(peer_index) = self.select_peer_for_packet(packet) else {
            return Ok(Vec::new());
        };

        let mut processed = {
            let peer = self
                .peers
                .get_mut(peer_index)
                .ok_or_else(|| anyhow!("selected peer index out of range"))?;
            let mut dst = vec![0_u8; MAX_WIREGUARD_PACKET_SIZE];
            let participant_pubkey = peer.participant_pubkey.clone();
            let endpoint = peer.endpoint;
            let result = peer.tunnel.encapsulate(packet, &mut dst);
            process_tunn_result(&participant_pubkey, endpoint, result)
        };

        processed
            .outgoing
            .extend(self.flush_queued_packets(peer_index));
        Ok(processed.outgoing)
    }

    pub(crate) fn receive_datagram(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
    ) -> Result<DatagramProcessingResult> {
        let mut candidates = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer.endpoint == source)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        candidates.extend(
            self.peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| peer.endpoint != source)
                .map(|(index, _)| index),
        );

        for peer_index in candidates {
            let processed = {
                let peer = self
                    .peers
                    .get_mut(peer_index)
                    .ok_or_else(|| anyhow!("selected peer index out of range"))?;
                let mut dst = vec![0_u8; MAX_WIREGUARD_PACKET_SIZE];
                let participant_pubkey = peer.participant_pubkey.clone();
                let endpoint = peer.endpoint;
                let result = peer
                    .tunnel
                    .decapsulate(Some(source.ip()), datagram, &mut dst);
                if matches_nonmatching_peer(&result) {
                    DatagramProcessingResult {
                        outgoing: vec![OutgoingDatagram {
                            participant_pubkey: String::new(),
                            endpoint,
                            payload: Vec::new(),
                        }],
                        tunnel_packets: Vec::new(),
                    }
                } else {
                    process_tunn_result(&participant_pubkey, endpoint, result)
                }
            };

            if processed.outgoing.len() == 1
                && processed.outgoing[0].participant_pubkey.is_empty()
                && processed.outgoing[0].payload.is_empty()
            {
                continue;
            }

            if let Some(peer) = self.peers.get_mut(peer_index) {
                peer.endpoint = source;
            }

            let mut processed = processed;
            for outgoing in &mut processed.outgoing {
                outgoing.endpoint = source;
            }
            let flushed = self.flush_queued(peer_index);
            processed.outgoing.extend(flushed.outgoing);
            processed.tunnel_packets.extend(flushed.tunnel_packets);
            return Ok(processed);
        }

        Ok(DatagramProcessingResult::default())
    }

    pub(crate) fn initiate_handshakes(&mut self) -> Vec<OutgoingDatagram> {
        let mut outgoing = Vec::new();
        for peer_index in 0..self.peers.len() {
            let processed = {
                let peer = self
                    .peers
                    .get_mut(peer_index)
                    .expect("peer index should be valid");
                let mut dst = vec![0_u8; MAX_WIREGUARD_PACKET_SIZE];
                let participant_pubkey = peer.participant_pubkey.clone();
                let endpoint = peer.endpoint;
                let result = peer.tunnel.format_handshake_initiation(&mut dst, false);
                process_tunn_result(&participant_pubkey, endpoint, result)
            };
            outgoing.extend(processed.outgoing);
        }
        outgoing
    }

    pub(crate) fn tick_timers(&mut self) -> DatagramProcessingResult {
        let mut processed = DatagramProcessingResult::default();
        for peer_index in 0..self.peers.len() {
            let mut peer_processed = {
                let peer = self
                    .peers
                    .get_mut(peer_index)
                    .expect("peer index should be valid");
                let mut dst = vec![0_u8; MAX_WIREGUARD_PACKET_SIZE];
                let participant_pubkey = peer.participant_pubkey.clone();
                let endpoint = peer.endpoint;
                let result = peer.tunnel.update_timers(&mut dst);
                process_tunn_result(&participant_pubkey, endpoint, result)
            };
            let flushed = self.flush_queued(peer_index);
            peer_processed.outgoing.extend(flushed.outgoing);
            peer_processed.tunnel_packets.extend(flushed.tunnel_packets);
            processed.outgoing.extend(peer_processed.outgoing);
            processed
                .tunnel_packets
                .extend(peer_processed.tunnel_packets);
        }
        processed
    }

    pub(crate) fn peer_statuses(&self) -> Vec<PeerRuntimeStatus> {
        self.peers
            .iter()
            .map(|peer| {
                let (handshake_age, _, _, _, _) = peer.tunnel.stats();
                PeerRuntimeStatus {
                    participant_pubkey: peer.participant_pubkey.clone(),
                    endpoint: peer.endpoint,
                    last_handshake_age: handshake_age,
                }
            })
            .collect()
    }

    fn select_peer_for_packet(&self, packet: &[u8]) -> Option<usize> {
        let destination = match Tunn::dst_address(packet)? {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return None,
        };

        self.peers
            .iter()
            .enumerate()
            .flat_map(|(index, peer)| {
                peer.routes
                    .iter()
                    .filter(move |route| route.matches(destination))
                    .map(move |route| (index, route.prefix_len))
            })
            .max_by_key(|(_, prefix_len)| *prefix_len)
            .map(|(index, _)| index)
    }

    fn flush_queued(&mut self, peer_index: usize) -> DatagramProcessingResult {
        let mut processed = DatagramProcessingResult::default();
        loop {
            let next = {
                let peer = self
                    .peers
                    .get_mut(peer_index)
                    .expect("peer index should be valid");
                let mut dst = vec![0_u8; MAX_WIREGUARD_PACKET_SIZE];
                let participant_pubkey = peer.participant_pubkey.clone();
                let endpoint = peer.endpoint;
                let result = peer.tunnel.decapsulate(None, &[], &mut dst);
                process_tunn_result(&participant_pubkey, endpoint, result)
            };

            if next.outgoing.is_empty() && next.tunnel_packets.is_empty() {
                return processed;
            }
            processed.outgoing.extend(next.outgoing);
            processed.tunnel_packets.extend(next.tunnel_packets);
        }
    }

    fn flush_queued_packets(&mut self, peer_index: usize) -> Vec<OutgoingDatagram> {
        self.flush_queued(peer_index).outgoing
    }
}

fn matches_nonmatching_peer(result: &TunnResult<'_>) -> bool {
    matches!(
        result,
        TunnResult::Err(
            boringtun::noise::errors::WireGuardError::WrongKey
                | boringtun::noise::errors::WireGuardError::WrongIndex
                | boringtun::noise::errors::WireGuardError::InvalidMac
                | boringtun::noise::errors::WireGuardError::InvalidAeadTag
                | boringtun::noise::errors::WireGuardError::UnexpectedPacket
                | boringtun::noise::errors::WireGuardError::WrongPacketType
                | boringtun::noise::errors::WireGuardError::NoCurrentSession
                | boringtun::noise::errors::WireGuardError::InvalidPacket
                | boringtun::noise::errors::WireGuardError::InvalidCounter
                | boringtun::noise::errors::WireGuardError::DuplicateCounter
        )
    )
}

fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn process_tunn_result(
    participant_pubkey: &str,
    endpoint: SocketAddr,
    result: TunnResult<'_>,
) -> DatagramProcessingResult {
    match result {
        TunnResult::Done | TunnResult::Err(_) => DatagramProcessingResult::default(),
        TunnResult::WriteToNetwork(packet) => DatagramProcessingResult {
            outgoing: vec![OutgoingDatagram {
                participant_pubkey: participant_pubkey.to_string(),
                endpoint,
                payload: packet.to_vec(),
            }],
            tunnel_packets: Vec::new(),
        },
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            DatagramProcessingResult {
                outgoing: Vec::new(),
                tunnel_packets: vec![packet.to_vec()],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MobileWireGuardRuntime, WireGuardPeerConfig};
    use nostr_vpn_core::crypto::generate_keypair;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn ipv4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let total_len = 20 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(10, 44, 10, 1).octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..].copy_from_slice(&payload);
        packet
    }

    #[test]
    fn longest_prefix_route_wins() {
        let local_keys = generate_keypair();
        let general_peer = generate_keypair();
        let specific_peer = generate_keypair();

        let mut runtime = MobileWireGuardRuntime::new(
            &local_keys.private_key,
            vec![
                WireGuardPeerConfig {
                    participant_pubkey: "general".to_string(),
                    public_key: general_peer.public_key,
                    endpoint: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40101)),
                    allowed_ips: vec!["10.44.0.0/16".to_string()],
                },
                WireGuardPeerConfig {
                    participant_pubkey: "specific".to_string(),
                    public_key: specific_peer.public_key,
                    endpoint: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40102)),
                    allowed_ips: vec!["10.44.22.44/32".to_string()],
                },
            ],
        )
        .expect("runtime");

        let outgoing = runtime
            .queue_tunnel_packet(&ipv4_packet(Ipv4Addr::new(10, 44, 22, 44)))
            .expect("queue packet");

        assert_eq!(outgoing.len(), 1, "expected a handshake init for one peer");
        assert_eq!(outgoing[0].participant_pubkey, "specific");
        assert_eq!(
            outgoing[0].endpoint,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40102))
        );
    }

    #[test]
    fn two_peers_complete_handshake_and_exchange_packet() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let alice_endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41101));
        let bob_endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41102));
        let tunneled_packet = ipv4_packet(Ipv4Addr::new(10, 44, 33, 8));

        let mut alice_runtime = MobileWireGuardRuntime::new(
            &alice.private_key,
            vec![WireGuardPeerConfig {
                participant_pubkey: "bob".to_string(),
                public_key: bob.public_key.clone(),
                endpoint: bob_endpoint,
                allowed_ips: vec!["10.44.33.8/32".to_string()],
            }],
        )
        .expect("alice runtime");
        let mut bob_runtime = MobileWireGuardRuntime::new(
            &bob.private_key,
            vec![WireGuardPeerConfig {
                participant_pubkey: "alice".to_string(),
                public_key: alice.public_key.clone(),
                endpoint: alice_endpoint,
                allowed_ips: vec!["10.44.10.1/32".to_string()],
            }],
        )
        .expect("bob runtime");

        let mut network_queue = alice_runtime
            .queue_tunnel_packet(&tunneled_packet)
            .expect("alice should start a handshake");
        let mut delivered = Vec::new();

        for _ in 0..8 {
            if network_queue.is_empty() {
                break;
            }

            let mut next_round = Vec::new();
            for datagram in network_queue {
                let result = if datagram.endpoint == bob_endpoint {
                    bob_runtime
                        .receive_datagram(alice_endpoint, &datagram.payload)
                        .expect("bob receive")
                } else {
                    alice_runtime
                        .receive_datagram(bob_endpoint, &datagram.payload)
                        .expect("alice receive")
                };
                delivered.extend(result.tunnel_packets);
                next_round.extend(result.outgoing);
            }
            network_queue = next_round;
        }

        assert!(
            delivered.iter().any(|packet| packet == &tunneled_packet),
            "expected the tunneled IPv4 packet to be delivered after the WireGuard handshake"
        );
    }
}
