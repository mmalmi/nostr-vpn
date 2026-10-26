use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::normalize_nostr_pubkey;
use crate::data_plane::MeshPeerStatus;
use crate::paid_route_accounting::{ExitFlowFilter, is_public_exit_destination};
#[cfg(feature = "paid-exit")]
use crate::paid_route_store::PaidRouteSellerAdmission;
use crate::paid_routes::PaidRouteAccessState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsMeshPeerConfig {
    pub participant_pubkey: String,
    pub endpoint_npub: String,
    pub allowed_ips: Vec<String>,
}

impl FipsMeshPeerConfig {
    pub fn from_participant_pubkey(
        participant_pubkey: impl AsRef<str>,
        allowed_ips: Vec<String>,
    ) -> Result<Self> {
        let participant_pubkey = normalize_nostr_pubkey(participant_pubkey.as_ref())?;
        let endpoint_npub = npub_for_pubkey_hex(&participant_pubkey)?;

        Ok(Self {
            participant_pubkey,
            endpoint_npub,
            allowed_ips,
        })
    }

    pub fn advertises_default_route(&self) -> bool {
        self.allowed_ips
            .iter()
            .any(|route| matches!(route.trim(), "0.0.0.0/0" | "::/0"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsPaidRouteAdmission {
    pub participant_pubkey: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_allowed_ips: Vec<String>,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub amount_due_msat: u64,
    pub paid_msat: u64,
    pub unpaid_msat: u64,
    pub expires_at_unix: u64,
    pub updated_at_unix: u64,
}

#[cfg(feature = "paid-exit")]
impl From<PaidRouteSellerAdmission> for FipsPaidRouteAdmission {
    fn from(value: PaidRouteSellerAdmission) -> Self {
        Self {
            participant_pubkey: value.buyer_pubkey,
            session_id: value.session_id,
            allowed_ips: vec![value.buyer_tunnel_ip],
            destination_allowed_ips: value.destination_allowed_ips,
            allow_routing: value.allow_routing,
            state: value.state,
            amount_due_msat: value.amount_due_msat,
            paid_msat: value.paid_msat,
            unpaid_msat: value.unpaid_msat,
            expires_at_unix: value.expires_at_unix,
            updated_at_unix: value.updated_at_unix,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RoutedFipsPacket<'a> {
    pub participant_pubkey: &'a str,
    pub participant_pubkey_bytes: Option<&'a [u8; 32]>,
    pub endpoint_node_addr: &'a [u8; 16],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedFipsPeer<'a> {
    pub participant_pubkey: &'a str,
    pub participant_pubkey_bytes: Option<&'a [u8; 32]>,
    pub endpoint_node_addr: &'a [u8; 16],
    pub via_default_route: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AcceptedFipsPacket<'a, B = Vec<u8>> {
    pub source_pubkey: &'a str,
    pub source_pubkey_bytes: Option<&'a [u8; 32]>,
    pub bytes: B,
}

#[derive(Debug, Clone, Copy)]
pub struct FipsEndpointSourceAdmitter<'a> {
    runtime: &'a FipsMeshRuntime,
    peer: &'a FipsMeshPeerRuntime,
}

#[derive(Debug, Default, Clone)]
pub struct FipsEndpointAdmissionCache {
    source: Option<(IpAddr, bool)>,
    destination: Option<(IpAddr, bool)>,
}

#[derive(Debug, Clone)]
pub struct FipsMeshRuntime {
    peers: Vec<FipsMeshPeerRuntime>,
    local_routes: Vec<IpRoute>,
    paid_route_admissions: HashMap<[u8; 32], FipsPaidRouteAdmission>,
    paid_route_destination_routes: HashMap<[u8; 32], Vec<IpRoute>>,
    paid_route_peers: Vec<FipsMeshPeerRuntime>,
    paid_route_routing_peers: Vec<FipsMeshPeerRuntime>,
    participant_peer_index: HashMap<[u8; 32], usize>,
    endpoint_node_addr_peer_index: HashMap<[u8; 16], usize>,
    exact_route_peer_index: HashMap<IpAddr, ExactRouteMatch>,
    prefix_v4_route_peer_index: Vec<IndexedIpRoute>,
    prefix_v6_route_peer_index: Vec<IndexedIpRoute>,
    paid_exact_route_peer_index: HashMap<IpAddr, ExactRouteMatch>,
    paid_prefix_v4_route_peer_index: Vec<IndexedIpRoute>,
    paid_prefix_v6_route_peer_index: Vec<IndexedIpRoute>,
    exit_flows: Arc<Mutex<ExitFlowFilter>>,
}

#[derive(Debug, Clone)]
struct FipsMeshPeerRuntime {
    participant_pubkey: Option<[u8; 32]>,
    participant_pubkey_hex: String,
    endpoint_npub: Option<String>,
    endpoint_node_addr: Option<[u8; 16]>,
    routes: Vec<IpRoute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRoute {
    network: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactRouteMatch {
    Peer(usize),
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedIpRoute {
    peer_index: usize,
    route: IpRoute,
}

#[derive(Clone, Copy)]
enum PeerRouteSelection<'a> {
    None,
    Match {
        peer: &'a FipsMeshPeerRuntime,
        prefix_len: u8,
    },
    Ambiguous {
        prefix_len: u8,
    },
}

impl<'a> PeerRouteSelection<'a> {
    fn combine(self, candidate: Self) -> Self {
        match (self.prefix_len(), candidate.prefix_len()) {
            (None, _) => candidate,
            (_, None) => self,
            (Some(current), Some(next)) if next > current => candidate,
            (Some(current), Some(next)) if current > next => self,
            (Some(prefix_len), Some(_)) => match (self, candidate) {
                (Self::Match { peer: left, .. }, Self::Match { peer: right, .. })
                    if same_participant(left, right) =>
                {
                    self
                }
                _ => Self::Ambiguous { prefix_len },
            },
        }
    }

    fn prefix_len(self) -> Option<u8> {
        match self {
            Self::None => None,
            Self::Match { prefix_len, .. } | Self::Ambiguous { prefix_len } => Some(prefix_len),
        }
    }

    fn peer(self) -> Option<&'a FipsMeshPeerRuntime> {
        match self {
            Self::Match { peer, .. } => Some(peer),
            Self::None | Self::Ambiguous { .. } => None,
        }
    }
}

impl FipsMeshRuntime {
    pub fn new(peers: Vec<FipsMeshPeerConfig>) -> Self {
        Self::with_local_routes(peers, Vec::new())
    }

    pub fn with_local_routes(
        peers: Vec<FipsMeshPeerConfig>,
        local_allowed_ips: Vec<String>,
    ) -> Self {
        Self::with_local_routes_internal(peers, local_allowed_ips, Vec::new())
    }

    pub fn with_local_routes_and_paid_route_admissions(
        peers: Vec<FipsMeshPeerConfig>,
        local_allowed_ips: Vec<String>,
        paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    ) -> Self {
        Self::with_local_routes_internal(peers, local_allowed_ips, paid_route_admissions)
    }

    fn with_local_routes_internal(
        peers: Vec<FipsMeshPeerConfig>,
        local_allowed_ips: Vec<String>,
        paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    ) -> Self {
        let peers = peers
            .into_iter()
            .map(|peer| {
                let routes = peer
                    .allowed_ips
                    .iter()
                    .filter_map(|route| IpRoute::parse(route))
                    .collect();

                let endpoint_pubkey = parse_nostr_pubkey_bytes(&peer.endpoint_npub);
                let endpoint_node_addr = endpoint_pubkey.map(endpoint_node_addr_from_pubkey_bytes);
                let endpoint_npub =
                    endpoint_pubkey.and_then(|pubkey| npub_for_pubkey_bytes(&pubkey).ok());
                let (participant_pubkey, participant_pubkey_hex) =
                    runtime_participant_pubkey(&peer.participant_pubkey);

                FipsMeshPeerRuntime {
                    participant_pubkey,
                    participant_pubkey_hex,
                    endpoint_npub,
                    endpoint_node_addr,
                    routes,
                }
            })
            .collect::<Vec<_>>();
        let participant_peer_index = participant_peer_index(&peers);
        let endpoint_node_addr_peer_index = endpoint_node_addr_peer_index(&peers);
        let regular_exact_route_peer_index = exact_route_peer_index(&peers);
        let (prefix_v4_route_peer_index, prefix_v6_route_peer_index) =
            prefix_route_peer_indexes(&peers);
        let local_routes = local_allowed_ips
            .iter()
            .filter_map(|route| IpRoute::parse(route))
            .collect();

        let paid_route_admissions = normalize_paid_route_admissions(paid_route_admissions);
        let paid_route_destination_routes =
            paid_route_destination_routes_from_admissions(&paid_route_admissions);
        let paid_route_peers = paid_route_peers_from_admissions(&paid_route_admissions, false);
        let paid_route_routing_peers =
            paid_route_peers_from_admissions(&paid_route_admissions, true);
        let paid_exact_route_peer_index = exact_route_peer_index(&paid_route_routing_peers);
        let (paid_prefix_v4_route_peer_index, paid_prefix_v6_route_peer_index) =
            prefix_route_peer_indexes(&paid_route_routing_peers);

        Self {
            peers,
            local_routes,
            paid_route_admissions,
            paid_route_destination_routes,
            paid_route_peers,
            paid_route_routing_peers,
            participant_peer_index,
            endpoint_node_addr_peer_index,
            exact_route_peer_index: regular_exact_route_peer_index,
            prefix_v4_route_peer_index,
            prefix_v6_route_peer_index,
            paid_exact_route_peer_index,
            paid_prefix_v4_route_peer_index,
            paid_prefix_v6_route_peer_index,
            exit_flows: Arc::new(Mutex::new(ExitFlowFilter::default())),
        }
    }

    pub fn inherit_exit_flows(&mut self, previous: &Self) {
        self.exit_flows = Arc::clone(&previous.exit_flows);
    }

    pub fn replace_paid_route_admissions(
        &mut self,
        paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    ) {
        self.paid_route_admissions = normalize_paid_route_admissions(paid_route_admissions);
        self.paid_route_destination_routes =
            paid_route_destination_routes_from_admissions(&self.paid_route_admissions);
        self.paid_route_peers =
            paid_route_peers_from_admissions(&self.paid_route_admissions, false);
        self.paid_route_routing_peers =
            paid_route_peers_from_admissions(&self.paid_route_admissions, true);
        self.paid_exact_route_peer_index = exact_route_peer_index(&self.paid_route_routing_peers);
        (
            self.paid_prefix_v4_route_peer_index,
            self.paid_prefix_v6_route_peer_index,
        ) = prefix_route_peer_indexes(&self.paid_route_routing_peers);
    }

    pub fn route_outbound_packet_peer<'a>(&'a self, packet: &[u8]) -> Option<RoutedFipsPeer<'a>> {
        let (_, destination) = packet_endpoints(packet)?;
        let peer = self.select_peer_for_ip(destination)?;
        let via_default_route = self.peer_uses_default_route(peer, destination);
        self.note_exit_outbound(peer, destination, packet);

        routed_fips_peer(peer, via_default_route)
    }

    pub fn route_outbound_destination_peer<'a>(
        &'a self,
        destination: IpAddr,
    ) -> Option<RoutedFipsPeer<'a>> {
        let peer = self.select_peer_for_ip(destination)?;

        routed_fips_peer(peer, self.peer_uses_default_route(peer, destination))
    }

    pub fn route_outbound_packet_owned_with_peer<'a>(
        &'a self,
        packet: Vec<u8>,
    ) -> Option<RoutedFipsPacket<'a>> {
        let (_, destination) = packet_endpoints(&packet)?;
        self.route_outbound_packet_owned_with_peer_to_destination(packet, destination)
    }

    fn route_outbound_packet_owned_with_peer_to_destination<'a>(
        &'a self,
        packet: Vec<u8>,
        destination: IpAddr,
    ) -> Option<RoutedFipsPacket<'a>> {
        let peer = self.select_peer_for_ip(destination)?;
        self.note_exit_outbound(peer, destination, &packet);

        routed_fips_packet(peer, packet)
    }

    pub fn receive_endpoint_data_owned_with_source_node_addr<'a, B>(
        &'a self,
        source_node_addr: &[u8; 16],
        data: B,
    ) -> Option<AcceptedFipsPacket<'a, B>>
    where
        B: AsRef<[u8]>,
    {
        self.endpoint_source_admitter(source_node_addr)?
            .receive_owned(data)
    }

    pub fn endpoint_source_admitter<'a>(
        &'a self,
        source_node_addr: &[u8; 16],
    ) -> Option<FipsEndpointSourceAdmitter<'a>> {
        let peer = self.peer_for_endpoint_node_addr(source_node_addr)?;
        Some(FipsEndpointSourceAdmitter {
            runtime: self,
            peer,
        })
    }

    pub fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        self.peers
            .iter()
            .map(|peer| MeshPeerStatus {
                pubkey: peer.participant_pubkey_hex.clone(),
                connected: false,
                endpoint_npub: peer.endpoint_npub.clone().unwrap_or_default(),
                transport_addr: None,
                transport_type: None,
                srtt_ms: None,
                srtt_age_ms: None,
                link_packets_sent: 0,
                link_packets_recv: 0,
                link_bytes_sent: 0,
                link_bytes_recv: 0,
                rekey_in_progress: false,
                rekey_draining: false,
                current_k_bit: None,
                last_outbound_route: None,
                direct_probe_pending: false,
                direct_probe_after_ms: None,
                direct_probe_retry_count: 0,
                direct_probe_auto_reconnect: false,
                direct_probe_expires_at_ms: None,
                nostr_traversal_consecutive_failures: 0,
                nostr_traversal_in_cooldown: false,
                nostr_traversal_cooldown_until_ms: None,
                nostr_traversal_last_observed_skew_ms: None,
                last_seen_at: None,
                last_control_seen_at: None,
                last_data_seen_at: None,
                tx_bytes: 0,
                rx_bytes: 0,
                error: Some("fips link pending".to_string()),
            })
            .collect()
    }

    pub fn participant_for_endpoint_node_addr(
        &self,
        endpoint_node_addr: &[u8; 16],
    ) -> Option<String> {
        self.peer_for_endpoint_node_addr(endpoint_node_addr)
            .map(|peer| peer.participant_pubkey_hex.clone())
    }

    pub fn peer_endpoint_node_addr(&self, participant_pubkey: &str) -> Option<[u8; 16]> {
        let participant_pubkey = parse_nostr_pubkey_bytes(participant_pubkey)?;
        self.peer_endpoint_node_addr_for_participant_pubkey_bytes(&participant_pubkey)
    }

    pub fn peer_endpoint_node_addr_for_participant_pubkey_bytes(
        &self,
        participant_pubkey: &[u8; 32],
    ) -> Option<[u8; 16]> {
        self.peer_for_participant_pubkey_bytes(participant_pubkey)
            .and_then(|peer| peer.endpoint_node_addr)
    }

    pub fn peer_pubkeys(&self) -> Vec<String> {
        let mut pubkeys = Vec::new();
        for peer in self.peers.iter().chain(self.paid_route_peers.iter()) {
            if !pubkeys
                .iter()
                .any(|pubkey| pubkey == &peer.participant_pubkey_hex)
            {
                pubkeys.push(peer.participant_pubkey_hex.clone());
            }
        }
        pubkeys
    }

    fn peer_for_endpoint_node_addr(
        &self,
        endpoint_node_addr: &[u8; 16],
    ) -> Option<&FipsMeshPeerRuntime> {
        self.endpoint_node_addr_peer_index
            .get(endpoint_node_addr)
            .and_then(|peer_index| self.peers.get(*peer_index))
            .or_else(|| {
                self.paid_route_peers
                    .iter()
                    .find(|peer| peer.endpoint_node_addr.as_ref() == Some(endpoint_node_addr))
            })
    }

    fn peer_for_participant_pubkey_bytes(
        &self,
        participant_pubkey: &[u8; 32],
    ) -> Option<&FipsMeshPeerRuntime> {
        self.participant_peer_index
            .get(participant_pubkey)
            .and_then(|peer_index| self.peers.get(*peer_index))
            .or_else(|| {
                self.paid_route_peers
                    .iter()
                    .find(|peer| peer.participant_pubkey.as_ref() == Some(participant_pubkey))
            })
    }

    fn select_peer_for_ip(&self, destination: IpAddr) -> Option<&FipsMeshPeerRuntime> {
        self.select_route_for_ip(destination).peer()
    }

    fn select_route_for_ip(&self, destination: IpAddr) -> PeerRouteSelection<'_> {
        select_indexed_peer_for_ip(
            &self.peers,
            &self.exact_route_peer_index,
            &self.prefix_v4_route_peer_index,
            &self.prefix_v6_route_peer_index,
            destination,
        )
        .combine(select_indexed_peer_for_ip(
            &self.paid_route_routing_peers,
            &self.paid_exact_route_peer_index,
            &self.paid_prefix_v4_route_peer_index,
            &self.paid_prefix_v6_route_peer_index,
            destination,
        ))
    }

    fn peer_allows_inbound_destination(
        &self,
        peer: &FipsMeshPeerRuntime,
        destination: IpAddr,
    ) -> bool {
        let paid_participant = peer.participant_pubkey.as_ref();
        let paid_admission =
            paid_participant.and_then(|participant| self.paid_route_admissions.get(participant));
        if let Some(admission) = paid_admission {
            // Payment buys Internet egress, never private host/LAN or mesh
            // routes (including configured publicly numbered subnets).
            if !admission.allow_routing
                || !is_public_exit_destination(destination)
                || self
                    .select_local_route_for_ip(destination)
                    .is_some_and(|route| !route.is_default_route())
                || self
                    .select_route_for_ip(destination)
                    .prefix_len()
                    .is_some_and(|prefix| prefix != 0)
            {
                return false;
            }
            if let Some(destination_routes) = paid_participant
                .and_then(|participant| self.paid_route_destination_routes.get(participant))
                && !destination_routes.is_empty()
            {
                return destination_routes
                    .iter()
                    .any(|route| route.matches(destination));
            }
        }
        if self.local_routes.is_empty() {
            return true;
        }
        let Some(local_route) = self.select_local_route_for_ip(destination) else {
            return false;
        };
        if paid_admission.is_some() {
            return local_route.is_default_route();
        }
        true
    }

    fn select_local_route_for_ip(&self, destination: IpAddr) -> Option<IpRoute> {
        self.local_routes
            .iter()
            .copied()
            .filter(|route| route.matches(destination))
            .max_by_key(|route| route.prefix_len)
    }

    fn peer_uses_default_route(&self, peer: &FipsMeshPeerRuntime, address: IpAddr) -> bool {
        peer.routes
            .iter()
            .filter(|route| route.matches(address))
            .max_by_key(|route| route.prefix_len)
            .is_some_and(|route| route.is_default_route())
    }

    fn note_exit_outbound(&self, peer: &FipsMeshPeerRuntime, destination: IpAddr, packet: &[u8]) {
        if !self.peer_uses_default_route(peer, destination) {
            return;
        }
        let Some(peer) = peer.endpoint_node_addr else {
            return;
        };
        if let Ok(mut flows) = self.exit_flows.lock() {
            flows.note_outbound(peer, packet);
        }
    }

    pub fn note_cached_exit_outbound(&self, peer: [u8; 16], packet: &[u8]) {
        if let Ok(mut flows) = self.exit_flows.lock() {
            flows.note_outbound(peer, packet);
        }
    }

    fn admits_exit_inbound(
        &self,
        peer: &FipsMeshPeerRuntime,
        source: IpAddr,
        packet: &[u8],
    ) -> bool {
        if !self.peer_uses_default_route(peer, source) {
            return true;
        }
        let Some(peer) = peer.endpoint_node_addr else {
            return false;
        };
        self.exit_flows
            .lock()
            .is_ok_and(|mut flows| flows.admits_inbound(peer, packet))
    }
}

impl<'a> FipsEndpointSourceAdmitter<'a> {
    pub fn source_pubkey(&self) -> &'a str {
        &self.peer.participant_pubkey_hex
    }

    pub fn source_pubkey_bytes(&self) -> Option<&'a [u8; 32]> {
        self.peer.participant_pubkey.as_ref()
    }

    pub fn admit_packet_cached(&self, data: &[u8], cache: &mut FipsEndpointAdmissionCache) -> bool {
        self.admit_with_cache(data, Some(cache)).is_some()
    }

    pub fn receive_owned<B>(&self, data: B) -> Option<AcceptedFipsPacket<'a, B>>
    where
        B: AsRef<[u8]>,
    {
        self.admit(data.as_ref())?;
        Some(AcceptedFipsPacket {
            source_pubkey: &self.peer.participant_pubkey_hex,
            source_pubkey_bytes: self.peer.participant_pubkey.as_ref(),
            bytes: data,
        })
    }

    fn admit(&self, data: &[u8]) -> Option<&'a FipsMeshPeerRuntime> {
        self.admit_with_cache(data, None)
    }

    fn admit_with_cache(
        &self,
        data: &[u8],
        mut cache: Option<&mut FipsEndpointAdmissionCache>,
    ) -> Option<&'a FipsMeshPeerRuntime> {
        let (packet_source, packet_destination) = packet_endpoints(data)?;
        let source_allowed = match cache.as_mut() {
            Some(cache) => match cache.source {
                Some((source, allowed)) if source == packet_source => allowed,
                _ => {
                    let allowed = self.peer_allows_inbound_source(packet_source);
                    cache.source = Some((packet_source, allowed));
                    allowed
                }
            },
            None => self.peer_allows_inbound_source(packet_source),
        };
        if !source_allowed {
            return None;
        }

        let destination_allowed = match cache.as_mut() {
            Some(cache) => match cache.destination {
                Some((destination, allowed)) if destination == packet_destination => allowed,
                _ => {
                    let allowed = self
                        .runtime
                        .peer_allows_inbound_destination(self.peer, packet_destination);
                    cache.destination = Some((packet_destination, allowed));
                    allowed
                }
            },
            None => self
                .runtime
                .peer_allows_inbound_destination(self.peer, packet_destination),
        };
        if !destination_allowed {
            return None;
        }
        if !self
            .runtime
            .admits_exit_inbound(self.peer, packet_source, data)
        {
            return None;
        }
        Some(self.peer)
    }

    fn peer_allows_inbound_source(&self, source: IpAddr) -> bool {
        self.runtime
            .select_peer_for_ip(source)
            .is_some_and(|peer| same_participant(peer, self.peer))
    }
}

include!("fips_mesh/route_helpers.rs");

#[cfg(test)]

include!("fips_mesh/tests.rs");
