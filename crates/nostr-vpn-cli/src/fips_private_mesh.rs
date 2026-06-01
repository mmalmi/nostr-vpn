#![allow(dead_code)]

use anyhow::{Context, Result, anyhow};
use fips_endpoint::{
    Config, ConnectPolicy, FipsEndpoint, FipsEndpointError, FipsEndpointMessage, FipsEndpointPeer,
    NostrDiscoveryPolicy, PeerAddress, PeerConfig as FipsPeerConfig, RoutingMode,
    TransportInstances, UdpConfig,
};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, WireGuardExitConfig, derive_mesh_tunnel_ip, normalize_nostr_pubkey,
    split_peer_transport_addr,
};
use nostr_vpn_core::data_plane::{MeshPeerStatus, PrivatePacket};
use nostr_vpn_core::fips_control::{
    FipsControlFragmentBuffer, FipsControlFrame, NetworkRoster, PeerCapabilities, PeerEndpointHint,
    SignedRoster, decode_fips_control_frame, encode_fips_control_frame,
    encode_fips_control_messages,
};
use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
use nostr_vpn_core::join_requests::MeshJoinRequest;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::IoSlice;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{self, Write};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::mem::ManuallyDrop;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command as ProcessCommand;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle as ThreadJoinHandle};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::Interest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::io::unix::AsyncFd;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::sync::mpsc;

const FIPS_PEER_ONLINE_GRACE_SECS: u64 = 45;
const FIPS_NOSTR_DISCOVERY_APP: &str = "fips-overlay-v1";
const FIPS_LAN_DISCOVERY_SCOPE_PREFIX: &str = "nostr-vpn";
const FIPS_PEER_CAPS_GRACE_SECS: u64 = 600;
const FIPS_DISCOVERY_BACKOFF_BASE_SECS: u64 = 30;
const FIPS_DISCOVERY_BACKOFF_MAX_SECS: u64 = 300;
const FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS: u64 = 30;
const FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING: usize = 8;
const FIPS_NOSTR_FAILURE_STREAK_THRESHOLD: u32 = 2;
const FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS: u64 = 300;
const FIPS_PEER_ACTIVE_PING_INTERVAL_SECS: u64 = 10;
const FIPS_PEER_LINK_PING_INTERVAL_SECS: u64 = 15;
const FIPS_PEER_DISCOVERY_PROBE_INTERVAL_SECS: u64 = 120;
const FIPS_CONTROL_RTT_MAX_ACCEPT_MS: u128 = 10_000;
const MESH_LAN_UNDERLAY_UDP_MTU: u16 = 1420;
const MESH_LAN_TUNNEL_MTU: u16 = 1290;
const MESH_MIN_UNDERLAY_UDP_MTU: u16 = 1280;
const MESH_MIN_TUNNEL_MTU: u16 = 576;
const MESH_MAX_MTU: u16 = 9000;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const FIPS_TUN_READ_BURST: usize = 64;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const FIPS_MESH_SEND_BURST: usize = 64;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIPS_MESH_EVENT_DRAIN_LIMIT: usize = 256;
#[cfg(target_os = "windows")]
const WINDOWS_FIPS_TUN_READ_BURST: usize = 64;
#[cfg(target_os = "windows")]
const WINDOWS_FIPS_TUN_WRITE_BURST: usize = 64;

fn fips_lan_discovery_scope(network_id: &str) -> String {
    let digest = Sha256::digest(network_id.trim().as_bytes());
    format!(
        "{FIPS_LAN_DISCOVERY_SCOPE_PREFIX}:{}",
        hex::encode(&digest[..16])
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
use boringtun::device::{Error as TunError, tun::TunSocket};
#[cfg(target_os = "windows")]
use nostr_vpn_wintun::load_wintun;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::task::JoinHandle;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::time::{Duration, sleep};
#[cfg(target_os = "windows")]
use wintun::{Adapter, MAX_RING_CAPACITY, Session};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fips_host_tunnel::FipsHostTunnelConfig;

pub(crate) struct FipsPrivateMeshRuntime {
    endpoint: FipsEndpoint,
    mesh: RwLock<FipsMeshRuntime>,
    presence: RwLock<HashMap<String, FipsPeerPresence>>,
    link_status: RwLock<HashMap<String, FipsEndpointPeer>>,
    other_link_status: RwLock<HashMap<String, FipsEndpointPeer>>,
    peer_capabilities: RwLock<HashMap<String, PeerCapabilitiesEntry>>,
    control_fragments: Mutex<ControlFragmentBuffer>,
}

type ControlFragmentBuffer = FipsControlFragmentBuffer;

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct BorrowedTunFd(RawFd);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl AsRawFd for BorrowedTunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TunPipelinePacket {
    bytes: Vec<u8>,
    queued_at: Option<std::time::Instant>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunPipelinePacket {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            queued_at: crate::pipeline_profile::stamp(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FipsPeerPresence {
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    last_ping_started_at: Option<Instant>,
    rtt_ms: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MeshMtu {
    underlay_udp: u16,
    tunnel: u16,
}

fn private_mesh_mtu_from_app(app: Option<&AppConfig>) -> MeshMtu {
    let env_profile_raw = std::env::var("NVPN_MESH_MTU_PROFILE").ok();
    let env_profile = env_profile_raw.as_deref().and_then(non_empty_str);
    let config_profile = app.and_then(|app| non_empty_str(&app.mesh_mtu_profile));
    let env_underlay = parse_mtu_env("NVPN_MESH_UNDERLAY_UDP_MTU");
    let config_underlay = app.and_then(|app| non_zero_u16(app.mesh_underlay_udp_mtu));
    let env_tunnel = parse_mtu_env("NVPN_MESH_TUNNEL_MTU");
    let config_tunnel = app.and_then(|app| non_zero_u16(app.mesh_tunnel_mtu));

    resolve_private_mesh_mtu(
        env_profile.or(config_profile),
        env_underlay.or(config_underlay),
        env_tunnel.or(config_tunnel),
    )
}

fn resolve_private_mesh_mtu(
    profile: Option<&str>,
    underlay_override: Option<u16>,
    tunnel_override: Option<u16>,
) -> MeshMtu {
    let mut mtu = match normalized_mtu_profile(profile).as_deref() {
        Some("lan") => MeshMtu {
            underlay_udp: MESH_LAN_UNDERLAY_UDP_MTU,
            tunnel: MESH_LAN_TUNNEL_MTU,
        },
        _ => MeshMtu {
            underlay_udp: nostr_vpn_core::MESH_UNDERLAY_UDP_MTU,
            tunnel: nostr_vpn_core::MESH_TUNNEL_MTU,
        },
    };

    if let Some(underlay_udp) = clamp_mtu(underlay_override, MESH_MIN_UNDERLAY_UDP_MTU) {
        mtu.underlay_udp = underlay_udp;
        if tunnel_override.is_none() {
            mtu.tunnel = tunnel_mtu_for_underlay(underlay_udp);
        }
    }
    if let Some(tunnel) = clamp_mtu(tunnel_override, MESH_MIN_TUNNEL_MTU) {
        mtu.tunnel = tunnel;
    }

    let max_tunnel = tunnel_mtu_for_underlay(mtu.underlay_udp);
    if mtu.tunnel > max_tunnel {
        mtu.tunnel = max_tunnel;
    }
    mtu
}

fn normalized_mtu_profile(profile: Option<&str>) -> Option<String> {
    let profile = profile?.trim();
    if profile.is_empty() {
        return None;
    }
    Some(profile.to_ascii_lowercase())
}

fn parse_mtu_env(name: &str) -> Option<u16> {
    std::env::var(name).ok()?.trim().parse::<u16>().ok()
}

fn fips_nostr_discovery_policy_from_env() -> NostrDiscoveryPolicy {
    std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY")
        .ok()
        .as_deref()
        .and_then(parse_fips_nostr_discovery_policy)
        .unwrap_or(NostrDiscoveryPolicy::Open)
}

fn fips_nostr_discovery_policy_from_app(app: &AppConfig) -> NostrDiscoveryPolicy {
    std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY")
        .ok()
        .as_deref()
        .and_then(parse_fips_nostr_discovery_policy)
        .unwrap_or(if app.connect_to_non_roster_fips_peers {
            NostrDiscoveryPolicy::Open
        } else {
            NostrDiscoveryPolicy::ConfiguredOnly
        })
}

fn parse_fips_nostr_discovery_policy(value: &str) -> Option<NostrDiscoveryPolicy> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "disabled" | "off" | "false" | "0" => Some(NostrDiscoveryPolicy::Disabled),
        "configured_only" | "configuredonly" | "configured" => {
            Some(NostrDiscoveryPolicy::ConfiguredOnly)
        }
        "open" | "true" | "1" => Some(NostrDiscoveryPolicy::Open),
        _ => None,
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn non_zero_u16(value: u16) -> Option<u16> {
    (value != 0).then_some(value)
}

fn clamp_mtu(value: Option<u16>, min: u16) -> Option<u16> {
    value.map(|mtu| mtu.clamp(min, MESH_MAX_MTU))
}

fn tunnel_mtu_for_underlay(underlay_udp_mtu: u16) -> u16 {
    let tunnel_headroom =
        nostr_vpn_core::MESH_UNDERLAY_UDP_MTU.saturating_sub(nostr_vpn_core::MESH_TUNNEL_MTU);
    underlay_udp_mtu
        .saturating_sub(tunnel_headroom)
        .max(MESH_MIN_TUNNEL_MTU)
}

fn exit_node_ipv4_mss_clamp(tunnel_mtu: u16) -> u16 {
    tunnel_mtu.saturating_sub(40).max(536)
}

#[derive(Debug, Clone)]
struct PeerCapabilitiesEntry {
    capabilities: PeerCapabilities,
    received_at: u64,
}

fn fips_peer_liveness(
    last_seen_at: Option<u64>,
    link_connected: bool,
    peer_error: Option<String>,
    now: u64,
) -> (bool, Option<String>) {
    let presence_connected = last_seen_at.is_some_and(|last_seen_at| {
        now.saturating_sub(last_seen_at) <= FIPS_PEER_ONLINE_GRACE_SECS
    });
    if presence_connected {
        return (true, None);
    }
    if link_connected {
        return (true, None);
    }
    (
        false,
        peer_error.or_else(|| Some("fips link pending".to_string())),
    )
}

fn fips_peer_ping_interval_secs(last_seen_at: Option<u64>, link_connected: bool, now: u64) -> u64 {
    if last_seen_at
        .is_some_and(|last_seen_at| now.saturating_sub(last_seen_at) <= FIPS_PEER_ONLINE_GRACE_SECS)
    {
        FIPS_PEER_ACTIVE_PING_INTERVAL_SECS
    } else if link_connected {
        FIPS_PEER_LINK_PING_INTERVAL_SECS
    } else {
        FIPS_PEER_DISCOVERY_PROBE_INTERVAL_SECS
    }
}

fn fips_peer_ping_due(
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    link_connected: bool,
    now: u64,
) -> bool {
    let interval = fips_peer_ping_interval_secs(last_seen_at, link_connected, now);
    last_ping_sent_at.is_none_or(|sent_at| now.saturating_sub(sent_at) >= interval)
}

fn mesh_status_from_endpoint_peer(
    pubkey: String,
    peer: &FipsEndpointPeer,
    now: u64,
) -> MeshPeerStatus {
    MeshPeerStatus {
        pubkey,
        connected: true,
        endpoint_npub: normalize_fips_endpoint_npub(&peer.npub),
        transport_addr: peer.transport_addr.clone(),
        transport_type: peer.transport_type.clone(),
        srtt_ms: peer.srtt_ms,
        link_packets_sent: peer.packets_sent,
        link_packets_recv: peer.packets_recv,
        link_bytes_sent: peer.bytes_sent,
        link_bytes_recv: peer.bytes_recv,
        last_seen_at: Some(now),
        tx_bytes: 0,
        rx_bytes: 0,
        error: None,
    }
}

fn endpoint_peer_status_pubkey(peer: &FipsEndpointPeer) -> Option<String> {
    normalize_nostr_pubkey(&peer.npub).ok()
}

fn other_endpoint_peer_statuses(
    other_link_status: &HashMap<String, FipsEndpointPeer>,
    now: u64,
) -> Vec<MeshPeerStatus> {
    let mut statuses = other_link_status
        .values()
        .filter_map(|peer| {
            endpoint_peer_status_pubkey(peer)
                .map(|pubkey| mesh_status_from_endpoint_peer(pubkey, peer, now))
        })
        .collect::<Vec<_>>();
    statuses.sort_by(|left, right| left.pubkey.cmp(&right.pubkey));
    statuses.dedup_by(|left, right| left.pubkey == right.pubkey);
    statuses
}

fn peer_endpoint_hint_addr(hint: &PeerEndpointHint) -> Option<String> {
    nostr_vpn_core::fips_control::peer_endpoint_hint_addr(hint)
}

fn endpoint_addr_ip(addr: &str) -> Option<IpAddr> {
    let trimmed = addr.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return Some(parsed.ip());
    }

    let (host, _) = trimmed.rsplit_once(':')?;
    host.trim().parse::<IpAddr>().ok()
}

fn endpoint_uses_tunnel_ip(addr: &str, tunnel_ips: &HashSet<IpAddr>) -> bool {
    endpoint_addr_ip(addr).is_some_and(|ip| tunnel_ips.contains(&ip))
}

fn filter_static_tunnel_endpoints(
    groups: Vec<(String, Vec<String>)>,
    tunnel_ips: &HashSet<IpAddr>,
) -> Vec<(String, Vec<String>)> {
    groups
        .into_iter()
        .filter_map(|(participant, addrs)| {
            let addrs = addrs
                .into_iter()
                .filter(|addr| !endpoint_uses_tunnel_ip(addr, tunnel_ips))
                .collect::<Vec<_>>();
            (!addrs.is_empty()).then_some((participant, addrs))
        })
        .collect()
}

fn filter_stamped_tunnel_endpoints(
    groups: Vec<(String, Vec<(String, u64)>)>,
    tunnel_ips: &HashSet<IpAddr>,
) -> Vec<(String, Vec<(String, u64)>)> {
    groups
        .into_iter()
        .filter_map(|(participant, addrs)| {
            let addrs = addrs
                .into_iter()
                .filter(|(addr, _)| !endpoint_uses_tunnel_ip(addr, tunnel_ips))
                .collect::<Vec<_>>();
            (!addrs.is_empty()).then_some((participant, addrs))
        })
        .collect()
}

fn fips_tunnel_endpoint_hosts(app: &AppConfig, network_id: &str) -> HashSet<IpAddr> {
    let mut hosts = HashSet::new();
    if let Ok(ip) = strip_cidr(&app.node.tunnel_ip).parse::<IpAddr>() {
        hosts.insert(ip);
    }
    for participant in app.participant_pubkeys_hex() {
        if let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &participant)
            && let Ok(ip) = strip_cidr(&tunnel_ip).parse::<IpAddr>()
        {
            hosts.insert(ip);
        }
    }
    hosts
}

// The historical FIPS endpoint cache (`daemon.fips-cache.json`) persisted observed
// peer transport addresses across daemon restarts. For peers reached via NAT
// traversal the observed address is an ephemeral source port that closes when
// the session ends; replaying it on the next start makes fips-core dial a dead
// socket forever instead of falling back to udp:nat traversal. The cache is gone;
// peer endpoint discovery is delegated to fips-core's overlay (Nostr advert +
// udp:nat). Any stale cache file from older builds is removed at startup.
pub(crate) fn legacy_fips_endpoint_cache_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.fips-cache.json")
}

pub(crate) fn purge_legacy_fips_endpoint_cache(config_path: &Path) {
    let path = legacy_fips_endpoint_cache_file_path(config_path);
    if let Err(error) = fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "daemon: failed to remove legacy FIPS endpoint cache {}: {error}",
            path.display()
        );
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FipsRelayStatus {
    pub(crate) url: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone)]
pub(crate) enum FipsPrivateMeshEvent {
    Packet(PrivatePacket),
    Presence {
        participant_pubkey: String,
        last_seen_at: u64,
    },
    JoinRequest {
        sender_pubkey: String,
        requested_at: u64,
        request: MeshJoinRequest,
    },
    Roster {
        sender_pubkey: String,
        network_id: String,
        roster: NetworkRoster,
        signed_roster: Option<Box<SignedRoster>>,
    },
    Capabilities {
        sender_pubkey: String,
        network_id: String,
        capabilities: PeerCapabilities,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn drain_event_batch(
    event_rx: &mut mpsc::Receiver<FipsPrivateMeshEvent>,
    limit: usize,
) -> Vec<FipsPrivateMeshEvent> {
    let mut events = Vec::new();
    for _ in 0..limit {
        let Ok(event) = event_rx.try_recv() else {
            break;
        };
        events.push(event);
    }
    events
}

impl FipsPrivateMeshRuntime {
    pub(crate) async fn bind(
        identity_nsec: impl Into<String>,
        network_id: impl AsRef<str>,
        peers: Vec<FipsMeshPeerConfig>,
    ) -> Result<Self> {
        let scope = fips_lan_discovery_scope(network_id.as_ref());
        let endpoint_peers = fips_endpoint_peers_from_mesh(&peers, Vec::new(), Vec::new());
        let config = fips_endpoint_config(
            &endpoint_peers,
            None,
            private_mesh_mtu_from_app(None),
            fips_nostr_discovery_policy_from_env(),
        );
        Self::bind_with_config(identity_nsec, scope, peers, config, Vec::new()).await
    }

    async fn bind_with_config(
        identity_nsec: impl Into<String>,
        scope: impl Into<String>,
        peers: Vec<FipsMeshPeerConfig>,
        config: Config,
        local_allowed_ips: Vec<String>,
    ) -> Result<Self> {
        let scope = scope.into();
        let endpoint = FipsEndpoint::builder()
            .config(config)
            .identity_nsec(identity_nsec)
            .discovery_scope(scope)
            .without_system_tun()
            .bind()
            .await
            .context("failed to bind embedded FIPS endpoint")?;

        Ok(Self {
            endpoint,
            mesh: RwLock::new(FipsMeshRuntime::with_local_routes(peers, local_allowed_ips)),
            presence: RwLock::new(HashMap::new()),
            link_status: RwLock::new(HashMap::new()),
            other_link_status: RwLock::new(HashMap::new()),
            peer_capabilities: RwLock::new(HashMap::new()),
            control_fragments: Mutex::new(ControlFragmentBuffer::default()),
        })
    }

    pub(crate) fn npub(&self) -> &str {
        self.endpoint.npub()
    }

    pub(crate) async fn send_tunnel_packet(&self, packet: &[u8]) -> Result<bool> {
        let outgoing = {
            self.mesh
                .read()
                .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
                .route_outbound_packet(packet)
        };
        let Some(outgoing) = outgoing else {
            return Ok(false);
        };

        let bytes_len = outgoing.bytes.len();
        self.endpoint
            .send(outgoing.endpoint_npub, outgoing.bytes)
            .await
            .context("failed to send private packet over FIPS endpoint data")?;
        self.note_tx(&outgoing.participant_pubkey, bytes_len)?;
        Ok(true)
    }

    pub(crate) async fn send_tunnel_packet_owned(&self, packet: Vec<u8>) -> Result<bool> {
        let outgoing = {
            self.mesh
                .read()
                .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
                .route_outbound_packet_owned(packet)
        };
        let Some(outgoing) = outgoing else {
            return Ok(false);
        };

        let bytes_len = outgoing.bytes.len();
        self.endpoint
            .send(outgoing.endpoint_npub, outgoing.bytes)
            .await
            .context("failed to send private packet over FIPS endpoint data")?;
        self.note_tx(&outgoing.participant_pubkey, bytes_len)?;
        Ok(true)
    }

    pub(crate) async fn recv_mesh_event(&self) -> Result<Option<FipsPrivateMeshEvent>> {
        loop {
            let Some(message) = self.endpoint.recv().await else {
                return Ok(None);
            };

            if let Some(event) = self.endpoint_message_to_mesh_event(message).await? {
                return Ok(Some(event));
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) async fn try_recv_mesh_event(&self) -> Result<Option<FipsPrivateMeshEvent>> {
        loop {
            let Some(message) = self.endpoint.try_recv() else {
                return Ok(None);
            };

            if let Some(event) = self.endpoint_message_to_mesh_event(message).await? {
                return Ok(Some(event));
            }
        }
    }

    async fn endpoint_message_to_mesh_event(
        &self,
        message: FipsEndpointMessage,
    ) -> Result<Option<FipsPrivateMeshEvent>> {
        if let Some(frame) = self.decode_endpoint_control_frame(&message)? {
            let source_pubkey = {
                let mesh = self
                    .mesh
                    .read()
                    .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?;
                control_frame_source_pubkey(&mesh, message.source_npub.as_deref(), &frame)
            };
            let Some(source_pubkey) = source_pubkey else {
                return Ok(None);
            };
            let now = unix_timestamp();
            self.note_rx(&source_pubkey, message.data.len(), now)?;
            match frame {
                FipsControlFrame::Ping {
                    network_id,
                    sent_at,
                } => {
                    let reply = FipsControlFrame::Pong {
                        network_id,
                        sent_at,
                        replied_at: now,
                    };
                    if let Some(source_npub) = message.source_npub {
                        let encoded = encode_fips_control_frame(&reply)?;
                        if let Err(error) = self.endpoint.send(source_npub, encoded).await {
                            eprintln!("fips: failed to reply to peer ping: {error}");
                        }
                    }
                    return Ok(Some(FipsPrivateMeshEvent::Presence {
                        participant_pubkey: source_pubkey,
                        last_seen_at: now,
                    }));
                }
                FipsControlFrame::Pong { sent_at, .. } => {
                    self.note_pong(&source_pubkey, sent_at)?;
                    return Ok(Some(FipsPrivateMeshEvent::Presence {
                        participant_pubkey: source_pubkey,
                        last_seen_at: now,
                    }));
                }
                FipsControlFrame::JoinRequest {
                    requested_at,
                    request,
                } => {
                    return Ok(Some(FipsPrivateMeshEvent::JoinRequest {
                        sender_pubkey: source_pubkey,
                        requested_at,
                        request,
                    }));
                }
                FipsControlFrame::Roster {
                    network_id,
                    roster,
                    signed_roster,
                } => {
                    return Ok(Some(FipsPrivateMeshEvent::Roster {
                        sender_pubkey: source_pubkey,
                        network_id,
                        roster,
                        signed_roster,
                    }));
                }
                FipsControlFrame::Capabilities {
                    network_id,
                    capabilities,
                } => {
                    self.record_peer_capabilities(&source_pubkey, &capabilities, now)?;
                    return Ok(Some(FipsPrivateMeshEvent::Capabilities {
                        sender_pubkey: source_pubkey,
                        network_id,
                        capabilities,
                    }));
                }
                FipsControlFrame::Fragment { .. } => return Ok(None),
            }
        }

        let data_len = message.data.len();
        if let Some(packet) = self
            .mesh
            .read()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
            .receive_endpoint_data_owned(message.source_npub.as_deref(), message.data)
        {
            let now = unix_timestamp();
            self.note_rx(&packet.source_pubkey, data_len, now)?;
            return Ok(Some(FipsPrivateMeshEvent::Packet(packet)));
        }

        Ok(None)
    }

    fn decode_endpoint_control_frame(
        &self,
        message: &FipsEndpointMessage,
    ) -> Result<Option<FipsControlFrame>> {
        let Some(frame) = decode_fips_control_frame(&message.data)? else {
            return Ok(None);
        };
        let FipsControlFrame::Fragment {
            id,
            index,
            total,
            data,
        } = frame
        else {
            return Ok(Some(frame));
        };

        let Some(source_npub) = message.source_npub.as_deref() else {
            return Ok(None);
        };
        let Some(reassembled) = self
            .control_fragments
            .lock()
            .map_err(|_| anyhow!("FIPS control fragment buffer lock poisoned"))?
            .push(source_npub, id, index, total, data, unix_timestamp())?
        else {
            return Ok(None);
        };
        decode_fips_control_frame(&reassembled)
    }

    #[cfg(test)]
    pub(crate) async fn recv_tunnel_packet(&self) -> Result<Option<PrivatePacket>> {
        loop {
            match self.recv_mesh_event().await? {
                Some(FipsPrivateMeshEvent::Packet(packet)) => return Ok(Some(packet)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        let now = unix_timestamp();
        let presence = self.presence.read().ok();
        let link_status = self.link_status.read().ok();
        let other_link_status = self.other_link_status.read().ok();
        let mut statuses = self
            .mesh
            .read()
            .map(|mesh| mesh.peer_statuses())
            .unwrap_or_default();
        for status in &mut statuses {
            let peer_presence = presence
                .as_ref()
                .and_then(|presence| presence.get(&status.pubkey));
            let peer_link = link_status
                .as_ref()
                .and_then(|link_status| link_status.get(&status.pubkey));
            status.last_seen_at = peer_presence.and_then(|value| value.last_seen_at);
            status.tx_bytes = peer_presence.map(|value| value.tx_bytes).unwrap_or(0);
            status.rx_bytes = peer_presence.map(|value| value.rx_bytes).unwrap_or(0);
            if let Some(peer_link) = peer_link {
                status.endpoint_npub = peer_link.npub.clone();
                status.transport_addr = peer_link.transport_addr.clone();
                status.transport_type = peer_link.transport_type.clone();
                status.srtt_ms = peer_link.srtt_ms;
                status.link_packets_sent = peer_link.packets_sent;
                status.link_packets_recv = peer_link.packets_recv;
                status.link_bytes_sent = peer_link.bytes_sent;
                status.link_bytes_recv = peer_link.bytes_recv;
            }
            if status.srtt_ms.is_none() {
                status.srtt_ms = peer_presence.and_then(|value| value.rtt_ms);
            }
            let link_connected = peer_link.is_some();
            let (connected, error) = fips_peer_liveness(
                status.last_seen_at,
                link_connected,
                peer_presence.and_then(|value| value.error.clone()),
                now,
            );
            status.connected = connected;
            status.error = error;
        }
        if let Some(other_link_status) = other_link_status {
            statuses.extend(other_endpoint_peer_statuses(&other_link_status, now));
        }
        statuses.sort_by(|left, right| left.pubkey.cmp(&right.pubkey));
        statuses.dedup_by(|left, right| left.pubkey == right.pubkey);
        statuses
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        let endpoint_peers = self
            .endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")?;
        let mesh = self
            .mesh
            .read()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?;
        let mut link_status = HashMap::new();
        let mut other_link_status = HashMap::new();
        for peer in endpoint_peers {
            if let Some(participant) = mesh.participant_for_endpoint_npub(&peer.npub) {
                link_status.insert(participant, peer);
            } else if let Some(pubkey) = endpoint_peer_status_pubkey(&peer) {
                other_link_status.insert(pubkey, peer);
            }
        }
        *self
            .link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))? = link_status;
        *self
            .other_link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh other link status lock poisoned"))? = other_link_status;
        Ok(())
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        self.endpoint
            .relay_statuses()
            .await
            .context("failed to snapshot FIPS endpoint relays")
            .map(|relays| {
                relays
                    .into_iter()
                    .map(|relay| FipsRelayStatus {
                        url: relay.url,
                        status: relay.status,
                    })
                    .collect()
            })
    }

    pub(crate) async fn update_relays(&self, relays: &[String]) -> Result<()> {
        self.endpoint
            .update_relays(relays.to_vec(), relays.to_vec())
            .await
            .context("failed to update FIPS endpoint relays")
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        self.mesh
            .read()
            .map(|mesh| mesh.peer_pubkeys())
            .unwrap_or_default()
    }

    fn ping_due_participants(&self, now: u64) -> Result<Vec<String>> {
        let participants = self
            .mesh
            .read()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
            .peer_pubkeys();
        let presence = self
            .presence
            .read()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        let link_status = self
            .link_status
            .read()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?;
        Ok(participants
            .into_iter()
            .filter(|participant| {
                let peer_presence = presence.get(participant);
                let link_connected = link_status.contains_key(participant);
                fips_peer_ping_due(
                    peer_presence.and_then(|value| value.last_seen_at),
                    peer_presence.and_then(|value| value.last_ping_sent_at),
                    link_connected,
                    now,
                )
            })
            .collect())
    }

    /// Snapshot `(endpoint_npub, transport-tagged addr)` pairs for every peer
    /// that currently has an authenticated FIPS link, including open-discovery
    /// transit peers outside the private-network roster. Used by the daemon
    /// heartbeat to update the on-disk recent-peers cache so restarts can seed
    /// useful overlay peers before relay discovery has warmed up.
    pub(crate) async fn authenticated_peer_transport_addrs(&self) -> Result<Vec<(String, String)>> {
        let peers = self
            .endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")?;
        Ok(peers
            .into_iter()
            .filter_map(|peer| {
                tag_authenticated_transport_addr(peer.transport_addr, peer.transport_type)
                    .map(|addr| (peer.npub, addr))
            })
            .collect())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) async fn peer_transport_ipv4_hosts(&self) -> Result<Vec<Ipv4Addr>> {
        let mut hosts = self
            .endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")?
            .into_iter()
            .filter_map(|peer| peer.transport_addr)
            .filter_map(|addr| endpoint_transport_ipv4_host(&addr))
            .collect::<Vec<_>>();
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }

    pub(crate) fn replace_peers(
        &self,
        peers: Vec<FipsMeshPeerConfig>,
        local_allowed_ips: Vec<String>,
    ) -> Result<()> {
        *self
            .mesh
            .write()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))? =
            FipsMeshRuntime::with_local_routes(peers, local_allowed_ips);
        let configured = self
            .mesh
            .read()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
            .peer_pubkeys();
        self.presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        self.link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        self.other_link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh other link status lock poisoned"))?
            .clear();
        self.peer_capabilities
            .write()
            .map_err(|_| anyhow!("FIPS mesh peer capabilities lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        Ok(())
    }

    pub(crate) fn peer_advertised_routes(&self, participant: &str) -> Vec<String> {
        let normalized = match normalize_nostr_pubkey(participant) {
            Ok(value) => value,
            Err(_) => return Vec::new(),
        };
        let now = unix_timestamp();
        let caps = match self.peer_capabilities.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        caps.get(&normalized)
            .filter(|entry| now.saturating_sub(entry.received_at) <= FIPS_PEER_CAPS_GRACE_SECS)
            .map(|entry| entry.capabilities.advertised_routes.clone())
            .unwrap_or_default()
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        let now = unix_timestamp();
        let caps = match self.peer_capabilities.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let mut out = caps
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.received_at) <= FIPS_PEER_CAPS_GRACE_SECS)
            .filter_map(|(participant, entry)| {
                let mut addresses = entry
                    .capabilities
                    .endpoint_hints
                    .iter()
                    .filter_map(peer_endpoint_hint_addr)
                    .map(|addr| (addr, entry.received_at.saturating_mul(1000)))
                    .collect::<Vec<_>>();
                addresses.sort_by(|left, right| left.0.cmp(&right.0));
                addresses.dedup_by(|left, right| left.0 == right.0);
                (!addresses.is_empty()).then_some((participant.clone(), addresses))
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.0.cmp(&right.0));
        out
    }

    fn record_peer_capabilities(
        &self,
        participant: &str,
        capabilities: &PeerCapabilities,
        now: u64,
    ) -> Result<()> {
        let normalized = normalize_nostr_pubkey(participant)?;
        let mut caps = self
            .peer_capabilities
            .write()
            .map_err(|_| anyhow!("FIPS mesh peer capabilities lock poisoned"))?;
        match caps.get(&normalized) {
            Some(existing) if existing.capabilities.signed_at > capabilities.signed_at => {
                return Ok(());
            }
            _ => {}
        }
        caps.insert(
            normalized,
            PeerCapabilitiesEntry {
                capabilities: capabilities.clone(),
                received_at: now,
            },
        );
        Ok(())
    }

    pub(crate) async fn ping_peers(&self, network_id: &str, now: u64) -> Result<usize> {
        let frame = FipsControlFrame::Ping {
            network_id: network_id.to_string(),
            sent_at: now,
        };
        let participants = self.ping_due_participants(now)?;
        let mut sent = 0usize;
        for participant in participants {
            self.note_ping_attempt(&participant, now)?;
            if self.send_control_frame(&participant, &frame).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub(crate) async fn send_join_request(
        &self,
        participant: &str,
        requested_at: u64,
        request: MeshJoinRequest,
    ) -> Result<()> {
        self.send_control_frame(
            participant,
            &FipsControlFrame::JoinRequest {
                requested_at,
                request,
            },
        )
        .await
    }

    pub(crate) async fn send_roster(
        &self,
        participant: &str,
        signed_roster: SignedRoster,
    ) -> Result<()> {
        let network_id = signed_roster.network_id()?;
        let roster = signed_roster.roster()?;
        self.send_control_frame(
            participant,
            &FipsControlFrame::Roster {
                network_id,
                roster,
                signed_roster: Some(Box::new(signed_roster)),
            },
        )
        .await
    }

    pub(crate) async fn send_capabilities(
        &self,
        participant: &str,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<()> {
        self.send_control_frame(
            participant,
            &FipsControlFrame::Capabilities {
                network_id: network_id.to_string(),
                capabilities,
            },
        )
        .await
    }

    pub(crate) async fn broadcast_capabilities(
        &self,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<usize> {
        let frame = FipsControlFrame::Capabilities {
            network_id: network_id.to_string(),
            capabilities,
        };
        self.broadcast_control_frame(&frame).await
    }

    async fn broadcast_control_frame(&self, frame: &FipsControlFrame) -> Result<usize> {
        let participants = self
            .mesh
            .read()
            .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?
            .peer_pubkeys();
        let mut sent = 0usize;
        for participant in participants {
            if self.send_control_frame(&participant, frame).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    async fn send_control_frame(&self, participant: &str, frame: &FipsControlFrame) -> Result<()> {
        let endpoint_npub = {
            let mesh = self
                .mesh
                .read()
                .map_err(|_| anyhow!("FIPS mesh route table lock poisoned"))?;
            control_frame_destination_npub(&mesh, participant)?
        };
        let messages = encode_fips_control_messages(frame)?;
        let mut sent_len = 0usize;
        for encoded in messages {
            sent_len += encoded.len();
            self.endpoint
                .send(endpoint_npub.clone(), encoded)
                .await
                .with_context(|| format!("failed to send FIPS control frame to {participant}"))?;
        }
        self.note_tx(participant, sent_len)?;
        Ok(())
    }

    fn note_tx(&self, participant: &str, len: usize) -> Result<()> {
        // Hot path. Caller passes a hex pubkey that was normalized at config
        // load time (see fips_mesh.rs `normalize_participant_pubkey`); a
        // round-trip through `normalize_nostr_pubkey` here would re-parse
        // the secp256k1 point and burn 30%+ of CPU under load just to
        // produce a hashmap key. Trust the caller; allocate only on first
        // sight of a key.
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(participant) {
            entry.tx_bytes = entry.tx_bytes.saturating_add(len as u64);
        } else {
            let entry = FipsPeerPresence {
                tx_bytes: len as u64,
                ..Default::default()
            };
            presence.insert(participant.to_string(), entry);
        }
        Ok(())
    }

    fn note_ping_attempt(&self, participant: &str, now: u64) -> Result<()> {
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(participant) {
            entry.last_ping_sent_at = Some(now);
            entry.last_ping_started_at = Some(Instant::now());
        } else {
            let entry = FipsPeerPresence {
                last_ping_sent_at: Some(now),
                last_ping_started_at: Some(Instant::now()),
                ..Default::default()
            };
            presence.insert(participant.to_string(), entry);
        }
        Ok(())
    }

    fn note_pong(&self, participant: &str, sent_at: u64) -> Result<()> {
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        let Some(entry) = presence.get_mut(participant) else {
            return Ok(());
        };
        if entry.last_ping_sent_at == Some(sent_at)
            && let Some(started_at) = entry.last_ping_started_at.take()
        {
            let elapsed_ms = started_at.elapsed().as_millis();
            if elapsed_ms <= FIPS_CONTROL_RTT_MAX_ACCEPT_MS {
                entry.rtt_ms = Some(elapsed_ms.min(u128::from(u64::MAX)) as u64);
            } else {
                entry.last_ping_sent_at = None;
            }
        }
        Ok(())
    }

    fn note_rx(&self, participant: &str, len: usize, now: u64) -> Result<()> {
        // Hot path; see note_tx for why the EC-point normalize is omitted
        // and why we side-step the entry API to avoid per-packet allocs.
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(participant) {
            entry.last_seen_at = Some(now);
            entry.rx_bytes = entry.rx_bytes.saturating_add(len as u64);
            entry.error = None;
        } else {
            let entry = FipsPeerPresence {
                last_seen_at: Some(now),
                rx_bytes: len as u64,
                error: None,
                ..Default::default()
            };
            presence.insert(participant.to_string(), entry);
        }
        Ok(())
    }

    pub(crate) async fn shutdown(self) -> Result<(), FipsEndpointError> {
        self.endpoint.shutdown().await
    }

    /// Hand the latest peer roster to fips without restarting the endpoint.
    ///
    /// The wrapper translates nvpn's intermediate hint shape
    /// ([`FipsEndpointPeerTransportConfig`]) into `fips_endpoint::PeerConfig`
    /// (carrying `seen_at_ms` per address) and calls
    /// [`fips_endpoint::FipsEndpoint::update_peers`]. fips diffs new vs old,
    /// initiates connections for fresh npubs, drops retry entries for
    /// removed ones, and refreshes address hints in place for the rest.
    pub(crate) async fn update_peers(
        &self,
        endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        let peers: Vec<FipsPeerConfig> = endpoint_peers
            .iter()
            .map(|peer| FipsPeerConfig {
                npub: peer.npub.clone(),
                alias: None,
                addresses: peer
                    .addresses
                    .iter()
                    .map(fips_peer_address_from_hint)
                    .collect(),
                connect_policy: ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                discovery_fallback_transit: peer.discovery_fallback_transit,
            })
            .collect();
        self.endpoint
            .update_peers(peers)
            .await
            .context("fips: update_peers rejected by endpoint")
    }
}

fn control_frame_source_pubkey(
    mesh: &FipsMeshRuntime,
    source_npub: Option<&str>,
    frame: &FipsControlFrame,
) -> Option<String> {
    let source_npub = source_npub?;
    mesh.participant_for_endpoint_npub(source_npub).or_else(|| {
        matches!(frame, FipsControlFrame::JoinRequest { .. })
            .then(|| normalize_nostr_pubkey(source_npub).ok())
            .flatten()
    })
}

fn control_frame_destination_npub(mesh: &FipsMeshRuntime, participant: &str) -> Result<String> {
    if let Some(endpoint_npub) = mesh.peer_endpoint_npub(participant) {
        return Ok(endpoint_npub);
    }

    let participant_pubkey = normalize_nostr_pubkey(participant)
        .with_context(|| format!("invalid FIPS control frame recipient {participant}"))?;
    PublicKey::parse(&participant_pubkey)
        .ok()
        .and_then(|pubkey| pubkey.to_bech32().ok())
        .ok_or_else(|| anyhow!("invalid FIPS control frame recipient {participant}"))
}

#[derive(Debug, Clone)]
struct FipsEndpointTransportConfig {
    listen_port: u16,
    advertised_endpoint: String,
    advertise_endpoint: bool,
    /// Find/advertise peers over Nostr relays. When false, the endpoint still
    /// dials static/bootstrap peers and does LAN discovery, but does not use
    /// relays for endpoint discovery or advertising.
    nostr_discovery_enabled: bool,
    stun_servers: Vec<String>,
    nostr_relays: Vec<String>,
    share_local_candidates: bool,
}

/// Address hint carried through nvpn's intermediate config types before
/// being lowered into a fips `PeerAddress`. `seen_at_ms` is the
/// most-recent observation timestamp (Unix ms) when we have one — set for
/// recent-peers cache entries, `None` for operator-supplied static hints.
/// fips's dialer ranks candidates by this field descending, so cached
/// addresses sort ahead of unstamped hints in the same try-everything pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsPeerAddressHint {
    pub(crate) addr: String,
    pub(crate) seen_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsEndpointPeerTransportConfig {
    pub(crate) npub: String,
    pub(crate) addresses: Vec<FipsPeerAddressHint>,
    pub(crate) discovery_fallback_transit: bool,
}

fn fips_peer_address_from_hint(hint: &FipsPeerAddressHint) -> PeerAddress {
    let (transport, addr) = split_peer_transport_addr(&hint.addr);
    let mut peer_address = PeerAddress::new(transport, addr);
    if let Some(seen_at_ms) = hint.seen_at_ms {
        peer_address = peer_address.with_seen_at_ms(seen_at_ms);
    }
    peer_address
}

fn fips_endpoint_config(
    peers: &[FipsEndpointPeerTransportConfig],
    transport: Option<&FipsEndpointTransportConfig>,
    mesh_mtu: MeshMtu,
    nostr_discovery_policy: NostrDiscoveryPolicy,
) -> Config {
    let mut config = Config::new();
    config.node.control.enabled = false;
    // App mesh peers may be routable only through already-connected
    // neighbors when direct NAT traversal fails. Reply-learned routing lets
    // first-contact EndpointData trigger discovery through those neighbors.
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.dns.enabled = false;
    // nvpn keeps public/open discovery available as a fallback, but it should
    // be polite to public transit nodes when stale roster peers or cached
    // adverts cannot be reached.
    config.node.discovery.backoff_base_secs = FIPS_DISCOVERY_BACKOFF_BASE_SECS;
    config.node.discovery.backoff_max_secs = FIPS_DISCOVERY_BACKOFF_MAX_SECS;
    config.node.discovery.forward_min_interval_secs = FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS;
    let advertise_udp = transport
        .map(|transport| transport.advertise_endpoint)
        .unwrap_or(false);
    // The "find peers over Nostr relays" toggle. When off we neither advertise
    // nor stream adverts/DMs, but static + bootstrap peers (config.peers below)
    // are still dialed directly and LAN discovery still runs.
    let nostr_discovery_enabled = transport
        .map(|transport| transport.nostr_discovery_enabled)
        .unwrap_or(true);
    let advertise_on_nostr = nostr_discovery_enabled && advertise_udp;
    let nostr_enabled = nostr_discovery_enabled && (advertise_udp || !peers.is_empty());
    config.node.discovery.nostr.enabled = nostr_enabled;
    config.node.discovery.nostr.advertise = advertise_on_nostr;
    // Open discovery by default (unless the user opts into configured-only
    // discovery) so we can FIPS-handshake with any nvpn node we see on relays,
    // not just configured roster peers. This is what lets us route app-mesh
    // traffic through transit hops that aren't in our network roster (a
    // friend-of-a-friend nvpn node can ferry our packets when direct
    // traversal fails). Security boundary: the FIPS handshake can be open; the
    // per-network data plane is NOT. `FipsMeshRuntime::receive_endpoint_data*`
    // drops every inbound packet whose source npub doesn't own the inner
    // source IP per our roster, so a non-roster transit peer can carry frames
    // but cannot inject anything that surfaces on the tun. See the
    // `inbound_endpoint_data_*` tests in `nostr-vpn-core::fips_mesh`.
    // Headless e2e meshes can force configured-only discovery to avoid
    // contending with ambient public relay traffic.
    config.node.discovery.nostr.policy = nostr_discovery_policy;
    config.node.discovery.nostr.open_discovery_max_pending = FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING;
    config.node.discovery.nostr.failure_streak_threshold = FIPS_NOSTR_FAILURE_STREAK_THRESHOLD;
    config.node.discovery.nostr.startup_sweep_max_age_secs = FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS;
    config.node.discovery.nostr.share_local_candidates = transport
        .map(|transport| transport.share_local_candidates)
        .unwrap_or(false);
    config.node.discovery.lan.enabled = transport
        .map(|transport| transport.share_local_candidates)
        .unwrap_or(false);
    // Leave the relay-side `app` at fips-core's default ("fips-overlay-v1").
    // We deliberately do NOT bake the per-network mesh id into it: the relay
    // `protocol` tag is publicly visible, so per-network apps would let any
    // observer count members of each private network. The builder receives a
    // hashed per-network LAN discovery scope separately; that scope is carried
    // only in mDNS TXT records on the local link, while the private data plane
    // still enforces roster ownership before packets reach the tun.
    let bind_addr = transport.map(fips_udp_bind_addr);
    let external_addr = transport.and_then(fips_udp_external_addr);
    if let Some(transport) = transport {
        config.node.discovery.nostr.stun_servers = transport.stun_servers.clone();
        if !transport.nostr_relays.is_empty() {
            config.node.discovery.nostr.advert_relays = transport.nostr_relays.clone();
            config.node.discovery.nostr.dm_relays = transport.nostr_relays.clone();
        }
    }
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr,
        advertise_on_nostr: Some(advertise_on_nostr),
        public: Some(external_addr.is_some()),
        external_addr,
        outbound_only: Some(transport.is_none()),
        accept_connections: Some(transport.is_some()),
        // The safe default remains IPv6-minimum sized for NAT traversal and
        // nested tunnels. Clean-LAN tests must opt into a larger paired budget
        // through config or NVPN_MESH_* env overrides.
        mtu: Some(mesh_mtu.underlay_udp),
        ..UdpConfig::default()
    });
    // Outbound TCP transport so peers reachable only over tcp:443 (e.g. on
    // networks that block UDP outright) can still be dialed. bind_addr=None keeps
    // it outbound-only — no listener.
    let needs_tcp = peers.iter().any(|peer| {
        peer.addresses
            .iter()
            .any(|hint| split_peer_transport_addr(&hint.addr).0 == "tcp")
    });
    if needs_tcp {
        // Default = outbound-only (no bind_addr). Inferred type keeps this the
        // exact `TcpConfig` of `config.transports`, which matters under the e2e's
        // [patch.crates-io] where a second fips-core version can be in the graph,
        // so we deliberately keep `Default::default()` over `TcpConfig::default()`.
        #[allow(clippy::default_trait_access)]
        {
            config.transports.tcp = TransportInstances::Single(Default::default());
        }
    }
    config.peers = peers
        .iter()
        .map(|peer| FipsPeerConfig {
            npub: peer.npub.clone(),
            alias: None,
            addresses: peer
                .addresses
                .iter()
                .map(fips_peer_address_from_hint)
                .collect(),
            connect_policy: ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: peer.discovery_fallback_transit,
        })
        .collect();
    config
}

fn fips_endpoint_peers_from_mesh(
    mesh_peers: &[FipsMeshPeerConfig],
    operator_static_endpoints: Vec<(String, Vec<String>)>,
    recent_peer_endpoints: Vec<(String, Vec<(String, u64)>)>,
) -> Vec<FipsEndpointPeerTransportConfig> {
    let mut peers = HashMap::<String, FipsEndpointPeerTransportConfig>::new();
    for peer in mesh_peers {
        let npub = normalize_fips_endpoint_npub(&peer.endpoint_npub);
        peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                discovery_fallback_transit: !peer.advertises_default_route(),
            });
    }

    // Operator-configured hints have no freshness signal — fips sorts
    // them after any address we've actually observed.
    for (npub, addresses) in operator_static_endpoints {
        let npub = normalize_fips_endpoint_npub(&npub);
        let peer = peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                discovery_fallback_transit: true,
            });
        for raw in addresses {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            peer.addresses.push(FipsPeerAddressHint {
                addr: trimmed.to_string(),
                seen_at_ms: None,
            });
        }
    }

    // Recent-peers cache entries arrive with `last_success_at_ms` so the
    // fips dialer ranks them ahead of unstamped operator hints in the
    // same try-everything pass. Authenticated non-roster entries are kept
    // too: those are overlay transit peers we successfully handshook with
    // before, and reseeding them as fallback transit keeps the FIPS overlay
    // useful before relay discovery catches up.
    for (npub, addresses) in recent_peer_endpoints {
        let npub = normalize_fips_endpoint_npub(&npub);
        let peer = peers
            .entry(npub.clone())
            .or_insert_with(|| FipsEndpointPeerTransportConfig {
                npub,
                addresses: Vec::new(),
                discovery_fallback_transit: true,
            });
        for (addr, seen_at_ms) in addresses {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Same (npub, addr) from multiple sources: keep the freshest
            // timestamp. The dedup pass below collapses duplicates.
            if let Some(existing) = peer.addresses.iter_mut().find(|hint| hint.addr == trimmed) {
                existing.seen_at_ms = match (existing.seen_at_ms, Some(seen_at_ms)) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (a, _) => a,
                };
                continue;
            }
            peer.addresses.push(FipsPeerAddressHint {
                addr: trimmed.to_string(),
                seen_at_ms: Some(seen_at_ms),
            });
        }
    }

    let mut peers = peers.into_values().collect::<Vec<_>>();
    for peer in &mut peers {
        peer.addresses.sort_by(|a, b| a.addr.cmp(&b.addr));
        peer.addresses.dedup_by(|a, b| a.addr == b.addr);
    }
    peers.sort_by(|left, right| left.npub.cmp(&right.npub));
    peers
}

fn normalize_fips_endpoint_npub(value: &str) -> String {
    let trimmed = value.trim();
    normalize_nostr_pubkey(trimmed)
        .ok()
        .and_then(|pubkey| {
            PublicKey::from_hex(&pubkey)
                .ok()
                .and_then(|public_key| public_key.to_bech32().ok())
        })
        .unwrap_or_else(|| trimmed.to_string())
}

fn fips_udp_bind_addr(transport: &FipsEndpointTransportConfig) -> String {
    SocketAddr::V4(SocketAddrV4::new(
        std::net::Ipv4Addr::UNSPECIFIED,
        transport.listen_port,
    ))
    .to_string()
}

fn fips_udp_external_addr(transport: &FipsEndpointTransportConfig) -> Option<String> {
    let endpoint = transport.advertised_endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    endpoint.parse::<SocketAddr>().ok()?;
    Some(endpoint.to_string())
}

#[derive(Debug, Clone)]
pub(crate) struct FipsPrivateTunnelConfig {
    pub(crate) identity_nsec: String,
    pub(crate) network_id: String,
    pub(crate) iface: String,
    pub(crate) local_address: String,
    pub(crate) listen_port: u16,
    pub(crate) advertised_endpoint: String,
    pub(crate) advertise_endpoint: bool,
    pub(crate) stun_servers: Vec<String>,
    pub(crate) nostr_relays: Vec<String>,
    pub(crate) share_local_candidates: bool,
    pub(crate) peers: Vec<FipsMeshPeerConfig>,
    pub(crate) endpoint_peers: Vec<FipsEndpointPeerTransportConfig>,
    pub(crate) route_targets: Vec<String>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fips_host: Option<FipsHostTunnelConfig>,
    pub(crate) local_advertised_routes: Vec<String>,
    pub(crate) wireguard_exit: WireGuardExitConfig,
    pub(crate) exit_node_leak_protection: bool,
    nostr_discovery_enabled: bool,
    nostr_discovery_policy: NostrDiscoveryPolicy,
    mesh_mtu: MeshMtu,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) control_plane_bypass_hosts: Vec<Ipv4Addr>,
}

impl FipsPrivateTunnelConfig {
    pub(crate) fn from_app(
        app: &AppConfig,
        network_id: &str,
        iface: impl Into<String>,
        own_pubkey: Option<&str>,
        recent_peers: Option<&nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
        live_peer_endpoints: &[(String, Vec<(String, u64)>)],
    ) -> Result<Self> {
        let mut peers = Vec::new();
        let mut route_targets = Vec::new();
        let participants = app.participant_pubkeys_hex();
        let mut route_by_participant = HashMap::<String, Vec<String>>::new();
        for participant in participants {
            if Some(participant.as_str()) == own_pubkey {
                continue;
            }
            let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &participant) else {
                continue;
            };
            let allowed_ip = format!("{}/32", strip_cidr(&tunnel_ip));
            route_targets.push(allowed_ip.clone());
            route_by_participant
                .entry(participant.clone())
                .or_default()
                .push(allowed_ip);
            if app.exit_node == participant {
                let exit_routes = crate::runtime_exit_node_default_routes();
                route_targets.extend(exit_routes.iter().cloned());
                route_by_participant
                    .entry(participant)
                    .or_default()
                    .extend(exit_routes);
            }
        }

        for participant in app
            .active_network_signal_pubkeys_hex()
            .into_iter()
            .filter(|participant| Some(participant.as_str()) != own_pubkey)
        {
            let mut allowed_ips = route_by_participant
                .remove(&participant)
                .unwrap_or_default();
            allowed_ips.sort();
            allowed_ips.dedup();
            peers.push(FipsMeshPeerConfig::from_participant_pubkey(
                participant,
                allowed_ips,
            )?);
        }
        peers.sort_by(|left, right| left.participant_pubkey.cmp(&right.participant_pubkey));
        peers.dedup_by(|left, right| left.participant_pubkey == right.participant_pubkey);
        // Address hints feed into fips's unified `PeerConfig.addresses`:
        //   * operator-configured `fips_peer_endpoints` (unstamped)
        //   * recent-peers cache entries (stamped with `last_success_at`)
        // fips's dialer races every hint in parallel, ranked by `seen_at_ms`
        // descending — recent observations naturally beat unstamped hints,
        // and a fresh nostr advert beats both because it's stamped at fetch.
        let desired_endpoint_hint_npubs = app
            .active_network_signal_pubkeys_hex()
            .into_iter()
            .filter(|participant| Some(participant.as_str()) != own_pubkey)
            .map(|participant| normalize_fips_endpoint_npub(&participant))
            .collect::<std::collections::HashSet<_>>();
        let tunnel_endpoint_hosts = fips_tunnel_endpoint_hosts(app, network_id);
        let mut operator_static = filter_static_tunnel_endpoints(
            app.fips_static_peer_endpoints(),
            &tunnel_endpoint_hosts,
        );
        // Built-in public bootstrap nodes as fallback transit. They share the
        // same `discovery_fallback_transit` path as operator-configured static
        // peers, so they ferry frames when direct traversal fails but never
        // become roster route targets.
        operator_static.extend(filter_static_tunnel_endpoints(
            app.fips_bootstrap_peer_endpoints(),
            &tunnel_endpoint_hosts,
        ));
        let mut recent_peer_endpoints = recent_peers
            .map(|cache| cache.as_static_peer_endpoints_with_seen_at())
            .unwrap_or_default();
        recent_peer_endpoints =
            filter_stamped_tunnel_endpoints(recent_peer_endpoints, &tunnel_endpoint_hosts);
        // Live capability hints are accepted only for network signal peers because
        // they are claims carried by that peer. The disk cache above is
        // different: it records peers this endpoint already authenticated.
        recent_peer_endpoints.extend(
            filter_stamped_tunnel_endpoints(
                live_peer_endpoints
                    .iter()
                    .filter(|(participant, _)| {
                        desired_endpoint_hint_npubs
                            .contains(&normalize_fips_endpoint_npub(participant))
                    })
                    .cloned()
                    .collect(),
                &tunnel_endpoint_hosts,
            )
            .into_iter()
            .filter(|(participant, _)| {
                desired_endpoint_hint_npubs.contains(&normalize_fips_endpoint_npub(participant))
            }),
        );
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(&peers, operator_static, recent_peer_endpoints);
        route_targets.sort();
        route_targets.dedup();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let fips_host = FipsHostTunnelConfig::from_app(app)?;

        Ok(Self {
            identity_nsec: app.nostr.secret_key.clone(),
            network_id: network_id.to_string(),
            iface: iface.into(),
            local_address: own_pubkey
                .and_then(|pubkey| derive_mesh_tunnel_ip(network_id, pubkey))
                .map(|tunnel_ip| local_interface_address_for_tunnel(&tunnel_ip))
                .unwrap_or_else(|| local_interface_address_for_tunnel(&app.node.tunnel_ip)),
            listen_port: app.node.listen_port,
            advertised_endpoint: app.node.endpoint.clone(),
            advertise_endpoint: app.fips_advertise_endpoint,
            stun_servers: app.nat.stun_servers.clone(),
            nostr_relays: app.nostr.relays.clone(),
            share_local_candidates: app.lan_discovery_enabled,
            peers,
            endpoint_peers,
            route_targets,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            fips_host,
            local_advertised_routes: crate::runtime_effective_advertised_routes(app),
            wireguard_exit: app.wireguard_exit.clone(),
            exit_node_leak_protection: app.exit_node_leak_protection,
            nostr_discovery_enabled: app.fips_nostr_discovery_enabled,
            nostr_discovery_policy: fips_nostr_discovery_policy_from_app(app),
            mesh_mtu: private_mesh_mtu_from_app(Some(app)),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            control_plane_bypass_hosts: crate::control_plane_bypass_ipv4_hosts(app),
        })
    }

    fn local_allowed_ips(&self) -> Vec<String> {
        let mut routes = vec![self.local_address.clone()];
        routes.extend(self.local_advertised_routes.iter().cloned());
        routes.sort();
        routes.dedup();
        routes
    }

    fn interface_addresses(&self) -> Vec<String> {
        let mut addresses = vec![self.local_address.clone()];
        addresses.sort();
        addresses.dedup();
        addresses
    }

    fn interface_route_targets(&self) -> Vec<String> {
        let mut targets = self.route_targets.clone();
        targets.sort();
        targets.dedup();
        targets
    }
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    let tunnel_ip = tunnel_ip.trim();
    if tunnel_ip.is_empty() {
        return "10.44.0.1/32".to_string();
    }
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn tag_authenticated_transport_addr(
    addr: Option<String>,
    transport_type: Option<String>,
) -> Option<String> {
    let addr = addr?;
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }

    let (addr_transport, host_port) = split_peer_transport_addr(addr);
    let transport = transport_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(addr_transport.as_str())
        .to_ascii_lowercase();

    match transport.as_str() {
        "udp" => Some(host_port),
        "tcp" => Some(format!("tcp:{host_port}")),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn endpoint_transport_ipv4_host(addr: &str) -> Option<Ipv4Addr> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return match socket_addr.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        };
    }

    let (host, _) = crate::split_host_port(addr, 0)?;
    host.parse::<Ipv4Addr>().ok()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct FipsPrivateTunnelRuntime {
    iface: String,
    mesh: Arc<FipsPrivateMeshRuntime>,
    config: FipsPrivateTunnelConfig,
    _tun: Arc<TunSocket>,
    tun_fd: Arc<AsyncFd<BorrowedTunFd>>,
    fips_host: Option<crate::fips_host_tunnel::FipsHostTunnelRuntime>,
    tun_read_task: JoinHandle<()>,
    mesh_send_task: JoinHandle<()>,
    mesh_recv_task: JoinHandle<()>,
    event_rx: mpsc::Receiver<FipsPrivateMeshEvent>,
    #[cfg(target_os = "linux")]
    endpoint_bypass_routes: Vec<String>,
    #[cfg(target_os = "linux")]
    original_default_route: Option<String>,
    #[cfg(target_os = "linux")]
    original_default_ipv6_route: Option<String>,
    #[cfg(target_os = "linux")]
    exit_node_runtime: crate::LinuxExitNodeRuntime,
    #[cfg(target_os = "macos")]
    exit_node_runtime: crate::MacosExitNodeRuntime,
    /// Userspace WG upstream tunnel (Mullvad/Proton-style). Owned for
    /// the lifetime of "WG upstream is enabled in config"; dropped on
    /// disable. Populated by `reconcile_macos_wg_upstream` after a
    /// successful handshake — `None` means either WG upstream is
    /// disabled in the config or the most recent reconcile attempt
    /// could not complete a handshake (in which case the routing
    /// table was deliberately left untouched).
    #[cfg(target_os = "macos")]
    wg_upstream: Option<crate::wg_upstream_runtime::DaemonWgUpstream>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FipsPrivateTunnelRuntime {
    pub(crate) async fn start(config: FipsPrivateTunnelConfig) -> Result<Self> {
        crate::pipeline_profile::maybe_spawn_reporter();
        #[cfg(target_os = "linux")]
        ensure_linux_tun_permissions(&config.iface)?;

        let scope = fips_lan_discovery_scope(&config.network_id);
        let transport = FipsEndpointTransportConfig {
            listen_port: config.listen_port,
            advertised_endpoint: config.advertised_endpoint.clone(),
            advertise_endpoint: config.advertise_endpoint,
            nostr_discovery_enabled: config.nostr_discovery_enabled,
            stun_servers: config.stun_servers.clone(),
            nostr_relays: config.nostr_relays.clone(),
            share_local_candidates: config.share_local_candidates,
        };
        let endpoint_config = fips_endpoint_config(
            &config.endpoint_peers,
            Some(&transport),
            config.mesh_mtu,
            config.nostr_discovery_policy,
        );
        let local_allowed_ips = config.local_allowed_ips();
        let mesh = Arc::new(
            FipsPrivateMeshRuntime::bind_with_config(
                config.identity_nsec.clone(),
                scope,
                config.peers.clone(),
                endpoint_config,
                local_allowed_ips,
            )
            .await?,
        );
        let tun = Arc::new(
            TunSocket::new(&config.iface)
                .with_context(|| fips_tun_create_context(&config.iface))?
                .set_non_blocking()
                .context("failed to set FIPS tunnel nonblocking")?,
        );
        let iface = tun.name().context("failed to read FIPS tunnel name")?;
        let tun_fd = Arc::new(
            AsyncFd::with_interest(
                BorrowedTunFd(tun.as_raw_fd()),
                Interest::READABLE | Interest::WRITABLE,
            )
            .context("failed to register FIPS tunnel fd with reactor")?,
        );

        let (packet_tx, mut packet_rx) = mpsc::channel::<TunPipelinePacket>(1024);
        let (event_tx, event_rx) = mpsc::channel::<FipsPrivateMeshEvent>(1024);
        let tun_read_task = spawn_tun_read_task(Arc::clone(&tun), Arc::clone(&tun_fd), packet_tx);
        let mesh_send_task = {
            let mesh = Arc::clone(&mesh);
            tokio::spawn(async move {
                while let Some(packet) = packet_rx.recv().await {
                    send_mesh_packet_or_log(&mesh, packet).await;

                    let mut drained = 1;
                    while drained < FIPS_MESH_SEND_BURST {
                        match packet_rx.try_recv() {
                            Ok(packet) => {
                                send_mesh_packet_or_log(&mesh, packet).await;
                                drained += 1;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => return,
                        }
                    }

                    if drained == FIPS_MESH_SEND_BURST {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };
        let mesh_recv_task = spawn_mesh_recv_task(Arc::clone(&mesh), Arc::clone(&tun_fd), event_tx);

        let mut runtime = Self {
            iface,
            mesh,
            config: config.clone(),
            _tun: tun,
            tun_fd,
            fips_host: None,
            tun_read_task,
            mesh_send_task,
            mesh_recv_task,
            event_rx,
            #[cfg(target_os = "linux")]
            endpoint_bypass_routes: Vec::new(),
            #[cfg(target_os = "linux")]
            original_default_route: None,
            #[cfg(target_os = "linux")]
            original_default_ipv6_route: None,
            #[cfg(target_os = "linux")]
            exit_node_runtime: crate::LinuxExitNodeRuntime::default(),
            #[cfg(target_os = "macos")]
            exit_node_runtime: crate::MacosExitNodeRuntime::default(),
            #[cfg(target_os = "macos")]
            wg_upstream: None,
        };
        runtime.apply_interface_config(&config).await?;
        runtime
            .reconcile_fips_host_runtime(config.fips_host.clone())
            .await?;
        Ok(runtime)
    }

    pub(crate) fn iface(&self) -> &str {
        &self.iface
    }

    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        self.mesh.peer_statuses()
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        self.mesh.relay_statuses().await
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        self.mesh.peer_pubkeys()
    }

    pub(crate) async fn authenticated_peer_transport_addrs(&self) -> Result<Vec<(String, String)>> {
        self.mesh.authenticated_peer_transport_addrs().await
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        self.mesh.peer_endpoint_hints()
    }

    /// Forward a refreshed peer roster + address hints to fips without
    /// restarting the endpoint. Daemon heartbeat path: when the
    /// recent-peers cache or active-network roster changes, build the
    /// merged hint list and call this so fips can diff + apply.
    pub(crate) async fn update_peers(
        &self,
        endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        self.mesh.update_peers(endpoint_peers).await
    }

    pub(crate) async fn update_relays(&self, relays: &[String]) -> Result<()> {
        self.mesh.update_relays(relays).await
    }

    pub(crate) fn requires_endpoint_restart(&self, config: &FipsPrivateTunnelConfig) -> bool {
        // `endpoint_peers` is deliberately NOT in this list. Its `addresses`
        // field is fed from the recent-peers cache, which the same daemon
        // refreshes every few seconds — gating restart on it caused a
        // self-inflicted flap loop: cache observed a new public-IP hint
        // for one peer → next config-sync tick saw `endpoint_peers !=
        // self.config.endpoint_peers` → whole FIPS endpoint torn down and
        // re-bound → every link briefly offline → cold-start retry
        // backoff (5/10/20/40/80s) before any peer came back. Address
        // hints get pushed via `FipsPrivateMeshRuntime::update_peers`
        // (kicked from `update_recent_peers_from_runtime`) without
        // tearing the endpoint down. Peer roster adds/removes still
        // propagate via `apply_config` → `mesh.replace_peers`, which
        // doesn't need a restart either.
        self.config.identity_nsec != config.identity_nsec
            || self.config.network_id != config.network_id
            || self.config.listen_port != config.listen_port
            || self.config.advertised_endpoint != config.advertised_endpoint
            || self.config.advertise_endpoint != config.advertise_endpoint
            || self.config.stun_servers != config.stun_servers
            || self.config.nostr_relays != config.nostr_relays
            || self.config.share_local_candidates != config.share_local_candidates
            || self.config.nostr_discovery_policy != config.nostr_discovery_policy
            || self.config.mesh_mtu.underlay_udp != config.mesh_mtu.underlay_udp
    }

    pub(crate) async fn apply_config(&mut self, config: FipsPrivateTunnelConfig) -> Result<()> {
        self.mesh
            .replace_peers(config.peers.clone(), config.local_allowed_ips())?;
        if let Err(error) = self.mesh.update_peers(&config.endpoint_peers).await {
            eprintln!("fips: update_peers during apply_config failed: {error}");
        }
        if self.config.nostr_relays != config.nostr_relays {
            self.mesh.update_relays(&config.nostr_relays).await?;
        }
        self.apply_interface_config(&config).await?;
        self.reconcile_fips_host_runtime(config.fips_host.clone())
            .await?;
        self.config = config;
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if !crate::route_targets_require_endpoint_bypass(&self.config.route_targets) {
                return Ok(());
            }

            let config = self.config.clone();
            return self.apply_interface_config(&config).await;
        }

        #[cfg(target_os = "macos")]
        {
            Ok(())
        }
    }

    pub(crate) async fn ping_peers(&self, network_id: &str, now: u64) -> Result<usize> {
        self.mesh.ping_peers(network_id, now).await
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        self.mesh.refresh_link_statuses().await
    }

    pub(crate) async fn send_join_request(
        &self,
        participant: &str,
        requested_at: u64,
        request: MeshJoinRequest,
    ) -> Result<()> {
        self.mesh
            .send_join_request(participant, requested_at, request)
            .await
    }

    pub(crate) async fn send_roster(
        &self,
        participant: &str,
        signed_roster: SignedRoster,
    ) -> Result<()> {
        self.mesh.send_roster(participant, signed_roster).await
    }

    pub(crate) async fn send_capabilities(
        &self,
        participant: &str,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<()> {
        self.mesh
            .send_capabilities(participant, network_id, capabilities)
            .await
    }

    pub(crate) async fn broadcast_capabilities(
        &self,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<usize> {
        self.mesh
            .broadcast_capabilities(network_id, capabilities)
            .await
    }

    pub(crate) fn peer_advertised_routes(&self, participant: &str) -> Vec<String> {
        self.mesh.peer_advertised_routes(participant)
    }

    pub(crate) fn drain_events(&mut self) -> Vec<FipsPrivateMeshEvent> {
        drain_event_batch(&mut self.event_rx, FIPS_MESH_EVENT_DRAIN_LIMIT)
    }

    pub(crate) async fn stop(self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let mut runtime = self;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let runtime = self;
        #[cfg(target_os = "linux")]
        runtime.cleanup_linux_network_state();
        #[cfg(target_os = "macos")]
        runtime.cleanup_macos_exit_node_forwarding();
        #[cfg(target_os = "macos")]
        if let Some(handle) = runtime.wg_upstream.take() {
            handle.cleanup().await;
        }
        runtime.stop_fips_host_runtime().await;
        runtime.tun_read_task.abort();
        runtime.mesh_send_task.abort();
        runtime.mesh_recv_task.abort();
        let _ = runtime.tun_read_task.await;
        let _ = runtime.mesh_send_task.await;
        let _ = runtime.mesh_recv_task.await;
        if let Ok(mesh) = Arc::try_unwrap(runtime.mesh) {
            mesh.shutdown()
                .await
                .context("failed to stop FIPS endpoint")?;
        }
        Ok(())
    }

    async fn apply_interface_config(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.apply_linux_network_state(config).await?;
        }
        #[cfg(target_os = "macos")]
        {
            // FIPS mesh peer routes go in first. They're /32s for
            // each peer's tunnel IP, so even when we swap the default
            // route to the WG tun below, mesh traffic still wins on
            // longest-prefix-match and stays inside the FIPS tunnel.
            crate::apply_local_interface_network_with_mtu_and_addresses(
                &self.iface,
                &config.interface_addresses(),
                &config.interface_route_targets(),
                config.mesh_mtu.tunnel,
            )
            .with_context(|| format!("failed to configure FIPS tunnel interface {}", self.iface))?;
            self.reconcile_macos_wg_upstream(&config.wireguard_exit)
                .await;
            self.reconcile_macos_exit_node_forwarding(
                &config.local_address,
                &config.local_advertised_routes,
            );
        }
        Ok(())
    }

    async fn reconcile_fips_host_runtime(
        &mut self,
        config: Option<FipsHostTunnelConfig>,
    ) -> Result<()> {
        let needs_restart = match (&self.fips_host, &config) {
            (Some(runtime), Some(config)) => runtime.requires_restart(config),
            (Some(_), None) => true,
            (None, Some(_)) => true,
            (None, None) => false,
        };
        if needs_restart {
            self.stop_fips_host_runtime().await;
        }

        match config {
            Some(config) if self.fips_host.is_none() => {
                let runtime = crate::fips_host_tunnel::FipsHostTunnelRuntime::start(config).await?;
                eprintln!("fips-host: .fips IPv6 resolver active");
                self.fips_host = Some(runtime);
            }
            None => {
                crate::fips_host_tunnel::FipsHostTunnelRuntime::cleanup_disabled_artifacts();
            }
            Some(_) => {}
        }
        Ok(())
    }

    async fn stop_fips_host_runtime(&mut self) {
        if let Some(runtime) = self.fips_host.take()
            && let Err(error) = runtime.stop().await
        {
            eprintln!("fips-host: failed to stop .fips runtime: {error}");
        }
    }

    /// Bring the WG upstream tunnel up / down to match `wireguard_exit`.
    ///
    /// Called on every `apply_interface_config` (which fires on
    /// startup, on every config change, and on the periodic
    /// peer-dependent route refresh). The function is idempotent: a
    /// no-op if the existing tunnel already matches the config, a
    /// teardown-then-bring-up if the config changed, just a teardown
    /// if WG is now disabled.
    ///
    /// **Safe-by-construction**: if the WG handshake doesn't complete
    /// within the watchdog window (10s), nothing modifies the routing
    /// table. The host's default route only ever swaps to the WG tun
    /// after we've seen a real handshake from the upstream.
    #[cfg(target_os = "macos")]
    async fn reconcile_macos_wg_upstream(&mut self, wg_config: &WireGuardExitConfig) {
        let want_up = wg_config.enabled && wg_config.configured();

        // Already up with matching config → nothing to do.
        if want_up
            && self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.matches(wg_config))
        {
            return;
        }

        // If we have a stale tunnel (config changed, or now disabled),
        // tear it down before doing anything else. This restores the
        // original default route + deletes the bypass.
        if let Some(existing) = self.wg_upstream.take() {
            existing.cleanup().await;
        }

        if !want_up {
            return;
        }

        let mut bypass_hosts = self.config.control_plane_bypass_hosts.clone();
        match self.mesh.peer_transport_ipv4_hosts().await {
            Ok(peer_hosts) => bypass_hosts.extend(peer_hosts),
            Err(error) => {
                eprintln!(
                    "fips: WG upstream continuing without peer transport bypass hosts: {error}"
                );
            }
        }
        bypass_hosts.sort_unstable();
        bypass_hosts.dedup();

        match crate::wg_upstream_runtime::apply_daemon_wg_upstream(
            wg_config,
            crate::wg_upstream_runtime::DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT,
            &bypass_hosts,
        )
        .await
        {
            Ok(handle) => {
                eprintln!(
                    "fips: WG upstream up on {} via {} (default route swapped)",
                    handle.iface, handle.upstream
                );
                self.wg_upstream = Some(handle);
            }
            Err(error) => {
                // The watchdog fired or another error occurred. The
                // routing table was deliberately left untouched, so
                // the host's internet is still fine — surface the
                // error for the GUI / status page and try again on
                // the next reconcile tick.
                eprintln!("fips: WG upstream not started: {error}");
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn reconcile_macos_exit_node_forwarding(&mut self, local_address: &str, routes: &[String]) {
        let route_families = crate::linux_exit_node_default_route_families(routes);
        if !route_families.ipv4 {
            self.cleanup_macos_exit_node_forwarding();
            return;
        }
        if route_families.ipv6 {
            eprintln!(
                "fips: IPv6 exit-node forwarding is disabled on macOS until nvpn has IPv6 PF source filtering"
            );
        }

        let Some(tunnel_source_cidr) = crate::linux_exit_node_source_cidr(local_address) else {
            eprintln!("fips: invalid IPv4 tunnel address '{local_address}'");
            self.cleanup_macos_exit_node_forwarding();
            return;
        };

        let outbound_iface = match crate::macos_underlay_default_route_from_system() {
            Ok(Some(route)) => route.interface,
            Ok(None) => {
                eprintln!("fips: failed to resolve macOS underlay default route for exit NAT");
                self.cleanup_macos_exit_node_forwarding();
                return;
            }
            Err(error) => {
                eprintln!("fips: failed to resolve macOS underlay default route: {error}");
                self.cleanup_macos_exit_node_forwarding();
                return;
            }
        };

        let already_configured = self.exit_node_runtime.outbound_iface.as_deref()
            == Some(outbound_iface.as_str())
            && self.exit_node_runtime.tunnel_source_cidr.as_deref()
                == Some(tunnel_source_cidr.as_str());
        if already_configured {
            return;
        }

        self.cleanup_macos_exit_node_forwarding();
        match crate::macos_pf_enabled() {
            Ok(enabled) => {
                self.exit_node_runtime.pf_was_enabled = Some(enabled);
                if !enabled && let Err(error) = crate::enable_macos_pf() {
                    eprintln!("fips: failed to enable macOS PF for exit NAT: {error}");
                    self.cleanup_macos_exit_node_forwarding();
                    return;
                }
            }
            Err(error) => {
                eprintln!("fips: failed to read macOS PF state: {error}");
                self.cleanup_macos_exit_node_forwarding();
                return;
            }
        }

        if let Err(error) =
            crate::apply_macos_exit_node_pf_rules(&self.iface, &outbound_iface, &tunnel_source_cidr)
        {
            eprintln!("fips: failed to install macOS exit PF rules: {error}");
            self.cleanup_macos_exit_node_forwarding();
            return;
        }

        self.exit_node_runtime.outbound_iface = Some(outbound_iface);
        self.exit_node_runtime.tunnel_source_cidr = Some(tunnel_source_cidr);
    }

    #[cfg(target_os = "macos")]
    fn cleanup_macos_exit_node_forwarding(&mut self) {
        if self.exit_node_runtime.pf_was_enabled.is_some()
            && let Err(error) = crate::cleanup_macos_pf_nat()
        {
            eprintln!("fips: failed to remove macOS exit PF rules: {error}");
        }

        if self.exit_node_runtime.pf_was_enabled == Some(false)
            && let Err(error) = crate::run_checked(ProcessCommand::new("pfctl").arg("-d"))
        {
            eprintln!("fips: failed to restore macOS PF enabled state: {error}");
        }

        self.exit_node_runtime = crate::MacosExitNodeRuntime::default();
    }

    #[cfg(target_os = "linux")]
    async fn apply_linux_network_state(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        let mut route_targets = config.route_targets.clone();
        let requested_ipv4_exit = route_targets.iter().any(|route| route == "0.0.0.0/0");
        let requested_ipv6_exit = route_targets.iter().any(|route| route == "::/0");
        let requested_exit = requested_ipv4_exit || requested_ipv6_exit;
        let strict_exit = config.exit_node_leak_protection && requested_exit;
        let original_route_targets_require_bypass =
            crate::route_targets_require_endpoint_bypass(&route_targets);
        let mut peer_endpoint_hosts = Vec::new();
        if original_route_targets_require_bypass {
            peer_endpoint_hosts = self.mesh.peer_transport_ipv4_hosts().await?;
            if route_targets.iter().any(|route| route == "0.0.0.0/0")
                && peer_endpoint_hosts.is_empty()
            {
                eprintln!(
                    "fips: withholding default route until the selected exit peer underlay endpoint is known"
                );
                route_targets.retain(|route| !crate::is_exit_node_route(route));
            }
        }

        let active_ipv4_exit = route_targets.iter().any(|route| route == "0.0.0.0/0");
        let active_ipv6_exit = route_targets.iter().any(|route| route == "::/0");

        if requested_ipv4_exit {
            self.capture_linux_original_default_route();
        } else {
            self.restore_linux_original_default_route();
        }
        if requested_ipv6_exit {
            self.capture_linux_original_default_ipv6_route();
        } else {
            self.restore_linux_original_default_ipv6_route();
        }
        if !strict_exit {
            if requested_ipv4_exit && !active_ipv4_exit {
                self.restore_linux_original_default_route();
            }
            if requested_ipv6_exit && !active_ipv6_exit {
                self.restore_linux_original_default_ipv6_route();
            }
        }

        let endpoint_bypass_specs = if original_route_targets_require_bypass || strict_exit {
            let mut bypass_hosts = config.control_plane_bypass_hosts.clone();
            bypass_hosts.extend(peer_endpoint_hosts);
            bypass_hosts.sort_unstable();
            bypass_hosts.dedup();
            crate::linux_bypass_route_specs_for_hosts(
                bypass_hosts,
                &self.iface,
                self.original_default_route.as_deref(),
            )?
        } else {
            Vec::new()
        };
        self.reconcile_linux_endpoint_bypass_routes(&endpoint_bypass_specs);

        let mut interface_route_targets = route_targets.clone();
        interface_route_targets.sort();
        interface_route_targets.dedup();
        crate::apply_local_interface_network_with_mtu_and_addresses(
            &self.iface,
            &config.interface_addresses(),
            &interface_route_targets,
            config.mesh_mtu.tunnel,
        )
        .with_context(|| format!("failed to configure FIPS tunnel interface {}", self.iface))?;
        if let Err(error) = crate::flush_linux_route_cache() {
            eprintln!("fips: failed to flush linux route cache: {error}");
        }
        if strict_exit {
            if requested_ipv4_exit && !active_ipv4_exit {
                self.block_linux_original_default_route();
            }
            if requested_ipv6_exit && !active_ipv6_exit {
                self.block_linux_original_default_ipv6_route();
            }
        }
        self.reconcile_linux_exit_node_forwarding(
            &config.local_address,
            &config.local_advertised_routes,
            &config.wireguard_exit,
            config.exit_node_leak_protection,
            config.mesh_mtu.tunnel,
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn capture_linux_original_default_route(&mut self) {
        if self.original_default_route.is_some() {
            return;
        }
        match crate::linux_default_route() {
            Ok(route) => self.original_default_route = Some(route.line),
            Err(error) => eprintln!("fips: failed to capture original default route: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn capture_linux_original_default_ipv6_route(&mut self) {
        if self.original_default_ipv6_route.is_some() {
            return;
        }
        match crate::linux_default_ipv6_route() {
            Ok(route) => self.original_default_ipv6_route = Some(route.line),
            Err(error) => eprintln!("fips: failed to capture original IPv6 default route: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn restore_linux_original_default_route(&mut self) {
        let Some(route) = self.original_default_route.take() else {
            return;
        };
        if let Err(error) = crate::restore_linux_default_route(&route) {
            eprintln!("fips: failed to restore original default route: {error}");
            self.original_default_route = Some(route);
        }
    }

    #[cfg(target_os = "linux")]
    fn restore_linux_original_default_ipv6_route(&mut self) {
        let Some(route) = self.original_default_ipv6_route.take() else {
            return;
        };
        if let Err(error) = crate::restore_linux_default_ipv6_route(&route) {
            eprintln!("fips: failed to restore original IPv6 default route: {error}");
            self.original_default_ipv6_route = Some(route);
        }
    }

    #[cfg(target_os = "linux")]
    fn block_linux_original_default_route(&mut self) {
        match crate::linux_default_route() {
            Ok(route) if Some(route.line.as_str()) == self.original_default_route.as_deref() => {
                if let Err(error) = crate::delete_linux_default_route() {
                    eprintln!("fips: failed to block IPv4 default route: {error}");
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    #[cfg(target_os = "linux")]
    fn block_linux_original_default_ipv6_route(&mut self) {
        match crate::linux_default_ipv6_route() {
            Ok(route)
                if Some(route.line.as_str()) == self.original_default_ipv6_route.as_deref() =>
            {
                if let Err(error) = crate::delete_linux_default_ipv6_route() {
                    eprintln!("fips: failed to block IPv6 default route: {error}");
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_endpoint_bypass_routes(
        &mut self,
        routes: &[crate::LinuxEndpointBypassRoute],
    ) {
        let desired = routes
            .iter()
            .map(|route| route.target.clone())
            .collect::<std::collections::HashSet<_>>();

        let stale = self
            .endpoint_bypass_routes
            .iter()
            .filter(|route| !desired.contains(*route))
            .cloned()
            .collect::<Vec<_>>();
        for route in stale {
            if let Err(error) = crate::delete_linux_endpoint_bypass_route(&route) {
                eprintln!("fips: failed to remove endpoint bypass route {route}: {error}");
            }
        }

        for route in routes {
            if let Err(error) = crate::apply_linux_endpoint_bypass_route(route) {
                eprintln!(
                    "fips: failed to install endpoint bypass route {}: {}",
                    route.target, error
                );
            }
        }

        self.endpoint_bypass_routes = desired.into_iter().collect();
        self.endpoint_bypass_routes.sort();
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_exit_node_forwarding(
        &mut self,
        local_address: &str,
        routes: &[String],
        wireguard_exit: &WireGuardExitConfig,
        exit_node_leak_protection: bool,
        tunnel_mtu: u16,
    ) {
        let ipv4_mss_clamp = exit_node_ipv4_mss_clamp(tunnel_mtu);
        let mut route_families = crate::linux_exit_node_default_route_families(routes);
        if route_families.ipv6 {
            eprintln!(
                "fips: IPv6 exit-node forwarding is disabled until nvpn has IPv6 mesh source filtering"
            );
            route_families.ipv6 = false;
        }
        // WG upstream as this host's own egress does not imply mesh
        // exit-node forwarding. Only advertised default routes should
        // turn on ip_forward/NAT below.
        let needs_ipv4_tunnel_source = route_families.ipv4 || wireguard_exit.enabled;
        let ipv4_tunnel_source_cidr = if needs_ipv4_tunnel_source {
            let Some(tunnel_source_cidr) = crate::linux_exit_node_source_cidr(local_address) else {
                eprintln!("fips: invalid IPv4 tunnel address '{local_address}'");
                self.reconcile_linux_exit_node_forwarding_cleanup();
                return;
            };
            Some(tunnel_source_cidr)
        } else {
            None
        };

        let wireguard_exit_iface = if wireguard_exit.enabled {
            let Some(source_cidr) = ipv4_tunnel_source_cidr.as_deref() else {
                self.reconcile_linux_exit_node_forwarding_cleanup();
                return;
            };
            match crate::validate_linux_wireguard_exit_config(wireguard_exit) {
                Ok(iface) => {
                    if !crate::linux_wireguard_exit_ipv6_default(wireguard_exit) {
                        route_families.ipv6 = false;
                    }
                    if let Err(error) =
                        self.apply_linux_wireguard_exit_upstream(wireguard_exit, source_cidr)
                    {
                        eprintln!("fips: failed to configure WireGuard exit upstream: {error}");
                        self.cleanup_linux_exit_node_forwarding_rules();
                        self.cleanup_linux_wireguard_exit_upstream();
                        self.block_linux_wireguard_exit_if_strict(exit_node_leak_protection);
                        return;
                    }
                    Some((iface, source_cidr.to_string()))
                }
                Err(error) => {
                    eprintln!("fips: WireGuard exit upstream is not ready: {error}");
                    self.cleanup_linux_exit_node_forwarding_rules();
                    self.cleanup_linux_wireguard_exit_upstream();
                    self.block_linux_wireguard_exit_if_strict(
                        exit_node_leak_protection && wireguard_exit.enabled,
                    );
                    return;
                }
            }
        } else {
            self.cleanup_linux_wireguard_exit_upstream();
            None
        };

        if !route_families.ipv4 && !route_families.ipv6 {
            self.cleanup_linux_exit_node_forwarding_rules();
            return;
        }

        let ipv4_outbound_iface = if route_families.ipv4 {
            if let Some((iface, _)) = wireguard_exit_iface.as_ref() {
                Some(iface.clone())
            } else {
                match crate::linux_default_route() {
                    Ok(route) => Some(route.dev),
                    Err(error) => {
                        eprintln!("fips: failed to resolve default IPv4 route device: {error}");
                        self.cleanup_linux_exit_node_forwarding_rules();
                        return;
                    }
                }
            }
        } else {
            None
        };

        let ipv6_outbound_iface = None;

        if !route_families.ipv4 && !route_families.ipv6 {
            self.cleanup_linux_exit_node_forwarding_rules();
            return;
        }

        let already_configured = self.exit_node_runtime.ipv4_outbound_iface == ipv4_outbound_iface
            && self.exit_node_runtime.ipv6_outbound_iface == ipv6_outbound_iface
            && self.exit_node_runtime.ipv4_tunnel_source_cidr == ipv4_tunnel_source_cidr
            && self.exit_node_runtime.ipv4_mss_clamp == Some(ipv4_mss_clamp);
        if already_configured {
            return;
        }

        self.cleanup_linux_exit_node_forwarding_rules();

        self.exit_node_runtime.ipv4_outbound_iface = ipv4_outbound_iface.clone();
        self.exit_node_runtime.ipv6_outbound_iface = ipv6_outbound_iface.clone();
        self.exit_node_runtime.ipv4_tunnel_source_cidr = ipv4_tunnel_source_cidr.clone();
        self.exit_node_runtime.ipv4_mss_clamp = Some(ipv4_mss_clamp);

        if route_families.ipv4 {
            match crate::read_linux_ip_forward(crate::LinuxExitNodeIpFamily::V4) {
                Ok(previous) => {
                    self.exit_node_runtime.ipv4_forward_was_enabled = Some(previous);
                    if !previous
                        && let Err(error) =
                            crate::write_linux_ip_forward(crate::LinuxExitNodeIpFamily::V4, true)
                    {
                        eprintln!("fips: failed to enable IPv4 forwarding: {error}");
                        self.cleanup_linux_exit_node_forwarding_rules();
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("fips: failed to read IPv4 forwarding state: {error}");
                    self.cleanup_linux_exit_node_forwarding_rules();
                    return;
                }
            }
        }

        if let (Some(outbound_iface), Some(tunnel_source_cidr)) = (
            ipv4_outbound_iface.as_deref(),
            ipv4_tunnel_source_cidr.as_deref(),
        ) {
            self.cleanup_linux_legacy_exit_node_forwarding_rules();
            let forward_in = crate::linux_exit_node_forward_in_rule(
                &self.iface,
                outbound_iface,
                tunnel_source_cidr,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let forward_out = crate::linux_exit_node_forward_out_rule(
                &self.iface,
                outbound_iface,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let masquerade =
                crate::linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);
            let mss_clamp = crate::linux_exit_node_ipv4_mss_clamp_rule(
                &self.iface,
                outbound_iface,
                tunnel_source_cidr,
                ipv4_mss_clamp,
            );

            if let Err(error) = crate::linux_iptables_ensure_rule_at_front(
                crate::LinuxExitNodeIpFamily::V4,
                None,
                &forward_in,
            )
            .and_then(|()| {
                crate::linux_iptables_ensure_rule_at_front(
                    crate::LinuxExitNodeIpFamily::V4,
                    None,
                    &forward_out,
                )
            })
            .and_then(|()| {
                crate::linux_iptables_ensure_rule(
                    crate::LinuxExitNodeIpFamily::V4,
                    Some("nat"),
                    &masquerade,
                )
            })
            .and_then(|()| {
                crate::linux_iptables_ensure_rule_at_front(
                    crate::LinuxExitNodeIpFamily::V4,
                    Some("mangle"),
                    &mss_clamp,
                )
            }) {
                eprintln!("fips: failed to install IPv4 exit firewall rules: {error}");
                self.cleanup_linux_exit_node_forwarding_rules();
                return;
            }
        }

        self.cleanup_linux_legacy_exit_node_forwarding_rules();
    }

    #[cfg(target_os = "linux")]
    fn apply_linux_wireguard_exit_upstream(
        &mut self,
        config: &WireGuardExitConfig,
        source_cidr: &str,
    ) -> Result<()> {
        let mut preserve_created_interface = false;
        let mut previous_runtime = None;
        if let Some(runtime) = self.exit_node_runtime.wireguard_exit.as_ref()
            && (runtime.interface != config.interface || runtime.source_cidr != source_cidr)
        {
            self.cleanup_linux_wireguard_exit_upstream();
        } else if let Some(runtime) = self.exit_node_runtime.wireguard_exit.as_ref() {
            preserve_created_interface = runtime.created_interface;
            previous_runtime = Some(runtime.clone());
        }
        let mut runtime = crate::apply_linux_wireguard_exit_upstream(
            config,
            source_cidr,
            previous_runtime.as_ref(),
            self.original_default_route.as_deref(),
        )?;
        runtime.created_interface |= preserve_created_interface;
        if let Err(error) = self.ensure_linux_wireguard_exit_inbound_guard(&runtime) {
            crate::cleanup_linux_wireguard_exit_upstream(&runtime);
            return Err(error);
        }
        self.exit_node_runtime.wireguard_exit = Some(runtime);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ensure_linux_wireguard_exit_inbound_guard(
        &self,
        runtime: &crate::LinuxWireGuardExitRuntime,
    ) -> Result<()> {
        let drop_inbound = crate::linux_wireguard_exit_inbound_drop_rule(
            &runtime.interface,
            &self.iface,
            &runtime.source_cidr,
        );
        crate::linux_iptables_ensure_rule_at_front(
            crate::LinuxExitNodeIpFamily::V4,
            None,
            &drop_inbound,
        )
    }

    #[cfg(target_os = "linux")]
    fn cleanup_linux_wireguard_exit_inbound_guard(
        &self,
        runtime: &crate::LinuxWireGuardExitRuntime,
    ) {
        let drop_inbound = crate::linux_wireguard_exit_inbound_drop_rule(
            &runtime.interface,
            &self.iface,
            &runtime.source_cidr,
        );
        if let Err(error) =
            crate::linux_iptables_delete_rule(crate::LinuxExitNodeIpFamily::V4, None, &drop_inbound)
        {
            eprintln!("fips: failed to remove WireGuard inbound guard rule: {error}");
        }
    }

    #[cfg(target_os = "linux")]
    fn block_linux_wireguard_exit_if_strict(&mut self, enabled: bool) {
        if !enabled {
            return;
        }
        self.capture_linux_original_default_route();
        self.block_linux_original_default_route();
    }

    #[cfg(target_os = "linux")]
    fn cleanup_linux_wireguard_exit_upstream(&mut self) {
        let Some(runtime) = self.exit_node_runtime.wireguard_exit.take() else {
            return;
        };
        self.cleanup_linux_wireguard_exit_inbound_guard(&runtime);
        crate::cleanup_linux_wireguard_exit_upstream(&runtime);
    }

    #[cfg(target_os = "linux")]
    fn cleanup_linux_exit_node_forwarding_rules(&mut self) {
        if let (Some(outbound_iface), Some(tunnel_source_cidr)) = (
            self.exit_node_runtime.ipv4_outbound_iface.as_deref(),
            self.exit_node_runtime.ipv4_tunnel_source_cidr.as_deref(),
        ) {
            if let Some(mss) = self.exit_node_runtime.ipv4_mss_clamp {
                let mss_clamp = crate::linux_exit_node_ipv4_mss_clamp_rule(
                    &self.iface,
                    outbound_iface,
                    tunnel_source_cidr,
                    mss,
                );
                if let Err(error) = crate::linux_iptables_delete_rule(
                    crate::LinuxExitNodeIpFamily::V4,
                    Some("mangle"),
                    &mss_clamp,
                ) {
                    eprintln!("fips: failed to remove MSS clamp rule: {error}");
                }
            }
            let forward_in = crate::linux_exit_node_forward_in_rule(
                &self.iface,
                outbound_iface,
                tunnel_source_cidr,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let forward_out = crate::linux_exit_node_forward_out_rule(
                &self.iface,
                outbound_iface,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let masquerade =
                crate::linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);

            if let Err(error) = crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                Some("nat"),
                &masquerade,
            ) {
                eprintln!("fips: failed to remove masquerade rule: {error}");
            }
            if let Err(error) = crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                None,
                &forward_out,
            ) {
                eprintln!("fips: failed to remove forward-out rule: {error}");
            }
            if let Err(error) = crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                None,
                &forward_in,
            ) {
                eprintln!("fips: failed to remove forward-in rule: {error}");
            }
        }

        self.cleanup_linux_legacy_exit_node_forwarding_rules();

        if self.exit_node_runtime.ipv4_forward_was_enabled == Some(false)
            && let Err(error) =
                crate::write_linux_ip_forward(crate::LinuxExitNodeIpFamily::V4, false)
        {
            eprintln!("fips: failed to restore IPv4 forwarding state: {error}");
        }
        if self.exit_node_runtime.ipv6_forward_was_enabled == Some(false)
            && let Err(error) =
                crate::write_linux_ip_forward(crate::LinuxExitNodeIpFamily::V6, false)
        {
            eprintln!("fips: failed to restore IPv6 forwarding state: {error}");
        }

        self.exit_node_runtime.ipv4_outbound_iface = None;
        self.exit_node_runtime.ipv6_outbound_iface = None;
        self.exit_node_runtime.ipv4_tunnel_source_cidr = None;
        self.exit_node_runtime.ipv4_mss_clamp = None;
        self.exit_node_runtime.ipv4_forward_was_enabled = None;
        self.exit_node_runtime.ipv6_forward_was_enabled = None;
    }

    #[cfg(target_os = "linux")]
    fn cleanup_linux_legacy_exit_node_forwarding_rules(&self) {
        for family in [
            crate::LinuxExitNodeIpFamily::V4,
            crate::LinuxExitNodeIpFamily::V6,
        ] {
            let forward_in = crate::linux_exit_node_legacy_forward_in_rule(&self.iface, family);
            let forward_out = crate::linux_exit_node_legacy_forward_out_rule(&self.iface, family);
            let _ = crate::linux_iptables_delete_rule(family, None, &forward_out);
            let _ = crate::linux_iptables_delete_rule(family, None, &forward_in);
        }
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_exit_node_forwarding_cleanup(&mut self) {
        self.cleanup_linux_exit_node_forwarding_rules();
        self.cleanup_linux_wireguard_exit_upstream();
        self.exit_node_runtime = crate::LinuxExitNodeRuntime::default();
    }

    #[cfg(target_os = "linux")]
    fn cleanup_linux_network_state(&mut self) {
        self.reconcile_linux_endpoint_bypass_routes(&[]);
        self.reconcile_linux_exit_node_forwarding_cleanup();
        self.restore_linux_original_default_route();
        self.restore_linux_original_default_ipv6_route();
        if let Err(error) = crate::flush_linux_route_cache() {
            eprintln!("fips: failed to flush linux route cache: {error}");
        }
    }
}

#[cfg(any(target_os = "linux", test))]
const LINUX_CAP_NET_ADMIN_BIT: u32 = 12;

#[cfg(target_os = "linux")]
fn ensure_linux_tun_permissions(iface: &str) -> Result<()> {
    if fs::metadata("/dev/net/tun").is_err() {
        return Err(anyhow!(linux_tun_setup_error(
            iface,
            "missing /dev/net/tun device"
        )));
    }

    if let Ok(status) = fs::read_to_string("/proc/self/status")
        && linux_cap_eff_has_net_admin(&status) == Some(false)
    {
        return Err(anyhow!(linux_tun_setup_error(
            iface,
            "current process lacks CAP_NET_ADMIN"
        )));
    }

    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn linux_cap_eff_has_net_admin(status: &str) -> Option<bool> {
    let value = status
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("CapEff:"))?
        .trim();
    let caps = u64::from_str_radix(value, 16).ok()?;
    Some((caps & (1_u64 << LINUX_CAP_NET_ADMIN_BIT)) != 0)
}

#[cfg(any(target_os = "linux", test))]
fn linux_tun_setup_error(iface: &str, reason: &str) -> String {
    format!(
        "Linux tunnel setup requires CAP_NET_ADMIN and /dev/net/tun before FIPS can create {iface}: {reason}. For a foreground session run `sudo nvpn start --connect` or `sudo nvpn connect`; for unattended use install/start the system service. In Docker add `--cap-add NET_ADMIN --device /dev/net/tun`."
    )
}

#[cfg(target_os = "linux")]
fn fips_tun_create_context(iface: &str) -> String {
    linux_tun_setup_error(iface, "kernel rejected TUN creation")
}

#[cfg(target_os = "macos")]
fn fips_tun_create_context(iface: &str) -> String {
    format!("failed to create FIPS tunnel {iface}")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_tun_read_task(
    tun: Arc<TunSocket>,
    tun_fd: Arc<AsyncFd<BorrowedTunFd>>,
    packet_tx: mpsc::Sender<TunPipelinePacket>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_535];
        loop {
            let mut guard = match tun_fd.readable().await {
                Ok(guard) => guard,
                Err(error) => {
                    eprintln!("fips: tun reactor await failed: {error}");
                    return;
                }
            };

            let mut drained = 0;
            let mut pending_send = None;
            let mut sleep_after_error = false;
            loop {
                let read_result = {
                    let _t = crate::pipeline_profile::Timer::start(
                        crate::pipeline_profile::Stage::TunRead,
                    );
                    tun.read(&mut buf)
                };
                match read_result {
                    Ok([]) => {
                        // 0-byte read on a readable fd means "no packet right now";
                        // clear ready so the next readable().await blocks on the
                        // kernel instead of busy-looping.
                        guard.clear_ready();
                        break;
                    }
                    Ok(packet) => {
                        let mut bytes = packet.to_vec();
                        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(
                            &mut bytes,
                        );
                        match packet_tx.try_send(TunPipelinePacket::new(bytes)) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(packet)) => {
                                pending_send = Some(packet);
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        }
                        drained += 1;
                        if drained >= FIPS_TUN_READ_BURST {
                            break;
                        }
                        // Keep reading while the fd is hot. BoringTun and
                        // wireguard-go both batch TUN-side work; without this
                        // bounded drain we pay a scheduler/channel round trip
                        // for every packet on the macOS laptop sender path.
                    }
                    Err(error) if temporary_tun_read_error(&error) => {
                        guard.clear_ready();
                        break;
                    }
                    Err(error) => {
                        eprintln!("fips: tunnel read failed: {error}");
                        guard.clear_ready();
                        sleep_after_error = true;
                        break;
                    }
                }
            }
            drop(guard);

            if let Some(packet) = pending_send
                && packet_tx.send(packet).await.is_err()
            {
                break;
            }

            if sleep_after_error {
                sleep(Duration::from_millis(100)).await;
            }

            if drained >= FIPS_TUN_READ_BURST {
                tokio::task::yield_now().await;
            }
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn send_mesh_packet_or_log(mesh: &FipsPrivateMeshRuntime, packet: TunPipelinePacket) {
    crate::pipeline_profile::record_since(
        crate::pipeline_profile::Stage::TunToMeshQueueWait,
        packet.queued_at,
    );
    let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshSend);
    if let Err(error) = mesh.send_tunnel_packet_owned(packet.bytes).await {
        eprintln!("fips: failed to send tunnel packet: {error}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_mesh_recv_task(
    mesh: Arc<FipsPrivateMeshRuntime>,
    tun_fd: Arc<AsyncFd<BorrowedTunFd>>,
    event_tx: mpsc::Sender<FipsPrivateMeshEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match mesh.recv_mesh_event().await {
                Ok(Some(event)) => {
                    if !forward_mesh_event_to_tun(event, &tun_fd, &event_tx).await {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    eprintln!("fips: failed to receive tunnel packet: {error}");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn forward_mesh_event_to_tun(
    event: FipsPrivateMeshEvent,
    tun_fd: &AsyncFd<BorrowedTunFd>,
    event_tx: &mpsc::Sender<FipsPrivateMeshEvent>,
) -> bool {
    match event {
        FipsPrivateMeshEvent::Packet(packet) => {
            // Hot path. Write to TUN inline and DON'T forward the Packet event
            // upstream: the control-loop consumer discards packet events. The
            // raw fd write below still waits on utun writability instead of
            // silently dropping `EWOULDBLOCK` like boringtun's helper does.
            let mut bytes = packet.bytes;
            nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut bytes);
            write_packet_to_tun(tun_fd, &bytes).await;
            true
        }
        event => event_tx.send(event).await.is_ok(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn write_packet_to_tun(tun_fd: &AsyncFd<BorrowedTunFd>, packet: &[u8]) {
    let Some(address_family) = tunnel_packet_address_family(packet) else {
        return;
    };

    let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::TunWrite);
    loop {
        match raw_write_packet_to_tun(tun_fd.get_ref().as_raw_fd(), packet, address_family) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                match tun_fd.writable().await {
                    Ok(mut guard) => guard.clear_ready(),
                    Err(error) => {
                        eprintln!("fips: tunnel write reactor await failed: {error}");
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!("fips: failed to write tunnel packet: {error}");
                return;
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tunnel_packet_address_family(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|byte| byte >> 4) {
        #[cfg(target_os = "macos")]
        Some(4) => Some(2),
        #[cfg(target_os = "macos")]
        Some(6) => Some(30),
        #[cfg(target_os = "linux")]
        Some(4) | Some(6) => Some(0),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn raw_write_packet_to_tun(fd: RawFd, packet: &[u8], address_family: u8) -> io::Result<()> {
    let header = [0_u8, 0, 0, address_family];
    let mut file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    let written = file.write_vectored(&[IoSlice::new(&header), IoSlice::new(packet)])?;
    if written == header.len() + packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short tunnel packet write",
        ))
    }
}

#[cfg(target_os = "linux")]
fn raw_write_packet_to_tun(fd: RawFd, packet: &[u8], _address_family: u8) -> io::Result<()> {
    let mut file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    let written = file.write(packet)?;
    if written == packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short tunnel packet write",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn temporary_tun_read_error(error: &TunError) -> bool {
    match error {
        TunError::IfaceRead(source) => matches!(
            source.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ),
        _ => false,
    }
}

#[cfg(target_os = "windows")]
pub(crate) struct FipsPrivateTunnelRuntime {
    iface: String,
    mesh: Arc<FipsPrivateMeshRuntime>,
    config: FipsPrivateTunnelConfig,
    session: Arc<Session>,
    stop: Arc<AtomicBool>,
    tun_read_thread: ThreadJoinHandle<()>,
    mesh_send_task: JoinHandle<()>,
    mesh_recv_task: JoinHandle<()>,
    event_rx: mpsc::Receiver<FipsPrivateMeshEvent>,
    interface_index: u32,
    route_targets: Vec<String>,
    /// Same shape as the macOS variant: a userspace WG upstream
    /// tunnel (boringtun + a *separate* WinTun adapter, distinct from
    /// the FIPS adapter above) that the daemon reconciles whenever
    /// `wireguard_exit` changes.
    wg_upstream: Option<crate::wg_upstream_runtime::DaemonWgUpstream>,
}

#[cfg(target_os = "windows")]
impl FipsPrivateTunnelRuntime {
    pub(crate) async fn start(config: FipsPrivateTunnelConfig) -> Result<Self> {
        let scope = fips_lan_discovery_scope(&config.network_id);
        let transport = FipsEndpointTransportConfig {
            listen_port: config.listen_port,
            advertised_endpoint: config.advertised_endpoint.clone(),
            advertise_endpoint: config.advertise_endpoint,
            nostr_discovery_enabled: config.nostr_discovery_enabled,
            stun_servers: config.stun_servers.clone(),
            nostr_relays: config.nostr_relays.clone(),
            share_local_candidates: config.share_local_candidates,
        };
        let endpoint_config = fips_endpoint_config(
            &config.endpoint_peers,
            Some(&transport),
            config.mesh_mtu,
            config.nostr_discovery_policy,
        );
        let mesh = Arc::new(
            FipsPrivateMeshRuntime::bind_with_config(
                config.identity_nsec.clone(),
                scope,
                config.peers.clone(),
                endpoint_config,
                config.local_allowed_ips(),
            )
            .await?,
        );
        let (session, iface, interface_index) = start_windows_fips_wintun(&config)?;
        let route_targets =
            crate::windows_tunnel::apply_windows_routes(interface_index, &config.route_targets)?;

        let stop = Arc::new(AtomicBool::new(false));
        let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<Vec<u8>>>(1024);
        let (event_tx, event_rx) = mpsc::channel::<FipsPrivateMeshEvent>(1024);
        let tun_read_thread =
            spawn_windows_fips_tun_read_thread(stop.clone(), session.clone(), packet_tx);
        let mesh_send_task = {
            let mesh = Arc::clone(&mesh);
            tokio::spawn(async move {
                while let Some(packets) = packet_rx.recv().await {
                    for packet in packets {
                        let debug = windows_fips_packet_debug_enabled();
                        if debug {
                            eprintln!(
                                "fips: Windows Wintun -> mesh {} bytes {}",
                                packet.len(),
                                describe_ip_packet(&packet)
                            );
                        }
                        match mesh.send_tunnel_packet_owned(packet).await {
                            Ok(true) => {}
                            Ok(false) => {
                                if debug {
                                    eprintln!("fips: Windows mesh route miss");
                                }
                            }
                            Err(error) => {
                                eprintln!("fips: failed to send Windows tunnel packet: {error}");
                            }
                        }
                    }
                }
            })
        };
        let mesh_recv_task =
            spawn_windows_fips_mesh_recv_task(Arc::clone(&mesh), session.clone(), event_tx);

        let mut runtime = Self {
            iface,
            mesh,
            config: config.clone(),
            session,
            stop,
            tun_read_thread,
            mesh_send_task,
            mesh_recv_task,
            event_rx,
            interface_index,
            route_targets,
            wg_upstream: None,
        };
        // Reconcile the WG upstream against the initial config. Same
        // safe-by-construction guarantee as macOS: if the WG handshake
        // doesn't complete within the watchdog window, the routing
        // table stays untouched.
        runtime
            .reconcile_windows_wg_upstream(&config.wireguard_exit)
            .await;
        Ok(runtime)
    }

    pub(crate) fn iface(&self) -> &str {
        &self.iface
    }

    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        self.mesh.peer_statuses()
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        self.mesh.relay_statuses().await
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        self.mesh.peer_pubkeys()
    }

    pub(crate) async fn authenticated_peer_transport_addrs(&self) -> Result<Vec<(String, String)>> {
        self.mesh.authenticated_peer_transport_addrs().await
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        self.mesh.peer_endpoint_hints()
    }

    /// Forward a refreshed peer roster + address hints to fips without
    /// restarting the endpoint. Daemon heartbeat path: when the
    /// recent-peers cache or active-network roster changes, build the
    /// merged hint list and call this so fips can diff + apply.
    pub(crate) async fn update_peers(
        &self,
        endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        self.mesh.update_peers(endpoint_peers).await
    }

    pub(crate) async fn update_relays(&self, relays: &[String]) -> Result<()> {
        self.mesh.update_relays(relays).await
    }

    pub(crate) fn requires_endpoint_restart(&self, config: &FipsPrivateTunnelConfig) -> bool {
        // See `requires_endpoint_restart` on the unix tunnel runtime for
        // why `endpoint_peers` is not in this list — address hints flow
        // through `update_peers` (no-restart), peer-set changes flow
        // through `apply_config` → `mesh.replace_peers`.
        self.config.identity_nsec != config.identity_nsec
            || self.config.network_id != config.network_id
            || self.config.iface != config.iface
            || self.config.local_address != config.local_address
            || self.config.listen_port != config.listen_port
            || self.config.advertised_endpoint != config.advertised_endpoint
            || self.config.advertise_endpoint != config.advertise_endpoint
            || self.config.stun_servers != config.stun_servers
            || self.config.nostr_relays != config.nostr_relays
            || self.config.nostr_discovery_policy != config.nostr_discovery_policy
            || self.config.mesh_mtu.underlay_udp != config.mesh_mtu.underlay_udp
    }

    pub(crate) async fn apply_config(&mut self, config: FipsPrivateTunnelConfig) -> Result<()> {
        self.mesh
            .replace_peers(config.peers.clone(), config.local_allowed_ips())?;
        if let Err(error) = self.mesh.update_peers(&config.endpoint_peers).await {
            eprintln!("fips: update_peers during apply_config failed: {error}");
        }
        if self.config.nostr_relays != config.nostr_relays {
            self.mesh.update_relays(&config.nostr_relays).await?;
        }
        if self.config.route_targets != config.route_targets {
            crate::windows_tunnel::remove_windows_routes(self.interface_index, &self.route_targets)
                .context("failed to remove stale Windows FIPS routes")?;
            self.route_targets = crate::windows_tunnel::apply_windows_routes(
                self.interface_index,
                &config.route_targets,
            )
            .context("failed to apply Windows FIPS routes")?;
        }
        self.reconcile_windows_wg_upstream(&config.wireguard_exit)
            .await;
        self.config = config;
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&mut self) -> Result<()> {
        Ok(())
    }

    /// Same shape as the macOS reconcile: a no-op if the existing
    /// tunnel already matches, teardown-then-rebuild on config change,
    /// just teardown on disable. Handshake-first, watchdog-protected:
    /// the routing table is only modified after a successful WG
    /// handshake.
    async fn reconcile_windows_wg_upstream(&mut self, wg_config: &WireGuardExitConfig) {
        let want_up = wg_config.enabled && wg_config.configured();
        if want_up
            && self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.matches(wg_config))
        {
            return;
        }
        if let Some(existing) = self.wg_upstream.take() {
            existing.cleanup().await;
        }
        if !want_up {
            return;
        }
        match crate::wg_upstream_runtime::apply_daemon_wg_upstream(
            wg_config,
            crate::wg_upstream_runtime::DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT,
        )
        .await
        {
            Ok(handle) => {
                eprintln!(
                    "fips: WG upstream up on {} via {} (default route swapped)",
                    handle.iface, handle.upstream
                );
                self.wg_upstream = Some(handle);
            }
            Err(error) => {
                eprintln!("fips: WG upstream not started: {error}");
            }
        }
    }

    pub(crate) async fn ping_peers(&self, network_id: &str, now: u64) -> Result<usize> {
        self.mesh.ping_peers(network_id, now).await
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        self.mesh.refresh_link_statuses().await
    }

    pub(crate) async fn send_join_request(
        &self,
        participant: &str,
        requested_at: u64,
        request: MeshJoinRequest,
    ) -> Result<()> {
        self.mesh
            .send_join_request(participant, requested_at, request)
            .await
    }

    pub(crate) async fn send_roster(
        &self,
        participant: &str,
        signed_roster: SignedRoster,
    ) -> Result<()> {
        self.mesh.send_roster(participant, signed_roster).await
    }

    pub(crate) async fn send_capabilities(
        &self,
        participant: &str,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<()> {
        self.mesh
            .send_capabilities(participant, network_id, capabilities)
            .await
    }

    pub(crate) async fn broadcast_capabilities(
        &self,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<usize> {
        self.mesh
            .broadcast_capabilities(network_id, capabilities)
            .await
    }

    pub(crate) fn peer_advertised_routes(&self, participant: &str) -> Vec<String> {
        self.mesh.peer_advertised_routes(participant)
    }

    pub(crate) fn drain_events(&mut self) -> Vec<FipsPrivateMeshEvent> {
        drain_event_batch(&mut self.event_rx, FIPS_MESH_EVENT_DRAIN_LIMIT)
    }

    pub(crate) async fn stop(self) -> Result<()> {
        let mut runtime = self;
        // Tear the WG upstream down BEFORE the FIPS bits so the route
        // revert lands while we still have a sane working tree.
        if let Some(handle) = runtime.wg_upstream.take() {
            handle.cleanup().await;
        }
        runtime.stop.store(true, Ordering::Relaxed);
        let _ = runtime.session.shutdown();
        if let Err(error) = crate::windows_tunnel::remove_windows_routes(
            runtime.interface_index,
            &runtime.route_targets,
        ) {
            eprintln!("fips: failed to remove Windows FIPS routes: {error}");
        }
        let _ = runtime.tun_read_thread.join();
        runtime.mesh_send_task.abort();
        runtime.mesh_recv_task.abort();
        let _ = runtime.mesh_send_task.await;
        let _ = runtime.mesh_recv_task.await;
        if let Ok(mesh) = Arc::try_unwrap(runtime.mesh) {
            mesh.shutdown()
                .await
                .context("failed to stop FIPS endpoint")?;
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn start_windows_fips_wintun(
    config: &FipsPrivateTunnelConfig,
) -> Result<(Arc<Session>, String, u32)> {
    let wintun = load_wintun()?;
    let adapter = Adapter::open(&wintun, &config.iface)
        .or_else(|_| Adapter::create(&wintun, &config.iface, "NostrVPN", None))
        .with_context(|| format!("failed to open or create wintun adapter {}", config.iface))?;
    adapter
        .set_mtu(config.mesh_mtu.tunnel as usize)
        .with_context(|| format!("failed to set MTU on wintun adapter {}", config.iface))?;
    let parsed_address = crate::windows_tunnel::windows_interface_address(&config.local_address)?;
    adapter
        .set_network_addresses_tuple(
            parsed_address.address.into(),
            parsed_address.mask.into(),
            None,
        )
        .with_context(|| format!("failed to set address on wintun adapter {}", config.iface))?;
    let interface_index = adapter
        .get_adapter_index()
        .with_context(|| format!("failed to resolve interface index for {}", config.iface))?;
    let session = Arc::new(
        adapter
            .start_session(MAX_RING_CAPACITY)
            .with_context(|| format!("failed to start wintun session for {}", config.iface))?,
    );
    Ok((session, config.iface.clone(), interface_index))
}

#[cfg(target_os = "windows")]
fn spawn_windows_fips_tun_read_thread(
    stop: Arc<AtomicBool>,
    session: Arc<Session>,
    packet_tx: mpsc::Sender<Vec<Vec<u8>>>,
) -> ThreadJoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let packet = match session.receive_blocking() {
                Ok(packet) => packet,
                Err(error) => {
                    if !stop.load(Ordering::Relaxed) {
                        eprintln!("fips: Windows Wintun receive failed: {error}");
                    }
                    break;
                }
            };
            let mut batch = Vec::with_capacity(WINDOWS_FIPS_TUN_READ_BURST);
            let payload = packet.bytes().to_vec();
            drop(packet);
            if windows_fips_packet_debug_enabled() {
                eprintln!(
                    "fips: Windows Wintun read {} bytes {}",
                    payload.len(),
                    describe_ip_packet(&payload)
                );
            }
            batch.push(payload);
            while batch.len() < WINDOWS_FIPS_TUN_READ_BURST {
                match session.try_receive() {
                    Ok(Some(packet)) => {
                        let payload = packet.bytes().to_vec();
                        drop(packet);
                        if windows_fips_packet_debug_enabled() {
                            eprintln!(
                                "fips: Windows Wintun read {} bytes {}",
                                payload.len(),
                                describe_ip_packet(&payload)
                            );
                        }
                        batch.push(payload);
                    }
                    Ok(None) => break,
                    Err(error) => {
                        if !stop.load(Ordering::Relaxed) {
                            eprintln!("fips: Windows Wintun receive failed: {error}");
                        }
                        return;
                    }
                }
            }
            if packet_tx.blocking_send(batch).is_err() {
                break;
            }
        }
    })
}

#[cfg(target_os = "windows")]
fn spawn_windows_fips_mesh_recv_task(
    mesh: Arc<FipsPrivateMeshRuntime>,
    session: Arc<Session>,
    event_tx: mpsc::Sender<FipsPrivateMeshEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match mesh.recv_mesh_event().await {
                Ok(Some(FipsPrivateMeshEvent::Packet(packet))) => {
                    // Hot path; write to Wintun inline and don't forward
                    // upstream — see linux/macos branch for rationale.
                    let mut packets = Vec::with_capacity(WINDOWS_FIPS_TUN_WRITE_BURST);
                    packets.push(packet.bytes);
                    while packets.len() < WINDOWS_FIPS_TUN_WRITE_BURST {
                        match mesh.try_recv_mesh_event().await {
                            Ok(Some(FipsPrivateMeshEvent::Packet(packet))) => {
                                packets.push(packet.bytes);
                            }
                            Ok(Some(event)) => {
                                if event_tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                            Ok(None) => break,
                            Err(error) => {
                                eprintln!("fips: failed to drain Windows tunnel packets: {error}");
                                break;
                            }
                        }
                    }
                    if windows_fips_packet_debug_enabled() {
                        for packet in &packets {
                            eprintln!(
                                "fips: Windows mesh -> Wintun {} bytes {}",
                                packet.len(),
                                describe_ip_packet(packet)
                            );
                        }
                    }
                    if let Err(error) =
                        crate::windows_tunnel::write_tunnel_packets(&session, &packets)
                    {
                        eprintln!("fips: failed to write Windows tunnel packet: {error}");
                    }
                }
                Ok(Some(event)) => {
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    eprintln!("fips: failed to receive tunnel packet: {error}");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

#[cfg(target_os = "windows")]
fn windows_fips_packet_debug_enabled() -> bool {
    std::env::var_os("NVPN_FIPS_PACKET_DEBUG").is_some()
}

#[cfg(target_os = "windows")]
fn describe_ip_packet(packet: &[u8]) -> String {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => format!(
            "{} -> {}",
            std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])
        ),
        Some(6) if packet.len() >= 40 => "IPv6".to_string(),
        Some(version) => format!("IPv{version} malformed"),
        None => "empty packet".to_string(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) struct FipsPrivateTunnelRuntime;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl FipsPrivateTunnelRuntime {
    pub(crate) async fn start(_config: FipsPrivateTunnelConfig) -> Result<Self> {
        Err(anyhow!(
            "FIPS private tunnel runtime is not implemented for this platform"
        ))
    }

    pub(crate) fn iface(&self) -> &str {
        ""
    }

    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        Vec::new()
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        Ok(Vec::new())
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        Vec::new()
    }

    pub(crate) async fn authenticated_peer_transport_addrs(&self) -> Result<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        Vec::new()
    }

    pub(crate) async fn update_peers(
        &self,
        _endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        Ok(fips_endpoint::UpdatePeersOutcome::default())
    }

    pub(crate) async fn update_relays(&self, _relays: &[String]) -> Result<()> {
        Ok(())
    }

    pub(crate) fn requires_endpoint_restart(&self, _config: &FipsPrivateTunnelConfig) -> bool {
        false
    }

    pub(crate) async fn apply_config(&self, _config: FipsPrivateTunnelConfig) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn ping_peers(&self, _network_id: &str, _now: u64) -> Result<usize> {
        Ok(0)
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn send_join_request(
        &self,
        _participant: &str,
        _requested_at: u64,
        _request: MeshJoinRequest,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn send_roster(
        &self,
        _participant: &str,
        _signed_roster: SignedRoster,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn send_capabilities(
        &self,
        _participant: &str,
        _network_id: &str,
        _capabilities: PeerCapabilities,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn broadcast_capabilities(
        &self,
        _network_id: &str,
        _capabilities: PeerCapabilities,
    ) -> Result<usize> {
        Ok(0)
    }

    pub(crate) fn peer_advertised_routes(&self, _participant: &str) -> Vec<String> {
        Vec::new()
    }

    pub(crate) fn drain_events(&mut self) -> Vec<FipsPrivateMeshEvent> {
        Vec::new()
    }

    pub(crate) async fn stop(self) -> Result<()> {
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        ControlFragmentBuffer, FIPS_DISCOVERY_BACKOFF_BASE_SECS, FIPS_DISCOVERY_BACKOFF_MAX_SECS,
        FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS, FIPS_LAN_DISCOVERY_SCOPE_PREFIX,
        FIPS_MESH_EVENT_DRAIN_LIMIT, FIPS_NOSTR_DISCOVERY_APP, FIPS_NOSTR_FAILURE_STREAK_THRESHOLD,
        FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING, FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS,
        FipsEndpointTransportConfig, FipsPeerAddressHint, FipsPrivateMeshEvent,
        FipsPrivateMeshRuntime, FipsPrivateTunnelConfig, control_frame_destination_npub,
        control_frame_source_pubkey, drain_event_batch, fips_endpoint_config,
        fips_endpoint_peers_from_mesh, fips_lan_discovery_scope, fips_peer_address_from_hint,
        linux_cap_eff_has_net_admin, linux_tun_setup_error, other_endpoint_peer_statuses,
        parse_fips_nostr_discovery_policy, strip_cidr, tag_authenticated_transport_addr,
        unix_timestamp,
    };
    use fips_endpoint::{
        Config, ConnectPolicy, FipsEndpointPeer, NostrDiscoveryPolicy,
        PeerConfig as FipsPeerConfig, RoutingMode, TransportInstances, UdpConfig,
    };
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::{AppConfig, PendingOutboundJoinRequest, derive_mesh_tunnel_ip};
    use nostr_vpn_core::data_plane::MeshPeerStatus;
    use nostr_vpn_core::fips_control::{
        FipsControlFrame, NetworkRoster, PeerEndpointHint, decode_fips_control_frame,
        encode_fips_control_messages,
    };
    use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
    use nostr_vpn_core::join_requests::MeshJoinRequest;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    #[test]
    fn parses_fips_nostr_discovery_policy_override() {
        assert_eq!(
            parse_fips_nostr_discovery_policy("configured-only"),
            Some(fips_endpoint::NostrDiscoveryPolicy::ConfiguredOnly)
        );
        assert_eq!(
            parse_fips_nostr_discovery_policy("configured_only"),
            Some(fips_endpoint::NostrDiscoveryPolicy::ConfiguredOnly)
        );
        assert_eq!(
            parse_fips_nostr_discovery_policy("open"),
            Some(fips_endpoint::NostrDiscoveryPolicy::Open)
        );
        assert_eq!(
            parse_fips_nostr_discovery_policy("disabled"),
            Some(fips_endpoint::NostrDiscoveryPolicy::Disabled)
        );
        assert_eq!(parse_fips_nostr_discovery_policy("wat"), None);
    }

    #[test]
    fn authenticated_transport_addr_preserves_tcp_type_and_legacy_udp() {
        assert_eq!(
            tag_authenticated_transport_addr(
                Some("203.0.113.20:51820".to_string()),
                Some("udp".to_string())
            ),
            Some("203.0.113.20:51820".to_string())
        );
        assert_eq!(
            tag_authenticated_transport_addr(
                Some("203.0.113.20:443".to_string()),
                Some("tcp".to_string())
            ),
            Some("tcp:203.0.113.20:443".to_string())
        );
        assert_eq!(
            tag_authenticated_transport_addr(Some("tcp:203.0.113.20:443".to_string()), None),
            Some("tcp:203.0.113.20:443".to_string())
        );
    }

    #[test]
    fn fips_peer_address_hint_splits_transport_tags_for_live_updates() {
        let tcp = fips_peer_address_from_hint(&FipsPeerAddressHint {
            addr: "tcp:203.0.113.20:443".to_string(),
            seen_at_ms: Some(123_000),
        });
        assert_eq!(tcp.transport, "tcp");
        assert_eq!(tcp.addr, "203.0.113.20:443");
        assert_eq!(tcp.seen_at_ms, Some(123_000));

        let udp = fips_peer_address_from_hint(&FipsPeerAddressHint {
            addr: "udp:203.0.113.21:2121".to_string(),
            seen_at_ms: None,
        });
        assert_eq!(udp.transport, "udp");
        assert_eq!(udp.addr, "203.0.113.21:2121");
    }

    #[test]
    fn fips_private_tunnel_config_uses_non_roster_peer_setting_for_discovery_policy() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let mut app = AppConfig::generated();
        app.fips_host_tunnel_enabled = false;
        app.connect_to_non_roster_fips_peers = false;
        let network_id = app.effective_network_id();
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("configured-only tunnel config");
        assert_eq!(
            config.nostr_discovery_policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );

        app.connect_to_non_roster_fips_peers = true;
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("open tunnel config");
        assert_eq!(config.nostr_discovery_policy, NostrDiscoveryPolicy::Open);
    }

    #[test]
    fn linux_cap_eff_parsing_detects_net_admin() {
        assert_eq!(
            linux_cap_eff_has_net_admin("CapEff:\t0000000000000000\n"),
            Some(false)
        );
        assert_eq!(
            linux_cap_eff_has_net_admin("CapEff:\t0000000000001000\n"),
            Some(true)
        );
        assert_eq!(linux_cap_eff_has_net_admin("Name:\tnvpn\n"), None);
    }

    #[test]
    fn linux_tun_setup_error_points_to_root_service_or_docker_flags() {
        let message = linux_tun_setup_error("utun100", "current process lacks CAP_NET_ADMIN");

        assert!(message.contains("CAP_NET_ADMIN"));
        assert!(message.contains("/dev/net/tun"));
        assert!(message.contains("utun100"));
        assert!(message.contains("sudo nvpn start --connect"));
        assert!(message.contains("system service"));
        assert!(message.contains("--cap-add NET_ADMIN --device /dev/net/tun"));
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let total_len = 20 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(&payload);
        packet
    }

    #[test]
    fn drain_event_batch_respects_limit() {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<FipsPrivateMeshEvent>(FIPS_MESH_EVENT_DRAIN_LIMIT + 8);
        for index in 0..(FIPS_MESH_EVENT_DRAIN_LIMIT + 5) {
            tx.try_send(FipsPrivateMeshEvent::Presence {
                participant_pubkey: format!("peer-{index}"),
                last_seen_at: index as u64,
            })
            .expect("queue test event");
        }

        let drained = drain_event_batch(&mut rx, FIPS_MESH_EVENT_DRAIN_LIMIT);

        assert_eq!(drained.len(), FIPS_MESH_EVENT_DRAIN_LIMIT);
        assert_eq!(rx.len(), 5);
    }

    fn mesh_peer_status(
        pubkey: impl AsRef<str>,
        endpoint_npub: impl AsRef<str>,
        transport_addr: Option<&str>,
        transport_type: Option<&str>,
        connected: bool,
        last_seen_at: Option<u64>,
    ) -> MeshPeerStatus {
        MeshPeerStatus {
            pubkey: pubkey.as_ref().to_string(),
            connected,
            endpoint_npub: endpoint_npub.as_ref().to_string(),
            transport_addr: transport_addr.map(str::to_string),
            transport_type: transport_type.map(str::to_string),
            srtt_ms: Some(18),
            link_packets_sent: 7,
            link_packets_recv: 8,
            link_bytes_sent: 900,
            link_bytes_recv: 1200,
            last_seen_at,
            tx_bytes: 0,
            rx_bytes: 0,
            error: None,
        }
    }

    #[test]
    fn non_roster_endpoint_peers_surface_as_mesh_statuses() {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().expect("npub");
        let mut peers = HashMap::new();
        peers.insert(
            pubkey.clone(),
            FipsEndpointPeer {
                npub: npub.clone(),
                transport_addr: Some("203.0.113.9:9000".to_string()),
                transport_type: Some("udp".to_string()),
                link_id: 42,
                srtt_ms: Some(7),
                packets_sent: 11,
                packets_recv: 12,
                bytes_sent: 1300,
                bytes_recv: 1400,
            },
        );

        let statuses = other_endpoint_peer_statuses(&peers, 123);

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].pubkey, pubkey);
        assert_eq!(statuses[0].endpoint_npub, npub);
        assert!(statuses[0].connected);
        assert_eq!(
            statuses[0].transport_addr.as_deref(),
            Some("203.0.113.9:9000")
        );
        assert_eq!(statuses[0].transport_type.as_deref(), Some("udp"));
        assert_eq!(statuses[0].srtt_ms, Some(7));
        assert_eq!(statuses[0].link_packets_sent, 11);
        assert_eq!(statuses[0].link_packets_recv, 12);
        assert_eq!(statuses[0].link_bytes_sent, 1300);
        assert_eq!(statuses[0].link_bytes_recv, 1400);
        assert_eq!(statuses[0].last_seen_at, Some(123));
        assert_eq!(statuses[0].error, None);
    }

    #[test]
    fn fragmented_control_frames_reassemble_to_original_frame() {
        let roster = NetworkRoster {
            network_name: "Network 1".to_string(),
            participants: (0..12).map(|value| format!("{value:064x}")).collect(),
            admins: vec!["f".repeat(64)],
            aliases: (0..12)
                .map(|value| (format!("{value:064x}"), format!("node-{value}")))
                .collect(),
            signed_at: 123,
        };
        let frame = FipsControlFrame::Roster {
            network_id: "mesh".to_string(),
            roster,
            signed_roster: None,
        };
        let messages = encode_fips_control_messages(&frame).expect("fragment messages");
        let mut buffer = ControlFragmentBuffer::default();
        let mut reassembled = None;

        for message in messages {
            let decoded = decode_fips_control_frame(&message)
                .expect("decode fragment")
                .expect("fragment frame");
            let FipsControlFrame::Fragment {
                id,
                index,
                total,
                data,
            } = decoded
            else {
                panic!("expected fragment");
            };
            reassembled = buffer
                .push("npub1source", id, index, total, data, 1)
                .expect("push fragment")
                .or(reassembled);
        }

        let decoded = decode_fips_control_frame(&reassembled.expect("reassembled frame"))
            .expect("decode reassembled")
            .expect("control frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn private_mesh_mtu_defaults_to_safe_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, None, None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: nostr_vpn_core::MESH_UNDERLAY_UDP_MTU,
                tunnel: nostr_vpn_core::MESH_TUNNEL_MTU,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_lan_profile_uses_larger_paired_budget() {
        let mtu = super::resolve_private_mesh_mtu(Some(" LAN "), None, None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1420,
                tunnel: 1290,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_underlay_override_derives_tunnel_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, Some(1500), None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1500,
                tunnel: 1370,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_caps_tunnel_to_underlay_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, Some(1280), Some(1420));

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1280,
                tunnel: 1150,
            }
        );
    }

    #[test]
    fn peer_endpoint_hint_addr_accepts_only_udp_socket_addresses() {
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22:51820")),
            Some("192.168.50.22:51820".to_string())
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("peer.example.com:51820")),
            Some("peer.example.com:51820".to_string())
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint {
                transport: "tcp".to_string(),
                addr: "192.168.50.22:51820".to_string(),
            }),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("127.0.0.1:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("100.120.94.10:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("198.51.100.10:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("0.0.0.0:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("localhost:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp(format!(
                "{}:51820",
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            ))),
            None
        );
    }

    #[test]
    fn fips_peer_liveness_trusts_authenticated_link_snapshot() {
        assert_eq!(
            super::fips_peer_liveness(Some(100), true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(None, true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(Some(10), true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(None, false, Some("dial failed".to_string()), 120),
            (false, Some("dial failed".to_string()))
        );
    }

    #[test]
    fn fips_peer_ping_due_uses_peer_state_intervals() {
        assert!(super::fips_peer_ping_due(Some(100), None, true, 120));
        assert!(!super::fips_peer_ping_due(Some(100), Some(115), true, 120));
        assert!(super::fips_peer_ping_due(Some(100), Some(110), true, 120));

        assert!(!super::fips_peer_ping_due(None, Some(110), true, 120));
        assert!(super::fips_peer_ping_due(None, Some(105), true, 120));

        assert!(!super::fips_peer_ping_due(None, Some(1), false, 120));
        assert!(super::fips_peer_ping_due(None, Some(0), false, 120));
    }

    #[test]
    fn control_frames_from_rostered_endpoint_resolve_to_participant() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let endpoint_npub = keys.public_key().to_bech32().expect("npub");
        let mesh = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: participant_pubkey.clone(),
            endpoint_npub: endpoint_npub.clone(),
            allowed_ips: vec!["10.44.1.2/32".to_string()],
        }]);
        let frame = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: 42,
        };

        assert_eq!(
            control_frame_source_pubkey(&mesh, Some(&endpoint_npub), &frame),
            Some(participant_pubkey)
        );
    }

    #[test]
    fn control_frames_from_unknown_endpoints_are_limited_to_join_requests() {
        let keys = Keys::generate();
        let unknown_pubkey = keys.public_key().to_hex();
        let unknown_npub = keys.public_key().to_bech32().expect("npub");
        let mesh = FipsMeshRuntime::new(Vec::new());
        let ping = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: 42,
        };
        let roster = FipsControlFrame::Roster {
            network_id: "network".to_string(),
            roster: NetworkRoster {
                network_name: "network".to_string(),
                participants: Vec::new(),
                admins: Vec::new(),
                aliases: HashMap::new(),
                signed_at: 42,
            },
            signed_roster: None,
        };
        let join_request = FipsControlFrame::JoinRequest {
            requested_at: 42,
            request: MeshJoinRequest {
                network_id: "network".to_string(),
                invite_secret: String::new(),
                requester_node_name: "new-device".to_string(),
            },
        };

        assert!(control_frame_source_pubkey(&mesh, Some(&unknown_npub), &ping).is_none());
        assert!(control_frame_source_pubkey(&mesh, Some(&unknown_npub), &roster).is_none());
        assert_eq!(
            control_frame_source_pubkey(&mesh, Some(&unknown_npub), &join_request),
            Some(unknown_pubkey)
        );
    }

    #[test]
    fn control_frame_destinations_can_target_pending_join_requester() {
        let keys = Keys::generate();
        let requester_pubkey = keys.public_key().to_hex();
        let requester_npub = keys.public_key().to_bech32().expect("npub");
        let mesh = FipsMeshRuntime::new(Vec::new());

        assert_eq!(
            control_frame_destination_npub(&mesh, &requester_pubkey).expect("destination npub"),
            requester_npub
        );
    }

    #[tokio::test]
    async fn endpoint_data_runtime_sends_and_receives_raw_packets() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let participant_pubkey = keys.public_key().to_hex();
        let source = Ipv4Addr::new(10, 44, 10, 1);
        let destination = Ipv4Addr::new(10, 44, 22, 44);

        // The FIPS endpoint self-loop is used only to exercise send/recv
        // without external discovery. Real peers should not own both routes.
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec![format!("{source}/32"), format!("{destination}/32")],
        )
        .expect("peer config");
        let runtime = FipsPrivateMeshRuntime::bind(nsec, "test-network", vec![peer])
            .await
            .expect("runtime should bind");
        let packet = ipv4_packet(source, destination);

        let sent = runtime
            .send_tunnel_packet(&packet)
            .await
            .expect("send packet");
        assert!(sent);

        let received = tokio::time::timeout(Duration::from_secs(2), runtime.recv_tunnel_packet())
            .await
            .expect("packet should arrive")
            .expect("receive packet")
            .expect("packet should pass admission");

        assert_eq!(received.source_pubkey, participant_pubkey);
        assert_eq!(received.bytes, packet);
        runtime.shutdown().await.expect("shutdown");
    }

    fn available_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .expect("bind test port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    #[test]
    fn tunnel_config_routes_default_through_selected_exit_peer() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let carol_pubkey = carol_keys.public_key().to_hex();
        let network_id = "fips-exit-route-test";
        let bob_tunnel_ip = derive_mesh_tunnel_ip(network_id, &bob_pubkey).expect("bob tunnel ip");

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].participants = vec![
            alice_pubkey.clone(),
            bob_pubkey.clone(),
            carol_pubkey.clone(),
        ];
        app.exit_node = bob_pubkey.clone();

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");
        let bob_peer = config
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == bob_pubkey)
            .expect("bob peer");
        let carol_peer = config
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == carol_pubkey)
            .expect("carol peer");

        assert!(bob_peer.allowed_ips.contains(&bob_tunnel_ip));
        assert!(bob_peer.allowed_ips.contains(&"0.0.0.0/0".to_string()));
        assert!(!bob_peer.allowed_ips.contains(&"::/0".to_string()));
        assert!(!carol_peer.allowed_ips.contains(&"0.0.0.0/0".to_string()));
        assert!(config.route_targets.contains(&"0.0.0.0/0".to_string()));
        assert!(!config.route_targets.contains(&"::/0".to_string()));
    }

    fn direct_udp_endpoint_config(
        local_port: u16,
        peer_npub: &str,
        peer_port: u16,
        auto_connect: bool,
    ) -> Config {
        let mut config = Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{local_port}")),
            accept_connections: Some(true),
            ..UdpConfig::default()
        });
        let mut peer = FipsPeerConfig::new(peer_npub, "udp", format!("127.0.0.1:{peer_port}"));
        if !auto_connect {
            peer.connect_policy = ConnectPolicy::Manual;
        }
        config.peers.push(peer);
        config
    }

    fn direct_udp_endpoint_config_many(local_port: u16, peers: &[(&str, u16, bool)]) -> Config {
        let mut config = Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{local_port}")),
            accept_connections: Some(true),
            ..UdpConfig::default()
        });
        for (peer_npub, peer_port, auto_connect) in peers {
            let mut peer = FipsPeerConfig::new(*peer_npub, "udp", format!("127.0.0.1:{peer_port}"));
            if !*auto_connect {
                peer.connect_policy = ConnectPolicy::Manual;
            }
            config.peers.push(peer);
        }
        config
    }

    async fn send_with_retry(runtime: &FipsPrivateMeshRuntime, packet: &[u8]) {
        let mut last_error = None;
        for _ in 0..50 {
            match runtime.send_tunnel_packet(packet).await {
                Ok(true) => return,
                Ok(false) => panic!("packet had no FIPS route"),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        panic!(
            "packet did not send after retry: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }

    async fn wait_for_fips_peer(runtime: &FipsPrivateMeshRuntime, peer_npub: &str) {
        let mut last_snapshot = Vec::new();
        let mut last_error = None;
        for _ in 0..50 {
            match runtime.endpoint.peers().await {
                Ok(peers) => {
                    if peers.iter().any(|peer| {
                        peer.npub == peer_npub && peer.transport_addr.as_deref().is_some()
                    }) {
                        return;
                    }
                    last_snapshot = peers;
                }
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "FIPS peer {peer_npub} did not establish; last snapshot: {last_snapshot:?}; last error: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
    }

    #[tokio::test]
    async fn two_local_endpoints_exchange_raw_packets_over_fips() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let bob_nsec = bob_keys.secret_key().to_bech32().expect("bob nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let alice_port = available_udp_port();
        let bob_port = available_udp_port();
        let alice_ip = Ipv4Addr::new(10, 44, 11, 1);
        let bob_ip = Ipv4Addr::new(10, 44, 11, 2);
        let scope = "nostr-vpn:two-local-endpoints";

        let alice_runtime = FipsPrivateMeshRuntime::bind_with_config(
            alice_nsec,
            scope,
            vec![FipsMeshPeerConfig {
                participant_pubkey: bob_pubkey.clone(),
                endpoint_npub: bob_npub.clone(),
                allowed_ips: vec![format!("{bob_ip}/32")],
            }],
            direct_udp_endpoint_config(alice_port, &bob_npub, bob_port, true),
            vec![format!("{alice_ip}/32")],
        )
        .await
        .expect("alice endpoint should bind");
        let bob_runtime = FipsPrivateMeshRuntime::bind_with_config(
            bob_nsec,
            scope,
            vec![FipsMeshPeerConfig {
                participant_pubkey: alice_pubkey.clone(),
                endpoint_npub: alice_npub.clone(),
                allowed_ips: vec![format!("{alice_ip}/32")],
            }],
            direct_udp_endpoint_config(bob_port, &alice_npub, alice_port, false),
            vec![format!("{bob_ip}/32")],
        )
        .await
        .expect("bob endpoint should bind");

        wait_for_fips_peer(&alice_runtime, &bob_npub).await;
        wait_for_fips_peer(&bob_runtime, &alice_npub).await;

        let alice_to_bob = ipv4_packet(alice_ip, bob_ip);
        send_with_retry(&alice_runtime, &alice_to_bob).await;
        let received =
            tokio::time::timeout(Duration::from_secs(5), bob_runtime.recv_tunnel_packet())
                .await
                .expect("Bob should receive Alice packet")
                .expect("receive packet")
                .expect("packet should pass Bob admission");
        assert_eq!(received.source_pubkey, alice_pubkey);
        assert_eq!(received.bytes, alice_to_bob);

        let bob_to_alice = ipv4_packet(bob_ip, alice_ip);
        send_with_retry(&bob_runtime, &bob_to_alice).await;
        let received =
            tokio::time::timeout(Duration::from_secs(5), alice_runtime.recv_tunnel_packet())
                .await
                .expect("Alice should receive Bob packet")
                .expect("receive packet")
                .expect("packet should pass Alice admission");
        assert_eq!(received.source_pubkey, bob_pubkey);
        assert_eq!(received.bytes, bob_to_alice);

        alice_runtime.shutdown().await.expect("shutdown alice");
        bob_runtime.shutdown().await.expect("shutdown bob");
    }

    #[tokio::test]
    async fn relayed_control_ping_marks_peer_present_without_direct_link() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let bob_nsec = bob_keys.secret_key().to_bech32().expect("bob nsec");
        let carol_nsec = carol_keys.secret_key().to_bech32().expect("carol nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let carol_pubkey = carol_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let carol_npub = carol_keys.public_key().to_bech32().expect("carol npub");
        let alice_port = available_udp_port();
        let bob_port = available_udp_port();
        let carol_port = available_udp_port();
        let alice_ip = Ipv4Addr::new(10, 44, 21, 1);
        let bob_ip = Ipv4Addr::new(10, 44, 21, 2);
        let carol_ip = Ipv4Addr::new(10, 44, 21, 3);
        let scope = "nostr-vpn:relayed-control-presence";

        let alice_runtime = FipsPrivateMeshRuntime::bind_with_config(
            alice_nsec,
            scope,
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: bob_pubkey.clone(),
                    endpoint_npub: bob_npub.clone(),
                    allowed_ips: vec![format!("{bob_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: carol_pubkey.clone(),
                    endpoint_npub: carol_npub.clone(),
                    allowed_ips: vec![format!("{carol_ip}/32")],
                },
            ],
            direct_udp_endpoint_config_many(alice_port, &[(&bob_npub, bob_port, true)]),
            vec![format!("{alice_ip}/32")],
        )
        .await
        .expect("alice endpoint should bind");
        let bob_runtime = FipsPrivateMeshRuntime::bind_with_config(
            bob_nsec,
            scope,
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: alice_pubkey.clone(),
                    endpoint_npub: alice_npub.clone(),
                    allowed_ips: vec![format!("{alice_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: carol_pubkey.clone(),
                    endpoint_npub: carol_npub.clone(),
                    allowed_ips: vec![format!("{carol_ip}/32")],
                },
            ],
            direct_udp_endpoint_config_many(
                bob_port,
                &[
                    (&alice_npub, alice_port, true),
                    (&carol_npub, carol_port, true),
                ],
            ),
            vec![format!("{bob_ip}/32")],
        )
        .await
        .expect("bob endpoint should bind");
        let carol_runtime = FipsPrivateMeshRuntime::bind_with_config(
            carol_nsec,
            scope,
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: alice_pubkey.clone(),
                    endpoint_npub: alice_npub.clone(),
                    allowed_ips: vec![format!("{alice_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: bob_pubkey.clone(),
                    endpoint_npub: bob_npub.clone(),
                    allowed_ips: vec![format!("{bob_ip}/32")],
                },
            ],
            direct_udp_endpoint_config_many(carol_port, &[(&bob_npub, bob_port, true)]),
            vec![format!("{carol_ip}/32")],
        )
        .await
        .expect("carol endpoint should bind");

        wait_for_fips_peer(&alice_runtime, &bob_npub).await;
        wait_for_fips_peer(&bob_runtime, &alice_npub).await;
        wait_for_fips_peer(&bob_runtime, &carol_npub).await;
        wait_for_fips_peer(&carol_runtime, &bob_npub).await;

        let frame = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: unix_timestamp(),
        };
        let mut alice_saw_carol = false;
        for _ in 0..80 {
            let _ = alice_runtime
                .send_control_frame(&carol_pubkey, &frame)
                .await;

            let _ =
                tokio::time::timeout(Duration::from_millis(50), carol_runtime.recv_mesh_event())
                    .await;

            if let Ok(Ok(Some(FipsPrivateMeshEvent::Presence {
                participant_pubkey, ..
            }))) =
                tokio::time::timeout(Duration::from_millis(50), alice_runtime.recv_mesh_event())
                    .await
                && participant_pubkey == carol_pubkey
            {
                alice_saw_carol = true;
                break;
            }
        }

        assert!(alice_saw_carol, "Alice never received Carol's relayed Pong");
        let carol_status = alice_runtime
            .peer_statuses()
            .into_iter()
            .find(|status| status.pubkey == carol_pubkey)
            .expect("Carol status");
        assert!(carol_status.connected);
        assert_eq!(carol_status.transport_addr, None);

        alice_runtime.shutdown().await.expect("shutdown alice");
        bob_runtime.shutdown().await.expect("shutdown bob");
        carol_runtime.shutdown().await.expect("shutdown carol");
    }

    #[test]
    fn endpoint_config_respects_requested_nostr_policy() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
        );

        assert!(!config.node.control.enabled);
        assert_eq!(config.node.routing.mode, RoutingMode::ReplyLearned);
        assert!(!config.dns.enabled);
        assert_eq!(
            config.node.discovery.backoff_base_secs,
            FIPS_DISCOVERY_BACKOFF_BASE_SECS
        );
        assert_eq!(
            config.node.discovery.backoff_max_secs,
            FIPS_DISCOVERY_BACKOFF_MAX_SECS
        );
        assert_eq!(
            config.node.discovery.forward_min_interval_secs,
            FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS
        );
        assert!(config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open
        );
        let configured_only_config = fips_endpoint_config(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::ConfiguredOnly,
        );
        assert_eq!(
            configured_only_config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            FIPS_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert_eq!(
            config.node.discovery.nostr.startup_sweep_max_age_secs,
            FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS
        );
        assert!(!config.node.discovery.nostr.share_local_candidates);
        assert!(!config.node.discovery.lan.enabled);
        // The mesh id must NOT appear in the publicly visible relay app tag.
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        let udp = match config.transports.udp {
            fips_endpoint::TransportInstances::Single(udp) => udp,
            _ => panic!("expected one UDP transport"),
        };
        assert!(udp.outbound_only());
        assert!(!udp.advertise_on_nostr());
        assert!(!udp.accept_connections());
        assert_eq!(config.peers.len(), 1);
        assert!(config.peers[0].addresses.is_empty());
    }

    #[test]
    fn lan_discovery_scope_is_hashed_from_network_id() {
        let scope = fips_lan_discovery_scope(" private-network-id ");
        assert!(scope.starts_with(&format!("{FIPS_LAN_DISCOVERY_SCOPE_PREFIX}:")));
        assert!(!scope.contains("private-network-id"));
        assert_eq!(scope, fips_lan_discovery_scope("private-network-id"));
    }

    #[test]
    fn endpoint_config_advertises_app_owned_endpoint_over_nostr() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let transport = FipsEndpointTransportConfig {
            listen_port: 51820,
            advertised_endpoint: "192.168.50.20:51820".to_string(),
            advertise_endpoint: true,
            nostr_discovery_enabled: true,
            stun_servers: vec!["stun:stun.example.org:3478".to_string()],
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            share_local_candidates: true,
        };

        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            FIPS_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert!(config.node.discovery.nostr.share_local_candidates);
        assert!(config.node.discovery.lan.enabled);
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        assert_eq!(
            config.node.discovery.nostr.stun_servers,
            vec!["stun:stun.example.org:3478".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.advert_relays,
            vec!["wss://relay.example.org".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.dm_relays,
            vec!["wss://relay.example.org".to_string()]
        );
        let udp = match config.transports.udp {
            fips_endpoint::TransportInstances::Single(udp) => udp,
            _ => panic!("expected one UDP transport"),
        };
        assert_eq!(udp.bind_addr.as_deref(), Some("0.0.0.0:51820"));
        assert!(!udp.outbound_only());
        assert!(udp.advertise_on_nostr());
        assert!(udp.accept_connections());
        assert_eq!(udp.external_addr.as_deref(), Some("192.168.50.20:51820"));
        assert_eq!(config.peers.len(), 1);
    }

    #[test]
    fn endpoint_config_disables_nostr_when_discovery_off() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let transport = FipsEndpointTransportConfig {
            listen_port: 51820,
            advertised_endpoint: "192.168.50.20:51820".to_string(),
            advertise_endpoint: true,
            nostr_discovery_enabled: false,
            stun_servers: vec!["stun:stun.example.org:3478".to_string()],
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            share_local_candidates: true,
        };

        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
        );

        // Relay discovery + advertising are off, but the peer is still dialed
        // directly so static/bootstrap connectivity keeps working.
        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        let udp = match config.transports.udp {
            fips_endpoint::TransportInstances::Single(udp) => udp,
            _ => panic!("expected one UDP transport"),
        };
        assert!(!udp.advertise_on_nostr());
        assert!(udp.accept_connections());
        assert_eq!(config.peers.len(), 1);
    }

    #[test]
    fn endpoint_config_keeps_static_transit_peers_outside_mesh_routes() {
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("npub");
        let mesh_peer =
            FipsMeshPeerConfig::from_participant_pubkey(&bob_pubkey, vec!["10.44.1.2/32".into()])
                .expect("mesh peer");
        let endpoint_peers = fips_endpoint_peers_from_mesh(
            std::slice::from_ref(&mesh_peer),
            vec![(charlie_npub.clone(), vec!["10.203.0.12:51820".to_string()])],
            Vec::new(),
        );
        let transport = FipsEndpointTransportConfig {
            listen_port: 51820,
            advertised_endpoint: "10.203.0.10:51820".to_string(),
            advertise_endpoint: false,
            nostr_discovery_enabled: true,
            stun_servers: Vec::new(),
            nostr_relays: Vec::new(),
            share_local_candidates: false,
        };

        let config = fips_endpoint_config(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert!(!config.node.discovery.lan.enabled);
        assert_eq!(endpoint_peers.len(), 2);
        assert_eq!(config.peers.len(), 2);
        let bob = config
            .peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should be configured");
        assert!(bob.addresses.is_empty());
        assert!(
            bob.discovery_fallback_transit,
            "roster peer should be eligible for private lookup transit"
        );
        let charlie = config
            .peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("static transit peer should be configured");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].transport, "udp");
        assert_eq!(charlie.addresses[0].addr, "10.203.0.12:51820");
        assert!(
            charlie.discovery_fallback_transit,
            "operator-configured transit peers are explicit lookup transit"
        );
    }

    #[test]
    fn endpoint_config_marks_default_route_peers_non_transit() {
        let exit_keys = Keys::generate();
        let exit_pubkey = exit_keys.public_key().to_hex();
        let mesh_peer = FipsMeshPeerConfig::from_participant_pubkey(
            &exit_pubkey,
            vec!["10.44.1.2/32".into(), "0.0.0.0/0".into()],
        )
        .expect("mesh peer");

        let endpoint_peers =
            fips_endpoint_peers_from_mesh(std::slice::from_ref(&mesh_peer), Vec::new(), Vec::new());

        let peer = endpoint_peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should be configured");
        assert!(
            !peer.discovery_fallback_transit,
            "exit/default-route peers should not receive ambient lookup transit"
        );
    }

    #[test]
    fn stamped_endpoint_hints_seed_outside_roster_transit_peers() {
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let mesh_peer =
            FipsMeshPeerConfig::from_participant_pubkey(&bob_pubkey, vec!["10.44.1.2/32".into()])
                .expect("mesh peer");

        let endpoint_peers = fips_endpoint_peers_from_mesh(
            std::slice::from_ref(&mesh_peer),
            Vec::new(),
            vec![(
                charlie_pubkey,
                vec![("10.203.0.12:51820".to_string(), 123_000)],
            )],
        );

        assert_eq!(endpoint_peers.len(), 2);
        let bob = endpoint_peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should remain configured");
        assert!(bob.addresses.is_empty());
        let charlie = endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("recent non-roster peer should be retained as transit");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].addr, "10.203.0.12:51820");
        assert_eq!(charlie.addresses[0].seen_at_ms, Some(123_000));
        assert!(
            charlie.discovery_fallback_transit,
            "recent non-roster peers should remain useful as fallback lookup transit"
        );
    }

    #[test]
    fn tunnel_config_applies_live_endpoint_hints_only_for_network_signal_peers() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let admin_pubkey = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        let network_id = "fips-live-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].participants = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.networks[0].admins = vec![admin_pubkey.clone()];

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[
                (
                    bob_pubkey.clone(),
                    vec![("192.168.50.22:51820".to_string(), 123_000)],
                ),
                (
                    admin_pubkey.clone(),
                    vec![("192.168.50.33:51820".to_string(), 123_000)],
                ),
            ],
        )
        .expect("fips tunnel config");

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("bob endpoint peer");
        assert_eq!(bob.addresses.len(), 1);
        assert_eq!(bob.addresses[0].addr, "192.168.50.22:51820");
        assert_eq!(bob.addresses[0].seen_at_ms, Some(123_000));

        let admin = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint peer");
        assert_eq!(admin.addresses.len(), 1);
        assert_eq!(admin.addresses[0].addr, "192.168.50.33:51820");
        assert_eq!(admin.addresses[0].seen_at_ms, Some(123_000));
    }

    #[test]
    fn tunnel_config_keeps_static_endpoint_hint_for_control_only_admin() {
        let alice_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let admin_pubkey = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        let network_id = "fips-admin-static-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].participants = Vec::new();
        app.networks[0].admins = vec![admin_pubkey.clone()];
        app.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin_pubkey.clone(),
            requested_at: 1,
        });
        app.fips_peer_endpoints
            .insert(admin_npub.clone(), vec!["10.203.0.10:51820".to_string()]);

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");

        assert!(
            config.peers.iter().all(|peer| peer.allowed_ips.is_empty()),
            "join-request admin peers must not get private-network routes before roster acceptance",
        );
        let admin = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint peer");
        assert_eq!(admin.addresses.len(), 1);
        assert_eq!(admin.addresses[0].addr, "10.203.0.10:51820");
        assert_eq!(admin.addresses[0].seen_at_ms, None);
    }

    #[test]
    fn tunnel_config_seeds_recent_outside_roster_transit_peers() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-recent-transit-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].participants = vec![alice_pubkey.clone(), bob_pubkey.clone()];

        let mut recent = nostr_vpn_core::recent_peers::RecentPeerEndpoints::default();
        assert!(recent.note_success(&charlie_pubkey, "203.0.113.55:51820", 123));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert!(
            config
                .peers
                .iter()
                .all(|peer| peer.participant_pubkey != charlie_pubkey),
            "non-roster transit peers must not get private-network routes",
        );
        let charlie = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("recent non-roster peer should seed endpoint config");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].addr, "203.0.113.55:51820");
        assert_eq!(charlie.addresses[0].seen_at_ms, Some(123_000));
        assert!(
            charlie.discovery_fallback_transit,
            "recent non-roster peers should receive fallback lookup fanout"
        );
    }

    #[test]
    fn tunnel_config_drops_overlay_tunnel_endpoint_hints() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let network_id = "fips-tunnel-hints-test";
        let bob_tunnel_ip = derive_mesh_tunnel_ip(network_id, &bob_pubkey).expect("bob tunnel ip");
        let bob_tunnel_endpoint = format!("{}:51820", strip_cidr(&bob_tunnel_ip));

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].participants = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_peer_endpoints.insert(
            bob_npub.clone(),
            vec![
                bob_tunnel_endpoint.clone(),
                "192.168.50.23:51820".to_string(),
            ],
        );

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[(
                bob_pubkey.clone(),
                vec![
                    (bob_tunnel_endpoint, 123_000),
                    ("192.168.50.22:51820".to_string(), 124_000),
                ],
            )],
        )
        .expect("fips tunnel config");

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("bob endpoint peer");
        let addrs = bob
            .addresses
            .iter()
            .map(|hint| hint.addr.as_str())
            .collect::<Vec<_>>();
        assert_eq!(addrs, vec!["192.168.50.22:51820", "192.168.50.23:51820"]);
    }

    /// Pin the open-discovery / closed-data-plane invariant.
    ///
    /// FIPS handshake is `Open` so any nvpn node we see on relays may
    /// connect to us (this is what enables transit through friend-of-a-friend
    /// peers). The data plane MUST stay closed: a packet whose FIPS source
    /// npub doesn't own its inner-source IP per the local roster is dropped
    /// before it reaches the tun. This test wires both halves together so a
    /// future "fix" that opens ambient discovery OR loosens the roster gate
    /// will fail loudly.
    ///
    /// The cross-platform integration variants (T1: live handshake, T4:
    /// transit through non-roster peer) live in the FIPS docker continuity
    /// suite — they need a real endpoint pair and can't run as unit tests.
    #[test]
    fn open_discovery_does_not_loosen_tun_roster_gate() {
        let roster_peer = Keys::generate();
        let stranger = Keys::generate();
        let roster_pubkey = roster_peer.public_key().to_hex();
        let roster_npub = roster_peer.public_key().to_bech32().expect("roster npub");
        let stranger_npub = stranger.public_key().to_bech32().expect("stranger npub");

        let mesh_peer = FipsMeshPeerConfig::from_participant_pubkey(
            &roster_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("roster peer config");
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(std::slice::from_ref(&mesh_peer), Vec::new(), Vec::new());
        let config = fips_endpoint_config(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
        );

        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open,
            "open FIPS discovery must not loosen private roster traffic admission",
        );

        let mesh = FipsMeshRuntime::new(vec![mesh_peer.clone()]);

        // The roster peer's own packet is admitted.
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 44, 1, 2]);
        packet[16..20].copy_from_slice(&[10, 44, 1, 1]);
        assert!(
            mesh.receive_endpoint_data(Some(&roster_npub), &packet)
                .is_some(),
            "roster peer's owned source IP must be admitted",
        );

        // A stranger that successfully completed the open FIPS handshake
        // still cannot inject anything onto our tun, regardless of inner
        // source IP.
        assert!(
            mesh.receive_endpoint_data(Some(&stranger_npub), &packet)
                .is_none(),
            "non-roster peer must not inject packets onto the tun",
        );

        let mut spoofed = packet.clone();
        spoofed[12..16].copy_from_slice(&[203, 0, 113, 9]);
        assert!(
            mesh.receive_endpoint_data(Some(&stranger_npub), &spoofed)
                .is_none(),
            "non-roster peer must not inject packets onto the tun (spoofed source)",
        );
    }
}
