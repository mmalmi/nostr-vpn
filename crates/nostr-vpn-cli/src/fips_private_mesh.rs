use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
#[cfg(feature = "paid-exit")]
use cashu_service::StreamingRoutePaymentEnvelope;
use fips_core::discovery::nostr::OverlayEndpointAdvert;
use fips_endpoint::{
    Config, ConnectPolicy, EthernetConfig, FipsEndpoint, FipsEndpointData, FipsEndpointMessage,
    FipsEndpointPeer, NostrDiscoveryPolicy, NostrPeerfindingSource, PeerAddress,
    PeerConfig as FipsPeerConfig, PeerIdentity, RoutingMode, TransportInstances, UdpConfig,
    WebSocketConfig,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use fips_endpoint::{
    FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS, FipsEndpointDirectPacketRun,
    FipsEndpointDirectReceiver,
};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_FIPS_BOOTSTRAP_PEERS, ExitDnsConfig, ExitDnsResolverConfig, InternetSource,
    PaidExitSellerEgress, WireGuardExitConfig, derive_mesh_tunnel_ip, effective_fips_nostr_relays,
    normalize_nostr_pubkey, split_peer_transport_addr,
};
use nostr_vpn_core::data_plane::MeshPeerStatus;
use nostr_vpn_core::fips_control::{
    FipsControlFrame, JoinRosterControl, PeerCapabilities, PeerEndpointHint, SignedRoster,
    decode_fips_control_frame, encode_fips_control_frame, is_fips_control_frame,
};
use nostr_vpn_core::fips_control_tcp::{
    FipsControlTcpRuntime, FipsControlTcpSender, ReceivedFipsControlFrame,
    send_join_roster_with_receipt,
};
#[cfg(test)]
use nostr_vpn_core::fips_discovery::FIPS_LAN_DISCOVERY_SCOPE_PREFIX;
use nostr_vpn_core::fips_discovery::fips_lan_discovery_scope;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use nostr_vpn_core::fips_mesh::RoutedFipsPeer;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use nostr_vpn_core::fips_mesh::packet_endpoints;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use nostr_vpn_core::fips_mesh::{FipsEndpointAdmissionCache, FipsEndpointSourceAdmitter};
use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime, FipsPaidRouteAdmission};
use nostr_vpn_core::join_requests::MeshJoinRequest;
use nostr_vpn_core::magic_dns::build_magic_dns_records;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_route_accounting::PaidRouteTrafficAccountant;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_route_store::PaidRouteSellerAdmission;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_routes::PaidRouteUsage;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_routes::{PaidExitConfig, PaidRouteSessionOpen};
#[cfg(feature = "paid-exit")]
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::pin::Pin;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as ProcessCommand;
#[cfg(feature = "paid-exit")]
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle as ThreadJoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::sync::mpsc;

const FIPS_PEER_ONLINE_GRACE_SECS: u64 = 20;
const FIPS_PEER_MAX_FUTURE_SKEW_SECS: u64 = 2;
const FIPS_PEER_CAPS_GRACE_SECS: u64 = 600;
const FIPS_RECONNECT_BACKOFF_BASE_SECS: u64 = 1;
const FIPS_RECONNECT_BACKOFF_MAX_SECS: u64 = 60;
const FIPS_DISCOVERY_BACKOFF_BASE_SECS: u64 = 30;
const FIPS_DISCOVERY_BACKOFF_MAX_SECS: u64 = 300;
const FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS: u64 = 2;
const FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING: usize = 8;
const FIPS_NOSTR_EXIT_OPEN_DISCOVERY_MAX_PENDING: usize = 8;
// A public paid seller must accept the buyer's first authenticated FIPS
// connection before it can receive and verify the paid session-open frame.
// Keep this bounded, but leave enough room that a handful of ambient public
// scanners cannot permanently occupy every admission slot.
const FIPS_NOSTR_PAID_EXIT_OPEN_DISCOVERY_MAX_PENDING: usize = 64;
// Public WebSocket listeners are explicit FIPS bootstrap routers. Keep their
// unaffiliated authenticated-adjacency budget bounded, but large enough that
// a handful of slow or abandoned handshakes cannot deny all fresh clients.
const FIPS_WEBSOCKET_LISTENER_OPEN_DISCOVERY_MAX_PENDING: usize = 128;
// Public bootstrap routers need more physical sockets than an ordinary client
// listener. Keep spare total slots for their configured upstream seeds, and
// evict peers that do not answer transport pings before they consume the
// entire inbound budget.
const FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS: usize = 640;
const FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS: usize = 512;
const FIPS_PUBLIC_WEBSOCKET_IDLE_TIMEOUT_SECS: u64 = 30;
const FIPS_STATIC_NON_ROSTER_TRANSIT_MAX_SEEDS: usize = 2;
const FIPS_RECENT_NON_ROSTER_TRANSIT_MAX_SEEDS: usize = 4;
// Relay announcements are discovery hints, not a reason to keep probing an
// unaffiliated peer forever. Configured peers retain their ordinary unlimited
// auto-reconnect path; these bounds apply to ambient open-discovery candidates.
const FIPS_NOSTR_FAILURE_STREAK_THRESHOLD: u32 = 3;
const FIPS_NOSTR_EXTENDED_COOLDOWN_SECS: u64 = 30 * 60;
const FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS: u64 = 300;
// Keep traversal/NAT paths warm enough for interactive traffic. FIPS core uses
// this cadence plus fast_link_dead_timeout_secs for recent-path recovery, while
// authenticated payload traffic keeps healthy paths from false-staling.
const FIPS_ENDPOINT_HEARTBEAT_INTERVAL_SECS: u64 = 2;
const FIPS_ENDPOINT_LINK_DEAD_TIMEOUT_SECS: u64 = 30;
const FIPS_ENDPOINT_FAST_LINK_DEAD_TIMEOUT_SECS: u64 = 5;
const FIPS_ENDPOINT_SESSION_IDLE_TIMEOUT_SECS: u64 = 0;
const FIPS_ENDPOINT_PENDING_PACKETS_PER_DEST: usize = 64;
const FIPS_ENDPOINT_REKEY_AFTER_SECS: u64 = 3600;
// FIPS maintains its own two-second link heartbeat. App-level presence pings
// only need two chances inside the 20-second online grace; a ten-second cadence
// also avoids repeatedly rediscovering healthy routed peers.
const FIPS_PEER_ACTIVE_PING_INTERVAL_SECS: u64 = 10;
const FIPS_PEER_LINK_PING_INTERVAL_SECS: u64 = 5;
const FIPS_PEER_DISCOVERY_PROBE_INTERVAL_SECS: u64 = 30;
const FIPS_CONTROL_RTT_MAX_ACCEPT_MS: u128 = 10_000;
const MESH_LAN_UNDERLAY_UDP_MTU: u16 = 1452;
const MESH_LAN_TUNNEL_MTU: u16 = 1322;
const MESH_MIN_UNDERLAY_UDP_MTU: u16 = 1280;
const MESH_MIN_TUNNEL_MTU: u16 = 576;
const MESH_MAX_MTU: u16 = 9000;
#[cfg(target_os = "linux")]
const FIPS_TUN_READ_BURST: usize = 128;
#[cfg(target_os = "macos")]
const FIPS_TUN_READ_BURST: usize = 64;
#[cfg(any(target_os = "macos", test))]
const MACOS_UDP_SEND_BUF_MIN_MULTIPLIER: usize = 4;
const MIN_FIPS_UDP_SEND_BUF_SIZE: usize = 64 * 1024;
const MAX_FIPS_UDP_SEND_BUF_SIZE: usize = 8 * 1024 * 1024;

pub(crate) type FipsJoinRosterDelivery = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

#[cfg(any(target_os = "macos", test))]
const fn macos_default_udp_send_buf_size() -> usize {
    MIN_FIPS_UDP_SEND_BUF_SIZE * MACOS_UDP_SEND_BUF_MIN_MULTIPLIER
}

// Keep WireGuard-style bounded packet turns and let actual queue pressure decide
// whether the sender should yield between batches. FIPS's raw
// `FIPS_MACOS_SEND_PACE_MBPS` rate knob remains opt-in for lab A/Bs; the default
// path shapes backlog instead of sleeping to a fixed bandwidth number.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIPS_MESH_RECV_BURST: usize = FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIPS_MESH_EVENT_DRAIN_LIMIT: usize = 256;
#[cfg(target_os = "linux")]
const DEFAULT_LINUX_TUN_TX_QUEUE_LEN: usize = 4096;
#[cfg(target_os = "macos")]
const DEFAULT_FIPS_UDP_SEND_BUF_SIZE: Option<usize> = Some(macos_default_udp_send_buf_size());
#[cfg(not(target_os = "macos"))]
const DEFAULT_FIPS_UDP_SEND_BUF_SIZE: Option<usize> = None;
#[cfg(target_os = "windows")]
const WINDOWS_FIPS_TUN_READ_BURST: usize = 128;

fn fips_udp_send_buf_size() -> Option<usize> {
    static VALUE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_fips_udp_send_buf_size(
            std::env::var("NVPN_FIPS_UDP_SEND_BUF_SIZE").ok().as_deref(),
            DEFAULT_FIPS_UDP_SEND_BUF_SIZE,
        )
    })
}

fn parse_fips_udp_send_buf_size(raw: Option<&str>, default: Option<usize>) -> Option<usize> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return default;
    };
    match raw.parse::<usize>().ok() {
        Some(0) => None,
        Some(value) => Some(value.clamp(MIN_FIPS_UDP_SEND_BUF_SIZE, MAX_FIPS_UDP_SEND_BUF_SIZE)),
        None => default,
    }
}

#[cfg(target_os = "linux")]
fn linux_tun_tx_queue_len() -> Option<usize> {
    static VALUE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_linux_tun_tx_queue_len(
            std::env::var("NVPN_FIPS_LINUX_TUN_TX_QUEUE_LEN")
                .ok()
                .as_deref(),
            DEFAULT_LINUX_TUN_TX_QUEUE_LEN,
        )
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_tun_tx_queue_len(raw: Option<&str>, default: usize) -> Option<usize> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(default.clamp(64, 65_536));
    };
    if value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
    {
        return None;
    }
    value
        .parse::<usize>()
        .ok()
        .map(|value| value.clamp(64, 65_536))
}

#[cfg(target_os = "macos")]
use boringtun::device::tun::TunSocket;
#[cfg(target_os = "windows")]
use nostr_vpn_wintun::load_wintun;
#[cfg(target_os = "windows")]
use tokio::task::JoinHandle;
#[cfg(target_os = "windows")]
use wintun::{Adapter, MAX_RING_CAPACITY, Session};

#[cfg(target_os = "windows")]
use crate::WindowsNetworkCleanupState;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fips_host_tunnel::FipsHostTunnelConfig;

pub(crate) struct FipsPrivateMeshRuntime {
    endpoint: Arc<FipsEndpoint>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    direct_endpoint_rx: FipsEndpointDirectReceiver,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    local_tunnel_ips: HashSet<IpAddr>,
    mesh: ArcSwap<FipsMeshRuntime>,
    mesh_generation: AtomicU64,
    peer_activity: ArcSwap<FipsPeerActivityMap>,
    peer_identities: ArcSwap<FipsPeerIdentityMap>,
    presence: RwLock<HashMap<String, FipsPeerPresence>>,
    link_status: RwLock<HashMap<String, FipsEndpointPeer>>,
    other_link_status: RwLock<HashMap<String, FipsEndpointPeer>>,
    peer_capabilities: RwLock<HashMap<String, PeerCapabilitiesEntry>>,
    #[cfg(feature = "paid-exit")]
    paid_route_accounting: Mutex<FipsPaidRouteAccounting>,
}

impl FipsPrivateMeshRuntime {
    pub(crate) fn endpoint(&self) -> &Arc<FipsEndpoint> {
        &self.endpoint
    }
}

include!("fips_private_mesh/types_and_mtu.rs");
include!("fips_private_mesh/mtu_and_policy.rs");
include!("fips_private_mesh/peer_status_and_events.rs");
include!("fips_private_mesh/tun_pipeline.rs");
include!("fips_private_mesh/runtime_send.rs");
include!("fips_private_mesh/runtime_receive.rs");
include!("fips_private_mesh/runtime_status.rs");
include!("fips_private_mesh/runtime_control.rs");
include!("fips_private_mesh/control_frame.rs");
include!("fips_private_mesh/endpoint_config.rs");
include!("fips_private_mesh/tunnel_config.rs");
include!("fips_private_mesh/mesh_bind.rs");
include!("fips_private_mesh/macos_bypass_reconcile.rs");
include!("fips_private_mesh/macos_wg_runtime.rs");
include!("fips_private_mesh/tunnel_runtime_unix_core.rs");
include!("fips_private_mesh/tunnel_runtime_unix_workers.rs");
include!("fips_private_mesh/linux_interface_state.rs");
include!("fips_private_mesh/linux_cleanup.rs");
include!("fips_private_mesh/tunnel_runtime_linux.rs");
#[cfg(target_os = "linux")]
include!("fips_private_mesh/linux_vnet_tun.rs");
include!("fips_private_mesh/unix_tun.rs");
include!("fips_private_mesh/windows_cleanup.rs");
include!("fips_private_mesh/tunnel_runtime_windows.rs");
include!("fips_private_mesh/windows_tun.rs");
include!("fips_private_mesh/tunnel_runtime_unsupported.rs");
include!("fips_private_mesh/time.rs");
#[cfg(test)]
mod tests {
    include!("fips_private_mesh/tests_core.rs");
    include!("fips_private_mesh/tests_tun_pipeline.rs");
    include!("fips_private_mesh/tests_status.rs");
    include!("fips_private_mesh/tests_status_endpoint_data.rs");
    include!("fips_private_mesh/tests_runtime.rs");
    include!("fips_private_mesh/tests_network_cleanup.rs");
    include!("fips_private_mesh/tests_macos_bypass.rs");
    include!("fips_private_mesh/tests_config.rs");
}
