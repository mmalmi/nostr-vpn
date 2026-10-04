use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(debug_assertions)]
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(test)]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(target_os = "android")]
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use fips_endpoint::{
    Config as FipsConfig, ConnectPolicy, FipsEndpoint, FipsEndpointMessage, FipsEndpointPeer,
    NostrDiscoveryPolicy, PeerAddress, PeerConfig as FipsPeerConfig,
    PeerIdentity, RoutingMode, TransportInstances, UdpConfig, WebSocketConfig,
};
use nostr_sdk::prelude::PublicKey;
use nostr_vpn_core::config::{
    AppConfig, ExitDnsConfig, ExitDnsResolverConfig, MESH_TUNNEL_IPV4_CIDR, WireGuardExitConfig,
    derive_mesh_tunnel_ip, effective_nostr_relays, maybe_autoconfigure_node,
    normalize_fips_transport_address, normalize_nostr_pubkey, normalize_runtime_network_id,
    split_peer_transport_addr,
};
use nostr_vpn_core::control_pubsub_runtime::{ControlPubsubClient, ControlPubsubFipsRuntime, ControlRelayStatus};
use nostr_vpn_core::fips_control::{
    FipsControlFrame, JoinRosterControl, NetworkRoster, PeerCapabilities, PeerEndpointHint,
    SignedRoster, decode_fips_control_frame, encode_fips_control_frame,
    local_fips_dataplane_features, peer_endpoint_hint_addr,
};
use nostr_vpn_core::fips_control_tcp::{
    FipsControlTcpRuntime, FipsControlTcpSender, ReceivedFipsControlFrame,
    send_join_roster_with_receipt,
};
use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
use nostr_vpn_core::join_delivery::{
    QueuedJoinRoster, join_roster_delivery_expired, load_join_rosters, record_join_roster_attempt,
};
use nostr_vpn_core::join_requests::{FIPS_JOIN_REQUEST_RETRY_SECS, MeshJoinRequest};
use nostr_vpn_core::join_roster_persistence::{
    apply_join_roster, apply_join_roster_durably, join_roster_is_durably_persisted,
};
use nostr_vpn_core::magic_dns::{
    build_magic_dns_records, build_magic_dns_response_if_handled,
    build_magic_dns_server_failure_response,
};
use nostr_vpn_core::secure_dns::{SecureDnsLookup, SecureDnsResolver, build_servfail_response};
use nostr_vpn_core::signed_rosters::{signed_rosters_file_path, upsert_signed_roster};
use nostr_vpn_core::wg_upstream::{DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT, WgUpstreamRuntime};
use serde::{Deserialize, Serialize};

use crate::platform::{RuntimePlatform, current_runtime_platform};
use crate::state::{DaemonPeerState, DaemonRuntimeState};
use crate::wg_upstream_nat::{rewrite_ipv4_destination, rewrite_ipv4_source};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinHandle;

#[cfg(target_os = "android")]
include!("mobile_tunnel/native_tun.rs");
#[cfg(any(test, target_os = "ios"))]
include!("mobile_tunnel/ios_packet_flow.rs");
include!("mobile_tunnel/config.rs");
include!("mobile_tunnel/runtime.rs");
include!("mobile_tunnel/endpoint_control.rs");
include!("mobile_tunnel/runtime_state.rs");
include!("mobile_tunnel/endpoint_config.rs");
include!("mobile_tunnel/magic_dns.rs");
#[cfg(feature = "paid-exit")]
include!("mobile_tunnel/paid_exit_offer.rs");

#[cfg(test)]
mod tests {
    include!("mobile_tunnel/tests_core.rs");
    include!("mobile_tunnel/tests_control_source.rs");
    include!("mobile_tunnel/tests_pending_identity.rs");
    include!("mobile_tunnel/tests_identity.rs");
    include!("mobile_tunnel/tests_runtime_join_request.rs");
    include!("mobile_tunnel/tests_runtime.rs");
    include!("mobile_tunnel/tests_runtime_pubsub.rs");
    include!("mobile_tunnel/tests_runtime_state.rs");
    include!("mobile_tunnel/tests_runtime_manual_join.rs");
    include!("mobile_tunnel/tests_runtime_desktop_mobile_join.rs");
    include!("mobile_tunnel/tests_runtime_future_presence.rs");
    include!("mobile_tunnel/tests_paid_route.rs");
    include!("mobile_tunnel/tests_config.rs");
}
