pub mod config;
mod config_defaults;
mod config_magic_dns;
mod config_secrets;
#[cfg(feature = "cashu-wallet")]
pub use config_secrets::PlatformCashuWalletSeedStore;
pub mod control;
pub mod control_pubsub;
pub mod data_plane;
pub mod diagnostics;
pub mod fips_control;
pub mod fips_control_tcp;
pub mod fips_discovery;
pub mod fips_mesh;
pub mod identity_bridge;
pub mod join_delivery;
pub mod join_requests;
pub mod join_roster_persistence;
pub mod magic_dns;
mod network_roster;
mod network_routes;
pub mod packet_checksums;
pub mod paid_route_accounting;
pub mod paid_route_probe;
#[cfg(feature = "paid-exit")]
pub mod paid_route_ratings;
#[cfg(feature = "paid-exit")]
pub mod paid_route_store;
pub mod paid_routes;
pub mod paths;
pub mod platform_paths;
pub mod process_ext;
pub mod recent_peers;
#[cfg(feature = "secure-dns")]
pub mod secure_dns;
pub mod signed_rosters;
#[cfg(feature = "updater")]
pub mod updater;
pub mod wg_upstream;

pub use config::DEFAULT_RELAYS;

/// Underlay UDP MTU the daemon targets for the encrypted FIPS frame.
///
/// Keep the default at the IPv6-safe 1280-byte wire budget until the
/// mesh has blackhole-safe active PMTU probing. LAN-sized budgets work
/// on some direct paths, but a global 1420-byte encrypted datagram can
/// silently break NAT-traversed or nested-tunnel routes. This mirrors
/// Tailscale's policy: safe first-contact MTU, higher only with path
/// evidence or an explicit operator override.
pub const MESH_UNDERLAY_UDP_MTU: u16 = 1280;

/// Tunnel-side MTU: maximum IPv4/IPv6 packet a TUN device hands to the daemon
/// for encryption + transit. Equals `MESH_UNDERLAY_UDP_MTU` minus the 106-byte
/// FIPS overhead (handshake nonce + AEAD framing + inner header; see fips-core
/// `upper::icmp::FIPS_OVERHEAD`) minus a 24-byte cushion for the optional
/// COORDS warmup tag and any per-link variance. Single source of truth —
/// every TUN config, every UdpConfig, every Wintun adapter, every linux
/// `ip link set mtu` should derive from this.
pub const MESH_TUNNEL_MTU: u16 = 1150;

/// In-tunnel IPv4 address for the local MagicDNS responder.
///
/// Mobile platforms install this as a VPN DNS server when MagicDNS is enabled;
/// app-core owns the responder inside each tunnel instance and forwards
/// non-.nvpn queries onward. This is not a remote peer address: derived peer
/// addresses use `10.44.1.1` through `10.44.254.254`, leaving `10.44.0.0/24`
/// outside the peer-derived range for local mesh services.
pub const MESH_MAGIC_DNS_SERVER: &str = "10.44.0.53";
