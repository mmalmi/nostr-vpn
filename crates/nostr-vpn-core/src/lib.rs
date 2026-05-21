pub mod config;
mod config_defaults;
mod config_magic_dns;
pub mod control;
pub mod data_plane;
pub mod diagnostics;
pub mod fips_control;
pub mod fips_mesh;
pub mod invite;
pub mod join_requests;
pub mod lan_pairing;
pub mod magic_dns;
pub mod namecoin_resolver;
mod network_roster;
mod network_routes;
pub mod paths;
pub mod platform_paths;
pub mod process_ext;
pub mod recent_peers;
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
