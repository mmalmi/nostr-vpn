#[cfg(target_os = "macos")]
use crate::macos_file_io as fs;
#[cfg(not(target_os = "macos"))]
use fs::OpenOptions;
use std::collections::{HashMap, HashSet};
#[cfg(not(target_os = "macos"))]
use std::fs;
#[cfg(not(target_os = "macos"))]
use std::io::Write;
use std::net::IpAddr;
#[cfg(all(unix, not(target_os = "macos")))]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nostr_sdk::prelude::{Keys, ToBech32};

pub use crate::config_magic_dns::{
    default_magic_dns_label_for_pubkey, default_node_name_for_hostname_or_pubkey,
    default_node_name_for_pubkey, default_node_name_from_hostname, normalize_magic_dns_label,
    normalize_magic_dns_suffix,
};
pub use crate::network_routes::{
    MESH_TUNNEL_IPV4_CIDR, derive_mesh_tunnel_ip, effective_advertised_routes,
    exit_node_default_routes, normalize_advertised_route, normalize_advertised_routes,
    route_is_ipv6,
};

use crate::config_defaults::{
    current_unix_timestamp, default_autoconnect, default_close_to_tray_on_close,
    default_connect_to_non_roster_fips_peers, default_endpoint,
    default_fips_advertise_public_endpoint, default_fips_bootstrap_enabled,
    default_fips_host_tunnel_enabled, default_fips_nostr_discovery_enabled,
    default_fips_webrtc_enabled, default_join_secret, default_lan_discovery_enabled,
    default_launch_on_startup, default_listen_for_join_requests, default_listen_port,
    default_nat_discovery_timeout_secs, default_nat_enabled, default_nat_stun_servers,
    default_network_enabled, default_network_id, default_node_id, default_relays,
    default_tunnel_ip, generate_nostr_identity, is_true, is_zero, needs_generated_network_id,
};
pub use crate::config_defaults::{
    maybe_autoconfigure_node, needs_endpoint_autoconfig, needs_tunnel_ip_autoconfig,
    normalize_nostr_pubkey, normalize_runtime_network_id, npub_for_pubkey_hex,
};
use crate::config_magic_dns::{
    default_magic_dns_suffix, default_network_entry_id, default_network_name, default_node_name,
    default_peer_aliases, detected_hostname, normalize_network_entry_id, uniquify_magic_dns_label,
    uniquify_network_entry_id, uses_default_node_name,
};
use crate::config_secrets::{
    SecretPersistence, config_file_needs_secret_migration, delete_config_secrets,
    hydrate_config_secrets, prepare_config_secrets_for_save,
};
use crate::fips_control::{PeerEndpointHint, SignedRoster, peer_endpoint_hint_addr};
use crate::identity_bridge::NostrIdentityId;
use crate::join_requests::PendingNostrJoinRequest;
use crate::network_roster::{
    canonical_npub_key, canonicalize_inbound_join_requests, canonicalize_outbound_join_request,
    normalize_inbound_join_requests, normalize_network_admins, normalize_outbound_join_request,
    normalize_shared_roster_devices,
};
use crate::network_routes::is_exit_node_route;
use crate::paid_routes::{ManualPaidExitProvider, PaidExitConfig, PaidExitUpstream};
use crate::signed_rosters::signed_roster_artifact_wins;
use serde::{Deserialize, Serialize};

include!("config/types.rs");
include!("config/app_config_persistence.rs");
include!("config/app_config_defaults.rs");
include!("config/app_config_networks.rs");
include!("config/app_config_rosters.rs");
include!("config/app_config_fips.rs");
include!("config/app_config_identity_dns.rs");
include!("config/file_io.rs");
include!("config/tests.rs");
