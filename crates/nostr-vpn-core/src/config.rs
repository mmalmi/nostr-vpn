use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::{Keys, ToBech32};

pub use crate::config_magic_dns::{
    default_magic_dns_label_for_pubkey, default_node_name_for_hostname_or_pubkey,
    default_node_name_for_pubkey, default_node_name_from_hostname, normalize_magic_dns_label,
    normalize_magic_dns_suffix,
};
pub use crate::network_routes::{
    MESH_TUNNEL_IPV4_CIDR, derive_mesh_tunnel_ip, effective_advertised_routes,
    exit_node_default_routes, normalize_advertised_route, normalize_advertised_routes,
};

use crate::config_defaults::{
    current_unix_timestamp, default_autoconnect, default_close_to_tray_on_close, default_endpoint,
    default_fips_advertise_endpoint, default_lan_discovery_enabled, default_launch_on_startup,
    default_listen_for_join_requests, default_listen_port, default_nat_discovery_timeout_secs,
    default_nat_enabled, default_nat_stun_servers, default_network_enabled, default_network_id,
    default_node_id, default_relays, default_tunnel_ip, generate_nostr_identity, is_true, is_zero,
    needs_generated_network_id, npub_for_pubkey_hex,
};
pub use crate::config_defaults::{
    maybe_autoconfigure_node, needs_endpoint_autoconfig, needs_tunnel_ip_autoconfig,
    normalize_nostr_pubkey, normalize_runtime_network_id,
};
use crate::config_magic_dns::{
    default_magic_dns_suffix, default_network_entry_id, default_network_name, default_node_name,
    default_peer_aliases, detected_hostname, normalize_network_entry_id, uniquify_magic_dns_label,
    uniquify_network_entry_id, uses_default_node_name,
};
use crate::fips_control::{PeerEndpointHint, peer_endpoint_hint_addr};
use crate::network_roster::{
    canonical_npub_key, canonicalize_inbound_join_requests, canonicalize_outbound_join_request,
    normalize_inbound_join_requests, normalize_network_admins, normalize_npub_key,
    normalize_outbound_join_request, normalize_shared_roster_participants,
};
use crate::network_routes::is_exit_node_route;
use serde::{Deserialize, Serialize};

pub const DEFAULT_RELAYS: &[&str] = &[];

pub fn normalize_fips_peer_endpoint_hint(endpoint: &str) -> Option<String> {
    peer_endpoint_hint_addr(&PeerEndpointHint::udp(endpoint.trim()))
}

pub fn normalize_relay_urls(values: Vec<String>) -> Vec<String> {
    let mut relays = values
        .into_iter()
        .flat_map(|value| {
            value
                .split([',', '\n', '\r', ' ', '\t'])
                .map(str::trim)
                .filter(|relay| !relay.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    relays.sort();
    relays.dedup();
    relays
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_relays: Vec<String>,
    /// Nostr private identity key in `nsec` or hex format.
    #[serde(default)]
    pub secret_key: String,
    /// Nostr public identity key in `npub` or hex format.
    #[serde(default)]
    pub public_key: String,
}

impl Default for NostrConfig {
    fn default() -> Self {
        let (secret_key, public_key) = generate_nostr_identity();
        Self {
            relays: default_relays(),
            disabled_relays: Vec::new(),
            secret_key,
            public_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_lan_discovery_enabled", skip_serializing)]
    pub lan_discovery_enabled: bool,
    #[serde(default = "default_launch_on_startup")]
    pub launch_on_startup: bool,
    #[serde(default = "default_autoconnect")]
    pub autoconnect: bool,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub fips_peer_endpoints: HashMap<String, Vec<String>>,
    #[serde(
        default = "default_fips_advertise_endpoint",
        skip_serializing_if = "is_true"
    )]
    pub fips_advertise_endpoint: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mesh_mtu_profile: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub mesh_underlay_udp_mtu: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub mesh_tunnel_mtu: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exit_node: String,
    #[serde(
        default = "default_exit_node_leak_protection",
        skip_serializing_if = "is_true"
    )]
    pub exit_node_leak_protection: bool,
    #[serde(default = "default_close_to_tray_on_close")]
    pub close_to_tray_on_close: bool,
    #[serde(default = "default_magic_dns_suffix")]
    pub magic_dns_suffix: String,
    #[serde(default, skip_serializing_if = "WireGuardExitConfig::is_default")]
    pub wireguard_exit: WireGuardExitConfig,
    #[serde(default = "default_peer_aliases")]
    pub peer_aliases: HashMap<String, String>,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default)]
    pub nostr: NostrConfig,
    #[serde(default)]
    pub node: NodeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardExitConfig {
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    #[serde(
        default = "default_wireguard_exit_interface",
        skip_serializing_if = "wireguard_exit_interface_is_default"
    )]
    pub interface: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_preshared_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(
        default = "default_wireguard_exit_allowed_ips",
        skip_serializing_if = "wireguard_exit_allowed_ips_is_default"
    )]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(
        default = "default_wireguard_exit_mtu",
        skip_serializing_if = "wireguard_exit_mtu_is_default"
    )]
    pub mtu: u16,
    #[serde(
        default = "default_wireguard_exit_persistent_keepalive_secs",
        skip_serializing_if = "wireguard_exit_persistent_keepalive_secs_is_default"
    )]
    pub persistent_keepalive_secs: u16,
}

impl Default for WireGuardExitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_wireguard_exit_interface(),
            address: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            peer_preshared_key: String::new(),
            endpoint: String::new(),
            allowed_ips: default_wireguard_exit_allowed_ips(),
            dns: Vec::new(),
            mtu: default_wireguard_exit_mtu(),
            persistent_keepalive_secs: default_wireguard_exit_persistent_keepalive_secs(),
        }
    }
}

impl WireGuardExitConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn configured(&self) -> bool {
        !self.address.trim().is_empty()
            && !self.private_key.trim().is_empty()
            && !self.peer_public_key.trim().is_empty()
            && !self.endpoint.trim().is_empty()
    }
}

pub fn parse_wireguard_exit_config(raw: &str) -> Result<WireGuardExitConfig> {
    let mut config = WireGuardExitConfig {
        allowed_ips: Vec::new(),
        ..WireGuardExitConfig::default()
    };
    let mut section = WireGuardConfigSection::None;
    let mut saw_interface = false;
    let mut saw_peer = false;
    let mut addresses = Vec::new();

    for (line_index, raw_line) in raw.lines().enumerate() {
        let line_no = line_index + 1;
        let line = strip_wireguard_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section_name) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            let section_name = section_name.trim().to_ascii_lowercase();
            section = match section_name.as_str() {
                "interface" => {
                    saw_interface = true;
                    WireGuardConfigSection::Interface
                }
                "peer" => {
                    if saw_peer {
                        return Err(anyhow!(
                            "WireGuard upstream import supports exactly one peer; extra [Peer] at line {line_no}"
                        ));
                    }
                    saw_peer = true;
                    WireGuardConfigSection::Peer
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard section [{section_name}] at line {line_no}"
                    ));
                }
            };
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("expected key = value at line {line_no}"))?;
        let key = normalize_wireguard_config_key(key);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if wireguard_config_key_is_shell_hook(&key) {
            return Err(anyhow!(
                "WireGuard hook directive at line {line_no} is not supported"
            ));
        }

        match section {
            WireGuardConfigSection::None => {
                return Err(anyhow!(
                    "WireGuard setting before any section at line {line_no}"
                ));
            }
            WireGuardConfigSection::Interface => match key.as_str() {
                "privatekey" => config.private_key = value.to_string(),
                "address" => addresses = parse_wireguard_address_list(value, line_no)?,
                "dns" => config.dns = parse_wireguard_value_list(value),
                "mtu" => config.mtu = parse_wireguard_u16(value, "MTU", line_no)?,
                "listenport" | "fwmark" | "table" | "saveconfig" => {
                    return Err(anyhow!(
                        "WireGuard interface setting '{key}' at line {line_no} is not supported by the upstream importer"
                    ));
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard interface setting '{key}' at line {line_no}"
                    ));
                }
            },
            WireGuardConfigSection::Peer => match key.as_str() {
                "publickey" => config.peer_public_key = value.to_string(),
                "presharedkey" => config.peer_preshared_key = value.to_string(),
                "endpoint" => config.endpoint = value.to_string(),
                "allowedips" => {
                    config.allowed_ips = parse_wireguard_allowed_ips(value, line_no)?;
                }
                "persistentkeepalive" => {
                    config.persistent_keepalive_secs =
                        parse_wireguard_u16(value, "PersistentKeepalive", line_no)?;
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard peer setting '{key}' at line {line_no}"
                    ));
                }
            },
        }
    }

    if !saw_interface {
        return Err(anyhow!(
            "WireGuard config is missing an [Interface] section"
        ));
    }
    if !saw_peer {
        return Err(anyhow!("WireGuard config is missing a [Peer] section"));
    }
    if !addresses.is_empty() {
        config.address = select_wireguard_exit_address(&addresses);
    }
    if config.allowed_ips.is_empty() {
        return Err(anyhow!("WireGuard peer is missing AllowedIPs"));
    }
    if !config.allowed_ips.iter().any(|route| route == "0.0.0.0/0") {
        return Err(anyhow!(
            "WireGuard upstream AllowedIPs must include 0.0.0.0/0"
        ));
    }

    normalize_wireguard_exit_config(&mut config);
    if config.address.trim().is_empty() {
        return Err(anyhow!("WireGuard interface is missing Address"));
    }
    if config.private_key.trim().is_empty() {
        return Err(anyhow!("WireGuard interface is missing PrivateKey"));
    }
    if config.peer_public_key.trim().is_empty() {
        return Err(anyhow!("WireGuard peer is missing PublicKey"));
    }
    if config.endpoint.trim().is_empty() {
        return Err(anyhow!("WireGuard peer is missing Endpoint"));
    }
    Ok(config)
}

pub fn wireguard_exit_config_text(config: &WireGuardExitConfig) -> String {
    if !config.configured() {
        return String::new();
    }

    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {}", config.private_key),
        format!("Address = {}", config.address),
    ];
    if !config.dns.is_empty() {
        lines.push(format!("DNS = {}", config.dns.join(", ")));
    }
    if config.mtu > 0 {
        lines.push(format!("MTU = {}", config.mtu));
    }

    lines.push(String::new());
    lines.push("[Peer]".to_string());
    lines.push(format!("PublicKey = {}", config.peer_public_key));
    if !config.peer_preshared_key.trim().is_empty() {
        lines.push(format!("PresharedKey = {}", config.peer_preshared_key));
    }
    lines.push(format!("Endpoint = {}", config.endpoint));
    lines.push(format!("AllowedIPs = {}", config.allowed_ips.join(", ")));
    if config.persistent_keepalive_secs > 0 {
        lines.push(format!(
            "PersistentKeepalive = {}",
            config.persistent_keepalive_secs
        ));
    }

    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireGuardConfigSection {
    None,
    Interface,
    Peer,
}

fn strip_wireguard_config_comment(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or(line)
}

fn normalize_wireguard_config_key(key: &str) -> String {
    key.trim()
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn wireguard_config_key_is_shell_hook(key: &str) -> bool {
    matches!(
        key,
        "preup" | "postup" | "predown" | "postdown" | "preupcmd" | "postupcmd"
    )
}

fn parse_wireguard_value_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_wireguard_address_list(value: &str, line_no: usize) -> Result<Vec<String>> {
    parse_wireguard_value_list(value)
        .into_iter()
        .map(|address| normalize_wireguard_address(&address, line_no))
        .collect()
}

fn normalize_wireguard_address(value: &str, line_no: usize) -> Result<String> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid WireGuard Address '{value}' at line {line_no}"))?;
    let ip: std::net::IpAddr = ip
        .trim()
        .parse()
        .with_context(|| format!("invalid WireGuard Address IP '{value}' at line {line_no}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .with_context(|| format!("invalid WireGuard Address prefix '{value}' at line {line_no}"))?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(anyhow!(
            "invalid WireGuard Address prefix '{value}' at line {line_no}"
        ));
    }
    Ok(format!("{ip}/{prefix}"))
}

fn select_wireguard_exit_address(addresses: &[String]) -> String {
    addresses
        .iter()
        .find(|address| {
            address
                .split_once('/')
                .and_then(|(ip, _)| ip.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_ipv4())
        })
        .or_else(|| addresses.first())
        .cloned()
        .unwrap_or_default()
}

fn parse_wireguard_allowed_ips(value: &str, line_no: usize) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for route in parse_wireguard_value_list(value) {
        let normalized = normalize_advertised_route(&route).ok_or_else(|| {
            anyhow!("invalid WireGuard AllowedIPs route '{route}' at line {line_no}")
        })?;
        routes.push(normalized);
    }
    routes.sort();
    routes.dedup();
    Ok(routes)
}

fn parse_wireguard_u16(value: &str, field: &str, line_no: usize) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .with_context(|| format!("invalid WireGuard {field} '{value}' at line {line_no}"))
}

fn default_wireguard_exit_interface() -> String {
    "nvpn-wg-exit".to_string()
}

fn default_wireguard_exit_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string()]
}

fn default_wireguard_exit_mtu() -> u16 {
    1420
}

fn default_wireguard_exit_persistent_keepalive_secs() -> u16 {
    25
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn wireguard_exit_interface_is_default(value: &str) -> bool {
    value == default_wireguard_exit_interface()
}

fn wireguard_exit_allowed_ips_is_default(value: &[String]) -> bool {
    value == default_wireguard_exit_allowed_ips().as_slice()
}

fn wireguard_exit_mtu_is_default(value: &u16) -> bool {
    *value == default_wireguard_exit_mtu()
}

fn wireguard_exit_persistent_keepalive_secs_is_default(value: &u16) -> bool {
    *value == default_wireguard_exit_persistent_keepalive_secs()
}

fn default_exit_node_leak_protection() -> bool {
    true
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

fn normalize_wireguard_exit_config(config: &mut WireGuardExitConfig) {
    config.interface = config.interface.trim().to_string();
    if config.interface.is_empty() {
        config.interface = default_wireguard_exit_interface();
    }
    config.address = config.address.trim().to_string();
    config.private_key = config.private_key.trim().to_string();
    config.peer_public_key = config.peer_public_key.trim().to_string();
    config.peer_preshared_key = config.peer_preshared_key.trim().to_string();
    config.endpoint = config.endpoint.trim().to_string();
    config.allowed_ips = config
        .allowed_ips
        .iter()
        .filter_map(|route| normalize_advertised_route(route))
        .collect();
    config.allowed_ips.sort();
    config.allowed_ips.dedup();
    if config.allowed_ips.is_empty() {
        config.allowed_ips = default_wireguard_exit_allowed_ips();
    }
    config.dns = config
        .dns
        .iter()
        .map(|server| server.trim().to_string())
        .filter(|server| !server.is_empty())
        .collect();
    config.dns.sort();
    config.dns.dedup();
    if config.mtu == 0 {
        config.mtu = default_wireguard_exit_mtu();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default = "default_nat_enabled")]
    pub enabled: bool,
    #[serde(default = "default_nat_stun_servers")]
    pub stun_servers: Vec<String>,
    #[serde(default = "default_nat_discovery_timeout_secs")]
    pub discovery_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_network_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub participants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<String>,
    #[serde(
        default = "default_listen_for_join_requests",
        skip_serializing_if = "is_true"
    )]
    pub listen_for_join_requests: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invite_inviter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_join_request: Option<PendingOutboundJoinRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_join_requests: Vec<PendingInboundJoinRequest>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub shared_roster_updated_at: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub shared_roster_signed_by: String,
    /// Set when the chain-anchored admin set diverged from a local admin
    /// update. Quarantined networks stop accepting roster updates and surface
    /// loudly in status output; clear by resolving the chain mismatch and
    /// calling [`AppConfig::clear_network_chain_quarantine`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chain_quarantine_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PendingOutboundJoinRequest {
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub requested_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PendingInboundJoinRequest {
    #[serde(default)]
    pub requester: String,
    #[serde(default)]
    pub requester_node_name: String,
    #[serde(default)]
    pub requested_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnabledNetworkMesh {
    pub id: String,
    pub name: String,
    pub network_id: String,
    pub participants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNetworkRoster {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub participants: Vec<String>,
    pub admins: Vec<String>,
    pub aliases: HashMap<String, String>,
    pub updated_at: u64,
    pub signed_by: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut config = Self {
            networks: vec![NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: default_network_enabled(),
                network_id: default_network_id(),
                participants: Vec::new(),
                admins: Vec::new(),
                listen_for_join_requests: default_listen_for_join_requests(),
                invite_inviter: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                shared_roster_updated_at: 0,
                shared_roster_signed_by: String::new(),
                chain_quarantine_reason: String::new(),
            }],
            node_name: default_node_name(),
            lan_discovery_enabled: default_lan_discovery_enabled(),
            launch_on_startup: default_launch_on_startup(),
            autoconnect: default_autoconnect(),
            fips_peer_endpoints: HashMap::new(),
            fips_advertise_endpoint: default_fips_advertise_endpoint(),
            mesh_mtu_profile: String::new(),
            mesh_underlay_udp_mtu: 0,
            mesh_tunnel_mtu: 0,
            exit_node: String::new(),
            exit_node_leak_protection: default_exit_node_leak_protection(),
            close_to_tray_on_close: default_close_to_tray_on_close(),
            magic_dns_suffix: default_magic_dns_suffix(),
            wireguard_exit: WireGuardExitConfig::default(),
            peer_aliases: default_peer_aliases(),
            nat: NatConfig::default(),
            nostr: NostrConfig::default(),
            node: NodeConfig::default(),
        };
        config.ensure_defaults();
        config
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: default_nat_enabled(),
            stun_servers: default_nat_stun_servers(),
            discovery_timeout_secs: default_nat_discovery_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_id")]
    pub id: String,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_tunnel_ip")]
    pub tunnel_ip: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    #[serde(default)]
    pub advertise_exit_node: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: default_node_id(),
            endpoint: default_endpoint(),
            tunnel_ip: default_tunnel_ip(),
            listen_port: default_listen_port(),
            advertised_routes: Vec::new(),
            advertise_exit_node: false,
        }
    }
}

impl AppConfig {
    pub fn generated() -> Self {
        Self::default()
    }

    pub fn generated_without_networks() -> Self {
        let mut config = Self::default();
        config.networks.clear();
        config.peer_aliases.clear();
        config
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: AppConfig =
            toml::from_str(&raw).with_context(|| "failed to parse config TOML")?;
        config.apply_load_migrations();
        config.ensure_defaults();
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut to_write = self.clone();
        to_write.ensure_defaults();
        to_write.canonicalize_user_facing_pubkeys();

        let raw = toml::to_string_pretty(&to_write).with_context(|| "failed to encode TOML")?;
        write_config_file(path, raw.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn ensure_defaults(&mut self) {
        self.ensure_nostr_identity();
        let own_pubkey_hex = self.own_nostr_pubkey_hex().ok();
        if uses_default_node_name(&self.node_name, own_pubkey_hex.as_deref()) {
            let hostname = detected_hostname();
            self.node_name = own_pubkey_hex
                .as_deref()
                .map(|pubkey_hex| {
                    default_node_name_for_hostname_or_pubkey(hostname.as_deref(), pubkey_hex)
                })
                .or_else(|| {
                    hostname
                        .as_deref()
                        .and_then(default_node_name_from_hostname)
                })
                .unwrap_or_else(default_node_name);
        }

        self.mesh_mtu_profile = self.mesh_mtu_profile.trim().to_ascii_lowercase();
        self.magic_dns_suffix = normalize_magic_dns_suffix(&self.magic_dns_suffix);
        normalize_wireguard_exit_config(&mut self.wireguard_exit);
        self.nostr.relays = normalize_relay_urls(std::mem::take(&mut self.nostr.relays));
        self.nostr.disabled_relays =
            normalize_relay_urls(std::mem::take(&mut self.nostr.disabled_relays));
        let enabled_relays = self.nostr.relays.iter().cloned().collect::<HashSet<_>>();
        self.nostr
            .disabled_relays
            .retain(|relay| !enabled_relays.contains(relay));

        if self.node.id.trim().is_empty() {
            self.node.id = default_node_id();
        }

        if self.node.endpoint.trim().is_empty() {
            self.node.endpoint = default_endpoint();
        }

        if self.node.tunnel_ip.trim().is_empty() {
            self.node.tunnel_ip = default_tunnel_ip();
        }

        if self.node.listen_port == 0 {
            self.node.listen_port = default_listen_port();
        }

        let mut advertise_exit_node = self.node.advertise_exit_node;
        let mut advertised_routes = normalize_advertised_routes(&self.node.advertised_routes);
        advertised_routes.retain(|route| {
            if is_exit_node_route(route) {
                advertise_exit_node = true;
                false
            } else {
                true
            }
        });
        self.node.advertised_routes = advertised_routes;
        self.node.advertise_exit_node = advertise_exit_node;

        self.exit_node = normalize_nostr_pubkey(self.exit_node.trim()).unwrap_or_default();
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex()
            && self.exit_node == own_pubkey
        {
            self.exit_node.clear();
        }

        let mut used_ids = HashSet::new();
        for (index, network) in self.networks.iter_mut().enumerate() {
            let ordinal = index + 1;
            if network.name.trim().is_empty() {
                network.name = default_network_name(ordinal);
            } else {
                network.name = network.name.trim().to_string();
            }

            if network.id.trim().is_empty() {
                network.id = default_network_entry_id(ordinal);
            } else {
                network.id = normalize_network_entry_id(&network.id, ordinal);
            }

            if !used_ids.insert(network.id.clone()) {
                network.id = uniquify_network_entry_id(network.id.clone(), &mut used_ids);
            }

            if network.network_id.trim().is_empty() {
                network.network_id = default_network_id();
            }
            network.invite_inviter =
                normalize_nostr_pubkey(&network.invite_inviter).unwrap_or_default();

            network.participants = network
                .participants
                .iter()
                .filter_map(|participant| normalize_nostr_pubkey(participant).ok())
                .collect();
            network.participants.sort();
            network.participants.dedup();
            network.admins = normalize_network_admins(
                std::mem::take(&mut network.admins),
                own_pubkey_hex.as_deref(),
                &network.invite_inviter,
            );
            network.outbound_join_request = normalize_outbound_join_request(
                network.outbound_join_request.take(),
                &network.participants,
            );
            network.inbound_join_requests = normalize_inbound_join_requests(
                std::mem::take(&mut network.inbound_join_requests),
                &network.participants,
            );
            network.shared_roster_signed_by =
                normalize_nostr_pubkey(&network.shared_roster_signed_by).unwrap_or_default();
            if network.shared_roster_signed_by.is_empty() {
                network.shared_roster_updated_at = 0;
            }
        }

        self.ensure_single_active_network();
        self.generate_placeholder_network_ids();
        self.normalize_selected_exit_node();
        self.normalize_fips_peer_endpoints();
        self.normalize_peer_aliases();
    }

    fn apply_load_migrations(&mut self) {}

    fn canonicalize_user_facing_pubkeys(&mut self) {
        self.nostr.public_key = canonical_npub_key(&self.nostr.public_key).unwrap_or_default();
        self.exit_node = canonical_npub_key(&self.exit_node).unwrap_or_default();
        self.normalize_fips_peer_endpoints();

        for network in &mut self.networks {
            network.participants = network
                .participants
                .iter()
                .filter_map(|participant| canonical_npub_key(participant))
                .collect();
            network.participants.sort();
            network.participants.dedup();
            network.admins = network
                .admins
                .iter()
                .filter_map(|admin| canonical_npub_key(admin))
                .collect();
            network.admins.sort();
            network.admins.dedup();
            network.invite_inviter =
                canonical_npub_key(&network.invite_inviter).unwrap_or_default();
            network.outbound_join_request =
                canonicalize_outbound_join_request(network.outbound_join_request.take());
            network.inbound_join_requests = canonicalize_inbound_join_requests(std::mem::take(
                &mut network.inbound_join_requests,
            ));
            network.shared_roster_signed_by =
                canonical_npub_key(&network.shared_roster_signed_by).unwrap_or_default();
            if network.shared_roster_signed_by.is_empty() {
                network.shared_roster_updated_at = 0;
            }
        }

        self.normalize_peer_aliases();
    }

    pub fn effective_network_id(&self) -> String {
        self.active_network_opt()
            .map(|network| normalize_runtime_network_id(&network.network_id))
            .unwrap_or_default()
    }

    pub fn enabled_network_meshes(&self) -> Vec<EnabledNetworkMesh> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut participants = network.participants.clone();
        participants.sort();
        participants.dedup();

        vec![EnabledNetworkMesh {
            id: network.id.clone(),
            name: network.name.clone(),
            network_id: normalize_runtime_network_id(&network.network_id),
            participants,
        }]
    }

    pub fn participant_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut participants = network.participants.clone();
        participants.sort();
        participants.dedup();
        participants
    }

    pub fn all_participant_pubkeys_hex(&self) -> Vec<String> {
        let mut participants = self
            .networks
            .iter()
            .flat_map(|network| network.participants.iter().cloned())
            .collect::<Vec<_>>();
        participants.sort();
        participants.dedup();
        participants
    }

    fn all_network_member_pubkeys_hex(&self) -> Vec<String> {
        let mut members = self
            .networks
            .iter()
            .flat_map(|network| {
                network
                    .participants
                    .iter()
                    .chain(network.admins.iter())
                    .cloned()
            })
            .collect::<Vec<_>>();
        members.sort();
        members.dedup();
        members
    }

    pub fn enabled_network_count(&self) -> usize {
        self.networks
            .iter()
            .filter(|network| network.enabled)
            .count()
    }

    pub fn active_network(&self) -> &NetworkConfig {
        self.active_network_opt()
            .expect("config has no active network")
    }

    pub fn active_network_opt(&self) -> Option<&NetworkConfig> {
        let index = self
            .networks
            .iter()
            .position(|network| network.enabled)
            .unwrap_or(0);
        self.networks.get(index)
    }

    pub fn active_network_mut(&mut self) -> &mut NetworkConfig {
        self.active_network_mut_opt()
            .expect("config has no active network")
    }

    pub fn active_network_mut_opt(&mut self) -> Option<&mut NetworkConfig> {
        let index = self
            .networks
            .iter()
            .position(|network| network.enabled)
            .unwrap_or(0);
        self.networks.get_mut(index)
    }

    pub fn network_by_id(&self, network_id: &str) -> Option<&NetworkConfig> {
        self.networks
            .iter()
            .find(|network| network.id == network_id)
    }

    pub fn network_by_id_mut(&mut self, network_id: &str) -> Option<&mut NetworkConfig> {
        self.networks
            .iter_mut()
            .find(|network| network.id == network_id)
    }

    pub fn add_owned_network(&mut self, name: &str) -> String {
        self.seed_self_magic_dns_alias_for_first_owned_network();
        self.add_network(name)
    }

    pub fn add_network(&mut self, name: &str) -> String {
        let ordinal = self.networks.len() + 1;
        let mut used_ids = self
            .networks
            .iter()
            .map(|network| network.id.clone())
            .collect::<HashSet<_>>();
        let id = uniquify_network_entry_id(default_network_entry_id(ordinal), &mut used_ids);
        let name = if name.trim().is_empty() {
            default_network_name(ordinal)
        } else {
            name.trim().to_string()
        };

        let enabled = self.networks.is_empty();
        self.networks.push(NetworkConfig {
            id: id.clone(),
            name,
            enabled,
            network_id: default_network_id(),
            participants: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: default_listen_for_join_requests(),
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            chain_quarantine_reason: String::new(),
        });
        let _ = self.note_network_roster_local_change(&id);
        id
    }

    fn seed_self_magic_dns_alias_for_first_owned_network(&mut self) {
        if !self.networks.is_empty() {
            return;
        }

        let _ = self.ensure_self_magic_dns_alias();
    }

    pub fn rename_network(&mut self, network_id: &str, name: &str) -> Result<()> {
        let normalized = name.trim();
        if normalized.is_empty() {
            return Err(anyhow::anyhow!("network name cannot be empty"));
        }
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            network.name = normalized.to_string();
        }
        self.note_network_roster_local_change(network_id)?;
        Ok(())
    }

    pub fn remove_network(&mut self, network_id: &str) -> Result<()> {
        let previous_len = self.networks.len();
        self.networks.retain(|network| network.id != network_id);
        if self.networks.len() == previous_len {
            return Err(anyhow::anyhow!("network not found"));
        }

        if !self.networks.iter().any(|network| network.enabled)
            && let Some(first_network) = self.networks.first_mut()
        {
            first_network.enabled = true;
        }

        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(())
    }

    pub fn set_network_enabled(&mut self, network_id: &str, enabled: bool) -> Result<()> {
        let index = self
            .networks
            .iter()
            .position(|network| network.id == network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;

        if enabled {
            for (candidate_index, network) in self.networks.iter_mut().enumerate() {
                network.enabled = candidate_index == index;
            }
            return Ok(());
        }

        if self.networks[index].enabled {
            return Err(anyhow::anyhow!(
                "activate another network before disabling this one"
            ));
        }

        self.networks[index].enabled = false;
        Ok(())
    }

    pub fn set_network_join_requests_enabled(
        &mut self,
        network_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network.listen_for_join_requests = enabled;
        Ok(())
    }

    pub fn join_requests_enabled(&self) -> bool {
        self.networks
            .iter()
            .any(|network| network.listen_for_join_requests)
    }

    pub fn record_inbound_join_request(
        &mut self,
        requested_network_id: &str,
        requester: &str,
        requester_node_name: &str,
        requested_at: u64,
    ) -> Result<Option<String>> {
        let requested_network_id = normalize_runtime_network_id(requested_network_id);
        if requested_network_id.is_empty() {
            return Ok(None);
        }

        let requester = normalize_nostr_pubkey(requester)?;
        let requester_node_name = requester_node_name.trim().to_string();
        let Some(network) = self.networks.iter_mut().find(|network| {
            network.listen_for_join_requests
                && normalize_runtime_network_id(&network.network_id) == requested_network_id
        }) else {
            return Ok(None);
        };

        if network
            .participants
            .iter()
            .any(|participant| participant == &requester)
        {
            return Ok(None);
        }

        let mut changed = false;
        if let Some(existing) = network
            .inbound_join_requests
            .iter_mut()
            .find(|request| request.requester == requester)
        {
            if existing.requested_at < requested_at
                || existing.requester_node_name != requester_node_name
            {
                existing.requested_at = existing.requested_at.max(requested_at);
                existing.requester_node_name = requester_node_name;
                changed = true;
            }
        } else {
            network
                .inbound_join_requests
                .push(PendingInboundJoinRequest {
                    requester,
                    requester_node_name,
                    requested_at,
                });
            network
                .inbound_join_requests
                .sort_by(|left, right| left.requester.cmp(&right.requester));
            changed = true;
        }

        if changed {
            Ok(Some(network.name.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn reject_inbound_join_request(&mut self, network_id: &str, requester: &str) -> Result<()> {
        let requester = normalize_nostr_pubkey(requester)?;
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network
            .inbound_join_requests
            .retain(|pending| pending.requester != requester);
        Ok(())
    }

    pub fn set_network_mesh_id(&mut self, network_id: &str, mesh_id: &str) -> Result<()> {
        let normalized = normalize_runtime_network_id(mesh_id);
        if normalized.is_empty() {
            return Err(anyhow::anyhow!("network id cannot be empty"));
        }

        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network.network_id = normalized;

        Ok(())
    }

    pub fn set_active_network_id(&mut self, network_id: &str) -> Result<()> {
        let active_network_entry_id = self
            .active_network_opt()
            .ok_or_else(|| anyhow::anyhow!("network not found"))?
            .id
            .clone();
        self.set_network_mesh_id(&active_network_entry_id, network_id)
    }

    pub fn add_participant_to_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<String> {
        let normalized = normalize_nostr_pubkey(participant)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if !network
                .participants
                .iter()
                .any(|configured| configured == &normalized)
            {
                network.participants.push(normalized.clone());
                network.participants.sort();
                network.participants.dedup();
            }
        }

        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(normalized)
    }

    pub fn remove_participant_from_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<()> {
        let normalized = normalize_nostr_pubkey(participant)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if network.admins.len() == 1 && network.admins.iter().any(|admin| admin == &normalized)
            {
                return Err(anyhow::anyhow!("cannot remove the last admin"));
            }
            network
                .participants
                .retain(|configured| configured != &normalized);
            network
                .admins
                .retain(|configured| configured != &normalized);
            if network.invite_inviter == normalized {
                network.invite_inviter = network.admins.first().cloned().unwrap_or_default();
            }
        }

        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(())
    }

    pub fn add_admin_to_network(&mut self, network_id: &str, admin: &str) -> Result<String> {
        let normalized = normalize_nostr_pubkey(admin)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if !network
                .admins
                .iter()
                .any(|configured| configured == &normalized)
            {
                network.admins.push(normalized.clone());
                network.admins.sort();
                network.admins.dedup();
            }
            if network.invite_inviter.is_empty() {
                network.invite_inviter = normalized.clone();
            }
        }
        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        Ok(normalized)
    }

    pub fn remove_admin_from_network(&mut self, network_id: &str, admin: &str) -> Result<()> {
        let normalized = normalize_nostr_pubkey(admin)?;
        {
            let network = self
                .network_by_id_mut(network_id)
                .ok_or_else(|| anyhow::anyhow!("network not found"))?;
            if !network
                .admins
                .iter()
                .any(|configured| configured == &normalized)
            {
                return Ok(());
            }
            if network.admins.len() <= 1 {
                return Err(anyhow::anyhow!("cannot remove the last admin"));
            }
            network
                .admins
                .retain(|configured| configured != &normalized);
            if network.invite_inviter == normalized {
                network.invite_inviter = network.admins.first().cloned().unwrap_or_default();
            }
        }
        self.note_network_roster_local_change(network_id)?;
        self.normalize_selected_exit_node();
        Ok(())
    }

    pub fn network_admin_pubkeys_hex(&self, network_id: &str) -> Result<Vec<String>> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();
        Ok(admins)
    }

    pub fn network_signal_pubkeys_hex(&self, network_id: &str) -> Result<Vec<String>> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut members = network.participants.clone();
        members.extend(network.admins.iter().cloned());
        members.sort();
        members.dedup();
        Ok(members)
    }

    pub fn active_network_admin_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();
        admins
    }

    pub fn active_network_signal_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut members = network.participants.clone();
        members.extend(network.admins.iter().cloned());
        members.sort();
        members.dedup();
        members
    }

    pub fn is_network_admin(&self, network_id: &str, pubkey: &str) -> bool {
        let Ok(normalized) = normalize_nostr_pubkey(pubkey) else {
            return false;
        };
        self.network_by_id(network_id)
            .map(|network| network.admins.iter().any(|admin| admin == &normalized))
            .unwrap_or(false)
    }

    pub fn shared_network_roster(&self, network_id: &str) -> Result<SharedNetworkRoster> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut participants = network.participants.clone();
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex() {
            participants.push(own_pubkey);
        }
        participants.sort();
        participants.dedup();

        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();

        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let mut alias_keys = participants.clone();
        alias_keys.extend(admins.iter().cloned());
        alias_keys.sort();
        alias_keys.dedup();
        let aliases = alias_keys
            .into_iter()
            .filter_map(|member| {
                let alias = if own_pubkey.as_deref() == Some(member.as_str()) {
                    self.self_magic_dns_label()
                } else {
                    self.peer_alias(&member)
                }?;
                Some((member, alias))
            })
            .collect::<HashMap<_, _>>();

        Ok(SharedNetworkRoster {
            id: network.id.clone(),
            network_id: normalize_runtime_network_id(&network.network_id),
            name: network.name.clone(),
            participants,
            admins,
            aliases,
            updated_at: network.shared_roster_updated_at,
            signed_by: network.shared_roster_signed_by.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_admin_signed_shared_roster(
        &mut self,
        network_id: &str,
        network_name: &str,
        participants: Vec<String>,
        admins: Vec<String>,
        aliases: HashMap<String, String>,
        signed_at: u64,
        signed_by: &str,
    ) -> Result<bool> {
        let normalized_network_id = normalize_runtime_network_id(network_id);
        if normalized_network_id.is_empty() {
            return Ok(false);
        }

        let normalized_signed_by = normalize_nostr_pubkey(signed_by)?;
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let now = current_unix_timestamp();
        if signed_at > now.saturating_add(MAX_SHARED_ROSTER_FUTURE_SECS) {
            return Err(anyhow::anyhow!(
                "shared roster timestamp is too far in the future"
            ));
        }

        let Some(network_index) = self.networks.iter().position(|network| {
            normalize_runtime_network_id(&network.network_id) == normalized_network_id
        }) else {
            return Ok(false);
        };

        {
            let network = &self.networks[network_index];
            if !network
                .admins
                .iter()
                .any(|admin| admin == &normalized_signed_by)
            {
                return Ok(false);
            }
            if signed_at <= network.shared_roster_updated_at {
                return Ok(false);
            }
        }

        let own_in_shared_roster = own_pubkey.as_deref().is_none_or(|own_pubkey| {
            participants
                .iter()
                .chain(admins.iter())
                .filter_map(|member| normalize_nostr_pubkey(member).ok())
                .any(|member| member == own_pubkey)
        });
        let own_in_previous_roster = own_pubkey.as_deref().is_some_and(|own_pubkey| {
            let network = &self.networks[network_index];
            network
                .participants
                .iter()
                .chain(network.admins.iter())
                .filter_map(|member| normalize_nostr_pubkey(member).ok())
                .any(|member| member == own_pubkey)
        });

        if own_pubkey.is_some() && own_in_previous_roster && !own_in_shared_roster {
            let was_enabled = self.networks[network_index].enabled;
            self.networks.remove(network_index);
            if was_enabled
                && !self.networks.iter().any(|network| network.enabled)
                && let Some(first) = self.networks.first_mut()
            {
                first.enabled = true;
            }
            self.normalize_selected_exit_node();
            self.normalize_peer_aliases();
            return Ok(true);
        }

        let own_join_completed = own_pubkey.is_some() && own_in_shared_roster;
        let participants = if own_in_shared_roster {
            normalize_shared_roster_participants(participants, own_pubkey.as_deref())?
        } else {
            Vec::new()
        };
        let network = &mut self.networks[network_index];
        let admins =
            normalize_network_admins(admins, own_pubkey.as_deref(), &network.invite_inviter);
        if admins.is_empty() {
            return Err(anyhow::anyhow!(
                "shared roster must include at least one admin"
            ));
        }

        network.participants = participants;
        network.admins = admins;
        if !network_name.trim().is_empty() {
            network.name = network_name.trim().to_string();
        }
        if !network
            .admins
            .iter()
            .any(|admin| admin == &network.invite_inviter)
        {
            network.invite_inviter = normalized_signed_by.clone();
        }
        network.shared_roster_updated_at = signed_at;
        network.shared_roster_signed_by = normalized_signed_by;
        network.outbound_join_request = if own_join_completed {
            None
        } else {
            normalize_outbound_join_request(
                network.outbound_join_request.take(),
                &network.participants,
            )
        };
        network.inbound_join_requests = normalize_inbound_join_requests(
            std::mem::take(&mut network.inbound_join_requests),
            &network.participants,
        );

        let mut allowed_members = network.participants.clone();
        allowed_members.extend(network.admins.iter().cloned());
        if own_in_shared_roster && let Some(own_pubkey) = &own_pubkey {
            allowed_members.push(own_pubkey.clone());
        }
        allowed_members.sort();
        allowed_members.dedup();
        let allowed_members = allowed_members.into_iter().collect::<HashSet<_>>();
        for (participant, alias) in aliases {
            let Ok(normalized_participant) = normalize_nostr_pubkey(&participant) else {
                continue;
            };
            if !allowed_members.contains(&normalized_participant) {
                continue;
            }
            let Some(normalized_alias) = normalize_magic_dns_label(&alias) else {
                continue;
            };
            self.peer_aliases.insert(
                npub_for_pubkey_hex(&normalized_participant),
                normalized_alias,
            );
        }
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        Ok(true)
    }

    /// Apply an admin-signed roster, but first verify the proposed admin set
    /// is a subset of the supplied chain anchor when the network is
    /// Namecoin-anchored (`network_id` of the form `d/<name>`).
    ///
    /// When the chain record is `None` and the id IS Namecoin-anchored, this
    /// method refuses to apply (caller failed to resolve the chain — fail
    /// closed). When the id is NOT Namecoin-anchored, the chain record is
    /// ignored. On mismatch the network is quarantined and the new roster is
    /// NOT applied.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admin_signed_shared_roster_with_chain(
        &mut self,
        network_id: &str,
        network_name: &str,
        participants: Vec<String>,
        admins: Vec<String>,
        aliases: HashMap<String, String>,
        signed_at: u64,
        signed_by: &str,
        chain: Option<&crate::namecoin_name_verify::ChainNetworkRecord>,
    ) -> Result<bool> {
        let namecoin_id = crate::namecoin_name_verify::parse_namecoin_network_id(network_id);

        if let Some(namecoin_id) = namecoin_id.as_ref() {
            let chain = chain.ok_or_else(|| {
                anyhow::anyhow!(
                    "refusing to apply roster for chain-anchored network {} without a chain record",
                    namecoin_id.display()
                )
            })?;
            if let Err(error) =
                crate::namecoin_name_verify::verify_admins_against_chain(&admins, chain)
            {
                let reason = format!(
                    "admin set diverged from chain anchor {}: {error}",
                    namecoin_id.display()
                );
                self.quarantine_network(network_id, &reason);
                return Ok(false);
            }
        }

        self.apply_admin_signed_shared_roster(
            network_id,
            network_name,
            participants,
            admins,
            aliases,
            signed_at,
            signed_by,
        )
    }

    /// Mark a network as quarantined. Idempotent; later calls overwrite the
    /// reason but preserve the quarantine state. Returns `true` if a network
    /// matched.
    pub fn quarantine_network(&mut self, network_id: &str, reason: &str) -> bool {
        let normalized = normalize_runtime_network_id(network_id);
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| normalize_runtime_network_id(&network.network_id) == normalized)
        else {
            return false;
        };
        network.chain_quarantine_reason = reason.trim().to_string();
        true
    }

    /// Clear the chain-quarantine state for a network (e.g. after an operator
    /// has reconciled local admins against the chain by hand).
    pub fn clear_network_chain_quarantine(&mut self, network_id: &str) -> bool {
        let normalized = normalize_runtime_network_id(network_id);
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| normalize_runtime_network_id(&network.network_id) == normalized)
        else {
            return false;
        };
        let was_set = !network.chain_quarantine_reason.is_empty();
        network.chain_quarantine_reason.clear();
        was_set
    }

    pub fn mesh_members_pubkeys(&self) -> Vec<String> {
        let mut members = self.participant_pubkeys_hex();
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex() {
            members.push(own_pubkey);
        }
        members.sort();
        members.dedup();
        members
    }

    pub fn fips_static_peer_endpoints(&self) -> Vec<(String, Vec<String>)> {
        let mut peers = self
            .fips_peer_endpoints
            .iter()
            .map(|(npub, endpoints)| (npub.clone(), endpoints.clone()))
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| left.0.cmp(&right.0));
        peers
    }

    pub fn has_fips_static_peer_endpoints(&self) -> bool {
        self.fips_peer_endpoints
            .values()
            .any(|endpoints| endpoints.iter().any(|endpoint| !endpoint.trim().is_empty()))
    }

    pub fn add_fips_peer_endpoint_hints(&mut self, peer: &str, endpoints: &[String]) -> Result<()> {
        let peer_pubkey = normalize_nostr_pubkey(peer)?;
        let peer_npub = npub_for_pubkey_hex(&peer_pubkey);
        let entry = self.fips_peer_endpoints.entry(peer_npub).or_default();
        entry.extend(
            endpoints
                .iter()
                .filter_map(|endpoint| normalize_fips_peer_endpoint_hint(endpoint)),
        );
        entry.sort();
        entry.dedup();
        self.normalize_fips_peer_endpoints();
        Ok(())
    }

    fn ensure_single_active_network(&mut self) {
        let mut first_active_index = None;
        for (index, network) in self.networks.iter_mut().enumerate() {
            if !network.enabled {
                continue;
            }

            if first_active_index.is_none() {
                first_active_index = Some(index);
            } else {
                network.enabled = false;
            }
        }

        if first_active_index.is_none()
            && let Some(first_network) = self.networks.first_mut()
        {
            first_network.enabled = true;
        }
    }

    fn normalize_fips_peer_endpoints(&mut self) {
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let mut normalized = HashMap::new();
        for (peer, endpoints) in std::mem::take(&mut self.fips_peer_endpoints) {
            let Ok(peer_pubkey) = normalize_nostr_pubkey(&peer) else {
                continue;
            };
            if own_pubkey.as_deref() == Some(peer_pubkey.as_str()) {
                continue;
            }
            let mut endpoints = endpoints
                .into_iter()
                .filter_map(|endpoint| normalize_fips_peer_endpoint_hint(&endpoint))
                .collect::<Vec<_>>();
            endpoints.sort();
            endpoints.dedup();
            if endpoints.is_empty() {
                continue;
            }
            normalized
                .entry(npub_for_pubkey_hex(&peer_pubkey))
                .or_insert_with(Vec::new)
                .extend(endpoints);
        }

        for endpoints in normalized.values_mut() {
            endpoints.sort();
            endpoints.dedup();
        }
        self.fips_peer_endpoints = normalized;
    }

    fn generate_placeholder_network_ids(&mut self) {
        for network in &mut self.networks {
            if !needs_generated_network_id(&network.network_id) {
                continue;
            }

            network.network_id = default_network_id();
        }
    }

    pub fn effective_advertised_routes(&self) -> Vec<String> {
        effective_advertised_routes(&self.node.advertised_routes, self.node.advertise_exit_node)
    }

    pub fn nostr_keys(&self) -> Result<Keys> {
        Keys::parse(&self.nostr.secret_key).context("invalid nostr secret key")
    }

    pub fn own_nostr_pubkey_hex(&self) -> Result<String> {
        normalize_nostr_pubkey(&self.nostr.public_key)
            .or_else(|_| self.nostr_keys().map(|keys| keys.public_key().to_hex()))
    }

    fn ensure_nostr_identity(&mut self) {
        if self.nostr.secret_key.trim().is_empty() {
            let (secret_key, public_key) = generate_nostr_identity();
            self.nostr.secret_key = secret_key;
            self.nostr.public_key = public_key;
            return;
        }

        if normalize_nostr_pubkey(&self.nostr.public_key).is_ok() {
            return;
        }

        if let Ok(keys) = Keys::parse(&self.nostr.secret_key) {
            if self.nostr.public_key.trim().is_empty() {
                self.nostr.public_key = keys
                    .public_key()
                    .to_bech32()
                    .unwrap_or_else(|_| keys.public_key().to_hex());
            }
            return;
        }

        let (secret_key, public_key) = generate_nostr_identity();
        self.nostr.secret_key = secret_key;
        self.nostr.public_key = public_key;
    }

    fn normalize_peer_aliases(&mut self) {
        let mut normalized_aliases = HashMap::new();
        for (participant, alias) in &self.peer_aliases {
            if let Some(participant_npub) = normalize_npub_key(participant)
                && let Some(alias) = normalize_magic_dns_label(alias)
            {
                normalized_aliases.insert(participant_npub, alias);
            }
        }

        let mut used_aliases = HashSet::new();
        let mut final_aliases = HashMap::new();
        let mut members = self.all_network_member_pubkeys_hex();
        let member_set = members.iter().cloned().collect::<HashSet<_>>();
        let mut own_npub = None;
        if let Ok(own_pubkey_hex) = self.own_nostr_pubkey_hex() {
            let own_npub_value = npub_for_pubkey_hex(&own_pubkey_hex);
            own_npub = Some(own_npub_value.clone());
            if member_set.contains(&own_pubkey_hex)
                && let Some(node_alias) = self.custom_node_name_magic_dns_label()
            {
                let existing = normalized_aliases.get(&own_npub_value).cloned();
                if existing
                    .as_deref()
                    .is_some_and(|alias| self.is_generated_self_magic_dns_label(alias))
                {
                    normalized_aliases.insert(own_npub_value.clone(), node_alias);
                }
            }
            if let Some(index) = members
                .iter()
                .position(|participant| participant == &own_pubkey_hex)
            {
                let own = members.remove(index);
                members.insert(0, own);
            } else if normalized_aliases.contains_key(&own_npub_value) {
                members.insert(0, own_pubkey_hex);
            }
        }
        for participant in &members {
            let participant_npub = npub_for_pubkey_hex(participant);
            if own_npub.as_deref() == Some(participant_npub.as_str())
                && !normalized_aliases.contains_key(&participant_npub)
            {
                continue;
            }
            let Some(preferred) = normalized_aliases.remove(&participant_npub) else {
                continue;
            };
            let alias = uniquify_magic_dns_label(preferred, &mut used_aliases);
            final_aliases.insert(participant_npub, alias);
        }
        self.peer_aliases = final_aliases;
    }

    fn normalize_selected_exit_node(&mut self) {
        if self.exit_node.is_empty() {
            return;
        }

        if !self
            .active_network_signal_pubkeys_hex()
            .iter()
            .any(|participant| participant == &self.exit_node)
        {
            self.exit_node.clear();
        }
    }

    pub fn self_magic_dns_label(&self) -> Option<String> {
        let own_pubkey_hex = self.own_nostr_pubkey_hex().ok()?;
        self.peer_alias(&own_pubkey_hex)
    }

    pub fn self_magic_dns_name(&self) -> Option<String> {
        let alias = self.self_magic_dns_label()?;
        if self.magic_dns_suffix.is_empty() {
            Some(alias)
        } else {
            Some(format!("{alias}.{}", self.magic_dns_suffix))
        }
    }

    pub fn peer_alias(&self, participant: &str) -> Option<String> {
        let participant_hex = normalize_nostr_pubkey(participant).ok()?;
        let participant_npub = npub_for_pubkey_hex(&participant_hex);
        self.peer_aliases.get(&participant_npub).cloned()
    }

    fn custom_node_name_magic_dns_label(&self) -> Option<String> {
        let own_pubkey_hex = self.own_nostr_pubkey_hex().ok();
        if uses_default_node_name(&self.node_name, own_pubkey_hex.as_deref()) {
            return None;
        }
        normalize_magic_dns_label(&self.node_name)
    }

    fn default_self_magic_dns_label(&self) -> Option<String> {
        self.custom_node_name_magic_dns_label()
            .or_else(|| Some("self".to_string()))
    }

    fn is_generated_self_magic_dns_label(&self, alias: &str) -> bool {
        if alias == "self" {
            return true;
        }
        self.own_nostr_pubkey_hex()
            .ok()
            .is_some_and(|own_pubkey| alias == default_node_name_for_pubkey(&own_pubkey))
    }

    pub fn ensure_self_magic_dns_alias(&mut self) -> Result<String> {
        let own_pubkey_hex = self.own_nostr_pubkey_hex()?;
        if let Some(alias) = self.peer_alias(&own_pubkey_hex) {
            return Ok(alias);
        }
        let alias = self
            .default_self_magic_dns_label()
            .ok_or_else(|| anyhow::anyhow!("could not derive local device name"))?;
        self.set_peer_alias(&own_pubkey_hex, &alias)
    }

    pub fn ensure_temporary_self_magic_dns_alias(&mut self) -> Result<String> {
        let own_pubkey_hex = self.own_nostr_pubkey_hex()?;
        if let Some(alias) = self.peer_alias(&own_pubkey_hex) {
            return Ok(alias);
        }
        self.set_peer_alias(&own_pubkey_hex, "self")
    }

    pub fn set_peer_alias(&mut self, participant: &str, alias: &str) -> Result<String> {
        let participant_hex = normalize_nostr_pubkey(participant)?;
        let is_own_pubkey =
            self.own_nostr_pubkey_hex().ok().as_deref() == Some(participant_hex.as_str());
        let affected_network_ids = self
            .networks
            .iter()
            .filter(|network| {
                network
                    .participants
                    .iter()
                    .any(|configured| configured == &participant_hex)
                    || network
                        .admins
                        .iter()
                        .any(|configured| configured == &participant_hex)
            })
            .map(|network| network.id.clone())
            .collect::<Vec<_>>();
        if !self
            .all_network_member_pubkeys_hex()
            .iter()
            .any(|configured| configured == &participant_hex)
            && !is_own_pubkey
        {
            return Err(anyhow::anyhow!("participant is not configured"));
        }

        let alias = alias.trim();
        let participant_npub = npub_for_pubkey_hex(&participant_hex);
        if alias.is_empty() {
            self.peer_aliases.remove(&participant_npub);
            self.normalize_peer_aliases();
            for network_id in &affected_network_ids {
                let _ = self.note_network_roster_local_change(network_id);
            }
            return Ok(String::new());
        }

        let normalized_alias =
            normalize_magic_dns_label(alias).ok_or_else(|| anyhow::anyhow!("invalid alias"))?;
        self.peer_aliases
            .insert(participant_npub.clone(), normalized_alias);
        self.normalize_peer_aliases();
        for network_id in &affected_network_ids {
            let _ = self.note_network_roster_local_change(network_id);
        }
        self.peer_aliases
            .get(&participant_npub)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("failed to persist alias"))
    }

    pub fn magic_dns_name_for_participant(&self, participant: &str) -> Option<String> {
        let alias = self.peer_alias(participant)?;
        if self.magic_dns_suffix.is_empty() {
            Some(alias)
        } else {
            Some(format!("{alias}.{}", self.magic_dns_suffix))
        }
    }

    pub fn resolve_magic_dns_query(&self, query: &str) -> Option<String> {
        let query = query.trim().trim_end_matches('.').to_lowercase();
        if query.is_empty() {
            return None;
        }

        if let Ok(own_pubkey_hex) = self.own_nostr_pubkey_hex() {
            if self
                .self_magic_dns_label()
                .is_some_and(|alias| query == alias.as_str())
            {
                return Some(own_pubkey_hex.clone());
            }

            if self
                .self_magic_dns_name()
                .is_some_and(|name| query == name.as_str())
            {
                return Some(own_pubkey_hex);
            }
        }

        for participant in &self.participant_pubkeys_hex() {
            let participant_npub = npub_for_pubkey_hex(participant);
            let Some(alias) = self.peer_aliases.get(&participant_npub) else {
                continue;
            };

            if query == alias.as_str() {
                return Some(participant.clone());
            }

            if !self.magic_dns_suffix.is_empty()
                && query == format!("{alias}.{}", self.magic_dns_suffix)
            {
                return Some(participant.clone());
            }
        }

        None
    }

    pub fn note_active_network_roster_local_change(&mut self) -> Result<()> {
        let network_id = self
            .active_network_opt()
            .ok_or_else(|| anyhow::anyhow!("network not found"))?
            .id
            .clone();
        self.note_network_roster_local_change(&network_id)
    }

    fn note_network_roster_local_change(&mut self, network_id: &str) -> Result<()> {
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let Some(own_pubkey) = own_pubkey else {
            return Ok(());
        };
        if !network.admins.iter().any(|admin| admin == &own_pubkey) {
            return Ok(());
        }
        network.shared_roster_updated_at =
            next_shared_roster_updated_at(network.shared_roster_updated_at);
        network.shared_roster_signed_by = own_pubkey;
        Ok(())
    }
}

const MAX_SHARED_ROSTER_FUTURE_SECS: u64 = 600;

fn next_shared_roster_updated_at(previous: u64) -> u64 {
    current_unix_timestamp().max(previous.saturating_add(1))
}

#[cfg(unix)]
fn write_config_file(path: &Path, raw: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing_owner = fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    let parent_owner = fs::metadata(parent)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    let desired_owner = preferred_config_owner(existing_owner, parent_owner);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut temp_path = None;
    let mut temp_file = None;
    for attempt in 0..128u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate unique config temp file",
        )
    })?;
    let mut file = temp_file.expect("temp file set with temp path");
    if let Err(error) = file.write_all(raw) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    if let Err(error) = file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    if let Some((uid, gid)) = desired_owner {
        let metadata = fs::metadata(path)?;
        if metadata.uid() != uid || metadata.gid() != gid {
            match std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(error) => return Err(error),
            }
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
fn preferred_config_owner(
    existing_owner: Option<(u32, u32)>,
    parent_owner: Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    match (existing_owner, parent_owner) {
        (Some((0, _)), Some((parent_uid, parent_gid))) if parent_uid != 0 => {
            Some((parent_uid, parent_gid))
        }
        (Some(owner), _) => Some(owner),
        (None, Some((parent_uid, parent_gid))) if parent_uid != 0 => Some((parent_uid, parent_gid)),
        (None, _) => None,
    }
}

#[cfg(not(unix))]
fn write_config_file(path: &Path, raw: &[u8]) -> std::io::Result<()> {
    fs::write(path, raw)
}

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, normalize_nostr_pubkey, parse_wireguard_exit_config, wireguard_exit_config_text,
    };
    use crate::config_defaults::generate_nostr_identity;
    #[test]
    fn ensure_defaults_keeps_existing_public_identity_without_parsing_secret_key() {
        let (_, public_key) = generate_nostr_identity();
        let public_key_hex = normalize_nostr_pubkey(&public_key).expect("valid public key");
        let mut config = AppConfig::default();
        config.nostr.secret_key = "not-a-secret-key".to_string();
        config.nostr.public_key = public_key.clone();

        config.ensure_defaults();

        assert_eq!(
            normalize_nostr_pubkey(&config.nostr.public_key).expect("valid public key"),
            public_key_hex
        );
        assert_eq!(config.nostr.secret_key, "not-a-secret-key");
    }

    #[test]
    fn wireguard_exit_defaults_and_normalization_are_stable() {
        let mut config = AppConfig::default();
        config.wireguard_exit.enabled = true;
        config.wireguard_exit.interface = "  ".to_string();
        config.wireguard_exit.address = " 10.200.0.2/32 ".to_string();
        config.wireguard_exit.private_key = " private ".to_string();
        config.wireguard_exit.peer_public_key = " peer ".to_string();
        config.wireguard_exit.endpoint = " 198.51.100.20:51830 ".to_string();
        config.wireguard_exit.allowed_ips = vec![
            "0.0.0.0/0".to_string(),
            "bad-route".to_string(),
            "0.0.0.0/0".to_string(),
        ];
        config.wireguard_exit.dns = vec![" 9.9.9.9 ".to_string(), "9.9.9.9".to_string()];

        config.ensure_defaults();

        assert!(config.wireguard_exit.enabled);
        assert_eq!(config.wireguard_exit.interface, "nvpn-wg-exit");
        assert_eq!(config.wireguard_exit.address, "10.200.0.2/32");
        assert_eq!(config.wireguard_exit.private_key, "private");
        assert_eq!(config.wireguard_exit.peer_public_key, "peer");
        assert_eq!(config.wireguard_exit.endpoint, "198.51.100.20:51830");
        assert_eq!(config.wireguard_exit.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(config.wireguard_exit.dns, vec!["9.9.9.9"]);
        assert!(config.wireguard_exit.configured());
    }

    #[test]
    fn wireguard_exit_import_accepts_provider_config() {
        let imported = parse_wireguard_exit_config(
            r#"
            # Provider export
            [Interface]
            PrivateKey = client-private
            Address = 10.64.70.195/32, fc00:bbbb:bbbb:bb01::1:46c2/128
            DNS = 10.64.0.1, 1.1.1.1
            MTU = 1380

            [Peer]
            PublicKey = provider-public
            PresharedKey = optional-psk
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = vpn.example.test:51820
            PersistentKeepalive = 20
            "#,
        )
        .expect("provider config parses");

        assert_eq!(imported.address, "10.64.70.195/32");
        assert_eq!(imported.private_key, "client-private");
        assert_eq!(imported.peer_public_key, "provider-public");
        assert_eq!(imported.peer_preshared_key, "optional-psk");
        assert_eq!(imported.endpoint, "vpn.example.test:51820");
        assert_eq!(imported.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(imported.dns, vec!["1.1.1.1", "10.64.0.1"]);
        assert_eq!(imported.mtu, 1380);
        assert_eq!(imported.persistent_keepalive_secs, 20);
        assert!(wireguard_exit_config_text(&imported).contains("[Peer]"));
    }

    #[test]
    fn wireguard_exit_import_rejects_shell_hooks() {
        let error = parse_wireguard_exit_config(
            r#"
            [Interface]
            PrivateKey = client-private
            Address = 10.64.70.195/32
            PostUp = echo unsafe

            [Peer]
            PublicKey = provider-public
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.test:51820
            "#,
        )
        .expect_err("shell hooks are rejected")
        .to_string();

        assert!(error.contains("hook directive"), "{error}");
    }

    #[test]
    fn fips_peer_endpoints_normalize_and_exclude_self() {
        let (_, own_public_key) = generate_nostr_identity();
        let (_, peer_public_key) = generate_nostr_identity();
        let peer_public_key_hex =
            normalize_nostr_pubkey(&peer_public_key).expect("valid peer public key");
        let mut config = AppConfig::default();
        config.nostr.secret_key = "not-a-secret-key".to_string();
        config.nostr.public_key = own_public_key.clone();
        config.fips_peer_endpoints.insert(
            peer_public_key_hex,
            vec![
                " 10.203.0.12:51820 ".to_string(),
                "10.203.0.12:51820".to_string(),
                "198.51.100.10:51820".to_string(),
                format!("{peer_public_key}:51820"),
                "fips".to_string(),
            ],
        );
        config
            .fips_peer_endpoints
            .insert(own_public_key, vec!["10.203.0.10:51820".to_string()]);

        config.ensure_defaults();

        assert_eq!(
            config.fips_static_peer_endpoints(),
            vec![(peer_public_key, vec!["10.203.0.12:51820".to_string()])]
        );
        assert!(config.has_fips_static_peer_endpoints());
    }

    #[cfg(unix)]
    #[test]
    fn config_save_prefers_user_owned_parent_over_stale_root_owned_file() {
        assert_eq!(
            super::preferred_config_owner(Some((0, 0)), Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            super::preferred_config_owner(Some((502, 20)), Some((501, 20))),
            Some((502, 20))
        );
        assert_eq!(
            super::preferred_config_owner(None, Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(super::preferred_config_owner(None, Some((0, 0))), None);
    }
}
