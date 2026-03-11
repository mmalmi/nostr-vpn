use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::Path;

use anyhow::{Context, Result};
use nostr_sdk::prelude::{Keys, PublicKey, ToBech32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::generate_keypair;

/// Same defaults as hashtree's `DEFAULT_RELAYS`.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://temp.iris.to",
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    #[serde(default = "default_relays")]
    pub relays: Vec<String>,
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
            secret_key,
            public_key,
        }
    }
}

fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS
        .iter()
        .map(|relay| relay.to_string())
        .collect()
}

fn default_nat_enabled() -> bool {
    true
}

fn default_nat_stun_servers() -> Vec<String> {
    vec![
        "stun:stun.iris.to:3478".to_string(),
        "stun:stun.l.google.com:19302".to_string(),
        "stun:stun.cloudflare.com:3478".to_string(),
    ]
}

const fn default_nat_discovery_timeout_secs() -> u64 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default = "default_network_id")]
    pub network_id: String,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_auto_disconnect_relays_when_mesh_ready")]
    pub auto_disconnect_relays_when_mesh_ready: bool,
    #[serde(default = "default_lan_discovery_enabled")]
    pub lan_discovery_enabled: bool,
    #[serde(default = "default_launch_on_startup")]
    pub launch_on_startup: bool,
    #[serde(default = "default_autoconnect")]
    pub autoconnect: bool,
    #[serde(default = "default_close_to_tray_on_close")]
    pub close_to_tray_on_close: bool,
    #[serde(default = "default_magic_dns_suffix")]
    pub magic_dns_suffix: String,
    #[serde(default = "default_peer_aliases")]
    pub peer_aliases: HashMap<String, String>,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default)]
    pub nostr: NostrConfig,
    #[serde(default)]
    pub node: NodeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default = "default_nat_enabled")]
    pub enabled: bool,
    #[serde(default = "default_nat_stun_servers")]
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub reflectors: Vec<String>,
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
    pub participants: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut config = Self {
            networks: vec![NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: default_network_enabled(),
                participants: Vec::new(),
            }],
            network_id: default_network_id(),
            node_name: default_node_name(),
            auto_disconnect_relays_when_mesh_ready: default_auto_disconnect_relays_when_mesh_ready(
            ),
            lan_discovery_enabled: default_lan_discovery_enabled(),
            launch_on_startup: default_launch_on_startup(),
            autoconnect: default_autoconnect(),
            close_to_tray_on_close: default_close_to_tray_on_close(),
            magic_dns_suffix: default_magic_dns_suffix(),
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
            reflectors: Vec::new(),
            discovery_timeout_secs: default_nat_discovery_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_id")]
    pub id: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
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
        let key_pair = generate_keypair();
        Self {
            id: default_node_id(),
            private_key: key_pair.private_key,
            public_key: key_pair.public_key,
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

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: AppConfig =
            toml::from_str(&raw).with_context(|| "failed to parse config TOML")?;
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

        let raw = toml::to_string_pretty(&to_write).with_context(|| "failed to encode TOML")?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn ensure_defaults(&mut self) {
        if self.node_name.trim().is_empty() {
            self.node_name = default_node_name();
        }

        if self.network_id.trim().is_empty() {
            self.network_id = default_network_id();
        }
        self.magic_dns_suffix = normalize_magic_dns_suffix(&self.magic_dns_suffix);

        if self.nostr.relays.is_empty() {
            self.nostr.relays = default_relays();
        }

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

        if self.node.private_key.trim().is_empty() || self.node.public_key.trim().is_empty() {
            let key_pair = generate_keypair();
            self.node.private_key = key_pair.private_key;
            self.node.public_key = key_pair.public_key;
        }

        self.ensure_nostr_identity();

        if self.networks.is_empty() {
            self.networks.push(NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: true,
                participants: Vec::new(),
            });
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

            network.participants = network
                .participants
                .iter()
                .filter_map(|participant| normalize_nostr_pubkey(participant).ok())
                .collect();
            network.participants.sort();
            network.participants.dedup();
        }

        self.normalize_peer_aliases();
    }

    pub fn effective_network_id(&self) -> String {
        if self.participant_pubkeys_hex().is_empty() {
            return self.network_id.clone();
        }

        let mesh_members = self.mesh_members_pubkeys();
        if mesh_members.is_empty() {
            return self.network_id.clone();
        }

        derive_network_id_from_participants(&mesh_members)
    }

    pub fn participant_pubkeys_hex(&self) -> Vec<String> {
        let mut participants = self
            .networks
            .iter()
            .filter(|network| network.enabled)
            .flat_map(|network| network.participants.iter().cloned())
            .collect::<Vec<_>>();
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

    pub fn enabled_network_count(&self) -> usize {
        self.networks
            .iter()
            .filter(|network| network.enabled)
            .count()
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

        self.networks.push(NetworkConfig {
            id: id.clone(),
            name,
            enabled: true,
            participants: Vec::new(),
        });
        id
    }

    pub fn rename_network(&mut self, network_id: &str, name: &str) -> Result<()> {
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let normalized = name.trim();
        if normalized.is_empty() {
            return Err(anyhow::anyhow!("network name cannot be empty"));
        }
        network.name = normalized.to_string();
        Ok(())
    }

    pub fn remove_network(&mut self, network_id: &str) -> Result<()> {
        if self.networks.len() <= 1 {
            return Err(anyhow::anyhow!("at least one network is required"));
        }

        let previous_len = self.networks.len();
        self.networks.retain(|network| network.id != network_id);
        if self.networks.len() == previous_len {
            return Err(anyhow::anyhow!("network not found"));
        }

        self.normalize_peer_aliases();
        Ok(())
    }

    pub fn set_network_enabled(&mut self, network_id: &str, enabled: bool) -> Result<()> {
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network.enabled = enabled;
        Ok(())
    }

    pub fn add_participant_to_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<String> {
        let normalized = normalize_nostr_pubkey(participant)?;
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

        self.normalize_peer_aliases();
        Ok(normalized)
    }

    pub fn remove_participant_from_network(
        &mut self,
        network_id: &str,
        participant: &str,
    ) -> Result<()> {
        let normalized = normalize_nostr_pubkey(participant)?;
        let network = self
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        network
            .participants
            .retain(|configured| configured != &normalized);

        self.normalize_peer_aliases();
        Ok(())
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
        for participant in &self.all_participant_pubkeys_hex() {
            let participant_npub = npub_for_pubkey_hex(participant);
            let preferred = normalized_aliases
                .remove(&participant_npub)
                .unwrap_or_else(|| default_magic_dns_label_for_pubkey(participant, &used_aliases));
            let alias = uniquify_magic_dns_label(preferred, &mut used_aliases);
            final_aliases.insert(participant_npub, alias);
        }
        self.peer_aliases = final_aliases;
    }

    pub fn peer_alias(&self, participant: &str) -> Option<String> {
        let participant_hex = normalize_nostr_pubkey(participant).ok()?;
        let participant_npub = npub_for_pubkey_hex(&participant_hex);
        self.peer_aliases.get(&participant_npub).cloned()
    }

    pub fn set_peer_alias(&mut self, participant: &str, alias: &str) -> Result<String> {
        let participant_hex = normalize_nostr_pubkey(participant)?;
        if !self
            .all_participant_pubkeys_hex()
            .iter()
            .any(|configured| configured == &participant_hex)
        {
            return Err(anyhow::anyhow!("participant is not configured"));
        }

        let alias = alias.trim();
        let participant_npub = npub_for_pubkey_hex(&participant_hex);
        if alias.is_empty() {
            self.peer_aliases.remove(&participant_npub);
            self.normalize_peer_aliases();
            return self
                .peer_aliases
                .get(&participant_npub)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("failed to persist alias"));
        }

        let normalized_alias =
            normalize_magic_dns_label(alias).ok_or_else(|| anyhow::anyhow!("invalid alias"))?;
        self.peer_aliases
            .insert(participant_npub.clone(), normalized_alias);
        self.normalize_peer_aliases();
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
}

pub fn derive_network_id_from_participants(participants: &[String]) -> String {
    let mut normalized: Vec<String> = participants.to_vec();
    normalized.sort();
    normalized.dedup();

    let mut hasher = Sha256::new();
    for participant in normalized {
        hasher.update(participant.as_bytes());
        hasher.update(b"\n");
    }

    let digest = hasher.finalize();
    format!("nostr-vpn:{}", &hex::encode(digest)[..16])
}

pub fn normalize_nostr_pubkey(value: &str) -> Result<String> {
    PublicKey::parse(value)
        .map(|public_key| public_key.to_hex())
        .map_err(|error| anyhow::anyhow!("invalid participant pubkey '{value}': {error}"))
}

pub fn maybe_autoconfigure_node(config: &mut AppConfig) {
    if needs_endpoint_autoconfig(&config.node.endpoint)
        && let Some(ip) = detect_primary_ipv4()
    {
        config.node.endpoint = format!("{ip}:{}", config.node.listen_port);
    }

    let mesh_members = config.mesh_members_pubkeys();
    if needs_tunnel_ip_autoconfig(&config.node.tunnel_ip)
        && let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(&mesh_members, &own_pubkey)
    {
        config.node.tunnel_ip = tunnel_ip;
    }
}

pub fn derive_mesh_tunnel_ip(participants: &[String], own_pubkey_hex: &str) -> Option<String> {
    if participants.is_empty() {
        return None;
    }

    let mut normalized = participants.to_vec();
    normalized.sort();
    normalized.dedup();

    let host_octet = if let Some(index) = normalized.iter().position(|key| key == own_pubkey_hex) {
        ((index % 250) + 1) as u8
    } else {
        let digest = Sha256::digest(own_pubkey_hex.as_bytes());
        (digest[0] % 241) + 10
    };

    Some(format!("10.44.0.{host_octet}/32"))
}

pub fn normalize_advertised_route(value: &str) -> Option<String> {
    let value = value.trim();
    let (addr, bits) = value.split_once('/')?;
    let addr: IpAddr = addr.trim().parse().ok()?;
    let bits: u8 = bits.trim().parse().ok()?;

    let max_bits = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if bits > max_bits {
        return None;
    }

    let network = match addr {
        IpAddr::V4(ip) => IpAddr::V4(mask_ipv4(ip, bits)),
        IpAddr::V6(ip) => IpAddr::V6(mask_ipv6(ip, bits)),
    };

    Some(format!("{network}/{bits}"))
}

pub fn normalize_advertised_routes(routes: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for route in routes {
        let Some(route) = normalize_advertised_route(route) else {
            continue;
        };
        if seen.insert(route.clone()) {
            normalized.push(route);
        }
    }

    normalized
}

pub fn effective_advertised_routes(routes: &[String], advertise_exit_node: bool) -> Vec<String> {
    let mut effective = normalize_advertised_routes(routes);
    let mut seen = effective.iter().cloned().collect::<HashSet<_>>();

    if advertise_exit_node {
        for route in exit_node_default_routes() {
            if seen.insert(route.clone()) {
                effective.push(route);
            }
        }
    }

    effective
}

pub fn exit_node_default_routes() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

fn is_exit_node_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

fn mask_ipv4(ip: Ipv4Addr, bits: u8) -> Ipv4Addr {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_ipv6(ip: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    Ipv6Addr::from(u128::from_be_bytes(ip.octets()) & mask)
}

pub fn needs_endpoint_autoconfig(endpoint: &str) -> bool {
    let value = endpoint.trim();
    if value.is_empty() {
        return true;
    }

    let host = value
        .rsplit_once(':')
        .map_or(value, |(host, _port)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');

    matches!(host, "127.0.0.1" | "0.0.0.0" | "localhost" | "::1")
}

pub fn needs_tunnel_ip_autoconfig(tunnel_ip: &str) -> bool {
    let value = tunnel_ip.trim();
    value.is_empty() || value == "10.44.0.1/32"
}

fn detect_primary_ipv4() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_ipv4() { Some(ip) } else { None }
}

fn generate_nostr_identity() -> (String, String) {
    let keys = Keys::generate();

    let secret_key = keys
        .secret_key()
        .to_bech32()
        .unwrap_or_else(|_| keys.secret_key().to_secret_hex());

    let public_key = keys
        .public_key()
        .to_bech32()
        .unwrap_or_else(|_| keys.public_key().to_hex());

    (secret_key, public_key)
}

fn default_network_id() -> String {
    "nostr-vpn".to_string()
}

const fn default_network_enabled() -> bool {
    true
}

fn default_network_name(ordinal: usize) -> String {
    format!("Network {ordinal}")
}

fn default_network_entry_id(ordinal: usize) -> String {
    format!("network-{ordinal}")
}

fn normalize_network_entry_id(value: &str, ordinal: usize) -> String {
    normalize_magic_dns_label(value).unwrap_or_else(|| default_network_entry_id(ordinal))
}

fn uniquify_network_entry_id(candidate: String, used_ids: &mut HashSet<String>) -> String {
    if used_ids.insert(candidate.clone()) {
        return candidate;
    }

    let base = candidate;
    let mut suffix = 2_usize;
    loop {
        let next = format!("{base}-{suffix}");
        if used_ids.insert(next.clone()) {
            return next;
        }
        suffix += 1;
    }
}

fn default_magic_dns_suffix() -> String {
    "nvpn".to_string()
}

fn default_peer_aliases() -> HashMap<String, String> {
    HashMap::new()
}

fn default_node_name() -> String {
    "nostr-vpn-node".to_string()
}

const fn default_auto_disconnect_relays_when_mesh_ready() -> bool {
    true
}

const fn default_lan_discovery_enabled() -> bool {
    true
}

const fn default_launch_on_startup() -> bool {
    true
}

const fn default_autoconnect() -> bool {
    true
}

const fn default_close_to_tray_on_close() -> bool {
    true
}

fn default_node_id() -> String {
    Uuid::new_v4().to_string()
}

fn default_endpoint() -> String {
    "127.0.0.1:51820".to_string()
}

fn default_tunnel_ip() -> String {
    "10.44.0.1/32".to_string()
}

const fn default_listen_port() -> u16 {
    51820
}

pub fn normalize_magic_dns_suffix(value: &str) -> String {
    let mut normalized_labels = value
        .trim()
        .trim_end_matches('.')
        .split('.')
        .filter_map(normalize_magic_dns_label)
        .collect::<Vec<_>>();
    normalized_labels.retain(|label| !label.is_empty());

    if normalized_labels.is_empty() {
        return default_magic_dns_suffix();
    }

    normalized_labels.join(".")
}

pub fn normalize_magic_dns_label(value: &str) -> Option<String> {
    let mut label = String::new();
    let mut previous_dash = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            label.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            label.push('-');
            previous_dash = true;
        }
    }

    while label.ends_with('-') {
        label.pop();
    }
    while label.starts_with('-') {
        label.remove(0);
    }

    if label.is_empty() {
        return None;
    }

    if label.len() > 63 {
        label.truncate(63);
        while label.ends_with('-') {
            label.pop();
        }
    }

    if label.is_empty() { None } else { Some(label) }
}

pub fn default_magic_dns_label_for_pubkey(
    pubkey_hex: &str,
    used_aliases: &HashSet<String>,
) -> String {
    if !HASHTREE_ANIMAL_ALIASES.is_empty() {
        let digest = Sha256::digest(pubkey_hex.as_bytes());
        let mut index =
            ((digest[0] as usize) << 8 | digest[1] as usize) % HASHTREE_ANIMAL_ALIASES.len();
        for _ in 0..HASHTREE_ANIMAL_ALIASES.len() {
            let candidate = HASHTREE_ANIMAL_ALIASES[index];
            if !used_aliases.contains(candidate) {
                return candidate.to_string();
            }
            index = (index + 1) % HASHTREE_ANIMAL_ALIASES.len();
        }
    }

    let short = pubkey_hex.chars().take(12).collect::<String>();
    format!("peer-{short}")
}

// Derived from hashtree animals list:
// - apps/hashtree-cc/src/lib/data/animals.json
// - apps/iris-files/src/utils/data/animals.json
const HASHTREE_ANIMAL_ALIASES: &[&str] = &[
    "aardvark",
    "aardwolf",
    "albatross",
    "alligator",
    "alpaca",
    "anaconda",
    "angelfish",
    "ant",
    "anteater",
    "antelope",
    "ape",
    "armadillo",
    "baboon",
    "badger",
    "barracuda",
    "bat",
    "bear",
    "beaver",
    "bee",
    "beetle",
    "bison",
    "blackbird",
    "boa",
    "boar",
    "bobcat",
    "bonobo",
    "butterfly",
    "buzzard",
    "camel",
    "capybara",
    "cardinal",
    "caribou",
    "carp",
    "cat",
    "catfish",
    "centipede",
    "chameleon",
    "cheetah",
    "chicken",
    "chimpanzee",
    "chinchilla",
    "chipmunk",
    "clam",
    "clownfish",
    "cobra",
    "cockroach",
    "condor",
    "cougar",
    "cow",
    "coyote",
    "crab",
    "crane",
    "crayfish",
    "cricket",
    "crocodile",
    "crow",
    "cuckoo",
    "deer",
    "dingo",
    "dolphin",
    "donkey",
    "dove",
    "dragonfly",
    "duck",
    "eagle",
    "earthworm",
    "echidna",
    "eel",
    "egret",
    "elephant",
    "elk",
    "emu",
    "falcon",
    "ferret",
    "finch",
    "firefly",
    "fish",
    "flamingo",
    "fox",
    "frog",
    "gazelle",
    "gecko",
    "gerbil",
    "giraffe",
    "goat",
    "goldfish",
    "goose",
    "gorilla",
    "grasshopper",
    "grouse",
    "guanaco",
    "gull",
    "hamster",
    "hare",
    "hawk",
    "hedgehog",
    "heron",
    "hippopotamus",
    "hornet",
    "horse",
    "hummingbird",
    "hyena",
    "ibis",
    "iguana",
    "impala",
    "jackal",
    "jaguar",
    "jellyfish",
    "kangaroo",
    "koala",
    "koi",
    "ladybug",
    "lemur",
    "leopard",
    "lion",
    "lizard",
    "llama",
    "lobster",
    "lynx",
    "macaw",
    "magpie",
    "manatee",
    "marten",
    "meerkat",
    "mink",
    "mole",
    "mongoose",
    "monkey",
    "moose",
    "mosquito",
    "moth",
    "mouse",
    "mule",
    "narwhal",
    "newt",
    "nightingale",
    "octopus",
    "opossum",
    "orangutan",
    "orca",
    "ostrich",
    "otter",
    "owl",
    "oyster",
    "panda",
    "panther",
    "parrot",
    "peacock",
    "pelican",
    "penguin",
    "pheasant",
    "pig",
    "pigeon",
    "piranha",
    "platypus",
    "porcupine",
    "porpoise",
    "puffin",
    "python",
    "quail",
    "rabbit",
    "raccoon",
    "ram",
    "rat",
    "raven",
    "reindeer",
    "rhino",
    "salamander",
    "salmon",
    "scorpion",
    "seahorse",
    "seal",
    "shark",
    "sheep",
    "skunk",
    "sloth",
    "snail",
    "snake",
    "sparrow",
    "spider",
    "squid",
    "squirrel",
    "starfish",
    "stork",
    "swan",
    "tapir",
    "termite",
    "tiger",
    "toad",
    "toucan",
    "trout",
    "turkey",
    "turtle",
    "viper",
    "vulture",
    "walrus",
    "wasp",
    "weasel",
    "whale",
    "wildcat",
    "wolf",
    "wombat",
    "woodpecker",
    "yak",
    "zebra",
];

fn npub_for_pubkey_hex(pubkey_hex: &str) -> String {
    PublicKey::from_hex(pubkey_hex)
        .ok()
        .and_then(|public_key| public_key.to_bech32().ok())
        .unwrap_or_else(|| pubkey_hex.to_string())
}

fn normalize_npub_key(value: &str) -> Option<String> {
    let candidate = value.trim();
    if !candidate.starts_with("npub1") {
        return None;
    }

    PublicKey::parse(candidate)
        .ok()
        .and_then(|public_key| public_key.to_bech32().ok())
}

fn uniquify_magic_dns_label(mut base: String, used: &mut HashSet<String>) -> String {
    if base.is_empty() {
        base = "peer".to_string();
    }

    if !used.contains(&base) {
        used.insert(base.clone());
        return base;
    }

    for counter in 2..10_000 {
        let suffix = format!("-{counter}");
        let max_base_len = 63usize.saturating_sub(suffix.len());
        let mut candidate_base = base.clone();
        if candidate_base.len() > max_base_len {
            candidate_base.truncate(max_base_len);
            while candidate_base.ends_with('-') {
                candidate_base.pop();
            }
        }
        let candidate = format!("{candidate_base}{suffix}");
        if !used.contains(&candidate) {
            used.insert(candidate.clone());
            return candidate;
        }
    }

    base
}
