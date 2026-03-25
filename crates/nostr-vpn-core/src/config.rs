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
const LEGACY_DEFAULT_NODE_NAME: &str = "nostr-vpn-node";

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
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_auto_disconnect_relays_when_mesh_ready")]
    pub auto_disconnect_relays_when_mesh_ready: bool,
    // Legacy field kept so older config files still deserialize cleanly.
    #[serde(default = "default_lan_discovery_enabled", skip_serializing)]
    pub lan_discovery_enabled: bool,
    #[serde(default = "default_launch_on_startup")]
    pub launch_on_startup: bool,
    #[serde(default = "default_autoconnect")]
    pub autoconnect: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exit_node: String,
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
    pub network_id: String,
    #[serde(default)]
    pub participants: Vec<String>,
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

const LEGACY_NETWORK_ID_COMPAT_PREFIX: &str = "nostr-vpn:";

impl Default for AppConfig {
    fn default() -> Self {
        let mut config = Self {
            networks: vec![NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: default_network_enabled(),
                network_id: default_network_id(),
                participants: Vec::new(),
                listen_for_join_requests: default_listen_for_join_requests(),
                invite_inviter: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
            }],
            node_name: default_node_name(),
            auto_disconnect_relays_when_mesh_ready: default_auto_disconnect_relays_when_mesh_ready(
            ),
            lan_discovery_enabled: default_lan_discovery_enabled(),
            launch_on_startup: default_launch_on_startup(),
            autoconnect: default_autoconnect(),
            exit_node: String::new(),
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
        to_write.canonicalize_user_facing_pubkeys();

        let raw = toml::to_string_pretty(&to_write).with_context(|| "failed to encode TOML")?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
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
        self.exit_node = normalize_nostr_pubkey(self.exit_node.trim()).unwrap_or_default();
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex()
            && self.exit_node == own_pubkey
        {
            self.exit_node.clear();
        }

        if self.networks.is_empty() {
            self.networks.push(NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: true,
                network_id: default_network_id(),
                participants: Vec::new(),
                listen_for_join_requests: default_listen_for_join_requests(),
                invite_inviter: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
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
            network.outbound_join_request = normalize_outbound_join_request(
                network.outbound_join_request.take(),
                &network.participants,
            );
            network.inbound_join_requests = normalize_inbound_join_requests(
                std::mem::take(&mut network.inbound_join_requests),
                &network.participants,
            );
        }

        self.ensure_single_active_network();
        self.derive_default_network_ids();
        self.normalize_peer_aliases();
    }

    fn canonicalize_user_facing_pubkeys(&mut self) {
        self.nostr.public_key = canonical_npub_key(&self.nostr.public_key).unwrap_or_default();
        self.exit_node = canonical_npub_key(&self.exit_node).unwrap_or_default();

        for network in &mut self.networks {
            network.participants = network
                .participants
                .iter()
                .filter_map(|participant| canonical_npub_key(participant))
                .collect();
            network.participants.sort();
            network.participants.dedup();
            network.invite_inviter =
                canonical_npub_key(&network.invite_inviter).unwrap_or_default();
            network.outbound_join_request =
                canonicalize_outbound_join_request(network.outbound_join_request.take());
            network.inbound_join_requests = canonicalize_inbound_join_requests(std::mem::take(
                &mut network.inbound_join_requests,
            ));
        }

        self.normalize_peer_aliases();
    }

    pub fn effective_network_id(&self) -> String {
        normalize_runtime_network_id(&self.active_network().network_id)
    }

    pub fn enabled_network_meshes(&self) -> Vec<EnabledNetworkMesh> {
        let network = self.active_network();
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
        let mut participants = self.active_network().participants.clone();
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

    pub fn active_network(&self) -> &NetworkConfig {
        let index = self
            .networks
            .iter()
            .position(|network| network.enabled)
            .unwrap_or(0);
        &self.networks[index]
    }

    pub fn active_network_mut(&mut self) -> &mut NetworkConfig {
        let index = self
            .networks
            .iter()
            .position(|network| network.enabled)
            .unwrap_or(0);
        &mut self.networks[index]
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
            enabled: false,
            network_id: default_network_id(),
            participants: Vec::new(),
            listen_for_join_requests: default_listen_for_join_requests(),
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
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

        if !self.networks.iter().any(|network| network.enabled)
            && let Some(first_network) = self.networks.first_mut()
        {
            first_network.enabled = true;
        }

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
                "at least one active network is required; activate another network first"
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
        let active_network_entry_id = self.active_network().id.clone();
        self.set_network_mesh_id(&active_network_entry_id, network_id)
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

    fn derive_default_network_ids(&mut self) {
        let own_pubkey = self.own_nostr_pubkey_hex().ok();

        for network in &mut self.networks {
            if !uses_default_network_id(&network.network_id) {
                continue;
            }

            let Some(own_pubkey) = own_pubkey.as_ref() else {
                network.network_id = default_network_id();
                continue;
            };

            if network.participants.is_empty() {
                network.network_id = default_network_id();
                continue;
            }

            let mut mesh_members = network.participants.clone();
            mesh_members.push(own_pubkey.clone());
            mesh_members.sort();
            mesh_members.dedup();
            network.network_id = derive_network_id_from_participants(&mesh_members);
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
        if let Some(self_alias) = self.preferred_self_magic_dns_label() {
            used_aliases.insert(self_alias);
        }
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

    fn preferred_self_magic_dns_label(&self) -> Option<String> {
        normalize_magic_dns_label(&self.node_name)
    }

    pub fn self_magic_dns_label(&self) -> Option<String> {
        let preferred = self.preferred_self_magic_dns_label()?;
        let mut used_aliases = self
            .peer_aliases
            .values()
            .cloned()
            .collect::<HashSet<String>>();
        Some(uniquify_magic_dns_label(preferred, &mut used_aliases))
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
    hex::encode(digest)[..16].to_string()
}

pub fn normalize_runtime_network_id(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix(LEGACY_NETWORK_ID_COMPAT_PREFIX)
        .unwrap_or(trimmed)
        .to_string()
}

pub fn normalize_nostr_pubkey(value: &str) -> Result<String> {
    PublicKey::parse(value)
        .map(|public_key| public_key.to_hex())
        .map_err(|error| anyhow::anyhow!("invalid participant pubkey '{value}': {error}"))
}

pub fn maybe_autoconfigure_node(config: &mut AppConfig) {
    config.ensure_defaults();

    if needs_endpoint_autoconfig(&config.node.endpoint)
        && let Some(ip) = detect_primary_ipv4()
    {
        config.node.endpoint = format!("{ip}:{}", config.node.listen_port);
    }

    let network_id = config.effective_network_id();
    if needs_tunnel_ip_autoconfig(&config.node.tunnel_ip)
        && let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(&network_id, &own_pubkey)
    {
        config.node.tunnel_ip = tunnel_ip;
    }
}

pub fn derive_mesh_tunnel_ip(network_id: &str, own_pubkey_hex: &str) -> Option<String> {
    let network_id = normalize_runtime_network_id(network_id);
    let network_id = network_id.trim();
    let own_pubkey_hex = own_pubkey_hex.trim();
    if network_id.is_empty() || own_pubkey_hex.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(network_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(own_pubkey_hex.as_bytes());
    let digest = hasher.finalize();

    let third_octet = (digest[0] % 254) + 1;
    let fourth_octet = (digest[1] % 254) + 1;
    Some(format!("10.44.{third_octet}.{fourth_octet}/32"))
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

fn uses_default_network_id(value: &str) -> bool {
    value.trim().is_empty() || value.trim() == "nostr-vpn"
}

const fn default_network_enabled() -> bool {
    true
}

const fn default_listen_for_join_requests() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
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
    LEGACY_DEFAULT_NODE_NAME.to_string()
}

fn uses_default_node_name(value: &str, own_pubkey_hex: Option<&str>) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty()
        || trimmed == LEGACY_DEFAULT_NODE_NAME
        || own_pubkey_hex
            .map(|pubkey_hex| trimmed == default_node_name_for_pubkey(pubkey_hex))
            .unwrap_or(false)
}

pub fn default_node_name_for_pubkey(pubkey_hex: &str) -> String {
    default_magic_dns_label_for_pubkey(pubkey_hex, &HashSet::new())
}

pub fn default_node_name_from_hostname(hostname: &str) -> Option<String> {
    let first_label = hostname
        .trim()
        .trim_matches('.')
        .split('.')
        .find(|label| !label.trim().is_empty())?;
    let normalized = normalize_magic_dns_label(first_label)?;
    if normalized == "localhost" {
        return None;
    }
    Some(normalized)
}

pub fn default_node_name_for_hostname_or_pubkey(
    hostname: Option<&str>,
    pubkey_hex: &str,
) -> String {
    hostname
        .and_then(default_node_name_from_hostname)
        .unwrap_or_else(|| default_node_name_for_pubkey(pubkey_hex))
}

fn detected_hostname() -> Option<String> {
    let hostname = hostname::get().ok()?;
    Some(hostname.to_string_lossy().into_owned())
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

fn canonical_npub_key(value: &str) -> Option<String> {
    let normalized = normalize_nostr_pubkey(value).ok()?;
    Some(npub_for_pubkey_hex(&normalized))
}

fn normalize_outbound_join_request(
    request: Option<PendingOutboundJoinRequest>,
    _participants: &[String],
) -> Option<PendingOutboundJoinRequest> {
    let request = request?;
    let recipient = normalize_nostr_pubkey(&request.recipient).ok()?;
    Some(PendingOutboundJoinRequest {
        recipient,
        requested_at: request.requested_at,
    })
}

fn canonicalize_outbound_join_request(
    request: Option<PendingOutboundJoinRequest>,
) -> Option<PendingOutboundJoinRequest> {
    let request = request?;
    let recipient = canonical_npub_key(&request.recipient)?;
    Some(PendingOutboundJoinRequest {
        recipient,
        requested_at: request.requested_at,
    })
}

fn normalize_inbound_join_requests(
    requests: Vec<PendingInboundJoinRequest>,
    participants: &[String],
) -> Vec<PendingInboundJoinRequest> {
    let mut deduped = HashMap::new();

    for request in requests {
        let Ok(requester) = normalize_nostr_pubkey(&request.requester) else {
            continue;
        };
        if participants
            .iter()
            .any(|participant| participant == &requester)
        {
            continue;
        }

        let normalized = PendingInboundJoinRequest {
            requester: requester.clone(),
            requester_node_name: request.requester_node_name.trim().to_string(),
            requested_at: request.requested_at,
        };
        if deduped
            .get(&requester)
            .map(|existing: &PendingInboundJoinRequest| {
                existing.requested_at >= normalized.requested_at
            })
            .unwrap_or(false)
        {
            continue;
        }
        deduped.insert(requester, normalized);
    }

    let mut normalized = deduped.into_values().collect::<Vec<_>>();
    normalized.sort_by(|left, right| left.requester.cmp(&right.requester));
    normalized
}

fn canonicalize_inbound_join_requests(
    requests: Vec<PendingInboundJoinRequest>,
) -> Vec<PendingInboundJoinRequest> {
    requests
        .into_iter()
        .filter_map(|request| {
            let requester = canonical_npub_key(&request.requester)?;
            Some(PendingInboundJoinRequest {
                requester,
                requester_node_name: request.requester_node_name,
                requested_at: request.requested_at,
            })
        })
        .collect()
}

fn normalize_npub_key(value: &str) -> Option<String> {
    let candidate = value.trim();
    if !candidate.starts_with("npub1") {
        return None;
    }

    canonical_npub_key(candidate)
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
