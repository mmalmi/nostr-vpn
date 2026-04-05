use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nostr_sdk::prelude::{Keys, ToBech32};

pub use crate::config_magic_dns::{
    default_magic_dns_label_for_pubkey, default_node_name_for_hostname_or_pubkey,
    default_node_name_for_pubkey, default_node_name_from_hostname, normalize_magic_dns_label,
    normalize_magic_dns_suffix,
};
pub use crate::network_routes::{
    derive_mesh_tunnel_ip, effective_advertised_routes, exit_node_default_routes,
    normalize_advertised_route, normalize_advertised_routes,
};

use crate::config_defaults::{
    current_unix_timestamp, default_autoconnect, default_close_to_tray_on_close, default_endpoint,
    default_lan_discovery_enabled, default_launch_on_startup, default_listen_for_join_requests,
    default_listen_port, default_nat_discovery_timeout_secs, default_nat_enabled,
    default_nat_stun_servers, default_network_enabled, default_network_id, default_node_id,
    default_provide_nat_assist, default_relay_for_others, default_relays, default_tunnel_ip,
    default_use_public_relay_fallback, generate_nostr_identity, is_true, is_zero,
    npub_for_pubkey_hex, uses_default_network_id,
};
pub use crate::config_defaults::{
    derive_network_id_from_participants, maybe_autoconfigure_node, needs_endpoint_autoconfig,
    needs_tunnel_ip_autoconfig, normalize_nostr_pubkey, normalize_runtime_network_id,
};
use crate::config_magic_dns::{
    default_magic_dns_suffix, default_network_entry_id, default_network_name, default_node_name,
    default_peer_aliases, detected_hostname, normalize_network_entry_id, uniquify_magic_dns_label,
    uniquify_network_entry_id, uses_default_node_name,
};
use crate::network_roster::{
    canonical_npub_key, canonicalize_inbound_join_requests, canonicalize_outbound_join_request,
    normalize_inbound_join_requests, normalize_network_admins, normalize_npub_key,
    normalize_outbound_join_request, normalize_shared_roster_participants,
};
use crate::network_routes::is_exit_node_route;
use serde::{Deserialize, Serialize};

use crate::crypto::generate_keypair;

/// Same defaults as hashtree's `DEFAULT_RELAYS`.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://temp.iris.to",
    "wss://relay.damus.io",
    "wss://relay.snort.social",
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_use_public_relay_fallback")]
    pub use_public_relay_fallback: bool,
    #[serde(default = "default_relay_for_others")]
    pub relay_for_others: bool,
    #[serde(default = "default_provide_nat_assist")]
    pub provide_nat_assist: bool,
    // Legacy field kept so older config files still deserialize cleanly.
    #[serde(default, skip_serializing)]
    pub auto_disconnect_relays_when_mesh_ready: bool,
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
            }],
            node_name: default_node_name(),
            use_public_relay_fallback: default_use_public_relay_fallback(),
            relay_for_others: default_relay_for_others(),
            provide_nat_assist: default_provide_nat_assist(),
            auto_disconnect_relays_when_mesh_ready: false,
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
        self.auto_disconnect_relays_when_mesh_ready = false;
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
                admins: Vec::new(),
                listen_for_join_requests: default_listen_for_join_requests(),
                invite_inviter: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                shared_roster_updated_at: 0,
                shared_roster_signed_by: String::new(),
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
        self.derive_default_network_ids();
        self.normalize_selected_exit_node();
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
            admins: Vec::new(),
            listen_for_join_requests: default_listen_for_join_requests(),
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        });
        let _ = self.note_network_roster_local_change(&id);
        id
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
        let mut admins = self.active_network().admins.clone();
        admins.sort();
        admins.dedup();
        admins
    }

    pub fn active_network_signal_pubkeys_hex(&self) -> Vec<String> {
        let mut members = self.active_network().participants.clone();
        members.extend(self.active_network().admins.iter().cloned());
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

        let Some(network) = self.networks.iter_mut().find(|network| {
            normalize_runtime_network_id(&network.network_id) == normalized_network_id
        }) else {
            return Ok(false);
        };

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

        let participants =
            normalize_shared_roster_participants(participants, own_pubkey.as_deref())?;
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
        network.outbound_join_request = normalize_outbound_join_request(
            network.outbound_join_request.take(),
            &network.participants,
        );
        network.inbound_join_requests = normalize_inbound_join_requests(
            std::mem::take(&mut network.inbound_join_requests),
            &network.participants,
        );

        let mut allowed_members = network.participants.clone();
        allowed_members.extend(network.admins.iter().cloned());
        allowed_members.sort();
        allowed_members.dedup();
        let allowed_members = allowed_members.into_iter().collect::<HashSet<_>>();
        for (participant, alias) in aliases {
            let Ok(normalized_participant) = normalize_nostr_pubkey(&participant) else {
                continue;
            };
            if Some(normalized_participant.as_str()) == own_pubkey.as_deref() {
                continue;
            }
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
        for participant in &self.all_network_member_pubkeys_hex() {
            let participant_npub = npub_for_pubkey_hex(participant);
            let preferred = normalized_aliases
                .remove(&participant_npub)
                .unwrap_or_else(|| default_magic_dns_label_for_pubkey(participant, &used_aliases));
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
        network.shared_roster_updated_at = current_unix_timestamp();
        network.shared_roster_signed_by = own_pubkey;
        Ok(())
    }
}

const MAX_SHARED_ROSTER_FUTURE_SECS: u64 = 600;
