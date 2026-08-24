impl AppConfig {
    pub fn ensure_defaults(&mut self) {
        let used_legacy_websocket_seed_defaults =
            is_legacy_default_fips_websocket_seed_urls(&self.fips_websocket_seed_urls);
        for (npub, addrs) in default_fips_bootstrap_peers() {
            match self.fips_bootstrap_peers.entry(npub) {
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if is_legacy_fips_bootstrap(entry.key(), entry.get()) =>
                {
                    entry.insert(addrs);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(addrs);
                }
            }
        }
        self.fips_websocket_seed_urls = normalize_relay_urls(std::mem::take(
            &mut self.fips_websocket_seed_urls,
        ));
        if used_legacy_websocket_seed_defaults {
            self.fips_websocket_seed_urls.clear();
        }
        self.fips_websocket_bind_addr = self.fips_websocket_bind_addr.trim().to_string();
        self.fips_websocket_public_url = self.fips_websocket_public_url.trim().to_string();
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
        self.fips_host_inbound_tcp_ports.sort_unstable();
        self.fips_host_inbound_tcp_ports.dedup();
        self.exit_dns.normalize();
        normalize_wireguard_exit_config(&mut self.wireguard_exit);
        self.normalize_internet_source();
        self.paid_exit.normalize();
        if !self.manual_paid_exit_provider.is_default() {
            self.manual_paid_exit_provider = ManualPaidExitProvider::new(
                &self.manual_paid_exit_provider.npub,
                self.manual_paid_exit_provider.max_price_msat_per_gb,
                (!self.manual_paid_exit_provider.mint.is_empty())
                    .then_some(self.manual_paid_exit_provider.mint.as_str()),
            )
            .unwrap_or_default();
        }
        self.nostr.relays = normalize_relay_urls(std::mem::take(&mut self.nostr.relays));
        self.nostr.disabled_relays =
            normalize_relay_urls(std::mem::take(&mut self.nostr.disabled_relays));
        self.nostr.pubsub.normalize();
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
            self.exit_node_public_paid_exit = false;
        }
        if self.exit_node.is_empty()
            || !self.connect_to_non_roster_fips_peers
        {
            self.exit_node_public_paid_exit = false;
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

            network.network_id = normalize_runtime_network_id(&network.network_id);
            if network.network_id.trim().is_empty() {
                network.network_id = default_network_id();
            }
            network.join_secret = network.join_secret.trim().to_string();
            if network.join_secret.is_empty() {
                network.join_secret = default_join_secret();
            }
            network.join_request_admin =
                normalize_nostr_pubkey(&network.join_request_admin).unwrap_or_default();

            network.devices = network
                .devices
                .iter()
                .filter_map(|participant| normalize_nostr_pubkey(participant).ok())
                .collect();
            network.devices.sort();
            network.devices.dedup();
            network.removed_devices = network
                .removed_devices
                .iter()
                .filter_map(|participant| normalize_nostr_pubkey(participant).ok())
                .collect();
            network.removed_devices.sort();
            network.removed_devices.dedup();
            network.admins = normalize_network_admins(
                std::mem::take(&mut network.admins),
                own_pubkey_hex.as_deref(),
                &network.join_request_admin,
            );
            network.outbound_join_request = normalize_outbound_join_request(
                network.outbound_join_request.take(),
                &network.devices,
            );
            network.inbound_join_requests = normalize_inbound_join_requests(
                std::mem::take(&mut network.inbound_join_requests),
                &network.devices,
            );
            network.shared_roster_signed_by =
                normalize_nostr_pubkey(&network.shared_roster_signed_by).unwrap_or_default();
            if network.shared_roster_signed_by.is_empty() {
                network.shared_roster_updated_at = 0;
            }
            if !network.local_identity_confirmation_pending
                && network.outbound_join_request.is_none()
                && network.shared_roster_updated_at == 0
                && network.shared_roster_signed_by.is_empty()
                && own_pubkey_hex
                    .as_deref()
                    .is_some_and(|own| network.join_request_admin != own)
                && !network.join_request_admin.is_empty()
            {
                // Pre-marker manual joins used this exact state while waiting
                // for their first accepted roster. Recover it on upgrade so a
                // receipt-backed approval can still complete.
                network.local_identity_confirmation_pending = true;
            }
        }

        self.ensure_single_active_network();
        self.generate_placeholder_network_ids();
        self.normalize_selected_exit_node();
        self.normalize_fips_peer_endpoints();
        self.normalize_peer_aliases();
    }

    fn apply_load_migrations(&mut self) {
        if self.internet_source == InternetSource::Direct {
            self.internet_source = if self.wireguard_exit.enabled {
                InternetSource::WireGuard
            } else if self.exit_node_public_paid_exit && !self.exit_node.trim().is_empty() {
                InternetSource::PaidManual
            } else if !self.exit_node.trim().is_empty() {
                InternetSource::PrivateVpn
            } else {
                InternetSource::Direct
            };
        }
    }

    fn normalize_internet_source(&mut self) {
        if self.internet_source == InternetSource::Direct {
            self.apply_load_migrations();
        }

        match self.internet_source {
            InternetSource::Direct => {
                self.exit_node.clear();
                self.exit_node_public_paid_exit = false;
                self.wireguard_exit.enabled = false;
            }
            InternetSource::PrivateVpn => {
                self.exit_node_public_paid_exit = false;
                self.wireguard_exit.enabled = false;
            }
            InternetSource::PaidAutomatic => {
                self.exit_node_public_paid_exit = !self.exit_node.trim().is_empty();
                self.wireguard_exit.enabled = false;
                self.connect_to_non_roster_fips_peers = true;
                self.fips_nostr_discovery_enabled = true;
            }
            InternetSource::PaidManual => {
                self.exit_node_public_paid_exit = !self.exit_node.trim().is_empty();
                self.wireguard_exit.enabled = false;
                self.connect_to_non_roster_fips_peers = true;
            }
            InternetSource::WireGuard => {
                self.exit_node.clear();
                self.exit_node_public_paid_exit = false;
                self.wireguard_exit.enabled = true;
            }
        }
    }

    fn canonicalize_user_facing_pubkeys(&mut self) {
        self.nostr.public_key = canonical_npub_key(&self.nostr.public_key).unwrap_or_default();
        self.exit_node = canonical_npub_key(&self.exit_node).unwrap_or_default();
        self.manual_paid_exit_provider.npub =
            canonical_npub_key(&self.manual_paid_exit_provider.npub).unwrap_or_default();
        self.normalize_fips_peer_endpoints();

        for network in &mut self.networks {
            network.devices = network
                .devices
                .iter()
                .filter_map(|participant| canonical_npub_key(participant))
                .collect();
            network.devices.sort();
            network.devices.dedup();
            network.removed_devices = network
                .removed_devices
                .iter()
                .filter_map(|participant| canonical_npub_key(participant))
                .collect();
            network.removed_devices.sort();
            network.removed_devices.dedup();
            network.admins = network
                .admins
                .iter()
                .filter_map(|admin| canonical_npub_key(admin))
                .collect();
            network.admins.sort();
            network.admins.dedup();
            network.join_request_admin =
                canonical_npub_key(&network.join_request_admin).unwrap_or_default();
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
        let mut devices = network.devices.clone();
        devices.sort();
        devices.dedup();

        vec![EnabledNetworkMesh {
            id: network.id.clone(),
            name: network.name.clone(),
            network_id: normalize_runtime_network_id(&network.network_id),
            devices,
        }]
    }

    pub fn device_pubkeys_hex(&self) -> Vec<String> {
        let Some(network) = self.active_network_opt() else {
            return Vec::new();
        };
        let mut devices = network
            .devices
            .iter()
            .filter_map(|device| normalize_nostr_pubkey(device).ok())
            .collect::<Vec<_>>();
        devices.sort();
        devices.dedup();
        devices
    }

    pub fn participant_pubkeys_hex(&self) -> Vec<String> {
        self.device_pubkeys_hex()
    }

    pub fn all_device_pubkeys_hex(&self) -> Vec<String> {
        let mut devices = self
            .networks
            .iter()
            .flat_map(|network| {
                network
                    .devices
                    .iter()
                    .filter_map(|device| normalize_nostr_pubkey(device).ok())
            })
            .collect::<Vec<_>>();
        devices.sort();
        devices.dedup();
        devices
    }

    pub fn all_participant_pubkeys_hex(&self) -> Vec<String> {
        self.all_device_pubkeys_hex()
    }

    fn all_network_member_pubkeys_hex(&self) -> Vec<String> {
        let mut members = self
            .networks
            .iter()
            .flat_map(|network| {
                network
                    .devices
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
        self.networks.iter().find(|network| network.enabled)
    }

    pub fn active_network_mut(&mut self) -> &mut NetworkConfig {
        self.active_network_mut_opt()
            .expect("config has no active network")
    }

    pub fn active_network_mut_opt(&mut self) -> Option<&mut NetworkConfig> {
        self.networks.iter_mut().find(|network| network.enabled)
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
            join_secret: default_join_secret(),
            devices: Vec::new(),
            removed_devices: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: default_listen_for_join_requests(),
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        });
        let _ = self.note_network_roster_local_change(&id);
        id
    }

}

fn default_wallet_fiat_enabled() -> bool {
    true
}
