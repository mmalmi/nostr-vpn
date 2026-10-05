/// Relays used by signed FIPS peer/service announcements. Physical FIPS
/// datagrams are never carried through these relays.
pub fn effective_nostr_relays(configured: &[String], disabled: &[String]) -> Vec<String> {
    let configured = normalize_relay_urls(configured.to_vec());
    let mut relays = if configured.is_empty() {
        default_relays()
    } else {
        configured
    };
    let disabled = normalize_relay_urls(disabled.to_vec());
    relays.retain(|relay| !disabled.contains(relay));
    relays
}

impl AppConfig {
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

    /// The operator-configured transit/bootstrap peers as `(npub, [addr])`,
    /// sorted. Empty when the bootstrap master switch is off. Our own identity
    /// is filtered out so a node does not dial itself.
    pub fn fips_bootstrap_peer_endpoints(&self) -> Vec<(String, Vec<String>)> {
        if !self.fips_bootstrap_enabled {
            return Vec::new();
        }
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let mut peers = self
            .fips_bootstrap_peers
            .iter()
            .filter(|(npub, addrs)| {
                if addrs.iter().all(|addr| addr.trim().is_empty()) {
                    return false;
                }
                match (own_pubkey.as_deref(), normalize_nostr_pubkey(npub)) {
                    (Some(own), Ok(hex)) => own != hex,
                    _ => true,
                }
            })
            .map(|(npub, addrs)| (npub.clone(), addrs.clone()))
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| left.0.cmp(&right.0));
        peers
    }

    /// Clear the bootstrap/transit peer list back to the public WebSocket seeds.
    pub fn reset_fips_bootstrap_peers(&mut self) {
        self.fips_bootstrap_peers = default_fips_bootstrap_peers();
    }

    /// Replace the bootstrap/transit peer list, normalizing keys to npub and
    /// validating each transport-tagged address. Invalid entries are dropped.
    pub fn set_fips_bootstrap_peers(&mut self, peers: HashMap<String, Vec<String>>) {
        let mut normalized = HashMap::new();
        for (key, addrs) in peers {
            let Ok(pubkey) = normalize_nostr_pubkey(&key) else {
                continue;
            };
            let npub = npub_for_pubkey_hex(&pubkey);
            let mut valid = Vec::new();
            for addr in addrs {
                if let Some(address) = normalize_fips_transport_address(&addr)
                    && !valid.contains(&address)
                {
                    valid.push(address);
                }
            }
            if !valid.is_empty() {
                normalized.insert(npub, valid);
            }
        }
        self.fips_bootstrap_peers = normalized;
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

    pub fn set_fips_peer_endpoint_hints(&mut self, peer: &str, endpoints: &[String]) -> Result<()> {
        let peer_pubkey = normalize_nostr_pubkey(peer)?;
        let peer_npub = npub_for_pubkey_hex(&peer_pubkey);
        let mut normalized = Vec::new();
        for endpoint in endpoints {
            let endpoint = endpoint.trim();
            if endpoint.is_empty() {
                continue;
            }
            let Some(endpoint) = normalize_fips_peer_endpoint_hint(endpoint) else {
                return Err(anyhow!(
                    "FIPS address hint must be a usable UDP host or host:port, for example 192.168.1.10, 192.168.1.10:51820, or peer.example.com"
                ));
            };
            normalized.push(endpoint);
        }
        normalized.sort();
        normalized.dedup();

        if normalized.is_empty() {
            self.fips_peer_endpoints.remove(&peer_npub);
        } else {
            self.fips_peer_endpoints.insert(peer_npub, normalized);
        }
        self.normalize_fips_peer_endpoints();
        Ok(())
    }

    pub fn fips_peer_endpoint_hints(&self, peer: &str) -> Vec<String> {
        let Ok(peer_pubkey) = normalize_nostr_pubkey(peer) else {
            return Vec::new();
        };
        let peer_npub = npub_for_pubkey_hex(&peer_pubkey);
        self.fips_peer_endpoints
            .get(&peer_npub)
            .cloned()
            .unwrap_or_default()
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
}
