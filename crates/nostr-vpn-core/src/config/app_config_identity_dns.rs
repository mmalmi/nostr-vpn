impl AppConfig {
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
            if let Some(participant_npub) = canonical_npub_key(participant)
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

        if self.exit_node_public_paid_exit
            && self.connect_to_non_roster_fips_peers
            && (self.internet_source == InternetSource::PaidManual
                || (self.internet_source == InternetSource::PaidAutomatic
                    && self.fips_nostr_discovery_enabled))
        {
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
                    .devices
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
                return Some(own_pubkey_hex);
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
        network.shared_roster_artifact_hash.clear();
        Ok(())
    }
}
