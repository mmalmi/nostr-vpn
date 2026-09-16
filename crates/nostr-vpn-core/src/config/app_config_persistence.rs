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

    pub fn set_internet_source(&mut self, source: InternetSource) {
        let previous_source = self.internet_source;
        self.internet_source = source;
        match source {
            InternetSource::Direct => {
                self.exit_node.clear();
                self.exit_node_public_paid_exit = false;
                self.wireguard_exit.enabled = false;
            }
            InternetSource::WireGuard => {
                self.exit_node.clear();
                self.exit_node_public_paid_exit = false;
            }
            InternetSource::PrivateVpn => {
                if self.exit_node_public_paid_exit {
                    self.exit_node.clear();
                }
                self.exit_node_public_paid_exit = false;
            }
            InternetSource::PaidAutomatic => {
                self.clear_manual_paid_exit_provider();
                self.exit_node.clear();
                self.exit_node_public_paid_exit = false;
            }
            InternetSource::PaidManual => {
                if !self.exit_node_public_paid_exit {
                    self.exit_node.clear();
                }
            }
        }
        self.normalize_internet_source();
        if matches!(
            previous_source,
            InternetSource::PaidAutomatic | InternetSource::PaidManual
        ) && !matches!(
            self.internet_source,
            InternetSource::PaidAutomatic | InternetSource::PaidManual
        ) && self.manual_paid_exit_provider_pubkey_hex().is_none()
        {
            self.connect_to_non_roster_fips_peers = false;
        }
    }

    pub fn set_paid_exit_seller_enabled(&mut self, enabled: bool) {
        self.paid_exit.enabled = enabled;
        if enabled {
            self.enable_paid_exit_relay_control();
        }
    }

    pub fn enable_paid_exit_market_discovery(&mut self) -> bool {
        let changed = !self.connect_to_non_roster_fips_peers;
        self.connect_to_non_roster_fips_peers = true;
        self.enable_paid_exit_relay_control() || changed
    }

    fn enable_paid_exit_relay_control(&mut self) -> bool {
        if self.nostr.pubsub.mode == NostrPubsubMode::Off {
            self.nostr.pubsub.mode = NostrPubsubMode::Relay;
            true
        } else {
            false
        }
    }

    pub fn select_private_exit_node(&mut self, peer: &str) -> Result<String> {
        let peer_pubkey = normalize_nostr_pubkey(peer)
            .map_err(|error| anyhow!("invalid private exit peer pubkey: {error}"))?;
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex()
            && peer_pubkey == own_pubkey
        {
            return Err(anyhow!("cannot select this device as its own private exit"));
        }
        self.internet_source = InternetSource::PrivateVpn;
        self.exit_node = peer_pubkey.clone();
        self.exit_node_public_paid_exit = false;
        self.normalize_internet_source();
        Ok(peer_pubkey)
    }

    pub fn select_public_paid_exit_node(&mut self, seller: &str) -> Result<String> {
        let seller_pubkey = normalize_nostr_pubkey(seller)
            .map_err(|error| anyhow!("invalid paid exit seller pubkey: {error}"))?;
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex()
            && seller_pubkey == own_pubkey
        {
            return Err(anyhow!("cannot select this device as its own paid exit"));
        }

        if self.internet_source != InternetSource::PaidAutomatic {
            self.internet_source = InternetSource::PaidManual;
        }
        self.exit_node = seller_pubkey.clone();
        self.exit_node_public_paid_exit = true;
        self.ensure_defaults();
        if self.exit_node != seller_pubkey {
            return Err(anyhow!(
                "paid exit seller was not retained as the selected exit node"
            ));
        }
        Ok(seller_pubkey)
    }

    pub fn set_manual_paid_exit_provider(&mut self, value: &str) -> Result<()> {
        let provider = ManualPaidExitProvider::parse(value)?;
        let provider_hex = normalize_nostr_pubkey(&provider.npub)?;
        if self
            .own_nostr_pubkey_hex()
            .is_ok_and(|own_pubkey| own_pubkey == provider_hex)
        {
            return Err(anyhow!("cannot use this device as its own paid exit"));
        }
        self.manual_paid_exit_provider = provider;
        self.connect_to_non_roster_fips_peers = true;
        if self.nostr.pubsub.mode == NostrPubsubMode::Off {
            self.nostr.pubsub.mode = NostrPubsubMode::Client;
        }
        Ok(())
    }

    pub fn clear_manual_paid_exit_provider(&mut self) {
        self.manual_paid_exit_provider = ManualPaidExitProvider::default();
    }

    pub fn manual_paid_exit_provider_pubkey_hex(&self) -> Option<String> {
        normalize_nostr_pubkey(&self.manual_paid_exit_provider.npub).ok()
    }

    pub fn public_paid_exit_node_pubkey_hex(&self) -> Option<String> {
        if !self.exit_node_public_paid_exit || !self.connect_to_non_roster_fips_peers {
            return None;
        }
        normalize_nostr_pubkey(&self.exit_node).ok()
    }

    pub fn paid_exit_seller_egress(&self) -> Result<PaidExitSellerEgress> {
        match self.internet_source {
            InternetSource::Direct => Ok(PaidExitSellerEgress::Direct),
            InternetSource::WireGuard => Ok(PaidExitSellerEgress::WireGuard),
            InternetSource::PrivateVpn => {
                let peer = normalize_nostr_pubkey(&self.exit_node)
                    .map_err(|_| anyhow!("select a private exit before selling internet"))?;
                if let Ok(own_pubkey) = self.own_nostr_pubkey_hex()
                    && peer == own_pubkey
                {
                    return Err(anyhow!("cannot resell this device as its own private exit"));
                }
                if !self
                    .active_network_signal_pubkeys_hex()
                    .iter()
                    .any(|participant| participant == &peer)
                {
                    return Err(anyhow!(
                        "selected private exit is not in the active network"
                    ));
                }
                Ok(PaidExitSellerEgress::PrivatePeer { pubkey: peer })
            }
            InternetSource::PaidAutomatic | InternetSource::PaidManual => Err(anyhow!(
                "paid exits cannot be resold; choose device internet, WireGuard, or a private exit"
            )),
        }
    }

    pub fn validate_paid_exit_seller_buyer(&self, buyer: &str) -> Result<String> {
        let buyer = normalize_nostr_pubkey(buyer)
            .map_err(|error| anyhow!("invalid paid exit buyer pubkey: {error}"))?;
        if self
            .paid_exit_seller_egress()?
            .private_peer_pubkey()
            .is_some_and(|upstream| upstream == buyer)
        {
            return Err(anyhow!(
                "private exit upstream cannot also connect as this seller's buyer"
            ));
        }
        Ok(buyer)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: AppConfig =
            toml::from_str(&raw).with_context(|| "failed to parse config TOML")?;
        config.apply_load_migrations();
        hydrate_config_secrets(path, &mut config)?;
        config.ensure_defaults();
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.save_with_secret_persistence(path, SecretPersistence::Platform)
    }

    pub fn save_plaintext(&self, path: &Path) -> Result<()> {
        self.save(path)
    }

    pub fn delete_persisted_secrets_for_path(path: &Path) -> Result<()> {
        delete_config_secrets(path)
    }

    pub fn config_file_needs_secret_migration(path: &Path) -> Result<bool> {
        config_file_needs_secret_migration(path)
    }

    pub fn migrate_persisted_secrets(path: &Path) -> Result<bool> {
        if !Self::config_file_needs_secret_migration(path)? {
            return Ok(false);
        }

        let config = Self::load(path)?;
        config.save(path)?;
        Ok(true)
    }

    pub fn persisted_toml_for_path(&self, path: &Path) -> Result<String> {
        self.toml_with_secret_persistence(path, SecretPersistence::Platform)
    }

    pub fn plaintext_toml(&self) -> Result<String> {
        self.toml_with_secret_persistence(Path::new(""), SecretPersistence::Plaintext)
    }

    fn save_with_secret_persistence(
        &self,
        path: &Path,
        persistence: SecretPersistence,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let raw = self.toml_with_secret_persistence(path, persistence)?;
        write_private_file_preserving_user_owner(path, raw.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    fn toml_with_secret_persistence(
        &self,
        path: &Path,
        persistence: SecretPersistence,
    ) -> Result<String> {
        let mut to_write = self.clone();
        to_write.ensure_defaults();
        to_write.canonicalize_user_facing_pubkeys();
        prepare_config_secrets_for_save(path, &mut to_write, persistence)?;

        toml::to_string_pretty(&to_write).with_context(|| "failed to encode TOML")
    }
}

#[cfg(test)]
mod public_paid_exit_tests {
    use super::AppConfig;
    use crate::config::{InternetSource, NostrPubsubMode};

    #[test]
    fn configured_public_paid_exit_does_not_require_nostr_discovery() {
        let seller = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut app = AppConfig::generated();
        app.select_public_paid_exit_node(seller)
            .expect("select public paid exit");
        app.fips_nostr_discovery_enabled = false;

        assert_eq!(
            app.public_paid_exit_node_pubkey_hex().as_deref(),
            Some(seller)
        );
    }

    #[test]
    fn manual_provider_pins_control_peer_without_enabling_relay_discovery() {
        let seller = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut app = AppConfig::generated();
        app.fips_nostr_discovery_enabled = false;
        app.nostr.pubsub.mode = NostrPubsubMode::Off;

        app.set_manual_paid_exit_provider(seller)
            .expect("set manual provider");

        assert_eq!(app.internet_source, InternetSource::Direct);
        assert!(app.exit_node.is_empty());
        assert!(app.connect_to_non_roster_fips_peers);
        assert_eq!(app.nostr.pubsub.mode, NostrPubsubMode::Client);
        assert!(!app.fips_nostr_discovery_enabled);
        assert_eq!(
            app.manual_paid_exit_provider_pubkey_hex().as_deref(),
            Some(seller)
        );
    }

    #[test]
    fn adding_manual_provider_does_not_change_current_internet_source() {
        let seller = "1111111111111111111111111111111111111111111111111111111111111111";
        for source in [
            InternetSource::Direct,
            InternetSource::WireGuard,
            InternetSource::PrivateVpn,
        ] {
            let mut app = AppConfig::generated();
            app.internet_source = source;
            app.exit_node = if source == InternetSource::PrivateVpn {
                "2222222222222222222222222222222222222222222222222222222222222222".to_string()
            } else {
                String::new()
            };
            let prior_exit = app.exit_node.clone();

            app.set_manual_paid_exit_provider(seller)
                .expect("pin manual provider");

            assert_eq!(app.internet_source, source);
            assert_eq!(app.exit_node, prior_exit);
            assert!(!app.exit_node_public_paid_exit);
        }
    }

    #[test]
    fn legacy_variable_pricing_is_rejected_instead_of_becoming_free() {
        let raw = r#"
[paid_exit]
enabled = true

[paid_exit.pricing]
price_msat = 2500
per_units = 1000000
"#;
        let error = toml::from_str::<AppConfig>(raw).expect_err("legacy pricing rejected");

        assert!(error.to_string().contains("price_msat_per_gb"));
    }
}
