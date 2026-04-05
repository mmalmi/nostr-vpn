use super::*;

impl NvpnBackend {
    fn persist_config_with_defaults(&mut self) -> Result<PersistConfigOutcome> {
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()
    }

    fn finish_config_mutation(
        &mut self,
        persist_outcome: PersistConfigOutcome,
        ensure_peers: bool,
        ensure_relays: bool,
        reload_live_process: bool,
    ) -> Result<()> {
        if ensure_peers {
            self.ensure_peer_status_entries();
        }
        if ensure_relays {
            self.ensure_relay_status_entries();
        }
        if persist_outcome.needs_explicit_daemon_reload() {
            if reload_live_process {
                if self.daemon_running {
                    self.reload_daemon_process()?;
                }
            } else {
                self.reload_daemon_if_running()?;
            }
        }
        self.sync_daemon_state();
        Ok(())
    }

    pub(crate) fn add_network(&mut self, name: &str) -> Result<()> {
        self.config.add_network(name);
        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, true, false, false)?;
        Ok(())
    }

    pub(crate) fn rename_network(&mut self, network_id: &str, name: &str) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        self.config.rename_network(network_id, name)?;
        let _ = self.persist_config()?;
        self.sync_daemon_state();
        Ok(())
    }

    pub(crate) fn set_network_mesh_id(&mut self, network_id: &str, mesh_id: &str) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let is_active_network = self
            .config
            .network_by_id(network_id)
            .map(|network| network.enabled)
            .ok_or_else(|| anyhow!("network not found"))?;

        self.config.set_network_mesh_id(network_id, mesh_id)?;
        let persist_outcome = self.persist_config_with_defaults()?;

        if is_active_network {
            self.finish_config_mutation(persist_outcome, true, false, false)?;
            if self.daemon_running {
                self.session_status = "Mesh ID updated and applied.".to_string();
            }
        } else {
            self.finish_config_mutation(persist_outcome, false, false, false)?;
        }
        Ok(())
    }

    pub(crate) fn remove_network(&mut self, network_id: &str) -> Result<()> {
        self.config.remove_network(network_id)?;
        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, true, false, false)?;
        Ok(())
    }

    pub(crate) fn set_network_enabled(&mut self, network_id: &str, enabled: bool) -> Result<()> {
        self.config.set_network_enabled(network_id, enabled)?;
        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, false, false, false)?;
        Ok(())
    }

    fn ensure_network_admin(&self, network_id: &str) -> Result<()> {
        let own_pubkey = self.config.own_nostr_pubkey_hex()?;
        if self.config.is_network_admin(network_id, &own_pubkey) {
            return Ok(());
        }
        Err(anyhow!("only network admins can manage members"))
    }

    fn ensure_participant_admin(&self, participant: &str) -> Result<()> {
        let normalized = normalize_nostr_pubkey(participant)?;
        let own_pubkey = self.config.own_nostr_pubkey_hex()?;
        let mut matched_network = false;

        for network in &self.config.networks {
            let contains_participant = network.participants.iter().any(|configured| configured == &normalized)
                || network.admins.iter().any(|configured| configured == &normalized);
            if !contains_participant {
                continue;
            }
            matched_network = true;
            if self.config.is_network_admin(&network.id, &own_pubkey) {
                return Ok(());
            }
        }

        if matched_network {
            Err(anyhow!("only network admins can rename participants"))
        } else {
            Err(anyhow!("participant is not configured"))
        }
    }

    pub(crate) fn add_participant(
        &mut self,
        network_id: &str,
        npub: &str,
        alias: Option<&str>,
    ) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let input = npub.trim();
        if input.is_empty() {
            return Err(anyhow!("participant npub is empty"));
        }
        if !input.starts_with("npub1") {
            return Err(anyhow!("participant must be an npub"));
        }

        let normalized = self.config.add_participant_to_network(network_id, input)?;
        if let Some(alias) = alias {
            let alias = alias.trim();
            if !alias.is_empty() {
                self.config.set_peer_alias(&normalized, alias)?;
            }
        }
        self.peer_status.entry(normalized).or_default();

        let persist_outcome = self.persist_config_with_defaults()?;
        if self.daemon_running {
            self.session_status = "Participant saved and applied.".to_string();
        }
        self.finish_config_mutation(persist_outcome, true, false, true)?;

        Ok(())
    }

    pub(crate) fn add_admin(&mut self, network_id: &str, npub: &str) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let normalized = self.config.add_admin_to_network(network_id, npub)?;
        self.peer_status.entry(normalized).or_default();

        let persist_outcome = self.persist_config_with_defaults()?;
        if self.daemon_running {
            self.session_status = "Admin saved and applied.".to_string();
        }
        self.finish_config_mutation(persist_outcome, true, false, true)?;

        Ok(())
    }

    pub(crate) fn import_network_invite(&mut self, invite_code: &str) -> Result<()> {
        let invite = parse_network_invite(invite_code)?;
        apply_network_invite_to_active_network(&mut self.config, &invite)?;
        let active_network_id = self.config.active_network().id.clone();
        let normalized_inviter = normalize_nostr_pubkey(&invite.inviter_npub)?;
        self.peer_status.entry(normalized_inviter).or_default();

        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, true, true, false)?;
        let imported_network_name = self.config.active_network().name.clone();
        self.session_status = if self.daemon_running {
            format!("Invite imported and applied for {}.", imported_network_name)
        } else {
            format!("Invite imported for {}.", imported_network_name)
        };
        if let Err(error) = self.request_network_join(&active_network_id) {
            self.session_status = format!(
                "{} Join request not sent automatically: {error}",
                self.session_status
            );
        }

        Ok(())
    }

    pub(crate) fn remove_participant(&mut self, network_id: &str, npub_or_hex: &str) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let normalized = normalize_nostr_pubkey(npub_or_hex)?;
        self.config
            .remove_participant_from_network(network_id, &normalized)?;
        self.peer_status.remove(&normalized);
        if let Some(network) = self.config.network_by_id_mut(network_id) {
            if network.invite_inviter == normalized {
                network.invite_inviter.clear();
            }
            if network
                .outbound_join_request
                .as_ref()
                .map(|request| request.recipient == normalized)
                .unwrap_or(false)
            {
                network.outbound_join_request = None;
            }
            network
                .inbound_join_requests
                .retain(|request| request.requester != normalized);
        }

        let persist_outcome = self.persist_config_with_defaults()?;
        if self.daemon_running {
            self.session_status = "Participant removed and applied.".to_string();
        }
        self.finish_config_mutation(persist_outcome, true, false, true)?;

        Ok(())
    }

    pub(crate) fn remove_admin(&mut self, network_id: &str, npub_or_hex: &str) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let normalized = normalize_nostr_pubkey(npub_or_hex)?;
        self.config
            .remove_admin_from_network(network_id, &normalized)?;

        let persist_outcome = self.persist_config_with_defaults()?;
        if self.daemon_running {
            self.session_status = "Admin removed and applied.".to_string();
        }
        self.finish_config_mutation(persist_outcome, true, false, true)?;

        Ok(())
    }

    pub(crate) fn set_network_join_requests_enabled(
        &mut self,
        network_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let listener_was_enabled = local_join_request_listener_enabled(&self.config);
        self.ensure_network_admin(network_id)?;
        self.config
            .set_network_join_requests_enabled(network_id, enabled)?;
        self.persist_config_without_daemon_reload()?;
        let listener_is_enabled = local_join_request_listener_enabled(&self.config);
        if self.daemon_running {
            self.reload_daemon_process()?;
            if listener_is_enabled && !self.session_active {
                self.resume_daemon_process()?;
            } else if listener_was_enabled && !listener_is_enabled && !self.session_active {
                self.pause_daemon_process()?;
            }
        } else if listener_is_enabled {
            self.start_daemon_process()?;
        }
        self.sync_daemon_state();
        self.session_status = if enabled {
            "Join requests enabled.".to_string()
        } else {
            "Join requests disabled.".to_string()
        };
        Ok(())
    }

    pub(crate) fn request_network_join(&mut self, network_id: &str) -> Result<()> {
        let network = self
            .config
            .network_by_id(network_id)
            .ok_or_else(|| anyhow!("network not found"))?;
        let mut recipients = network.admins.clone();
        recipients.sort();
        recipients.dedup();
        if recipients.is_empty() {
            return Err(anyhow!("this network was not imported from an invite"));
        }
        let primary_recipient = preferred_join_request_recipient(network)
            .or_else(|| recipients.first().cloned())
            .ok_or_else(|| anyhow!("this network was not imported from an invite"))?;
        if let Some(request) = &network.outbound_join_request
            && request.recipient == primary_recipient
        {
            return Ok(());
        }

        let keys = self.config.nostr_keys()?;
        let relays = self.config.nostr.relays.clone();
        let request = MeshJoinRequest {
            network_id: normalize_runtime_network_id(&network.network_id),
            requester_node_name: self.config.node_name.trim().to_string(),
        };
        let should_connect_session = !self.session_active;
        self.runtime.block_on(async {
            for recipient in &recipients {
                publish_join_request(keys.clone(), &relays, recipient.clone(), request.clone())
                    .await?;
            }
            Result::<(), anyhow::Error>::Ok(())
        })?;

        if let Some(network) = self.config.network_by_id_mut(network_id) {
            network.outbound_join_request = Some(PendingOutboundJoinRequest {
                recipient: primary_recipient.clone(),
                requested_at: current_unix_timestamp(),
            });
        }
        self.persist_config_without_daemon_reload()?;

        let connect_error = if should_connect_session {
            self.connect_session().err().map(|error| error.to_string())
        } else {
            None
        };

        let recipient_npub = shorten_middle(&to_npub(&primary_recipient), 18, 12);
        self.session_status = match connect_error {
            Some(error) => {
                format!("Join request sent to {recipient_npub}, but VPN start failed: {error}")
            }
            None if should_connect_session => {
                format!("Join request sent to {recipient_npub} and VPN started.")
            }
            None => format!("Join request sent to {recipient_npub}."),
        };
        Ok(())
    }

    pub(crate) fn accept_join_request(
        &mut self,
        network_id: &str,
        requester_npub: &str,
    ) -> Result<()> {
        self.ensure_network_admin(network_id)?;
        let requester = normalize_nostr_pubkey(requester_npub)?;
        let should_connect_session = !self.session_active;
        let requester_node_name = self
            .config
            .network_by_id(network_id)
            .and_then(|network| {
                network
                    .inbound_join_requests
                    .iter()
                    .find(|request| request.requester == requester)
                    .map(|request| request.requester_node_name.clone())
            })
            .unwrap_or_default();
        self.config
            .add_participant_to_network(network_id, &requester)?;
        if !requester_node_name.trim().is_empty() {
            let _ = self.config.set_peer_alias(&requester, &requester_node_name);
        }
        if let Some(network) = self.config.network_by_id_mut(network_id) {
            network
                .inbound_join_requests
                .retain(|request| request.requester != requester);
        }
        self.peer_status.entry(requester).or_default();

        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, true, false, true)?;

        let connect_error = if should_connect_session {
            self.connect_session().err().map(|error| error.to_string())
        } else {
            None
        };

        self.session_status = match connect_error {
            Some(error) => format!("Join request accepted, but VPN start failed: {error}"),
            None if should_connect_session => {
                if self.daemon_running {
                    "Join request accepted, applied, and VPN started.".to_string()
                } else {
                    "Join request accepted and VPN started.".to_string()
                }
            }
            None if self.daemon_running => "Join request accepted and applied.".to_string(),
            None => "Join request accepted.".to_string(),
        };

        Ok(())
    }

    pub(crate) fn add_relay(&mut self, relay: &str) -> Result<()> {
        let relay = relay.trim();
        if relay.is_empty() {
            return Err(anyhow!("relay URL is empty"));
        }

        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(anyhow!("relay URL must start with ws:// or wss://"));
        }

        if self
            .config
            .nostr
            .relays
            .iter()
            .any(|existing| existing == relay)
        {
            return Ok(());
        }

        self.config.nostr.relays.push(relay.to_string());
        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, false, true, false)?;

        Ok(())
    }

    pub(crate) fn remove_relay(&mut self, relay: &str) -> Result<()> {
        if self.config.nostr.relays.len() <= 1 {
            return Err(anyhow!("at least one relay is required"));
        }

        let previous_len = self.config.nostr.relays.len();
        self.config.nostr.relays.retain(|value| value != relay);

        if self.config.nostr.relays.len() == previous_len {
            return Ok(());
        }

        let persist_outcome = self.persist_config_with_defaults()?;
        self.finish_config_mutation(persist_outcome, false, true, false)?;

        Ok(())
    }

    pub(crate) fn update_settings(&mut self, patch: SettingsPatch) -> Result<()> {
        let mut restart_required = false;

        if let Some(node_name) = patch.node_name {
            self.config.node_name = node_name;
            restart_required = true;
        }

        if let Some(endpoint) = patch.endpoint {
            self.config.node.endpoint = endpoint;
            restart_required = true;
        }

        if let Some(tunnel_ip) = patch.tunnel_ip {
            self.config.node.tunnel_ip = tunnel_ip;
            restart_required = true;
        }

        if let Some(listen_port) = patch.listen_port {
            if listen_port == 0 {
                return Err(anyhow!("listen port must be > 0"));
            }
            self.config.node.listen_port = listen_port;
            restart_required = true;
        }

        if let Some(exit_node) = patch.exit_node {
            self.config.exit_node = parse_exit_node_input(&exit_node)?;
            restart_required = true;
        }

        if let Some(advertise_exit_node) = patch.advertise_exit_node {
            self.config.node.advertise_exit_node = advertise_exit_node;
            restart_required = true;
        }

        if let Some(advertised_routes) = patch.advertised_routes {
            self.config.node.advertised_routes = parse_advertised_routes_input(&advertised_routes)?;
            restart_required = true;
        }

        if let Some(use_public_relay_fallback) = patch.use_public_relay_fallback {
            self.config.use_public_relay_fallback = use_public_relay_fallback;
            restart_required = true;
        }

        if let Some(relay_for_others) = patch.relay_for_others {
            self.config.relay_for_others = relay_for_others;
            restart_required = true;
        }

        if let Some(provide_nat_assist) = patch.provide_nat_assist {
            self.config.provide_nat_assist = provide_nat_assist;
            restart_required = true;
        }

        if let Some(magic_dns_suffix) = patch.magic_dns_suffix {
            self.config.magic_dns_suffix = magic_dns_suffix;
            restart_required = true;
        }

        if let Some(autoconnect) = patch.autoconnect {
            self.config.autoconnect = autoconnect;
        }

        if let Some(launch_on_startup) = patch.launch_on_startup {
            self.config.launch_on_startup = launch_on_startup;
        }

        if let Some(close_to_tray_on_close) = patch.close_to_tray_on_close {
            self.config.close_to_tray_on_close = close_to_tray_on_close;
        }

        let persist_outcome = self.persist_config_with_defaults()?;

        if restart_required && persist_outcome.needs_explicit_daemon_reload() {
            self.reload_daemon_if_running()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    pub(crate) fn set_participant_alias(&mut self, npub: &str, alias: &str) -> Result<()> {
        self.ensure_participant_admin(npub)?;
        self.config.set_peer_alias(npub, alias)?;
        let persist_outcome = self.persist_config()?;
        if persist_outcome.needs_explicit_daemon_reload() {
            self.reload_daemon_if_running()?;
        }
        self.sync_daemon_state();
        Ok(())
    }
}
