fn action_error_text(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

impl NativeAppRuntime {
    fn dispatch(&mut self, action: NativeAppAction) {
        let result = self.apply_action(action);
        match result {
            Ok(()) => self.last_error.clear(),
            Err(error) => self.set_error(action_error_text(&error)),
        }
        self.rev = self.rev.saturating_add(1);
    }

    #[allow(clippy::too_many_lines)]
    fn apply_action(&mut self, action: NativeAppAction) -> Result<()> {
        if self.startup_error.is_some() {
            match &action {
                NativeAppAction::GetState => return Ok(()),
                NativeAppAction::InstallCli
                | NativeAppAction::UninstallCli
                | NativeAppAction::InstallSystemService => {}
                _ => self.recover_from_startup_error().with_context(
                    || "cannot modify VPN config until the config file is readable",
                )?,
            }
        }

        match action {
            NativeAppAction::GetState | NativeAppAction::Tick => {
                #[cfg(feature = "paid-exit")]
                self.refresh_pending_paid_route_wallet();
                if self.mobile_runtime {
                    self.refresh_mobile_status()?;
                } else {
                    self.refresh_status()?;
                }
                #[cfg(feature = "paid-exit")]
                if !self.config.manual_paid_exit_provider.is_default()
                    && self.config.internet_source != InternetSource::PaidManual
                {
                    self.import_manual_paid_exit_provider_offer(0)?;
                    self.buy_manual_paid_exit_provider_if_available()?;
                }
                Ok(())
            }
            NativeAppAction::ConnectVpn => self.connect_vpn(),
            NativeAppAction::DisconnectVpn => self.disconnect_vpn(),
            NativeAppAction::InstallCli => {
                let output = self.run_nvpn(["install-cli", "--force"])?;
                ensure_success("nvpn install-cli", &output)
            }
            NativeAppAction::UninstallCli => {
                let output = self.run_nvpn(["uninstall-cli"])?;
                ensure_success("nvpn uninstall-cli", &output)
            }
            NativeAppAction::InstallSystemService => {
                // Preserve "VPN was on" across the service swap: --force tears
                // down the old daemon and starts a fresh one, which by default
                // comes up disconnected. Without restoring, the user sees the
                // VPN switch flip to OFF every time they update the service —
                // doubly bad after an in-app update where they didn't ask to
                // disconnect.
                let was_vpn_on = self.vpn_enabled || self.vpn_active;
                let output = self.run_nvpn_service_action([
                    "service",
                    "install",
                    "--force",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service install", &output)?;
                self.invalidate_service_status();
                self.recover_from_startup_error()?;
                self.refresh_service_status()?;
                self.arm_daemon_status_grace();
                // Refresh the daemon state after the service swap before
                // deciding whether to reconnect. Otherwise stale pre-bootout
                // `vpn_active` can make us skip the restore and the next UI
                // tick flips the VPN switch off.
                let _ = self.refresh_status();
                if was_vpn_on && !(self.vpn_enabled || self.vpn_active) {
                    // Best-effort: ignore connect_vpn errors so a transient
                    // race (new daemon not quite ready yet) doesn't surface
                    // as a "service install failed" message — the install
                    // itself succeeded.
                    let _ = self.connect_vpn();
                }
                Ok(())
            }
            NativeAppAction::UninstallSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "uninstall",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service uninstall", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()
            }
            NativeAppAction::EnableSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "enable",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service enable", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()?;
                self.arm_daemon_status_grace();
                Ok(())
            }
            NativeAppAction::DisableSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "disable",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service disable", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()
            }
            NativeAppAction::AddNetwork { name } => {
                let network_id = self.config.add_owned_network(&name);
                self.config.set_network_enabled(&network_id, true)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::RenameNetwork { network_id, name } => {
                self.config.rename_network(&network_id, &name)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::RemoveNetwork { network_id } => {
                self.config.remove_network(&network_id)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkMeshId {
                network_id,
                mesh_id,
            } => {
                self.config.set_network_mesh_id(&network_id, &mesh_id)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkEnabled {
                network_id,
                enabled,
            } => {
                self.config.set_network_enabled(&network_id, enabled)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkJoinRequestsEnabled {
                network_id,
                enabled,
            } => {
                self.config
                    .set_network_join_requests_enabled(&network_id, enabled)?;
                self.save_reload_refresh_and_maybe_connect_for_join_requests(enabled)
            }
            NativeAppAction::AddParticipant {
                network_id,
                npub,
                alias,
            } => {
                let was_participant = normalize_nostr_pubkey(&npub).is_ok_and(|candidate| {
                    self.config.network_by_id(&network_id).is_some_and(|network| {
                        network
                            .devices
                            .iter()
                            .chain(network.admins.iter())
                            .any(|participant| participant == &candidate)
                    })
                });
                let normalized = self.config.add_participant_to_network(&network_id, &npub)?;
                if let Some(alias) = alias
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    self.config.set_peer_alias(&normalized, alias)?;
                }
                if !was_participant {
                    let delivery =
                        prepare_manual_join_delivery(&self.config, &network_id, &normalized)?;
                    self.queue_join_roster_delivery_to(&normalized, &delivery)?;
                }
                let should_start_networking = !was_participant && !self.vpn_enabled;
                if should_start_networking {
                    self.config.autoconnect = true;
                }
                self.save_reload_and_refresh()?;
                if should_start_networking && !self.vpn_enabled {
                    self.connect_vpn()?;
                }
                Ok(())
            }
            NativeAppAction::AddAdmin { network_id, npub } => {
                self.config.add_admin_to_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::ImportJoinRequest { request } => self.import_join_request(&request),
            NativeAppAction::ManualAddNetwork {
                admin_npub,
                mesh_network_id,
            } => {
                self.manual_add_network(&admin_npub, &mesh_network_id)?;
                if !self.vpn_enabled {
                    self.connect_vpn()?;
                }
                Ok(())
            }
            NativeAppAction::RemoveParticipant { network_id, npub } => {
                self.config
                    .remove_participant_from_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::RemoveAdmin { network_id, npub } => {
                self.config.remove_admin_from_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::AcceptJoinRequest {
                network_id,
                requester_npub,
            } => self.accept_join_request(&network_id, &requester_npub),
            NativeAppAction::RejectJoinRequest {
                network_id,
                requester_npub,
            } => {
                self.config
                    .reject_inbound_join_request(&network_id, &requester_npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetParticipantAlias { npub, alias } => {
                self.config.set_peer_alias(&npub, &alias)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetParticipantEndpointHints {
                npub,
                endpoint_hints,
            } => {
                self.config
                    .set_fips_peer_endpoint_hints(&npub, &endpoint_hints)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetPaidRouteMarketFilter {
                query,
                country_code,
                mint_url,
                require_ipv4,
                require_ipv6,
                sort,
            } => {
                self.paid_route_market_filter = NativePaidRouteMarketFilterState {
                    query: query.trim().to_string(),
                    country_code: normalize_paid_route_country_code(&country_code),
                    mint_url: mint_url.trim().to_string(),
                    require_ipv4,
                    require_ipv6,
                    sort: if sort.trim().is_empty() {
                        "quality".to_string()
                    } else {
                        sort.trim().to_ascii_lowercase()
                    },
                };
                Ok(())
            }
            NativeAppAction::AddPaidRouteWalletMint { url, label } => {
                self.add_paid_route_wallet_mint(&url, label.as_deref())
            }
            NativeAppAction::RemovePaidRouteWalletMint { url } => {
                self.remove_paid_route_wallet_mint(&url)
            }
            NativeAppAction::SetPaidRouteDefaultMint { url } => {
                self.set_paid_route_default_mint(&url)
            }
            NativeAppAction::RefreshPaidRouteWallet { refresh } => {
                self.refresh_paid_route_wallet(refresh)
            }
            NativeAppAction::TopUpPaidRouteWallet {
                mint_url,
                amount_sat,
            } => self.top_up_paid_route_wallet(mint_url.as_deref(), amount_sat),
            NativeAppAction::ReceivePaidRouteWalletToken { token } => {
                self.receive_paid_route_wallet_token(&token)
            }
            NativeAppAction::PreviewPaidRouteWalletToken { token } => {
                self.preview_paid_route_wallet_token(&token)
            }
            NativeAppAction::SendPaidRouteWalletToken {
                mint_url,
                amount_sat,
            } => self.send_paid_route_wallet_token(mint_url.as_deref(), amount_sat),
            NativeAppAction::WithdrawPaidRouteWalletLightning { mint_url, invoice } => {
                self.withdraw_paid_route_wallet_lightning(mint_url.as_deref(), &invoice)
            }
            NativeAppAction::BuyPaidRouteOffer {
                offer_key,
                mint_url,
                channel_capacity_sat,
            } => self.buy_paid_route_offer(&offer_key, mint_url.as_deref(), channel_capacity_sat),
            NativeAppAction::BuyBestPaidRouteOffer {
                mint_url,
                channel_capacity_sat,
            } => self.buy_best_paid_route_offer(mint_url.as_deref(), channel_capacity_sat),
            NativeAppAction::SetManualPaidExitProvider { provider } => {
                let mut config = self.config.clone();
                config.set_manual_paid_exit_provider(&provider)?;
                #[cfg(feature = "paid-exit")]
                if !config.manual_paid_exit_provider.mint.is_empty() {
                    self.add_paid_route_wallet_mint(
                        &config.manual_paid_exit_provider.mint,
                        None,
                    )?;
                }
                self.config = config;
                self.save_reload_and_refresh()?;
                #[cfg(feature = "paid-exit")]
                {
                    if !self.vpn_enabled {
                        self.connect_vpn()?;
                    }
                    self.import_manual_paid_exit_provider_offer(0)?;
                    if !self.buy_manual_paid_exit_provider_if_available()? {
                        self.import_manual_paid_exit_provider_offer(5)?;
                        self.buy_manual_paid_exit_provider_if_available()?;
                    }
                }
                Ok(())
            }
            NativeAppAction::ClearManualPaidExitProvider => {
                self.config.clear_manual_paid_exit_provider();
                self.save_reload_and_refresh()
            }
            NativeAppAction::SelectPaidRouteSession {
                session_id,
                connect,
            } => self.select_paid_route_session(&session_id, connect),
            NativeAppAction::ProbePaidRouteSession {
                session_id,
                timeout_secs,
            } => self.probe_paid_route_session(&session_id, timeout_secs),
            NativeAppAction::RecordPaidRouteProbe {
                session_id,
                realized_exit_ip,
                observed_country_code,
                observed_asn,
                latency_ms,
                jitter_ms,
                packet_loss_ppm,
                down_bps,
                up_bps,
                uptime_secs,
                last_seen_unix,
            } => self.record_paid_route_probe(
                &session_id,
                realized_exit_ip.as_deref(),
                observed_country_code.as_deref(),
                observed_asn,
                latency_ms,
                jitter_ms,
                packet_loss_ppm,
                down_bps,
                up_bps,
                uptime_secs,
                last_seen_unix,
            ),
            NativeAppAction::CreatePaidRoutePaymentEnvelope {
                session_id,
                kind,
                payment_json,
                delivered_units,
                paid_msat,
            } => self.create_paid_route_payment_envelope(
                &session_id,
                &kind,
                &payment_json,
                delivered_units,
                paid_msat,
            ),
            NativeAppAction::OpenPaidRouteChannelFromWallet {
                session_id,
                mint_url,
                paid_msat,
                max_amount_per_output,
                keyset_id,
            } => self.open_paid_route_channel_from_wallet(
                &session_id,
                mint_url.as_deref(),
                paid_msat,
                max_amount_per_output,
                keyset_id.as_deref(),
            ),
            NativeAppAction::SignPaidRoutePaymentEnvelopeFromWallet {
                session_id,
                kind,
                delivered_units,
                paid_msat,
            } => self.sign_paid_route_payment_envelope_from_wallet(
                &session_id,
                &kind,
                delivered_units,
                paid_msat,
            ),
            NativeAppAction::ClosePaidRouteChannelFromWallet {
                session_id,
                publish,
            } => self.close_paid_route_channel_from_wallet(&session_id, publish),
            NativeAppAction::ApplyPaidRoutePaymentEnvelope { envelope_json } => {
                self.apply_paid_route_payment_envelope(&envelope_json)
            }
            NativeAppAction::SendPaidRoutePaymentEnvelope { envelope_json } => {
                self.send_paid_route_payment_envelope(&envelope_json)
            }
            NativeAppAction::StreamPaidRoutePayments {
                publish,
                min_increment_msat,
                limit,
            } => self.stream_paid_route_payments(publish, min_increment_msat, limit),
            NativeAppAction::ReceivePaidRoutePayments { duration_secs } => {
                self.receive_paid_route_payments(duration_secs)
            }
            NativeAppAction::CollectPaidExitChannel { channel_id } => {
                self.collect_paid_exit_channel(&channel_id)
            }
            NativeAppAction::CollectDuePaidExitChannels => self.collect_due_paid_exit_channels(),
            NativeAppAction::PublishPaidExitOffer => self.publish_paid_exit_offer(),
            NativeAppAction::DiscoverPaidRouteOffers { duration_secs } => {
                self.discover_paid_route_offers(duration_secs)
            }
            NativeAppAction::UpdateSettings { patch } => {
                self.apply_settings_patch(patch)?;
                self.save_reload_and_refresh()
            }
        }
    }

    fn import_join_request(&mut self, request: &str) -> Result<()> {
        let parsed = parse_join_request_qr_code_or_link(request)?;
        self.import_parsed_join_request(&parsed.bootstrap)
    }

    fn manual_add_network(&mut self, admin_npub: &str, mesh_network_id: &str) -> Result<()> {
        // Manual join trusts the two identifiers exchanged out of band until
        // the admin's signed roster confirms this device as a member. The
        // locally generated join secret remains an internal config invariant
        // and is never presented as the admin network's secret.
        self.config
            .add_manual_join_network(admin_npub, mesh_network_id)?;
        self.save_reload_and_refresh()
    }

    fn import_parsed_join_request(
        &mut self,
        bootstrap: &nostr_vpn_core::identity_bridge::NostrIdentityDeviceApprovalBootstrap,
    ) -> Result<()> {
        let network_id = self.active_admin_network_id()?;
        let prepared =
            prepare_join_approval(&self.config, &network_id, bootstrap, unix_timestamp())?;
        self.config = prepared.updated_config;
        self.queue_join_roster_delivery(bootstrap, &prepared.join_roster)?;
        // Commit the durable outbox entry before asking the daemon to apply
        // the new roster. The daemon can then start delivery as part of that
        // same control transaction instead of waiting for its next heartbeat.
        self.save_reload_and_refresh()?;
        if self.config.autoconnect && !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::unnecessary_wraps)]
    fn queue_join_roster_delivery(
        &mut self,
        bootstrap: &nostr_vpn_core::identity_bridge::NostrIdentityDeviceApprovalBootstrap,
        join_roster: &nostr_vpn_core::fips_control::JoinRosterControl,
    ) -> Result<()> {
        self.queue_join_roster_delivery_to(&bootstrap.device_app_key_npub, join_roster)
    }

    #[cfg(test)]
    fn queue_join_roster_delivery_to(
        &mut self,
        recipient: &str,
        join_roster: &nostr_vpn_core::fips_control::JoinRosterControl,
    ) -> Result<()> {
        nostr_vpn_core::join_delivery::queue_join_roster(
            &self.config_path,
            recipient,
            join_roster,
        )?;
        self.queued_join_rosters.push(join_roster.clone());
        Ok(())
    }

    #[cfg(not(test))]
    fn queue_join_roster_delivery(
        &mut self,
        bootstrap: &nostr_vpn_core::identity_bridge::NostrIdentityDeviceApprovalBootstrap,
        join_roster: &nostr_vpn_core::fips_control::JoinRosterControl,
    ) -> Result<()> {
        self.queue_join_roster_delivery_to(&bootstrap.device_app_key_npub, join_roster)
    }

    #[cfg(not(test))]
    fn queue_join_roster_delivery_to(
        &mut self,
        recipient: &str,
        join_roster: &nostr_vpn_core::fips_control::JoinRosterControl,
    ) -> Result<()> {
        nostr_vpn_core::join_delivery::queue_join_roster(
            &self.config_path,
            recipient,
            join_roster,
        )?;
        Ok(())
    }

    fn active_admin_network_id(&self) -> Result<String> {
        let own_pubkey = self.config.own_nostr_pubkey_hex().ok();
        self.config
            .networks
            .iter()
            .find(|network| {
                network.enabled
                    && own_pubkey.as_deref().is_some_and(|own_pubkey| {
                        network.admins.iter().any(|admin| admin == own_pubkey)
                    })
            })
            .map(|network| network.id.clone())
            .ok_or_else(|| anyhow!("active network is not administered by this device"))
    }

    fn add_join_requester_to_network(
        &mut self,
        network_id: &str,
        requester: &str,
        requester_node_name: &str,
    ) -> Result<()> {
        let requester = normalize_nostr_pubkey(requester)?;
        self.config
            .add_participant_to_network(network_id, &requester)?;
        let requester_node_name = requester_node_name.trim();
        if !requester_node_name.is_empty() {
            let _ = self.config.set_peer_alias(&requester, requester_node_name);
        }
        if let Some(network) = self.config.network_by_id_mut(network_id) {
            network
                .inbound_join_requests
                .retain(|pending| pending.requester != requester);
        }
        self.save_reload_and_refresh()?;
        if !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

    fn accept_join_request(&mut self, network_id: &str, requester_npub: &str) -> Result<()> {
        let requester = normalize_nostr_pubkey(requester_npub)?;
        let network = self
            .config
            .network_by_id(network_id)
            .ok_or_else(|| anyhow!("network not found"))?;
        let requester_node_name = network
            .inbound_join_requests
            .iter()
            .find(|pending| pending.requester == requester)
            .map(|pending| pending.requester_node_name.clone())
            .ok_or_else(|| anyhow!("no pending join request from {requester_npub}"))?;

        self.add_join_requester_to_network(network_id, &requester, &requester_node_name)
    }

}
