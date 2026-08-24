impl NativeAppRuntime {
    #[cfg(test)]
    fn new(data_dir: &str, app_version: String) -> Result<Self> {
        let config_path = native_config_path(data_dir);
        Self::new_with_config_path(config_path, app_version, None)
    }

    fn new_with_config_path(
        config_path: PathBuf,
        app_version: String,
        nvpn_bin: Option<PathBuf>,
    ) -> Result<Self> {
        let config_exists = config_path
            .try_exists()
            .with_context(|| format!("failed to inspect config {}", config_path.display()))?;
        let migrated_config_secrets = config_exists
            && AppConfig::migrate_persisted_secrets(&config_path).with_context(|| {
                format!(
                    "failed to migrate persisted config secrets in {}",
                    config_path.display()
                )
            })?;
        let persist_identity_defaults =
            config_exists && config_file_needs_identity_defaults(&config_path)?;
        let mut config = if config_exists {
            AppConfig::load(&config_path)?
        } else {
            AppConfig::generated_without_networks()
        };
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        let capabilities = current_runtime_capabilities();
        let pending_join_request_changed = if capabilities.mobile {
            config.ensure_pending_nostr_join_request(unix_timestamp())?
        } else {
            false
        };
        if !config_exists
            || migrated_config_secrets
            || persist_identity_defaults
            || pending_join_request_changed
        {
            config.save(&config_path)?;
        }

        let exchange_rate_service =
            ExchangeRateService::for_currency(config.wallet_fiat_currency);
        let join_request_qr_code_or_link = if capabilities.mobile {
            own_join_request_qr_code_or_link(&config).unwrap_or_default()
        } else {
            String::new()
        };
        #[cfg(all(feature = "paid-exit", any(target_os = "ios", target_os = "android")))]
        let cashu_wallet_runtime = Some(paid_exit::PaidRouteWalletRuntime::open(&config_path)?);
        let mut runtime = Self {
            rev: 0,
            app_version,
            config_path,
            config,
            nvpn_bin: nvpn_bin.or_else(|| resolve_nvpn_cli_path().ok()),
            mobile_runtime: capabilities.mobile,
            startup_error: None,
            last_error: String::new(),
            daemon_running: false,
            vpn_enabled: false,
            vpn_active: false,
            vpn_status: "Disconnected".to_string(),
            join_request_qr_code_or_link,
            daemon_state: None,
            service_supported: !capabilities.mobile && desktop_service_supported(),
            service_enablement_supported: !capabilities.mobile && desktop_service_supported(),
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: String::new(),
            service_binary_version: String::new(),
            expected_service_binary_version: String::new(),
            daemon_status_grace_until: Some(Instant::now() + DAEMON_STARTUP_STATUS_GRACE),
            last_service_status_refresh_at: None,
            paid_route_market_filter: NativePaidRouteMarketFilterState::default(),
            paid_route_wallet_last_action: NativePaidRouteWalletActionState::default(),
            #[cfg(feature = "paid-exit")]
            paid_route_wallet_next_refresh_at: None,
            #[cfg(all(feature = "paid-exit", any(target_os = "ios", target_os = "android")))]
            cashu_wallet_runtime,
            paid_route_payment_last_action: NativePaidRoutePaymentActionState::default(),
            exchange_rate_service,
            #[cfg(test)]
            queued_join_rosters: Vec::new(),
            #[cfg(target_os = "macos")]
            privileged_command_runner: None,
        };
        runtime.refresh_expected_service_binary_version();
        if runtime.mobile_runtime {
            let _ = runtime.refresh_mobile_status();
        } else {
            let _ = runtime.refresh_status();
        }
        Ok(runtime)
    }

    fn from_startup_error(error: &anyhow::Error) -> Self {
        let error = error.to_string();
        #[cfg(not(test))]
        let config = AppConfig::generated_without_networks();
        #[cfg(test)]
        let mut config = AppConfig::generated_without_networks();
        #[cfg(test)]
        {
            config.node.endpoint = "198.51.100.10:51820".to_string();
            let _ = config.ensure_pending_nostr_join_request(unix_timestamp());
        }
        let exchange_rate_service =
            ExchangeRateService::for_currency(config.wallet_fiat_currency);
        let join_request_qr_code_or_link =
            own_join_request_qr_code_or_link(&config).unwrap_or_default();
        Self {
            rev: 0,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            config_path: default_config_path(),
            config,
            nvpn_bin: resolve_nvpn_cli_path().ok(),
            mobile_runtime: current_runtime_capabilities().mobile,
            startup_error: Some(error.clone()),
            last_error: error,
            daemon_running: false,
            vpn_enabled: false,
            vpn_active: false,
            vpn_status: "Startup failed".to_string(),
            join_request_qr_code_or_link,
            daemon_state: None,
            service_supported: desktop_service_supported(),
            service_enablement_supported: desktop_service_supported(),
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: "Service status unavailable during startup failure".to_string(),
            service_binary_version: String::new(),
            expected_service_binary_version: String::new(),
            daemon_status_grace_until: Some(Instant::now() + DAEMON_STARTUP_STATUS_GRACE),
            last_service_status_refresh_at: None,
            paid_route_market_filter: NativePaidRouteMarketFilterState::default(),
            paid_route_wallet_last_action: NativePaidRouteWalletActionState::default(),
            #[cfg(feature = "paid-exit")]
            paid_route_wallet_next_refresh_at: None,
            #[cfg(all(feature = "paid-exit", any(target_os = "ios", target_os = "android")))]
            cashu_wallet_runtime: None,
            paid_route_payment_last_action: NativePaidRoutePaymentActionState::default(),
            exchange_rate_service,
            #[cfg(test)]
            queued_join_rosters: Vec::new(),
            #[cfg(target_os = "macos")]
            privileged_command_runner: None,
        }
    }

    fn from_startup_error_for_config(
        error: &anyhow::Error,
        config_path: PathBuf,
        app_version: String,
    ) -> Self {
        let mut runtime = Self::from_startup_error(error);
        runtime.config_path = config_path;
        runtime.app_version = app_version;
        runtime
    }

    fn current_join_request_link(&self) -> String {
        if self.mobile_runtime {
            own_join_request_qr_code_or_link(&self.config).unwrap_or_default()
        } else {
            self.join_request_qr_code_or_link.clone()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn state(&self) -> NativeAppState {
        let capabilities = current_runtime_capabilities();
        let config_unavailable = self.startup_error.is_some();
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().unwrap_or_default();
        let active_network = self.config.active_network_opt();
        let network_setup_required =
            !config_unavailable && network_setup_required_for_config(&self.config);
        let daemon_state = self.daemon_state.as_ref();
        let vpn_enabled = self
            .daemon_state
            .as_ref()
            .map_or(self.vpn_enabled, |state| state.vpn_enabled);
        let vpn_active = self
            .daemon_state
            .as_ref()
            .map_or(self.vpn_active, |state| state.vpn_active);
        let expected_peer_count = if network_setup_required {
            0
        } else {
            daemon_state.map_or_else(
                || {
                    active_network.map_or(0, |network| {
                        remote_network_participant_count(network, &own_pubkey_hex)
                    })
                },
                |state| state.expected_peer_count,
            )
        };
        let connected_peer_count = if vpn_active && !network_setup_required {
            daemon_state.map_or(0, |state| state.connected_peer_count)
        } else {
            0
        };
        let endpoint = daemon_state
            .and_then(|state| non_empty(&state.advertised_endpoint))
            .unwrap_or_else(|| self.config.node.endpoint.clone());
        let listen_port = daemon_state
            .and_then(|state| (state.listen_port > 0).then_some(state.listen_port))
            .unwrap_or(self.config.node.listen_port);
        let health = daemon_state
            .map(|state| native_health_issues(&state.health))
            .unwrap_or_default();
        let network = daemon_state
            .map(|state| native_network_summary(&state.network))
            .unwrap_or_default();
        let port_mapping = daemon_state
            .map(|state| native_port_mapping_status(&state.port_mapping))
            .unwrap_or_default();
        let exit_node_status = if network_setup_required {
            ExitNodeUiStatus::default()
        } else {
            active_network
                .map(|network| {
                    self.exit_node_ui_status(vpn_enabled, vpn_active, daemon_state, network)
                })
                .unwrap_or_default()
        };
        let networks = if config_unavailable {
            Vec::new()
        } else {
            self.network_states(&own_pubkey_hex, vpn_active)
        };
        let fips_peer_stats = active_network_fips_peer_stats(&networks, &own_pubkey_hex);
        let other_fips_peer_count =
            daemon_state.map_or(0, |state| state.fips_other_peer_count as u64);
        let daemon_binary_version = daemon_state
            .map(|state| state.binary_version.clone())
            .unwrap_or_default();
        let service_binary_version =
            if self.service_binary_version.is_empty() && self.service_running {
                daemon_binary_version.clone()
            } else {
                self.service_binary_version.clone()
            };
        let config_for_paid = (!config_unavailable).then_some(&self.config);
        let raw_port_mapping = daemon_state.map(|state| &state.port_mapping);
        if !config_unavailable && self.config.wallet_fiat_enabled {
            let _ = self.exchange_rate_service.refresh_if_due();
        }
        let mut paid_route_market = self.paid_route_market_state(config_for_paid);
        if !config_unavailable && self.config.wallet_fiat_enabled {
            apply_exchange_rate(
                &mut paid_route_market.wallet,
                &self.exchange_rate_service.snapshot(),
            );
        }

        NativeAppState {
            rev: self.rev,
            platform: capabilities.platform,
            mobile: capabilities.mobile,
            vpn_control_supported: capabilities.vpn_control_supported,
            cli_install_supported: capabilities.cli_install_supported,
            startup_settings_supported: capabilities.startup_settings_supported,
            tray_behavior_supported: capabilities.tray_behavior_supported,
            runtime_status_detail: capabilities.runtime_status_detail,
            app_version: if self.app_version.is_empty() {
                env!("CARGO_PKG_VERSION").to_string()
            } else {
                self.app_version.clone()
            },
            config_path: self.config_path.display().to_string(),
            error: self
                .startup_error
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| self.last_error.clone()),
            cli_installed: capabilities.cli_install_supported && cli_binary_installed(),
            service_supported: self.service_supported,
            service_enablement_supported: self.service_enablement_supported,
            service_installed: self.service_installed,
            service_disabled: self.service_disabled,
            service_running: self.service_running,
            service_status_detail: self.service_status_detail.clone(),
            daemon_running: self.daemon_running,
            vpn_enabled,
            vpn_active,
            vpn_status: self.vpn_status.clone(),
            daemon_binary_version,
            service_binary_version,
            expected_service_binary_version: self.expected_service_binary_version.clone(),
            own_npub: if config_unavailable {
                String::new()
            } else {
                npub_for_pubkey_hex(&own_pubkey_hex)
            },
            own_pubkey_hex: if config_unavailable {
                String::new()
            } else {
                own_pubkey_hex
            },
            node_id: if config_unavailable {
                String::new()
            } else {
                self.config.node.id.clone()
            },
            node_name: if config_unavailable {
                String::new()
            } else {
                self.config.node_name.clone()
            },
            self_magic_dns_name: if config_unavailable {
                String::new()
            } else {
                self.self_magic_dns_name_for_display()
            },
            endpoint: if config_unavailable {
                String::new()
            } else {
                endpoint
            },
            tunnel_ip: if config_unavailable {
                String::new()
            } else {
                self.config.node.tunnel_ip.clone()
            },
            listen_port: if config_unavailable {
                0
            } else {
                u32::from(listen_port)
            },
            relays: if config_unavailable {
                Vec::new()
            } else {
                self.relay_views()
            },
            nostr_pubsub_mode: if config_unavailable {
                "off".to_string()
            } else {
                self.config.nostr.pubsub.mode.as_str().to_string()
            },
            nostr_pubsub_fanout: if config_unavailable {
                0
            } else {
                usize_to_u32_saturating(self.config.nostr.pubsub.fanout)
            },
            nostr_pubsub_max_hops: if config_unavailable {
                0
            } else {
                self.config.nostr.pubsub.max_hops
            },
            nostr_pubsub_max_event_bytes: if config_unavailable {
                0
            } else {
                usize_to_u32_saturating(self.config.nostr.pubsub.max_event_bytes)
            },
            network_id: if config_unavailable || network_setup_required {
                String::new()
            } else {
                self.config.effective_network_id()
            },
            join_request_qr_code_or_link: if config_unavailable {
                String::new()
            } else {
                self.current_join_request_link()
            },
            internet_source: if config_unavailable {
                String::new()
            } else {
                self.config.internet_source.as_str().to_string()
            },
            exit_node: if self.config.exit_node.trim().is_empty() {
                String::new()
            } else {
                npub_for_pubkey_hex(&self.config.exit_node)
            },
            exit_node_leak_protection: self.config.exit_node_leak_protection,
            exit_node_active: exit_node_status.active,
            exit_node_blocked: exit_node_status.blocked,
            exit_node_status_text: exit_node_status.text,
            exit_dns_mode: self.config.exit_dns.mode.as_str().to_string(),
            exit_dns_doh_provider: self.config.exit_dns.doh_provider.as_str().to_string(),
            exit_dns_custom_doh_url: self.config.exit_dns.custom_doh_url.clone(),
            exit_dns_custom_doh_bootstrap_ips: self
                .config
                .exit_dns
                .custom_doh_bootstrap_ips
                .join(", "),
            exit_dns_through_exit_servers: self
                .config
                .exit_dns
                .through_exit_servers
                .join(", "),
            advertise_exit_node: !config_unavailable && self.config.node.advertise_exit_node,
            advertised_routes: if config_unavailable {
                Vec::new()
            } else {
                self.config.node.advertised_routes.clone()
            },
            effective_advertised_routes: if config_unavailable {
                Vec::new()
            } else {
                self.config.effective_advertised_routes()
            },
            wireguard_exit_enabled: !config_unavailable
                && self.config.internet_source == InternetSource::WireGuard,
            wireguard_exit_configured: !config_unavailable
                && self.config.wireguard_exit.configured(),
            wireguard_exit_interface: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.interface.clone()
            },
            wireguard_exit_address: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.address.clone()
            },
            wireguard_exit_private_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.private_key.clone()
            },
            wireguard_exit_peer_public_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.peer_public_key.clone()
            },
            wireguard_exit_peer_preshared_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.peer_preshared_key.clone()
            },
            wireguard_exit_endpoint: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.endpoint.clone()
            },
            wireguard_exit_allowed_ips: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.allowed_ips.join(", ")
            },
            wireguard_exit_dns: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.dns.join(", ")
            },
            wireguard_exit_mtu: if config_unavailable {
                0
            } else {
                self.config.wireguard_exit.mtu
            },
            wireguard_exit_persistent_keepalive_secs: if config_unavailable {
                0
            } else {
                self.config.wireguard_exit.persistent_keepalive_secs
            },
            wireguard_exit_config: if config_unavailable {
                String::new()
            } else {
                wireguard_exit_config_text(&self.config.wireguard_exit)
            },
            wallet_fiat_enabled: !config_unavailable && self.config.wallet_fiat_enabled,
            wallet_fiat_currency: if config_unavailable {
                String::new()
            } else {
                self.config.wallet_fiat_currency.as_str().to_string()
            },
            paid_exit_seller: self.paid_exit_seller_state(
                config_for_paid,
                raw_port_mapping,
                capabilities.mobile,
            ),
            paid_route_market,
            fips_host_tunnel_enabled: !config_unavailable && self.config.fips_host_tunnel_enabled,
            connect_to_non_roster_fips_peers: !config_unavailable
                && self.config.connect_to_non_roster_fips_peers,
            fips_nostr_discovery_enabled: !config_unavailable
                && self.config.fips_nostr_discovery_enabled,
            fips_webrtc_enabled: !config_unavailable && self.config.fips_webrtc_enabled,
            fips_bootstrap_enabled: !config_unavailable && self.config.fips_bootstrap_enabled,
            fips_bootstrap_peers: if config_unavailable {
                std::collections::HashMap::new()
            } else {
                self.config.fips_bootstrap_peers.clone()
            },
            fips_bootstrap_peer_defaults: nostr_vpn_core::config::default_fips_bootstrap_peers(),
            fips_host_inbound_tcp_ports: if config_unavailable {
                String::new()
            } else {
                self.config
                    .fips_host_inbound_tcp_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            magic_dns_suffix: if config_unavailable {
                String::new()
            } else {
                self.config.magic_dns_suffix.clone()
            },
            magic_dns_status: if config_unavailable {
                String::new()
            } else {
                self.magic_dns_status()
            },
            autoconnect: !config_unavailable && self.config.autoconnect,
            launch_on_startup: !config_unavailable && self.config.launch_on_startup,
            close_to_tray_on_close: !config_unavailable && self.config.close_to_tray_on_close,
            connected_peer_count: connected_peer_count as u64,
            expected_peer_count: expected_peer_count as u64,
            fips_connected_peer_count: fips_peer_stats.direct_roster_peer_count,
            fips_roster_peer_count: fips_peer_stats.roster_peer_count,
            // Legacy wire field name: UIs now use this as connected non-roster FIPS peers.
            non_fips_roster_peer_count: other_fips_peer_count,
            mesh_ready: !network_setup_required
                && vpn_active
                && daemon_state.is_some_and(|state| state.mesh_ready),
            health,
            network,
            port_mapping,
            networks,
        }
    }

}

fn config_file_needs_identity_defaults(path: &Path) -> Result<bool> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw).context("failed to parse config TOML")?;
    let Some(nostr) = value.get("nostr").and_then(toml::Value::as_table) else {
        return Ok(true);
    };

    let has_secret = nostr
        .get("secret_key")
        .and_then(toml::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    let has_public_key = nostr
        .get("public_key")
        .and_then(toml::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    Ok(!has_secret || !has_public_key)
}

fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
