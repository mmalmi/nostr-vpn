impl NativeAppRuntime {
    fn network_states(&self, own_pubkey_hex: &str, vpn_active: bool) -> Vec<NativeNetworkState> {
        self.config
            .networks
            .iter()
            .map(|network| self.network_state(network, own_pubkey_hex, vpn_active))
            .collect()
    }

    fn exit_node_ui_status(
        &self,
        vpn_enabled: bool,
        vpn_active: bool,
        daemon_state: Option<&DaemonRuntimeState>,
        active_network: &NetworkConfig,
    ) -> ExitNodeUiStatus {
        let selected_exit_node = self.config.exit_node.trim();
        if !selected_exit_node.is_empty() {
            let source = match self.config.internet_source {
                InternetSource::PaidAutomatic => "Automatic paid exit",
                InternetSource::PaidManual => "Manual paid exit",
                InternetSource::WireGuard => "WireGuard exit",
                InternetSource::Direct | InternetSource::PrivateVpn => "Private exit",
            };
            let name = exit_node_display_name(&self.config, active_network, selected_exit_node);
            let selected_peer = daemon_state.and_then(|state| {
                state
                    .peers
                    .iter()
                    .find(|peer| peer.participant_pubkey == selected_exit_node)
            });
            let active_paid_exit_ip = matches!(
                self.config.internet_source,
                InternetSource::PaidAutomatic | InternetSource::PaidManual
            )
            .then(|| self.active_paid_route_exit_ip(selected_exit_node))
            .flatten();
            let selected_exit_active = vpn_active
                && if matches!(
                    self.config.internet_source,
                    InternetSource::PaidAutomatic | InternetSource::PaidManual
                ) {
                    // Public paid sellers are authenticated endpoint peers,
                    // not members of the user's private network roster. A
                    // fresh end-to-end probe is the readiness evidence.
                    active_paid_exit_ip.is_some()
                } else {
                    selected_peer.is_some_and(|peer| {
                        peer.reachable && peer_offers_exit_node(&peer.advertised_routes)
                    })
                };
            let blocked =
                self.config.exit_node_leak_protection && vpn_enabled && !selected_exit_active;
            let text = if blocked {
                format!("{source} · Blocked, waiting for {name}")
            } else if selected_exit_active {
                let realized_exit_ip = active_paid_exit_ip.unwrap_or_default();
                if realized_exit_ip.is_empty() {
                    format!("{source} · {name} · Connected")
                } else {
                    format!("{source} · {name} · {realized_exit_ip} · Connected")
                }
            } else {
                format!("{source} · {name} · Pending")
            };
            return ExitNodeUiStatus {
                active: selected_exit_active,
                blocked,
                text,
            };
        }

        let pending_source = match self.config.internet_source {
            InternetSource::PrivateVpn => Some("Private exit"),
            InternetSource::PaidAutomatic => Some("Automatic paid exit"),
            InternetSource::PaidManual => Some("Manual paid exit"),
            InternetSource::Direct | InternetSource::WireGuard => None,
        };
        if let Some(source) = pending_source {
            let blocked = self.config.exit_node_leak_protection && vpn_enabled;
            return ExitNodeUiStatus {
                active: false,
                blocked,
                text: if blocked {
                    format!("{source} · Blocked")
                } else {
                    format!("{source} · Pending")
                },
            };
        }

        let wireguard_exit_selected = self.config.internet_source == InternetSource::WireGuard;
        if wireguard_exit_selected {
            let wireguard_exit_active = vpn_active
                && self.config.wireguard_exit.configured()
                && daemon_state.is_some_and(|state| state.wireguard_exit_ready);
            let blocked =
                self.config.exit_node_leak_protection && vpn_enabled && !wireguard_exit_active;
            let text = if blocked {
                "WireGuard exit · Blocked".to_string()
            } else if wireguard_exit_active {
                "WireGuard exit · Connected".to_string()
            } else {
                "WireGuard exit · Pending".to_string()
            };
            return ExitNodeUiStatus {
                active: wireguard_exit_active,
                blocked,
                text,
            };
        }

        ExitNodeUiStatus {
            text: "Direct internet".to_string(),
            ..ExitNodeUiStatus::default()
        }
    }

    fn network_state(
        &self,
        network: &NetworkConfig,
        own_pubkey_hex: &str,
        vpn_active: bool,
    ) -> NativeNetworkState {
        let mut admins = network
            .admins
            .iter()
            .map(|admin| npub_for_pubkey_hex(admin))
            .collect::<Vec<_>>();
        admins.sort();
        admins.dedup();
        let mut participant_keys = network.devices.clone();
        participant_keys.extend(network.admins.iter().cloned());
        participant_keys.sort();
        participant_keys.dedup();
        if !own_pubkey_hex.is_empty()
            && !participant_keys.iter().any(|value| value == own_pubkey_hex)
        {
            participant_keys.push(own_pubkey_hex.to_string());
        }
        let participants = participant_keys
            .iter()
            .map(|participant| {
                self.participant_state(participant, network, own_pubkey_hex, vpn_active)
            })
            .collect::<Vec<_>>();
        let online_count = participants
            .iter()
            .filter(|participant| participant.reachable)
            .count() as u64;
        let expected_count = participants.len() as u64;
        let join_request_qr_code_or_link = self.current_join_request_link();

        NativeNetworkState {
            id: network.id.clone(),
            name: network.name.clone(),
            enabled: network.enabled,
            network_id: normalize_runtime_network_id(&network.network_id),
            local_is_admin: self.config.is_network_admin(&network.id, own_pubkey_hex),
            join_requests_enabled: network.listen_for_join_requests,
            join_request_admin_npub: if network.join_request_admin.is_empty() {
                String::new()
            } else {
                npub_for_pubkey_hex(&network.join_request_admin)
            },
            admin_npubs: admins.clone(),
            outbound_join_request: network
                .outbound_join_request
                .as_ref()
                .map(native_outbound_join_request),
            join_request_qr_code_or_link,
            inbound_join_requests: network
                .inbound_join_requests
                .iter()
                .map(native_inbound_join_request)
                .collect(),
            online_count,
            expected_count,
            admins,
            participants,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn participant_state(
        &self,
        participant: &str,
        network: &NetworkConfig,
        own_pubkey_hex: &str,
        vpn_active: bool,
    ) -> NativeParticipantState {
        let daemon_peer = vpn_active.then_some(()).and_then(|()| {
            self.daemon_state.as_ref().and_then(|state| {
                state
                    .peers
                    .iter()
                    .find(|peer| peer.participant_pubkey == participant)
            })
        });
        let is_local = participant == own_pubkey_hex;
        let roster_accepted = !self.network_access_pending(network, own_pubkey_hex);
        let reachable = vpn_active && (is_local || daemon_peer.is_some_and(|peer| peer.reachable));
        let access_pending = !roster_accepted && !is_local;
        let assigned_magic_dns_alias = self.config.peer_alias(participant).unwrap_or_default();
        let magic_dns_alias = if assigned_magic_dns_alias.is_empty() && is_local {
            self.config.self_magic_dns_label().unwrap_or_default()
        } else {
            assigned_magic_dns_alias
        };
        let assigned_magic_dns_name = self
            .config
            .magic_dns_name_for_participant(participant)
            .unwrap_or_default();
        let magic_dns_name = if assigned_magic_dns_name.is_empty() && is_local {
            self.self_magic_dns_name_for_display()
        } else {
            assigned_magic_dns_name
        };
        let alias = non_empty(&magic_dns_alias).unwrap_or_else(|| short_pubkey(participant));
        let tunnel_ip = daemon_peer
            .map(|peer| peer.tunnel_ip.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                derive_mesh_tunnel_ip(&network.network_id, participant)
                    .unwrap_or_else(|| "-".to_string())
            });
        let advertised_routes = if is_local {
            self.config.effective_advertised_routes()
        } else {
            daemon_peer
                .map(|peer| peer.advertised_routes.clone())
                .unwrap_or_default()
        };
        let offers_exit_node = if is_local {
            self.config.node.advertise_exit_node
        } else {
            peer_offers_exit_node(&advertised_routes)
        };
        let peer_state = if access_pending {
            "pending".to_string()
        } else {
            self.peer_state_label(participant, daemon_peer, is_local, vpn_active)
        };
        let mesh_state = Self::peer_mesh_label(daemon_peer, is_local, vpn_active);
        let status_text = if access_pending {
            if network
                .outbound_join_request
                .as_ref()
                .is_some_and(|request| request.recipient == participant)
            {
                "join request sent".to_string()
            } else {
                "waiting for admin".to_string()
            }
        } else {
            Self::peer_status_text(daemon_peer, is_local, &peer_state)
        };

        NativeParticipantState {
            npub: npub_for_pubkey_hex(participant),
            pubkey_hex: participant.to_string(),
            alias,
            magic_dns_alias,
            magic_dns_name,
            tunnel_ip,
            is_admin: network.admins.iter().any(|admin| admin == participant),
            roster_accepted,
            reachable,
            tx_bytes: daemon_peer.map_or(0, |peer| peer.tx_bytes),
            rx_bytes: daemon_peer.map_or(0, |peer| peer.rx_bytes),
            advertised_routes,
            offers_exit_node,
            fips_endpoint_npub: daemon_peer
                .map(|peer| peer.fips_endpoint_npub.clone())
                .unwrap_or_default(),
            fips_endpoint_hints: self.config.fips_peer_endpoint_hints(participant),
            fips_transport_addr: daemon_peer
                .map(|peer| peer.fips_transport_addr.clone())
                .unwrap_or_default(),
            fips_transport_type: daemon_peer
                .map(|peer| peer.fips_transport_type.clone())
                .unwrap_or_default(),
            fips_srtt_ms: daemon_peer.and_then(|peer| peer.fips_srtt_ms).unwrap_or(0),
            fips_srtt_age_ms: daemon_peer
                .and_then(|peer| peer.fips_srtt_age_ms)
                .unwrap_or(0),
            fips_packets_sent: daemon_peer.map_or(0, |peer| peer.fips_packets_sent),
            fips_packets_recv: daemon_peer.map_or(0, |peer| peer.fips_packets_recv),
            fips_bytes_sent: daemon_peer.map_or(0, |peer| peer.fips_bytes_sent),
            fips_bytes_recv: daemon_peer.map_or(0, |peer| peer.fips_bytes_recv),
            fips_direct_probe_pending: daemon_peer.is_some_and(|peer| peer.direct_probe_pending),
            fips_direct_probe_after_ms: daemon_peer
                .and_then(|peer| peer.direct_probe_after_ms)
                .unwrap_or(0),
            fips_direct_probe_retry_count: daemon_peer
                .map_or(0, |peer| peer.direct_probe_retry_count),
            fips_direct_probe_auto_reconnect: daemon_peer
                .is_some_and(|peer| peer.direct_probe_auto_reconnect),
            fips_direct_probe_expires_at_ms: daemon_peer
                .and_then(|peer| peer.direct_probe_expires_at_ms)
                .unwrap_or(0),
            state: peer_state,
            mesh_state,
            status_text,
            last_fips_control_seen_text: Self::peer_last_fips_control_seen_text(
                daemon_peer,
                is_local,
            ),
            last_fips_data_seen_text: Self::peer_last_fips_data_seen_text(daemon_peer, is_local),
            last_seen_text: Self::peer_last_fips_seen_text(daemon_peer, is_local),
        }
    }

    fn network_access_pending(&self, network: &NetworkConfig, own_pubkey_hex: &str) -> bool {
        if own_pubkey_hex.is_empty() {
            return false;
        }
        !self
            .config
            .network_has_confirmed_local_identity(&network.id)
    }

}
