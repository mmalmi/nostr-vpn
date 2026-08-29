#[cfg(feature = "paid-exit")]
pub(crate) fn fips_paid_route_admission_from_seller_admission(
    admission: PaidRouteSellerAdmission,
) -> FipsPaidRouteAdmission {
    let mut admission = FipsPaidRouteAdmission::from(admission);
    admission.destination_allowed_ips =
        crate::runtime_supported_advertised_routes(admission.destination_allowed_ips);
    admission
}

fn fips_exit_route_ready(
    config: &FipsPrivateTunnelConfig,
    peer_statuses: &[MeshPeerStatus],
) -> bool {
    let connected = connected_peer_pubkeys(peer_statuses);
    fips_exit_route_ready_for_connected(
        &config.route_targets,
        &config.peers,
        config.exit_node_leak_protection,
        config.wireguard_exit.enabled,
        config.public_paid_exit_waiting_for_admission,
        &connected,
    )
}

fn connected_peer_pubkeys(peer_statuses: &[MeshPeerStatus]) -> HashSet<&str> {
    peer_statuses
        .iter()
        .filter(|status| status.connected)
        .map(|status| status.pubkey.as_str())
        .collect()
}

fn fips_exit_route_ready_for_connected(
    route_targets: &[String],
    peers: &[FipsMeshPeerConfig],
    leak_protection: bool,
    wireguard_exit_enabled: bool,
    public_paid_exit_waiting_for_admission: bool,
    connected: &HashSet<&str>,
) -> bool {
    let exit_requested = route_targets
        .iter()
        .any(|route| crate::is_exit_node_route(route));
    if !exit_requested || leak_protection || wireguard_exit_enabled {
        return true;
    }
    if public_paid_exit_waiting_for_admission {
        return false;
    }

    peers.iter().any(|peer| {
        peer.advertises_default_route() && connected.contains(peer.participant_pubkey.as_str())
    })
}

fn local_exit_seller_egress_ready(
    config: &FipsPrivateTunnelConfig,
    connected: &HashSet<&str>,
    wireguard_ready: bool,
    active_listen_port: Option<u16>,
) -> bool {
    if active_listen_port.is_none() {
        return false;
    }
    match config.local_exit_seller_egress.as_ref() {
        Some(PaidExitSellerEgress::Direct) => true,
        Some(PaidExitSellerEgress::WireGuard) => wireguard_ready,
        Some(PaidExitSellerEgress::PrivatePeer { pubkey }) => {
            config.peers.iter().any(|peer| {
                peer.participant_pubkey == *pubkey && peer.advertises_default_route()
            }) && connected.contains(pubkey.as_str())
        }
        None => false,
    }
}

fn paid_route_admissions_for_egress(
    config: &FipsPrivateTunnelConfig,
    egress_ready: bool,
) -> Vec<FipsPaidRouteAdmission> {
    let private_upstream = config
        .local_exit_seller_egress
        .as_ref()
        .and_then(PaidExitSellerEgress::private_peer_pubkey);
    config
        .paid_route_admissions
        .iter()
        .cloned()
        .map(|mut admission| {
            admission.allow_routing &= egress_ready
                && private_upstream != Some(admission.participant_pubkey.as_str());
            admission
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn local_exit_outbound_interface(
    seller_egress: Option<&PaidExitSellerEgress>,
    tunnel_iface: &str,
    wireguard_iface: Option<&str>,
    host_default_iface: Option<&str>,
) -> Option<String> {
    match seller_egress {
        Some(PaidExitSellerEgress::Direct) => host_default_iface.map(str::to_owned),
        Some(PaidExitSellerEgress::WireGuard) => wireguard_iface.map(str::to_owned),
        Some(PaidExitSellerEgress::PrivatePeer { .. }) => Some(tunnel_iface.to_string()),
        None => None,
    }
}

pub(crate) fn effective_fips_route_targets(
    config: &FipsPrivateTunnelConfig,
    peer_statuses: &[MeshPeerStatus],
) -> Vec<String> {
    let mut targets = config.route_targets.clone();
    if !fips_exit_route_ready(config, peer_statuses) {
        targets.retain(|route| !crate::is_exit_node_route(route));
    }
    targets
}

impl FipsPrivateTunnelConfig {
    #[cfg(feature = "paid-exit")]
    pub(crate) fn require_public_paid_exit_admission(&mut self, admitted: bool) {
        self.public_paid_exit_waiting_for_admission = !admitted;
    }

    pub(crate) fn from_app(
        app: &AppConfig,
        network_id: &str,
        iface: impl Into<String>,
        own_pubkey: Option<&str>,
        recent_peers: Option<&nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
        live_peer_endpoints: &[(String, Vec<(String, u64)>)],
    ) -> Result<Self> {
        Self::from_app_with_control_recipients(
            app,
            network_id,
            iface,
            own_pubkey,
            recent_peers,
            live_peer_endpoints,
            &[],
        )
    }

    pub(crate) fn from_app_with_control_recipients(
        app: &AppConfig,
        network_id: &str,
        iface: impl Into<String>,
        own_pubkey: Option<&str>,
        recent_peers: Option<&nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
        live_peer_endpoints: &[(String, Vec<(String, u64)>)],
        control_recipient_pubkeys: &[&str],
    ) -> Result<Self> {
        let local_identity_confirmation_pending = app
            .active_network_opt()
            .is_some_and(|network| network.local_identity_confirmation_pending);
        let network_id = if local_identity_confirmation_pending {
            ""
        } else {
            network_id
        };
        let mut peers = Vec::new();
        let mut route_targets = Vec::new();
        let participants = if local_identity_confirmation_pending {
            Vec::new()
        } else {
            app.participant_pubkeys_hex()
        };
        let mut route_by_participant = HashMap::<String, Vec<String>>::new();
        for participant in participants {
            if Some(participant.as_str()) == own_pubkey {
                continue;
            }
            let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &participant) else {
                continue;
            };
            let allowed_ip = format!("{}/32", strip_cidr(&tunnel_ip));
            route_targets.push(allowed_ip.clone());
            route_by_participant
                .entry(participant.clone())
                .or_default()
                .push(allowed_ip);
            if app.exit_node == participant {
                let exit_routes = crate::runtime_exit_node_default_routes();
                route_targets.extend(exit_routes.iter().cloned());
                route_by_participant
                    .entry(participant)
                    .or_default()
                    .extend(exit_routes);
            }
        }

        #[cfg(feature = "paid-exit")]
        if !local_identity_confirmation_pending
            && let Some(public_paid_exit) = app.public_paid_exit_node_pubkey_hex()
            && Some(public_paid_exit.as_str()) != own_pubkey
        {
            let exit_routes = crate::runtime_exit_node_default_routes();
            route_targets.extend(exit_routes.iter().cloned());
            route_by_participant
                .entry(public_paid_exit)
                .or_default()
                .extend(exit_routes);
        }

        let pending_remote_exit = app.exit_node.is_empty()
            && matches!(
                app.internet_source,
                InternetSource::PrivateVpn
                    | InternetSource::PaidAutomatic
                    | InternetSource::PaidManual
            );
        if !local_identity_confirmation_pending
            && app.exit_node_leak_protection
            && pending_remote_exit
        {
            route_targets.extend(crate::runtime_exit_node_default_routes());
        }

        let mut route_participants = app.active_network_signal_pubkeys_hex();
        #[cfg(feature = "paid-exit")]
        if !local_identity_confirmation_pending
            && let Some(public_paid_exit) = app.public_paid_exit_node_pubkey_hex()
        {
            route_participants.push(public_paid_exit);
        }
        #[cfg(feature = "paid-exit")]
        if !local_identity_confirmation_pending
            && let Some(provider) = app.manual_paid_exit_provider_pubkey_hex()
        {
            route_participants.push(provider);
        }
        route_participants.sort();
        route_participants.dedup();

        for participant in route_participants
            .into_iter()
            .filter(|participant| Some(participant.as_str()) != own_pubkey)
        {
            let mut allowed_ips = route_by_participant
                .remove(&participant)
                .unwrap_or_default();
            allowed_ips.sort();
            allowed_ips.dedup();
            peers.push(FipsMeshPeerConfig::from_participant_pubkey(
                participant,
                allowed_ips,
            )?);
        }
        peers.sort_by(|left, right| left.participant_pubkey.cmp(&right.participant_pubkey));
        peers.dedup_by(|left, right| left.participant_pubkey == right.participant_pubkey);
        // Address hints feed into fips's unified `PeerConfig.addresses`:
        //   * operator-configured `fips_peer_endpoints` (unstamped)
        //   * recent-peers cache entries (stamped with `last_success_at`)
        // Configured hints are authenticated by FIPS and may intentionally
        // cross a routed private network, so only reject overlay tunnel loops.
        let mut desired_endpoint_hint_npubs = app
            .active_network_signal_pubkeys_hex()
            .into_iter()
            .filter(|participant| Some(participant.as_str()) != own_pubkey)
            .map(|participant| normalize_fips_endpoint_npub(&participant))
            .collect::<std::collections::HashSet<_>>();
        desired_endpoint_hint_npubs.extend(control_recipient_pubkeys.iter().filter_map(
            |recipient| {
                normalize_nostr_pubkey(recipient)
                    .ok()
                    .filter(|recipient| Some(recipient.as_str()) != own_pubkey)
                    .map(|recipient| normalize_fips_endpoint_npub(&recipient))
            },
        ));
        #[cfg(feature = "paid-exit")]
        let desired_endpoint_hint_npubs = {
            let mut desired_endpoint_hint_npubs = desired_endpoint_hint_npubs;
            if let Some(public_paid_exit) = app.public_paid_exit_node_pubkey_hex()
                && Some(public_paid_exit.as_str()) != own_pubkey
            {
                desired_endpoint_hint_npubs.insert(normalize_fips_endpoint_npub(&public_paid_exit));
            }
            if let Some(provider) = app.manual_paid_exit_provider_pubkey_hex()
                && Some(provider.as_str()) != own_pubkey
            {
                desired_endpoint_hint_npubs.insert(normalize_fips_endpoint_npub(&provider));
            }
            desired_endpoint_hint_npubs
        };
        let nostr_discovery_policy = fips_nostr_discovery_policy_from_app(app);
        let allow_non_roster_transit = nostr_discovery_policy == NostrDiscoveryPolicy::Open;
        let websocket_listener = !app.fips_websocket_bind_addr.is_empty();
        let public_websocket_listener =
            websocket_listener && !app.fips_websocket_public_url.trim().is_empty();
        let tunnel_endpoint_hosts = fips_tunnel_endpoint_hosts(app, network_id);
        let local_private_subnets = local_private_ipv4_subnets();
        // In static-only mode, the configured endpoint is the user's only path.
        // Keep routed private addresses such as VM/container host-only networks
        // even when they are not on a directly attached subnet.
        let mut operator_static = filter_static_tunnel_endpoints_with_policy(
            app.fips_static_peer_endpoints(),
            &tunnel_endpoint_hosts,
            &local_private_subnets,
            true,
        );
        // Built-in public bootstrap nodes as fallback transit. They share the
        // same `discovery_fallback_transit` path as operator-configured static
        // peers, so they ferry frames when direct traversal fails but never
        // become roster route targets.
        if allow_non_roster_transit {
            let bootstrap_transit = filter_static_tunnel_endpoints(
                app.fips_bootstrap_peer_endpoints(),
                &tunnel_endpoint_hosts,
                &local_private_subnets,
            );
            operator_static.extend(cap_static_non_roster_transit_endpoints(
                bootstrap_transit,
                &desired_endpoint_hint_npubs,
                FIPS_STATIC_NON_ROSTER_TRANSIT_MAX_SEEDS,
            ));
        }
        let static_non_roster_transit_seeds = if allow_non_roster_transit {
            non_roster_endpoint_group_count(&operator_static, &desired_endpoint_hint_npubs)
        } else {
            0
        };
        #[cfg(feature = "paid-exit")]
        let paid_exit_seller = app.paid_exit.enabled;
        #[cfg(not(feature = "paid-exit"))]
        let paid_exit_seller = false;
        let mut open_discovery_max_pending = if paid_exit_seller {
            FIPS_NOSTR_PAID_EXIT_OPEN_DISCOVERY_MAX_PENDING
        } else if app.node.advertise_exit_node {
            FIPS_NOSTR_EXIT_OPEN_DISCOVERY_MAX_PENDING
        } else if allow_non_roster_transit {
            if websocket_listener {
                FIPS_WEBSOCKET_LISTENER_OPEN_DISCOVERY_MAX_PENDING
            } else {
                open_discovery_limit_after_transit_seeds(
                    FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
                    static_non_roster_transit_seeds,
                )
            }
        } else {
            0
        };
        let open_discovery_restart_max_pending = open_discovery_max_pending;
        // With discovery disabled, configured static endpoints are the whole path;
        // stamped recent/live hints can redirect a deterministic direct setup.
        let stamped_endpoint_hints_enabled = app.fips_nostr_discovery_enabled;
        let mut recent_peer_endpoints = if stamped_endpoint_hints_enabled {
            recent_peers
                .map(|cache| cache.as_static_peer_endpoints_with_seen_at())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        recent_peer_endpoints = filter_stamped_tunnel_endpoints(
            recent_peer_endpoints,
            &tunnel_endpoint_hosts,
            &local_private_subnets,
        );
        // Roster endpoint hints are always retained. Recent authenticated
        // non-roster peers are transport-only transit seeds; cap them so they
        // cannot consume the whole open-discovery adjacency budget.
        recent_peer_endpoints = cap_recent_non_roster_transit_endpoints(
            recent_peer_endpoints,
            &desired_endpoint_hint_npubs,
            if allow_non_roster_transit && !websocket_listener {
                FIPS_RECENT_NON_ROSTER_TRANSIT_MAX_SEEDS
            } else {
                0
            },
        );
        let recent_non_roster_transit_seeds =
            non_roster_endpoint_group_count(&recent_peer_endpoints, &desired_endpoint_hint_npubs);
        open_discovery_max_pending =
            open_discovery_max_pending.saturating_sub(recent_non_roster_transit_seeds);
        // Live capability hints are accepted only for network signal peers or
        // pending control recipients because they are claims carried by that
        // authenticated peer. The disk cache above records peers this endpoint
        // already authenticated.
        if stamped_endpoint_hints_enabled {
            recent_peer_endpoints.extend(
                filter_stamped_tunnel_endpoints(
                    live_peer_endpoints
                        .iter()
                        .filter(|(participant, _)| {
                            desired_endpoint_hint_npubs
                                .contains(&normalize_fips_endpoint_npub(participant))
                        })
                        .cloned()
                        .collect(),
                    &tunnel_endpoint_hosts,
                    &local_private_subnets,
                )
                .into_iter()
                .filter(|(participant, _)| {
                    desired_endpoint_hint_npubs.contains(&normalize_fips_endpoint_npub(participant))
                }),
            );
        }
        let mut endpoint_peers =
            fips_endpoint_peers_from_mesh(&peers, operator_static, recent_peer_endpoints);
        // Keep configured and cached WebRTC hints out of the endpoint when the
        // transport is disabled.
        retain_enabled_peer_transport_addresses(&mut endpoint_peers, app.fips_webrtc_enabled);
        apply_canonical_websocket_dial_direction(
            &mut endpoint_peers,
            own_pubkey.unwrap_or_default(),
            public_websocket_listener,
        );
        let websocket_seed_urls = websocket_seed_urls_after_peer_dial_ownership(
            &app.fips_websocket_seed_urls,
            &endpoint_peers,
        );
        let nostr_relays = effective_fips_nostr_relays(&app.nostr.relays);
        let websocket = WebSocketConfig {
            bind_addr: (!app.fips_websocket_bind_addr.is_empty())
                .then(|| app.fips_websocket_bind_addr.clone()),
            public_url: (!app.fips_websocket_public_url.is_empty())
                .then(|| app.fips_websocket_public_url.clone()),
            seed_urls: websocket_seed_urls,
            max_connections: public_websocket_listener
                .then_some(FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS),
            max_inbound_connections: public_websocket_listener
                .then_some(FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS),
            idle_timeout_secs: public_websocket_listener
                .then_some(FIPS_PUBLIC_WEBSOCKET_IDLE_TIMEOUT_SECS),
            ..WebSocketConfig::default()
        };
        websocket
            .validate()
            .map_err(|error| anyhow!("invalid FIPS WebSocket configuration: {error}"))?;
        if !stamped_endpoint_hints_enabled {
            // Without ambient discovery, route targets are direct-only. Preserve
            // explicitly configured non-roster peers as designated FIPS transit.
            for peer in &mut endpoint_peers {
                if peer.auto_reconnect && desired_endpoint_hint_npubs.contains(&peer.npub) {
                    peer.discovery_fallback_transit = false;
                }
            }
            #[cfg(feature = "paid-exit")]
            if let Some(provider) = app.manual_paid_exit_provider_pubkey_hex()
                && let Some(peer) = endpoint_peers.iter_mut().find(|peer| {
                    peer.npub == normalize_fips_endpoint_npub(&provider)
                })
            {
                // A manually pinned provider is intentionally reachable by
                // identity through FIPS transit even without Nostr discovery.
                peer.discovery_fallback_transit = true;
            }
        }
        route_targets.sort();
        route_targets.dedup();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let fips_host = if local_identity_confirmation_pending {
            None
        } else {
            FipsHostTunnelConfig::from_app(app)?
        };
        #[cfg(target_os = "linux")]
        let control_plane_bypass_hosts =
            if crate::route_targets_require_endpoint_bypass(&route_targets) {
                crate::control_plane_bypass_ipv4_hosts(app)
            } else {
                Vec::new()
            };

        Ok(Self {
            identity_nsec: app.nostr.secret_key.clone(),
            network_id: network_id.to_string(),
            iface: iface.into(),
            local_address: own_pubkey
                .and_then(|pubkey| derive_mesh_tunnel_ip(network_id, pubkey))
                .map(|tunnel_ip| local_interface_address_for_tunnel(&tunnel_ip))
                .unwrap_or_else(|| local_interface_address_for_tunnel(&app.node.tunnel_ip)),
            listen_port: app.node.listen_port,
            underlay_interface: None,
            advertised_endpoint: app.node.endpoint.clone(),
            advertise_public_endpoint: app.fips_advertise_public_endpoint
                && !local_identity_confirmation_pending,
            stun_servers: app.nat.stun_servers.clone(),
            nostr_relays,
            nostr_pubsub: app.nostr.pubsub.clone(),
            control_pubsub_store_path: PathBuf::new(),
            ethernet_underlay: None,
            websocket,
            share_local_candidates: app.lan_discovery_enabled,
            peers,
            endpoint_peers,
            client_dataplane_enabled: true,
            route_targets,
            secure_dns_requested: !app.internet_source.is_direct()
                && (!local_identity_confirmation_pending
                    || app.internet_source == InternetSource::WireGuard),
            public_paid_exit_waiting_for_admission: false,
            magic_dns_records: if local_identity_confirmation_pending {
                HashMap::new()
            } else {
                build_magic_dns_records(app)
            },
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            fips_host,
            local_advertised_routes: if local_identity_confirmation_pending {
                Vec::new()
            } else {
                crate::runtime_effective_advertised_routes(app)
            },
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            local_exit_forwarding_routes: if local_identity_confirmation_pending {
                Vec::new()
            } else {
                crate::runtime_local_exit_forwarding_routes(app)
            },
            local_exit_seller_egress: if local_identity_confirmation_pending {
                None
            } else {
                app.paid_exit_seller_egress().ok()
            },
            paid_route_admissions: Vec::new(),
            #[cfg(feature = "paid-exit")]
            paid_route_accounting_peers: if local_identity_confirmation_pending {
                Vec::new()
            } else {
                app.public_paid_exit_node_pubkey_hex()
                    .and_then(|participant_pubkey| {
                        FipsPaidRouteAccountingPeer::parse(
                            &participant_pubkey,
                            FipsPaidRouteAccountingRole::LocalBuyer,
                        )
                    })
                    .into_iter()
                    .collect()
            },
            #[cfg(feature = "paid-exit")]
            paid_exit: if local_identity_confirmation_pending {
                PaidExitConfig::default()
            } else {
                app.paid_exit.clone()
            },
            #[cfg(feature = "paid-exit")]
            paid_route_store_path: PathBuf::new(),
            #[cfg(feature = "paid-exit")]
            paid_route_wallet_data_dir: PathBuf::new(),
            #[cfg(feature = "paid-exit")]
            paid_route_payment_relays: Vec::new(),
            exit_dns: app.exit_dns.clone(),
            wireguard_exit: app.wireguard_exit.clone(),
            exit_node_leak_protection: !local_identity_confirmation_pending
                && app.exit_node_leak_protection,
            nostr_discovery_enabled: app.fips_nostr_discovery_enabled,
            // A pending manual join has no durable roster route yet. Publish
            // the same generic identity-bound reachability advert as mobile
            // so its configured admin can deliver the signed roster after
            // this config replaces the pre-join runtime.
            advertise_on_nostr: true,
            webrtc_enabled: app.fips_webrtc_enabled,
            nostr_discovery_policy,
            open_discovery_restart_max_pending,
            open_discovery_max_pending,
            mesh_mtu: private_mesh_mtu_from_app(Some(app)),
            #[cfg(target_os = "linux")]
            control_plane_bypass_hosts,
        })
    }

    pub(crate) fn clamp_mesh_mtu_to_underlay_interface_mtu(
        &mut self,
        underlay_interface_mtu: Option<u32>,
    ) {
        self.mesh_mtu =
            clamp_mesh_mtu_to_underlay_interface_mtu(self.mesh_mtu, underlay_interface_mtu);
    }

    pub(crate) fn disable_client_dataplane(&mut self) {
        self.client_dataplane_enabled = false;
        self.route_targets.clear();
        for peer in &mut self.peers {
            peer.allowed_ips.clear();
        }
        self.secure_dns_requested = false;
        self.public_paid_exit_waiting_for_admission = false;
        self.wireguard_exit.enabled = false;
        self.exit_node_leak_protection = false;
    }

    fn local_allowed_ips(&self) -> Vec<String> {
        let mut routes = vec![self.local_address.clone()];
        routes.extend(self.local_advertised_routes.iter().cloned());
        routes.sort();
        routes.dedup();
        routes
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn interface_addresses(&self) -> Vec<String> {
        let mut addresses = vec![self.local_address.clone()];
        if let Some(fips_host) = self.fips_host.as_ref() {
            addresses.push(format!("{}/128", fips_host.fips_address));
        }
        addresses.sort();
        addresses.dedup();
        addresses
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn interface_route_targets(&self, mut routes: Vec<String>) -> Vec<String> {
        routes.extend(
            self.paid_route_admissions
                .iter()
                .flat_map(|admission| admission.allowed_ips.iter().cloned()),
        );
        if self.fips_host.is_some() {
            routes.push("fd00::/8".to_string());
        }
        routes.sort();
        routes.dedup();
        routes
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn interface_mtu(&self) -> u16 {
        if self.fips_host.is_some() {
            self.mesh_mtu.tunnel.max(1280)
        } else {
            self.mesh_mtu.tunnel
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn local_tunnel_ips(&self) -> Vec<IpAddr> {
        let mut ips = self
            .interface_addresses()
            .into_iter()
            .filter_map(|address| strip_cidr(&address).parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        ips.sort();
        ips.dedup();
        ips
    }

    fn secure_dns_required(&self) -> bool {
        // Until a public paid seller authenticates and admits the selected
        // session there is no usable exit path for forwarded DNS. Keep the
        // system resolver on the direct underlay while ordinary Internet is
        // allowed to fall through; leak-protected configurations deliberately
        // remain fail closed.
        if self.public_paid_exit_waiting_for_admission && !self.exit_node_leak_protection {
            return false;
        }
        let active_client_path = self.secure_dns_requested
            || self.fips_host_enabled()
            || (self.wireguard_exit.enabled && self.wireguard_exit.configured())
            || self
                .route_targets
                .iter()
                .any(|route| matches!(route.trim(), "0.0.0.0/0" | "::/0"));
        self.client_dataplane_enabled && active_client_path
    }

    fn fips_host_enabled(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.fips_host.is_some()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    fn public_paid_exit_selected(&self) -> bool {
        #[cfg(feature = "paid-exit")]
        {
            !self.paid_route_accounting_peers.is_empty()
        }
        #[cfg(not(feature = "paid-exit"))]
        {
            false
        }
    }

    fn exit_dns_resolver_config(
        &self,
        wireguard_active: bool,
    ) -> Result<ExitDnsResolverConfig> {
        if !self.client_dataplane_enabled || !self.secure_dns_requested {
            return ExitDnsConfig::default().resolver_config(None);
        }
        let public_paid_exit_active = self.public_paid_exit_selected() && !wireguard_active;
        if !public_paid_exit_active
            && self.exit_dns.mode == nostr_vpn_core::config::ExitDnsMode::ThroughExit
            && self.wireguard_exit.enabled
            && !wireguard_active
        {
            return Ok(ExitDnsResolverConfig::FailClosed);
        }
        let wireguard = wireguard_active.then_some(&self.wireguard_exit);
        let resolver = self.exit_dns.resolver_config(wireguard)?;
        let ExitDnsResolverConfig::ThroughExit { servers } = resolver else {
            return Ok(resolver);
        };
        if !public_paid_exit_active {
            return Ok(ExitDnsResolverConfig::ThroughExit { servers });
        }

        // Private provider DNS addresses such as 10.64.0.1 are only
        // reachable inside their owning WireGuard tunnel. Reusing one after
        // selecting an unrelated public paid exit makes the localhost DNS
        // stub wait forever while ordinary IP traffic through the seller is
        // otherwise healthy. Preserve explicitly configured public servers;
        // when none remain, use the encrypted public default.
        let public_servers = servers
            .into_iter()
            .filter(|server| !endpoint_ip_is_private_or_local(*server))
            .collect::<Vec<_>>();
        if public_servers.is_empty() {
            ExitDnsConfig::default().resolver_config(None)
        } else {
            Ok(ExitDnsResolverConfig::ThroughExit {
                servers: public_servers,
            })
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn endpoint_hint_ipv4_hosts(&self) -> Vec<Ipv4Addr> {
        let mut hosts = self
            .endpoint_peers
            .iter()
            .flat_map(|peer| peer.addresses.iter())
            .filter_map(|hint| endpoint_transport_ipv4_host(&hint.addr))
            .filter(|host| !route_targets_include_ipv4_host(&self.route_targets, *host))
            .collect::<Vec<_>>();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn route_targets_include_ipv4_host(route_targets: &[String], host: Ipv4Addr) -> bool {
    route_targets.iter().any(|route| {
        let Some((target, bits)) = route.split_once('/') else {
            return route.parse::<Ipv4Addr>() == Ok(host);
        };
        bits == "32" && target.parse::<Ipv4Addr>() == Ok(host)
    })
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    let tunnel_ip = tunnel_ip.trim();
    if tunnel_ip.is_empty() {
        return "10.44.0.1/32".to_string();
    }
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn fips_tunnel_requires_endpoint_restart(
    current: &FipsPrivateTunnelConfig,
    next: &FipsPrivateTunnelConfig,
) -> bool {
    // `endpoint_peers` is deliberately not in this list. Its addresses are fed
    // from recent-peer and live hint refreshes, so treating hint drift as a
    // restart requirement creates endpoint flap loops. Peer roster changes
    // still propagate through `apply_config` -> `mesh.replace_peers`.
    current.identity_nsec != next.identity_nsec
        || current.network_id != next.network_id
        || current.local_address != next.local_address
        || current.listen_port != next.listen_port
        || fips_tunnel_public_udp_external_addr(current)
            != fips_tunnel_public_udp_external_addr(next)
        || current.advertise_public_endpoint != next.advertise_public_endpoint
        || current.stun_servers != next.stun_servers
        || current.nostr_relays != next.nostr_relays
        || current.nostr_pubsub != next.nostr_pubsub
        || current.control_pubsub_store_path != next.control_pubsub_store_path
        || current.ethernet_underlay != next.ethernet_underlay
        || current.websocket != next.websocket
        || current.nostr_discovery_enabled != next.nostr_discovery_enabled
        || current.webrtc_enabled != next.webrtc_enabled
        || current.share_local_candidates != next.share_local_candidates
        || current.nostr_discovery_policy != next.nostr_discovery_policy
        // Authenticated recent transit peers are a live cache, not a transport
        // setting. Their bounded deduction changes `open_discovery_max_pending`
        // during ordinary reloads; restarting here would discard the carrier
        // that delivered a join approval. Durable capacity or static-seed
        // changes still differ in `open_discovery_restart_max_pending`.
        || current.open_discovery_restart_max_pending
            != next.open_discovery_restart_max_pending
        || current.mesh_mtu.underlay_udp != next.mesh_mtu.underlay_udp
        || fips_host_config_changed(current, next)
}

fn fips_tunnel_public_udp_external_addr(config: &FipsPrivateTunnelConfig) -> Option<String> {
    config
        .advertise_public_endpoint
        .then(|| fips_udp_external_addr(&config.advertised_endpoint))
        .flatten()
}

fn fips_host_config_changed(
    current: &FipsPrivateTunnelConfig,
    next: &FipsPrivateTunnelConfig,
) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        current.fips_host != next.fips_host
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (current, next);
        false
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn endpoint_transport_ipv4_host(addr: &str) -> Option<Ipv4Addr> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return match socket_addr.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        };
    }

    let (host, _) = crate::split_host_port(addr, 0)?;
    host.parse::<Ipv4Addr>().ok()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct FipsPrivateTunnelRuntime {
    iface: String,
    mesh: Arc<FipsPrivateMeshRuntime>,
    control_pubsub: Option<crate::control_pubsub_runtime::ControlPubsubFipsRuntime>,
    state_control: FipsControlTcpRuntime,
    secure_dns: Option<crate::secure_dns_runtime::SecureDnsRuntime>,
    manages_secure_dns: bool,
    config: FipsPrivateTunnelConfig,
    cleanup_journal_config_path: std::path::PathBuf,
    _tun: Arc<SystemTun>,
    fips_host: Option<crate::fips_host_tunnel::FipsHostTunnelRuntime>,
    fips_host_disabled_artifacts_cleaned: bool,
    tun_send_worker: Option<FipsTunSendWorker>,
    mesh_recv_worker: Option<FipsMeshRecvWorker>,
    fips_host_recv_worker: Option<FipsHostRecvWorker>,
    event_rx: mpsc::Receiver<FipsPrivateMeshEvent>,
    exit_route_ready: bool,
    local_exit_seller_egress_ready: bool,
    active_listen_port: Option<u16>,
    #[cfg(target_os = "macos")]
    endpoint_bypass_routes: Vec<String>,
    #[cfg(target_os = "linux")]
    endpoint_bypass_routes: Vec<crate::LinuxManagedEndpointBypassRoute>,
    #[cfg(target_os = "macos")]
    endpoint_bypass_underlay: Option<crate::MacosRouteSpec>,
    #[cfg(target_os = "macos")]
    macos_underlay_refresh_pending: bool,
    #[cfg(target_os = "linux")]
    original_default_route: Option<String>,
    #[cfg(target_os = "linux")]
    ethernet_underlay_default_route: Option<String>,
    #[cfg(target_os = "linux")]
    original_default_ipv6_route: Option<String>,
    #[cfg(target_os = "linux")]
    linux_network_state_initialized: bool,
    #[cfg(target_os = "linux")]
    exit_node_runtime: crate::LinuxExitNodeRuntime,
    #[cfg(target_os = "macos")]
    exit_node_runtime: crate::MacosExitNodeRuntime,
    /// Userspace WG upstream tunnel (Mullvad/Proton-style). Owned for
    /// the lifetime of "WG upstream is enabled in config"; dropped on
    /// disable. Populated by `reconcile_macos_wg_upstream` after a
    /// successful handshake — `None` means either WG upstream is
    /// disabled in the config or the most recent reconcile attempt
    /// could not complete a handshake (in which case the routing
    /// table was deliberately left untouched).
    #[cfg(target_os = "macos")]
    wg_upstream: Option<crate::wg_upstream_runtime::DaemonWgUpstream>,
}
