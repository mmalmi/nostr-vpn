#[cfg(test)]
mod endpoint_config_tests {
    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};

    fn websocket_peer(npub: String) -> FipsEndpointPeerTransportConfig {
        FipsEndpointPeerTransportConfig {
            npub,
            addresses: vec![FipsPeerAddressHint {
                addr: "websocket:wss://seed.example.org/fips".to_string(),
                seen_at_ms: None,
                priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
            }],
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        }
    }

    fn test_peer() -> FipsMeshPeerConfig {
        let participant = Keys::generate().public_key().to_hex();
        FipsMeshPeerConfig::from_participant_pubkey(&participant, vec!["10.44.1.2/32".to_string()])
            .expect("peer config")
    }

    fn test_transport(
        nostr_discovery_enabled: bool,
        webrtc_enabled: bool,
    ) -> FipsEndpointTransportConfig {
        FipsEndpointTransportConfig {
            listen_port: 51820,
            bind_interface: None,
            advertised_endpoint: "192.168.50.20:51820".to_string(),
            advertise_public_endpoint: false,
            nostr_discovery_enabled,
            advertise_on_nostr: true,
            webrtc_enabled,
            stun_servers: vec!["stun:stun.example.org:3478".to_string()],
            nostr_relays: vec!["wss://relay.example.org".to_string()],
            websocket: WebSocketConfig {
                seed_urls: vec!["wss://seed.example.org/fips".to_string()],
                ..WebSocketConfig::default()
            },
            share_local_candidates: true,
        }
    }

    fn udp_carriers(config: &Config) -> &HashMap<String, UdpConfig> {
        let TransportInstances::Named(udp) = &config.transports.udp else {
            panic!("expected named IPv4 and IPv6 UDP transports");
        };
        assert_eq!(udp.len(), 2);
        udp
    }

    #[test]
    fn fresh_joiner_routes_by_known_npub_without_publishing_an_advert() {
        let transport = test_transport(true, false);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &[],
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(
            config.node.discovery.nostr.enabled,
            "the joiner still needs configured transit and discovery routing"
        );
        assert!(
            !config.node.discovery.nostr.advertise,
            "the signed join request already supplies the joiner's npub"
        );
        assert!(
            udp_carriers(&config)
                .values()
                .all(|udp| !udp.advertise_on_nostr())
        );
    }

    #[test]
    fn public_websocket_listener_has_matching_fips_capacity() {
        let mut transport = test_transport(true, false);
        transport.websocket = WebSocketConfig {
            bind_addr: Some("127.0.0.1:8765".to_string()),
            public_url: Some("wss://seed.example.org/fips".to_string()),
            max_connections: Some(FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS),
            max_inbound_connections: Some(FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS),
            idle_timeout_secs: Some(FIPS_PUBLIC_WEBSOCKET_IDLE_TIMEOUT_SECS),
            ..WebSocketConfig::default()
        };
        let config = fips_endpoint_config_with_open_discovery_limit(
            &[],
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_WEBSOCKET_LISTENER_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert_eq!(
            config.node.limits.max_connections,
            FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS,
        );
        assert_eq!(
            config.node.limits.max_peers,
            FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS,
        );
        assert_eq!(
            config.node.limits.max_links,
            FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS,
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            256,
        );
        assert!(
            config.node.discovery.nostr.open_discovery_max_pending
                < FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS,
            "public unaffiliated admission must remain bounded below socket capacity",
        );
    }

    #[test]
    fn configured_websocket_fallback_enables_transport_without_independent_seed_dial() {
        let mut transport = test_transport(true, false);
        transport.websocket.seed_urls.clear();
        let config = fips_endpoint_config_with_open_discovery_limit(
            &[websocket_peer(Keys::generate().public_key().to_bech32().expect("npub"))],
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        let (_, websocket) = config
            .transports
            .websocket
            .iter()
            .next()
            .expect("configured fallback needs an outbound WebSocket transport");
        assert!(websocket.seed_urls.is_empty());
    }

    #[test]
    fn configured_udp_seed_outranks_its_websocket_fallback() {
        let npub = Keys::generate().public_key().to_bech32().expect("npub");
        let peers = fips_endpoint_peers_from_mesh(
            &[],
            vec![(
                npub,
                vec![
                    "seed.example.org:51820".to_string(),
                    "websocket:wss://seed.example.org/fips".to_string(),
                ],
            )],
            Vec::new(),
        );

        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0]
                .addresses
                .iter()
                .map(|hint| (hint.addr.as_str(), hint.priority))
                .collect::<Vec<_>>(),
            [
                ("seed.example.org:51820", FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY),
                (
                    "websocket:wss://seed.example.org/fips",
                    FIPS_WEBSOCKET_FALLBACK_ENDPOINT_PRIORITY,
                ),
            ]
        );
    }

    #[test]
    fn udp_hostname_hints_resolve_before_family_specific_transport_selection() {
        let addresses = fips_peer_addresses_from_hint(&FipsPeerAddressHint {
            addr: "localhost:51820".to_string(),
            seen_at_ms: None,
            priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
        });

        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| {
            address.transport == "udp" && address.addr.parse::<SocketAddr>().is_ok()
        }));
    }

    #[test]
    fn configured_control_peer_does_not_force_joiner_advertising() {
        let mut transport = test_transport(true, false);
        transport.advertise_on_nostr = false;
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[test_peer()], Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert!(
            udp_carriers(&config)
                .values()
                .all(|udp| !udp.advertise_on_nostr())
        );
    }

    #[test]
    fn endpoint_config_configures_webrtc_when_nostr_discovery_on() {
        let peer = test_peer();
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let transport = test_transport(true, true);
        let mesh_mtu = resolve_private_mesh_mtu(None, None, None);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            mesh_mtu,
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        config
            .validate()
            .expect("WebRTC-enabled endpoint config should validate");
        let TransportInstances::Single(webrtc) = &config.transports.webrtc else {
            panic!("expected one WebRTC transport");
        };
        assert_eq!(webrtc.advertise_on_nostr, Some(true));
        assert_eq!(webrtc.auto_connect, Some(true));
        assert_eq!(webrtc.accept_connections, Some(true));
        assert_eq!(webrtc.mtu, Some(mesh_mtu.underlay_udp));
        assert_eq!(
            webrtc.stun_servers.as_ref().expect("stun servers"),
            &transport.stun_servers
        );
        let TransportInstances::Single(websocket) = &config.transports.websocket else {
            panic!("expected one WebSocket transport");
        };
        assert_eq!(websocket.seed_urls, transport.websocket.seed_urls);
    }

    #[test]
    fn endpoint_config_binds_carrier_and_traversal_to_underlay_interface() {
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(&[test_peer()], Vec::new(), Vec::new());
        let mut transport = test_transport(true, true);
        transport.bind_interface = Some("en0".to_string());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(
            udp_carriers(&config)
                .values()
                .all(|udp| udp.bind_interface.as_deref() == Some("en0"))
        );
        assert_eq!(
            config.node.discovery.nostr.bind_interface.as_deref(),
            Some("en0"),
            "STUN and direct-traversal sockets must use the carrier underlay"
        );
    }

    #[test]
    fn endpoint_config_binds_ipv4_and_ipv6_on_the_same_port() {
        let transport = test_transport(false, false);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &[],
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::ConfiguredOnly,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );
        let udp = udp_carriers(&config);

        assert_eq!(
            udp[FIPS_UDP_IPV4_TRANSPORT].bind_addr.as_deref(),
            Some("0.0.0.0:51820")
        );
        assert_eq!(
            udp[FIPS_UDP_IPV6_TRANSPORT].bind_addr.as_deref(),
            Some("[::]:51820")
        );
    }

    #[test]
    fn public_ipv6_endpoint_is_advertised_by_the_ipv6_carrier() {
        let mut transport = test_transport(true, false);
        transport.advertise_public_endpoint = true;
        transport.advertised_endpoint = "[2001:4860:4860::8888]:51820".to_string();
        let config = fips_endpoint_config_with_open_discovery_limit(
            &[websocket_peer(Keys::generate().public_key().to_bech32().unwrap())],
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );
        let udp = udp_carriers(&config);
        let ipv4 = &udp[FIPS_UDP_IPV4_TRANSPORT];
        let ipv6 = &udp[FIPS_UDP_IPV6_TRANSPORT];

        assert!(!ipv4.advertise_on_nostr());
        assert_eq!(ipv4.external_addr, None);
        assert!(ipv6.advertise_on_nostr());
        assert_eq!(
            ipv6.external_addr.as_deref(),
            Some("[2001:4860:4860::8888]:51820")
        );
    }

    #[test]
    fn endpoint_config_uses_external_nostr_peerfinding_provider() {
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(&[test_peer()], Vec::new(), Vec::new());
        let transport = test_transport(true, false);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.peerfinding_source,
            NostrPeerfindingSource::External,
            "standard nostr-pubsub must be the sole peer-advert relay provider"
        );
    }

    #[test]
    fn endpoint_config_keeps_in_fips_webrtc_when_nostr_discovery_off() {
        let peer = test_peer();
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let transport = test_transport(false, true);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::ConfiguredOnly,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(!config.node.discovery.nostr.enabled);
        let TransportInstances::Single(webrtc) = &config.transports.webrtc else {
            panic!("expected one WebRTC transport");
        };
        assert_eq!(webrtc.advertise_on_nostr, Some(false));
        assert_eq!(webrtc.auto_connect, Some(false));
        assert_eq!(
            webrtc.accept_connections,
            Some(true),
            "authenticated in-FIPS offers must not depend on relay discovery"
        );
        assert!(!config.transports.websocket.is_empty());
    }

    #[test]
    fn endpoint_config_keeps_websocket_transport_without_webrtc() {
        let peer = test_peer();
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let transport = test_transport(true, false);
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert!(config.transports.webrtc.is_empty());
        assert!(!config.transports.udp.is_empty());
        let TransportInstances::Single(websocket) = &config.transports.websocket else {
            panic!("expected one WebSocket transport");
        };
        assert_eq!(websocket.seed_urls, transport.websocket.seed_urls);
    }

    #[test]
    fn join_roster_recipient_keeps_enabled_roster_transports() {
        let roster = test_peer();
        let roster_npub = normalize_fips_endpoint_npub(&roster.endpoint_npub);
        let ambient_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let peers = fips_endpoint_peers_from_mesh(
            std::slice::from_ref(&roster),
            vec![
                (
                    roster_npub.clone(),
                    vec![
                        "203.0.113.10:51820".to_string(),
                        "tcp:203.0.113.10:443".to_string(),
                        format!("webrtc:02{}", Keys::generate().public_key().to_hex()),
                    ],
                ),
                (
                    ambient_npub.clone(),
                    vec!["203.0.113.20:51820".to_string()],
                ),
            ],
            Vec::new(),
        );
        let peers = prioritize_fips_control_recipient(peers, &roster.endpoint_npub)
            .expect("join roster recipient");

        let roster_peer = &peers[0];
        assert_eq!(roster_peer.npub, roster_npub);
        for transport in ["udp", "tcp", "webrtc"] {
            assert!(roster_peer.addresses.iter().any(|address| {
                split_peer_transport_addr(&address.addr).0 == transport
            }));
        }
        assert!(peers.iter().any(|peer| peer.npub == ambient_npub));
    }

    #[test]
    fn operator_static_control_peer_reconnects_without_becoming_a_mesh_route() {
        let peer_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let peers = fips_endpoint_peers_from_mesh(
            &[],
            vec![(
                peer_npub.clone(),
                vec!["203.0.113.20:51820".to_string()],
            )],
            Vec::new(),
        );

        let peer = peers
            .iter()
            .find(|peer| peer.npub == peer_npub)
            .expect("static control peer");
        assert!(peer.auto_reconnect);
        assert!(peer.discovery_fallback_transit);
    }

    #[test]
    fn canonical_npub_gives_exactly_one_public_websocket_seed_dial_ownership() {
        let mut npubs = [
            Keys::generate().public_key().to_bech32().expect("npub"),
            Keys::generate().public_key().to_bech32().expect("npub"),
        ];
        npubs.sort();
        let [lower_npub, higher_npub] = npubs;

        let mut lower_seed_peers = vec![websocket_peer(higher_npub.clone())];
        apply_canonical_websocket_dial_direction(&mut lower_seed_peers, &lower_npub, true);
        assert!(
            !lower_seed_peers[0].connect_on_start,
            "the lower canonical npub keeps the peer configured but does not dial"
        );
        assert!(lower_seed_peers[0].auto_reconnect);
        assert!(lower_seed_peers[0].discovery_fallback_transit);

        let mut higher_seed_peers = vec![websocket_peer(lower_npub.clone())];
        apply_canonical_websocket_dial_direction(&mut higher_seed_peers, &higher_npub, true);
        assert!(
            higher_seed_peers[0].connect_on_start,
            "the higher canonical npub owns the one physical dial"
        );
    }

    #[test]
    fn websocket_seed_dial_ownership_ignores_url_spelling_and_learned_direct_hints() {
        let mut npubs = [
            Keys::generate().public_key().to_bech32().expect("npub"),
            Keys::generate().public_key().to_bech32().expect("npub"),
        ];
        npubs.sort();
        let [lower_npub, higher_npub] = npubs;
        let mut peer = websocket_peer(higher_npub);
        peer.addresses[0].addr = "websocket:wss://zzz.example/fips".to_string();
        peer.addresses.push(FipsPeerAddressHint {
            addr: format!("webrtc:02{}", Keys::generate().public_key().to_hex()),
            seen_at_ms: Some(1),
            priority: FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY,
        });

        apply_canonical_websocket_dial_direction(
            std::slice::from_mut(&mut peer),
            &lower_npub,
            true,
        );
        assert!(
            !peer.connect_on_start,
            "only canonical identities decide which seed dials"
        );
    }

    #[test]
    fn canonical_seed_dial_rule_does_not_override_non_seed_or_non_listener_peers() {
        let local_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let peer_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let mut mixed_transport_peer = websocket_peer(peer_npub.clone());
        mixed_transport_peer.addresses.push(FipsPeerAddressHint {
            addr: "udp:203.0.113.10:51820".to_string(),
            seen_at_ms: None,
            priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
        });
        apply_canonical_websocket_dial_direction(
            std::slice::from_mut(&mut mixed_transport_peer),
            &local_npub,
            true,
        );
        assert!(mixed_transport_peer.connect_on_start);

        let mut ordinary_client_peer = websocket_peer(peer_npub);
        apply_canonical_websocket_dial_direction(
            std::slice::from_mut(&mut ordinary_client_peer),
            &local_npub,
            false,
        );
        assert!(ordinary_client_peer.connect_on_start);
    }

    #[test]
    fn transport_seed_urls_do_not_bypass_canonical_manual_peer_policy() {
        let mut manual_peer =
            websocket_peer(Keys::generate().public_key().to_bech32().expect("npub"));
        manual_peer.connect_on_start = false;
        manual_peer.addresses[0].addr =
            "websocket:wss://manual.example/fips".to_string();
        let mut automatic_peer =
            websocket_peer(Keys::generate().public_key().to_bech32().expect("npub"));
        automatic_peer.addresses[0].addr =
            "websocket:wss://automatic.example/fips".to_string();

        let seed_urls = websocket_seed_urls_after_peer_dial_ownership(
            &[
                "wss://manual.example/fips".to_string(),
                "wss://automatic.example/fips".to_string(),
                "wss://identity-unknown.example/fips".to_string(),
            ],
            &[manual_peer, automatic_peer],
        );

        assert_eq!(
            seed_urls,
            [
                "wss://automatic.example/fips",
                "wss://identity-unknown.example/fips"
            ]
        );
    }

    #[test]
    fn disabled_webrtc_remains_disabled_for_join_roster_recipient() {
        let recipient_pubkey = Keys::generate().public_key().to_hex();
        let recipient_npub = normalize_fips_endpoint_npub(&recipient_pubkey);
        let mut peers = vec![FipsEndpointPeerTransportConfig {
            npub: recipient_npub.clone(),
            addresses: vec![
                FipsPeerAddressHint {
                    addr: "udp:203.0.113.20:51820".to_string(),
                    seen_at_ms: None,
                    priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
                },
                FipsPeerAddressHint {
                    addr: format!(
                        "webrtc:02{}",
                        Keys::generate().public_key().to_hex()
                    ),
                    seen_at_ms: Some(1),
                    priority: FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY,
                },
            ],
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        }];

        retain_enabled_peer_transport_addresses(&mut peers, false);
        let peers = prioritize_fips_control_recipient(peers, &recipient_pubkey)
            .expect("join roster recipient");

        let webrtc_addresses = peers
            .iter()
            .flat_map(|peer| peer.addresses.iter())
            .filter(|hint| split_peer_transport_addr(&hint.addr).0 == "webrtc")
            .collect::<Vec<_>>();
        assert!(webrtc_addresses.is_empty());
        assert_eq!(peers[0].npub, recipient_npub);
        assert!(peers.iter().any(|peer| {
            peer.addresses
                .iter()
                .any(|hint| hint.addr == "udp:203.0.113.20:51820")
        }));
    }

    #[test]
    fn ethernet_underlay_validates_interface_and_scope() {
        let parsed = FipsEthernetUnderlayConfig::parse(" eth0 ", " local-pairing ")
            .expect("valid Ethernet underlay");
        assert_eq!(parsed.interface, "eth0");
        assert_eq!(parsed.discovery_scope, "local-pairing");
        assert!(FipsEthernetUnderlayConfig::parse("", "scope").is_err());
        assert!(FipsEthernetUnderlayConfig::parse("eth0", " ").is_err());
        assert!(FipsEthernetUnderlayConfig::parse("eth0", &"x".repeat(256)).is_err());
    }

    #[test]
    fn ethernet_underlay_is_additive_to_ordinary_transports() {
        let peer = test_peer();
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(std::slice::from_ref(&peer), Vec::new(), Vec::new());
        let transport = test_transport(false, true);
        let ethernet =
            FipsEthernetUnderlayConfig::parse("eth0", "local-pairing").expect("underlay");
        let mesh_mtu = resolve_private_mesh_mtu(None, None, None);
        let config = fips_endpoint_config_for_ethernet(
            &endpoint_peers,
            Some(&transport),
            &ethernet,
            mesh_mtu,
            NostrDiscoveryPolicy::ConfiguredOnly,
            0,
        );

        config.validate().expect("Ethernet endpoint config");
        assert!(!config.transports.udp.is_empty());
        assert!(config.transports.tcp.is_empty());
        assert!(!config.transports.webrtc.is_empty());
        assert!(!config.transports.websocket.is_empty());
        let TransportInstances::Single(raw) = &config.transports.ethernet else {
            panic!("expected one Ethernet transport");
        };
        assert_eq!(raw.interface, "eth0");
        assert_eq!(raw.discovery_scope.as_deref(), Some("local-pairing"));
        assert_eq!(raw.discovery, Some(true));
        assert_eq!(raw.announce, Some(true));
        assert_eq!(raw.auto_connect, Some(true));
        assert_eq!(raw.accept_connections, Some(true));
        assert_eq!(config.peers.len(), 1);
        assert!(config.peers[0].addresses.is_empty());
    }

    #[test]
    fn pending_device_approval_uses_url_only_websocket_seed_without_known_admin() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "pending-device-approval".to_string();
        app.networks[0].devices.clear();
        app.networks[0].admins.clear();
        app.networks[0].listen_for_join_requests = false;
        app.fips_bootstrap_enabled = false;
        app.fips_websocket_seed_urls = vec!["wss://seed.example.org/fips".to_string()];
        app.ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending device approval");

        let tunnel = FipsPrivateTunnelConfig::from_app(
            &app,
            "pending-device-approval",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("pending join tunnel config");
        assert!(tunnel.endpoint_peers.is_empty());
        assert_eq!(
            tunnel.websocket.seed_urls,
            ["wss://seed.example.org/fips"]
        );
        assert_eq!(
            tunnel.nostr_discovery_policy,
            NostrDiscoveryPolicy::Open,
            "pending ordinary approval must admit authenticated physical adjacency"
        );
        assert!(tunnel.open_discovery_max_pending > 0);

        let ethernet =
            FipsEthernetUnderlayConfig::parse("eth0", "local-pairing").expect("underlay");
        let endpoint = fips_endpoint_config_for_ethernet(
            &tunnel.endpoint_peers,
            Some(&test_transport(false, true)),
            &ethernet,
            tunnel.mesh_mtu,
            tunnel.nostr_discovery_policy,
            tunnel.open_discovery_max_pending,
        );
        assert_eq!(
            endpoint.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open,
            "physical underlay must preserve the pending-approval admission policy"
        );
        assert!(endpoint.node.discovery.nostr.open_discovery_max_pending > 0);

        app.clear_pending_nostr_join_request();
        let closed = FipsPrivateTunnelConfig::from_app(
            &app,
            "pending-device-approval",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("closed join tunnel config");
        assert_eq!(closed.websocket, tunnel.websocket);
        assert_eq!(
            closed.nostr_discovery_policy,
            NostrDiscoveryPolicy::ConfiguredOnly,
            "ordinary admission must close when no approval is pending"
        );
        assert_eq!(closed.open_discovery_max_pending, 0);
    }

}
