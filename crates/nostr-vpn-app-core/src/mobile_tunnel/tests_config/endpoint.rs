    fn mobile_udp_carriers(config: &FipsConfig) -> &HashMap<String, UdpConfig> {
        let TransportInstances::Named(udp) = &config.transports.udp else {
            panic!("expected named IPv4 and IPv6 UDP transports");
        };
        assert_eq!(udp.len(), 2);
        udp
    }

    #[test]
    fn mobile_fips_config_uses_discovery_for_roster_peers() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer");
        let mobile = MobileTunnelConfig {
            peers: vec![peer],
            advertised_endpoint: "192.168.50.22".to_string(),
            listen_port: 51820,
            nostr_relays: vec!["wss://relay.example".to_string()],
            stun_servers: vec!["stun:stun.example:3478".to_string()],
            share_local_candidates: true,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        config
            .validate()
            .expect("mobile FIPS config should validate");
        assert_eq!(
            config.node.discovery.backoff_base_secs,
            FIPS_DISCOVERY_BACKOFF_BASE_SECS
        );
        assert_eq!(
            config.node.discovery.backoff_max_secs,
            FIPS_DISCOVERY_BACKOFF_MAX_SECS
        );
        assert_eq!(
            config.node.discovery.forward_min_interval_secs,
            2,
            "a missed first lookup after a route change must retry promptly"
        );
        assert_eq!(
            config.node.rate_limit.handshake_resend_interval_ms,
            MOBILE_HANDSHAKE_RESEND_INTERVAL_MS
        );
        assert!(
            (config.node.rate_limit.handshake_resend_backoff - MOBILE_HANDSHAKE_RESEND_BACKOFF)
                .abs()
                < f64::EPSILON
        );
        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert!(config.node.discovery.nostr.share_local_candidates);
        assert!(config.node.discovery.lan.enabled);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            MOBILE_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            MOBILE_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert_eq!(
            config.node.discovery.nostr.startup_sweep_max_age_secs,
            FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS
        );
        // The mesh id must NOT appear in the publicly visible relay app tag.
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        assert_eq!(
            config.node.discovery.nostr.advert_relays,
            vec!["wss://relay.example".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.stun_servers,
            vec!["stun:stun.example:3478".to_string()]
        );
        let udp = mobile_udp_carriers(&config);
        assert_eq!(udp[MOBILE_UDP_IPV4_TRANSPORT].bind_addr(), "0.0.0.0:51820");
        assert_eq!(udp[MOBILE_UDP_IPV6_TRANSPORT].bind_addr(), "[::]:51820");
        for udp in udp.values() {
            assert!(!udp.outbound_only());
            assert!(udp.accept_connections());
            assert!(!udp.is_public());
        }
        assert!(udp[MOBILE_UDP_IPV4_TRANSPORT].advertise_on_nostr());
        assert!(!udp[MOBILE_UDP_IPV6_TRANSPORT].advertise_on_nostr());
        assert_eq!(
            mobile_endpoint_hints_with_candidates(&mobile, Vec::new()),
            vec![PeerEndpointHint::udp("192.168.50.22:51820")]
        );
        assert_eq!(config.peers.len(), 1);
        assert!(
            !config.peers[0].auto_reconnect,
            "mobile roster peers should use bounded FIPS retries"
        );
        // Mobile peer caps are clamped well below fips's defaults so Open
        // discovery doesn't burn battery on ambient connections.
        assert_eq!(config.node.limits.max_peers, MOBILE_MAX_FIPS_PEERS);
        assert_eq!(
            config.node.limits.max_connections,
            MOBILE_MAX_FIPS_CONNECTIONS
        );
        assert_eq!(config.node.limits.max_links, MOBILE_MAX_FIPS_LINKS);
        assert!(config.peers[0].discovery_fallback_transit);
    }

    #[test]
    fn mobile_fips_config_can_scope_discovery_to_roster_peers() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer");
        let mobile = MobileTunnelConfig {
            peers: vec![peer],
            connect_to_non_roster_fips_peers: false,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );
    }

    #[test]
    fn mobile_lan_discovery_uses_the_shared_private_scope() {
        let scope = mobile_lan_discovery_scope(" private-network-id ");

        assert_eq!(
            scope,
            nostr_vpn_core::fips_discovery::fips_lan_discovery_scope("private-network-id")
        );
        assert!(!scope.contains("private-network-id"));
    }

    #[test]
    fn mobile_fips_config_keeps_default_route_roster_peers_as_transit() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string(), "0.0.0.0/0".to_string()],
        )
        .expect("peer");
        let mobile = MobileTunnelConfig {
            peers: vec![peer.clone()],
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let peer_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == peer.endpoint_npub)
            .expect("exit peer");

        assert!(
            peer_config.discovery_fallback_transit,
            "an exit-capable roster peer may also be the only path to its LAN peers"
        );
    }

    #[test]
    fn mobile_fips_config_uses_static_peer_hints() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer");
        let mut peer_hints = HashMap::new();
        peer_hints.insert(
            peer.participant_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }],
        );
        let mobile = MobileTunnelConfig {
            peers: vec![peer.clone()],
            peer_hints,
            nostr_relays: vec!["wss://relay.example".to_string()],
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let peer_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == peer.endpoint_npub)
            .expect("seeded peer");

        let static_hint = peer_config
            .addresses
            .iter()
            .find(|address| address.addr == "192.168.50.10:51820")
            .expect("static peer hint");
        assert_eq!(static_hint.transport, "udp");
        assert_eq!(
            static_hint.priority,
            FIPS_STATIC_PEER_ENDPOINT_PRIORITY
        );
    }

    #[test]
    fn mobile_fips_config_keeps_hinted_non_roster_peers() {
        let roster_peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("roster peer");
        let transit_peer = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("transit pubkey");
        let transit = FipsMeshPeerConfig::from_participant_pubkey(transit_peer, Vec::new())
            .expect("transit peer");
        let mut peer_hints = HashMap::new();
        peer_hints.insert(
            transit.participant_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: "192.168.50.33:51820".to_string(),
                seen_at_ms: Some(1234),
                priority: FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY,
            }],
        );
        let mobile = MobileTunnelConfig {
            peers: vec![roster_peer],
            peer_hints,
            connect_to_non_roster_fips_peers: true,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let transit_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == transit.endpoint_npub)
            .expect("hinted non-roster peer should seed FIPS");

        assert_eq!(transit_config.addresses.len(), 1);
        assert_eq!(transit_config.addresses[0].transport, "udp");
        assert_eq!(transit_config.addresses[0].addr, "192.168.50.33:51820");
        assert_eq!(transit_config.addresses[0].seen_at_ms, Some(1234));
        assert_eq!(
            transit_config.addresses[0].priority,
            FIPS_PRIVATE_DYNAMIC_PEER_ENDPOINT_PRIORITY
        );
        assert!(
            transit_config.discovery_fallback_transit,
            "hinted non-roster peers should be usable as fallback transit"
        );
        assert!(
            !transit_config.auto_reconnect,
            "hinted non-roster transit peers should not retry forever"
        );
    }

    #[test]
    fn mobile_fips_config_does_not_advertise_without_peers() {
        let config = fips_endpoint_config("nostr-vpn:test", &empty_config());

        config
            .validate()
            .expect("empty mobile FIPS config should validate");
        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert!(!config.node.discovery.lan.enabled);
        for udp in mobile_udp_carriers(&config).values() {
            assert!(!udp.advertise_on_nostr());
            assert!(udp.accept_connections());
        }
        assert!(config.peers.is_empty());
    }

    #[test]
    fn mobile_fips_config_advertises_pending_join_request_return_path() {
        let admin = Keys::generate().public_key().to_hex();
        let mobile = MobileTunnelConfig {
            pending_join_request_recipient: admin,
            pending_join_requested_at: 1,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(config.node.discovery.nostr.enabled);
        assert!(
            config.node.discovery.nostr.advertise,
            "the admin must be able to discover the pending joiner's encrypted return path"
        );
        assert_eq!(config.node.discovery.nostr.policy, NostrDiscoveryPolicy::Open);
        assert!(config.peers.is_empty());
    }
