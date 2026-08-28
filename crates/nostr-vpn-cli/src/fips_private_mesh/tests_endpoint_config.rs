    #[test]
    fn endpoint_config_respects_requested_nostr_policy() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(!config.node.control.enabled);
        assert_eq!(config.node.routing.mode, RoutingMode::ReplyLearned);
        assert!(!config.dns.enabled);
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
            config.node.retry.base_interval_secs,
            FIPS_RECONNECT_BACKOFF_BASE_SECS
        );
        assert_eq!(
            config.node.retry.max_backoff_secs,
            FIPS_RECONNECT_BACKOFF_MAX_SECS
        );
        assert_eq!(
            config.node.heartbeat_interval_secs,
            FIPS_ENDPOINT_HEARTBEAT_INTERVAL_SECS
        );
        assert_eq!(
            config.node.link_dead_timeout_secs,
            FIPS_ENDPOINT_LINK_DEAD_TIMEOUT_SECS
        );
        assert_eq!(
            config.node.fast_link_dead_timeout_secs,
            FIPS_ENDPOINT_FAST_LINK_DEAD_TIMEOUT_SECS
        );
        assert_eq!(
            config.node.session.idle_timeout_secs,
            FIPS_ENDPOINT_SESSION_IDLE_TIMEOUT_SECS
        );
        assert_eq!(
            config.node.session.pending_packets_per_dest,
            FIPS_ENDPOINT_PENDING_PACKETS_PER_DEST
        );
        assert_eq!(config.node.rekey.after_secs, FIPS_ENDPOINT_REKEY_AFTER_SECS);
        assert!(config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open
        );
        let configured_only_config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::ConfiguredOnly,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );
        assert_eq!(
            configured_only_config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            FIPS_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert_eq!(
            config.node.discovery.nostr.extended_cooldown_secs,
            FIPS_NOSTR_EXTENDED_COOLDOWN_SECS
        );
        assert_eq!(config.node.discovery.nostr.failure_streak_threshold, 3);
        assert_eq!(config.node.discovery.nostr.extended_cooldown_secs, 1_800);
        assert_eq!(
            config.node.discovery.nostr.startup_sweep_max_age_secs,
            FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS
        );
        assert!(!config.node.discovery.nostr.share_local_candidates);
        assert!(!config.node.discovery.lan.enabled);
        // The mesh id must NOT appear in the publicly visible relay app tag.
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        let udp = udp_carriers(&config);
        assert_eq!(udp[FIPS_UDP_IPV4_TRANSPORT].bind_addr(), "0.0.0.0:0");
        assert_eq!(udp[FIPS_UDP_IPV6_TRANSPORT].bind_addr(), "[::]:0");
        for udp in udp.values() {
            assert!(udp.outbound_only());
            assert!(!udp.advertise_on_nostr());
            assert!(!udp.accept_connections());
            assert_eq!(udp.send_buf_size, super::DEFAULT_FIPS_UDP_SEND_BUF_SIZE);
        }
        assert_eq!(config.peers.len(), 1);
        assert!(config.peers[0].addresses.is_empty());
    }

    #[test]
    fn endpoint_config_disables_lan_discovery_in_static_only_mode() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let transport = endpoint_transport("192.168.50.20:51820", false, false, true);
        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::ConfiguredOnly,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert!(!config.node.discovery.nostr.share_local_candidates);
        assert!(!config.node.discovery.lan.enabled);
        for udp in udp_carriers(&config).values() {
            assert!(!udp.outbound_only());
            assert!(!udp.advertise_on_nostr());
            assert!(udp.accept_connections());
        }
    }

    #[test]
    fn lan_discovery_scope_is_hashed_from_network_id() {
        let scope = fips_lan_discovery_scope(" private-network-id ");
        assert!(scope.starts_with(&format!("{FIPS_LAN_DISCOVERY_SCOPE_PREFIX}:")));
        assert!(!scope.contains("private-network-id"));
        assert_eq!(scope, fips_lan_discovery_scope("private-network-id"));
    }

    #[test]
    fn endpoint_config_uses_stun_when_public_advert_has_private_app_endpoint() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let mut transport = endpoint_transport("192.168.50.20:51820", true, true, true);
        transport.stun_servers = vec!["stun:stun.example.org:3478".to_string()];
        transport.nostr_relays = vec!["wss://relay.example.org".to_string()];

        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            FIPS_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert_eq!(
            config.node.discovery.nostr.extended_cooldown_secs,
            FIPS_NOSTR_EXTENDED_COOLDOWN_SECS
        );
        assert!(config.node.discovery.nostr.share_local_candidates);
        assert!(config.node.discovery.lan.enabled);
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        assert_eq!(
            config.node.discovery.nostr.stun_servers,
            vec!["stun:stun.example.org:3478".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.advert_relays,
            vec!["wss://relay.example.org".to_string()]
        );
        let udp = &udp_carriers(&config)[FIPS_UDP_IPV4_TRANSPORT];
        assert_eq!(udp.bind_addr.as_deref(), Some("0.0.0.0:51820"));
        assert!(!udp.outbound_only());
        assert!(udp.advertise_on_nostr());
        assert!(udp.is_public());
        assert!(udp.accept_connections());
        assert_eq!(udp.external_addr.as_deref(), None);
        assert_eq!(config.peers.len(), 1);
    }

    #[test]
    fn endpoint_config_advertises_public_app_endpoint_over_nostr() {
        let transport = endpoint_transport("198.51.100.20:51820", true, true, false);

        let config = fips_endpoint_config_with_open_discovery_limit(
            &[],
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );
        let udp = &udp_carriers(&config)[FIPS_UDP_IPV4_TRANSPORT];

        assert!(udp.advertise_on_nostr());
        assert!(udp.is_public());
        assert_eq!(udp.external_addr.as_deref(), Some("198.51.100.20:51820"));
    }

    #[test]
    fn endpoint_config_disables_nostr_when_discovery_off() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("peer config");
        let mut transport = endpoint_transport("192.168.50.20:51820", true, false, true);
        transport.stun_servers = vec!["stun:stun.example.org:3478".to_string()];
        transport.nostr_relays = vec!["wss://relay.example.org".to_string()];

        let endpoint_peers = fips_endpoint_peers_from_mesh(&[peer], Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        // Relay discovery + advertising are off, but the peer is still dialed
        // directly so static/bootstrap connectivity keeps working.
        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        for udp in udp_carriers(&config).values() {
            assert!(!udp.advertise_on_nostr());
            assert!(udp.accept_connections());
        }
        assert_eq!(config.peers.len(), 1);
    }

    #[test]
    fn endpoint_config_keeps_static_transit_peers_outside_mesh_routes() {
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("npub");
        let mesh_peer =
            FipsMeshPeerConfig::from_participant_pubkey(&bob_pubkey, vec!["10.44.1.2/32".into()])
                .expect("mesh peer");
        let endpoint_peers = fips_endpoint_peers_from_mesh(
            std::slice::from_ref(&mesh_peer),
            vec![(charlie_npub.clone(), vec!["10.203.0.12:51820".to_string()])],
            Vec::new(),
        );
        let transport = endpoint_transport("10.203.0.10:51820", false, true, false);

        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert!(!config.node.discovery.lan.enabled);
        let udp = &udp_carriers(&config)[FIPS_UDP_IPV4_TRANSPORT];
        assert!(udp.advertise_on_nostr());
        assert!(!udp.is_public());
        assert_eq!(udp.external_addr.as_deref(), None);
        assert_eq!(endpoint_peers.len(), 2);
        assert_eq!(config.peers.len(), 2);
        let bob = config
            .peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should be configured");
        assert!(bob.addresses.is_empty());
        assert!(
            bob.auto_reconnect,
            "roster peers should keep nvpn's fast auto-reconnect"
        );
        assert!(
            bob.discovery_fallback_transit,
            "roster peer should be eligible for private lookup transit"
        );
        let charlie = config
            .peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("static transit peer should be configured");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].transport, "udp");
        assert_eq!(charlie.addresses[0].addr, "10.203.0.12:51820");
        assert!(
            charlie.auto_reconnect,
            "operator-configured control peers should reconnect for relayless gossip"
        );
        assert!(
            charlie.discovery_fallback_transit,
            "operator-configured transit peers are explicit lookup transit"
        );
    }

    #[test]
    fn endpoint_config_keeps_default_route_roster_peers_as_transit() {
        let exit_keys = Keys::generate();
        let exit_pubkey = exit_keys.public_key().to_hex();
        let mesh_peer = FipsMeshPeerConfig::from_participant_pubkey(
            &exit_pubkey,
            vec!["10.44.1.2/32".into(), "0.0.0.0/0".into()],
        )
        .expect("mesh peer");

        let endpoint_peers =
            fips_endpoint_peers_from_mesh(std::slice::from_ref(&mesh_peer), Vec::new(), Vec::new());

        let peer = endpoint_peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should be configured");
        assert!(
            peer.auto_reconnect,
            "roster peers should keep nvpn's fast auto-reconnect"
        );
        assert!(
            peer.discovery_fallback_transit,
            "an exit-capable roster peer may also be the only path to its LAN peers"
        );
    }

    #[test]
    fn stamped_endpoint_hints_create_transit_only_non_roster_peers() {
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let mesh_peer =
            FipsMeshPeerConfig::from_participant_pubkey(&bob_pubkey, vec!["10.44.1.2/32".into()])
                .expect("mesh peer");

        let endpoint_peers = fips_endpoint_peers_from_mesh(
            std::slice::from_ref(&mesh_peer),
            Vec::new(),
            vec![(
                charlie_pubkey,
                vec![("10.203.0.12:51820".to_string(), 123_000)],
            )],
        );

        assert_eq!(endpoint_peers.len(), 2);
        let bob = endpoint_peers
            .iter()
            .find(|peer| peer.npub == mesh_peer.endpoint_npub)
            .expect("mesh peer should remain configured");
        assert!(bob.addresses.is_empty());
        assert!(
            bob.auto_reconnect,
            "roster peers should keep nvpn's fast auto-reconnect"
        );
        let charlie = endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("recent authenticated peer should seed FIPS transit");
        assert_eq!(charlie.addresses[0].seen_at_ms, Some(123_000));
        assert!(!charlie.auto_reconnect);
        assert!(charlie.discovery_fallback_transit);
    }
