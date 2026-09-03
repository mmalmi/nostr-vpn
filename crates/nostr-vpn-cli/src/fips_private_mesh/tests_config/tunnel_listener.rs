    #[test]
    fn websocket_listener_reserves_a_bounded_public_adjacency_budget() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let ambient_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let ambient_pubkey = ambient_keys.public_key().to_hex();
        let ambient_npub = ambient_keys
            .public_key()
            .to_bech32()
            .expect("ambient npub");
        let network_id = "fips-websocket-listener-admission-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = true;
        app.fips_websocket_bind_addr = "127.0.0.1:8765".to_string();
        app.fips_websocket_public_url = "wss://seed.example/fips".to_string();
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];

        let mut recent = nostr_vpn_core::recent_peers::RecentPeerEndpoints::new(
            alice_npub,
            nostr_vpn_core::recent_peers::recent_peers_scope(network_id),
        )
        .expect("recent peer cache");
        assert!(recent.note_success(&bob_pubkey, "198.51.100.10:51820", 1));
        assert!(recent.note_success(&ambient_pubkey, "198.51.100.11:51820", 2));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert_eq!(
            config.open_discovery_max_pending,
            FIPS_WEBSOCKET_LISTENER_OPEN_DISCOVERY_MAX_PENDING,
        );
        assert!(
            config.open_discovery_max_pending > FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
            "a public WSS listener must not share the small endpoint admission budget"
        );
        assert_eq!(
            config.websocket.max_connections(),
            FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS,
        );
        assert_eq!(
            config.websocket.max_inbound_connections(),
            FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS,
        );
        assert_eq!(
            config.websocket.idle_timeout_secs(),
            FIPS_PUBLIC_WEBSOCKET_IDLE_TIMEOUT_SECS,
        );
        assert!(
            config.endpoint_peers.iter().any(|peer| peer.npub == bob_npub),
            "roster peers must retain recent direct-path hints"
        );
        assert!(
            !config
                .endpoint_peers
                .iter()
                .any(|peer| peer.npub == ambient_npub),
            "a public WSS listener must not persist ambient peers as auto-reconnect seeds"
        );
    }

    #[test]
    fn public_seed_with_udp_and_websocket_keeps_one_canonical_dialer() {
        let mut identities = [Keys::generate(), Keys::generate()];
        identities.sort_by_key(|keys| keys.public_key().to_bech32().expect("npub"));
        let [listener_keys, peer_keys] = identities;
        let listener_pubkey = listener_keys.public_key().to_hex();
        let peer_npub = peer_keys.public_key().to_bech32().expect("peer npub");

        let mut app = AppConfig::default();
        app.nostr.secret_key = listener_keys
            .secret_key()
            .to_bech32()
            .expect("listener nsec");
        app.connect_to_non_roster_fips_peers = true;
        app.fips_websocket_bind_addr = "127.0.0.1:8765".to_string();
        app.fips_websocket_public_url = "wss://listener.example/fips".to_string();
        app.fips_bootstrap_peers = HashMap::from([(
            peer_npub.clone(),
            vec![
                "seed.example.org:51820".to_string(),
                "websocket:wss://seed.example.org/fips".to_string(),
            ],
        )]);
        app.networks[0].enabled = true;
        app.networks[0].network_id = "public-seed-canonical-dial".to_string();
        app.networks[0].devices = vec![listener_pubkey.clone()];

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "public-seed-canonical-dial",
            "utun-test",
            Some(&listener_pubkey),
            None,
            &[],
        )
        .expect("public seed config");
        let peer = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == peer_npub)
            .expect("configured bootstrap seed");

        assert!(
            !peer.connect_on_start,
            "the lower public seed must stay configured but accept the canonical inbound dial"
        );
        assert!(peer.auto_reconnect);
        assert!(peer.discovery_fallback_transit);
    }
