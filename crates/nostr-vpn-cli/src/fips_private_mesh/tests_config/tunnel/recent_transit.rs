    #[test]
    fn tunnel_config_seeds_recent_transit_without_granting_routes() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-recent-transit-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = true;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&charlie_pubkey, "203.0.113.55:51820", 123));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert!(
            config
                .peers
                .iter()
                .all(|peer| peer.participant_pubkey != charlie_pubkey),
            "non-roster transit peers must not get private-network routes",
        );
        let charlie = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("authenticated non-roster peer should seed FIPS transit");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].addr, "203.0.113.55:51820");
        assert_eq!(charlie.addresses[0].seen_at_ms, Some(123_000));
        assert!(!charlie.auto_reconnect);
        assert!(charlie.discovery_fallback_transit);
    }

    #[test]
    fn tunnel_config_drops_non_roster_transit_when_discovery_not_open() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-configured-only-transit-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = false;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_bootstrap_peers.clear();
        app.fips_bootstrap_peers.insert(
            charlie_npub.clone(),
            vec!["203.0.113.55:51820".to_string()],
        );

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&bob_pubkey, "1.1.1.1:51820", 123));
        assert!(recent.note_success(&charlie_pubkey, "203.0.113.66:51820", 456));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert_eq!(config.nostr_discovery_policy, NostrDiscoveryPolicy::ConfiguredOnly);
        assert_eq!(config.open_discovery_max_pending, 0);
        assert!(
            config.endpoint_peers.iter().any(|peer| peer.npub == bob_npub),
            "roster recent hints should still be retained"
        );
        assert!(
            config.endpoint_peers.iter().all(|peer| peer.npub != charlie_npub),
            "configured-only discovery must not seed non-roster transit peers"
        );
    }

    #[test]
    fn tunnel_config_uses_only_static_endpoint_hints_when_discovery_disabled() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-static-only-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.fips_nostr_discovery_enabled = false;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_peer_endpoints
            .insert(bob_npub.clone(), vec!["192.168.64.5:52528".to_string()]);
        app.fips_peer_endpoints.insert(
            charlie_npub.clone(),
            vec!["192.168.64.6:52528".to_string()],
        );

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&bob_pubkey, "198.51.100.7:52528", 123));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[(
                bob_pubkey.clone(),
                vec![("198.51.100.8:52528".to_string(), 456_000)],
            )],
        )
        .expect("fips tunnel config");

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("bob endpoint peer");
        assert_eq!(bob.addresses.len(), 1);
        assert_eq!(bob.addresses[0].addr, "192.168.64.5:52528");
        assert_eq!(bob.addresses[0].seen_at_ms, None);
        assert!(
            !bob.discovery_fallback_transit,
            "static-only peers must not become lookup transit"
        );

        let charlie = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("operator-configured non-roster transit peer");
        assert!(charlie.auto_reconnect);
        assert!(
            charlie.discovery_fallback_transit,
            "an explicit non-roster static peer is the fallback transit path when ambient discovery is disabled"
        );
        assert!(
            config
                .peers
                .iter()
                .all(|peer| peer.endpoint_npub != charlie_npub),
            "fallback transit must not become a private-network route target"
        );
    }
