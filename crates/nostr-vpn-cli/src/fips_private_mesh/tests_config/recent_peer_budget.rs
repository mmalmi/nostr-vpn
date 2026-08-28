    #[test]
    fn tunnel_config_caps_recent_non_roster_transit_peers() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let network_id = "fips-recent-transit-cap-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = true;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_bootstrap_enabled = false;

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&bob_pubkey, "1.1.1.1:51820", 1));

        let mut non_roster_npubs = Vec::new();
        for i in 0..(FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING + 2) {
            let keys = Keys::generate();
            let pubkey = keys.public_key().to_hex();
            let npub = keys.public_key().to_bech32().expect("transit npub");
            let addr = format!("1.1.1.{}:51820", i + 2);
            assert!(recent.note_success(&pubkey, &addr, 100 + i as u64));
            non_roster_npubs.push(npub);
        }

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("roster peer recent hint should be retained");
        assert_eq!(bob.addresses.len(), 1);
        assert_eq!(bob.addresses[0].addr, "1.1.1.1:51820");

        let seeded_non_roster = config
            .endpoint_peers
            .iter()
            .filter(|peer| non_roster_npubs.iter().any(|npub| npub == &peer.npub))
            .collect::<Vec<_>>();
        assert_eq!(
            seeded_non_roster.len(),
            FIPS_RECENT_NON_ROSTER_TRANSIT_MAX_SEEDS
        );
        assert!(
            seeded_non_roster
                .iter()
                .all(|peer| !peer.auto_reconnect && peer.discovery_fallback_transit)
        );
        assert_eq!(
            config.open_discovery_max_pending,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING
                - FIPS_RECENT_NON_ROSTER_TRANSIT_MAX_SEEDS,
            "cached transit seeds must leave capacity for fresh discovery"
        );
    }

    #[test]
    fn config_reload_does_not_restart_for_recent_peer_admission_budget_drift() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let ambient_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let ambient_pubkey = ambient_keys.public_key().to_hex();
        let network_id = "fips-reload-recent-peer-budget-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = true;
        app.fips_bootstrap_enabled = false;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey];

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&ambient_pubkey, "1.1.1.2:51820", 1));

        let current = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("current fips tunnel config");
        let consistent_reload = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("reloaded fips tunnel config");
        let dropped_cache = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("cache-free fips tunnel config");

        assert_eq!(
            current.open_discovery_max_pending,
            consistent_reload.open_discovery_max_pending
        );
        assert!(!fips_tunnel_requires_endpoint_restart(
            &current,
            &consistent_reload
        ));
        assert_ne!(
            current.open_discovery_max_pending,
            dropped_cache.open_discovery_max_pending,
            "dropping authenticated recent peers changes the admission budget"
        );
        assert!(
            !fips_tunnel_requires_endpoint_restart(&current, &dropped_cache),
            "transient recent-peer budget drift must not flap the endpoint"
        );
    }
