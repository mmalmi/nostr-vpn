    #[test]
    fn unconfirmed_manual_join_stays_out_of_the_mesh_until_admin_roster_arrives() {
        let admin_keys = Keys::generate();
        let admin = admin_keys.public_key().to_hex();
        let mut app = AppConfig::generated_without_networks();
        app.add_manual_join_network(&admin, "manual-mesh")
            .expect("configure manual join");

        let config = MobileTunnelConfig::from_app(&app).expect("manual bootstrap config");

        assert!(config.network_id.is_empty());
        assert!(config.peers.is_empty());
        assert!(config.route_targets.is_empty());
        assert!(
            config.dns_servers.is_empty(),
            "an addressless joiner must keep using the device DNS until a roster arrives"
        );
        assert!(
            config.magic_dns_server.is_empty(),
            "MagicDNS is unavailable before the joiner has a mesh"
        );
        assert!(config.dns_match_domains.is_empty());
        assert_eq!(app.active_network().network_id, "manual-mesh");
        assert_eq!(app.active_network().join_request_admin, admin);

        let signed_without_joiner = SignedRoster::sign(
            "manual-mesh",
            NetworkRoster {
                network_name: "Manual mesh".to_string(),
                devices: Vec::new(),
                admins: vec![admin],
                aliases: HashMap::new(),
                signed_at: unix_timestamp(),
            },
            &admin_keys,
        )
        .expect("sign admin roster without joiner");
        assert!(
            app.apply_verified_admin_signed_shared_roster(&signed_without_joiner)
                .expect("apply configured admin roster")
        );

        let still_pending =
            MobileTunnelConfig::from_app(&app).expect("pending manual bootstrap config");
        assert!(
            still_pending.network_id.is_empty(),
            "an unrelated signed roster must not move an unaccepted manual join into the mesh"
        );
        assert!(still_pending.peers.is_empty());
        assert!(still_pending.route_targets.is_empty());
        assert!(still_pending.dns_servers.is_empty());
        assert!(still_pending.magic_dns_server.is_empty());
        assert!(still_pending.dns_match_domains.is_empty());
    }

    #[test]
    fn mobile_admin_listener_without_roster_peers_discovers_without_advertising() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: Vec::new(),
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        // Isolate the admin-listener behavior from the built-in bootstrap nodes,
        // which would otherwise populate config.peers as fallback transit.
        app.fips_bootstrap_enabled = false;
        app.ensure_defaults();

        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(mobile.join_requests_enabled);
        assert!(mobile.peers.is_empty());
        assert!(config.node.discovery.nostr.enabled);
        assert!(
            !config.node.discovery.nostr.advertise,
            "a known approval npub routes through discovery transit without a public advert"
        );
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(config.peers.is_empty());
    }

    #[test]
    fn mobile_config_uses_only_operator_supplied_bootstrap_transit_peers() {
        let mut app = AppConfig::generated();
        app.connect_to_non_roster_fips_peers = true;
        app.fips_bootstrap_enabled = true;
        app.set_fips_bootstrap_peers(std::collections::HashMap::from([(
            "npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8"
                .to_string(),
            vec!["tcp:45.79.10.10:443".to_string()],
        )]));
        app.ensure_defaults();
        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        let configured = config
            .peers
            .iter()
            .find(|peer| {
                peer.npub
                    == "npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8"
            })
            .expect("operator bootstrap peer");
        assert!(
            configured
                .addresses
                .iter()
                .any(|address| address.addr == "45.79.10.10:443")
        );
        assert!(configured.discovery_fallback_transit);
        assert!(
            !configured.auto_reconnect,
            "bootstrap/transit peers should not use nvpn roster-style fast reconnect"
        );
        assert!(mobile.nostr_discovery_enabled);
    }

    #[test]
    fn mobile_config_identity_pins_each_default_bootstrap_peer_once() {
        let app = AppConfig::generated();
        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        let TransportInstances::Single(websocket) = &config.transports.websocket else {
            panic!("expected canonical WebSocket transport");
        };
        assert_eq!(
            websocket.seed_urls,
            nostr_vpn_core::config::default_fips_websocket_seed_urls()
        );
        assert_eq!(
            config.peers.len(),
            nostr_vpn_core::config::DEFAULT_FIPS_WEBSOCKET_SEEDS.len()
        );
        for (expected_npub, expected_url) in
            nostr_vpn_core::config::DEFAULT_FIPS_WEBSOCKET_SEEDS
        {
            let matching = config
                .peers
                .iter()
                .filter(|peer| peer.npub == *expected_npub)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1, "seed PeerConfig must not be duplicated");
            assert!(matching[0].addresses.iter().any(|address| {
                address.transport == "websocket" && address.addr == *expected_url
            }));
            assert!(
                matching[0]
                    .addresses
                    .iter()
                    .any(|address| address.transport == "udp"),
                "native bootstrap peers should retain their preferred UDP path"
            );
        }
    }

    #[test]
    fn mobile_config_omits_bootstrap_and_relays_when_disabled() {
        let mut app = AppConfig::generated();
        app.fips_bootstrap_enabled = false;
        app.fips_nostr_discovery_enabled = false;
        app.ensure_defaults();
        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(config.peers.is_empty());
        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
    }

    #[test]
    fn pending_mobile_join_request_targets_join_admin() {
        let admin = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        let expected_recipient = FipsMeshPeerConfig::from_participant_pubkey(admin, Vec::new())
            .expect("recipient")
            .endpoint_npub;
        let mobile = MobileTunnelConfig {
            network_id: "mesh-home".to_string(),
            node_name: "iPhone".to_string(),
            pending_join_request_recipient: admin.to_string(),
            pending_join_requested_at: 1_778_998_000,
            ..empty_config()
        };

        let (recipient, frame) = pending_mobile_join_request_frame(&mobile)
            .expect("join request frame")
            .expect("pending frame");

        assert_eq!(recipient, expected_recipient);
        assert_eq!(
            frame,
            FipsControlFrame::JoinRequest {
                requested_at: 1_778_998_000,
                request: MeshJoinRequest {
                    network_id: "mesh-home".to_string(),
                    join_secret: String::new(),
                    requester_node_name: "iPhone".to_string(),
                },
            }
        );
    }
