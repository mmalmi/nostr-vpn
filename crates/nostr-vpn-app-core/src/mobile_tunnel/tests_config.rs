    #[test]
    fn mobile_endpoint_send_run_batches_consecutive_resolved_peer() {
        let participant = Keys::generate().public_key().to_hex();
        let participant_key = mobile_participant_pubkey_bytes(&participant).expect("participant");
        let endpoint_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let identity = PeerIdentity::from_npub(&endpoint_npub).expect("peer identity");
        let endpoint_node_addr = *identity.node_addr().as_bytes();
        let mut identity_map = MobilePeerIdentityMap::default();
        identity_map
            .by_endpoint_node_addr
            .insert(endpoint_node_addr, identity);
        let identities = Arc::new(RwLock::new(identity_map));
        let mut run = None;

        assert!(
            push_mobile_endpoint_send_run(
                &mut run,
                &identities,
                None,
                Some(participant_key),
                endpoint_node_addr,
                vec![1],
            )
            .is_none()
        );
        assert!(
            push_mobile_endpoint_send_run(
                &mut run,
                &identities,
                None,
                Some(participant_key),
                endpoint_node_addr,
                vec![2],
            )
            .is_none()
        );

        let Some(MobileEndpointSendRun {
            participant_fallback: run_participant_fallback,
            participant_key: run_participant_key,
            identity: run_identity,
            payloads,
            packet_count,
            ..
        }) = run.as_ref()
        else {
            panic!("resolved peer should own an identity send run");
        };
        assert!(run_participant_fallback.is_none());
        assert_eq!(*run_participant_key, Some(participant_key));
        assert_eq!(*run_identity, identity);
        assert_eq!(*packet_count, 2);
        assert_eq!(*payloads, vec![vec![1], vec![2]]);

        let previous = push_mobile_endpoint_send_run(
            &mut run,
            &identities,
            Some("other".to_string()),
            None,
            [9; 16],
            vec![3],
        )
        .expect("peer change should flush previous run");
        let MobileEndpointSendRun {
            packet_count,
            payloads,
            ..
        } = previous;
        assert_eq!(packet_count, 2);
        assert_eq!(payloads, vec![vec![1], vec![2]]);
        assert!(run.is_none());
    }

    #[test]
    fn mobile_config_keeps_default_route_during_protected_exit_selection() {
        for internet_source in [
            "private_vpn",
            "paid_automatic",
            "paid_manual",
        ] {
            let mut route_targets = Vec::new();

            preserve_mobile_pending_exit_default_routes(
                &mut route_targets,
                "",
                true,
                Some(internet_source),
            );

            assert!(
                route_targets.iter().any(|route| route == "0.0.0.0/0"),
                "{internet_source:?} must capture traffic while exit selection is pending"
            );
        }
    }

    #[test]
    fn mobile_config_does_not_capture_pending_exit_without_leak_protection() {
        let mut route_targets = Vec::new();

        preserve_mobile_pending_exit_default_routes(
            &mut route_targets,
            "",
            false,
            Some("paid_automatic"),
        );

        assert!(!route_targets.iter().any(|route| route == "0.0.0.0/0"));
    }

    #[test]
    fn mobile_manual_paid_provider_is_an_addressless_transit_routable_control_peer() {
        let provider = Keys::generate();
        let provider_npub = provider.public_key().to_bech32().expect("provider npub");
        let provider_pubkey = provider.public_key().to_hex();
        let bootstrap = Keys::generate();
        let bootstrap_npub = bootstrap.public_key().to_bech32().expect("bootstrap npub");
        let mut app = AppConfig::generated_without_networks();
        app.ensure_defaults();
        app.set_manual_paid_exit_provider(&provider_npub)
            .expect("manual provider");
        app.fips_nostr_discovery_enabled = false;
        app.fips_websocket_seed_urls.clear();
        app.connect_to_non_roster_fips_peers = true;
        app.set_fips_bootstrap_peers(HashMap::from([(
            bootstrap_npub,
            vec!["192.168.50.20:51820".to_string()],
        )]));

        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let provider_peer = mobile
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == provider_pubkey)
            .expect("manual provider control peer");
        assert!(provider_peer.allowed_ips.is_empty());
        assert!(!mobile.route_targets.iter().any(|route| route == "0.0.0.0/0"));

        let endpoint = fips_endpoint_config("manual-provider", &mobile);
        let provider_endpoint = endpoint
            .peers
            .iter()
            .find(|peer| peer.npub == provider_npub)
            .expect("manual provider endpoint peer");
        assert!(provider_endpoint.addresses.is_empty());
        assert!(provider_endpoint.discovery_fallback_transit);
        assert!(!endpoint.node.discovery.nostr.enabled);
        assert_eq!(
            endpoint.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(endpoint.peers.iter().any(|peer| !peer.addresses.is_empty()));
    }

    #[test]
    fn mobile_peer_ping_due_recovers_from_future_timestamps() {
        assert!(!mobile_peer_ping_due(Some(122), Some(115), false, 120));
        assert!(!mobile_peer_ping_due(Some(180), Some(1), false, 120));
        assert!(!mobile_peer_ping_due(None, Some(122), false, 120));
        assert!(mobile_peer_ping_due(None, Some(180), false, 120));
    }

    #[test]
    fn offline_peer_probe_uses_battery_safe_fallback_interval() {
        assert!(!mobile_peer_ping_due(None, Some(0), false, 299));
        assert!(mobile_peer_ping_due(None, Some(0), false, 300));
    }

    #[test]
    fn configured_transit_is_pinged_before_the_fips_link_can_expire() {
        assert!(!mobile_peer_ping_due(None, Some(0), true, 9));
        assert!(mobile_peer_ping_due(None, Some(0), true, 10));
    }

    #[test]
    fn ping_participants_include_only_roster_and_configured_transit_peers() {
        let roster = Keys::generate().public_key().to_hex();
        let transit = Keys::generate().public_key().to_hex();
        let hint = FipsPeerAddressHint {
            priority: 0,
            addr: "udp://127.0.0.1:1".to_string(),
            seen_at_ms: None,
        };
        let bootstrap_peers = HashMap::from([
            (transit.clone(), vec![hint.clone()]),
            ("invalid ambient peer".to_string(), vec![hint]),
        ]);

        let participants = mobile_ping_participants(vec![roster.clone()], &bootstrap_peers);
        let mut expected = vec![(roster, false), (transit, true)];
        expected.sort();

        assert_eq!(participants, expected);
    }

    #[test]
    fn background_maintenance_uses_low_wakeup_intervals() {
        assert_eq!(MOBILE_RUNTIME_STATE_REFRESH_SECS, 10);
        assert_eq!(MOBILE_PEER_ACTIVE_PING_INTERVAL_SECS, 30);
        assert_eq!(MOBILE_ROSTER_RESEND_SECS, 60);
        assert_eq!(MOBILE_CAPABILITIES_BROADCAST_SECS, 60);
    }

    #[test]
    fn mobile_connected_roster_peers_rejects_far_future_presence() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own.clone()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
            config.peers.clone(),
            vec![],
        ));
        let now = unix_timestamp();
        let presence = Arc::new(RwLock::new(HashMap::from([(
            peer.to_string(),
            MobilePeerPresence {
                last_seen_at: Some(now + 60),
                ..MobilePeerPresence::default()
            },
        )])));

        let connected = mobile_connected_roster_peers(&mesh, &presence).expect("connected peers");

        assert!(connected.is_empty());
    }

    #[test]
    fn mobile_runtime_state_keeps_retry_only_probe_separate_from_link() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own.clone()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = FipsMeshRuntime::with_local_routes(config.peers.clone(), vec![]);
        let now = 1_778_998_000;
        let mut presence = HashMap::new();
        presence.insert(
            peer.to_string(),
            MobilePeerPresence {
                last_seen_at: Some(now - 4),
                ..MobilePeerPresence::default()
            },
        );
        let endpoint_node_addr = *PeerIdentity::from_npub(&config.peers[0].endpoint_npub)
            .expect("endpoint identity")
            .node_addr();
        let endpoint_peer = FipsEndpointPeer {
            npub: config.peers[0].endpoint_npub.clone(),
            node_addr: endpoint_node_addr,
            connected: false,
            transport_addr: None,
            transport_type: None,
            link_id: 0,
            srtt_ms: None,
            srtt_age_ms: None,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: true,
            direct_probe_after_ms: Some(98_765),
            direct_probe_retry_count: 2,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: Some(123_456),
            nostr_traversal_consecutive_failures: 2,
            nostr_traversal_in_cooldown: true,
            nostr_traversal_cooldown_until_ms: Some(99_000),
            nostr_traversal_last_observed_skew_ms: Some(200),
        };

        let state = mobile_runtime_state_with_tun_counters(
            &config,
            &mesh,
            &presence,
            vec![endpoint_peer],
            Vec::new(),
            MobileTunCounters::default(),
            now,
        );

        assert_eq!(state.connected_peer_count, 1);
        assert!(state.peers[0].reachable);
        assert!(state.peers[0].direct_probe_pending);
        assert_eq!(state.peers[0].direct_probe_after_ms, Some(98_765));
        assert_eq!(state.peers[0].direct_probe_retry_count, 2);
        assert!(!state.peers[0].direct_probe_auto_reconnect);
        assert_eq!(state.peers[0].direct_probe_expires_at_ms, Some(123_456));
        assert_eq!(state.peers[0].fips_nostr_traversal_failures, 2);
        assert!(state.peers[0].fips_nostr_traversal_in_cooldown);
        assert_eq!(
            state.peers[0].fips_nostr_traversal_cooldown_until_ms,
            Some(99_000)
        );
        assert_eq!(
            state.peers[0].fips_nostr_traversal_last_observed_skew_ms,
            Some(200)
        );
        assert_eq!(state.peers[0].fips_transport_addr, "");
        assert_eq!(state.peers[0].last_fips_seen_at, Some(now - 4));
    }

    #[test]
    fn mobile_endpoint_hints_include_current_lan_candidates() {
        let mobile = MobileTunnelConfig {
            advertised_endpoint: "192.168.50.22:51820".to_string(),
            listen_port: 51820,
            local_address: "10.44.1.2/32".to_string(),
            share_local_candidates: true,
            ..empty_config()
        };

        let hints = mobile_endpoint_hints_with_candidates(
            &mobile,
            vec![
                Ipv4Addr::new(192, 168, 50, 33),
                Ipv4Addr::new(10, 44, 1, 2),
                Ipv4Addr::new(100, 100, 50, 1),
            ],
        );
        let addrs = hints.into_iter().map(|hint| hint.addr).collect::<Vec<_>>();

        assert_eq!(
            addrs,
            vec![
                "192.168.50.22:51820".to_string(),
                "192.168.50.33:51820".to_string(),
            ]
        );
    }

    #[test]
    fn mobile_config_wireguard_exit_keeps_mesh_peer_routes_narrow() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own.clone()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.wireguard_exit = WireGuardExitConfig {
            enabled: true,
            address: "10.99.99.2/32".to_string(),
            private_key: "client-private-key".to_string(),
            peer_public_key: "server-public-key".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            ..WireGuardExitConfig::default()
        };

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        );
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );

        let peer_routes = config
            .route_targets
            .iter()
            .filter(|route| route.as_str() != "0.0.0.0/0")
            .filter(|route| route.as_str() != MESH_TUNNEL_IPV4_CIDR)
            .collect::<Vec<_>>();
        assert_eq!(peer_routes.len(), 1);
        assert!(peer_routes[0].starts_with("10."));
        assert!(peer_routes[0].ends_with("/32"));
        assert_eq!(config.peers[0].allowed_ips, vec![peer_routes[0].clone()]);

        let wg_config = config.wireguard_exit.as_ref().expect("wg config");
        assert_eq!(wg_config.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(wg_config.persistent_keepalive_secs, 25);
        assert_eq!(config.excluded_routes, vec!["198.51.100.20/32"]);
        assert_eq!(
            config.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
        assert_eq!(
            config.magic_dns_server,
            nostr_vpn_core::MESH_MAGIC_DNS_SERVER
        );
        assert_eq!(config.dns_match_domains, vec![""]);

        app.wireguard_exit.endpoint = "[2001:db8::20]:51820".to_string();
        let ipv6_transport =
            MobileTunnelConfig::from_app(&app).expect("IPv6 WG transport config");
        let ipv6_wg = ipv6_transport
            .wireguard_exit
            .as_ref()
            .expect("IPv6 WG config");
        assert_eq!(ipv6_wg.endpoint, "[2001:db8::20]:51820");
        assert!(ipv6_transport.excluded_routes.is_empty());
        assert!(
            ipv6_transport
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        assert!(
            ipv6_transport
                .local_address
                .split_once('/')
                .and_then(|(address, _)| address.parse::<Ipv4Addr>().ok())
                .is_some()
        );
        assert_eq!(
            ipv6_transport.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
    }

    #[test]
    fn mobile_config_wireguard_exit_keeps_local_stub_and_uses_profile_dns_only_while_active() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![own.clone()],
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
        app.wireguard_exit = WireGuardExitConfig {
            enabled: true,
            address: "10.99.99.2/32".to_string(),
            private_key: "client-private-key".to_string(),
            peer_public_key: "server-public-key".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["94.140.14.14".to_string()],
            ..WireGuardExitConfig::default()
        };

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(
            config.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
        assert_eq!(
            config.magic_dns_server,
            nostr_vpn_core::MESH_MAGIC_DNS_SERVER
        );
        assert_eq!(
            active_mobile_exit_dns_servers(&config).unwrap(),
            vec!["94.140.14.14".parse::<Ipv4Addr>().unwrap()]
        );

        app.set_internet_source(nostr_vpn_core::config::InternetSource::Direct);
        let direct = MobileTunnelConfig::from_app(&app).expect("direct mobile config");
        assert!(direct.wireguard_exit.is_none());
        assert!(active_mobile_exit_dns_servers(&direct).unwrap().is_empty());
        assert_eq!(direct.dns_match_domains, vec!["nvpn"]);
    }

    #[test]
    fn mobile_explicit_encrypted_dns_overrides_profile_and_through_exit_supports_fips() {
        let mut config: MobileTunnelConfig = serde_json::from_value(serde_json::json!({
            "identityNsec": "nsec-test",
            "networkId": "exit-dns-test",
            "localAddress": "10.44.0.2/32",
            "mtu": 1280,
            "peers": [],
            "routeTargets": ["0.0.0.0/0"],
            "magicDnsServer": nostr_vpn_core::MESH_MAGIC_DNS_SERVER
        }))
        .expect("minimal mobile config");
        config.wireguard_exit = Some(WireGuardExitConfig {
            dns: vec!["94.140.14.14".to_string()],
            ..WireGuardExitConfig::default()
        });
        config.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::Encrypted;
        config.exit_dns.doh_provider = nostr_vpn_core::config::ExitDohProvider::Quad9;

        assert!(active_mobile_exit_dns_servers(&config).unwrap().is_empty());
        assert!(matches!(
            mobile_exit_dns_resolver_config(&config).unwrap(),
            ExitDnsResolverConfig::Doh { url, .. }
                if url == nostr_vpn_core::config::QUAD9_DOH_URL
        ));

        config.wireguard_exit = None;
        config.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::ThroughExit;
        config.exit_dns.through_exit_servers = vec!["9.9.9.9".to_string()];
        assert_eq!(
            active_mobile_exit_dns_servers(&config).unwrap(),
            vec!["9.9.9.9".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mobile_wireguard_start_returns_before_handshake_watchdog() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("test nsec");
        let mut app = AppConfig::generated();
        app.nostr.secret_key.clone_from(&nsec);
        app.ensure_defaults();

        let mobile = MobileTunnelConfig {
            identity_nsec: nsec,
            network_id: "mobile-wg-start".to_string(),
            local_address: "10.44.10.2/32".to_string(),
            listen_port: 0,
            nostr_discovery_enabled: false,
            wireguard_exit: Some(WireGuardExitConfig {
                enabled: true,
                address: "10.99.99.2/32".to_string(),
                private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string(),
                peer_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string(),
                endpoint: format!("127.0.0.1:{}", available_udp_port()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                persistent_keepalive_secs: 25,
                ..WireGuardExitConfig::default()
            }),
            ..empty_config()
        };

        let started_at = Instant::now();
        let started = Box::pin(tokio::time::timeout(
            Duration::from_secs(2),
            MobileTunnel::start_async(mobile, app),
        ))
        .await
        .expect("mobile tunnel startup must not wait for WG handshake")
        .expect("mobile tunnel should start with a non-responding WG endpoint");
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "startup should return so Android can protect the WG socket before the watchdog expires"
        );
        #[cfg(target_os = "android")]
        {
            assert!(
                started.wg_upstream_socket_fd >= 0,
                "Android needs the WG UDP fd immediately after startup"
            );
        }

        shutdown_started_mobile_tunnel(started).await;
    }

    #[test]
    fn mobile_tunnel_start_is_safe_from_network_extension_sized_stack() {
        let own_keys = Keys::generate();
        let own_pubkey = own_keys.public_key().to_hex();
        let mut app = AppConfig::generated();
        app.nostr.secret_key = own_keys.secret_key().to_bech32().expect("test nsec");
        app.networks = vec![NetworkConfig {
            id: "ios-stack".to_string(),
            name: "iOS stack".to_string(),
            enabled: true,
            network_id: "ios-stack".to_string(),
            join_secret: "test-secret".to_string(),
            devices: std::iter::once(own_pubkey.clone())
                .chain((0..3).map(|_| Keys::generate().public_key().to_hex()))
                .collect(),
            removed_devices: Vec::new(),
            admins: vec![own_pubkey],
            listen_for_join_requests: false,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.ensure_defaults();
        let mut config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        config.webrtc_enabled = false;
        config.listen_port = 0;
        let config_json = serde_json::to_string(&config).expect("mobile config JSON");

        let tunnel = std::thread::Builder::new()
            .name("network-extension-stack-fixture".to_string())
            .stack_size(512 * 1024)
            .spawn(move || MobileTunnel::start(&config_json))
            .expect("spawn NetworkExtension-sized caller")
            .join()
            .expect("mobile tunnel caller should not overflow")
            .expect("mobile tunnel should start");

        drop(tunnel);
    }

    #[test]
    fn mobile_network_change_rebinds_live_fips_carriers_without_restarting_endpoint() {
        let own_keys = Keys::generate();
        let peer_keys = Keys::generate();
        let own_pubkey = own_keys.public_key().to_hex();
        let mut app = AppConfig::generated();
        app.nostr.secret_key = own_keys.secret_key().to_bech32().expect("test nsec");
        app.networks = vec![NetworkConfig {
            id: "mobile-network-change".to_string(),
            name: "Mobile network change".to_string(),
            enabled: true,
            network_id: "mobile-network-change".to_string(),
            join_secret: "test-secret".to_string(),
            devices: vec![own_pubkey.clone(), peer_keys.public_key().to_hex()],
            removed_devices: Vec::new(),
            admins: vec![own_pubkey],
            listen_for_join_requests: false,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.ensure_defaults();
        let mut config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        config.listen_port = available_udp_port();
        config.nostr_discovery_enabled = false;
        config.webrtc_enabled = false;
        let config_json = serde_json::to_string(&config).expect("mobile config JSON");
        let tunnel = MobileTunnel::start(&config_json).expect("mobile tunnel should start");
        let endpoint_npub = tunnel
            .endpoint
            .as_ref()
            .expect("live endpoint")
            .npub()
            .to_string();

        let outcome = tunnel
            .handle_underlay_network_change()
            .expect("live mobile FIPS endpoint should accept an underlay change");

        assert_eq!(
            outcome.rebound_transports, 3,
            "one underlay-change transaction must refresh the configured IPv4 UDP, IPv6 UDP, and WebSocket carriers exactly once each"
        );
        assert_eq!(
            tunnel.endpoint.as_ref().expect("live endpoint").npub(),
            endpoint_npub
        );
        drop(tunnel);
    }

    #[test]
    fn wg_upstream_excluded_route_is_ipv4_only() {
        assert_eq!(
            wg_upstream_excluded_route_for_addr("198.51.100.20:51820".parse().unwrap()),
            Some("198.51.100.20/32".to_string())
        );
        assert_eq!(
            wg_upstream_excluded_route_for_addr("[2001:db8::20]:51820".parse().unwrap()),
            None
        );
    }

    fn mobile_launch_redaction_fixture() -> (PathBuf, String, &'static str) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-launch-redaction-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.toml");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";

        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let secret_key = app.nostr.secret_key.clone();
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own.clone()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.wireguard_exit = WireGuardExitConfig {
            enabled: true,
            address: "10.99.99.2/32".to_string(),
            private_key: "client-private-key".to_string(),
            peer_public_key: "server-public-key".to_string(),
            peer_preshared_key: "client-peer-psk".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            ..WireGuardExitConfig::default()
        };
        app.note_active_network_roster_local_change()
            .expect("mark admin roster changed");
        app.save(&path).expect("save config");
        let queued_roster = SignedRoster::sign(
            "test",
            NetworkRoster {
                network_name: "Test".to_string(),
                devices: vec![peer.to_string()],
                admins: vec![own],
                aliases: HashMap::new(),
                signed_at: unix_timestamp(),
            },
            &app.nostr_keys().expect("admin keys"),
        )
        .expect("sign queued roster");
        let queued_control = JoinRosterControl::new(queued_roster, "request-secret")
            .expect("bind queued roster");
        nostr_vpn_core::join_delivery::queue_join_roster(&path, peer, &queued_control)
            .expect("queue mobile approval");
        (dir, secret_key, peer)
    }

    #[test]
    fn mobile_tunnel_launch_config_redacts_persisted_secrets() {
        let (dir, secret_key, peer) = mobile_launch_redaction_fixture();
        let path = dir.join("config.toml");

        let json = tunnel_config_json(dir.to_str().expect("utf8 temp dir"));
        assert!(!json.contains(&secret_key));
        assert!(!json.contains("join-secret"));
        assert!(!json.contains("client-private-key"));
        assert!(!json.contains("client-peer-psk"));
        assert!(json.contains("198.51.100.20:51820"));

        let launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&json).expect("launch config");
        assert_eq!(launch.queued_join_rosters.len(), 1);
        assert_eq!(launch.queued_join_rosters[0].recipient_npub, peer);
        assert!(launch.signed_roster.is_some());
        let launch_config = launch.tunnel;
        assert!(launch_config.app_config_toml.is_empty());
        assert!(launch_config.identity_nsec.is_empty());
        assert!(launch_config.join_secret.is_empty());
        assert!(launch_config.pending_join_secret.is_empty());
        assert_eq!(
            launch_config
                .wireguard_exit
                .as_ref()
                .expect("wireguard exit")
                .private_key,
            ""
        );

        let loaded = mobile_app_config(&launch_config).expect("load app config from path");
        let runtime_config =
            MobileTunnelConfig::from_app_with_config_path(&loaded, &path).expect("runtime config");
        assert_eq!(runtime_config.identity_nsec, secret_key);
        assert_eq!(
            runtime_config
                .wireguard_exit
                .as_ref()
                .expect("runtime wireguard")
                .private_key,
            "client-private-key"
        );

        let provider_json =
            tunnel_provider_options_config_json(dir.to_str().expect("utf8 temp dir"));
        assert!(provider_json.contains(&secret_key));
        assert!(provider_json.contains("join-secret"));
        assert!(provider_json.contains("client-private-key"));
        assert!(provider_json.contains("client-peer-psk"));

        let provider_launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&provider_json).expect("provider options config");
        assert_eq!(provider_launch.queued_join_rosters.len(), 1);
        assert_eq!(provider_launch.queued_join_rosters[0].recipient_npub, peer);
        assert!(provider_launch.signed_roster.is_some());
        assert_eq!(
            PathBuf::from(&provider_launch.private_state_config_path),
            path,
            "provider launch must retain only the private state anchor used for receipt and outbox sidecars"
        );
        let provider_config = provider_launch.tunnel;
        assert!(
            provider_config.config_path.is_empty(),
            "packet tunnel extension must not read the containing app's private config path"
        );
        assert_eq!(
            provider_config.route_targets, launch_config.route_targets,
            "saved and start-option configs must describe the same routes"
        );
        assert_eq!(
            provider_config.wireguard_exit.is_some(),
            launch_config.wireguard_exit.is_some(),
            "saved and start-option configs must agree on WireGuard exit state"
        );

        let provider_loaded =
            mobile_app_config(&provider_config).expect("load app config from embedded toml");
        let provider_runtime =
            MobileTunnelConfig::from_app_with_config_path(&provider_loaded, Path::new(""))
                .expect("provider runtime config");
        assert_eq!(provider_runtime.identity_nsec, secret_key);
        assert_eq!(
            provider_runtime
                .wireguard_exit
                .as_ref()
                .expect("provider runtime wireguard")
                .private_key,
            "client-private-key"
        );
        assert!(provider_runtime.config_path.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provider_launch_persists_fresh_runtime_state_via_private_anchor() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-provider-runtime-state-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let config_path = dir.join("config.toml");
        let runtime_state_path = dir.join(MOBILE_RUNTIME_STATE_FILE);

        let mut app = AppConfig::generated_without_networks();
        app.ensure_defaults();
        app.fips_nostr_discovery_enabled = false;
        app.fips_webrtc_enabled = false;
        app.lan_discovery_enabled = false;
        app.nostr.relays.clear();
        app.save(&config_path).expect("save provider fixture");

        let provider_json =
            tunnel_provider_options_config_json(dir.to_str().expect("utf8 temp dir"));
        let launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&provider_json).expect("provider launch config");
        assert!(launch.tunnel.config_path.is_empty());
        assert_eq!(
            PathBuf::from(&launch.private_state_config_path),
            config_path
        );

        let tunnel = MobileTunnel::start(&provider_json).expect("start provider tunnel");
        let deadline = Instant::now() + Duration::from_secs(2);
        let runtime_state = loop {
            if let Ok(bytes) = fs::read(&runtime_state_path)
                && let Ok(state) = serde_json::from_slice::<DaemonRuntimeState>(&bytes)
            {
                break state;
            }
            assert!(
                Instant::now() < deadline,
                "provider launch did not persist runtime state through its private anchor"
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        assert!(runtime_state.vpn_enabled);
        assert!(runtime_state.vpn_active);
        assert!(
            unix_timestamp().saturating_sub(runtime_state.updated_at) <= 1,
            "provider runtime state was not fresh"
        );

        drop(tunnel);
        let stopped_runtime_state = fs::read(&runtime_state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<DaemonRuntimeState>(&bytes).ok());
        let _ = fs::remove_dir_all(&dir);
        assert!(
            stopped_runtime_state
                .as_ref()
                .is_none_or(|state| !state.vpn_enabled && !state.vpn_active),
            "provider teardown left fresh active runtime state"
        );
    }

    #[test]
    fn mobile_config_json_reports_errors_as_json() {
        let json = tunnel_config_json("\0/not-a-path");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert!(value["error"].as_str().is_some());
    }

    include!("tests_config/endpoint.rs");
