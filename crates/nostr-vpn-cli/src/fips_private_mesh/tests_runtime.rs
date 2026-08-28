    static LOCAL_UDP_ENDPOINT_TEST_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    #[test]
    fn disabled_fips_host_artifacts_are_cleaned_once_per_disabled_epoch() {
        assert!(super::fips_host_disabled_cleanup_due(false, false));
        assert!(!super::fips_host_disabled_cleanup_due(false, true));
        assert!(!super::fips_host_disabled_cleanup_due(true, false));
    }

    fn available_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .expect("bind test port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    fn udp_carriers(config: &Config) -> &HashMap<String, UdpConfig> {
        let TransportInstances::Named(udp) = &config.transports.udp else {
            panic!("expected named IPv4 and IPv6 UDP transports");
        };
        assert_eq!(udp.len(), 2);
        udp
    }

    fn endpoint_transport(
        endpoint: &str,
        public: bool,
        nostr_discovery: bool,
        share_local_candidates: bool,
    ) -> FipsEndpointTransportConfig {
        FipsEndpointTransportConfig {
            listen_port: 51820,
            bind_interface: None,
            advertised_endpoint: endpoint.to_string(),
            advertise_public_endpoint: public,
            nostr_discovery_enabled: nostr_discovery,
            advertise_on_nostr: true,
            webrtc_enabled: false,
            stun_servers: Vec::new(),
            nostr_relays: Vec::new(),
            websocket: fips_endpoint::WebSocketConfig::default(),
            share_local_candidates,
        }
    }

    #[test]
    fn tunnel_config_routes_default_through_selected_exit_peer() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let carol_pubkey = carol_keys.public_key().to_hex();
        let network_id = "fips-exit-route-test";
        let bob_tunnel_ip = derive_mesh_tunnel_ip(network_id, &bob_pubkey).expect("bob tunnel ip");

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![
            alice_pubkey.clone(),
            bob_pubkey.clone(),
            carol_pubkey.clone(),
        ];
        app.exit_node = bob_pubkey.clone();

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");
        let bob_peer = config
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == bob_pubkey)
            .expect("bob peer");
        let carol_peer = config
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == carol_pubkey)
            .expect("carol peer");

        assert!(bob_peer.allowed_ips.contains(&bob_tunnel_ip));
        assert!(bob_peer.allowed_ips.contains(&"0.0.0.0/0".to_string()));
        assert!(!bob_peer.allowed_ips.contains(&"::/0".to_string()));
        assert!(!carol_peer.allowed_ips.contains(&"0.0.0.0/0".to_string()));
        assert!(config.route_targets.contains(&"0.0.0.0/0".to_string()));
        assert!(!config.route_targets.contains(&"::/0".to_string()));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tunnel_config_for_paid_exit_seller_enables_local_forwarding_without_free_advertising() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let pubkey = keys.public_key().to_hex();
        let network_id = "fips-paid-exit-forwarding-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![pubkey.clone()];
        app.paid_exit.enabled = true;
        app.node.advertise_exit_node = false;
        app.node.advertised_routes.clear();

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");

        assert!(config.local_advertised_routes.is_empty());
        assert_eq!(config.local_exit_forwarding_routes, vec!["0.0.0.0/0"]);
    }

    fn direct_udp_endpoint_config(
        local_port: u16,
        peer_npub: &str,
        peer_port: u16,
        auto_connect: bool,
    ) -> Config {
        let mut config = Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{local_port}")),
            accept_connections: Some(true),
            ..UdpConfig::default()
        });
        let mut peer = FipsPeerConfig::new(peer_npub, "udp", format!("127.0.0.1:{peer_port}"));
        if !auto_connect {
            peer.connect_policy = ConnectPolicy::Manual;
        }
        config.peers.push(peer);
        config
    }

    fn direct_udp_endpoint_config_many(local_port: u16, peers: &[(&str, u16, bool)]) -> Config {
        let mut config = Config::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{local_port}")),
            accept_connections: Some(true),
            ..UdpConfig::default()
        });
        for (peer_npub, peer_port, auto_connect) in peers {
            let mut peer = FipsPeerConfig::new(*peer_npub, "udp", format!("127.0.0.1:{peer_port}"));
            if !*auto_connect {
                peer.connect_policy = ConnectPolicy::Manual;
            }
            config.peers.push(peer);
        }
        config
    }

    fn add_addressless_manual_peer(config: &mut Config, peer_npub: &str) {
        if config.peers.iter().any(|peer| peer.npub == peer_npub) {
            return;
        }

        config.node.discovery.nostr.enabled = true;
        config.node.discovery.nostr.advertise = false;
        config.node.discovery.nostr.advert_relays.clear();
        config.node.discovery.nostr.stun_servers.clear();
        config.node.discovery.nostr.share_local_candidates = false;
        config.node.discovery.lan.enabled = false;
        config.peers.push(FipsPeerConfig {
            npub: peer_npub.to_string(),
            connect_policy: ConnectPolicy::Manual,
            auto_reconnect: false,
            ..FipsPeerConfig::default()
        });
    }

    async fn send_with_retry(runtime: &FipsPrivateMeshRuntime, packet: &[u8]) {
        let mut last_error = None;
        for _ in 0..50 {
            match send_tunnel_packet_batch_owned_with_capacity(runtime, vec![packet.to_vec()], 1) {
                Ok(1) => return,
                Ok(0) => panic!("packet had no FIPS route"),
                Ok(sent) => panic!("single packet send produced {sent} sends"),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        panic!(
            "packet did not send after retry: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }

    async fn wait_for_fips_peer(runtime: &FipsPrivateMeshRuntime, peer_npub: &str) {
        let mut last_snapshot = Vec::new();
        let mut last_error = None;
        for _ in 0..50 {
            match runtime.endpoint.peers().await {
                Ok(peers) => {
                    if peers.iter().any(|peer| {
                        peer.npub == peer_npub && peer.transport_addr.as_deref().is_some()
                    }) {
                        return;
                    }
                    last_snapshot = peers;
                }
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "FIPS peer {peer_npub} did not establish; last snapshot: {last_snapshot:?}; last error: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
    }

    #[test]
    fn two_local_endpoints_exchange_raw_packets_and_macos_rebind_recovers() {
        std::thread::Builder::new()
            .name("two-local-fips-endpoints".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("local FIPS endpoint test runtime")
                    .block_on(two_local_endpoints_exchange_raw_packets_over_fips_run());
            })
            .expect("spawn local FIPS endpoint test")
            .join()
            .expect("local FIPS endpoint test thread");
    }

    async fn two_local_endpoints_exchange_raw_packets_over_fips_run() {
        let _local_udp_guard = LOCAL_UDP_ENDPOINT_TEST_LOCK.lock().await;
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let bob_nsec = bob_keys.secret_key().to_bech32().expect("bob nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let alice_port = available_udp_port();
        let bob_port = available_udp_port();
        let alice_ip = Ipv4Addr::new(10, 44, 11, 1);
        let bob_ip = Ipv4Addr::new(10, 44, 11, 2);
        let scope = "nostr-vpn:two-local-endpoints";

        let alice_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            alice_nsec,
            Some(scope.to_string()),
            vec![FipsMeshPeerConfig {
                participant_pubkey: bob_pubkey.clone(),
                endpoint_npub: bob_npub.clone(),
                allowed_ips: vec![format!("{bob_ip}/32")],
            }],
            direct_udp_endpoint_config(alice_port, &bob_npub, bob_port, true),
            vec![format!("{alice_ip}/32")],
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("alice endpoint should bind");
        let bob_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            bob_nsec,
            Some(scope.to_string()),
            vec![FipsMeshPeerConfig {
                participant_pubkey: alice_pubkey.clone(),
                endpoint_npub: alice_npub.clone(),
                allowed_ips: vec![format!("{alice_ip}/32")],
            }],
            direct_udp_endpoint_config(bob_port, &alice_npub, alice_port, false),
            vec![format!("{bob_ip}/32")],
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("bob endpoint should bind");

        wait_for_fips_peer(&alice_runtime, &bob_npub).await;
        wait_for_fips_peer(&bob_runtime, &alice_npub).await;

        let alice_to_bob = ipv4_packet(alice_ip, bob_ip);
        send_with_retry(&alice_runtime, &alice_to_bob).await;
        let (mut messages, mut events) = (Vec::with_capacity(1), Vec::with_capacity(1));
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_mesh_event_batch_into(&bob_runtime, &mut messages, &mut events, 1),
        )
        .await
        .expect("Bob should receive Alice packet")
        .expect("receive Bob event batch")
        .expect("packet should pass Bob admission");
        assert_eq!(events.len(), 1);
        let received = match events.drain(..).next().expect("one Bob event") {
            FipsPrivateMeshEvent::Packet(packet) => packet.as_ref().to_vec(),
            event => panic!("expected packet event, got {event:?}"),
        };
        assert_eq!(received, alice_to_bob);

        let bob_to_alice = ipv4_packet(bob_ip, alice_ip);
        send_with_retry(&bob_runtime, &bob_to_alice).await;
        tokio::time::timeout(
            Duration::from_secs(5),
            recv_mesh_event_batch_into(&alice_runtime, &mut messages, &mut events, 1),
        )
        .await
        .expect("Alice should receive Bob packet")
        .expect("receive Alice event batch")
        .expect("packet should pass Alice admission");
        assert_eq!(events.len(), 1);
        let received = match events.drain(..).next().expect("one Alice event") {
            FipsPrivateMeshEvent::Packet(packet) => packet.as_ref().to_vec(),
            event => panic!("expected packet event, got {event:?}"),
        };
        assert_eq!(received, bob_to_alice);

        #[cfg(target_os = "macos")]
        {
            let started = std::time::Instant::now();
            let endpoint_peers = [FipsEndpointPeerTransportConfig {
                npub: bob_npub.clone(),
                addresses: vec![FipsPeerAddressHint {
                    addr: format!("udp:127.0.0.1:{bob_port}"),
                    seen_at_ms: None,
                    priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
                }],
                connect_on_start: true,
                auto_reconnect: true,
                discovery_fallback_transit: false,
            }];
            assert!(
                alice_runtime
                    .rebind_network_transports(Some("lo0".to_string()))
                    .await
                    .expect("rebind Alice to replacement underlay")
                    >= 1
            );
            alice_runtime
                .update_peers(&endpoint_peers)
                .await
                .expect("apply peer config after rebind");
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    let _ = send_tunnel_packet_batch_owned_with_capacity(
                        &alice_runtime,
                        vec![alice_to_bob.clone()],
                        1,
                    );
                    if let Ok(Ok(Some(_))) = tokio::time::timeout(
                        Duration::from_millis(75),
                        recv_mesh_event_batch_into(
                            &bob_runtime,
                            &mut messages,
                            &mut events,
                            1,
                        ),
                    )
                    .await
                        && events.iter().any(|event| {
                            matches!(event, FipsPrivateMeshEvent::Packet(packet) if packet.as_ref() == alice_to_bob)
                        })
                    {
                        break;
                    }
                }
            })
            .await
            .expect("authenticated payload did not recover within four seconds");
            assert!(started.elapsed() <= Duration::from_secs(4));
        }

        alice_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown alice");
        bob_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown bob");
    }

    #[test]
    fn relayed_control_ping_marks_peer_present_without_direct_link() {
        std::thread::Builder::new()
            .name("relayed-control-presence".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("relayed control test runtime")
                    .block_on(relayed_control_ping_marks_peer_present_without_direct_link_run());
            })
            .expect("spawn relayed control test")
            .join()
            .expect("relayed control test thread");
    }

    async fn relayed_control_ping_marks_peer_present_without_direct_link_run() {
        let _local_udp_guard = LOCAL_UDP_ENDPOINT_TEST_LOCK.lock().await;
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let bob_nsec = bob_keys.secret_key().to_bech32().expect("bob nsec");
        let carol_nsec = carol_keys.secret_key().to_bech32().expect("carol nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let carol_pubkey = carol_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let carol_npub = carol_keys.public_key().to_bech32().expect("carol npub");
        let alice_port = available_udp_port();
        let bob_port = available_udp_port();
        let carol_port = available_udp_port();
        let alice_ip = Ipv4Addr::new(10, 44, 21, 1);
        let bob_ip = Ipv4Addr::new(10, 44, 21, 2);
        let carol_ip = Ipv4Addr::new(10, 44, 21, 3);
        let scope = "nostr-vpn:relayed-control-presence";
        let mut alice_fips_config =
            direct_udp_endpoint_config_many(alice_port, &[(&bob_npub, bob_port, true)]);
        add_addressless_manual_peer(&mut alice_fips_config, &carol_npub);
        let bob_fips_config = direct_udp_endpoint_config_many(
            bob_port,
            &[
                (&alice_npub, alice_port, true),
                (&carol_npub, carol_port, true),
            ],
        );
        let mut carol_fips_config =
            direct_udp_endpoint_config_many(carol_port, &[(&bob_npub, bob_port, true)]);
        add_addressless_manual_peer(&mut carol_fips_config, &alice_npub);

        let alice_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            alice_nsec,
            Some(scope.to_string()),
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: bob_pubkey.clone(),
                    endpoint_npub: bob_npub.clone(),
                    allowed_ips: vec![format!("{bob_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: carol_pubkey.clone(),
                    endpoint_npub: carol_npub.clone(),
                    allowed_ips: vec![format!("{carol_ip}/32")],
                },
            ],
            alice_fips_config,
            vec![format!("{alice_ip}/32")],
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("alice endpoint should bind");
        let bob_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            bob_nsec,
            Some(scope.to_string()),
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: alice_pubkey.clone(),
                    endpoint_npub: alice_npub.clone(),
                    allowed_ips: vec![format!("{alice_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: carol_pubkey.clone(),
                    endpoint_npub: carol_npub.clone(),
                    allowed_ips: vec![format!("{carol_ip}/32")],
                },
            ],
            bob_fips_config,
            vec![format!("{bob_ip}/32")],
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("bob endpoint should bind");
        let carol_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            carol_nsec,
            Some(scope.to_string()),
            vec![
                FipsMeshPeerConfig {
                    participant_pubkey: alice_pubkey.clone(),
                    endpoint_npub: alice_npub.clone(),
                    allowed_ips: vec![format!("{alice_ip}/32")],
                },
                FipsMeshPeerConfig {
                    participant_pubkey: bob_pubkey.clone(),
                    endpoint_npub: bob_npub.clone(),
                    allowed_ips: vec![format!("{bob_ip}/32")],
                },
            ],
            carol_fips_config,
            vec![format!("{carol_ip}/32")],
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("carol endpoint should bind");

        wait_for_fips_peer(&alice_runtime, &bob_npub).await;
        wait_for_fips_peer(&bob_runtime, &alice_npub).await;
        wait_for_fips_peer(&bob_runtime, &carol_npub).await;
        wait_for_fips_peer(&carol_runtime, &bob_npub).await;
        tokio::time::sleep(Duration::from_millis(1_200)).await;

        let frame = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: unix_timestamp(),
        };
        let (mut carol_messages, mut carol_events) = (Vec::with_capacity(1), Vec::with_capacity(1));
        let (mut alice_messages, mut alice_events) = (Vec::with_capacity(1), Vec::with_capacity(1));
        let mut alice_saw_carol = false;
        for _ in 0..80 {
            let _ = alice_runtime
                .send_probe_frame(&carol_pubkey, &frame)
                .await;

            let _ = tokio::time::timeout(
                Duration::from_millis(50),
                recv_mesh_event_batch_into(
                    &carol_runtime,
                    &mut carol_messages,
                    &mut carol_events,
                    1,
                ),
            )
            .await;

            let alice_event = tokio::time::timeout(
                Duration::from_millis(50),
                recv_mesh_event_batch_into(
                    &alice_runtime,
                    &mut alice_messages,
                    &mut alice_events,
                    1,
                ),
            )
            .await;

            if let Ok(Ok(Some(_))) = alice_event
                && alice_events.drain(..).any(|event| {
                    matches!(
                        event,
                        FipsPrivateMeshEvent::Presence {
                            participant_pubkey,
                            ..
                        } if participant_pubkey == carol_pubkey
                    )
                })
            {
                alice_saw_carol = true;
                break;
            }
        }

        assert!(alice_saw_carol, "Alice never received Carol's relayed Pong");
        let carol_status = alice_runtime
            .peer_statuses()
            .into_iter()
            .find(|status| status.pubkey == carol_pubkey)
            .expect("Carol status");
        assert!(carol_status.connected);
        assert_eq!(carol_status.transport_addr, None);

        alice_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown alice");
        bob_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown bob");
        carol_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown carol");
    }

    #[tokio::test]
    async fn configured_non_roster_transit_ping_roundtrip() {
        let _local_udp_guard = LOCAL_UDP_ENDPOINT_TEST_LOCK.lock().await;
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let bob_nsec = bob_keys.secret_key().to_bech32().expect("bob nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let alice_npub = alice_keys.public_key().to_bech32().expect("alice npub");
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let alice_port = available_udp_port();
        let bob_port = available_udp_port();
        let alice_config =
            direct_udp_endpoint_config_many(alice_port, &[(&bob_npub, bob_port, true)]);
        let bob_config =
            direct_udp_endpoint_config_many(bob_port, &[(&alice_npub, alice_port, true)]);

        let alice_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            alice_nsec,
            None,
            Vec::new(),
            alice_config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("alice endpoint should bind");
        let bob_runtime = FipsPrivateMeshRuntime::bind_with_config_scoped(
            bob_nsec,
            None,
            Vec::new(),
            bob_config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("bob endpoint should bind");

        wait_for_fips_peer(&alice_runtime, &bob_npub).await;
        wait_for_fips_peer(&bob_runtime, &alice_npub).await;
        let frame = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: unix_timestamp(),
        };
        let (mut bob_messages, mut bob_events) = (Vec::with_capacity(1), Vec::with_capacity(1));
        let (mut alice_messages, mut alice_events) = (Vec::with_capacity(1), Vec::with_capacity(1));
        let mut alice_saw_bob = false;
        for _ in 0..40 {
            alice_runtime
                .send_probe_frame(&bob_pubkey, &frame)
                .await
                .expect("configured transit ping should send");
            let _ = tokio::time::timeout(
                Duration::from_millis(50),
                recv_mesh_event_batch_into(
                    &bob_runtime,
                    &mut bob_messages,
                    &mut bob_events,
                    1,
                ),
            )
            .await;
            let alice_event = tokio::time::timeout(
                Duration::from_millis(50),
                recv_mesh_event_batch_into(
                    &alice_runtime,
                    &mut alice_messages,
                    &mut alice_events,
                    1,
                ),
            )
            .await;
            if let Ok(Ok(Some(_))) = alice_event
                && alice_events.drain(..).any(|event| {
                    matches!(
                        event,
                        FipsPrivateMeshEvent::Presence {
                            participant_pubkey,
                            ..
                        } if participant_pubkey == bob_pubkey
                    )
                })
            {
                alice_saw_bob = true;
                break;
            }
        }

        assert!(alice_saw_bob, "configured non-roster transit did not answer Ping");
        assert!(
            alice_runtime.mesh.load().peer_pubkeys().is_empty()
                && bob_runtime.mesh.load().peer_pubkeys().is_empty(),
            "transit keepalive must not require roster membership"
        );
        assert!(
            alice_runtime
                .presence
                .read()
                .expect("alice presence")
                .contains_key(&bob_pubkey)
        );
        assert!(
            bob_runtime
                .presence
                .read()
                .expect("bob presence")
                .contains_key(&alice_pubkey)
        );

        alice_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown alice");
        bob_runtime
            .endpoint()
            .shutdown()
            .await
            .expect("shutdown bob");
    }

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
