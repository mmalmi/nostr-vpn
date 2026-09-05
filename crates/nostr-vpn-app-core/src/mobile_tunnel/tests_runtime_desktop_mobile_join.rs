    fn direct_manual_join_apps(
        network_id: &str,
    ) -> (AppConfig, AppConfig, QueuedJoinRoster, String) {
        let (mut admin, mut joiner, queued, admin_pubkey) =
            manual_join_apps("unused", network_id);
        for app in [&mut admin, &mut joiner] {
            app.fips_websocket_seed_urls.clear();
            app.fips_nostr_discovery_enabled = false;
            app.fips_webrtc_enabled = false;
            app.lan_discovery_enabled = false;
            app.fips_bootstrap_enabled = false;
            app.fips_bootstrap_peers.clear();
        }
        (admin, joiner, queued, admin_pubkey)
    }

    fn add_direct_mobile_peer_hint(
        mobile: &mut MobileTunnelConfig,
        participant: &str,
        port: u16,
    ) {
        mobile.peer_hints.insert(
            participant.to_string(),
            vec![FipsPeerAddressHint {
                addr: format!("127.0.0.1:{port}"),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }],
        );
    }

    async fn bind_direct_desktop_endpoint(
        identity_nsec: String,
        listen_port: u16,
        peer_pubkey: &str,
        peer_port: u16,
    ) -> Arc<FipsEndpoint> {
        let peer_npub = PublicKey::from_hex(peer_pubkey)
            .expect("desktop test peer pubkey")
            .to_bech32()
            .expect("desktop test peer npub");
        let mut config = FipsConfig::new();
        config.node.routing.mode = RoutingMode::ReplyLearned;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.nostr.advertise = false;
        config.node.discovery.lan.enabled = false;
        config.transports.websocket = TransportInstances::default();
        config.transports.webrtc = TransportInstances::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{listen_port}")),
            outbound_only: Some(false),
            accept_connections: Some(true),
            advertise_on_nostr: Some(false),
            public: Some(false),
            ..UdpConfig::default()
        });
        config.peers = vec![FipsPeerConfig::new(
            peer_npub,
            "udp",
            format!("127.0.0.1:{peer_port}"),
        )];
        Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(config)
                    .identity_nsec(identity_nsec)
                    .without_system_tun()
                    .bind(),
            )
            .await
            .expect("bind direct desktop FIPS endpoint"),
        )
    }

    fn desktop_mobile_join_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-{label}-{nonce}"));
        fs::create_dir_all(&dir).expect("create desktop/mobile join test directory");
        dir
    }

    fn run_desktop_mobile_join_test(
        thread_name: &str,
        test: impl FnOnce() + Send + 'static,
    ) {
        std::thread::Builder::new()
            .name(thread_name.to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(test)
            .expect("spawn desktop/mobile join test")
            .join()
            .expect("desktop/mobile join test thread");
    }

    #[test]
    fn desktop_mobile_manual_join_desktop_admin_to_mobile_joiner() {
        run_desktop_mobile_join_test("desktop-admin-mobile-joiner", || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("desktop/mobile join runtime")
                .block_on(desktop_admin_to_mobile_joiner(false));
        });
    }

    async fn desktop_admin_to_mobile_joiner(routed: bool) {
        let dir = desktop_mobile_join_test_dir("desktop-admin-mobile-joiner");
        let config_path = dir.join("mobile-config.toml");
        let (admin_app, joiner_app, queued, _admin_pubkey) =
            direct_manual_join_apps("desktop-admin-mobile-joiner");
        joiner_app.save(&config_path).expect("save mobile joiner config");
        let joiner_pubkey = joiner_app.own_nostr_pubkey_hex().expect("mobile pubkey");
        let mut mobile_config =
            MobileTunnelConfig::from_app_with_config_path(&joiner_app, &config_path)
                .expect("mobile joiner tunnel config");
        let (desktop, carriers) = bind_desktop_mobile_join_carrier(
            &admin_app, &joiner_pubkey, &mut mobile_config, routed,
        ).await;
        let mobile = Box::pin(MobileTunnel::start_async(mobile_config, joiner_app))
            .await
            .expect("start mobile joiner");
        let desktop_control = FipsControlTcpRuntime::start(Arc::clone(&desktop))
            .await
            .expect("start desktop state control");
        let destination = PeerIdentity::from_npub(mobile.endpoint.npub())
            .expect("mobile endpoint identity");

        send_join_roster_with_receipt(
            &desktop_control.sender(),
            destination,
            &queued.join_roster,
            Duration::from_secs(10),
        )
        .await
        .expect("desktop admin receives mobile durable join receipt");
        assert!(
            join_roster_is_durably_persisted(&config_path, &queued.join_roster)
                .expect("verify mobile durable join"),
            "mobile joiner must persist the exact desktop-admin roster before acknowledging"
        );

        assert_desktop_mobile_join_carrier(&desktop, &mobile, routed).await;
        desktop_control.stop().await;
        shutdown_started_mobile_tunnel(mobile).await;
        desktop.shutdown().await.expect("shutdown desktop endpoint");
        for carrier in carriers {
            carrier.shutdown().await.expect("shutdown local join carrier");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_mobile_manual_join_mobile_admin_to_desktop_joiner() {
        run_desktop_mobile_join_test("mobile-admin-desktop-joiner", || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mobile/desktop join runtime")
                .block_on(mobile_admin_to_desktop_joiner(false));
        });
    }

    async fn mobile_admin_to_desktop_joiner(routed: bool) {
        let dir = desktop_mobile_join_test_dir("mobile-admin-desktop-joiner");
        let mobile_config_path = dir.join("mobile-config.toml");
        let desktop_config_path = dir.join("desktop-config.toml");
        let (admin_app, joiner_app, queued, admin_pubkey) =
            direct_manual_join_apps("mobile-admin-desktop-joiner");
        admin_app.save(&mobile_config_path).expect("save mobile admin config");
        joiner_app
            .save(&desktop_config_path)
            .expect("save desktop joiner config");
        let joiner_pubkey = joiner_app.own_nostr_pubkey_hex().expect("desktop pubkey");
        let outbox_path = nostr_vpn_core::join_delivery::queue_join_roster(
            &mobile_config_path,
            &joiner_pubkey,
            &queued.join_roster,
        )
        .expect("queue mobile admin join roster");
        let mut mobile_config =
            MobileTunnelConfig::from_app_with_config_path(&admin_app, &mobile_config_path)
                .expect("mobile admin tunnel config");
        let (desktop, carriers) = bind_desktop_mobile_join_carrier(
            &joiner_app, &admin_pubkey, &mut mobile_config, routed,
        ).await;
        let mut desktop_control = FipsControlTcpRuntime::start(Arc::clone(&desktop))
            .await
            .expect("start desktop joiner state control");
        let queued_launch = nostr_vpn_core::join_delivery::load_join_rosters(&mobile_config_path)
            .into_iter()
            .map(|(_, queued)| queued)
            .collect();
        let mobile = Box::pin(MobileTunnel::start_async_with_launch_state(
            mobile_config,
            admin_app,
            queued_launch,
            None,
            None,
        ))
        .await
        .expect("start mobile admin");

        let received = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let received = desktop_control.recv().await.expect("desktop control closed");
                if matches!(&received.frame, FipsControlFrame::JoinRoster { .. }) {
                    break received;
                }
            }
        })
        .await
        .expect("desktop joiner did not receive mobile admin roster");
        let FipsControlFrame::JoinRoster { control } = received.frame else {
            unreachable!("filtered to join roster")
        };
        let mut desktop_app = AppConfig::load(&desktop_config_path)
            .expect("load desktop joiner config before apply");
        let applied = apply_join_roster_durably(
            &mut desktop_app,
            &desktop_config_path,
            &control,
            unix_timestamp(),
        )
        .expect("desktop durably applies mobile-admin roster");
        assert_eq!(applied.as_deref(), Some("mobile-admin-desktop-joiner"));
        desktop_control
            .sender()
            .enqueue(
                received.source_peer,
                &FipsControlFrame::JoinRosterAck {
                    roster_event_id: control.signed_roster.artifact_hash(),
                },
            )
            .expect("desktop queues exact durable receipt");
        tokio::time::timeout(Duration::from_secs(5), async {
            while outbox_path.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("mobile admin did not consume the roster after desktop receipt");
        assert!(
            join_roster_is_durably_persisted(&desktop_config_path, &control)
                .expect("verify desktop durable join"),
            "desktop joiner must persist the exact mobile-admin roster before acknowledging"
        );

        assert_desktop_mobile_join_carrier(&desktop, &mobile, routed).await;
        shutdown_started_mobile_tunnel(mobile).await;
        desktop_control.stop().await;
        desktop.shutdown().await.expect("shutdown desktop endpoint");
        for carrier in carriers {
            carrier.shutdown().await.expect("shutdown local join carrier");
        }
        let _ = fs::remove_dir_all(dir);
    }

    async fn bind_desktop_mobile_join_carrier(
        desktop_app: &AppConfig,
        mobile_pubkey: &str,
        mobile_config: &mut MobileTunnelConfig,
        via_seed: bool,
    ) -> (Arc<FipsEndpoint>, Vec<Arc<FipsEndpoint>>) {
        let desktop_port = available_udp_port();
        mobile_config.listen_port = available_udp_port();
        let desktop_pubkey = desktop_app.own_nostr_pubkey_hex().expect("desktop pubkey");
        let (peer_pubkey, peer_port, carriers) = if via_seed {
            let (seed, seed_url) = bind_manual_join_seed().await;
            mobile_config.websocket_seed_urls = vec![seed_url.clone()];
            let router_keys = Keys::generate();
            let router_port = available_udp_port();
            let router = bind_wss_physical_router(
                &seed_url,
                &PublicKey::from_hex(&desktop_pubkey)
                    .expect("desktop key")
                    .to_bech32()
                    .expect("desktop npub"),
                &format!("127.0.0.1:{desktop_port}"),
                &router_keys.secret_key().to_bech32().expect("router nsec"),
                router_port,
            )
            .await;
            (
                router_keys.public_key().to_hex(),
                router_port,
                vec![router, seed],
            )
        } else {
            add_direct_mobile_peer_hint(mobile_config, &desktop_pubkey, desktop_port);
            (mobile_pubkey.to_string(), mobile_config.listen_port, Vec::new())
        };
        let desktop = bind_direct_desktop_endpoint(
            desktop_app.nostr.secret_key.clone(),
            desktop_port,
            &peer_pubkey,
            peer_port,
        )
        .await;
        (desktop, carriers)
    }

    async fn assert_desktop_mobile_join_carrier(
        desktop: &FipsEndpoint,
        mobile: &MobileTunnelStarted,
        routed: bool,
    ) {
        if !routed {
            return;
        }
        for (endpoint, remote_npub) in [
            (desktop, mobile.endpoint.npub()),
            (mobile.endpoint.as_ref(), desktop.npub()),
        ] {
            assert!(
                endpoint.peers().await.expect("read physical peer links").iter()
                    .all(|peer| peer.npub != remote_npub || !peer.connected),
                "routed join must not bypass the local WebSocket seed with a direct link"
            );
        }
    }

    #[test]
    fn desktop_mobile_manual_join_desktop_admin_via_websocket_seed() {
        run_desktop_mobile_join_test("desktop-admin-wss-mobile", || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("routed desktop/mobile runtime")
                .block_on(desktop_admin_to_mobile_joiner(true));
        });
    }

    #[test]
    fn desktop_mobile_manual_join_mobile_admin_via_websocket_seed() {
        run_desktop_mobile_join_test("mobile-admin-wss-desktop", || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("routed mobile/desktop runtime")
                .block_on(mobile_admin_to_desktop_joiner(true));
        });
    }
