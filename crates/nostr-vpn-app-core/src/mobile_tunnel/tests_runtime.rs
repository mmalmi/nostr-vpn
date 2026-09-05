    fn available_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .expect("bind test port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    #[test]
    fn mobile_join_restart_waits_during_apply_before_receipt_is_queued() {
        let pending = PendingJoinRosterReceiptQueue::default();
        assert!(!pending.has_pending_receipts());
        {
            let _applying = pending.applying.lock().expect("begin roster apply");
            assert!(
                pending.has_pending_receipts(),
                "a config observer must not restart between persistence and receipt enqueue"
            );
        }
        assert!(
            !pending.has_pending_receipts(),
            "an ignored or failed apply must not leave a restart permanently deferred"
        );
    }

    fn available_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind test TCP port")
            .local_addr()
            .expect("local TCP addr")
            .port()
    }

    async fn shutdown_started_mobile_tunnel(started: MobileTunnelStarted) {
        let MobileTunnelStarted {
            endpoint,
            tasks,
            wg_upstream,
            ..
        } = started;
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        if let Some(wg) = wg_upstream {
            wg.shutdown().await;
        }
        let _ = endpoint.shutdown().await;
    }

    fn local_mobile_fips_config(scope: &str, mobile: &MobileTunnelConfig) -> FipsConfig {
        let mut config = fips_endpoint_config(scope, mobile);
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.nostr.advertise = false;
        config.node.discovery.lan.enabled = false;
        config.transports.webrtc = TransportInstances::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{}", mobile.listen_port)),
            outbound_only: Some(false),
            accept_connections: Some(true),
            advertise_on_nostr: Some(false),
            public: Some(false),
            ..UdpConfig::default()
        });
        config
    }

    fn bind_local_mobile_endpoint<'a>(
        scope: &'a str,
        mobile: &'a MobileTunnelConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Arc<FipsEndpoint>> + 'a>> {
        Box::pin(async move {
            Arc::new(
                Box::pin(
                    FipsEndpoint::builder()
                        .config(local_mobile_fips_config(scope, mobile))
                        .identity_nsec(mobile.identity_nsec.clone())
                        .discovery_scope(scope.to_string())
                        .without_system_tun()
                        .bind(),
                )
                .await
                .expect("bind local mobile FIPS endpoint"),
            )
        })
    }

    fn admin_join_request_app(admin_nsec: &str, admin_pubkey: &str, network_id: &str) -> AppConfig {
        let mut admin_app = AppConfig::generated();
        admin_app.nostr.public_key = admin_pubkey.to_string();
        admin_app.nostr.secret_key = admin_nsec.to_string();
        admin_app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Home".to_string(),
            enabled: true,
            network_id: network_id.to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![admin_pubkey.to_string()],
            removed_devices: Vec::new(),
            admins: vec![admin_pubkey.to_string()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        admin_app.ensure_defaults();
        admin_app
    }

    fn admin_mobile_join_request_config(
        admin_nsec: String,
        network_id: &str,
        listen_port: u16,
    ) -> MobileTunnelConfig {
        MobileTunnelConfig {
            identity_nsec: admin_nsec,
            node_name: "admin".to_string(),
            network_id: network_id.to_string(),
            local_address: "10.44.10.1/32".to_string(),
            listen_port,
            join_requests_enabled: true,
            ..empty_config()
        }
    }

    fn requester_mobile_join_request_config(
        requester_nsec: String,
        admin_pubkey: String,
        admin_port: u16,
        requester_port: u16,
        network_id: &str,
        requested_at: u64,
    ) -> MobileTunnelConfig {
        let admin_peer = FipsMeshPeerConfig::from_participant_pubkey(&admin_pubkey, Vec::new())
            .expect("admin control peer");
        let mut requester_peer_hints = HashMap::new();
        requester_peer_hints.insert(
            admin_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: format!("127.0.0.1:{admin_port}"),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }],
        );
        MobileTunnelConfig {
            identity_nsec: requester_nsec,
            node_name: "iPhone".to_string(),
            network_id: network_id.to_string(),
            local_address: "10.44.10.2/32".to_string(),
            listen_port: requester_port,
            peers: vec![admin_peer],
            peer_hints: requester_peer_hints,
            pending_join_request_recipient: admin_pubkey,
            pending_join_secret: "join-secret".to_string(),
            pending_join_requested_at: requested_at,
            ..empty_config()
        }
    }

    fn fips_exit_mobile_config(
        exit_nsec: String,
        exit_pubkey: &str,
        network_id: &str,
        listen_port: u16,
    ) -> MobileTunnelConfig {
        MobileTunnelConfig {
            identity_nsec: exit_nsec,
            node_name: "fips-exit".to_string(),
            network_id: network_id.to_string(),
            local_address: derive_mesh_tunnel_ip(network_id, exit_pubkey).expect("exit tunnel ip"),
            listen_port,
            nostr_discovery_enabled: false,
            ..empty_config()
        }
    }

    fn fips_exit_client_app(
        client_nsec: &str,
        client_pubkey: &str,
        exit_pubkey: &str,
        network_id: &str,
    ) -> AppConfig {
        let mut app = AppConfig::generated();
        app.nostr.secret_key = client_nsec.to_string();
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: network_id.to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![client_pubkey.to_string(), exit_pubkey.to_string()],
            removed_devices: Vec::new(),
            admins: vec![client_pubkey.to_string()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.exit_node = exit_pubkey.to_string();
        app.ensure_defaults();
        app
    }

    fn assert_mobile_fips_exit_config(
        client_mobile: &MobileTunnelConfig,
        exit_pubkey: &str,
    ) -> Ipv4Addr {
        assert!(
            client_mobile
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0"),
            "selected FIPS exit node must install a mobile default route"
        );
        assert_eq!(client_mobile.wireguard_exit, None);
        let exit_peer = client_mobile
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == exit_pubkey)
            .expect("selected exit peer");
        assert!(
            client_mobile
                .peer_hints
                .contains_key(&exit_peer.participant_pubkey),
            "selected FIPS exit member should have a static local endpoint hint in this test"
        );
        assert!(
            fips_peer_configs_from_mesh(
                &client_mobile.peers,
                &client_mobile.peer_hints,
                &client_mobile.bootstrap_peers,
                client_mobile.connect_to_non_roster_fips_peers,
            )
            .iter()
            .any(|peer| peer.npub == exit_peer.endpoint_npub && !peer.addresses.is_empty()),
            "selected FIPS exit member should bind with a static address"
        );
        assert!(
            exit_peer
                .allowed_ips
                .iter()
                .any(|route| route == "0.0.0.0/0"),
            "default traffic should route to the selected FIPS member"
        );
        parse_ipv4(&client_mobile.local_address).expect("client tunnel ip")
    }

    async fn send_pending_mobile_join_request(
        requester_endpoint: &Arc<FipsEndpoint>,
        admin_endpoint: &Arc<FipsEndpoint>,
        requester_mobile: &MobileTunnelConfig,
    ) -> (
        ReceivedFipsControlFrame,
        FipsControlTcpRuntime,
        FipsControlTcpRuntime,
    ) {
        let (recipient_npub, frame) = pending_mobile_join_request_frame(requester_mobile)
            .expect("pending join request frame")
            .expect("pending join request should exist");
        let recipient_peer =
            PeerIdentity::from_npub(&recipient_npub).expect("recipient endpoint identity");
        let requester_control = FipsControlTcpRuntime::start(Arc::clone(requester_endpoint))
            .await
            .expect("start requester state control");
        let mut admin_control = FipsControlTcpRuntime::start(Arc::clone(admin_endpoint))
            .await
            .expect("start admin state control");
        let (sent, received) = tokio::join!(
            requester_control.send(recipient_peer, &frame),
            tokio::time::timeout(Duration::from_secs(5), admin_control.recv()),
        );
        sent.expect("send join request over FIPS-TCP");
        let received = received
            .expect("admin state-control receive timeout")
            .expect("admin state-control service closed");
        (received, requester_control, admin_control)
    }

    async fn send_mobile_packets_until_received(
        started: &MobileTunnelStarted,
        recipient: &FipsEndpoint,
        packets: &[Vec<u8>],
    ) -> Vec<FipsEndpointMessage> {
        if packets.is_empty() {
            return Vec::new();
        }
        let mut messages = Vec::with_capacity(packets.len());
        let receive_limit = packets.len().saturating_mul(2).max(1);
        let mut received_batch = Vec::with_capacity(receive_limit);
        for _ in 0..50 {
            started
                .outbound_tx
                .send(packets.to_vec())
                .await
                .expect("send packet batch into mobile tunnel");
            for _ in 0..receive_limit {
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    recipient.recv_batch_into(&mut received_batch, receive_limit),
                )
                .await
                {
                    Ok(Some(received)) if received > 0 => {
                        for message in received_batch.drain(..) {
                            if message.source_peer.npub() == started.endpoint.npub()
                                && message.data.as_slice() == packets[messages.len()].as_slice()
                            {
                                messages.push(message);
                                if messages.len() == packets.len() {
                                    return messages;
                                }
                            }
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("recipient should receive mobile packets over FIPS");
    }

    async fn receive_mobile_inbound_packets_until(
        started: &mut MobileTunnelStarted,
        packets: &[Vec<u8>],
    ) {
        let mut remaining = packets.to_vec();
        for _ in 0..50 {
            loop {
                match started.inbound_rx.try_recv() {
                    Ok(batch) => {
                        for bytes in batch {
                            if let Some(index) = remaining
                                .iter()
                                .position(|packet| packet.as_slice() == bytes)
                            {
                                remaining.swap_remove(index);
                                if remaining.is_empty() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(tokio_mpsc::error::TryRecvError::Empty) => break,
                    Err(error) => panic!("mobile inbound channel closed: {error}"),
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "mobile tunnel should receive all inbound FIPS packets; missing {} packet(s)",
            remaining.len()
        );
    }

    async fn handle_admin_mobile_join_request(
        admin_endpoint: &FipsEndpoint,
        admin_app: AppConfig,
        admin_mobile: MobileTunnelConfig,
        config_path: &Path,
        state_control: &FipsControlTcpSender,
        received: ReceivedFipsControlFrame,
    ) -> (Arc<RwLock<AppConfig>>, AtomicBool) {
        let admin_app_config = Arc::new(RwLock::new(admin_app));
        let app_config_dirty = AtomicBool::new(false);
        let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
            Vec::new(),
            vec![admin_mobile.local_address.clone()],
        ));
        let mesh_peers = Arc::new(RwLock::new(Vec::new()));
        let peer_identities = Arc::new(RwLock::new(MobilePeerIdentityMap::default()));
        let peer_hints = Arc::new(RwLock::new(HashMap::new()));
        let presence = Arc::new(RwLock::new(HashMap::new()));
        let config_state = Arc::new(RwLock::new(admin_mobile));
        let join_request_active = AtomicBool::new(false);
        let pending_join_roster_receipts =
            Arc::new(PendingJoinRosterReceiptQueue::default());
        let control = MobileEndpointReceiveContext {
            endpoint: admin_endpoint,
            mesh: &mesh,
            mesh_peers: &mesh_peers,
            peer_identities: &peer_identities,
            peer_hints: &peer_hints,
            presence: &presence,
            config_state: &config_state,
            app_config: &admin_app_config,
            app_config_dirty: &app_config_dirty,
            pending_join_roster_receipts: &pending_join_roster_receipts,
            config_path: Some(config_path),
            join_request_active: &join_request_active,
            state_control,
        };

        handle_mobile_state_control_frame(&control, received)
            .await
            .expect("handle mobile join request frame");
        (admin_app_config, app_config_dirty)
    }

    #[test]
    fn mobile_join_request_sends_and_records_over_real_fips_endpoint() {
        std::thread::Builder::new()
            .name("mobile-join-fips".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mobile join test runtime")
                    .block_on(mobile_join_request_roundtrip());
            })
            .expect("spawn mobile join test")
            .join()
            .expect("mobile join test thread");
    }

    async fn mobile_join_request_roundtrip() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-fips-join-request-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");

        let admin_keys = Keys::generate();
        let requester_keys = Keys::generate();
        let admin_nsec = admin_keys.secret_key().to_bech32().expect("admin nsec");
        let requester_nsec = requester_keys
            .secret_key()
            .to_bech32()
            .expect("requester nsec");
        let admin_pubkey = admin_keys.public_key().to_hex();
        let requester_pubkey = requester_keys.public_key().to_hex();
        let network_id = format!("mobile-fips-join-{nonce}");
        let requested_at = 1_778_998_000;
        let scope = format!("nostr-vpn:{network_id}");

        let admin_app = admin_join_request_app(&admin_nsec, &admin_pubkey, &network_id);
        let admin_mobile =
            admin_mobile_join_request_config(admin_nsec, &network_id, available_udp_port());
        let admin_endpoint = bind_local_mobile_endpoint(&scope, &admin_mobile).await;
        let requester_mobile = requester_mobile_join_request_config(
            requester_nsec,
            admin_pubkey,
            admin_mobile.listen_port,
            available_udp_port(),
            &network_id,
            requested_at,
        );
        let requester_endpoint = bind_local_mobile_endpoint(&scope, &requester_mobile).await;

        let (received, requester_control, admin_control) = send_pending_mobile_join_request(
            &requester_endpoint,
            &admin_endpoint,
            &requester_mobile,
        )
        .await;
        assert_eq!(received.source_peer.npub(), requester_endpoint.npub());
        let admin_control_sender = admin_control.sender();
        let (admin_app_config, app_config_dirty) = handle_admin_mobile_join_request(
            &admin_endpoint,
            admin_app,
            admin_mobile,
            &config_path,
            &admin_control_sender,
            received,
        )
        .await;

        assert!(app_config_dirty.load(Ordering::Relaxed));
        {
            let saved = admin_app_config.read().expect("admin app config");
            let inbound = &saved.networks[0].inbound_join_requests;
            assert_eq!(inbound.len(), 1);
            assert_eq!(inbound[0].requester, requester_pubkey);
            assert_eq!(inbound[0].requester_node_name, "iPhone");
            assert_eq!(inbound[0].requested_at, requested_at);
        }
        let saved = AppConfig::load(&config_path).expect("load persisted admin config");
        assert_eq!(saved.networks[0].inbound_join_requests.len(), 1);
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester,
            requester_pubkey
        );

        requester_control.stop().await;
        admin_control.stop().await;
        requester_endpoint
            .shutdown()
            .await
            .expect("shutdown requester endpoint");
        admin_endpoint
            .shutdown()
            .await
            .expect("shutdown admin endpoint");
        let _ = std::fs::remove_dir_all(&dir);
    }

    include!("tests_runtime/websocket_join.rs");
