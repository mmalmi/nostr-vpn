    static WEBSOCKET_JOIN_LATENCY_GATE: Mutex<()> = Mutex::new(());

    #[test]
    fn websocket_seed_router_routes_new_recipient_without_preconverged_roster_peer() {
        let _latency_guard = WEBSOCKET_JOIN_LATENCY_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::thread::Builder::new()
            .name("mobile-wss-join-roster".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("WSS join test runtime")
                    .block_on(websocket_seed_router_join_roster_roundtrip(
                        JoinReceiptFailure::None,
                    ));
            })
            .expect("spawn WSS join test")
            .join()
            .expect("WSS join test thread");
    }

    #[test]
    fn websocket_seed_router_retries_durable_join_receipt_after_first_route_failure() {
        let _latency_guard = WEBSOCKET_JOIN_LATENCY_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::thread::Builder::new()
            .name("mobile-wss-join-receipt-retry".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("WSS join receipt retry runtime")
                    .block_on(websocket_seed_router_join_roster_roundtrip(
                        JoinReceiptFailure::WithoutRestart,
                    ));
            })
            .expect("spawn WSS join receipt retry test")
            .join()
            .expect("WSS join receipt retry test thread");
    }

    #[test]
    fn websocket_seed_router_delivers_durable_join_receipt_after_tunnel_restart() {
        let _latency_guard = WEBSOCKET_JOIN_LATENCY_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::thread::Builder::new()
            .name("mobile-wss-join-receipt-restart".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("WSS join receipt restart runtime")
                    .block_on(websocket_seed_router_join_roster_roundtrip(
                        JoinReceiptFailure::AcrossRestart,
                    ));
            })
            .expect("spawn WSS join receipt restart test")
            .join()
            .expect("WSS join receipt restart test thread");
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum JoinReceiptFailure {
        None,
        WithoutRestart,
        AcrossRestart,
    }

    async fn bind_wss_physical_router(
        seed_url: &str,
        guest_npub: &str,
        guest_udp_addr: &str,
        router_nsec: &str,
        router_port: u16,
    ) -> Arc<FipsEndpoint> {
        let mut router_config = FipsConfig::new();
        router_config.node.routing.mode = fips_endpoint::RoutingMode::ReplyLearned;
        router_config.node.discovery.nostr.enabled = false;
        router_config.node.discovery.nostr.advertise = false;
        router_config.node.discovery.lan.enabled = false;
        router_config.transports.websocket = TransportInstances::Single(WebSocketConfig {
            seed_urls: vec![seed_url.to_string()],
            ..WebSocketConfig::default()
        });
        router_config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{router_port}")),
            outbound_only: Some(false),
            accept_connections: Some(true),
            advertise_on_nostr: Some(false),
            public: Some(false),
            ..UdpConfig::default()
        });
        router_config.peers = vec![FipsPeerConfig::new(
            guest_npub.to_string(),
            "udp",
            guest_udp_addr.to_string(),
        )];
        Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(router_config)
                    .identity_nsec(router_nsec.to_string())
                    .without_system_tun()
                    .bind(),
            )
            .await
            .expect("bind WSS-to-physical router"),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn websocket_seed_router_join_roster_roundtrip(receipt_failure: JoinReceiptFailure) {
        let test_started_at = Instant::now();
        let requested_at = unix_timestamp().saturating_sub(1);
        let approved_at = unix_timestamp();

        let seed_keys = Keys::generate();
        let seed_nsec = seed_keys.secret_key().to_bech32().expect("seed nsec");
        let seed_port = available_tcp_port();
        let seed_url = format!("ws://127.0.0.1:{seed_port}/fips");
        let mut seed_config = FipsConfig::new();
        seed_config.node.routing.mode = fips_endpoint::RoutingMode::ReplyLearned;
        seed_config.node.discovery.nostr.enabled = false;
        seed_config.node.discovery.nostr.advertise = false;
        seed_config.node.discovery.lan.enabled = false;
        seed_config.transports.websocket = TransportInstances::Single(WebSocketConfig {
            bind_addr: Some(format!("127.0.0.1:{seed_port}")),
            ..WebSocketConfig::default()
        });
        let seed = Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(seed_config)
                    .identity_nsec(seed_nsec)
                    .without_system_tun()
                    .bind(),
            )
                .await
                .expect("bind WebSocket seed"),
        );

        let mut guest_app = AppConfig::generated_without_networks();
        guest_app.node_name = "Joining device".to_string();
        guest_app.fips_nostr_discovery_enabled = false;
        guest_app.fips_webrtc_enabled = false;
        guest_app.fips_bootstrap_enabled = false;
        guest_app.fips_bootstrap_peers.clear();
        guest_app
            .ensure_pending_nostr_join_request(requested_at)
            .expect("pending guest join request");
        let bootstrap = nostr_vpn_core::identity_bridge::nostr_identity_device_approval_bootstrap(
            &guest_app
                .pending_nostr_join_request
                .as_ref()
                .expect("pending request")
                .request,
        )
        .expect("guest join bootstrap");

        let admin_keys = Keys::generate();
        let admin_pubkey = admin_keys.public_key().to_hex();
        let mut admin_app = AppConfig::generated();
        admin_app.nostr.secret_key = admin_keys.secret_key().to_secret_hex();
        admin_app.nostr.public_key = admin_pubkey.clone();
        admin_app.networks[0].name = "Home".to_string();
        admin_app.networks[0].enabled = true;
        admin_app.networks[0].network_id = "wss-join-roster".to_string();
        admin_app.networks[0].devices = vec![admin_pubkey.clone()];
        admin_app.networks[0].admins = vec![admin_pubkey.clone()];
        // A real household/team roster pushes the completed config past the
        // safe NetworkExtension response size, so the UI handoff must use the
        // chunked protocol instead of relying on a tiny two-device fixture.
        for index in 0..16 {
            let participant = Keys::generate().public_key().to_hex();
            admin_app.networks[0].devices.push(participant.clone());
            admin_app.peer_aliases.insert(
                participant,
                format!("offline-regression-participant-{index:02}"),
            );
        }
        admin_app.ensure_defaults();
        admin_app.fips_websocket_seed_urls = vec![seed_url.clone()];
        admin_app.fips_nostr_discovery_enabled = false;
        admin_app.fips_webrtc_enabled = false;
        admin_app.fips_bootstrap_enabled = false;
        admin_app.fips_bootstrap_peers.clear();
        let preapproval_admin_app = admin_app.clone();
        let preapproval_admin_mobile =
            MobileTunnelConfig::from_app(&admin_app).expect("pre-approval admin config");
        let network_entry_id = admin_app.networks[0].id.clone();
        let prepared = crate::join_approval::prepare_join_approval(
            &admin_app,
            &network_entry_id,
            &bootstrap,
            approved_at,
        )
        .expect("prepare ordinary signed join roster");
        admin_app = prepared.updated_config;
        let guest_pubkey = normalize_nostr_pubkey(&bootstrap.device_app_key_npub)
            .expect("normalize guest pubkey");
        assert!(
            preapproval_admin_mobile
                .peers
                .iter()
                .all(|peer| peer.participant_pubkey != guest_pubkey),
            "the approval recipient must not be preconverged in the sender runtime graph"
        );

        let admin_dir = std::env::temp_dir().join(format!(
            "nvpn-mobile-queued-join-{}-{}-{}",
            std::process::id(),
            approved_at,
            &admin_pubkey[..16]
        ));
        std::fs::create_dir_all(&admin_dir).expect("create admin config directory");
        let admin_config_path = admin_dir.join("config.toml");
        let guest_config_path = admin_dir.join("guest/config.toml");
        std::fs::create_dir_all(
            guest_config_path
                .parent()
                .expect("guest config directory"),
        )
        .expect("create guest config directory");
        guest_app
            .save(&guest_config_path)
            .expect("persist initial guest config");
        let guest_receipt_path = pending_join_roster_receipts_path(&guest_config_path);
        admin_app
            .save(&admin_config_path)
            .expect("persist approved admin config");

        let mut guest_mobile =
            MobileTunnelConfig::from_app_with_config_path(&guest_app, &guest_config_path)
                .expect("guest config");
        guest_mobile.detach_from_persisted_config_path();
        guest_mobile.listen_port = available_udp_port();
        let guest_listen_port = guest_mobile.listen_port;
        let mut admin_mobile = preapproval_admin_mobile;
        // Match iOS provider options: the packet extension receives a complete
        // launch snapshot but cannot read the containing app's config path.
        admin_mobile.detach_from_persisted_config_path();
        admin_mobile.listen_port = available_udp_port();
        assert!(guest_mobile.peers.is_empty(), "guest must not know the admin");

        let guest_udp_addr = format!("127.0.0.1:{}", guest_mobile.listen_port);
        let mut guest = Box::pin(MobileTunnel::start_async_with_launch_state(
            guest_mobile,
            guest_app,
            Vec::new(),
            None,
            Some(guest_config_path.clone()),
        ))
        .await
        .expect("start guest on its physical edge");

        let router_nsec = Keys::generate()
            .secret_key()
            .to_bech32()
            .expect("router nsec");
        let router_port = available_udp_port();
        let router = bind_wss_physical_router(
            &seed_url,
            guest.endpoint.npub(),
            &guest_udp_addr,
            &router_nsec,
            router_port,
        )
        .await;
        let admin = Box::pin(MobileTunnel::start_async_with_launch_state(
            admin_mobile,
            preapproval_admin_app,
            Vec::new(),
            None,
            Some(admin_config_path.clone()),
        ))
            .await
            .expect("start admin through WebSocket seed");

        let seed_npub = seed.npub().to_string();
        let router_npub = router.npub().to_string();
        let guest_npub = guest.endpoint.npub().to_string();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let guest_ready = guest
                    .endpoint
                    .peers()
                    .await
                    .is_ok_and(|peers| {
                        peers
                            .iter()
                            .any(|peer| peer.npub == router_npub && peer.connected)
                    });
                let admin_ready = admin
                    .endpoint
                    .peers()
                    .await
                    .is_ok_and(|peers| {
                        peers
                            .iter()
                            .any(|peer| peer.npub == seed_npub && peer.connected)
                    });
                let router_ready = router.peers().await.is_ok_and(|peers| {
                    peers.iter().any(|peer| peer.npub == seed_npub && peer.connected)
                        && peers
                            .iter()
                            .any(|peer| peer.npub == guest_npub && peer.connected)
                });
                let seed_ready = seed.peers().await.is_ok_and(|peers| {
                    peers.iter().filter(|peer| peer.connected).count() == 2
                });
                if guest_ready && admin_ready && router_ready && seed_ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("admin, WSS seed, router, and physical guest should authenticate");
        let authenticated_at = Instant::now();
        let outbox_path = nostr_vpn_core::join_delivery::queue_join_roster(
            &admin_config_path,
            &bootstrap.device_app_key_npub,
            &prepared.join_roster,
        )
        .expect("queue approval after the mobile runtime authenticated its return carrier");
        assert!(outbox_path.exists(), "approval must enter the durable outbox");

        let guest_identity = PeerIdentity::from_npub(guest.endpoint.npub())
            .expect("guest endpoint identity");
        let admin_identity =
            PeerIdentity::from_npub(admin.endpoint.npub()).expect("admin endpoint identity");
        let expected_roster_event_id = prepared.join_roster.signed_roster.artifact_hash();
        let mut observed_admin_receipts = admin.state_control.subscribe();
        let queued_delivery = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let applied = guest.app_config.read().is_ok_and(|app| {
                    app.pending_nostr_join_request.is_some()
                        && app
                            .active_network_opt()
                            .is_some_and(|network| network.network_id == "wss-join-roster")
                });
                if applied {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            queued_delivery.is_ok(),
                "production queued approval was not delivered through WSS seed and physical router; admin={:?}; guest={:?}; router={:?}; seed={:?}",
                admin.endpoint.peers().await,
                guest.endpoint.peers().await,
                router.peers().await,
                seed.peers().await,
        );
        let roster_applied_at = Instant::now();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            guest
                .pending_join_roster_receipts
                .receipts
                .lock()
                .expect("pending receipt lock")
                .len(),
            1,
            "the detached packet tunnel must retain the application receipt until the host commits"
        );
        while let Ok(received) = observed_admin_receipts.try_recv() {
            assert!(
                !matches!(received.frame, FipsControlFrame::JoinRosterAck { .. }),
                "a detached iOS packet tunnel must not acknowledge the roster before the host app commits its config handoff"
            );
        }

        let capabilities = FipsControlFrame::Capabilities {
            network_id: "wss-join-roster".to_string(),
            capabilities: PeerCapabilities::default(),
        };
        let received_before = guest
            .presence
            .read()
            .ok()
            .and_then(|presence| presence.get(&admin_pubkey).map(|peer| peer.rx_bytes))
            .unwrap_or_default();
        tokio::time::timeout(
            Duration::from_secs(5),
            admin.state_control.send(guest_identity, &capabilities),
        )
        .await
        .expect("post-join capabilities delivery timeout")
        .expect("send post-join capabilities to guest");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let capabilities_processed = guest.presence.read().is_ok_and(|presence| {
                    presence
                        .get(&admin_pubkey)
                        .is_some_and(|peer| peer.rx_bytes > received_before)
                });
                if capabilities_processed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("joined guest must accept its new network id and process peer capabilities");
        let new_network_control_at = Instant::now();

        let joined_config = guest
            .take_app_config_toml()
            .expect("take joined app config for UI handoff");
        assert!(
            joined_config.len() > 3_072,
            "fixture must require a chunked iOS provider response"
        );
        let joined_app: AppConfig =
            toml::from_str(&joined_config).expect("decode joined app config handoff");
        assert_eq!(
            joined_app
                .active_network_opt()
                .expect("UI handoff must leave QR onboarding")
                .network_id,
            "wss-join-roster"
        );
        let retried_config = guest
            .take_app_config_toml()
            .expect("retry interrupted UI handoff");
        assert!(!retried_config.is_empty());
        assert_eq!(
            toml::from_str::<toml::Value>(&retried_config)
                .expect("decode retried UI handoff"),
            toml::from_str::<toml::Value>(&joined_config)
                .expect("decode initial UI handoff"),
            "an interrupted provider-to-app handoff must remain retryable"
        );
        joined_app
            .save(&guest_config_path)
            .expect("host durably persists joined guest config");
        let reloaded_joined_app =
            AppConfig::load(&guest_config_path).expect("reload transit-delivered signed roster");
        assert!(
            reloaded_joined_app.active_network_has_confirmed_local_identity(),
            "npub-only transit delivery must durably confirm the joining identity"
        );
        if receipt_failure == JoinReceiptFailure::AcrossRestart {
            guest
                .endpoint
                .shutdown()
                .await
                .expect("interrupt guest FIPS route before receipt commit");
        } else if receipt_failure == JoinReceiptFailure::WithoutRestart {
            let unreachable_destination = PeerIdentity::from_npub(
                &Keys::generate()
                    .public_key()
                    .to_bech32()
                    .expect("unreachable receipt npub"),
            )
            .expect("unreachable receipt identity");
            let mut receipts = guest
                .pending_join_roster_receipts
                .receipts
                .lock()
                .expect("pending receipt lock");
            receipts
                .get_mut(&expected_roster_event_id)
                .expect("queued receipt before host commit")
                .destination = unreachable_destination;
        }
        assert!(
            guest
                .acknowledge_app_config_toml(&joined_config)
                .expect("acknowledge persisted UI handoff")
        );
        if receipt_failure != JoinReceiptFailure::None {
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    let first_attempt_failed = guest
                        .pending_join_roster_receipts
                        .receipts
                        .lock()
                        .is_ok_and(|receipts| {
                            receipts
                                .get(&expected_roster_event_id)
                                .is_some_and(|receipt| receipt.failed_attempts >= 1)
                        });
                    if first_attempt_failed {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("the forced unrouted receipt attempt did not fail");
            assert_eq!(
                guest
                    .pending_join_roster_receipts
                    .receipts
                    .lock()
                    .expect("pending receipt lock")
                    .len(),
                1,
                "the first unrouted receipt attempt must remain queued"
            );
        }
        if receipt_failure == JoinReceiptFailure::WithoutRestart {
            guest
                .pending_join_roster_receipts
                .receipts
                .lock()
                .expect("pending receipt lock")
                .get_mut(&expected_roster_event_id)
                .expect("failed receipt remains queued")
                .destination = admin_identity;
            guest.pending_join_roster_receipts.changed.notify_one();
        } else if receipt_failure == JoinReceiptFailure::AcrossRestart {
            assert!(
                guest_receipt_path.exists(),
                "committed receipt must be durable before the old tunnel is interrupted"
            );
            let persisted_bytes =
                std::fs::read(&guest_receipt_path).expect("read committed receipt sidecar");
            let persisted: PersistedPendingJoinRosterReceipts =
                serde_json::from_slice(&persisted_bytes)
                    .expect("decode committed receipt sidecar");
            assert_eq!(persisted.version, PENDING_JOIN_ROSTER_RECEIPTS_VERSION);
            assert_eq!(persisted.receipts.len(), 1);
            assert_eq!(
                persisted.receipts[0].roster_event_id,
                expected_roster_event_id
            );
            assert_eq!(
                persisted.receipts[0].destination_npub,
                admin_identity.npub()
            );
            assert!(persisted.receipts[0].committed);
            #[cfg(unix)]
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(
                    &std::fs::metadata(&guest_receipt_path)
                        .expect("committed receipt sidecar metadata")
                        .permissions()
                ) & 0o777,
                0o600,
                "receipt sidecar must be private"
            );
            shutdown_started_mobile_tunnel(guest).await;

            let mut restarted_mobile =
                MobileTunnelConfig::from_app_with_config_path(&joined_app, &guest_config_path)
                    .expect("restarted guest config");
            restarted_mobile.detach_from_persisted_config_path();
            restarted_mobile.listen_port = guest_listen_port;
            guest = Box::pin(MobileTunnel::start_async_with_launch_state(
                restarted_mobile,
                joined_app.clone(),
                Vec::new(),
                None,
                Some(guest_config_path.clone()),
            ))
            .await
            .expect("restart joined guest with durable receipt sidecar");
            assert_eq!(
                guest.endpoint.npub(),
                guest_identity.npub(),
                "the restarted tunnel must preserve its authenticated endpoint identity"
            );
            {
                let receipts = guest
                    .pending_join_roster_receipts
                    .receipts
                    .lock()
                    .expect("restarted pending receipt lock");
                let receipt = receipts
                    .get(&expected_roster_event_id)
                    .expect("restart must reload the exact committed receipt");
                assert!(receipt.committed);
                assert_eq!(receipt.destination, admin_identity);
            }
        }
        let receipt_deadline = match receipt_failure {
            JoinReceiptFailure::None => Duration::from_secs(8),
            JoinReceiptFailure::WithoutRestart | JoinReceiptFailure::AcrossRestart => {
                Duration::from_secs(15)
            }
        };
        let observed_receipt = tokio::time::timeout(receipt_deadline, async {
            loop {
                let received = observed_admin_receipts
                    .recv()
                    .await
                    .expect("admin receipt observation channel closed");
                if matches!(received.frame, FipsControlFrame::JoinRosterAck { .. }) {
                    break received;
                }
            }
        })
        .await
        .expect("admin did not observe the host-commit receipt");
        assert_eq!(
            observed_receipt.source_peer, guest_identity,
            "receipt source must be the approved guest endpoint identity"
        );
        assert!(matches!(
            observed_receipt.frame,
            FipsControlFrame::JoinRosterAck { ref roster_event_id }
                if roster_event_id == &expected_roster_event_id
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let delivered_receipt_removed = guest
                    .pending_join_roster_receipts
                    .receipts
                    .lock()
                    .is_ok_and(|receipts| receipts.is_empty());
                if delivered_receipt_removed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the approving phone received the durable receipt but it remained queued");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if nostr_vpn_core::join_delivery::load_join_rosters(&admin_config_path).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("admin approval outbox was not removed after the exact durable receipt");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let no_pending_receipts = guest
                    .pending_join_roster_receipts
                    .receipts
                    .lock()
                    .is_ok_and(|receipts| receipts.is_empty());
                if no_pending_receipts && !guest_receipt_path.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("receipt sidecar remained after all transport-confirmed deliveries");
        assert_eq!(
            guest
                .take_app_config_toml()
                .expect("read acknowledged UI handoff"),
            ""
        );
        let ui_handoff_acknowledged_at = Instant::now();
        eprintln!(
            "mobile QR join latency: setup_auth={:?} signed_roster_delivery_and_durable_apply={:?} new_network_control={:?} ui_handoff_ack={:?} total={:?}",
            authenticated_at.duration_since(test_started_at),
            roster_applied_at.duration_since(authenticated_at),
            new_network_control_at.duration_since(roster_applied_at),
            ui_handoff_acknowledged_at.duration_since(new_network_control_at),
            ui_handoff_acknowledged_at.duration_since(test_started_at),
        );

        shutdown_started_mobile_tunnel(admin).await;
        shutdown_started_mobile_tunnel(guest).await;
        router.shutdown().await.expect("shutdown router");
        seed.shutdown().await.expect("shutdown WebSocket seed");
        let _ = std::fs::remove_dir_all(admin_dir);
    }
