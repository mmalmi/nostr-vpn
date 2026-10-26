// Exercise mobile's probe policy with generated peers and real loopback FIPS
// endpoints. Transport/session recovery itself remains owned by FIPS.
fn mobile_path_refresh_apps() -> [AppConfig; 3] {
    let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
    let participants = keys.each_ref().map(|key| key.public_key().to_hex());
    let mut base = admin_join_request_app(
        &keys[0].secret_key().to_bech32().expect("admin secret"),
        &participants[0],
        "mobile-path-refresh",
    );
    base.networks[0].devices = participants.to_vec();
    base.fips_nostr_discovery_enabled = false;
    base.fips_webrtc_enabled = false;
    base.lan_discovery_enabled = false;
    base.fips_bootstrap_enabled = false;
    base.fips_bootstrap_peers.clear();
    base.fips_websocket_seed_urls.clear();
    base.nostr.relays.clear();
    let roster = SignedRoster::sign(
        &base.networks[0].network_id,
        NetworkRoster {
            network_name: "Home".to_string(),
            devices: participants.to_vec(),
            admins: vec![participants[0].clone()],
            aliases: HashMap::default(),
            signed_at: unix_timestamp(),
        },
        &keys[0],
    )
    .expect("signed test roster");
    keys.each_ref().map(|key| {
        let mut app = base.clone();
        app.nostr.public_key = key.public_key().to_hex();
        app.nostr.secret_key = key.secret_key().to_bech32().expect("peer secret");
        // Derive each address only after assigning its identity.
        assert!(
            app.apply_verified_admin_signed_shared_roster(&roster)
                .expect("apply roster")
        );
        app
    })
}

fn mobile_path_refresh_config(app: &AppConfig) -> MobileTunnelConfig {
    let mut config = MobileTunnelConfig::from_app(app).expect("mobile config");
    config.listen_port = 0;
    config.share_local_candidates = false;
    config.peer_hints.clear();
    config
}

async fn mobile_path_listen_port(endpoint: &FipsEndpoint) -> u16 {
    endpoint
        .bound_udp_listen_addrs()
        .await
        .expect("bound UDP listeners")
        .into_iter()
        .find(|addr| addr.is_ipv4())
        .expect("bound IPv4 listener")
        .port()
}

async fn mobile_path_peer(endpoint: &FipsEndpoint, participant: &str) -> Option<FipsEndpointPeer> {
    let npub = PublicKey::from_hex(participant)
        .expect("participant")
        .to_bech32()
        .expect("peer npub");
    endpoint
        .peers()
        .await
        .expect("peer snapshot")
        .into_iter()
        .find(|peer| peer.npub == npub)
}

async fn wait_mobile_path_link(endpoint: &FipsEndpoint, participant: &str) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if mobile_path_peer(endpoint, participant)
                .await
                .is_some_and(|peer| peer.connected)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("authenticated link must connect");
}

async fn mobile_path_packet(
    sender: &MobileTunnelStarted,
    receiver: &mut MobileTunnelStarted,
    sequence: u32,
) {
    let source =
        parse_ipv4(&sender.config.read().expect("sender config").local_address).expect("source");
    let destination = parse_ipv4(
        &receiver
            .config
            .read()
            .expect("receiver config")
            .local_address,
    )
    .expect("destination");
    let mut packet = ipv4_udp_packet(source, destination, 43001, 43002, &sequence.to_be_bytes());
    nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut packet);
    sender
        .outbound_tx
        .send(vec![packet.clone()])
        .await
        .expect("outbound packet");
    let batch = tokio::time::timeout(Duration::from_secs(5), receiver.inbound_rx.recv())
        .await
        .expect("admitted mesh packet must arrive")
        .expect("inbound channel");
    assert_eq!(
        batch,
        vec![packet],
        "verify exact bytes, not only link status"
    );
}

// Advance only the app's due-probe input, never FIPS link/handshake timers.
async fn force_mobile_path_probe(
    mobile: &MobileTunnelStarted,
    config: &MobileTunnelConfig,
    participant: &str,
) {
    mobile
        .presence
        .write()
        .expect("presence")
        .entry(participant.to_string())
        .or_default()
        .last_ping_sent_at = None;
    let identities = Arc::new(RwLock::new(mobile_peer_identity_map(
        &config.peers,
        &config.bootstrap_peers,
    )));
    mobile_ping_peers(
        &mobile.endpoint,
        &mobile.mesh,
        &identities,
        &mobile.presence,
        &config.network_id,
        &config.bootstrap_peers,
    )
    .await
    .expect("due mobile probe");
}

#[test]
fn mobile_due_probe_recovers_exhausted_peer_preserving_healthy_peer() {
    run_mobile_path_refresh_recovery(false);
}

#[test]
#[ignore = "uses the real five-minute mobile discovery interval"]
fn mobile_background_probe_recovers_exhausted_peer_preserving_healthy_peer() {
    run_mobile_path_refresh_recovery(true);
}

// Keep the outage, healthy traffic and recovery assertions in one lifecycle.
#[allow(clippy::too_many_lines)]
fn run_mobile_path_refresh_recovery(background_timer: bool) {
    run_desktop_mobile_join_test("mobile-path-refresh", move || {
        RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(Box::pin(async {
                let [server_app, phone_app, healthy_app] = mobile_path_refresh_apps();
                let server_key = server_app.own_nostr_pubkey_hex().expect("server key");
                let healthy_key = healthy_app.own_nostr_pubkey_hex().expect("healthy key");
                let mut server_config = mobile_path_refresh_config(&server_app);
                let mut phone_config = mobile_path_refresh_config(&phone_app);
                let healthy_config = mobile_path_refresh_config(&healthy_app);
                assert_ne!(phone_config.local_address, server_config.local_address);
                assert_ne!(phone_config.local_address, healthy_config.local_address);
                assert_ne!(server_config.local_address, healthy_config.local_address);
                let mut server = Box::pin(MobileTunnel::start_async(
                    server_config.clone(),
                    server_app.clone(),
                ))
                .await
                .expect("server");
                let mut healthy = Box::pin(MobileTunnel::start_async(healthy_config, healthy_app))
                    .await
                    .expect("healthy peer");
                // Use ports already owned by the live endpoints, so parallel
                // tests cannot claim them between reservation and startup.
                // Retain the server's actual port for its later restart.
                server_config.listen_port = mobile_path_listen_port(&server.endpoint).await;
                // Only the phone can dial. A restarted server cannot repair the
                // test by initiating its own reverse connection to the phone.
                add_direct_mobile_peer_hint(
                    &mut phone_config,
                    &server_key,
                    server_config.listen_port,
                );
                add_direct_mobile_peer_hint(
                    &mut phone_config,
                    &healthy_key,
                    mobile_path_listen_port(&healthy.endpoint).await,
                );
                let mut phone =
                    Box::pin(MobileTunnel::start_async(phone_config.clone(), phone_app))
                        .await
                        .expect("phone");
                wait_mobile_path_link(&phone.endpoint, &server_key).await;
                wait_mobile_path_link(&phone.endpoint, &healthy_key).await;
                mobile_path_packet(&phone, &mut server, 1).await;
                mobile_path_packet(&server, &mut phone, 2).await;
                mobile_path_packet(&phone, &mut healthy, 3).await;
                mobile_path_packet(&healthy, &mut phone, 4).await;
                let endpoint = Arc::clone(&phone.endpoint);
                let identity = phone.endpoint.npub().to_string();
                let healthy_link = mobile_path_peer(&phone.endpoint, &healthy_key)
                    .await
                    .expect("healthy link")
                    .link_id;
                let healthy_refresh = phone
                    .presence
                    .read()
                    .expect("presence")
                    .get(&healthy_key)
                    .expect("healthy presence")
                    .last_path_refresh_attempt_at;
                shutdown_started_mobile_tunnel(server).await;
                // Reach a real link-dead timeout while the unrelated peer keeps
                // exchanging bytes through the very same phone endpoint.
                let loss_deadline = tokio::time::Instant::now() + Duration::from_secs(50);
                while tokio::time::Instant::now() < loss_deadline {
                    mobile_path_packet(&phone, &mut healthy, 5).await;
                    mobile_path_packet(&healthy, &mut phone, 6).await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                assert!(
                    !mobile_path_peer(&phone.endpoint, &server_key)
                        .await
                        .is_some_and(|peer| peer.connected || peer.direct_probe_pending),
                    "recovery must start from an exhausted path"
                );
                let mut server = Box::pin(MobileTunnel::start_async(server_config, server_app))
                    .await
                    .expect("same server identity and port return");
                if !background_timer {
                    // Startup may already have requested a refresh. Advance
                    // both app retry inputs, not the native transport timers.
                    phone
                        .presence
                        .write()
                        .expect("presence")
                        .entry(server_key.clone())
                        .or_default()
                        .last_path_refresh_attempt_at = Some(
                        unix_timestamp().saturating_sub(MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS),
                    );
                    force_mobile_path_probe(&phone, &phone_config, &server_key).await;
                }
                // The background branch never edits scheduler timestamps or
                // calls a manual probe. Keep healthy traffic running throughout.
                tokio::time::timeout(
                    Duration::from_secs(if background_timer { 350 } else { 8 }),
                    async {
                        loop {
                            mobile_path_packet(&phone, &mut healthy, 7).await;
                            mobile_path_packet(&healthy, &mut phone, 8).await;
                            if mobile_path_peer(&phone.endpoint, &server_key)
                                .await
                                .is_some_and(|peer| peer.connected)
                            {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                )
                .await
                .expect("mobile probe must recover the exhausted peer");
                mobile_path_packet(&phone, &mut server, 9).await;
                mobile_path_packet(&server, &mut phone, 10).await;
                assert!(
                    phone
                        .presence
                        .read()
                        .expect("presence")
                        .get(&server_key)
                        .expect("server presence")
                        .last_path_refresh_attempt_at
                        .is_some()
                );
                assert!(Arc::ptr_eq(&endpoint, &phone.endpoint));
                assert_eq!(phone.endpoint.npub(), identity);
                let config = phone.config.read().expect("phone config").clone();
                assert_eq!(config.local_address, phone_config.local_address);
                assert_eq!(config.network_id, phone_config.network_id);
                assert!(
                    phone
                        .endpoint
                        .peers()
                        .await
                        .expect("peers")
                        .iter()
                        .all(|peer| !peer.direct_probe_auto_reconnect)
                );
                // A connected path must also be preserved when the app's
                // presence sample is stale, rather than relying on that guard.
                phone
                    .presence
                    .write()
                    .expect("presence")
                    .get_mut(&healthy_key)
                    .expect("healthy presence")
                    .last_seen_at = None;
                force_mobile_path_probe(&phone, &phone_config, &healthy_key).await;
                assert_eq!(
                    phone
                        .presence
                        .read()
                        .expect("presence")
                        .get(&healthy_key)
                        .expect("healthy presence")
                        .last_path_refresh_attempt_at,
                    healthy_refresh
                );
                assert_eq!(
                    mobile_path_peer(&phone.endpoint, &healthy_key)
                        .await
                        .expect("healthy link")
                        .link_id,
                    healthy_link
                );
                mobile_path_packet(&phone, &mut healthy, 11).await;
                mobile_path_packet(&healthy, &mut phone, 12).await;
                shutdown_started_mobile_tunnel(phone).await;
                shutdown_started_mobile_tunnel(server).await;
                shutdown_started_mobile_tunnel(healthy).await;
            }));
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn mobile_path_refresh_throttles_failed_transit_attempts_and_preserves_fresh_presence() {
    run_desktop_mobile_join_test("mobile-refresh-cadence", || {
        RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(Box::pin(async {
                let [server_app, phone_app, _] = mobile_path_refresh_apps();
                let server_key = server_app.own_nostr_pubkey_hex().expect("server key");
                let mut config = mobile_path_refresh_config(&phone_app);
                // Mobile has no TCP carrier. Disable FIPS's internal retries
                // in this policy fixture so its pending guard cannot mask a
                // broken app-level throttle. Do not change any link timers.
                let hints = vec![FipsPeerAddressHint {
                    addr: "tcp://127.0.0.1:1".to_string(),
                    seen_at_ms: None,
                    priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
                }];
                config.peer_hints.insert(server_key.clone(), hints.clone());
                config.bootstrap_peers.insert(server_key.clone(), hints);
                let mut fips = fips_endpoint_config("mobile-refresh-cadence", &config);
                fips.node.retry.max_retries = 0;
                let endpoint = Box::pin(
                    FipsEndpoint::builder()
                        .config(fips)
                        .identity_nsec(config.identity_nsec.clone())
                        .without_system_tun()
                        .bind(),
                )
                .await
                .expect("endpoint");
                let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
                    config.peers.clone(),
                    vec![config.local_address.clone()],
                ));
                let presence = Arc::new(RwLock::new(HashMap::<String, MobilePeerPresence>::new()));
                let identities = Arc::new(RwLock::new(mobile_peer_identity_map(
                    &config.peers,
                    &config.bootstrap_peers,
                )));
                let probe = async || {
                    presence
                        .write()
                        .expect("presence")
                        .entry(server_key.clone())
                        .or_default()
                        .last_ping_sent_at = None;
                    mobile_ping_peers(
                        &endpoint,
                        &mesh,
                        &identities,
                        &presence,
                        &config.network_id,
                        &config.bootstrap_peers,
                    )
                    .await
                    .expect("due probe");
                    assert!(
                        !mobile_path_peer(&endpoint, &server_key)
                            .await
                            .is_some_and(|peer| peer.connected || peer.direct_probe_pending)
                    );
                };
                probe().await;
                let attempt = || {
                    presence
                        .read()
                        .expect("presence")
                        .get(&server_key)
                        .expect("presence entry")
                        .last_path_refresh_attempt_at
                };
                let first = attempt().expect("record failed attempt");
                // Use a distinct past timestamp so an erroneous refresh is
                // observable even when these calls run within one clock second.
                let previous_attempt = first - MOBILE_CONFIGURED_TRANSIT_PING_INTERVAL_SECS;
                presence
                    .write()
                    .expect("presence")
                    .get_mut(&server_key)
                    .expect("presence entry")
                    .last_path_refresh_attempt_at = Some(previous_attempt);
                // Transit Ping cadence is 10s, but repeated due Pings must not
                // request another refresh before the offline discovery interval.
                for _ in 0..3 {
                    probe().await;
                    assert_eq!(attempt(), Some(previous_attempt));
                }
                let recent_attempt =
                    unix_timestamp() - MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS / 2;
                presence
                    .write()
                    .expect("presence")
                    .get_mut(&server_key)
                    .expect("presence entry")
                    .last_path_refresh_attempt_at = Some(recent_attempt);
                probe().await;
                assert_eq!(attempt(), Some(recent_attempt));
                let expired_attempt = unix_timestamp() - MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS;
                {
                    let mut presence = presence.write().expect("presence");
                    let peer = presence.get_mut(&server_key).expect("presence entry");
                    peer.last_path_refresh_attempt_at = Some(expired_attempt);
                    peer.last_seen_at = Some(unix_timestamp());
                }
                probe().await;
                assert_eq!(
                    attempt(),
                    Some(expired_attempt),
                    "fresh app liveness must protect peers without a direct link"
                );
                presence
                    .write()
                    .expect("presence")
                    .get_mut(&server_key)
                    .expect("presence entry")
                    .last_seen_at = None;
                probe().await;
                assert!(
                    attempt().is_some_and(|at| at > expired_attempt),
                    "an exhausted peer must get another bounded attempt when due"
                );
                endpoint.shutdown().await.expect("shutdown endpoint");
            }));
    });
}

#[test]
fn mobile_path_refresh_leaves_pending_attempt_untouched() {
    run_desktop_mobile_join_test("mobile-refresh-pending", || {
        RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(Box::pin(async {
                let [server_app, phone_app, _] = mobile_path_refresh_apps();
                let server_key = server_app.own_nostr_pubkey_hex().expect("server key");
                // A missing carrier queues a real FIPS retry immediately,
                // without waiting for a native handshake timeout.
                let mut config = mobile_path_refresh_config(&phone_app);
                config.peer_hints.insert(
                    server_key.clone(),
                    vec![FipsPeerAddressHint {
                        addr: "tcp://127.0.0.1:1".to_string(),
                        seen_at_ms: None,
                        priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
                    }],
                );
                let phone = Box::pin(MobileTunnel::start_async(config.clone(), phone_app))
                    .await
                    .expect("phone");
                let pending = mobile_path_peer(&phone.endpoint, &server_key)
                    .await
                    .expect("queued retry");
                assert!(!pending.connected && pending.direct_probe_pending);
                phone
                    .presence
                    .write()
                    .expect("presence")
                    .entry(server_key.clone())
                    .or_default()
                    .last_path_refresh_attempt_at = None;
                for _ in 0..3 {
                    force_mobile_path_probe(&phone, &config, &server_key).await;
                    let presence = phone.presence.read().expect("presence");
                    let peer = presence.get(&server_key).expect("presence entry");
                    assert!(
                        peer.last_ping_sent_at.is_some(),
                        "exercise an already-due probe"
                    );
                    assert_eq!(
                        peer.last_path_refresh_attempt_at, None,
                        "do not refresh a pending path"
                    );
                }
                let after = mobile_path_peer(&phone.endpoint, &server_key)
                    .await
                    .expect("queued retry remains");
                assert_eq!(after.direct_probe_after_ms, pending.direct_probe_after_ms);
                assert_eq!(
                    after.direct_probe_retry_count,
                    pending.direct_probe_retry_count
                );
                shutdown_started_mobile_tunnel(phone).await;
            }));
    });
}
