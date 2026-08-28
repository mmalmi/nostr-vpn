#[cfg(feature = "paid-exit")]
fn paid_route_channel_open_frame(
    buyer_npub: &str,
    seller_npub: &str,
    seller_pubkey: &str,
    now_unix: u64,
) -> FipsControlFrame {
    let frame: FipsControlFrame = serde_json::from_value(serde_json::json!({
        "kind": "paid_route_payment",
        "id": "pending",
        "envelope": {
            "version": 1,
            "service_id": "mobile-paid-exit",
            "lease_id": "mobile-lease-1",
            "buyer": buyer_npub,
            "seller": seller_npub,
            "sent_at_unix": now_unix,
            "payload": {
                "type": "channel_open",
                "mint_url": "https://mint.example",
                "unit": "sat",
                "capacity": 10,
                "expires_unix": now_unix.saturating_add(600),
                "receiver_pubkey_hex": seller_pubkey,
                "paid_msat": 0,
                "payment": {
                    "channel_id": "mobile-channel-1",
                    "balance": 0,
                    "signature": "s".repeat(2_000),
                    "params": {"channel": "mobile-channel-1"},
                    "funding_proofs": {"proofs": []}
                }
            }
        }
    }))
    .expect("decode paid route payment frame");
    let FipsControlFrame::PaidRoutePayment { envelope, .. } = frame else {
        panic!("expected paid route payment frame");
    };
    let id =
        nostr_vpn_core::paid_route_store::paid_route_payment_id(&envelope).expect("payment id");
    FipsControlFrame::PaidRoutePayment { id, envelope }
}

#[cfg(feature = "paid-exit")]
#[test]
fn mobile_paid_route_payment_and_ack_roundtrip_over_real_fips_endpoint() {
    std::thread::Builder::new()
        .name("mobile-paid-route-fips".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mobile paid route test runtime")
                .block_on(mobile_paid_route_payment_and_ack_roundtrip());
        })
        .expect("spawn mobile paid route test")
        .join()
        .expect("mobile paid route test thread");
}

#[cfg(feature = "paid-exit")]
#[allow(clippy::too_many_lines)]
async fn mobile_paid_route_payment_and_ack_roundtrip() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-mobile-paid-route-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let seller_config_path = dir.join("seller/config.toml");
    let buyer_config_path = dir.join("buyer/config.toml");
    std::fs::create_dir_all(seller_config_path.parent().expect("seller config parent"))
        .expect("create seller config directory");
    std::fs::create_dir_all(buyer_config_path.parent().expect("buyer config parent"))
        .expect("create buyer config directory");

    let seller_keys = Keys::generate();
    let buyer_keys = Keys::generate();
    let seller_pubkey = seller_keys.public_key().to_hex();
    let buyer_pubkey = buyer_keys.public_key().to_hex();
    let seller_npub = seller_keys.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer_keys.public_key().to_bech32().expect("buyer npub");
    let seller_nsec = seller_keys.secret_key().to_bech32().expect("seller nsec");
    let buyer_nsec = buyer_keys.secret_key().to_bech32().expect("buyer nsec");
    let network_id = format!("mobile-paid-route-{nonce}");
    let scope = format!("nostr-vpn:{network_id}");

    let seller_mobile = fips_exit_mobile_config(
        seller_nsec.clone(),
        &seller_pubkey,
        &network_id,
        available_udp_port(),
    );
    let seller_endpoint = bind_local_mobile_endpoint(&scope, &seller_mobile).await;
    let seller_peer = FipsMeshPeerConfig::from_participant_pubkey(&seller_pubkey, Vec::new())
        .expect("seller peer");
    let mut buyer_hints = HashMap::new();
    buyer_hints.insert(
        seller_pubkey.clone(),
        vec![FipsPeerAddressHint {
            addr: format!("127.0.0.1:{}", seller_mobile.listen_port),
            seen_at_ms: None,
            priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
        }],
    );
    let buyer_mobile = MobileTunnelConfig {
        identity_nsec: buyer_nsec.clone(),
        node_name: "paid-route-buyer".to_string(),
        network_id: network_id.clone(),
        local_address: derive_mesh_tunnel_ip(&network_id, &buyer_pubkey).expect("buyer tunnel ip"),
        listen_port: available_udp_port(),
        peers: vec![seller_peer],
        peer_hints: buyer_hints,
        nostr_discovery_enabled: false,
        ..empty_config()
    };
    let buyer_endpoint = bind_local_mobile_endpoint(&scope, &buyer_mobile).await;
    let mut seller_state_control =
        FipsControlTcpRuntime::start(Arc::clone(&seller_endpoint))
            .await
            .expect("start seller state control");
    let seller_state_sender = seller_state_control.sender();
    let mut buyer_state_control = FipsControlTcpRuntime::start(Arc::clone(&buyer_endpoint))
        .await
        .expect("start buyer state control");
    let buyer_state_sender = buyer_state_control.sender();

    let now_unix = unix_timestamp();
    let payment =
        paid_route_channel_open_frame(&buyer_npub, &seller_npub, &seller_pubkey, now_unix);
    let (payment_id, payment_envelope) = match &payment {
        FipsControlFrame::PaidRoutePayment { id, envelope } => (id.clone(), envelope.clone()),
        _ => panic!("expected payment frame"),
    };
    let encoded = encode_fips_control_frame(&payment).expect("encode payment record");
    assert!(
        encoded.len() > 1_100,
        "test payment must exceed the old datagram fragment threshold"
    );

    let outbox =
        nostr_vpn_core::paid_route_store::paid_route_payment_outbox_directory(&buyer_config_path);
    std::fs::create_dir_all(&outbox).expect("create payment outbox");
    let outbox_entry = outbox.join(format!("{payment_id}.json"));
    std::fs::write(
        &outbox_entry,
        serde_json::to_vec(&payment_envelope).expect("encode payment envelope"),
    )
    .expect("write payment outbox entry");

    let mut seller_app = AppConfig::generated();
    seller_app.nostr.public_key = seller_pubkey.clone();
    seller_app.nostr.secret_key = seller_nsec;
    seller_app.paid_exit.enabled = true;
    seller_app.paid_exit.pricing.price_msat_per_gb = 2_500;
    seller_app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
    seller_app.paid_exit.channel.max_channel_capacity_sat = 100;
    seller_app.paid_exit.channel.channel_expiry_secs = 600;
    seller_app.paid_exit.channel.free_probe_units = 1_048_576;
    seller_app.ensure_defaults();

    let seller_mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
        Vec::new(),
        vec![seller_mobile.local_address.clone()],
    ));
    let seller_mesh_peers = Arc::new(RwLock::new(Vec::new()));
    let seller_peer_identities = Arc::new(RwLock::new(MobilePeerIdentityMap::default()));
    let seller_peer_hints = Arc::new(RwLock::new(HashMap::new()));
    let seller_presence = Arc::new(RwLock::new(HashMap::new()));
    let seller_config_state = Arc::new(RwLock::new(seller_mobile));
    let seller_app_config = Arc::new(RwLock::new(seller_app));
    let seller_dirty = AtomicBool::new(false);
    let seller_join = AtomicBool::new(false);
    let seller_pending_join_roster_receipts =
        Arc::new(PendingJoinRosterReceiptQueue::default());
    let seller_control = MobileEndpointReceiveContext {
        endpoint: &seller_endpoint,
        mesh: &seller_mesh,
        mesh_peers: &seller_mesh_peers,
        peer_identities: &seller_peer_identities,
        peer_hints: &seller_peer_hints,
        presence: &seller_presence,
        config_state: &seller_config_state,
        app_config: &seller_app_config,
        app_config_dirty: &seller_dirty,
        pending_join_roster_receipts: &seller_pending_join_roster_receipts,
        config_path: Some(&seller_config_path),
        join_request_active: &seller_join,
        state_control: &seller_state_sender,
    };
    let seller_identity =
        PeerIdentity::from_npub(seller_endpoint.npub()).expect("seller endpoint identity");
    let forged_buyer = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("forged buyer npub");
    let forged_payment =
        paid_route_channel_open_frame(&forged_buyer, &seller_npub, &seller_pubkey, now_unix);
    let (forged_sent, forged_received) = tokio::join!(
        buyer_state_sender.send(seller_identity, &forged_payment),
        tokio::time::timeout(Duration::from_secs(5), seller_state_control.recv()),
    );
    forged_sent.expect("send forged payment record over FIPS-TCP");
    let forged_error = handle_mobile_state_control_frame(
        &seller_control,
        forged_received
            .expect("forged payment receive timeout")
            .expect("seller state-control service closed"),
    )
    .await
    .expect_err("spoofed payment must be rejected");
    assert!(
        forged_error
            .to_string()
            .contains("buyer does not match authenticated FIPS source"),
        "spoofed payment must be source-bound"
    );
    assert!(
        !nostr_vpn_core::paid_route_store::paid_route_store_file_path(&seller_config_path).exists(),
        "rejected payment must not create seller state"
    );

    let (payment_sent, payment_received) = tokio::join!(
        buyer_state_sender.send(seller_identity, &payment),
        tokio::time::timeout(Duration::from_secs(5), seller_state_control.recv()),
    );
    payment_sent.expect("send payment record over FIPS-TCP");
    handle_mobile_state_control_frame(
        &seller_control,
        payment_received
            .expect("payment receive timeout")
            .expect("seller state-control service closed"),
    )
    .await
    .expect("handle mobile payment control");

    let seller_store_path =
        nostr_vpn_core::paid_route_store::paid_route_store_file_path(&seller_config_path);
    let seller_store = nostr_vpn_core::paid_route_store::load_paid_route_store(&seller_store_path)
        .expect("load seller paid route store");
    assert!(seller_store.channels.contains_key("mobile-channel-1"));

    let ack_message = tokio::time::timeout(Duration::from_secs(5), buyer_state_control.recv())
        .await
        .expect("payment acknowledgment receive timeout")
        .expect("buyer state-control service closed");
    assert!(matches!(
        &ack_message.frame,
        FipsControlFrame::PaidRoutePaymentAck { id } if id == &payment_id
    ));
    let wrong_source = nostr_vpn_core::paid_route_store::acknowledge_paid_route_payment_outbox(
        &buyer_config_path,
        &buyer_pubkey,
        &payment_id,
    )
    .expect_err("non-seller source must not clear payment outbox");
    assert!(
        wrong_source
            .to_string()
            .contains("acknowledgment source does not match seller")
    );
    assert!(outbox_entry.exists());
    let buyer_mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
        buyer_mobile.peers.clone(),
        vec![buyer_mobile.local_address.clone()],
    ));
    let buyer_mesh_peers = Arc::new(RwLock::new(buyer_mobile.peers.clone()));
    let buyer_peer_identities =
        Arc::new(RwLock::new(mobile_peer_identity_map(
            &buyer_mobile.peers,
            &buyer_mobile.bootstrap_peers,
        )));
    let buyer_peer_hints = Arc::new(RwLock::new(buyer_mobile.peer_hints.clone()));
    let buyer_presence = Arc::new(RwLock::new(HashMap::new()));
    let buyer_config_state = Arc::new(RwLock::new(buyer_mobile));
    let mut buyer_app = AppConfig::generated();
    buyer_app.nostr.public_key = buyer_pubkey;
    buyer_app.nostr.secret_key = buyer_nsec;
    buyer_app.ensure_defaults();
    let buyer_app_config = Arc::new(RwLock::new(buyer_app));
    let buyer_dirty = AtomicBool::new(false);
    let buyer_join = AtomicBool::new(false);
    let buyer_pending_join_roster_receipts =
        Arc::new(PendingJoinRosterReceiptQueue::default());
    let buyer_control = MobileEndpointReceiveContext {
        endpoint: &buyer_endpoint,
        mesh: &buyer_mesh,
        mesh_peers: &buyer_mesh_peers,
        peer_identities: &buyer_peer_identities,
        peer_hints: &buyer_peer_hints,
        presence: &buyer_presence,
        config_state: &buyer_config_state,
        app_config: &buyer_app_config,
        app_config_dirty: &buyer_dirty,
        pending_join_roster_receipts: &buyer_pending_join_roster_receipts,
        config_path: Some(&buyer_config_path),
        join_request_active: &buyer_join,
        state_control: &buyer_state_sender,
    };
    handle_mobile_state_control_frame(&buyer_control, ack_message)
        .await
        .expect("handle mobile payment ack");
    assert!(
        !outbox_entry.exists(),
        "seller-bound ack clears payment outbox"
    );

    buyer_state_control.stop().await;
    seller_state_control.stop().await;
    let _ = buyer_endpoint.shutdown().await;
    let _ = seller_endpoint.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
