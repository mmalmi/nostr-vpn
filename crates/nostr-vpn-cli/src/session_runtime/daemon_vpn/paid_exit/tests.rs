use super::*;

#[test]
fn payment_outbox_retry_is_bounded_and_logs_only_state_changes() {
    let start = Instant::now();
    let mut retry = PaidExitPaymentOutboxRetry::new(start);

    assert!(retry.due(start));
    assert!(retry.record_flush(start, 1, 0));
    assert!(!retry.due(start + Duration::from_secs(PAID_EXIT_PAYMENT_OUTBOX_RETRY_SECS - 1)));
    let next = start + Duration::from_secs(PAID_EXIT_PAYMENT_OUTBOX_RETRY_SECS);
    assert!(retry.due(next));
    assert!(!retry.record_flush(next, 1, 0));
    assert!(retry.record_flush(
        next + Duration::from_secs(PAID_EXIT_PAYMENT_OUTBOX_RETRY_SECS),
        0,
        0
    ));
}
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::paid_route_store::{
    OpenPaidRouteBuyerSessionRequest, PaidRouteLifecycleStatus,
};
use nostr_vpn_core::paid_routes::{
    PaidExitConfig, PaidRouteChannelTerms, PaidRouteIpSupport, signed_paid_exit_offer_from_config,
};

#[test]
fn manual_unacknowledged_session_fails_and_falls_back_to_direct() {
    let seller = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let mint = "https://mint.example";
    let offer_config = PaidExitConfig {
        enabled: true,
        channel: PaidRouteChannelTerms {
            accepted_mints: vec![mint.to_string()],
            max_channel_capacity_sat: 100,
            channel_expiry_secs: 600,
            free_probe_units: 1_048_576,
            ..PaidRouteChannelTerms::default()
        },
        ip_support: PaidRouteIpSupport {
            ipv4: true,
            ..PaidRouteIpSupport::default()
        },
        ..PaidExitConfig::default()
    };
    let signed =
        signed_paid_exit_offer_from_config("manual-timeout", &seller, &offer_config, None, 100)
            .expect("signed offer");
    let directory = std::env::temp_dir().join(format!(
        "nvpn-manual-paid-exit-timeout-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create test directory");
    let config_path = directory.join("config.toml");
    let store_path = paid_route_store_file_path(&config_path);
    let mut app = AppConfig::generated();
    let buyer_npub = app
        .nostr_keys()
        .expect("buyer keys")
        .public_key()
        .to_bech32()
        .expect("buyer npub");

    let session = update_paid_route_store(&store_path, |store| {
        store.upsert_wallet_mint(mint, "test", None, 100);
        store.upsert_signed_offer(signed, Vec::new(), 100)?;
        let session = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "manual-timeout".to_string(),
            buyer_npub,
            mint_url: Some(mint.to_string()),
            channel_capacity_sat: Some(20),
            initial_paid_msat: 0,
            now_unix: 100,
        })?;
        store.begin_buyer_session_open_attempt(&session.session_id, 100)?;
        Ok(session)
    })
    .expect("create selected buyer session");
    app.select_public_paid_exit_node(&seller_npub)
        .expect("select manual seller");
    app.save(&config_path).expect("save manual selection");

    let early = reconcile_selected_paid_exit_session(
        &mut app,
        &config_path,
        &seller.public_key().to_hex(),
        129,
    )
    .expect("early reconciliation");
    assert!(!early.selected_session_timed_out);
    assert_eq!(
        app.internet_source,
        nostr_vpn_core::config::InternetSource::PaidManual
    );

    let timed_out = reconcile_selected_paid_exit_session(
        &mut app,
        &config_path,
        &seller.public_key().to_hex(),
        130,
    )
    .expect("timeout reconciliation");
    assert!(timed_out.selected_session_timed_out);
    assert_eq!(timed_out.selected_session_id, session.session_id);
    assert_eq!(
        app.internet_source,
        nostr_vpn_core::config::InternetSource::Direct
    );
    assert_eq!(
        AppConfig::load(&config_path)
            .expect("saved direct fallback")
            .internet_source,
        nostr_vpn_core::config::InternetSource::Direct
    );
    let store = load_paid_route_store(&store_path).expect("reloaded failed session");
    assert_eq!(
        store.channels[&session.channel_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert!(
        store.channels[&session.channel_id]
            .error
            .contains("acknowledge")
    );

    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn seller_trial_uses_authenticated_carrier_ip_across_buyer_keys() {
    let dir = std::env::temp_dir().join(format!("nvpn-trial-carrier-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.paid_exit.channel.accepted_mints = vec!["https://mint.example".into()];
    let seller_npub = app.nostr_keys().unwrap().public_key().to_bech32().unwrap();
    let first = Keys::generate();
    let second = Keys::generate();
    let open = |lease: &str| PaidRouteSessionOpen {
        version: nostr_vpn_core::paid_routes::PAID_ROUTE_OFFER_VERSION.into(),
        service_id: "internet-exit".into(),
        lease_id: lease.into(),
        channel_id: format!("channel-{lease}"),
        seller_npub: seller_npub.clone(),
        buyer_tunnel_ip: "10.44.201.17/32".into(),
        expires_at_unix: unix_timestamp() + 600,
    };
    let mut peer = fips_endpoint::FipsEndpointPeer {
        npub: first.public_key().to_bech32().unwrap(),
        node_addr: fips_core::NodeAddr::from_bytes([7; 16]),
        connected: true,
        transport_addr: Some("203.0.113.9:2122".into()),
        transport_type: Some("udp".into()),
        link_id: 42,
        srtt_ms: None,
        srtt_age_ms: None,
        packets_sent: 1,
        packets_recv: 1,
        bytes_sent: 100,
        bytes_recv: 100,
        rekey_in_progress: false,
        rekey_draining: false,
        current_k_bit: None,
        last_outbound_route: None,
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        nostr_traversal_consecutive_failures: 0,
        nostr_traversal_in_cooldown: false,
        nostr_traversal_cooldown_until_ms: None,
        nostr_traversal_last_observed_skew_ms: None,
    };
    let result = apply_paid_exit_session_opens(
        &app,
        &config_path,
        vec![(first.public_key().to_hex(), open("first"))],
        &[peer.clone()],
    )
    .unwrap();
    assert_eq!(result.applied_count, 1);
    peer.npub = second.public_key().to_bech32().unwrap();
    let result = apply_paid_exit_session_opens(
        &app,
        &config_path,
        vec![(second.public_key().to_hex(), open("rotated-key"))],
        &[peer.clone()],
    )
    .unwrap();
    assert_eq!(result.error_count, 1);
    // An authenticated relay connection is not evidence of the buyer's IP.
    peer.transport_type = Some("websocket".into());
    peer.transport_addr = Some("203.0.113.10:443".into());
    let result = apply_paid_exit_session_opens(
        &app,
        &config_path,
        vec![(second.public_key().to_hex(), open("relay"))],
        &[peer.clone()],
    )
    .unwrap();
    assert_eq!(result.error_count, 1);
    peer.transport_type = Some("udp".into());
    peer.npub = first.public_key().to_bech32().unwrap();
    let result = apply_paid_exit_session_opens(
        &app,
        &config_path,
        vec![(second.public_key().to_hex(), open("other-hop"))],
        &[peer],
    )
    .unwrap();
    assert_eq!(result.error_count, 1);
    let store = load_paid_route_store(&paid_route_store_file_path(&config_path)).unwrap();
    assert_eq!(store.seller_free_probe_sources.len(), 1);
    assert!(store.seller_free_probe_sources.contains_key("203.0.113.9"));
    fs::remove_dir_all(dir).unwrap();
}
