use super::*;

fn fixture(
    max_capacity: u64,
    balance_msat: Option<u64>,
    bytes: u64,
) -> (PaidRouteStore, String, Keys, PaidExitConfig) {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 100_000;
    config.channel.max_channel_capacity_sat = max_capacity;
    config.channel.channel_expiry_secs = 86_400;
    let (mut store, session, _) = buyer_store_with_session(&seller, &buyer, &config);
    store.upsert_wallet_mint(&config.channel.accepted_mints[0], "Mint", balance_msat, 120);
    store
        .begin_buyer_session_open_attempt(&session, 120)
        .unwrap();
    if bytes > 0 {
        store
            .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
                seller_pubkey: seller.public_key().to_hex(),
                usage_delta: PaidRouteUsage {
                    billable_bytes: bytes,
                    ..Default::default()
                },
                now_unix: 720,
            })
            .unwrap()
            .unwrap();
    }
    (store, session, seller, config)
}

#[test]
fn expired_offer_cannot_start_an_adaptive_renewal() {
    let (mut store, session, _, _) = fixture(1_000, Some(100_000), 50_000_000);
    let before = store.sessions.len();
    let error = store
        .prepare_buyer_session_renewal(&session, 5_000)
        .unwrap_err();
    assert!(error.to_string().contains("expired"), "{error}");
    assert_eq!(store.sessions.len(), before);
    assert!(!store.buyer_session_renewals.contains_key(&session));
}

#[test]
fn adaptive_capacity_uses_delivered_traffic_for_renewal() {
    let (mut store, original, _, _) = fixture(1_000, Some(500_000), 0);
    assert_eq!(
        store
            .select_automatic_offer(120)
            .unwrap()
            .channel_capacity_sat,
        11
    );
    let seller = store.channels[&store.sessions[&original].session.payment.channel_id]
        .counterparty_npub
        .clone();
    store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller,
            usage_delta: PaidRouteUsage {
                billable_bytes: 100_000_000,
                ..Default::default()
            },
            now_unix: 720,
        })
        .unwrap()
        .unwrap();
    assert!(store.buyer_session_needs_renewal(&original, 720).unwrap());
    let next = store.prepare_buyer_session_renewal(&original, 720).unwrap();
    // 100 MB in ten minutes forecasts 600 MB for the next hour: 60 sat.
    assert_eq!(store.sessions[&next].session.payment.capacity_sat, 60);
    assert_eq!(store.selected_buyer_session_id, original);
    assert_eq!(store.sessions[&original].session.payment.capacity_sat, 10);
    assert_eq!(store.sessions[&next].session.usage.billable_bytes, 0);
}

#[test]
fn adaptive_capacity_retains_failed_renewal_size_across_restart_and_reselection() {
    let (mut store, original, seller, config) = fixture(1_000, Some(500_000), 100_000_000);
    let next = store.prepare_buyer_session_renewal(&original, 720).unwrap();
    store.begin_buyer_session_funding(&next, 721).unwrap();
    store
        .record_buyer_session_funding_shortfall(&next, 70)
        .unwrap();
    store
        .defer_buyer_mint_retry(
            &config.channel.accepted_mints[0],
            721,
            Some("Mint unavailable"),
            Some(600),
        )
        .unwrap();
    let scratch = ScratchDir::new("adaptive-capacity");
    let path = scratch.path().join("paid-routes.json");
    update_paid_route_store(&path, |saved| {
        *saved = store;
        Ok(())
    })
    .unwrap();
    let mut store = load_paid_route_store(&path).unwrap();
    assert_eq!(
        store.prepare_buyer_session_renewal(&original, 900).unwrap(),
        next
    );
    assert_eq!(store.sessions[&next].session.payment.capacity_sat, 60);
    // Refresh the advert after the traffic sample has aged out. A failed mint
    // retry must not make fresh selection fall back to an 11-sat purchase.
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, 4_900).unwrap();
    store.upsert_signed_offer(signed, vec![], 4_900).unwrap();
    assert_eq!(
        store
            .select_automatic_offer(5_000)
            .unwrap()
            .channel_capacity_sat,
        60
    );
}

#[test]
fn adaptive_capacity_respects_wallet_seller_and_automatic_limits() {
    for (seller_max, balance, bytes, expected) in [
        (1_000, Some(20_000), 100_000_000, 20),
        (30, Some(500_000), 100_000_000, 30),
        (5_000, Some(5_000_000), u64::MAX, 1_000),
    ] {
        let (mut store, original, _, _) = fixture(seller_max, balance, bytes);
        assert_eq!(
            store
                .select_automatic_offer(720)
                .unwrap()
                .channel_capacity_sat,
            expected
        );
        let next = store.prepare_buyer_session_renewal(&original, 720).unwrap();
        assert_eq!(store.sessions[&next].session.payment.capacity_sat, expected);
    }
    let (mut store, original, _, _) = fixture(1_000, Some(0), 100_000_000);
    let before = store.clone();
    assert!(store.prepare_buyer_session_renewal(&original, 720).is_err());
    assert_eq!(
        store, before,
        "an empty wallet must not open another unfundable renewal"
    );
}

#[test]
fn adaptive_capacity_times_usage_from_admission_and_renewal_handover() {
    let (mut store, original, seller, _) = fixture(1_000, Some(500_000), 0);
    let lease = store.sessions[&original].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease, 300)
        .unwrap();
    store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 60_000_000,
                ..Default::default()
            },
            now_unix: 900,
        })
        .unwrap()
        .unwrap();
    let next = store.prepare_buyer_session_renewal(&original, 900).unwrap();
    assert_eq!(store.sessions[&next].session.payment.capacity_sat, 36);
    // A repeated acknowledgment cannot shrink the observation period.
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease, 1_300)
        .unwrap();
    assert_eq!(
        store
            .select_automatic_offer(1_300)
            .unwrap()
            .channel_capacity_sat,
        36
    );
    store
        .start_buyer_session_renewal_handover(&original, 1_500)
        .unwrap();
    let usage = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 120_000_000,
                ..Default::default()
            },
            now_unix: 2_100,
        })
        .unwrap()
        .unwrap();
    assert_eq!(usage.session_id, next);
    let next_lease = store.sessions[&next].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &next_lease, 2_101)
        .unwrap();
    store
        .activate_buyer_session_renewal(&original, 2_101)
        .unwrap();
    assert_eq!(
        store
            .select_automatic_offer(2_102)
            .unwrap()
            .channel_capacity_sat,
        72,
        "time waiting for handover must not lower the measured traffic rate"
    );
}

#[test]
fn adaptive_capacity_ignores_stale_and_future_samples_and_preserves_explicit_amounts() {
    let (mut store, original, seller, config) = fixture(1_000, Some(500_000), 100_000_000);
    let mut legacy = serde_json::to_value(&store).unwrap();
    for session in legacy["sessions"].as_object_mut().unwrap().values_mut() {
        session
            .as_object_mut()
            .unwrap()
            .remove("last_usage_at_unix");
        session
            .as_object_mut()
            .unwrap()
            .remove("usage_started_at_unix");
    }
    let mut legacy: PaidRouteStore = serde_json::from_value(legacy).unwrap();
    assert_eq!(
        legacy
            .select_automatic_offer(720)
            .unwrap()
            .channel_capacity_sat,
        11,
        "old stores remain readable and wait for locally timed traffic"
    );
    let legacy_lease = legacy.sessions[&original].session.lease_id.clone();
    legacy
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &legacy_lease, 900)
        .unwrap();
    legacy
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 1_000_000,
                ..Default::default()
            },
            now_unix: 920,
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        legacy
            .select_automatic_offer(920)
            .unwrap()
            .channel_capacity_sat,
        46,
        "old traffic must not be attributed to the recent reconnect's short measurement window"
    );
    assert_eq!(
        store
            .select_automatic_offer(719)
            .unwrap()
            .channel_capacity_sat,
        11
    );
    let explicit = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".into(),
            buyer_npub: store.leases[&store.sessions[&original].session.lease_id]
                .lease
                .buyer_npub
                .clone(),
            mint_url: None,
            channel_capacity_sat: Some(7),
            initial_paid_msat: 0,
            now_unix: 730,
        })
        .unwrap();
    assert_eq!(explicit.channel_capacity_sat, 7);
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, 4_900).unwrap();
    store.upsert_signed_offer(signed, vec![], 4_900).unwrap();
    assert_eq!(
        store
            .select_automatic_offer(5_000)
            .unwrap()
            .channel_capacity_sat,
        11
    );
}

#[test]
fn adaptive_capacity_bounds_forecast_by_the_new_contracts_usable_lifetime() {
    let (mut store, original, seller, mut config) = fixture(1_000, Some(500_000), 100_000_000);
    config.channel.channel_expiry_secs = 1_200;
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, 730).unwrap();
    store.upsert_signed_offer(signed, vec![], 730).unwrap();
    let next = store.prepare_buyer_session_renewal(&original, 730).unwrap();
    assert_eq!(
        store.sessions[&next].session.payment.capacity_sat, 11,
        "a ten-minute usable contract must not buy an hour's traffic"
    );
}

#[test]
fn adaptive_capacity_can_shrink_after_a_new_channel_delivers_less_traffic() {
    let (mut store, original, seller, _) = fixture(1_000, Some(500_000), 100_000_000);
    let failed = store.prepare_buyer_session_renewal(&original, 720).unwrap();
    assert_eq!(store.sessions[&failed].session.payment.capacity_sat, 60);
    let replacement = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".into(),
            buyer_npub: store.leases[&store.sessions[&original].session.lease_id]
                .lease
                .buyer_npub
                .clone(),
            mint_url: None,
            channel_capacity_sat: Some(11),
            initial_paid_msat: 0,
            now_unix: 1_000,
        })
        .unwrap();
    store
        .begin_buyer_session_open_attempt(&replacement.session_id, 1_000)
        .unwrap();
    store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 10_000_000,
                ..Default::default()
            },
            now_unix: 1_600,
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .select_automatic_offer(1_600)
            .unwrap()
            .channel_capacity_sat,
        11,
        "an abandoned renewal must not pin later channels to an old high-traffic budget"
    );
}
