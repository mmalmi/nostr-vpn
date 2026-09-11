use super::*;

#[test]
fn successful_provider_survives_reconnect_expiry_and_store_reload() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 25_000;
    let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    assert!(
        !store
            .select_automatic_offer(130)
            .unwrap()
            .previously_verified
    );
    store
        .update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: session_id.clone(),
            realized_exit_ip: Some("203.0.113.42".into()),
            observed_country_code: None,
            observed_asn: None,
            quality: Some(PaidRouteQualityMetrics {
                latency_ms: Some(40),
                packet_loss_ppm: Some(0),
                ..Default::default()
            }),
            now_unix: 140,
        })
        .unwrap();
    assert!(
        store
            .select_automatic_offer(140)
            .unwrap()
            .previously_verified
    );
    // Recovery must require fresh health without erasing prior successful use.
    store
        .begin_buyer_session_open_attempt(&session_id, 150)
        .unwrap();
    assert!(store.sessions[&session_id].session.quality.is_none());
    assert!(
        store
            .select_automatic_offer(150)
            .unwrap()
            .previously_verified
    );
    let dir = ScratchDir::new("returning-provider");
    let path = dir.path().join("paid-routes.json");
    update_paid_route_store(&path, |target| {
        *target = store;
        Ok(())
    })
    .unwrap();
    let mut reloaded = load_paid_route_store(&path).unwrap();
    reloaded.reconcile_buyer_session_lifecycle(90_000, 30);
    // A fresh advert with no free trial is still eligible for this returning buyer.
    config.channel.free_probe_units = 0;
    let offer = signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, 90_000)
        .unwrap();
    reloaded.upsert_signed_offer(offer, vec![], 90_000).unwrap();
    assert!(
        reloaded
            .select_automatic_offer(90_000)
            .unwrap()
            .previously_verified
    );
    let stranger = Keys::generate();
    let (unknown, _, _) = buyer_store_with_session(&stranger, &buyer, &config);
    assert!(unknown.select_automatic_offer(130).is_err());
}

fn trial_request(
    seller: &Keys,
    buyer: &Keys,
    lease: &str,
    ip: Option<&str>,
    now: u64,
) -> ApplyPaidRouteSellerSessionOpenRequest {
    ApplyPaidRouteSellerSessionOpenRequest {
        open: PaidRouteSessionOpen {
            version: PAID_ROUTE_OFFER_VERSION.into(),
            service_id: "internet-exit".into(),
            lease_id: lease.into(),
            channel_id: format!("channel-{lease}"),
            seller_npub: seller.public_key().to_bech32().unwrap(),
            buyer_tunnel_ip: "10.44.201.17/32".into(),
            expires_at_unix: now + 600,
        },
        authenticated_buyer_pubkey: buyer.public_key().to_hex(),
        authenticated_source_ip: ip.map(|ip| ip.parse().unwrap()),
        seller_npub: seller.public_key().to_bech32().unwrap(),
        config: sample_config(),
        now_unix: now,
    }
}

#[test]
fn rotating_buyer_keys_cannot_reset_daily_ip_trial_after_restart() {
    let seller = Keys::generate();
    let first = Keys::generate();
    let second = Keys::generate();
    let mut store = PaidRouteStore::default();
    let initial = trial_request(&seller, &first, "first", Some("203.0.113.9"), 100);
    assert!(
        store
            .apply_seller_session_open(initial.clone())
            .unwrap()
            .allow_routing
    );
    assert!(!store.apply_seller_session_open(initial).unwrap().changed);
    let dir = ScratchDir::new("daily-ip-trial");
    let path = dir.path().join("paid-routes.json");
    update_paid_route_store(&path, |target| {
        *target = store;
        Ok(())
    })
    .unwrap();
    let mut store = load_paid_route_store(&path).unwrap();
    let before = store.clone();
    let error = store
        .apply_seller_session_open(trial_request(
            &seller,
            &second,
            "second",
            Some("203.0.113.9"),
            101,
        ))
        .unwrap_err();
    assert!(error.to_string().contains("source address"));
    assert_eq!(before, store, "a rejected trial must not alter accounting");
    let rotated_ip = trial_request(&seller, &first, "same-buyer", Some("203.0.113.10"), 101);
    assert!(store.apply_seller_session_open(rotated_ip).is_err());
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &second,
                "too-early",
                Some("203.0.113.9"),
                86_499
            ))
            .is_err()
    );
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &second,
                "tomorrow",
                Some("203.0.113.9"),
                86_500
            ))
            .unwrap()
            .allow_routing
    );
}

#[test]
fn trial_limits_group_ipv6_addresses_and_require_an_observed_source() {
    let seller = Keys::generate();
    let mut store = PaidRouteStore::default();
    store
        .apply_seller_session_open(trial_request(
            &seller,
            &Keys::generate(),
            "v6-first",
            Some("2001:db8:1:2::1"),
            100,
        ))
        .unwrap();
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "v6-rotated",
                Some("2001:db8:1:2::abcd"),
                101
            ))
            .is_err()
    );
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "relayed",
                None,
                101
            ))
            .is_err()
    );
    store
        .apply_seller_session_open(trial_request(
            &seller,
            &Keys::generate(),
            "v4",
            Some("203.0.113.8"),
            102,
        ))
        .unwrap();
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "mapped",
                Some("::ffff:203.0.113.8"),
                103
            ))
            .is_err()
    );
}

#[test]
fn zero_payment_channel_cannot_bypass_trial_limit_but_paid_credit_can() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut store = PaidRouteStore::default();
    store
        .apply_seller_session_open(trial_request(
            &seller,
            &Keys::generate(),
            "other-buyer",
            Some("203.0.113.9"),
            100,
        ))
        .unwrap();
    let request = trial_request(&seller, &buyer, "funded", Some("203.0.113.9"), 101);
    let seller_npub = seller.public_key().to_bech32().unwrap();
    let buyer_npub = buyer.public_key().to_bech32().unwrap();
    let payment = |paid_msat| ApplyPaidRouteSellerPaymentRequest {
        envelope: seller_payment_envelope(
            "internet-exit",
            "funded",
            &buyer_npub,
            &seller_npub,
            101,
            StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                mint_url: "https://mint.minibits.cash/Bitcoin".into(),
                unit: "sat".into(),
                capacity: 10,
                expires_unix: 500,
                receiver_pubkey_hex: seller.public_key().to_hex(),
                paid_msat,
                payment: sample_spilman_payment("channel-funded", paid_msat / 1_000),
            }),
        ),
        seller_npub: seller_npub.clone(),
        config: sample_config(),
        now_unix: 101,
    };
    store.apply_seller_payment(payment(0)).unwrap();
    assert!(store.apply_seller_session_open(request.clone()).is_err());
    assert!(
        !store
            .seller_admissions(&sample_config(), 101)
            .iter()
            .any(|admission| admission.buyer_npub == buyer_npub)
    );
    store.apply_seller_payment(payment(1_000)).unwrap();
    // Paid customers work over relays too, without a visible source address.
    let request = ApplyPaidRouteSellerSessionOpenRequest {
        authenticated_source_ip: None,
        ..request
    };
    assert!(
        store
            .apply_seller_session_open(request.clone())
            .unwrap()
            .allow_routing
    );
    assert!(!store.apply_seller_session_open(request).unwrap().changed);
    assert_eq!(store.seller_free_probe_sources.len(), 1);
}

#[test]
fn full_trial_table_does_not_evict_recent_addresses() {
    let seller = Keys::generate();
    let mut store = PaidRouteStore::default();
    for index in 0..256 {
        let mut request = trial_request(
            &seller,
            &Keys::generate(),
            &format!("trial-{index}"),
            Some(&format!("203.0.113.{index}")),
            100,
        );
        request.config.channel.free_probe_units = 1;
        request.config.channel.grace_units = 0;
        store.apply_seller_session_open(request).unwrap();
    }
    let before = store.clone();
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "overflow",
                Some("198.51.100.1"),
                101
            ))
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
    assert_eq!(store, before);
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "eviction-attempt",
                Some("203.0.113.0"),
                101
            ))
            .is_err()
    );
}

#[test]
fn seller_trial_byte_budget_includes_grace() {
    let seller = Keys::generate();
    let mut store = PaidRouteStore::default();
    let mut first = trial_request(
        &seller,
        &Keys::generate(),
        "large-trial",
        Some("203.0.113.1"),
        100,
    );
    first.config.channel.free_probe_units = 63 * 1024 * 1024;
    first.config.channel.grace_units = 1024 * 1024;
    store.apply_seller_session_open(first).unwrap();
    assert!(
        store
            .apply_seller_session_open(trial_request(
                &seller,
                &Keys::generate(),
                "overflow",
                Some("203.0.113.2"),
                101
            ))
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
}
