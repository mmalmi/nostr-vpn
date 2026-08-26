use super::*;

#[test]
fn seller_payment_rejects_regressing_balance_update_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 1_000,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 120,
        })
        .expect("apply first update");
    let before = store.clone();

    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                121,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 1_000,
                    paid_msat: 0,
                    payment: sample_spilman_payment("channel-1", 0),
                }),
            ),
            seller_npub,
            config,
            now_unix: 121,
        })
        .expect_err("regressing update rejected");

    assert!(error.to_string().contains("regressed"));
    assert_eq!(store, before);
}

#[test]
fn seller_payment_rejects_overclaimed_spilman_balance_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let before = store.clone();
    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 1_000,
                    paid_msat: 2_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config,
            now_unix: 120,
        })
        .expect_err("overclaimed balance update should fail");

    assert!(error.to_string().contains("does not match"));
    assert_eq!(store, before);
}

#[test]
fn seller_payment_rejects_underpaid_cooperative_close_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: config.clone(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 200,
                ..PaidRouteUsage::default()
            },
            now_unix: 120,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");
    let before = store.clone();

    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                130,
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config,
            now_unix: 130,
        })
        .expect_err("underpaid close should fail");

    assert!(error.to_string().contains("underpays amount due"));
    assert_eq!(store, before);
}

#[test]
fn seller_payment_cooperative_close_suspends_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 1_000,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 120,
        })
        .expect("apply first update");

    let result = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                130,
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 130,
        })
        .expect("apply close");

    assert_eq!(result.payload_type, "cooperative_close");
    assert_eq!(result.state, PaidRouteAccessState::Suspended);
    assert!(!result.allow_routing);
    assert_eq!(
        store.channels["channel-1"].status,
        PaidRouteLifecycleStatus::Closing
    );
    assert_eq!(
        store.leases["lease-1"].status,
        PaidRouteLifecycleStatus::Closing
    );
    assert!(!store.seller_admissions(&config, 131)[0].allow_routing);
    let collection = store.seller_collection_states(&config, 131);
    assert_eq!(collection.len(), 1);
    assert!(collection[0].collectable);
    assert!(collection[0].manual_collect);

    let mut refreshed_payment = sample_spilman_payment("channel-1", 1);
    refreshed_payment.signature.push_str("-retry");
    let retry = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                131,
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: 1_000,
                    payment: refreshed_payment.clone(),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 131,
        })
        .expect("refresh close authorization while settlement is pending");
    assert!(retry.changed);
    assert_eq!(
        store.channels["channel-1"]
            .payment
            .cashu_spilman_payment
            .as_ref(),
        Some(&refreshed_payment)
    );

    assert!(
        store
            .mark_seller_channel_closed("channel-1", 1_000, 132)
            .expect("settled close")
    );
    assert_eq!(
        store.channels["channel-1"].status,
        PaidRouteLifecycleStatus::Closed
    );
}

#[test]
fn repeated_seller_close_repairs_receiver_state_when_app_state_already_matches() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let receiver = FakeSpilmanReceiver::new("channel-1", 1);
    let request = ApplyPaidRouteSellerPaymentRequest {
        envelope: seller_payment_envelope(
            "internet-exit",
            "lease-1",
            &buyer_npub,
            &seller_npub,
            130,
            StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                final_paid_msat: 1_000,
                payment: sample_spilman_payment("channel-1", 1),
            }),
        ),
        seller_npub,
        config,
        now_unix: 130,
    };

    let first = store
        .apply_seller_payment_with_spilman_receiver(request.clone(), &receiver, &())
        .expect("apply close to app and receiver");
    assert!(first.changed);
    assert_eq!(receiver.process_calls.get(), 1);

    let repeated = store
        .apply_seller_payment_with_spilman_receiver(request, &receiver, &())
        .expect("replay close to repair receiver state");
    assert!(!repeated.changed);
    assert_eq!(receiver.process_calls.get(), 2);
}

#[test]
fn seller_manual_channel_close_suspends_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);

    let changed = store
        .mark_seller_channel_closed("channel-1", 1_000, 130)
        .expect("mark closed");

    assert!(changed);
    assert_eq!(
        store.channels["channel-1"].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert_eq!(store.channels["channel-1"].payment.paid_msat, 1_000);
    assert_eq!(
        store.leases["lease-1"].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .payment
            .paid_msat,
        1_000
    );
    let admissions = store.seller_admissions(&config, 131);
    assert_eq!(admissions.len(), 1);
    assert!(!admissions[0].allow_routing);
    assert!(
        !store
            .mark_seller_channel_closed("channel-1", 1_000, 131)
            .expect("idempotent mark")
    );
}

#[test]
fn seller_payment_rejects_overclaimed_spilman_close_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let before = store.clone();
    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                130,
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: 2_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config,
            now_unix: 130,
        })
        .expect_err("overclaimed close should fail");

    assert!(error.to_string().contains("does not match"));
    assert_eq!(store, before);
}

#[test]
fn paid_route_store_rejects_incompatible_buyer_mint() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");

    let error = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://other-mint.example".to_string()),
            channel_capacity_sat: None,
            initial_paid_msat: 0,
            now_unix: 120,
        })
        .expect_err("incompatible mint is rejected");

    assert!(error.to_string().contains("not accepted"));
    assert!(store.sessions.is_empty());
}

#[test]
fn paid_route_store_does_not_trust_seller_listed_mint() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");

    let error = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            channel_capacity_sat: None,
            initial_paid_msat: 0,
            now_unix: 120,
        })
        .expect_err("seller-listed mint is not wallet approval");

    assert!(error.to_string().contains("not approved in this wallet"));
    assert!(store.wallet.mints.is_empty());
    assert!(store.sessions.is_empty());
}

#[test]
fn paid_route_store_upserts_newer_offer_and_merges_relays() {
    let seller = Keys::generate();
    let old =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("old offer");
    let new =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 200)
            .expect("new offer");
    let mut store = PaidRouteStore::default();

    assert!(
        store
            .upsert_signed_offer(old.clone(), vec!["wss://a.example".to_string()], 101)
            .expect("old insert")
    );
    assert!(
        store
            .upsert_signed_offer(old, vec!["wss://b.example".to_string()], 102)
            .expect("same offer relay merge")
    );
    assert!(
        store
            .upsert_signed_offer(new.clone(), vec!["wss://c.example".to_string()], 201)
            .expect("newer replace")
    );

    let key = paid_route_offer_store_key(&new.offer().expect("offer").seller_npub, "internet-exit");
    let record = &store.offers[&key];
    assert_eq!(record.signed_offer.event.created_at.as_secs(), 200);
    assert_eq!(record.first_seen_unix, 101);
    assert_eq!(record.last_seen_unix, 201);
    assert_eq!(record.relay_urls, vec!["wss://c.example"]);
}

#[test]
fn paid_route_store_persists_offer_rating_score() {
    let seller = Keys::generate();
    let old =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("old offer");
    let new =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 200)
            .expect("new offer");
    let seller_npub = old.offer().expect("offer").seller_npub;
    let key = paid_route_offer_store_key(&seller_npub, "internet-exit");
    let mut store = PaidRouteStore::default();

    store
        .upsert_signed_offer(old, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");
    assert!(store.upsert_offer_rating_score(&seller_npub, 80, 120));
    assert!(!store.upsert_offer_rating_score(&seller_npub, -80, 110));
    store
        .upsert_signed_offer(new, vec!["wss://relay.example".to_string()], 201)
        .expect("replace offer");

    let record = &store.offers[&key];
    assert_eq!(record.rating_score, Some(80));
    assert_eq!(record.rating_updated_at_unix, 120);

    assert!(store.upsert_offer_rating_score(&seller_npub, -120, 220));
    let record = &store.offers[&key];
    assert_eq!(record.rating_score, Some(-100));
    assert_eq!(record.rating_updated_at_unix, 220);
}

#[test]
fn best_rated_offer_key_prefers_good_then_newcomer_over_degraded() {
    let good_seller = Keys::generate();
    let newcomer_seller = Keys::generate();
    let bad_seller = Keys::generate();
    let good_offer = signed_paid_exit_offer_from_config(
        "internet-exit",
        &good_seller,
        &sample_config(),
        None,
        100,
    )
    .expect("good offer");
    let newcomer_offer = signed_paid_exit_offer_from_config(
        "internet-exit",
        &newcomer_seller,
        &sample_config(),
        None,
        100,
    )
    .expect("newcomer offer");
    let bad_offer = signed_paid_exit_offer_from_config(
        "internet-exit",
        &bad_seller,
        &sample_config(),
        None,
        100,
    )
    .expect("bad offer");
    let good = good_offer.offer().expect("good offer record");
    let newcomer = newcomer_offer.offer().expect("newcomer offer record");
    let bad = bad_offer.offer().expect("bad offer record");
    let good_key = paid_route_offer_store_key(&good.seller_npub, &good.offer_id);
    let newcomer_key = paid_route_offer_store_key(&newcomer.seller_npub, &newcomer.offer_id);
    let bad_key = paid_route_offer_store_key(&bad.seller_npub, &bad.offer_id);
    let mut store = PaidRouteStore::default();

    store
        .upsert_signed_offer(good_offer, vec!["wss://relay.example".to_string()], 100)
        .expect("store good");
    store
        .upsert_signed_offer(newcomer_offer, vec!["wss://relay.example".to_string()], 110)
        .expect("store newcomer");
    store
        .upsert_signed_offer(bad_offer, vec!["wss://relay.example".to_string()], 120)
        .expect("store bad");
    assert!(store.upsert_offer_rating_score(&good.seller_npub, 80, 130));
    assert!(store.upsert_offer_rating_score(&bad.seller_npub, -80, 130));

    assert_eq!(
        store.best_rated_offer_key().expect("best rated offer"),
        good_key
    );

    assert!(store.upsert_offer_rating_score(&good.seller_npub, -90, 140));
    assert_eq!(
        store.best_rated_offer_key().expect("newcomer before bad"),
        newcomer_key
    );

    assert!(store.upsert_offer_rating_score(&newcomer.seller_npub, -10, 150));
    assert_eq!(
        store.best_rated_offer_key().expect("least bad offer"),
        newcomer_key
    );
    assert_ne!(
        store.best_rated_offer_key().expect("not worse bad offer"),
        bad_key
    );
}

#[test]
fn automatic_offer_selection_requires_safe_fresh_terms_and_a_wallet_mint() {
    let now_unix = 100_000;
    let assert_signed_rejected = |signed: SignedPaidRouteOffer| {
        let mut store = PaidRouteStore::default();
        store.upsert_wallet_mint(
            "https://mint.example",
            "Example",
            Some(50_000),
            now_unix - 1,
        );
        store
            .upsert_signed_offer(signed, vec!["wss://relay.example".to_string()], now_unix)
            .expect("store offer");

        assert!(store.select_automatic_offer(now_unix).is_err());
    };
    let assert_rejected = |mut config: PaidExitConfig, signed_at: u64| {
        config.channel.accepted_mints = vec!["https://mint.example".to_string()];
        let seller = Keys::generate();
        let signed =
            signed_paid_exit_offer_from_config("auto-exit", &seller, &config, None, signed_at)
                .expect("signed offer");
        assert_signed_rejected(signed);
    };

    let seller = Keys::generate();
    let signed = signed_paid_exit_offer_from_config(
        "auto-exit",
        &seller,
        &automatic_offer_config(),
        None,
        now_unix - 1,
    )
    .expect("signed offer");
    let mut untrusted = PaidRouteStore::default();
    untrusted
        .upsert_signed_offer(signed, vec!["wss://relay.example".to_string()], now_unix)
        .expect("store seller-listed mint");
    let wallet_before = untrusted.wallet.clone();
    assert!(untrusted.select_automatic_offer(now_unix).is_err());
    assert_eq!(untrusted.wallet, wallet_before);

    let seller = Keys::generate();
    let mut config = automatic_offer_config();
    config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let mut offer =
        signed_paid_exit_offer_from_config("auto-exit", &seller, &config, None, now_unix - 1)
            .expect("signed offer")
            .offer()
            .expect("decode offer");
    offer.ip_support.ipv4 = false;
    offer.ip_support.ipv6 = true;
    assert_signed_rejected(
        SignedPaidRouteOffer::sign(offer, &seller, now_unix - 1)
            .expect("sign external IPv6-only offer"),
    );
    let mut config = automatic_offer_config();
    config.channel.free_probe_units = PAID_ROUTE_AUTO_MIN_FREE_PROBE_BYTES - 1;
    assert_rejected(config, now_unix - 1);
    let mut config = automatic_offer_config();
    config.pricing.price_msat_per_gb = PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB + 1;
    assert_rejected(config, now_unix - 1);
    assert_rejected(
        automatic_offer_config(),
        now_unix - crate::paid_routes::PAID_ROUTE_OFFER_TTL_SECS,
    );
}

#[test]
fn automatic_offer_selection_prefers_local_probe_history_before_rating() {
    let now_unix = 100_000;
    let good_seller = Keys::generate();
    let poor_seller = Keys::generate();
    let good = signed_paid_exit_offer_from_config(
        "good",
        &good_seller,
        &automatic_offer_config(),
        None,
        now_unix - 20,
    )
    .expect("good offer");
    let poor = signed_paid_exit_offer_from_config(
        "poor",
        &poor_seller,
        &automatic_offer_config(),
        None,
        now_unix - 10,
    )
    .expect("poor offer");
    let good_offer = good.offer().expect("good terms");
    let poor_offer = poor.offer().expect("poor terms");
    let good_key = paid_route_offer_store_key(&good_offer.seller_npub, &good_offer.offer_id);
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.minibits.cash/Bitcoin",
        "Minibits",
        Some(50_000),
        now_unix - 30,
    );
    store
        .upsert_signed_offer(good, vec![], now_unix - 20)
        .expect("store good");
    store
        .upsert_signed_offer(poor, vec![], now_unix - 10)
        .expect("store poor");
    assert!(store.upsert_offer_rating_score(&good_offer.seller_npub, -100, now_unix));
    assert!(store.upsert_offer_rating_score(&poor_offer.seller_npub, 100, now_unix));
    add_local_offer_quality(&mut store, &good_offer, 30, 1_000, now_unix - 5);
    add_local_offer_quality(&mut store, &poor_offer, 300, 50_000, now_unix - 5);

    let selected = store
        .select_automatic_offer(now_unix)
        .expect("automatic selection");

    assert_eq!(selected.offer_key, good_key);
    assert_eq!(selected.mint_url, "https://mint.minibits.cash/Bitcoin");
    assert_eq!(selected.channel_capacity_sat, 6);
}

#[test]
fn automatic_offer_selection_uses_rating_price_freshness_and_stable_key_order() {
    let now_unix = 100_000;
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.minibits.cash/Bitcoin",
        "Minibits",
        Some(50_000),
        now_unix - 30,
    );
    let mut expected = Vec::new();
    for (offer_id, price_msat_per_gb, signed_at) in [
        ("older-expensive", 70_000, now_unix - 30),
        ("newer-expensive-rated-low", 70_000, now_unix - 20),
        ("newer-expensive-unrated", 70_000, now_unix - 20),
        ("newer-cheap", 50_000, now_unix - 10),
    ] {
        let seller = Keys::generate();
        let mut config = automatic_offer_config();
        config.pricing.price_msat_per_gb = price_msat_per_gb;
        let signed =
            signed_paid_exit_offer_from_config(offer_id, &seller, &config, None, signed_at)
                .expect("signed offer");
        let offer = signed.offer().expect("offer terms");
        let key = paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id);
        store
            .upsert_signed_offer(signed, vec![], signed_at)
            .expect("store offer");
        expected.push((key, offer.seller_npub));
    }

    assert_eq!(
        store
            .select_automatic_offer(now_unix)
            .expect("price winner")
            .offer_key,
        expected[3].0
    );
    assert_eq!(
        store
            .select_automatic_offer(now_unix)
            .expect("stable repeat selection")
            .offer_key,
        expected[3].0
    );

    assert!(store.upsert_offer_rating_score(&expected[0].1, 100, now_unix));
    assert!(store.upsert_offer_rating_score(&expected[1].1, -100, now_unix));
    assert!(store.upsert_offer_rating_score(&expected[3].1, -100, now_unix));
    assert_eq!(
        store
            .select_automatic_offer(now_unix)
            .expect("price precedes imported rating")
            .offer_key,
        expected[3].0
    );

    store
        .offers
        .get_mut(&expected[3].0)
        .expect("cheap offer")
        .offer
        .pricing
        .price_msat_per_gb = 70_000;
    assert_eq!(
        store
            .select_automatic_offer(now_unix)
            .expect("fresh unrated exploration candidate")
            .offer_key,
        expected[2].0
    );
}

#[test]
fn automatic_offer_selection_rejects_unfunded_seller_mint() {
    let now_unix = 100_000;
    let seller = Keys::generate();
    let mut config = automatic_offer_config();
    config.channel.accepted_mints = vec!["https://mint.destination".to_string()];
    let signed =
        signed_paid_exit_offer_from_config("auto-exit", &seller, &config, None, now_unix - 1)
            .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.destination",
        "Destination",
        Some(0),
        now_unix - 2,
    );
    store.upsert_wallet_mint("https://mint.source", "Source", Some(100_000), now_unix - 2);
    store
        .upsert_signed_offer(signed, vec![], now_unix - 1)
        .expect("store offer");

    assert!(store.select_automatic_offer(now_unix).is_err());
}

#[test]
fn automatic_offer_selection_reuses_a_funded_channel_when_wallet_balance_is_locked() {
    let now_unix = 100_000;
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = automatic_offer_config();
    let signed =
        signed_paid_exit_offer_from_config("auto-exit", &seller, &config, None, now_unix - 1)
            .expect("signed offer");
    let offer = signed.offer().expect("offer");
    let offer_key = paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id);
    let mint = "https://mint.minibits.cash/Bitcoin";
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(mint, "Minibits", Some(0), now_unix - 2);
    store
        .upsert_signed_offer(signed, vec![], now_unix - 1)
        .expect("store offer");
    let opened = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: offer_key.clone(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some(mint.to_string()),
            channel_capacity_sat: Some(20),
            initial_paid_msat: 0,
            now_unix,
        })
        .expect("open buyer session");
    let payment = CashuSpilmanPayment {
        channel_id: opened.channel_id.clone(),
        balance: 1,
        signature: "signed-balance".to_string(),
        params: Some(json!({"channel": opened.channel_id})),
        funding_proofs: Some(json!({"proofs": []})),
    };
    store
        .sessions
        .get_mut(&opened.session_id)
        .expect("buyer session")
        .session
        .payment
        .cashu_spilman_payment = Some(payment.clone());
    store
        .channels
        .get_mut(&opened.channel_id)
        .expect("buyer channel")
        .payment
        .cashu_spilman_payment = Some(payment);

    let selected = store
        .select_automatic_offer(now_unix + 1)
        .expect("reuse funded channel without free wallet balance");

    assert_eq!(selected.offer_key, offer_key);
    assert_eq!(selected.mint_url, mint);
    assert_eq!(selected.channel_capacity_sat, 20);
}

fn automatic_offer_config() -> PaidExitConfig {
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 50_000;
    config
}

fn add_local_offer_quality(
    store: &mut PaidRouteStore,
    offer: &PaidRouteOffer,
    latency_ms: u32,
    packet_loss_ppm: u32,
    measured_at_unix: u64,
) {
    let channel_id = format!("history-{}", offer.offer_id);
    store.upsert_channel(PaidRouteChannelRecord {
        channel_id: channel_id.clone(),
        offer_id: offer.offer_id.clone(),
        role: PaidRouteChannelRole::Buyer,
        status: PaidRouteLifecycleStatus::Closed,
        payment: PaidRoutePaymentState {
            channel_id: channel_id.clone(),
            ..PaidRoutePaymentState::default()
        },
        accepted_terms: Some(PaidExitConfig::from_paid_route_offer(offer)),
        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
        counterparty_npub: offer.seller_npub.clone(),
        created_at_unix: measured_at_unix,
        expires_at_unix: measured_at_unix,
        updated_at_unix: measured_at_unix,
        error: String::new(),
    });
    store.upsert_session(
        PaidRouteSession {
            session_id: format!("session-{}", offer.offer_id),
            lease_id: format!("lease-{}", offer.offer_id),
            usage: PaidRouteUsage::default(),
            payment: PaidRoutePaymentState {
                channel_id,
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: Some("198.51.100.42".to_string()),
            observed_country_code: None,
            observed_asn: None,
            quality: Some(PaidRouteQualityMetrics {
                latency_ms: Some(latency_ms),
                jitter_ms: Some(latency_ms / 10),
                packet_loss_ppm: Some(packet_loss_ppm),
                down_bps: Some(10_000_000),
                up_bps: Some(1_000_000),
                uptime_secs: None,
                last_seen_unix: Some(measured_at_unix),
            }),
        },
        measured_at_unix,
    );
}

#[test]
fn unreadable_paid_route_store_is_discarded() {
    let scratch = ScratchDir::new("unreadable");
    let store_path = scratch.path().join("paid-routes.json");
    fs::write(&store_path, "not json").expect("write junk");

    let store = load_paid_route_store(&store_path).expect("load default");

    assert_eq!(store, PaidRouteStore::default());
}

#[test]
fn paid_route_store_without_seller_tunnel_map_keeps_existing_state() {
    let scratch = ScratchDir::new("missing-seller-tunnel-map");
    let store_path = scratch.path().join("paid-routes.json");
    let mut stored = PaidRouteStore::default();
    assert!(stored.set_default_mint("https://mint.example"));
    let mut encoded = serde_json::to_value(stored).expect("encode store");
    encoded
        .as_object_mut()
        .expect("store object")
        .remove("seller_session_tunnel_ips");
    fs::write(
        &store_path,
        serde_json::to_vec_pretty(&encoded).expect("encode fixture"),
    )
    .expect("write fixture");

    let loaded = load_paid_route_store(&store_path).expect("load existing store");

    assert_eq!(loaded.wallet.default_mint, "https://mint.example");
    assert!(loaded.seller_session_tunnel_ips.is_empty());
}
