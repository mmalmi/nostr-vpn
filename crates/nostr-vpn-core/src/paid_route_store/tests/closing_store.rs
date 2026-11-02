use super::*;

#[test]
fn seller_payment_acknowledges_obsolete_balance_without_mutating_store() {
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

    let result = store
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
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 121,
        })
        .expect("obsolete update is already covered by the persisted payment");

    assert!(!result.changed);
    assert_eq!(result.paid_msat, 1_000);
    assert_eq!(store, before);

    let receiver = FakeSpilmanReceiver::new("channel-1", 1);
    for status in [
        PaidRouteLifecycleStatus::Closing,
        PaidRouteLifecycleStatus::Closed,
        PaidRouteLifecycleStatus::Expired,
        PaidRouteLifecycleStatus::Failed,
    ] {
        store.channels.get_mut("channel-1").unwrap().status = status;
        store.leases.get_mut("lease-1").unwrap().status = status;
        let before = store.clone();
        for payload in [
            StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                delivered_units: 0,
                amount_due_msat: 0,
                paid_msat: 0,
                payment: sample_spilman_payment("channel-1", 0),
            }),
            StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                mint_url: config.channel.accepted_mints[0].clone(),
                unit: "sat".into(),
                capacity: 10,
                expires_unix: 500,
                receiver_pubkey_hex: seller.public_key().to_hex(),
                paid_msat: 0,
                payment: sample_spilman_payment("channel-1", 0),
            }),
        ] {
            let request = ApplyPaidRouteSellerPaymentRequest {
                envelope: seller_payment_envelope(
                    "internet-exit",
                    "lease-1",
                    &buyer_npub,
                    &seller_npub,
                    121,
                    payload,
                ),
                seller_npub: seller_npub.clone(),
                config: config.clone(),
                now_unix: 121,
            };
            let result = store
                .apply_seller_payment_with_spilman_receiver(request.clone(), &receiver, &())
                .expect("obsolete payment remains acknowledgeable after settlement");
            assert!(!result.changed);
            assert!(!result.allow_routing);
            assert_eq!(store, before);
            let mut forged = request;
            forged.envelope.lease_id = "different-lease".into();
            assert!(store.apply_seller_payment(forged).is_err());
            assert_eq!(store, before);
        }
    }
    assert_eq!(receiver.validate_calls.get(), 0);
    assert_eq!(
        receiver.process_calls.get(),
        0,
        "obsolete retries must not contact the mint"
    );
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
    assert!(collection[0].auto_collect_due);
    assert_eq!(collection[0].due_at_unix, 130);
    assert!(collection[0].expires_at_unix > 131);

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
    assert!(store.seller_collection_states(&config, 132).is_empty());
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

    // Omitting the mint accepts only the seller's advertised free allowance.
    let trial = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
        offer_selector: "internet-exit".into(),
        buyer_npub: buyer.public_key().to_bech32().unwrap(),
        mint_url: None,
        channel_capacity_sat: None,
        initial_paid_msat: 0,
        now_unix: 121,
    }).expect("fresh wallet can open the advertised free trial");
    assert!(trial.mint_url.is_empty());
    assert!(store.wallet.mints.is_empty());
    assert!(store.buyer_session_allows_routing(&trial.session_id, 122).unwrap());
    assert_eq!(store.buyer_session_funding_retry_at(&trial.session_id), u64::MAX);
    assert!(store.upsert_wallet_mint("https://mint.minibits.cash/Bitcoin", "", Some(900_000), 122));
    assert_eq!(store.buyer_session_funding_retry_at(&trial.session_id), u64::MAX);
    assert!(store.set_manual_renewal(&trial.session_id, true).is_err());
    assert!(store.begin_buyer_session_funding(&trial.session_id, 122).is_err());
    assert_eq!(store.sessions[&trial.session_id].funding_started_unix, 0);
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
