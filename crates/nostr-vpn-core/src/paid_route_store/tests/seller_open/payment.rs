#[test]
fn legacy_seller_channel_without_terms_has_no_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    store.channels.get_mut("channel-1").unwrap().accepted_terms = None;

    assert!(store.seller_admissions(&config, 130).is_empty());
    assert!(
        store
            .record_seller_usage(RecordPaidRouteSellerUsageRequest {
                buyer_pubkey: buyer.public_key().to_hex(),
                config,
                usage_delta: PaidRouteUsage {
                    billable_bytes: 1,
                    ..PaidRouteUsage::default()
                },
                now_unix: 130,
            })
            .expect("legacy seller usage must fail closed")
            .is_none()
    );
}

#[test]
fn seller_payment_channel_open_creates_seller_session_and_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 100;
    config.channel.grace_units = 0;

    let mut store = PaidRouteStore::default();
    let request = ApplyPaidRouteSellerPaymentRequest {
        envelope: seller_payment_envelope(
            "internet-exit",
            "lease-1",
            &buyer_npub,
            &seller_npub,
            100,
            StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                unit: "sat".to_string(),
                capacity: 10,
                expires_unix: 500,
                receiver_pubkey_hex: seller.public_key().to_hex(),
                paid_msat: 0,
                payment: sample_spilman_payment("channel-1", 0),
            }),
        ),
        seller_npub: seller_npub.clone(),
        config: config.clone(),
        now_unix: 100,
    };
    let result = store
        .apply_seller_payment(request.clone())
        .expect("apply channel open");

    assert!(result.changed);
    assert_eq!(result.payload_type, "channel_open");
    assert_eq!(result.session_id, "seller-session-lease-1");
    assert_eq!(result.state, PaidRouteAccessState::FreeProbe);
    assert!(result.allow_routing);
    assert!(
        !store
            .apply_seller_payment(request)
            .expect("replay channel open")
            .changed
    );
    assert_eq!(
        store.quotes["seller-quote-lease-1"].quote.offer_id,
        "internet-exit"
    );
    assert_eq!(
        store.leases["lease-1"].lease.buyer_npub,
        buyer.public_key().to_bech32().expect("buyer npub")
    );
    assert_eq!(
        store.channels["channel-1"].role,
        PaidRouteChannelRole::Seller
    );
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .payment
            .capacity_sat,
        10
    );

    assert!(store.seller_admissions(&config, 101).is_empty());
    store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: PaidRouteSessionOpen {
                version: PAID_ROUTE_OFFER_VERSION.to_string(),
                service_id: "internet-exit".to_string(),
                lease_id: "lease-1".to_string(),
                channel_id: "channel-1".to_string(),
                seller_npub: seller_npub.clone(),
                buyer_tunnel_ip: "10.44.201.17/32".to_string(),
                expires_at_unix: 500,
            },
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub,
            config: config.clone(),
            now_unix: 101,
        })
        .expect("bind funded buyer tunnel IP");
    let admissions = store.seller_admissions(&config, 101);
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].buyer_pubkey, buyer.public_key().to_hex());
    assert!(admissions[0].allow_routing);
    assert_eq!(admissions[0].state, PaidRouteAccessState::FreeProbe);
}

#[test]
fn seller_payment_channel_open_rejects_reused_lease_with_new_channel() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let before = store.clone();

    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                110,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 10,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment: sample_spilman_payment("channel-2", 0),
                }),
            ),
            seller_npub,
            config,
            now_unix: 110,
        })
        .expect_err("lease id must not be rebound");

    assert!(error.to_string().contains("already bound to channel"));
    assert_eq!(store, before);
}

#[test]
fn seller_payment_channel_open_requires_spilman_funding_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 100;
    config.channel.grace_units = 0;
    let mut payment = sample_spilman_payment("channel-1", 0);
    payment.params = None;
    payment.funding_proofs = None;

    let mut store = PaidRouteStore::default();
    let before = store.clone();
    let error = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                100,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 10,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment,
                }),
            ),
            seller_npub,
            config,
            now_unix: 100,
        })
        .expect_err("missing Spilman funding should fail");

    assert!(error.to_string().contains("missing funding"));
    assert_eq!(store, before);
}

#[test]
fn seller_payment_with_spilman_receiver_validates_and_applies_channel_open() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 100;
    config.channel.grace_units = 0;
    let mut store = PaidRouteStore::default();
    let receiver = FakeSpilmanReceiver::new("channel-1", 0);

    let result = store
        .apply_seller_payment_with_spilman_receiver(
            ApplyPaidRouteSellerPaymentRequest {
                envelope: seller_payment_envelope(
                    "internet-exit",
                    "lease-1",
                    &buyer_npub,
                    &seller_npub,
                    100,
                    StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                        unit: "sat".to_string(),
                        capacity: 10,
                        expires_unix: 500,
                        receiver_pubkey_hex: seller.public_key().to_hex(),
                        paid_msat: 0,
                        payment: sample_spilman_payment("channel-1", 0),
                    }),
                ),
                seller_npub,
                config: config.clone(),
                now_unix: 100,
            },
            &receiver,
            &(),
        )
        .expect("apply receiver-validated channel open");

    assert!(result.changed);
    assert_eq!(result.payload_type, "channel_open");
    assert_eq!(result.state, PaidRouteAccessState::FreeProbe);
    assert_eq!(
        store.channels["channel-1"].payment.cashu_spilman_payment,
        Some(sample_spilman_payment("channel-1", 0))
    );
    assert_eq!(receiver.validate_calls.get(), 0);
    assert_eq!(receiver.process_calls.get(), 1);
}

#[test]
fn seller_payment_with_spilman_receiver_rejects_receiver_mismatch_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 100;
    config.channel.grace_units = 0;
    let mut store = PaidRouteStore::default();
    let before = store.clone();
    let receiver = FakeSpilmanReceiver::new("channel-1", 1);

    let error = store
        .apply_seller_payment_with_spilman_receiver(
            ApplyPaidRouteSellerPaymentRequest {
                envelope: seller_payment_envelope(
                    "internet-exit",
                    "lease-1",
                    &buyer_npub,
                    &seller_npub,
                    100,
                    StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                        unit: "sat".to_string(),
                        capacity: 10,
                        expires_unix: 500,
                        receiver_pubkey_hex: seller.public_key().to_hex(),
                        paid_msat: 0,
                        payment: sample_spilman_payment("channel-1", 0),
                    }),
                ),
                seller_npub,
                config,
                now_unix: 100,
            },
            &receiver,
            &(),
        )
        .expect_err("receiver mismatch should fail");

    assert!(error.to_string().contains("receiver validated balance"));
    assert_eq!(store, before);
    assert_eq!(receiver.validate_calls.get(), 0);
    assert_eq!(receiver.process_calls.get(), 1);
}

#[test]
fn seller_payment_with_spilman_receiver_settles_after_selling_is_disabled() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let mut store = PaidRouteStore::default();
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                100,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 10,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment: sample_spilman_payment("channel-1", 0),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 100,
        })
        .expect("seed seller channel");
    store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: PaidRouteSessionOpen {
                version: PAID_ROUTE_OFFER_VERSION.to_string(),
                service_id: "internet-exit".to_string(),
                lease_id: "lease-1".to_string(),
                channel_id: "channel-1".to_string(),
                seller_npub: seller_npub.clone(),
                buyer_tunnel_ip: "10.44.201.17/32".to_string(),
                expires_at_unix: 500,
            },
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 100,
        })
        .expect("bind funded buyer tunnel IP");
    store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: config.clone(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 200,
                ..PaidRouteUsage::default()
            },
            now_unix: 100,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");
    let receiver = FakeSpilmanReceiver::new("channel-1", 2);
    config.enabled = false;

    let result = store
        .apply_seller_payment_with_spilman_receiver(
            ApplyPaidRouteSellerPaymentRequest {
                envelope: seller_payment_envelope(
                    "internet-exit",
                    "lease-1",
                    &buyer_npub,
                    &seller_npub,
                    101,
                    StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                        delivered_units: 200,
                        amount_due_msat: 1_000,
                        paid_msat: 2_000,
                        payment: sample_spilman_payment("channel-1", 2),
                    }),
                ),
                seller_npub,
                config,
                now_unix: 101,
            },
            &receiver,
            &(),
        )
        .expect("existing channel settles while new selling is disabled");

    assert_eq!(result.amount_due_msat, 2_000);
    assert_eq!(result.paid_msat, 2_000);
    assert_eq!(result.unpaid_msat, 0);
    assert!(result.allow_routing);
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .usage
            .billable_bytes,
        200
    );
    assert_eq!(receiver.validate_calls.get(), 0);
    assert_eq!(receiver.process_calls.get(), 1);
}

#[test]
fn buyer_payment_envelope_channel_open_persists_spilman_snapshot() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);

    let result = store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub,
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
            payment: sample_spilman_payment(&channel_id, 0),
            delivered_units: None,
            paid_msat: Some(0),
            now_unix: 130,
        })
        .expect("build channel open envelope");

    assert!(result.changed);
    assert_eq!(result.payload_type, "channel_open");
    assert_eq!(result.offer_id, "internet-exit");
    assert_eq!(result.delivered_units, 0);
    assert_eq!(result.paid_msat, 0);
    match result.envelope.payload {
        StreamingRoutePaymentPayload::ChannelOpen(open) => {
            assert_eq!(open.mint_url, "https://mint.minibits.cash/Bitcoin");
            assert_eq!(open.unit, "sat");
            assert_eq!(open.capacity, 10);
            assert_eq!(open.receiver_pubkey_hex, seller.public_key().to_hex());
            assert!(open.payment.has_funding());
        }
        other => panic!("unexpected payload: {other:?}"),
    }
    assert!(
        store.sessions[&session_id]
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .is_some_and(CashuSpilmanPayment::has_funding)
    );
}

#[test]
fn buyer_payment_envelope_balance_update_advances_usage_and_paid_amount() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);

    let result = store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub: buyer_npub.clone(),
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
            payment: sample_spilman_payment(&channel_id, 1),
            delivered_units: Some(100),
            paid_msat: Some(1_000),
            now_unix: 140,
        })
        .expect("build balance update");

    assert!(result.changed);
    assert_eq!(result.payload_type, "balance_update");
    assert_eq!(result.state, PaidRouteAccessState::Paid);
    assert_eq!(result.delivered_units, 100);
    assert_eq!(result.amount_due_msat, 1_000);
    assert_eq!(result.unpaid_msat, 0);
    match result.envelope.payload {
        StreamingRoutePaymentPayload::BalanceUpdate(update) => {
            assert_eq!(update.delivered_units, 100);
            assert_eq!(update.amount_due_msat, 1_000);
            assert_eq!(update.paid_msat, 1_000);
            assert_eq!(update.payment.balance, 1);
        }
        other => panic!("unexpected payload: {other:?}"),
    }
    let record = &store.sessions[&session_id];
    assert_eq!(record.session.usage.billable_bytes, 100);
    assert_eq!(record.session.payment.paid_msat, 1_000);
    assert_eq!(
        record
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.balance),
        Some(1)
    );

    let error = store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id,
            buyer_npub,
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
            payment: sample_spilman_payment(&channel_id, 0),
            delivered_units: Some(50),
            paid_msat: Some(500),
            now_unix: 141,
        })
        .expect_err("regressing buyer update rejected");
    assert!(error.to_string().contains("regressed"));
}

#[test]
fn buyer_payment_envelope_rejects_overclaimed_spilman_balance_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    let before = store.clone();

    let error = store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id,
            buyer_npub,
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
            payment: sample_spilman_payment(&channel_id, 1),
            delivered_units: Some(100),
            paid_msat: Some(2_000),
            now_unix: 140,
        })
        .expect_err("overclaimed payment should fail");

    assert!(
        error
            .to_string()
            .contains("does not match Cashu Spilman balance")
    );
    assert_eq!(store, before);
}

#[test]
fn cashu_token_lease_fallback_prepays_buyer_but_seller_requires_redemption() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut buyer_store, session_id, channel_id) =
        buyer_store_with_session(&seller, &buyer, &config);
    buyer_store
        .sessions
        .get_mut(&session_id)
        .expect("buyer session")
        .session
        .usage
        .billable_bytes = 100;

    let buyer_payment = buyer_store
        .build_buyer_token_lease_envelope(BuildPaidRouteBuyerTokenLeaseEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub: buyer_npub.clone(),
            mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
            cashu_unit: "sat".to_string(),
            amount: 2,
            paid_msat: Some(1_500),
            token: "cashuBdevtoken".to_string(),
            expires_at_unix: Some(500),
            now_unix: 140,
        })
        .expect("build token lease");

    assert!(buyer_payment.changed);
    assert_eq!(buyer_payment.payload_type, "cashu_token_lease");
    assert_eq!(buyer_payment.state, PaidRouteAccessState::Paid);
    assert_eq!(buyer_payment.amount_due_msat, 1_000);
    assert_eq!(buyer_payment.paid_msat, 1_500);
    assert_eq!(buyer_payment.channel_id, channel_id);
    let buyer_payment_state = &buyer_store.sessions[&session_id].session.payment;
    assert_eq!(
        buyer_payment_state.mode,
        PaidRoutePaymentMode::CashuTokenLease
    );
    assert!(buyer_payment_state.cashu_spilman_payment.is_none());
    assert!(
        buyer_payment_state
            .cashu_token_lease
            .as_ref()
            .is_some_and(|lease| lease.token == "cashuBdevtoken")
    );
    match &buyer_payment.envelope.payload {
        StreamingRoutePaymentPayload::CashuTokenLease(lease) => {
            assert_eq!(lease.amount, 2);
            assert_eq!(lease.paid_msat, 1_500);
            assert_eq!(lease.expires_unix, 500);
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    let mut seller_store = PaidRouteStore::default();
    let before = seller_store.clone();
    let error = seller_store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: buyer_payment.envelope.clone(),
            seller_npub,
            config: config.clone(),
            now_unix: 141,
        })
        .expect_err("seller must redeem token leases before admitting routing");

    assert!(error.to_string().contains("token redemption"));
    assert_eq!(seller_store, before);
}
