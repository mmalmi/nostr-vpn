use super::*;

#[test]
fn cashu_token_lease_fallback_rejects_credit_above_token_amount() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);

    let error = store
        .build_buyer_token_lease_envelope(BuildPaidRouteBuyerTokenLeaseEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub,
            mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
            cashu_unit: "sat".to_string(),
            amount: 1,
            paid_msat: Some(1_001),
            token: "cashuBdevtoken".to_string(),
            expires_at_unix: Some(500),
            now_unix: 140,
        })
        .expect_err("over-credit should fail");

    assert!(error.to_string().contains("exceeds token amount"));
    let payment = &store.sessions[&session_id].session.payment;
    assert_eq!(payment.mode, PaidRoutePaymentMode::CashuSpilman);
    assert!(payment.cashu_token_lease.is_none());
}

#[test]
fn record_buyer_usage_updates_session_for_exit_seller() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);

    store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub,
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
            payment: sample_spilman_payment(&channel_id, 1),
            delivered_units: Some(0),
            paid_msat: Some(1_000),
            now_unix: 130,
        })
        .expect("apply paid balance");

    let result = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                rx_bytes: 60,
                rx_packets: 1,
                billable_bytes: 60,
                ..PaidRouteUsage::default()
            },
            now_unix: 131,
        })
        .expect("record buyer usage")
        .expect("matched buyer session");

    assert!(result.changed);
    assert_eq!(result.session_id, session_id);
    assert_eq!(result.usage.rx_bytes, 60);
    assert_eq!(result.amount_due_msat, 600);
    assert_eq!(result.unpaid_msat, 0);
    assert!(result.allow_routing);
    assert_eq!(result.state, PaidRouteAccessState::Paid);

    let result = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                tx_bytes: 50,
                tx_packets: 1,
                billable_bytes: 50,
                ..PaidRouteUsage::default()
            },
            now_unix: 132,
        })
        .expect("record buyer usage")
        .expect("matched buyer session");

    assert_eq!(result.usage.rx_bytes, 60);
    assert_eq!(result.usage.tx_bytes, 50);
    assert_eq!(result.amount_due_msat, 1_100);
    assert_eq!(result.unpaid_msat, 100);
    assert!(!result.allow_routing);
    assert_eq!(result.state, PaidRouteAccessState::Suspended);
}

#[test]
fn buyer_payment_updates_due_reports_signable_balance_updates() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);

    store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub: buyer_npub.clone(),
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
            payment: sample_spilman_payment(&channel_id, 1),
            delivered_units: Some(0),
            paid_msat: Some(1_000),
            now_unix: 130,
        })
        .expect("apply paid balance");
    store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                rx_bytes: 60,
                tx_bytes: 50,
                billable_bytes: 110,
                ..PaidRouteUsage::default()
            },
            now_unix: 131,
        })
        .expect("record buyer usage")
        .expect("matched buyer session");

    let due = store.buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
        now_unix: 132,
        min_increment_msat: 1,
    });

    assert_eq!(due.len(), 1);
    assert_eq!(due[0].session_id, session_id);
    assert_eq!(due[0].channel_id, channel_id);
    assert_eq!(due[0].delivered_units, 110);
    assert_eq!(due[0].amount_due_msat, 1_100);
    assert_eq!(due[0].paid_msat, 1_000);
    assert_eq!(due[0].target_paid_msat, 2_000);
    assert_eq!(due[0].payment_increment_msat, 1_000);
    assert_eq!(due[0].remaining_unpaid_msat, 0);
    assert!(!due[0].capacity_exhausted);

    let signed = store
        .build_buyer_signed_payment_envelope_for_due(&FakePaymentSigner, &buyer_npub, &due[0], 133)
        .expect("sign due update");

    assert_eq!(signed.due, due[0]);
    assert_eq!(signed.payment.paid_msat, 2_000);
    store = signed.store;
    assert!(
        store
            .buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
                now_unix: 134,
                min_increment_msat: 1,
            })
            .is_empty()
    );
}

#[test]
fn buyer_payment_updates_due_caps_at_channel_capacity() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    store
        .sessions
        .get_mut(&session_id)
        .unwrap()
        .session
        .payment
        .capacity_sat = 1;
    store
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .payment
        .capacity_sat = 1;
    store.sessions.get_mut(&session_id).unwrap().session.usage = PaidRouteUsage {
        rx_bytes: 250,
        billable_bytes: 250,
        ..PaidRouteUsage::default()
    };

    let due = store.buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
        now_unix: 132,
        min_increment_msat: 1,
    });

    assert_eq!(due.len(), 1);
    assert_eq!(due[0].amount_due_msat, 2_500);
    assert_eq!(due[0].target_paid_msat, 1_000);
    assert_eq!(due[0].capacity_msat, 1_000);
    assert_eq!(due[0].remaining_unpaid_msat, 1_500);
    assert!(due[0].capacity_exhausted);
}

#[test]
fn buyer_signed_payment_envelope_uses_cashu_service_signer() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);

    let result = store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub,
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
                delivered_units: Some(100),
                paid_msat: None,
                now_unix: 150,
            },
        )
        .expect("build signed payment envelope");

    assert!(result.changed);
    assert_eq!(result.amount_due_msat, 1);
    assert_eq!(result.paid_msat, 1_000);
    assert_eq!(result.state, PaidRouteAccessState::Paid);
    match result.envelope.payload {
        StreamingRoutePaymentPayload::BalanceUpdate(update) => {
            assert_eq!(update.paid_msat, 1_000);
            assert_eq!(update.payment.channel_id, channel_id);
            assert_eq!(update.payment.balance, 1);
            assert_eq!(
                update.payment.signature,
                format!("signed-{channel_id}-update")
            );
            assert!(!update.payment.has_funding());
        }
        other => panic!("unexpected payload: {other:?}"),
    }
    assert_eq!(store.sessions[&session_id].session.payment.paid_msat, 1_000);
}

#[test]
fn buyer_balance_update_retains_channel_funding_in_persisted_state() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let (mut store, session_id, channel_id) =
        buyer_store_with_session(&seller, &buyer, &sample_config());

    store
        .build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.clone(),
            buyer_npub: buyer_npub.clone(),
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
            payment: sample_spilman_payment(&channel_id, 0),
            delivered_units: Some(0),
            paid_msat: Some(0),
            now_unix: 130,
        })
        .expect("persist funded channel open");

    let update = store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub,
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
                delivered_units: Some(100),
                paid_msat: Some(1_000),
                now_unix: 131,
            },
        )
        .expect("persist balance update");

    let StreamingRoutePaymentPayload::BalanceUpdate(wire_update) = update.envelope.payload else {
        panic!("expected balance update payload");
    };
    assert!(!wire_update.payment.has_funding());
    assert!(
        store.sessions[&session_id]
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .expect("stored session payment")
            .has_funding()
    );
    assert!(
        store.channels[&channel_id]
            .payment
            .cashu_spilman_payment
            .as_ref()
            .expect("stored channel payment")
            .has_funding()
    );
}

#[test]
fn buyer_cooperative_close_remains_pending_until_refund_recovery() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let (mut store, session_id, channel_id) =
        buyer_store_with_session(&seller, &buyer, &sample_config());

    store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub: buyer_npub.clone(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
                delivered_units: Some(100),
                paid_msat: Some(2_000),
                now_unix: 130,
            },
        )
        .expect("build balance update");
    store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub: buyer_npub.clone(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose,
                delivered_units: Some(100),
                paid_msat: Some(2_000),
                now_unix: 140,
            },
        )
        .expect("build first cooperative close");

    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Closing
    );
    assert_eq!(
        store.leases[&store.sessions[&session_id].session.lease_id].status,
        PaidRouteLifecycleStatus::Closing
    );

    let retried = store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub: buyer_npub.clone(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose,
                delivered_units: Some(100),
                paid_msat: Some(2_000),
                now_unix: 150,
            },
        )
        .expect("re-sign cooperative close after local close");

    assert!(retried.changed);
    assert_eq!(retried.payload_type, "cooperative_close");
    assert_eq!(retried.paid_msat, 2_000);
    assert_eq!(retried.delivered_units, 100);
    assert_eq!(
        store.sessions[&session_id].session.usage.billable_bytes,
        100
    );
    assert_eq!(
        store.sessions[&session_id].session.payment.updated_at_unix,
        150
    );
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Closing
    );

    assert!(
        store
            .mark_buyer_channel_closed(&channel_id, 151)
            .expect("refund recovery closes buyer channel")
    );
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert_eq!(
        store.leases[&store.sessions[&session_id].session.lease_id].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert!(
        !store
            .mark_buyer_channel_closed(&channel_id, 152)
            .expect("closing an already recovered buyer channel is idempotent")
    );

    let error = store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id,
                buyer_npub,
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
                delivered_units: Some(100),
                paid_msat: Some(2_000),
                now_unix: 160,
            },
        )
        .expect_err("closed channel must still reject balance updates");
    assert!(error.to_string().contains("is not open"));
}

#[test]
fn seller_payment_balance_update_raises_paid_amount_and_usage() {
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
                billable_bytes: 100,
                ..PaidRouteUsage::default()
            },
            now_unix: 110,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");
    let result = store
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
        .expect("apply balance update");

    assert!(result.changed);
    assert_eq!(result.payload_type, "balance_update");
    assert_eq!(result.state, PaidRouteAccessState::Paid);
    assert!(result.allow_routing);
    assert_eq!(result.delivered_units, 100);
    assert_eq!(result.paid_msat, 1_000);
    assert_eq!(result.amount_due_msat, 1_000);
    assert_eq!(result.unpaid_msat, 0);
    assert_eq!(store.channels["channel-1"].payment.paid_msat, 1_000);
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .usage
            .billable_bytes,
        100
    );
    assert_eq!(
        store.seller_admissions(&config, 121)[0].state,
        PaidRouteAccessState::Paid
    );
}

#[test]
fn seller_payment_balance_update_does_not_import_buyer_overreported_units() {
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
                billable_bytes: 100,
                ..PaidRouteUsage::default()
            },
            now_unix: 110,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");

    let result = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 200,
                    amount_due_msat: 2_000,
                    paid_msat: 2_000,
                    payment: sample_spilman_payment("channel-1", 2),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 120,
        })
        .expect("apply overreported balance update");

    assert_eq!(result.delivered_units, 100);
    assert_eq!(result.amount_due_msat, 1_000);
    assert_eq!(result.paid_msat, 2_000);
    assert_eq!(result.unpaid_msat, 0);
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .usage
            .billable_bytes,
        100
    );
}

#[test]
fn seller_payment_balance_update_accepts_lagging_buyer_usage_counter() {
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
                rx_bytes: 150,
                billable_bytes: 150,
                ..PaidRouteUsage::default()
            },
            now_unix: 110,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");

    let result = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 1_500,
                    paid_msat: 2_000,
                    payment: sample_spilman_payment("channel-1", 2),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 120,
        })
        .expect("apply lagging balance update");

    assert_eq!(result.delivered_units, 150);
    assert_eq!(result.amount_due_msat, 1_500);
    assert_eq!(result.paid_msat, 2_000);
    assert_eq!(result.unpaid_msat, 0);
    assert_eq!(result.state, PaidRouteAccessState::Paid);
    assert!(result.allow_routing);
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .usage
            .rx_bytes,
        150
    );
}

#[test]
fn seller_payment_balance_update_accepts_underreported_due_without_importing_usage() {
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
                active_millis: 3_000,
                billable_bytes: 150,
                ..PaidRouteUsage::default()
            },
            now_unix: 110,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");

    let result = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                120,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 0,
                    amount_due_msat: 1,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config,
            now_unix: 120,
        })
        .expect("lagging traffic report is accepted as partial credit");

    assert_eq!(result.amount_due_msat, 1_500);
    assert_eq!(result.paid_msat, 1_000);
    assert_eq!(result.unpaid_msat, 500);
    assert_eq!(result.state, PaidRouteAccessState::Suspended);
    assert!(!result.allow_routing);
    assert_eq!(
        store.sessions["seller-session-lease-1"]
            .session
            .usage
            .billable_bytes,
        150
    );
}
