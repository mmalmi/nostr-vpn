use super::*;

#[test]
fn delayed_prepaid_update_resumes_seller_without_more_buyer_traffic() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().unwrap();
    let buyer_npub = buyer.public_key().to_bech32().unwrap();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut buyer_store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    let opening = buyer_store
        .build_buyer_signed_payment_envelope(
            &FakePaymentSigner,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.clone(),
                buyer_npub: buyer_npub.clone(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
                delivered_units: Some(0),
                paid_msat: Some(1_000),
                now_unix: 130,
            },
        )
        .unwrap();
    let mut seller_store = PaidRouteStore::default();
    seller_store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: opening.envelope,
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 130,
        })
        .unwrap();
    seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
            open: buyer_store
                .build_buyer_session_open(&session_id, &buyer_npub, "10.44.201.17/32", 130)
                .unwrap(),
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 130,
        })
        .unwrap();
    buyer_store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 60,
                ..Default::default()
            },
            now_unix: 131,
        })
        .unwrap();
    // Bytes already forwarded by the seller can still be in flight to the
    // buyer. A delayed top-up must recover even if no more data can arrive.
    let paused = seller_store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: config.clone(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 150,
                ..Default::default()
            },
            now_unix: 132,
        })
        .unwrap()
        .unwrap();
    assert!(!paused.allow_routing);
    let due = buyer_store.buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
        now_unix: 140,
        min_increment_msat: 1,
    });
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].amount_due_msat, 600);
    assert_eq!(due[0].target_paid_msat, 2_000);
    let payment = buyer_store
        .build_buyer_signed_payment_envelope_for_due(&FakePaymentSigner, &buyer_npub, &due[0], 140)
        .unwrap();
    let request = ApplyPaidRouteSellerPaymentRequest {
        envelope: payment.payment.envelope,
        seller_npub,
        config: config.clone(),
        now_unix: 140,
    };
    let resumed = seller_store.apply_seller_payment(request.clone()).unwrap();
    assert!(resumed.allow_routing);
    assert_eq!(resumed.amount_due_msat, 1_500);
    assert_eq!(resumed.paid_msat, 2_000);
    seller_store.apply_seller_payment(request).unwrap();
    let admission = &seller_store.seller_admissions(&config, 141)[0];
    assert!(admission.allow_routing);
    assert_eq!(admission.paid_msat, 2_000, "retry must not pay twice");
    assert_eq!(
        buyer_store.sessions[&session_id]
            .session
            .usage
            .billable_bytes,
        60
    );
}
