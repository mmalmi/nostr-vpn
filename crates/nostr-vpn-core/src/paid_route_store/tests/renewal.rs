use super::*;

#[test]
fn exhausted_seller_channel_accepts_close_at_its_funded_capacity() {
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
                billable_bytes: 1_050,
                ..PaidRouteUsage::default()
            },
            now_unix: 120,
        })
        .expect("record seller-observed usage")
        .expect("matched seller session");

    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                130,
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: 10_000,
                    payment: sample_spilman_payment("channel-1", 10),
                }),
            ),
            seller_npub,
            config,
            now_unix: 130,
        })
        .expect("close fully funded channel despite in-flight usage exceeding capacity");

    assert_eq!(
        store.channels["channel-1"].status,
        PaidRouteLifecycleStatus::Closing
    );
}

#[test]
fn renewal_preserves_route_and_usage_until_replacement_is_admitted_across_reload() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().unwrap();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, original, _) = buyer_store_with_session(&seller, &buyer, &config);
    store
        .begin_buyer_session_open_attempt(&original, 120)
        .unwrap();
    assert!(!store.buyer_session_needs_renewal(&original, 120).unwrap());
    store
        .sessions
        .get_mut(&original)
        .unwrap()
        .session
        .usage
        .billable_bytes = 500;
    assert!(store.buyer_session_needs_renewal(&original, 130).unwrap());
    let next = store.prepare_buyer_session_renewal(&original, 130).unwrap();
    assert_ne!(next, original);
    assert_eq!(store.selected_buyer_session_id, original);
    assert!(
        store
            .activate_buyer_session_renewal(&original, 131)
            .is_err()
    );
    let scratch = ScratchDir::new("renewal");
    let path = scratch.path().join("paid-routes.json");
    update_paid_route_store(&path, |persisted| {
        *persisted = store.clone();
        Ok(())
    })
    .unwrap();
    let mut store = load_paid_route_store(&path).unwrap();
    assert_eq!(
        store.prepare_buyer_session_renewal(&original, 132).unwrap(),
        next
    );
    let usage = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 5,
                ..Default::default()
            },
            now_unix: 132,
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        usage.session_id, original,
        "funding a newer channel must not steal accounting"
    );
    assert_eq!(store.sessions[&next].session.usage.billable_bytes, 0);
    let lease_id = store.sessions[&next].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease_id, 133)
        .unwrap();
    assert_eq!(
        store
            .activate_buyer_session_renewal(&original, 134)
            .unwrap(),
        next
    );
    let usage = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 7,
                ..Default::default()
            },
            now_unix: 134,
        })
        .unwrap()
        .unwrap();
    assert_eq!(usage.session_id, next);
    assert_eq!(store.sessions[&original].session.usage.billable_bytes, 505);
    assert_eq!(store.sessions[&next].session.usage.billable_bytes, 7);
    assert!(!store.buyer_session_needs_renewal(&next, 135).unwrap());
    assert!(
        store.buyer_session_needs_renewal(&next, 680).unwrap(),
        "renew before expiry too"
    );
    assert_eq!(buyer_npub, store.leases[&lease_id].lease.buyer_npub);
}

#[test]
fn delayed_payment_on_outgoing_channel_cannot_reclaim_seller_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().unwrap();
    let buyer_npub = buyer.public_key().to_bech32().unwrap();
    let config = sample_config();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let mut envelope = seller_payment_envelope(
        "internet-exit",
        "lease-next",
        &buyer_npub,
        &seller_npub,
        130,
        StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
            mint_url: "https://mint.minibits.cash/Bitcoin".into(),
            unit: "sat".into(),
            capacity: 10,
            expires_unix: 600,
            receiver_pubkey_hex: seller.public_key().to_hex(),
            paid_msat: 1_000,
            payment: sample_spilman_payment("channel-next", 1),
        }),
    );
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: envelope.clone(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 130,
        })
        .unwrap();
    store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            authenticated_source_ip: None,
            open: PaidRouteSessionOpen {
                version: PAID_ROUTE_OFFER_VERSION.into(),
                service_id: "internet-exit".into(),
                lease_id: "lease-next".into(),
                channel_id: "channel-next".into(),
                seller_npub: seller_npub.clone(),
                buyer_tunnel_ip: "10.44.201.17/32".into(),
                expires_at_unix: 600,
            },
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 131,
        })
        .unwrap();
    assert_eq!(
        store.seller_admissions(&config, 131)[0].channel_id,
        "channel-next"
    );
    envelope = seller_payment_envelope(
        "internet-exit",
        "lease-1",
        &buyer_npub,
        &seller_npub,
        140,
        StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
            delivered_units: 0,
            amount_due_msat: 0,
            paid_msat: 1_000,
            payment: sample_spilman_payment("channel-1", 1),
        }),
    );
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope,
            seller_npub,
            config: config.clone(),
            now_unix: 140,
        })
        .unwrap();
    assert_eq!(
        store.seller_admissions(&config, 140)[0].channel_id,
        "channel-next"
    );
}
