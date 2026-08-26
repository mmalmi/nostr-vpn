use super::*;

#[test]
fn authenticated_free_probe_open_creates_seller_admission_and_upgrades_to_payment() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let (buyer_store, session_id, placeholder_channel_id) =
        buyer_store_with_session(&seller, &buyer, &config);

    let open = buyer_store
        .build_buyer_session_open(&session_id, &buyer_npub, "10.44.201.17/32", 100)
        .expect("build free probe open");
    assert!(
        !buyer_store
            .buyer_session_is_seller_admitted(&session_id)
            .expect("unacknowledged buyer session")
    );
    assert_eq!(open.seller_npub, seller_npub);
    assert_eq!(open.channel_id, placeholder_channel_id);
    assert_eq!(open.buyer_tunnel_ip, "10.44.201.17/32");

    let mut seller_store = PaidRouteStore::default();
    let applied = seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: open.clone(),
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 100,
        })
        .expect("apply free probe open");
    assert!(applied.changed);
    assert!(applied.allow_routing);
    assert_eq!(applied.state, PaidRouteAccessState::FreeProbe);
    let admissions = seller_store.seller_admissions(&config, 100);
    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].buyer_tunnel_ip, "10.44.201.17/32");

    let repeated = seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: open.clone(),
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 101,
        })
        .expect("repeat free probe open");
    assert!(!repeated.changed);

    let payment_channel_id = "funded-channel-1";
    let paid = seller_store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                &applied.lease_id,
                &buyer_npub,
                &seller_npub,
                102,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 10,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment: sample_spilman_payment(payment_channel_id, 0),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 102,
        })
        .expect("upgrade probe to payment channel");
    assert_eq!(paid.channel_id, payment_channel_id);
    assert!(!seller_store.channels.contains_key(&placeholder_channel_id));
    assert_eq!(seller_store.seller_admissions(&config, 102).len(), 1);

    let mut acknowledged_buyer_store = buyer_store;
    assert!(
        acknowledged_buyer_store
            .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &applied.lease_id, 103,)
            .expect("acknowledge buyer session")
    );
    assert!(
        acknowledged_buyer_store
            .buyer_session_is_seller_admitted(&session_id)
            .expect("acknowledged buyer session")
    );

    let replay_after_payment = seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open,
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller.public_key().to_bech32().expect("seller npub"),
            config,
            now_unix: 103,
        })
        .expect("replay free probe open after funding");
    assert!(!replay_after_payment.changed);
}

#[test]
fn funded_reconnect_is_admitted_after_the_same_buyer_used_an_older_free_probe() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let mut store = PaidRouteStore::default();

    store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: PaidRouteSessionOpen {
                version: PAID_ROUTE_OFFER_VERSION.to_string(),
                service_id: "internet-exit".to_string(),
                lease_id: "old-free-lease".to_string(),
                channel_id: "old-free-channel".to_string(),
                seller_npub: seller_npub.clone(),
                buyer_tunnel_ip: "10.44.201.17/32".to_string(),
                expires_at_unix: 500,
            },
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 100,
        })
        .expect("consume the buyer's first free probe");

    let reconnect = PaidRouteSessionOpen {
        version: PAID_ROUTE_OFFER_VERSION.to_string(),
        service_id: "internet-exit".to_string(),
        lease_id: "funded-reconnect-lease".to_string(),
        channel_id: "funded-reconnect-channel".to_string(),
        seller_npub: seller_npub.clone(),
        buyer_tunnel_ip: "10.44.201.17/32".to_string(),
        expires_at_unix: 500,
    };
    let error = store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: reconnect.clone(),
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 110,
        })
        .expect_err("an unfunded second free probe remains rejected");
    assert!(error.to_string().contains("already consumed a free probe"));

    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "funded-reconnect-lease",
                &buyer_npub,
                &seller_npub,
                111,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 20,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment: sample_spilman_payment("funded-reconnect-channel", 0),
                }),
            ),
            seller_npub: seller_npub.clone(),
            config: config.clone(),
            now_unix: 111,
        })
        .expect("persist the funded reconnect before its next session-open retry");

    let applied = store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open: reconnect,
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub,
            config: config.clone(),
            now_unix: 112,
        })
        .expect("funded reconnect must bypass historical free-probe rejection");
    assert!(applied.allow_routing);
    assert_eq!(store.seller_admissions(&config, 112).len(), 1);
    assert_eq!(
        store.seller_admissions(&config, 112)[0].buyer_tunnel_ip,
        "10.44.201.17/32"
    );
}

#[test]
fn selected_buyer_session_expires_or_fails_instead_of_retrying_forever() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    let lease_id = store.sessions[&session_id].session.lease_id.clone();

    assert!(
        store
            .begin_buyer_session_open_attempt(&session_id, 130)
            .expect("select buyer session")
    );
    assert_eq!(store.selected_buyer_session_id, session_id);
    assert_eq!(store.buyer_session_open_attempts[&session_id], 130);

    let early = store.reconcile_buyer_session_lifecycle(159, 30);
    assert!(!early.selected_session_timed_out);
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Probing
    );

    let timed_out = store.reconcile_buyer_session_lifecycle(160, 30);
    assert!(timed_out.changed);
    assert!(timed_out.selected_session_timed_out);
    assert_eq!(timed_out.selected_session_id, session_id);
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert_eq!(
        store.leases[&lease_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert!(store.channels[&channel_id].error.contains("acknowledge"));
    assert!(!store.buyer_session_open_attempts.contains_key(&session_id));
    assert!(
        store
            .buyer_session_open_for_seller(
                &seller.public_key().to_hex(),
                &buyer.public_key().to_bech32().expect("buyer npub"),
                "10.44.201.17/32",
                160,
            )
            .expect("find selected buyer session")
            .is_none()
    );

    let (mut expired, expired_session_id, expired_channel_id) =
        buyer_store_with_session(&seller, &buyer, &config);
    let expired_lease_id = expired.sessions[&expired_session_id]
        .session
        .lease_id
        .clone();
    let expiry = expired.channels[&expired_channel_id].expires_at_unix;
    let result = expired.reconcile_buyer_session_lifecycle(expiry, 30);
    assert!(result.changed);
    assert_eq!(
        expired.channels[&expired_channel_id].status,
        PaidRouteLifecycleStatus::Expired
    );
    assert_eq!(
        expired.leases[&expired_lease_id].status,
        PaidRouteLifecycleStatus::Expired
    );
}

#[test]
fn seller_acknowledgment_activates_only_the_selected_buyer_session() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    let lease_id = store.sessions[&session_id].session.lease_id.clone();
    store
        .begin_buyer_session_open_attempt(&session_id, 130)
        .expect("select buyer session");

    assert!(
        store
            .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease_id, 140)
            .expect("acknowledge selected session")
    );
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(
        store.leases[&lease_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert!(!store.buyer_session_open_attempts.contains_key(&session_id));
    assert!(
        !store
            .reconcile_buyer_session_lifecycle(200, 30)
            .selected_session_timed_out
    );
}

#[test]
fn reconnect_clears_stale_end_to_end_health_evidence() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    let session = &mut store
        .sessions
        .get_mut(&session_id)
        .expect("buyer session")
        .session;
    session.realized_exit_ip = Some("198.51.100.42".to_string());
    session.observed_country_code = Some("IE".to_string());
    session.observed_asn = Some(64512);
    session.quality = Some(PaidRouteQualityMetrics {
        latency_ms: Some(42),
        last_seen_unix: Some(120),
        ..PaidRouteQualityMetrics::default()
    });

    store
        .begin_buyer_session_open_attempt(&session_id, 130)
        .expect("begin reconnect");

    let session = &store.sessions[&session_id].session;
    assert_eq!(session.realized_exit_ip, None);
    assert_eq!(session.observed_country_code, None);
    assert_eq!(session.observed_asn, None);
    assert_eq!(session.quality, None);
}

#[test]
fn selected_buyer_session_fails_when_end_to_end_exit_health_check_fails() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    let lease_id = store.sessions[&session_id].session.lease_id.clone();
    store
        .begin_buyer_session_open_attempt(&session_id, 130)
        .expect("select buyer session");
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease_id, 140)
        .expect("acknowledge selected session");

    assert!(
        store
            .fail_selected_buyer_session("Seller exit did not return Internet traffic", 145)
            .expect("fail selected session")
    );
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert_eq!(
        store.leases[&lease_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert!(store.channels[&channel_id].error.contains("did not return"));
    assert!(
        !store
            .buyer_session_allows_routing(&session_id, 146)
            .expect("failed session routing decision")
    );
}

#[test]
fn explicit_retry_reopens_a_failed_funded_buyer_session() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    let lease_id = store.sessions[&session_id].session.lease_id.clone();
    let payment = sample_spilman_payment("funded-channel", 0);
    store
        .sessions
        .get_mut(&session_id)
        .unwrap()
        .session
        .payment
        .cashu_spilman_payment = Some(payment.clone());
    store
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .payment
        .cashu_spilman_payment = Some(payment);
    store
        .begin_buyer_session_open_attempt(&session_id, 130)
        .expect("select buyer session");
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease_id, 140)
        .expect("acknowledge selected session");
    store
        .fail_selected_buyer_session("Seller exit did not return Internet traffic", 145)
        .expect("fail selected session");

    assert!(
        store
            .retry_failed_funded_buyer_session(&session_id, 146)
            .expect("retry funded session")
    );
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(
        store.leases[&lease_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert!(store.channels[&channel_id].error.is_empty());
    assert!(
        store
            .buyer_session_allows_routing(&session_id, 146)
            .expect("retried session routing decision")
    );
}

#[test]
fn explicit_retry_does_not_reopen_an_unfunded_failed_probe() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    store
        .begin_buyer_session_open_attempt(&session_id, 130)
        .expect("select buyer session");
    store
        .fail_selected_buyer_session("Seller exit did not return Internet traffic", 145)
        .expect("fail selected session");

    let error = store
        .retry_failed_funded_buyer_session(&session_id, 146)
        .expect_err("unfunded failed probe must stay terminal");

    assert!(error.to_string().contains("without a funded channel"));
}

#[test]
fn session_open_requires_current_version_buyer_tunnel_ip_and_rejects_public_sources() {
    let legacy = serde_json::json!({
        "version": "2",
        "service_id": "internet-exit",
        "lease_id": "lease-1",
        "channel_id": "channel-1",
        "seller_npub": Keys::generate().public_key().to_bech32().expect("seller npub"),
        "expires_at_unix": 200,
    });
    assert!(serde_json::from_value::<PaidRouteSessionOpen>(legacy).is_err());

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let config = sample_config();
    let (buyer_store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    let mut open = buyer_store
        .build_buyer_session_open(&session_id, &buyer_npub, "10.44.7.9/32", 100)
        .expect("build v3 session open");
    open.buyer_tunnel_ip = "203.0.113.9/32".to_string();

    let mut seller_store = PaidRouteStore::default();
    let before = seller_store.clone();
    let error = seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open,
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub,
            config,
            now_unix: 100,
        })
        .expect_err("public tunnel source must be rejected");
    assert!(error.to_string().contains("inside 10.44.0.0/16"));
    assert_eq!(seller_store, before);
}

#[test]
fn record_seller_usage_updates_session_and_admission_decision() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = seller_store_with_open_channel(&seller, &buyer, &config);
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                129,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 0,
                    amount_due_msat: 0,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 129,
        })
        .expect("apply paid balance");
    let result = store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: config.clone(),
            usage_delta: PaidRouteUsage {
                rx_bytes: 60,
                rx_packets: 1,
                billable_bytes: 60,
                ..PaidRouteUsage::default()
            },
            now_unix: 130,
        })
        .expect("record usage")
        .expect("matched seller session");

    assert!(result.changed);
    assert_eq!(result.session_id, "seller-session-lease-1");
    assert_eq!(result.usage.rx_bytes, 60);
    assert_eq!(result.usage.rx_packets, 1);
    assert_eq!(result.amount_due_msat, 600);
    assert_eq!(result.unpaid_msat, 0);
    assert!(result.allow_routing);
    assert_eq!(
        store.seller_admissions(&config, 130)[0].state,
        PaidRouteAccessState::Paid
    );

    let result = store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: config.clone(),
            usage_delta: PaidRouteUsage {
                tx_bytes: 50,
                tx_packets: 1,
                billable_bytes: 50,
                ..PaidRouteUsage::default()
            },
            now_unix: 131,
        })
        .expect("record usage")
        .expect("matched seller session");

    assert_eq!(result.usage.rx_bytes, 60);
    assert_eq!(result.usage.tx_bytes, 50);
    assert_eq!(result.amount_due_msat, 1_100);
    assert_eq!(result.unpaid_msat, 100);
    assert!(!result.allow_routing);
    assert_eq!(result.state, PaidRouteAccessState::Suspended);
    assert_eq!(
        store.seller_admissions(&config, 131)[0].state,
        PaidRouteAccessState::Suspended
    );
}

#[test]
fn seller_accounting_keeps_terms_after_selling_is_disabled() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut accepted = sample_config();
    accepted.pricing.price_msat_per_gb = 1_000_000_000;
    accepted.channel.free_probe_units = 0;
    accepted.channel.grace_units = 0;
    accepted.ip_support.ipv6 = false;
    let mut store = seller_store_with_open_channel(&seller, &buyer, &accepted);

    let mut changed = accepted.clone();
    changed.pricing.price_msat_per_gb = 10_000_000_000;
    changed.channel.accepted_mints = vec!["https://mint.changed.example".to_string()];
    changed.ip_support.ipv4 = false;
    changed.ip_support.ipv6 = true;
    let usage = store
        .record_seller_usage(RecordPaidRouteSellerUsageRequest {
            buyer_pubkey: buyer.public_key().to_hex(),
            config: changed.clone(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 100,
                rx_bytes: 100,
                ..PaidRouteUsage::default()
            },
            now_unix: 130,
        })
        .expect("record seller usage")
        .expect("seller session");

    assert_eq!(usage.amount_due_msat, 100);
    assert_eq!(
        store.seller_admissions(&changed, 130)[0].amount_due_msat,
        100
    );
    assert_eq!(
        store.seller_admissions(&changed, 130)[0].destination_allowed_ips,
        vec!["0.0.0.0/0"]
    );
    changed.enabled = false;
    let payment = store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer.public_key().to_bech32().expect("buyer npub"),
                &seller.public_key().to_bech32().expect("seller npub"),
                131,
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units: 100,
                    amount_due_msat: 100,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub: seller.public_key().to_bech32().expect("seller npub"),
            config: changed.clone(),
            now_unix: 131,
        })
        .expect("apply payment under original accepted terms");
    assert_eq!(payment.amount_due_msat, 100);
    let terms = store.channels["channel-1"]
        .accepted_terms
        .as_ref()
        .expect("accepted terms");
    assert_eq!(terms.pricing.price_msat_per_gb, 1_000_000_000);
    assert_eq!(
        terms.channel.accepted_mints,
        vec!["https://mint.minibits.cash/Bitcoin"]
    );
}

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
