use super::*;
use nostr_sdk::prelude::{EventBuilder, Kind, Tag, Timestamp};

fn legacy_offer(seller: &Keys, config: &PaidExitConfig) -> SignedPaidRouteOffer {
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", seller, config, None, 100).unwrap();
    let tags = signed.event.tags.iter().map(|tag| {
        if tag.as_slice().first().is_some_and(|kind| kind == "v") {
            Tag::parse(["v", "4"]).unwrap()
        } else {
            tag.clone()
        }
    });
    let event = EventBuilder::new(
        Kind::Custom(crate::paid_routes::PAID_ROUTE_OFFER_KIND),
        signed.event.content.clone(),
    )
    .tags(tags)
    .custom_created_at(Timestamp::from(100))
    .sign_with_keys(seller)
    .unwrap();
    SignedPaidRouteOffer::from_event(event)
        .expect("legacy listings must remain readable for funded sessions")
}

#[test]
fn new_session_persists_output_format_before_funding() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (store, session, _) = buyer_store_with_session(&seller, &buyer, &sample_config());
    let restarted: PaidRouteStore =
        serde_json::from_value(serde_json::to_value(&store).unwrap()).unwrap();
    let open = restarted
        .build_buyer_session_open(
            &session,
            &buyer.public_key().to_bech32().unwrap(),
            "10.44.201.17/32",
            121,
        )
        .unwrap();
    assert_eq!(
        open.version, "5",
        "old buyers must not accept new-format offers"
    );
    let lease = &restarted.leases[&open.lease_id];
    let quote = serde_json::to_value(&restarted.quotes[&lease.lease.quote_id].quote).unwrap();
    assert_eq!(
        quote["output_version"], 2,
        "funding must use saved agreement, not a later listing"
    );
}

#[test]
fn legacy_offer_cannot_start_new_buyer_funding() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.minibits.cash/Bitcoin",
        "Minibits",
        Some(100_000),
        99,
    );
    store
        .upsert_signed_offer(legacy_offer(&seller, &sample_config()), vec![], 101)
        .unwrap();
    let before = store.clone();
    let result = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
        offer_selector: "internet-exit".into(),
        buyer_npub: buyer.public_key().to_bech32().unwrap(),
        mint_url: None,
        channel_capacity_sat: Some(10),
        initial_paid_msat: 0,
        now_unix: 120,
    });
    assert!(
        result.is_err(),
        "legacy output format must be rejected before a wallet request"
    );
    assert_eq!(store, before);
}

#[test]
fn legacy_saved_agreement_reconnects_and_recovers_without_rewriting_funds() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    // Emulate the persisted pre-upgrade schema, which had no format field.
    let mut saved = serde_json::to_value(store).unwrap();
    for quote in saved["quotes"].as_object_mut().unwrap().values_mut() {
        quote["quote"]
            .as_object_mut()
            .unwrap()
            .remove("output_version");
    }
    let mut store: PaidRouteStore = serde_json::from_value(saved).unwrap();
    let mut payment = sample_spilman_payment("legacy-funded", 1);
    payment
        .params
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("output_version");
    store
        .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.clone(),
            channel_id: payment.channel_id.clone(),
            cashu_unit: "sat".into(),
            capacity_sat: 10,
            paid_msat: Some(1_000),
            payment: payment.clone(),
            now_unix: 121,
        })
        .unwrap();
    let store: PaidRouteStore =
        serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
    let open = store
        .build_buyer_session_open(
            &session_id,
            &buyer.public_key().to_bech32().unwrap(),
            "10.44.201.17/32",
            122,
        )
        .unwrap();
    assert_eq!(open.version, "4");
    assert_eq!(
        store.channels["legacy-funded"]
            .payment
            .cashu_spilman_payment
            .as_ref(),
        Some(&payment)
    );
    // A newer current listing cannot change this channel's agreed bytes.
    assert_eq!(
        store
            .offers
            .values()
            .next()
            .unwrap()
            .signed_offer
            .output_version()
            .unwrap(),
        2
    );

    let mut seller_store = PaidRouteStore::default();
    let envelope = seller_payment_envelope(
        "internet-exit",
        &open.lease_id,
        &buyer.public_key().to_bech32().unwrap(),
        &seller.public_key().to_bech32().unwrap(),
        123,
        StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
            mint_url: "https://mint.minibits.cash/Bitcoin".into(),
            unit: "sat".into(),
            capacity: 10,
            expires_unix: open.expires_at_unix,
            receiver_pubkey_hex: seller.public_key().to_hex(),
            paid_msat: 1_000,
            payment,
        }),
    );
    let mut before_upgrade = envelope.clone();
    if let StreamingRoutePaymentPayload::ChannelOpen(open) = &mut before_upgrade.payload {
        open.payment.params.as_mut().unwrap()["output_version"] = json!(2);
    }
    seller_store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: before_upgrade,
            seller_npub: seller.public_key().to_bech32().unwrap(),
            config: config.clone(),
            now_unix: 123,
        })
        .unwrap();
    // Restore the old persisted schema. A previously accepted channel may
    // reconnect; an unknown legacy payment must not create a new agreement.
    fn remove_versions(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                fields.remove("output_version");
                for value in fields.values_mut() {
                    remove_versions(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    remove_versions(value);
                }
            }
            _ => {}
        }
    }
    let mut saved = serde_json::to_value(&seller_store).unwrap();
    remove_versions(&mut saved);
    let mut seller_store: PaidRouteStore = serde_json::from_value(saved).unwrap();
    seller_store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope,
            seller_npub: seller.public_key().to_bech32().unwrap(),
            config: config.clone(),
            now_unix: 124,
        })
        .unwrap();
    let resumed = seller_store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            open,
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
            seller_npub: seller.public_key().to_bech32().unwrap(),
            config,
            now_unix: 124,
        })
        .unwrap();
    assert!(
        resumed.allow_routing,
        "previously committed legacy funds remain usable"
    );
}

#[test]
fn seller_rejects_unknown_legacy_payment_before_receiver_mutation() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut payment = sample_spilman_payment("legacy-unknown", 1);
    payment
        .params
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("output_version");
    let request = ApplyPaidRouteSellerPaymentRequest {
        envelope: seller_payment_envelope(
            "internet-exit",
            "legacy-lease",
            &buyer.public_key().to_bech32().unwrap(),
            &seller.public_key().to_bech32().unwrap(),
            122,
            StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                mint_url: "https://mint.minibits.cash/Bitcoin".into(),
                unit: "sat".into(),
                capacity: 10,
                expires_unix: 500,
                receiver_pubkey_hex: seller.public_key().to_hex(),
                paid_msat: 1_000,
                payment,
            }),
        ),
        seller_npub: seller.public_key().to_bech32().unwrap(),
        config: sample_config(),
        now_unix: 122,
    };
    let mut store = PaidRouteStore::default();
    let before = store.clone();
    let receiver = FakeSpilmanReceiver::new("legacy-unknown", 1);
    let error = store
        .apply_seller_payment_with_spilman_receiver(request, &receiver, &())
        .unwrap_err();
    assert!(error.to_string().contains("Upgrade"));
    assert_eq!(store, before);
    assert_eq!(receiver.validate_calls.get(), 0);
    assert_eq!(receiver.process_calls.get(), 0);
}

#[test]
fn wrong_funded_format_is_rejected_before_buyer_or_receiver_mutation() {
    for agreed in [1, 2] {
        let seller = Keys::generate();
        let buyer = Keys::generate();
        let config = sample_config();
        let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
        let mut open = store
            .build_buyer_session_open(
                &session_id,
                &buyer.public_key().to_bech32().unwrap(),
                "10.44.201.17/32",
                121,
            )
            .unwrap();
        let mut seller_store = PaidRouteStore::default();
        seller_store
            .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
                open: open.clone(),
                authenticated_buyer_pubkey: buyer.public_key().to_hex(),
                authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
                seller_npub: seller.public_key().to_bech32().unwrap(),
                config: config.clone(),
                now_unix: 121,
            })
            .unwrap();
        for quote in store
            .quotes
            .values_mut()
            .chain(seller_store.quotes.values_mut())
        {
            quote.quote.output_version = agreed;
        }
        let mut payment = sample_spilman_payment("wrong-format", 1);
        payment.params.as_mut().unwrap()["output_version"] = json!(3 - agreed);
        let before = store.clone();
        let error = store
            .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
                session_id,
                channel_id: payment.channel_id.clone(),
                cashu_unit: "sat".into(),
                capacity_sat: 10,
                paid_msat: Some(1_000),
                payment: payment.clone(),
                now_unix: 122,
            })
            .unwrap_err();
        assert!(error.to_string().contains("output format"));
        assert_eq!(store, before);
        let receiver = FakeSpilmanReceiver::new("wrong-format", 1);
        let before = seller_store.clone();
        let error = seller_store
            .apply_seller_payment_with_spilman_receiver(
                ApplyPaidRouteSellerPaymentRequest {
                    envelope: seller_payment_envelope(
                        "internet-exit",
                        &open.lease_id,
                        &buyer.public_key().to_bech32().unwrap(),
                        &seller.public_key().to_bech32().unwrap(),
                        122,
                        StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                            mint_url: "https://mint.minibits.cash/Bitcoin".into(),
                            unit: "sat".into(),
                            capacity: 10,
                            expires_unix: 500,
                            receiver_pubkey_hex: seller.public_key().to_hex(),
                            paid_msat: 1_000,
                            payment,
                        }),
                    ),
                    seller_npub: seller.public_key().to_bech32().unwrap(),
                    config: config.clone(),
                    now_unix: 122,
                },
                &receiver,
                &(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("output format"));
        assert_eq!(receiver.validate_calls.get(), 0);
        assert_eq!(receiver.process_calls.get(), 0);
        assert_eq!(seller_store, before);
        open.version = if agreed == 1 { "5" } else { "4" }.into();
        assert!(
            seller_store
                .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
                    open,
                    authenticated_buyer_pubkey: buyer.public_key().to_hex(),
                    authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
                    seller_npub: seller.public_key().to_bech32().unwrap(),
                    config,
                    now_unix: 122,
                })
                .unwrap_err()
                .to_string()
                .contains("output format")
        );
        assert_eq!(seller_store, before);
    }
}

#[test]
fn seller_rejects_fresh_legacy_session_before_admission() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    let open = store
        .build_buyer_session_open(
            &session_id,
            &buyer.public_key().to_bech32().unwrap(),
            "10.44.201.17/32",
            121,
        )
        .unwrap();
    for existing_unfunded in [false, true] {
        let mut store = PaidRouteStore::default();
        let mut request = ApplyPaidRouteSellerSessionOpenRequest {
            open: open.clone(),
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
            seller_npub: seller.public_key().to_bech32().unwrap(),
            config: config.clone(),
            now_unix: 122,
        };
        if existing_unfunded {
            store.apply_seller_session_open(request.clone()).unwrap();
            for quote in store.quotes.values_mut() {
                quote.quote.output_version = 1;
            }
        }
        request.open.version = "4".into();
        let before = store.clone();
        assert!(
            store
                .apply_seller_session_open(request)
                .unwrap_err()
                .to_string()
                .contains("Upgrade")
        );
        assert_eq!(store, before);
    }
}

#[test]
fn signed_offer_rejects_unknown_missing_and_ambiguous_versions() {
    let seller = Keys::generate();
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .unwrap();
    for versions in [vec![], vec!["6"], vec!["5", "4"], vec!["4", "5"]] {
        let mut tags: Vec<_> = signed
            .event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().is_none_or(|kind| kind != "v"))
            .cloned()
            .collect();
        tags.extend(
            versions
                .into_iter()
                .map(|version| Tag::parse(["v", version]).unwrap()),
        );
        let event = EventBuilder::new(
            Kind::Custom(crate::paid_routes::PAID_ROUTE_OFFER_KIND),
            signed.event.content.clone(),
        )
        .tags(tags)
        .custom_created_at(Timestamp::from(100))
        .sign_with_keys(&seller)
        .unwrap();
        assert!(SignedPaidRouteOffer::from_event(event).is_err());
    }
}

#[test]
fn automatic_selection_does_not_fund_a_legacy_listing() {
    let seller = Keys::generate();
    let mut config = sample_config();
    config.channel.free_probe_units = 8 * 1024 * 1024;
    config.pricing.price_msat_per_gb = 50_000;
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.minibits.cash/Bitcoin",
        "Minibits",
        Some(100_000),
        99,
    );
    let current =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, 100).unwrap();
    store.upsert_signed_offer(current, vec![], 101).unwrap();
    assert!(store.select_automatic_offer(120).is_ok());
    store.offers.clear();
    store
        .upsert_signed_offer(legacy_offer(&seller, &config), vec![], 101)
        .unwrap();
    assert!(store.select_automatic_offer(120).is_err());
}
