use super::*;

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
fn automatic_offer_selection_explains_its_price_limit() {
    let seller = Keys::generate();
    let mut config = automatic_offer_config();
    config.pricing.price_msat_per_gb = 250_000;
    let signed =
        signed_paid_exit_offer_from_config("expensive", &seller, &config, None, 120).unwrap();
    let mut store = PaidRouteStore::default();
    store.upsert_signed_offer(signed, vec![], 120).unwrap();
    store.upsert_wallet_mint(
        &config.channel.accepted_mints[0],
        "Mint",
        Some(1_000_000),
        120,
    );
    let error = store.select_automatic_offer(120).unwrap_err().to_string();
    assert!(error.contains("100 sat/GB"), "{error}");
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
            .expect("trusted rating precedes price within the safety cap")
            .offer_key,
        expected[0].0
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
            .expect("trusted rating precedes announcement recency")
            .offer_key,
        expected[0].0
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
        params: Some(json!({"channel": opened.channel_id, "unit": "sat"})),
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
    assert!(
        selected.funded,
        "zero wallet balance does not invalidate channel credit"
    );

    store
        .begin_buyer_session_open_attempt(&opened.session_id, now_unix + 2)
        .unwrap();
    // The purchase is a saved contract, not a dependency on a fresh advert.
    // Persist and reload the store to exercise the restart boundary.
    store.offers.clear();
    let dir = ScratchDir::new("funded-automatic-restart");
    let path = dir.path().join("paid-routes.json");
    update_paid_route_store(&path, |target| {
        *target = store;
        Ok(())
    })
    .unwrap();
    let store = load_paid_route_store(&path).unwrap();
    let before = store.clone();
    let recovered = store.select_automatic_offer(now_unix + 3).unwrap();
    assert_eq!(recovered.offer_key, selected.offer_key);
    assert_eq!(recovered.mint_url, selected.mint_url);
    assert_eq!(
        recovered.channel_capacity_sat,
        selected.channel_capacity_sat
    );
    assert!(recovered.funded);
    assert_eq!(store, before, "selection cannot mutate a saved purchase");
    assert_eq!(store.sessions.len(), 1);

    let mut reselect = store.clone();
    reselect.automatic_reselect_from = offer.seller_npub.clone();
    assert!(reselect.select_automatic_offer(now_unix + 3).is_err());
    for status in [
        PaidRouteLifecycleStatus::Failed,
        PaidRouteLifecycleStatus::Closing,
        PaidRouteLifecycleStatus::Closed,
        PaidRouteLifecycleStatus::Expired,
    ] {
        for channel_first in [true, false] {
            let mut stopped = store.clone();
            if channel_first {
                stopped.channels.get_mut(&opened.channel_id).unwrap().status = status;
            } else {
                stopped.leases.get_mut(&opened.lease_id).unwrap().status = status;
            }
            assert!(stopped.select_automatic_offer(now_unix + 3).is_err());
        }
    }
    assert!(store.select_automatic_offer(now_unix + 601).is_err());
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
