use super::*;

#[test]
fn paid_buyer_session_without_payment_does_not_allow_routing() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 1_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let (store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);

    assert!(paid_route_lifecycle_allows_routing(
        PaidRouteLifecycleStatus::Opening
    ));
    assert!(
        !store
            .buyer_session_allows_routing(&session_id, 121)
            .expect("route readiness")
    );
}

#[test]
fn paid_buyer_session_with_opening_payment_allows_routing() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 1_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let (mut store, session_id, _) = buyer_store_with_session(&seller, &buyer, &config);
    let channel_id = "spilman-real-channel-1";
    store
        .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.clone(),
            channel_id: channel_id.to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: Some(0),
            payment: sample_spilman_payment(channel_id, 0),
            now_unix: 130,
        })
        .expect("attach funded channel open");

    assert_eq!(
        store.channels[channel_id].status,
        PaidRouteLifecycleStatus::Opening
    );
    assert!(
        store
            .buyer_session_allows_routing(&session_id, 131)
            .expect("route readiness")
    );
}

#[test]
fn expired_offer_cannot_open_a_buyer_session() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let signed_at = 100;
    let signed = signed_paid_exit_offer_from_config(
        "internet-exit",
        &seller,
        &sample_config(),
        None,
        signed_at,
    )
    .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(
        "https://mint.minibits.cash/Bitcoin",
        "Minibits",
        Some(10_000),
        signed_at,
    );
    store
        .upsert_signed_offer(signed, Vec::new(), signed_at)
        .expect("store offer");

    let error = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: None,
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: signed_at + crate::paid_routes::PAID_ROUTE_OFFER_TTL_SECS,
        })
        .expect_err("expired offer must not open a buyer session");

    assert!(error.to_string().contains("expired"));
    assert!(store.sessions.is_empty());
    assert!(store.channels.is_empty());
}

#[test]
fn paid_route_store_path_sits_next_to_config() {
    let path = paid_route_store_file_path(Path::new("/tmp/nvpn/config.toml"));

    assert_eq!(path, PathBuf::from("/tmp/nvpn/paid-routes.json"));
}

#[test]
fn paid_route_store_persists_wallet_offer_session_and_channel_state() {
    let scratch = ScratchDir::new("roundtrip");
    let store_path = scratch.path().join("paid-routes.json");
    let seller = Keys::generate();
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("signed offer");

    let mut store = PaidRouteStore::default();
    assert!(store.upsert_wallet_mint(
        " https://mint.minibits.cash/Bitcoin ",
        "Minibits",
        Some(123_000),
        110
    ));
    assert!(
        store
            .upsert_signed_offer(
                signed_offer.clone(),
                vec!["wss://relay.example".to_string()],
                111
            )
            .expect("upsert offer")
    );
    assert!(store.upsert_channel(PaidRouteChannelRecord {
        channel_id: "channel-1".to_string(),
        offer_id: "internet-exit".to_string(),
        role: PaidRouteChannelRole::Buyer,
        status: PaidRouteLifecycleStatus::Active,
        payment: PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: "channel-1".to_string(),
            capacity_sat: 100,
            paid_msat: 42_000,
            updated_at_unix: 112,
            ..PaidRoutePaymentState::default()
        },
        accepted_terms: Some(sample_config()),
        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
        counterparty_npub: signed_offer.offer().expect("offer").seller_npub,
        created_at_unix: 111,
        expires_at_unix: 711,
        updated_at_unix: 112,
        error: String::new(),
    }));
    assert!(store.upsert_session(
        PaidRouteSession {
            session_id: "session-1".to_string(),
            lease_id: "lease-1".to_string(),
            usage: PaidRouteUsage {
                active_millis: 1000,
                tx_bytes: 10,
                rx_bytes: 20,
                tx_packets: 1,
                rx_packets: 2,
                billable_bytes: 30,
            },
            payment: PaidRoutePaymentState {
                mode: PaidRoutePaymentMode::CashuSpilman,
                channel_id: "channel-1".to_string(),
                capacity_sat: 100,
                paid_msat: 42_000,
                updated_at_unix: 112,
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: Some("198.51.100.42".to_string()),
            observed_country_code: Some("FI".to_string()),
            observed_asn: Some(14593),
            quality: Some(PaidRouteQualityMetrics {
                latency_ms: Some(42),
                jitter_ms: Some(7),
                packet_loss_ppm: Some(500),
                down_bps: Some(10_000_000),
                up_bps: Some(1_000_000),
                uptime_secs: Some(3600),
                last_seen_unix: Some(112),
            }),
        },
        112
    ));

    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("write store");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent_metadata = fs::metadata(scratch.path()).expect("parent metadata");
        let store_metadata = fs::metadata(&store_path).expect("store metadata");
        assert_eq!(store_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(store_metadata.uid(), parent_metadata.uid());
        assert_eq!(store_metadata.gid(), parent_metadata.gid());
    }
    let loaded = load_paid_route_store(&store_path).expect("load store");

    assert_eq!(
        loaded.wallet.default_mint,
        "https://mint.minibits.cash/Bitcoin"
    );
    assert_eq!(loaded.wallet.mints.len(), 1);
    assert_eq!(loaded.offers.len(), 1);
    assert_eq!(loaded.channels["channel-1"].payment.paid_msat, 42_000);
    assert_eq!(loaded.sessions["session-1"].session.usage.rx_bytes, 20);
    assert_eq!(
        loaded.sessions["session-1"]
            .session
            .quality
            .as_ref()
            .and_then(|quality| quality.jitter_ms),
        Some(7)
    );
}

#[test]
fn variable_denominator_store_upgrade_drops_only_offers() {
    let scratch = ScratchDir::new("variable-denominator-upgrade");
    let store_path = scratch.path().join("paid-routes.json");
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (store, session_id, channel_id) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let expected_mint = store.wallet.default_mint.clone();
    let mut encoded = serde_json::to_value(&store).expect("encode legacy store");
    encoded["version"] = json!(2);
    let legacy_offer = encoded["offers"]
        .as_object_mut()
        .and_then(|offers| offers.values_mut().next())
        .expect("legacy offer");
    legacy_offer["offer"]["pricing"] = json!({
        "price_msat": 2_500,
        "per_units": 1_000_000,
    });
    fs::write(
        &store_path,
        serde_json::to_vec_pretty(&encoded).expect("encode legacy fixture"),
    )
    .expect("write legacy fixture");

    let loaded = load_paid_route_store(&store_path).expect("upgrade legacy store");

    assert_eq!(loaded.version, CURRENT_VERSION);
    assert!(loaded.offers.is_empty());
    assert_eq!(loaded.wallet.default_mint, expected_mint);
    assert!(loaded.channels.contains_key(&channel_id));
    assert!(loaded.sessions.contains_key(&session_id));
}

#[test]
fn accepted_buyer_terms_survive_same_offer_replacement() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut accepted = sample_config();
    accepted.pricing.price_msat_per_gb = 1_000_000_000;
    accepted.channel.free_probe_units = 0;
    accepted.channel.grace_units = 0;
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &accepted);

    let mut replacement = accepted.clone();
    replacement.pricing.price_msat_per_gb = 10_000_000_000;
    replacement.channel.accepted_mints = vec!["https://mint.attacker.example".to_string()];
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &replacement, None, 122)
            .expect("replacement offer");
    store
        .upsert_signed_offer(signed, vec!["wss://relay.example".to_string()], 122)
        .expect("replace stored offer");

    let usage = store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                billable_bytes: 100,
                rx_bytes: 100,
                ..PaidRouteUsage::default()
            },
            now_unix: 123,
        })
        .expect("record buyer usage")
        .expect("buyer session");

    assert_eq!(usage.amount_due_msat, 100);
    let terms = store.channels[&channel_id]
        .accepted_terms
        .as_ref()
        .expect("accepted terms");
    assert_eq!(terms.pricing.price_msat_per_gb, 1_000_000_000);
    assert_eq!(
        terms.channel.accepted_mints,
        vec!["https://mint.minibits.cash/Bitcoin"]
    );
    assert_eq!(
        store
            .build_buyer_session_open(
                &session_id,
                &buyer.public_key().to_bech32().expect("buyer npub"),
                "10.44.201.17/32",
                124,
            )
            .expect("session open from accepted terms")
            .seller_npub,
        seller.public_key().to_bech32().expect("seller npub")
    );
}

#[test]
fn version_three_channels_are_preserved_but_fail_closed_without_terms() {
    let scratch = ScratchDir::new("accepted-terms-upgrade");
    let store_path = scratch.path().join("paid-routes.json");
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (store, session_id, channel_id) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let expected_offers = store.offers.len();
    let mut encoded = serde_json::to_value(store).expect("encode v3 store");
    encoded["version"] = json!(3);
    encoded["channels"][&channel_id]
        .as_object_mut()
        .expect("channel object")
        .remove("accepted_terms");
    fs::write(
        &store_path,
        serde_json::to_vec_pretty(&encoded).expect("encode v3 fixture"),
    )
    .expect("write v3 fixture");

    let loaded = load_paid_route_store(&store_path).expect("load v3 store");

    assert_eq!(loaded.version, CURRENT_VERSION);
    assert_eq!(loaded.offers.len(), expected_offers);
    assert!(loaded.channels.contains_key(&channel_id));
    assert!(loaded.sessions.contains_key(&session_id));
    assert!(
        loaded
            .buyer_session_allows_routing(&session_id, 121)
            .expect_err("legacy channel must fail closed")
            .to_string()
            .contains("no accepted terms")
    );
}

#[test]
fn paid_route_wallet_mints_can_be_defaulted_and_removed() {
    let mut store = PaidRouteStore::default();

    assert!(store.set_default_mint("https://mint.minibits.cash/Bitcoin"));
    assert_eq!(
        store.wallet.default_mint,
        "https://mint.minibits.cash/Bitcoin"
    );
    assert_eq!(store.wallet.mints.len(), 1);

    assert!(store.upsert_wallet_mint("https://mint.example", "Example", Some(10_000), 100));
    assert_eq!(store.wallet.mints.len(), 2);
    assert!(store.set_default_mint("https://mint.example"));
    assert_eq!(store.wallet.default_mint, "https://mint.example");

    assert!(store.remove_wallet_mint("https://mint.example"));
    assert_eq!(
        store.wallet.default_mint,
        "https://mint.minibits.cash/Bitcoin"
    );
    assert!(!store.remove_wallet_mint("https://missing.example"));
}

#[test]
fn paid_route_wallet_discards_invalid_mints_and_normalizes_valid_urls() {
    let mut store = PaidRouteStore::default();
    store.wallet.default_mint = "nvpn://join-request/bootstrap".to_string();
    store.wallet.mints = vec![
        PaidRouteWalletMint {
            url: "nvpn://join-request/bootstrap".to_string(),
            label: "Invalid paste".to_string(),
            balance_msat: None,
            last_checked_unix: 1,
        },
        PaidRouteWalletMint {
            url: "https://mint.example/path/".to_string(),
            label: "Valid".to_string(),
            balance_msat: None,
            last_checked_unix: 2,
        },
    ];

    store.retain_valid();

    assert_eq!(store.wallet.mints.len(), 1);
    assert_eq!(store.wallet.mints[0].url, "https://mint.example/path");
    assert_eq!(store.wallet.default_mint, "https://mint.example/path");
    assert!(normalize_paid_route_mint_url("not a URL").is_err());
    assert!(normalize_paid_route_mint_url("ftp://mint.example").is_err());
}

#[test]
fn paid_route_store_updates_session_probe_results() {
    let mut store = PaidRouteStore::default();
    assert!(store.upsert_session(
        PaidRouteSession {
            session_id: "session-1".to_string(),
            lease_id: "lease-1".to_string(),
            usage: PaidRouteUsage::default(),
            payment: PaidRoutePaymentState::default(),
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: Some(PaidRouteQualityMetrics {
                down_bps: Some(10_000),
                ..PaidRouteQualityMetrics::default()
            }),
        },
        100
    ));

    let result = store
        .update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: " session-1 ".to_string(),
            realized_exit_ip: Some(" 198.51.100.42 ".to_string()),
            observed_country_code: Some(" fi ".to_string()),
            observed_asn: Some(14_593),
            quality: Some(PaidRouteQualityMetrics {
                latency_ms: Some(42),
                jitter_ms: Some(7),
                ..PaidRouteQualityMetrics::default()
            }),
            now_unix: 123,
        })
        .expect("update probe");

    assert!(result.changed);
    assert_eq!(result.realized_exit_ip.as_deref(), Some("198.51.100.42"));
    assert_eq!(result.observed_country_code.as_deref(), Some("FI"));
    assert_eq!(result.observed_asn, Some(14_593));
    let quality = result.quality.expect("quality");
    assert_eq!(quality.latency_ms, Some(42));
    assert_eq!(quality.jitter_ms, Some(7));
    assert_eq!(quality.down_bps, Some(10_000));
    assert_eq!(quality.last_seen_unix, Some(123));
    assert_eq!(store.sessions["session-1"].updated_at_unix, 123);

    let unchanged = store
        .update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: "session-1".to_string(),
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: None,
            now_unix: 124,
        })
        .expect("empty update");
    assert!(!unchanged.changed);
    assert_eq!(store.sessions["session-1"].updated_at_unix, 123);
}

#[test]
fn paid_route_store_opens_buyer_probe_session_from_offer() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &sample_config(), None, 100)
            .expect("signed offer");
    let offer = signed_offer.offer().expect("offer");
    let offer_key = paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id);
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.minibits.cash/Bitcoin", "Minibits", None, 99);
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");

    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: None,
            channel_capacity_sat: Some(50),
            initial_paid_msat: 0,
            now_unix: 120,
        })
        .expect("open buyer session");

    assert!(result.changed);
    assert_eq!(result.offer_key, offer_key);
    assert_eq!(result.offer_id, "internet-exit");
    assert_eq!(result.seller_npub, offer.seller_npub);
    assert_eq!(result.mint_url, "https://mint.minibits.cash/Bitcoin");
    assert_eq!(result.channel_capacity_sat, 50);
    assert_eq!(result.expires_at_unix, 720);
    assert_eq!(store.wallet.mints[0].label, "Minibits");
    assert_eq!(
        store.quotes[&result.quote_id].quote.receiver_pubkey_hex,
        seller.public_key().to_hex()
    );
    assert_eq!(
        store.leases[&result.lease_id].status,
        PaidRouteLifecycleStatus::Probing
    );
    assert_eq!(
        store.channels[&result.channel_id].status,
        PaidRouteLifecycleStatus::Probing
    );
    assert_eq!(
        store.sessions[&result.session_id]
            .session
            .payment
            .channel_id,
        result.channel_id
    );
    assert_eq!(
        store
            .buyer_session_seller_npub(&result.session_id)
            .expect("resolve seller"),
        offer.seller_npub
    );
}

#[test]
fn paid_route_store_uses_offer_spilman_receiver_pubkey_for_buyer_quote() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let receiver_pubkey_hex = format!("03{}", "22".repeat(32));
    let signed_offer = signed_paid_exit_offer_from_config_with_receiver(
        "internet-exit",
        &seller,
        &sample_config(),
        Some(&receiver_pubkey_hex),
        None,
        100,
    )
    .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.minibits.cash/Bitcoin", "Minibits", None, 99);
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");

    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: None,
            channel_capacity_sat: Some(50),
            initial_paid_msat: 0,
            now_unix: 120,
        })
        .expect("open buyer session");

    assert_eq!(
        store.quotes[&result.quote_id].quote.receiver_pubkey_hex,
        receiver_pubkey_hex
    );
}

#[test]
fn buyer_session_seller_npub_rejects_seller_sessions() {
    let mut store = PaidRouteStore::default();
    assert!(store.upsert_channel(PaidRouteChannelRecord {
        channel_id: "channel-1".to_string(),
        offer_id: "internet-exit".to_string(),
        role: PaidRouteChannelRole::Seller,
        status: PaidRouteLifecycleStatus::Active,
        payment: PaidRoutePaymentState {
            channel_id: "channel-1".to_string(),
            ..PaidRoutePaymentState::default()
        },
        accepted_terms: None,
        mint_url: "https://mint.example".to_string(),
        counterparty_npub:
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfu2a5w".to_string(),
        created_at_unix: 100,
        expires_at_unix: 700,
        updated_at_unix: 100,
        error: String::new(),
    }));
    assert!(store.upsert_session(
        PaidRouteSession {
            session_id: "session-1".to_string(),
            lease_id: "lease-1".to_string(),
            usage: PaidRouteUsage::default(),
            payment: PaidRoutePaymentState {
                channel_id: "channel-1".to_string(),
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: None,
        },
        100
    ));

    let error = store
        .buyer_session_seller_npub("session-1")
        .expect_err("reject seller channel");

    assert!(error.to_string().contains("not a buyer session"));
}

#[test]
fn attach_buyer_spilman_channel_replaces_placeholder_channel_id() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, placeholder_channel_id) =
        buyer_store_with_session(&seller, &buyer, &config);
    let real_channel_id = "spilman-real-channel-1";

    let result = store
        .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.clone(),
            channel_id: real_channel_id.to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: Some(1_000),
            payment: sample_spilman_payment(real_channel_id, 1),
            now_unix: 130,
        })
        .expect("attach real channel");

    assert!(result.changed);
    assert_eq!(result.previous_channel_id, placeholder_channel_id);
    assert!(!store.channels.contains_key(&placeholder_channel_id));
    assert_eq!(
        store.channels[real_channel_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(
        store.sessions[&session_id].session.payment.channel_id,
        real_channel_id
    );
    assert_eq!(store.sessions[&session_id].session.payment.paid_msat, 1_000);
    assert_eq!(
        store.sessions[&session_id]
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.channel_id.as_str()),
        Some(real_channel_id)
    );
}

#[test]
fn attach_buyer_spilman_channel_rejects_overclaimed_payment_without_mutating_store() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;
    let (mut store, session_id, placeholder_channel_id) =
        buyer_store_with_session(&seller, &buyer, &config);
    let before = store.clone();

    let error = store
        .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.clone(),
            channel_id: "spilman-real-channel-1".to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: Some(2_000),
            payment: sample_spilman_payment("spilman-real-channel-1", 1),
            now_unix: 130,
        })
        .expect_err("overclaimed payment should fail");

    assert!(
        error
            .to_string()
            .contains("does not match Cashu Spilman balance")
    );
    assert_eq!(store, before);
    assert!(store.channels.contains_key(&placeholder_channel_id));
}

#[test]
fn seller_admissions_reflect_streaming_payment_decision() {
    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut config = sample_config();
    config.pricing.price_msat_per_gb = 10_000_000_000;
    config.channel.free_probe_units = 0;
    config.channel.grace_units = 0;

    let mut store = PaidRouteStore::default();
    assert!(store.upsert_lease(
        PaidRouteLease {
            lease_id: "lease-1".to_string(),
            offer_id: "internet-exit".to_string(),
            quote_id: "quote-1".to_string(),
            buyer_npub: buyer_npub.clone(),
            starts_at_unix: 100,
            expires_at_unix: 200,
        },
        PaidRouteLifecycleStatus::Active,
        100,
    ));
    store
        .seller_session_tunnel_ips
        .insert("session-1".to_string(), "10.44.201.17/32".to_string());
    assert!(store.upsert_channel(PaidRouteChannelRecord {
        channel_id: "channel-1".to_string(),
        offer_id: "internet-exit".to_string(),
        role: PaidRouteChannelRole::Seller,
        status: PaidRouteLifecycleStatus::Active,
        payment: PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: "channel-1".to_string(),
            capacity_sat: 10,
            paid_msat: 1_000,
            updated_at_unix: 100,
            ..PaidRoutePaymentState::default()
        },
        accepted_terms: Some(config.clone()),
        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
        counterparty_npub: buyer_npub.clone(),
        created_at_unix: 100,
        expires_at_unix: 200,
        updated_at_unix: 100,
        error: String::new(),
    }));
    assert!(store.upsert_session(
        PaidRouteSession {
            session_id: "session-1".to_string(),
            lease_id: "lease-1".to_string(),
            usage: PaidRouteUsage {
                rx_bytes: 100,
                billable_bytes: 100,
                ..PaidRouteUsage::default()
            },
            payment: PaidRoutePaymentState {
                mode: PaidRoutePaymentMode::CashuSpilman,
                channel_id: "channel-1".to_string(),
                capacity_sat: 10,
                paid_msat: 1_000,
                updated_at_unix: 100,
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: None,
        },
        100,
    ));

    let admissions = store.seller_admissions(&config, 149);

    assert_eq!(admissions.len(), 1);
    assert_eq!(admissions[0].buyer_pubkey, buyer.public_key().to_hex());
    assert_eq!(admissions[0].buyer_npub, buyer_npub);
    assert_eq!(admissions[0].buyer_tunnel_ip, "10.44.201.17/32");
    assert_eq!(admissions[0].state, PaidRouteAccessState::Paid);
    assert!(admissions[0].allow_routing);
    assert_eq!(admissions[0].amount_due_msat, 1_000);
    assert_eq!(admissions[0].unpaid_msat, 0);

    {
        let record = store.sessions.get_mut("session-1").expect("session");
        record.session.usage.rx_bytes = 200;
        record.session.usage.billable_bytes = 200;
        record.updated_at_unix = 151;
    }
    let admissions = store.seller_admissions(&config, 149);

    assert_eq!(admissions[0].state, PaidRouteAccessState::Suspended);
    assert!(!admissions[0].allow_routing);
    assert_eq!(admissions[0].amount_due_msat, 2_000);
    assert_eq!(admissions[0].unpaid_msat, 1_000);

    let admissions = store.seller_admissions(&config, 201);

    assert!(!admissions[0].allow_routing);
    assert_eq!(admissions[0].state, PaidRouteAccessState::Suspended);
}

#[test]
fn seller_collection_states_mark_preexpiry_spilman_credit_due() {
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
                    delivered_units: 100,
                    amount_due_msat: 1_000,
                    paid_msat: 1_000,
                    payment: sample_spilman_payment("channel-1", 1),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 129,
        })
        .expect("apply paid balance");

    let current = store.seller_collection_states(&config, 299);

    assert_eq!(current.len(), 1);
    assert!(current[0].collectable);
    assert!(current[0].manual_collect);
    assert!(!current[0].auto_collect_due);
    assert_eq!(current[0].reason, "manual");
    assert_eq!(current[0].paid_msat, 1_000);
    assert_eq!(current[0].due_at_unix, 300);
    assert_eq!(current[0].expires_at_unix, 500);

    let due = store.seller_collection_states(&config, 300);

    assert_eq!(due.len(), 1);
    assert!(due[0].collectable);
    assert!(due[0].manual_collect);
    assert!(due[0].auto_collect_due);
    assert_eq!(due[0].reason, "settlement_due");
    assert_eq!(due[0].channel_id, "channel-1");
    assert_eq!(due[0].session_id, "seller-session-lease-1");

    config.enabled = false;
    let disabled_due = store.seller_collection_states(&config, 500);

    assert_eq!(disabled_due.len(), 1);
    assert!(disabled_due[0].auto_collect_due);
    assert_eq!(disabled_due[0].channel_id, "channel-1");
    assert!(
        store
            .seller_collection_state_for_session(&config, 500, "seller-session-lease-1")
            .is_some_and(|state| state.auto_collect_due),
        "disabling new sales must not hide an existing collectable channel"
    );
}
