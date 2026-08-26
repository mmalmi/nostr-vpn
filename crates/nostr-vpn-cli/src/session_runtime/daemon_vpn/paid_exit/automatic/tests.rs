use super::*;
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::InternetSource;
use nostr_vpn_core::paid_routes::{PaidRouteChannelTerms, PaidRouteIpSupport, PaidRoutePricing};

#[test]
fn automatic_selection_activates_a_routable_unfunded_probe_session() {
    let seller = Keys::generate();
    let seller_pubkey = seller.public_key().to_hex();
    let now = unix_timestamp();
    let directory =
        std::env::temp_dir().join(format!("nvpn-auto-buyer-{}-{now}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create automatic buyer test directory");
    let config_path = directory.join("config.toml");
    let store_path = paid_route_store_file_path(&config_path);
    let mint = "https://mint.example";
    let offer_config = PaidExitConfig {
        enabled: true,
        pricing: PaidRoutePricing {
            price_msat_per_gb: 90_000,
        },
        channel: PaidRouteChannelTerms {
            accepted_mints: vec![mint.to_string()],
            max_channel_capacity_sat: 100,
            channel_expiry_secs: 600,
            free_probe_units: 1_048_576,
            ..PaidRouteChannelTerms::default()
        },
        ip_support: PaidRouteIpSupport {
            ipv4: true,
            ..PaidRouteIpSupport::default()
        },
        ..PaidExitConfig::default()
    };
    let signed = nostr_vpn_core::paid_routes::signed_paid_exit_offer_from_config(
        "automatic",
        &seller,
        &offer_config,
        None,
        now,
    )
    .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(mint, "approved", Some(100_000), now);
    store
        .upsert_signed_offer(signed, Vec::new(), now)
        .expect("stored offer");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("write store");

    let mut app = AppConfig::generated();
    app.set_internet_source(InternetSource::PaidAutomatic);
    let mut automatic = PaidExitAutomaticBuyer::default();
    assert!(
        reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &config_path, now,)
            .expect("automatic selection")
    );

    assert_eq!(app.internet_source, InternetSource::PaidAutomatic);
    assert_eq!(
        app.public_paid_exit_node_pubkey_hex().as_deref(),
        Some(seller_pubkey.as_str())
    );
    let stored = load_paid_route_store(&store_path).expect("reloaded store");
    assert_eq!(stored.sessions.len(), 1);
    let session = stored.sessions.values().next().expect("probe session");
    assert_eq!(session.session.payment.paid_msat, 0);
    assert!(session.session.payment.cashu_spilman_payment.is_none());
    assert!(
        stored
            .buyer_session_allows_routing(&session.session.session_id, now)
            .expect("automatic probe route decision")
    );
    let saved = AppConfig::load(&config_path).expect("saved automatic route config");
    assert_eq!(saved.internet_source, InternetSource::PaidAutomatic);
    assert_eq!(
        saved.public_paid_exit_node_pubkey_hex().as_deref(),
        Some(seller_pubkey.as_str())
    );
    let network_id = saved.effective_network_id();
    let own_pubkey = saved.own_nostr_pubkey_hex().expect("buyer pubkey");
    let tunnel = crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app(
        &saved,
        &network_id,
        "utun-test",
        Some(&own_pubkey),
        None,
        &[],
    )
    .expect("automatic paid exit tunnel config");
    let seller_peer = tunnel
        .peers
        .iter()
        .find(|peer| peer.participant_pubkey == seller_pubkey)
        .expect("selected seller tunnel peer");
    assert!(
        seller_peer
            .allowed_ips
            .iter()
            .any(|route| route == "0.0.0.0/0")
    );
    assert!(
        !crate::fips_private_mesh::effective_fips_route_targets(&tunnel, &[])
            .iter()
            .any(|route| route == "0.0.0.0/0"),
        "non-strict mode must retain the home route until the selected seller connects"
    );
    assert!(
        crate::fips_private_mesh::effective_fips_route_targets(
            &tunnel,
            &[test_peer_status(&seller_pubkey, now)],
        )
        .iter()
        .any(|route| route == "0.0.0.0/0"),
        "the automatic seller connection must activate the exit route"
    );
    assert!(!automatic.payments_allowed(&app, now));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn automatic_buyer_requires_probe_authenticated_seller_and_both_counter_directions() {
    let seller = Keys::generate();
    let seller_pubkey = seller.public_key().to_hex();
    let mut automatic = PaidExitAutomaticBuyer {
        candidate: Some(test_candidate(&seller_pubkey)),
        ..PaidExitAutomaticBuyer::default()
    };
    let mut app = AppConfig::generated();
    app.set_internet_source(InternetSource::PaidAutomatic);
    let now = 100;

    assert!(!automatic.payments_allowed(&app, now));
    let candidate = automatic.candidate.as_mut().expect("candidate");
    candidate.probe_succeeded = true;
    candidate.funded = true;
    candidate.observe_presence(&[test_peer_status("other", now)], now);
    candidate.observe_usage(
        &PaidRouteUsage {
            tx_bytes: 10,
            ..PaidRouteUsage::default()
        },
        now,
    );
    assert!(!automatic.payments_allowed(&app, now));

    automatic
        .candidate
        .as_mut()
        .expect("candidate")
        .observe_presence(&[test_peer_status(&seller_pubkey, now)], now);
    assert!(!automatic.payments_allowed(&app, now));
    automatic
        .candidate
        .as_mut()
        .expect("candidate")
        .observe_usage(
            &PaidRouteUsage {
                rx_bytes: 20,
                ..PaidRouteUsage::default()
            },
            now,
        );
    assert!(automatic.payments_allowed(&app, now));
    assert!(!automatic.payments_allowed(&app, now + PAID_EXIT_AUTO_HEALTH_TTL_SECS + 1));
}

#[test]
fn automatic_cancellation_never_overwrites_another_internet_mode() {
    let seller = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let seller_pubkey = seller.public_key().to_hex();
    let mut app = AppConfig::generated();
    app.select_public_paid_exit_node(&seller_npub)
        .expect("manual seller");
    let selected_before = app.exit_node.clone();
    let mut automatic = PaidExitAutomaticBuyer {
        candidate: Some(test_candidate(&seller_pubkey)),
        ..PaidExitAutomaticBuyer::default()
    };
    let generation = automatic.generation;

    automatic.cancel_if_disabled(&app);

    assert_eq!(app.internet_source, InternetSource::PaidManual);
    assert_eq!(app.exit_node, selected_before);
    assert!(automatic.candidate.is_none());
    assert_ne!(automatic.generation, generation);
    assert!(automatic.payments_allowed(&app, 100));
}

#[test]
fn automatic_failed_offer_is_retried_after_cooldown() {
    let mut automatic = PaidExitAutomaticBuyer::default();
    automatic.start_candidate(
        serde_json::from_value(json!({
            "offer_key": "offer",
            "mint_url": "https://mint.example",
            "channel_capacity_sat": 10,
        }))
        .expect("selection"),
        "seller".to_string(),
        "session".to_string(),
        false,
        100,
    );
    automatic.cancel_candidate(true, 120);

    assert!(automatic.rejected_offers.contains_key("offer"));
    automatic.expire_rejected_offers(120 + PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS - 1);
    assert!(automatic.rejected_offers.contains_key("offer"));
    automatic.expire_rejected_offers(120 + PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS);
    assert!(!automatic.rejected_offers.contains_key("offer"));
}

#[test]
fn automatic_candidate_keeps_same_offer_when_funded_capacity_becomes_authoritative() {
    let seller = Keys::generate();
    let mut candidate = test_candidate(&seller.public_key().to_hex());
    let funded = serde_json::from_value(json!({
        "offer_key": "offer",
        "mint_url": "https://mint.example",
        "channel_capacity_sat": 7,
    }))
    .expect("funded selection");

    candidate.reconcile_selection(funded);

    assert!(!candidate.failed);
    assert_eq!(candidate.selection.channel_capacity_sat, 7);

    let replacement = serde_json::from_value(json!({
        "offer_key": "replacement",
        "mint_url": "https://mint.example",
        "channel_capacity_sat": 7,
    }))
    .expect("replacement selection");
    candidate.reconcile_selection(replacement);
    assert!(candidate.failed);

    let mut candidate = test_candidate(&seller.public_key().to_hex());
    let changed_mint = serde_json::from_value(json!({
        "offer_key": "offer",
        "mint_url": "https://other-mint.example",
        "channel_capacity_sat": 7,
    }))
    .expect("changed mint selection");
    candidate.reconcile_selection(changed_mint);
    assert!(candidate.failed);
}

#[test]
fn automatic_probe_health_does_not_require_a_vendor_bandwidth_sample() {
    let measurement = PaidRouteProbeMeasurement {
        realized_exit_ip: Some("203.0.113.10".to_string()),
        observed_country_code: None,
        observed_asn: None,
        quality: Default::default(),
        samples: vec![PaidRouteProbeSample::success(
            "203.0.113.10".to_string(),
            12,
        )],
    };

    assert!(runtime::automatic_probe_observed_public_ip(&measurement));
    assert!(measurement.quality.down_bps.is_none());
    assert!(measurement.quality.up_bps.is_none());
}

fn test_candidate(seller_pubkey: &str) -> PaidExitAutomaticCandidate {
    PaidExitAutomaticCandidate {
        selection: serde_json::from_value(json!({
            "offer_key": "offer",
            "mint_url": "https://mint.example",
            "channel_capacity_sat": 10,
        }))
        .expect("selection"),
        seller_pubkey: seller_pubkey.to_string(),
        session_id: "session".to_string(),
        selected_at: 100,
        probe_started_at: Some(100),
        probe_succeeded: false,
        funding_attempted: false,
        funded: false,
        last_authenticated_at: None,
        last_tx_at: None,
        last_rx_at: None,
        last_healthy_at: None,
        failed: false,
    }
}

fn test_peer_status(pubkey: &str, now: u64) -> MeshPeerStatus {
    MeshPeerStatus {
        pubkey: pubkey.to_string(),
        connected: true,
        endpoint_npub: String::new(),
        transport_addr: None,
        transport_type: None,
        srtt_ms: None,
        srtt_age_ms: None,
        link_packets_sent: 0,
        link_packets_recv: 0,
        link_bytes_sent: 0,
        link_bytes_recv: 0,
        rekey_in_progress: false,
        rekey_draining: false,
        current_k_bit: None,
        last_outbound_route: None,
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        nostr_traversal_consecutive_failures: 0,
        nostr_traversal_in_cooldown: false,
        nostr_traversal_cooldown_until_ms: None,
        nostr_traversal_last_observed_skew_ms: None,
        last_seen_at: Some(now),
        last_control_seen_at: Some(now),
        last_data_seen_at: Some(now),
        tx_bytes: 0,
        rx_bytes: 0,
        error: None,
    }
}
