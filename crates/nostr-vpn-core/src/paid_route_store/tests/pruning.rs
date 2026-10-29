use super::*;

const DAY: u64 = 24 * 60 * 60;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Mirrors the refund recovery selector in the daemon: the channels whose
/// payment material can still be restored into the buyer wallet.
fn refund_recovery_channel_ids(store: &PaidRouteStore) -> Vec<String> {
    store
        .channels
        .values()
        .filter(|channel| {
            channel.role == PaidRouteChannelRole::Buyer
                && channel.payment.mode == PaidRoutePaymentMode::CashuSpilman
                && channel.payment.cashu_spilman_payment.is_some()
                && matches!(
                    channel.status,
                    PaidRouteLifecycleStatus::Closing
                        | PaidRouteLifecycleStatus::Closed
                        | PaidRouteLifecycleStatus::Failed
                        | PaidRouteLifecycleStatus::Expired
                )
        })
        .map(|channel| channel.channel_id.clone())
        .collect()
}

/// Adds a long-offline buyer channel with its own lease, quote, session, and
/// session-keyed state: exactly the records a refund recovery scan needs.
fn add_offline_buyer_records(
    store: &mut PaidRouteStore,
    seller: &Keys,
    channel_id: &str,
    status: PaidRouteLifecycleStatus,
    at_unix: u64,
) {
    let quote_id = format!("{channel_id}-quote");
    let lease_id = format!("{channel_id}-lease");
    let session_id = format!("{channel_id}-session");
    store.upsert_quote(
        PaidRouteQuote {
            quote_id: quote_id.clone(),
            offer_id: "internet-exit".to_string(),
            payment_mode: PaidRoutePaymentMode::CashuSpilman,
            channel_capacity_sat: 10,
            expires_at_unix: at_unix,
            receiver_pubkey_hex: seller.public_key().to_bech32().unwrap(),
        },
        at_unix,
    );
    store.upsert_lease(
        PaidRouteLease {
            lease_id: lease_id.clone(),
            offer_id: "internet-exit".to_string(),
            quote_id,
            buyer_npub: seller.public_key().to_bech32().unwrap(),
            starts_at_unix: at_unix,
            expires_at_unix: at_unix,
        },
        status,
        at_unix,
    );
    store.upsert_channel(PaidRouteChannelRecord {
        channel_id: channel_id.to_string(),
        offer_id: "internet-exit".to_string(),
        role: PaidRouteChannelRole::Buyer,
        status,
        payment: PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: channel_id.to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: 1_000,
            updated_at_unix: at_unix,
            cashu_spilman_payment: Some(sample_spilman_payment(channel_id, 1)),
            cashu_token_lease: None,
        },
        accepted_terms: None,
        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
        counterparty_npub: seller.public_key().to_bech32().unwrap(),
        created_at_unix: at_unix,
        expires_at_unix: at_unix,
        updated_at_unix: at_unix,
        error: String::new(),
    });
    store.upsert_session(
        PaidRouteSession {
            session_id: session_id.clone(),
            lease_id: lease_id.clone(),
            usage: PaidRouteUsage::default(),
            payment: PaidRoutePaymentState {
                channel_id: channel_id.to_string(),
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: None,
        },
        at_unix,
    );
    store.buyer_session_admissions.insert(lease_id, at_unix);
    store
        .seller_session_tunnel_ips
        .insert(session_id, "10.44.201.18/32".to_string());
}

/// A buyer returning online after months must still find every channel a
/// refund recovery scan selects: store loads never remove records, so
/// long-offline recovery state survives any number of reloads.
#[test]
fn refund_recovery_state_survives_offline_gap_longer_than_any_retention() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, live_session, live_channel) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let live_lease = store.sessions[&live_session].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &live_lease, 200)
        .unwrap();
    let offline_since = now_unix() - 90 * DAY;
    for (channel_id, status) in [
        ("recover-closing", PaidRouteLifecycleStatus::Closing),
        ("recover-expired", PaidRouteLifecycleStatus::Expired),
        ("recover-failed", PaidRouteLifecycleStatus::Failed),
    ] {
        add_offline_buyer_records(&mut store, &seller, channel_id, status, offline_since);
    }
    store.selected_buyer_session_id = "recover-closing-session".to_string();

    let scratch = ScratchDir::new("recovery-outlives-retention");
    let store_path = scratch.path().join("store.json");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .unwrap();

    let mut reloaded = load_paid_route_store(&store_path).unwrap();
    for _ in 0..5 {
        reloaded = load_paid_route_store(&store_path).unwrap();
    }

    for channel_id in ["recover-closing", "recover-expired", "recover-failed"] {
        let channel = reloaded
            .channels
            .get(channel_id)
            .unwrap_or_else(|| panic!("offline channel {channel_id} was pruned"));
        assert!(
            channel.payment.cashu_spilman_payment.is_some(),
            "{channel_id} lost its refund material"
        );
        assert!(
            reloaded
                .sessions
                .values()
                .any(|record| record.session.payment.channel_id == channel_id),
            "{channel_id} lost its session"
        );
        assert!(
            reloaded
                .buyer_session_admissions
                .contains_key(&format!("{channel_id}-lease")),
            "{channel_id} lost its admission"
        );
    }
    let selected = refund_recovery_channel_ids(&reloaded);
    for channel_id in ["recover-closing", "recover-expired", "recover-failed"] {
        assert!(
            selected.contains(&channel_id.to_string()),
            "recovery scan lost {channel_id}: {selected:?}"
        );
    }
    assert_eq!(
        reloaded.selected_buyer_session_id,
        "recover-closing-session"
    );
    assert!(reloaded.channels.contains_key(&live_channel));
    assert!(reloaded.sessions.contains_key(&live_session));
    assert!(reloaded.buyer_session_admissions.contains_key(&live_lease));
}

/// The completion writers leave their records readable. Loads must keep
/// them: late payment replays drain against the persisted seller channel,
/// and the refund scan still selects closed buyer channels.
#[test]
fn settled_records_survive_reload() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();

    let mut seller_store = seller_store_with_open_channel(&seller, &buyer, &config);
    seller_store
        .mark_seller_channel_closed("channel-1", 1_000, now_unix())
        .unwrap();

    let (mut buyer_store, live_session, live_channel) =
        buyer_store_with_session(&seller, &buyer, &config);
    let live_lease = buyer_store.sessions[&live_session].session.lease_id.clone();
    buyer_store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &live_lease, 200)
        .unwrap();
    let live_quote = buyer_store.leases[&live_lease].lease.quote_id.clone();
    buyer_store
        .mark_buyer_channel_closed(&live_channel, now_unix())
        .unwrap();

    let scratch = ScratchDir::new("settled-records-survive-reload");
    let seller_path = scratch.path().join("seller.json");
    let buyer_path = scratch.path().join("buyer.json");
    update_paid_route_store(&seller_path, |target| {
        *target = seller_store;
        Ok(())
    })
    .unwrap();
    update_paid_route_store(&buyer_path, |target| {
        *target = buyer_store;
        Ok(())
    })
    .unwrap();

    let mut seller_loaded = load_paid_route_store(&seller_path).unwrap();
    let mut buyer_loaded = load_paid_route_store(&buyer_path).unwrap();
    for _ in 0..5 {
        seller_loaded = load_paid_route_store(&seller_path).unwrap();
        buyer_loaded = load_paid_route_store(&buyer_path).unwrap();
    }

    assert_eq!(
        seller_loaded.channels["channel-1"].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert!(
        seller_loaded
            .sessions
            .contains_key("seller-session-lease-1")
    );
    assert!(seller_loaded.leases.contains_key("lease-1"));
    assert!(seller_loaded.quotes.contains_key("seller-quote-lease-1"));
    assert!(
        seller_loaded
            .seller_session_tunnel_ips
            .contains_key("seller-session-lease-1")
    );

    assert_eq!(
        buyer_loaded.channels[&live_channel].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert!(buyer_loaded.sessions.contains_key(&live_session));
    assert!(buyer_loaded.leases.contains_key(&live_lease));
    assert!(buyer_loaded.quotes.contains_key(&live_quote));
    assert!(
        buyer_loaded
            .buyer_session_admissions
            .contains_key(&live_lease)
    );
}
