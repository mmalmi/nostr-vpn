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

/// The state mark_seller_channel_closed leaves behind after collection.
fn settle_seller_records(store: &mut PaidRouteStore, at_unix: u64) {
    let channel = store.channels.get_mut("channel-1").unwrap();
    channel.status = PaidRouteLifecycleStatus::Closed;
    channel.created_at_unix = at_unix;
    channel.updated_at_unix = at_unix;
    let session = store.sessions.get_mut("seller-session-lease-1").unwrap();
    session.created_at_unix = at_unix;
    session.updated_at_unix = at_unix;
    let lease = store.leases.get_mut("lease-1").unwrap();
    lease.status = PaidRouteLifecycleStatus::Closed;
    lease.created_at_unix = at_unix;
    lease.updated_at_unix = at_unix;
    let quote = store
        .quotes
        .get_mut("seller-quote-lease-1")
        .expect("seller quote");
    quote.quote.expires_at_unix = at_unix;
    quote.created_at_unix = at_unix;
    quote.updated_at_unix = at_unix;
}

fn age_seller_records(store: &mut PaidRouteStore, at_unix: u64) {
    let channel = store.channels.get_mut("channel-1").unwrap();
    channel.created_at_unix = at_unix;
    channel.updated_at_unix = at_unix;
    let session = store.sessions.get_mut("seller-session-lease-1").unwrap();
    session.created_at_unix = at_unix;
    session.updated_at_unix = at_unix;
    let lease = store.leases.get_mut("lease-1").unwrap();
    lease.created_at_unix = at_unix;
    lease.updated_at_unix = at_unix;
    let quote = store
        .quotes
        .get_mut("seller-quote-lease-1")
        .expect("seller quote");
    quote.created_at_unix = at_unix;
    quote.updated_at_unix = at_unix;
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

/// Adds a long-settled buyer channel as mark_buyer_channel_closed leaves it,
/// with its own lease, quote, session, and session-keyed state.
fn add_settled_buyer_records(store: &mut PaidRouteStore, seller: &Keys, at_unix: u64) {
    add_offline_buyer_records(
        store,
        seller,
        "old-channel",
        PaidRouteLifecycleStatus::Closed,
        at_unix,
    );
    store.buyer_session_renewals.insert(
        "old-channel-session".to_string(),
        "missing-target".to_string(),
    );
    store
        .buyer_session_renewal_starts
        .insert("old-channel-session".to_string(), at_unix);
    store
        .buyer_session_open_attempts
        .insert("old-channel-session".to_string(), at_unix);
    store.selected_buyer_session_id = "old-channel-session".to_string();
}

#[test]
fn settled_channel_is_pruned_with_proofs_and_dependents() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &sample_config());
    let now = now_unix();
    settle_seller_records(&mut store, now - 30 * DAY);
    assert!(
        store.channels["channel-1"]
            .payment
            .cashu_spilman_payment
            .as_ref()
            .is_some_and(CashuSpilmanPayment::has_funding)
    );
    store.seller_session_tunnel_ips.insert(
        "seller-session-lease-1".to_string(),
        "10.44.201.17/32".to_string(),
    );

    store.prune_settled_records();

    assert!(!store.channels.contains_key("channel-1"));
    assert!(!store.sessions.contains_key("seller-session-lease-1"));
    assert!(!store.leases.contains_key("lease-1"));
    assert!(!store.quotes.contains_key("seller-quote-lease-1"));
    assert!(
        !store
            .seller_session_tunnel_ips
            .contains_key("seller-session-lease-1")
    );
}

#[test]
fn unsettled_seller_records_stay_however_old_they_are() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let now = now_unix();

    let mut closing = seller_store_with_open_channel(&seller, &buyer, &config);
    settle_seller_records(&mut closing, now - 30 * DAY);
    closing.channels.get_mut("channel-1").unwrap().status = PaidRouteLifecycleStatus::Closing;
    let before = closing.clone();
    closing.prune_settled_records();
    assert_eq!(closing, before, "settlement in flight stays");

    let mut expired = seller_store_with_open_channel(&seller, &buyer, &config);
    age_seller_records(&mut expired, now - 30 * DAY);
    expired.channels.get_mut("channel-1").unwrap().status = PaidRouteLifecycleStatus::Expired;
    expired.leases.get_mut("lease-1").unwrap().status = PaidRouteLifecycleStatus::Expired;
    let before = expired.clone();
    expired.prune_settled_records();
    assert_eq!(
        expired, before,
        "expired records stay without settlement proof"
    );

    let mut live = seller_store_with_open_channel(&seller, &buyer, &config);
    {
        let channel = live.channels.get_mut("channel-1").unwrap();
        channel.created_at_unix = now.saturating_sub(30 * DAY);
        channel.updated_at_unix = now.saturating_sub(30 * DAY);
    }
    let before = live.clone();
    live.prune_settled_records();
    assert_eq!(live, before, "routable channels stay however old they are");
}

#[test]
fn settled_buyer_channel_goes_while_live_flows_stay() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, live_session, live_channel) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let live_lease = store.sessions[&live_session].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &live_lease, 200)
        .unwrap();
    add_settled_buyer_records(&mut store, &seller, now_unix() - 30 * DAY);

    store.prune_settled_records();

    assert!(!store.channels.contains_key("old-channel"));
    assert!(!store.sessions.contains_key("old-channel-session"));
    assert!(!store.leases.contains_key("old-channel-lease"));
    assert!(!store.quotes.contains_key("old-channel-quote"));
    assert!(
        !store
            .buyer_session_admissions
            .contains_key("old-channel-lease")
    );
    assert!(
        !store
            .buyer_session_renewals
            .contains_key("old-channel-session")
    );
    assert!(
        !store
            .buyer_session_renewal_starts
            .contains_key("old-channel-session")
    );
    assert!(
        !store
            .buyer_session_open_attempts
            .contains_key("old-channel-session")
    );
    assert!(
        !store
            .seller_session_tunnel_ips
            .contains_key("old-channel-session")
    );
    assert_eq!(store.selected_buyer_session_id, "");

    assert!(store.channels.contains_key(&live_channel));
    assert!(store.sessions.contains_key(&live_session));
    assert!(store.buyer_session_admissions.contains_key(&live_lease));
}

/// A buyer returning online after months must still find every channel a
/// refund recovery scan selects: nothing but a proven settlement removes
/// recovery state, so long-offline records survive any number of reloads.
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

/// mark_buyer_channel_closed is the only writer of Closed on buyer channels
/// and runs once a refund finished importing, so its records are prunable.
#[test]
fn buyer_refund_completion_prunes_on_the_next_reload() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, live_session, live_channel) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let live_lease = store.sessions[&live_session].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &live_lease, 200)
        .unwrap();
    let live_quote = store.leases[&live_lease].lease.quote_id.clone();
    let channel = store.channels.get_mut(&live_channel).unwrap();
    channel.payment.cashu_spilman_payment = Some(sample_spilman_payment(&live_channel, 1));
    store
        .mark_buyer_channel_closed(&live_channel, now_unix())
        .unwrap();
    assert_eq!(
        store.channels[&live_channel].status,
        PaidRouteLifecycleStatus::Closed
    );

    let scratch = ScratchDir::new("buyer-refund-complete-prune");
    let store_path = scratch.path().join("store.json");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .unwrap();
    let reloaded = load_paid_route_store(&store_path).unwrap();

    assert!(!reloaded.channels.contains_key(&live_channel));
    assert!(!reloaded.sessions.contains_key(&live_session));
    assert!(!reloaded.leases.contains_key(&live_lease));
    assert!(!reloaded.quotes.contains_key(&live_quote));
    assert!(!reloaded.buyer_session_admissions.contains_key(&live_lease));
}

#[test]
fn store_reload_prunes_only_settled_records() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let now = now_unix();
    let scratch = ScratchDir::new("prune-on-reload");
    let settled_path = scratch.path().join("settled.json");
    let unsettled_path = scratch.path().join("unsettled.json");

    let mut settled = seller_store_with_open_channel(&seller, &buyer, &config);
    settle_seller_records(&mut settled, now - 30 * DAY);
    update_paid_route_store(&settled_path, |target| {
        *target = settled;
        Ok(())
    })
    .unwrap();

    let mut unsettled = seller_store_with_open_channel(&seller, &buyer, &config);
    age_seller_records(&mut unsettled, now - 30 * DAY);
    unsettled.channels.get_mut("channel-1").unwrap().status = PaidRouteLifecycleStatus::Expired;
    unsettled.leases.get_mut("lease-1").unwrap().status = PaidRouteLifecycleStatus::Expired;
    update_paid_route_store(&unsettled_path, |target| {
        *target = unsettled;
        Ok(())
    })
    .unwrap();

    let settled_loaded = load_paid_route_store(&settled_path).unwrap();
    assert!(!settled_loaded.channels.contains_key("channel-1"));
    assert!(
        !settled_loaded
            .sessions
            .contains_key("seller-session-lease-1")
    );
    assert!(!settled_loaded.leases.contains_key("lease-1"));
    assert!(!settled_loaded.quotes.contains_key("seller-quote-lease-1"));

    let unsettled_loaded = load_paid_route_store(&unsettled_path).unwrap();
    assert!(unsettled_loaded.channels.contains_key("channel-1"));
    assert!(
        unsettled_loaded.channels["channel-1"]
            .payment
            .cashu_spilman_payment
            .is_some()
    );
    assert!(
        unsettled_loaded
            .sessions
            .contains_key("seller-session-lease-1")
    );
    assert!(unsettled_loaded.leases.contains_key("lease-1"));
    assert!(unsettled_loaded.quotes.contains_key("seller-quote-lease-1"));
}
