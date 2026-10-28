use super::*;

const DAY: u64 = 24 * 60 * 60;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn aged_terminal_seller_records(store: &mut PaidRouteStore, at_unix: u64) {
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

#[test]
fn aged_closed_channel_is_pruned_with_proofs_and_dependents() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut store = seller_store_with_open_channel(&seller, &buyer, &sample_config());
    let now = now_unix();
    aged_terminal_seller_records(&mut store, now - 8 * DAY);
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

    store.prune_terminal_records(now);

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
fn closing_live_and_fresh_terminal_records_are_kept() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let now = now_unix();

    let mut closing = seller_store_with_open_channel(&seller, &buyer, &config);
    aged_terminal_seller_records(&mut closing, now - 8 * DAY);
    closing.channels.get_mut("channel-1").unwrap().status = PaidRouteLifecycleStatus::Closing;
    let before = closing.clone();
    closing.prune_terminal_records(now);
    assert_eq!(closing, before, "settlement in flight stays");

    let mut fresh = seller_store_with_open_channel(&seller, &buyer, &config);
    aged_terminal_seller_records(&mut fresh, now);
    let before = fresh.clone();
    fresh.prune_terminal_records(now);
    assert_eq!(fresh, before, "records inside the retention window stay");

    let mut live = seller_store_with_open_channel(&seller, &buyer, &config);
    {
        let channel = live.channels.get_mut("channel-1").unwrap();
        channel.created_at_unix = now.saturating_sub(30 * DAY);
        channel.updated_at_unix = now.saturating_sub(30 * DAY);
    }
    let before = live.clone();
    live.prune_terminal_records(now);
    assert_eq!(live, before, "routable channels stay however old they are");
}

#[test]
fn aged_terminal_buyer_records_go_while_live_flows_stay() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, live_session, live_channel) =
        buyer_store_with_session(&seller, &buyer, &sample_config());
    let live_lease = store.sessions[&live_session].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &live_lease, 200)
        .unwrap();
    let now = now_unix();
    let old_at = now - 8 * DAY;

    store.upsert_quote(
        PaidRouteQuote {
            quote_id: "old-quote".to_string(),
            offer_id: "internet-exit".to_string(),
            payment_mode: PaidRoutePaymentMode::CashuSpilman,
            channel_capacity_sat: 10,
            expires_at_unix: old_at,
            receiver_pubkey_hex: seller.public_key().to_bech32().unwrap(),
        },
        old_at,
    );
    store.upsert_lease(
        PaidRouteLease {
            lease_id: "old-lease".to_string(),
            offer_id: "internet-exit".to_string(),
            quote_id: "old-quote".to_string(),
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            starts_at_unix: old_at,
            expires_at_unix: old_at,
        },
        PaidRouteLifecycleStatus::Closed,
        old_at,
    );
    store.upsert_channel(PaidRouteChannelRecord {
        channel_id: "old-channel".to_string(),
        offer_id: "internet-exit".to_string(),
        role: PaidRouteChannelRole::Buyer,
        status: PaidRouteLifecycleStatus::Closed,
        payment: PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: "old-channel".to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: 1_000,
            updated_at_unix: old_at,
            cashu_spilman_payment: Some(sample_spilman_payment("old-channel", 1)),
            cashu_token_lease: None,
        },
        accepted_terms: None,
        mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
        counterparty_npub: seller.public_key().to_bech32().unwrap(),
        created_at_unix: old_at,
        expires_at_unix: old_at,
        updated_at_unix: old_at,
        error: String::new(),
    });
    store.upsert_session(
        PaidRouteSession {
            session_id: "old-session".to_string(),
            lease_id: "old-lease".to_string(),
            usage: PaidRouteUsage::default(),
            payment: PaidRoutePaymentState {
                channel_id: "old-channel".to_string(),
                ..PaidRoutePaymentState::default()
            },
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: None,
        },
        old_at,
    );
    store
        .buyer_session_admissions
        .insert("old-lease".to_string(), old_at);
    store
        .buyer_session_renewals
        .insert("old-session".to_string(), "missing-target".to_string());
    store
        .buyer_session_renewal_starts
        .insert("old-session".to_string(), old_at);
    store
        .buyer_session_open_attempts
        .insert("old-session".to_string(), old_at);
    store
        .seller_session_tunnel_ips
        .insert("old-session".to_string(), "10.44.201.18/32".to_string());
    store.selected_buyer_session_id = "old-session".to_string();

    store.prune_terminal_records(now);

    assert!(!store.channels.contains_key("old-channel"));
    assert!(!store.sessions.contains_key("old-session"));
    assert!(!store.leases.contains_key("old-lease"));
    assert!(!store.quotes.contains_key("old-quote"));
    assert!(!store.buyer_session_admissions.contains_key("old-lease"));
    assert!(!store.buyer_session_renewals.contains_key("old-session"));
    assert!(
        !store
            .buyer_session_renewal_starts
            .contains_key("old-session")
    );
    assert!(
        !store
            .buyer_session_open_attempts
            .contains_key("old-session")
    );
    assert!(!store.seller_session_tunnel_ips.contains_key("old-session"));
    assert_eq!(store.selected_buyer_session_id, "");

    assert!(store.channels.contains_key(&live_channel));
    assert!(store.sessions.contains_key(&live_session));
    assert!(store.buyer_session_admissions.contains_key(&live_lease));
}

#[test]
fn store_reload_prunes_only_records_past_retention() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let now = now_unix();
    let scratch = ScratchDir::new("prune-on-reload");
    let aged_path = scratch.path().join("aged.json");
    let fresh_path = scratch.path().join("fresh.json");

    let mut aged = seller_store_with_open_channel(&seller, &buyer, &config);
    aged_terminal_seller_records(&mut aged, now - 8 * DAY);
    update_paid_route_store(&aged_path, |target| {
        *target = aged;
        Ok(())
    })
    .unwrap();

    let mut fresh = seller_store_with_open_channel(&seller, &buyer, &config);
    aged_terminal_seller_records(&mut fresh, now);
    update_paid_route_store(&fresh_path, |target| {
        *target = fresh;
        Ok(())
    })
    .unwrap();

    let aged_loaded = load_paid_route_store(&aged_path).unwrap();
    assert!(!aged_loaded.channels.contains_key("channel-1"));
    assert!(!aged_loaded.sessions.contains_key("seller-session-lease-1"));
    assert!(!aged_loaded.leases.contains_key("lease-1"));
    assert!(!aged_loaded.quotes.contains_key("seller-quote-lease-1"));

    let fresh_loaded = load_paid_route_store(&fresh_path).unwrap();
    assert!(fresh_loaded.channels.contains_key("channel-1"));
    assert!(
        fresh_loaded.channels["channel-1"]
            .payment
            .cashu_spilman_payment
            .is_some()
    );
    assert!(fresh_loaded.sessions.contains_key("seller-session-lease-1"));
    assert!(fresh_loaded.leases.contains_key("lease-1"));
    assert!(fresh_loaded.quotes.contains_key("seller-quote-lease-1"));
}
