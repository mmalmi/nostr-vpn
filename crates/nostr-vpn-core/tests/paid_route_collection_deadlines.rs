#![cfg(feature = "paid-exit")]

use cashu_service::CashuSpilmanPayment;
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::paid_route_store::{
    OpenPaidRouteBuyerSessionRequest, PaidRouteChannelRole, PaidRouteLifecycleStatus,
    PaidRouteStore,
};
use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

const START: u64 = 1_000_000;
const HOUR: u64 = 3_600;

// Production store operations with synthetic payment material only: no wallet,
// mint requests, settlement or real funds are involved in these tests.
fn channel(lifetime: u64) -> (PaidRouteStore, PaidExitConfig, String, String) {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    config.channel.accepted_mints = vec!["https://mint.example".into()];
    config.channel.channel_expiry_secs = lifetime;
    let signed = signed_paid_exit_offer_from_config("exit", &seller, &config, None, START).unwrap();
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Synthetic", Some(10_000), START);
    store.upsert_signed_offer(signed, vec![], START).unwrap();
    let opened = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "exit".into(),
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            mint_url: Some("https://mint.example".into()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 1_000,
            now_unix: START,
        })
        .unwrap();
    let payment = CashuSpilmanPayment {
        channel_id: opened.channel_id.clone(),
        balance: 1,
        signature: "synthetic".into(),
        params: None,
        funding_proofs: None,
    };
    store
        .channels
        .get_mut(&opened.channel_id)
        .unwrap()
        .payment
        .cashu_spilman_payment = Some(payment.clone());
    store
        .sessions
        .get_mut(&opened.session_id)
        .unwrap()
        .session
        .payment
        .cashu_spilman_payment = Some(payment);
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &opened.lease_id, START + 1)
        .unwrap();
    store
        .seller_session_tunnel_ips
        .insert(opened.session_id.clone(), "10.44.201.17/32".into());
    (store, config, opened.session_id, opened.channel_id)
}

#[test]
fn collection_precedes_refunds_and_survives_reload_and_disabled_sales() {
    for (lifetime, collect_after) in [
        (24 * HOUR, 12 * HOUR),
        (48 * HOUR, 12 * HOUR),
        (HOUR, HOUR / 2),
    ] {
        let (mut store, mut config, session, id) = channel(lifetime);
        store.channels.get_mut(&id).unwrap().role = PaidRouteChannelRole::Seller;
        // Existing serialized channels gain the safety window without rewriting
        // any immutable funding/expiry data or inheriting new offer terms.
        let store: PaidRouteStore =
            serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
        let due = START + collect_after;
        let before = store
            .seller_collection_state_for_session(&config, due - 1, &session)
            .unwrap();
        assert_eq!(before.expires_at_unix, START + lifetime);
        assert_eq!(before.due_at_unix, due);
        assert!(!before.auto_collect_due);
        assert!(store.seller_admissions(&config, due - 1)[0].allow_routing);
        assert!(!store.seller_admissions(&config, due)[0].allow_routing);
        config.enabled = false;
        config.channel.channel_expiry_secs = 7 * 24 * HOUR;
        let ready = store
            .seller_collection_state_for_session(&config, due, &session)
            .unwrap();
        assert!(ready.auto_collect_due);
        assert_eq!(ready.reason, "settlement_due");
        assert_eq!(ready.due_at_unix, due);
        assert_eq!(store.channels[&id].expires_at_unix, START + lifetime);
    }
}

#[test]
fn buyer_renews_and_stops_before_collection_without_shortening_funding_expiry() {
    let (mut store, _, session, id) = channel(24 * HOUR);
    let cutoff = START + 12 * HOUR;
    let lease_id = store.sessions[&session].session.lease_id.clone();
    let buyer = store.leases[&lease_id].lease.buyer_npub.clone();
    let wire_open = store
        .build_buyer_session_open(&session, &buyer, "10.44.201.17/32", cutoff - 1)
        .unwrap();
    assert_eq!(
        wire_open.expires_at_unix,
        START + 24 * HOUR,
        "the on-wire funding deadline must not be halved again by the receiver"
    );
    assert!(
        store
            .build_buyer_session_open(&session, &buyer, "10.44.201.17/32", cutoff)
            .is_err()
    );
    assert!(
        !store
            .buyer_session_needs_renewal(&session, cutoff - 61)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_needs_renewal(&session, cutoff - 60)
            .unwrap()
    );
    assert!(
        !store
            .buyer_session_ready_to_handover(&session, cutoff - 16)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_ready_to_handover(&session, cutoff - 15)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_allows_routing(&session, cutoff - 1)
            .unwrap()
    );
    assert!(
        !store
            .buyer_session_allows_routing(&session, cutoff)
            .unwrap()
    );
    assert!(
        store
            .begin_buyer_session_open_attempt(&session, cutoff)
            .is_err()
    );
    assert!(store.begin_buyer_session_funding(&session, cutoff).is_err());
    assert_eq!(store.channels[&id].expires_at_unix, START + 24 * HOUR);
    store.reconcile_buyer_session_lifecycle(cutoff, 60);
    assert_eq!(
        store.channels[&id].status,
        PaidRouteLifecycleStatus::Expired
    );
}

#[test]
fn earlier_lease_and_closed_channel_remain_authoritative() {
    let (mut store, config, session, id) = channel(24 * HOUR);
    store.channels.get_mut(&id).unwrap().role = PaidRouteChannelRole::Seller;
    let lease = store.sessions[&session].session.lease_id.clone();
    store.leases.get_mut(&lease).unwrap().lease.expires_at_unix = START + HOUR;
    let state = store
        .seller_collection_state_for_session(&config, START + HOUR, &session)
        .unwrap();
    assert!(state.auto_collect_due);
    assert_eq!(state.due_at_unix, START + HOUR);
    store.channels.get_mut(&id).unwrap().status = PaidRouteLifecycleStatus::Closed;
    assert!(
        store
            .seller_collection_states(&config, START + HOUR)
            .is_empty()
    );
}

#[test]
fn deadline_math_is_bounded_and_token_leases_are_unchanged() {
    use nostr_vpn_core::paid_routes::{PaidRoutePaymentMode, paid_route_collection_after_secs};
    assert_eq!(paid_route_collection_after_secs(86_400), 43_200);
    assert_eq!(paid_route_collection_after_secs(u64::MAX), 43_200);
    assert_eq!(paid_route_collection_after_secs(1), 0);
    let (mut store, _, _, id) = channel(24 * HOUR);
    let channel = store.channels.get_mut(&id).unwrap();
    channel.created_at_unix = u64::MAX - 100;
    channel.expires_at_unix = u64::MAX;
    assert_eq!(channel.routing_expires_at_unix(u64::MAX), u64::MAX - 50);
    channel.expires_at_unix = 0;
    assert_eq!(channel.routing_expires_at_unix(u64::MAX), 0);
    channel.payment.mode = PaidRoutePaymentMode::CashuTokenLease;
    channel.created_at_unix = START;
    channel.expires_at_unix = START + 24 * HOUR;
    assert_eq!(channel.routing_expires_at_unix(u64::MAX), START + 24 * HOUR);
}
