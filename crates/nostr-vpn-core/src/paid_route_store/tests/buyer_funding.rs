use super::*;

#[test]
fn daemon_reconciliation_reuses_a_failed_funded_session_without_a_new_purchase() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, id, channel_id) = buyer_store_with_session(&seller, &buyer, &sample_config());
    let lease_id = store.sessions[&id].session.lease_id.clone();
    let payment = sample_spilman_payment(&channel_id, 1);
    store
        .sessions
        .get_mut(&id)
        .unwrap()
        .session
        .payment
        .cashu_spilman_payment = Some(payment.clone());
    store
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .payment
        .cashu_spilman_payment = Some(payment.clone());
    store.begin_buyer_session_open_attempt(&id, 130).unwrap();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease_id, 140)
        .unwrap();
    store
        .sessions
        .get_mut(&id)
        .unwrap()
        .session
        .realized_exit_ip = Some("203.0.113.1".into());
    store
        .fail_selected_buyer_session("Temporary exit failure", 145)
        .unwrap();
    let quotes = store.quotes.clone();
    let wallet = store.wallet.clone();
    assert_eq!(
        store
            .begin_latest_buyer_session_open_attempt_for_seller(&seller.public_key().to_hex(), 146)
            .unwrap(),
        Some(id.clone())
    );
    assert_eq!(store.selected_buyer_session_id, id);
    assert_eq!(store.sessions.len(), 1);
    assert_eq!(store.quotes, quotes);
    assert_eq!(store.wallet, wallet);
    assert_eq!(
        store.channels[&channel_id].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(
        store.channels[&channel_id].payment.cashu_spilman_payment,
        Some(payment)
    );
    assert!(
        store.sessions[&id].session.realized_exit_ip.is_none(),
        "recovery requires fresh egress evidence"
    );
    assert!(
        store
            .buyer_payment_signing_plan(&BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: id,
                buyer_npub: buyer.public_key().to_bech32().unwrap(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
                delivered_units: None,
                paid_msat: None,
                now_unix: 146,
            })
            .is_ok(),
        "restore the funded session before replaying its channel open"
    );
}

#[test]
fn funded_retry_never_revives_settled_expired_or_exhausted_credit() {
    for (channel_status, lease_status, bytes, now) in [
        (
            PaidRouteLifecycleStatus::Closed,
            PaidRouteLifecycleStatus::Failed,
            0,
            146,
        ),
        (
            PaidRouteLifecycleStatus::Failed,
            PaidRouteLifecycleStatus::Closing,
            0,
            146,
        ),
        (
            PaidRouteLifecycleStatus::Failed,
            PaidRouteLifecycleStatus::Failed,
            1_000_000_000,
            146,
        ),
        (
            PaidRouteLifecycleStatus::Failed,
            PaidRouteLifecycleStatus::Failed,
            0,
            421,
        ),
    ] {
        let seller = Keys::generate();
        let buyer = Keys::generate();
        let (mut store, id, channel_id) =
            buyer_store_with_session(&seller, &buyer, &sample_config());
        let lease_id = store.sessions[&id].session.lease_id.clone();
        let payment = sample_spilman_payment(&channel_id, 1);
        store
            .sessions
            .get_mut(&id)
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
            .sessions
            .get_mut(&id)
            .unwrap()
            .session
            .usage
            .billable_bytes = bytes;
        store.channels.get_mut(&channel_id).unwrap().status = channel_status;
        store.leases.get_mut(&lease_id).unwrap().status = lease_status;
        let before = store.clone();
        assert!(store.retry_failed_funded_buyer_session(&id, now).is_err());
        assert_eq!(store, before);
    }
}

#[test]
fn funding_wait_survives_restart_without_trial_routes_or_seller_timeout() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let config = sample_config();
    let (mut store, session_id, channel_id) = buyer_store_with_session(&seller, &buyer, &config);
    store
        .begin_buyer_session_open_attempt(&session_id, 121)
        .unwrap();
    let lease = store.sessions[&session_id].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease, 122)
        .unwrap();
    assert!(
        store
            .buyer_has_seller_admission(&seller.public_key().to_hex(), 122)
            .unwrap()
    );
    assert!(store.begin_buyer_session_funding(&session_id, 123).unwrap());
    store.channels.get_mut(&channel_id).unwrap().error =
        "Payment setup failed: mint unavailable".to_string();
    let mut store: PaidRouteStore =
        serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
    assert!(!store.begin_buyer_session_funding(&session_id, 160).unwrap());
    store
        .begin_buyer_session_open_attempt(&session_id, 160)
        .unwrap();
    assert!(
        !store
            .reconcile_buyer_session_lifecycle(200, 30)
            .selected_session_timed_out
    );
    assert!(
        !store
            .buyer_session_allows_routing(&session_id, 200)
            .unwrap()
    );
    assert!(
        !store
            .buyer_has_seller_admission(&seller.public_key().to_hex(), 200)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_open_for_seller(
                &seller.public_key().to_hex(),
                &buyer.public_key().to_bech32().unwrap(),
                "10.44.201.17/32",
                200
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(store.sessions.len(), 1);
    let funded = "funded-after-mint-recovery";
    store
        .attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.clone(),
            channel_id: funded.to_string(),
            cashu_unit: "sat".to_string(),
            capacity_sat: 10,
            paid_msat: Some(1_000),
            payment: sample_spilman_payment(funded, 1),
            now_unix: 201,
        })
        .unwrap();
    assert_eq!(store.sessions[&session_id].funding_started_unix, 0);
    assert!(store.channels[funded].error.is_empty());
    assert!(
        !store
            .buyer_has_seller_admission(&seller.public_key().to_hex(), 202)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_open_for_seller(
                &seller.public_key().to_hex(),
                &buyer.public_key().to_bech32().unwrap(),
                "10.44.201.17/32",
                202
            )
            .unwrap()
            .is_some()
    );
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &lease, 203)
        .unwrap();
    assert!(
        store
            .buyer_has_seller_admission(&seller.public_key().to_hex(), 204)
            .unwrap()
    );
    assert!(
        store
            .buyer_session_allows_routing(&session_id, 204)
            .unwrap()
    );
}

#[test]
fn old_admission_cannot_route_while_selected_session_waits_for_funding() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (mut store, old, _) = buyer_store_with_session(&seller, &buyer, &sample_config());
    let pubkey = seller.public_key().to_hex();
    let lease = store.sessions[&old].session.lease_id.clone();
    store
        .acknowledge_buyer_session_open(&pubkey, &lease, 121)
        .unwrap();
    let next = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: 122,
        })
        .unwrap();
    store
        .begin_buyer_session_open_attempt(&next.session_id, 123)
        .unwrap();
    assert!(store.buyer_has_seller_admission(&pubkey, 124).unwrap());
    store
        .begin_buyer_session_funding(&next.session_id, 125)
        .unwrap();
    assert!(!store.buyer_has_seller_admission(&pubkey, 126).unwrap());
    assert!(store.buyer_session_is_seller_admitted(&old).unwrap());
}
