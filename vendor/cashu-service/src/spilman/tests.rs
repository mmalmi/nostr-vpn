use super::{
    create_streaming_route_cashu_payment, create_streaming_route_cashu_token_lease,
    process_streaming_route_cashu_payment_with_receiver,
    validate_streaming_route_cashu_payment_claim,
    validate_streaming_route_cashu_payment_with_receiver, CashuSpilmanPayment,
    CashuSpilmanPaymentReceiver, CashuSpilmanPaymentReceiverValidation, CashuSpilmanPaymentSigner,
    StreamingRouteAccessState, StreamingRouteBalanceUpdate, StreamingRouteCashuPaymentKind,
    StreamingRouteCashuPaymentRequest, StreamingRouteCashuTokenLeaseRequest,
    StreamingRouteChannelOpen, StreamingRouteCooperativeCloseAck, StreamingRouteMeter,
    StreamingRoutePaymentEnvelope, StreamingRoutePaymentPayload, StreamingRoutePolicy,
    CASHU_SPILMAN_CHANNELS_REV, STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION,
};

#[test]
fn route_policy_charges_only_after_free_probe() {
    let policy = StreamingRoutePolicy {
        meter: StreamingRouteMeter::Bytes,
        price_msat: 25,
        per_units: 10,
        max_channel_capacity_sat: 100,
        channel_expiry_secs: 600,
        free_probe_units: 100,
        grace_units: 20,
    };

    assert_eq!(policy.amount_due_msat(100), 0);
    assert_eq!(policy.amount_due_msat(101), 3);
    assert_eq!(policy.amount_due_msat(130), 75);
    assert!(policy.is_balance_sufficient(119, 0));
    assert!(policy.is_balance_sufficient(130, 25));
    assert!(!policy.is_balance_sufficient(130, 24));
}

#[test]
fn route_policy_reports_free_paid_grace_and_suspended_states() {
    let policy = StreamingRoutePolicy {
        meter: StreamingRouteMeter::Bytes,
        price_msat: 25,
        per_units: 10,
        max_channel_capacity_sat: 100,
        channel_expiry_secs: 600,
        free_probe_units: 100,
        grace_units: 20,
    };

    let free = policy.routing_decision(100, 0);
    assert_eq!(free.state, StreamingRouteAccessState::FreeProbe);
    assert!(free.allow_routing);
    assert_eq!(free.amount_due_msat, 0);

    let paid = policy.routing_decision(130, 75);
    assert_eq!(paid.state, StreamingRouteAccessState::Paid);
    assert!(paid.allow_routing);
    assert_eq!(paid.unpaid_msat, 0);

    let grace = policy.routing_decision(130, 25);
    assert_eq!(grace.state, StreamingRouteAccessState::Grace);
    assert!(grace.allow_routing);
    assert_eq!(grace.amount_due_msat, 75);
    assert_eq!(grace.enforced_amount_due_msat, 25);
    assert_eq!(grace.unpaid_msat, 50);

    let suspended = policy.routing_decision(130, 24);
    assert_eq!(suspended.state, StreamingRouteAccessState::Suspended);
    assert!(!suspended.allow_routing);
    assert_eq!(suspended.unpaid_msat, 51);
}

#[test]
fn route_payment_envelope_round_trips_channel_open() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-1".to_string(),
        balance: 5,
        signature: "sig-5".to_string(),
        params: Some(serde_json::json!({"receiver":"receiver-pubkey"})),
        funding_proofs: Some(serde_json::json!([{"amount":8,"secret":"proof"}])),
    };
    assert!(payment.has_funding());

    let envelope = StreamingRoutePaymentEnvelope::new(
        "internet-exit",
        "lease-1",
        "npub1buyer",
        "npub1seller",
        123,
        StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
            mint_url: "https://mint.example".to_string(),
            unit: "sat".to_string(),
            capacity: 100,
            expires_unix: 723,
            receiver_pubkey_hex: "receiver-pubkey".to_string(),
            paid_msat: 5_000,
            payment,
        }),
    );

    let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
    assert!(encoded.contains(r#""type":"channel_open""#));
    assert!(encoded.contains(r#""version":1"#));

    let decoded: StreamingRoutePaymentEnvelope =
        serde_json::from_str(&encoded).expect("decode envelope");
    assert_eq!(decoded.version, STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION);
    assert_eq!(decoded.channel_id(), "channel-1");
    match decoded.payload {
        StreamingRoutePaymentPayload::ChannelOpen(open) => {
            assert_eq!(open.mint_url, "https://mint.example");
            assert_eq!(open.unit, "sat");
            assert_eq!(open.paid_msat, 5_000);
            assert!(open.payment.has_funding());
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn route_payment_payloads_expose_channel_id() {
    let update = StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
        delivered_units: 130,
        amount_due_msat: 75,
        paid_msat: 100,
        payment: CashuSpilmanPayment {
            channel_id: "channel-2".to_string(),
            balance: 1,
            signature: "sig-1".to_string(),
            params: None,
            funding_proofs: None,
        },
    });
    let ack =
        StreamingRoutePaymentPayload::CooperativeCloseAck(StreamingRouteCooperativeCloseAck {
            channel_id: "channel-3".to_string(),
            accepted_balance: 2,
            accepted_paid_msat: 2_000,
            closed_at_unix: 456,
            receipt: Some(serde_json::json!({"ok":true})),
        });
    let token = StreamingRoutePaymentPayload::CashuTokenLease(
        create_streaming_route_cashu_token_lease(StreamingRouteCashuTokenLeaseRequest {
            channel_id: "token-lease-4".to_string(),
            mint_url: "https://mint.example".to_string(),
            unit: "sat".to_string(),
            amount: 2,
            paid_msat: Some(1_500),
            expires_unix: 789,
            token: "cashuAdevtoken".to_string(),
        })
        .expect("token lease"),
    );

    assert_eq!(update.channel_id(), "channel-2");
    assert_eq!(ack.channel_id(), "channel-3");
    assert_eq!(token.channel_id(), "token-lease-4");
}

#[test]
fn route_token_lease_payment_round_trips_and_caps_credit() {
    let token_lease =
        create_streaming_route_cashu_token_lease(StreamingRouteCashuTokenLeaseRequest {
            channel_id: "token-lease-1".to_string(),
            mint_url: "https://mint.example".to_string(),
            unit: "sat".to_string(),
            amount: 2,
            paid_msat: Some(1_500),
            expires_unix: 999,
            token: "cashuBtoken".to_string(),
        })
        .expect("create token lease");
    assert_eq!(token_lease.paid_msat, 1_500);

    let envelope = StreamingRoutePaymentEnvelope::new(
        "internet-exit",
        "lease-1",
        "npub1buyer",
        "npub1seller",
        123,
        StreamingRoutePaymentPayload::CashuTokenLease(token_lease),
    );

    let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
    assert!(encoded.contains(r#""type":"cashu_token_lease""#));
    let decoded: StreamingRoutePaymentEnvelope =
        serde_json::from_str(&encoded).expect("decode envelope");
    assert_eq!(decoded.channel_id(), "token-lease-1");
    match decoded.payload {
        StreamingRoutePaymentPayload::CashuTokenLease(lease) => {
            assert_eq!(lease.unit, "sat");
            assert_eq!(lease.amount, 2);
            assert_eq!(lease.paid_msat, 1_500);
            assert_eq!(lease.token, "cashuBtoken");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    let too_much = create_streaming_route_cashu_token_lease(StreamingRouteCashuTokenLeaseRequest {
        channel_id: "token-lease-2".to_string(),
        mint_url: "https://mint.example".to_string(),
        unit: "sat".to_string(),
        amount: 2,
        paid_msat: Some(2_001),
        expires_unix: 999,
        token: "cashuBtoken".to_string(),
    })
    .expect_err("over-credit should fail");
    assert!(too_much.contains("exceeds token amount"));
}

#[cfg(feature = "spilman")]
#[test]
fn cashu_spilman_payment_converts_upstream_payment() {
    let upstream = super::upstream::Payment::new("channel-1".to_string(), 7, "sig-7".to_string());

    let payment = CashuSpilmanPayment::from(upstream);
    assert_eq!(payment.channel_id, "channel-1");
    assert_eq!(payment.balance, 7);
    assert!(!payment.has_funding());

    let restored = super::upstream::Payment::try_from(payment).expect("restore payment");
    assert_eq!(restored.channel_id, "channel-1");
    assert_eq!(restored.balance, 7);
    assert_eq!(restored.signature, "sig-7");
    assert!(restored.params.is_none());
    assert!(restored.funding_proofs.is_none());
}

#[test]
fn route_cashu_unit_conversions_round_up_sat_balances() {
    assert_eq!(
        super::streaming_route_cashu_balance_for_msat("sat", 1).unwrap(),
        1
    );
    assert_eq!(
        super::streaming_route_cashu_balance_for_msat("sat", 1_001).unwrap(),
        2
    );
    assert_eq!(
        super::streaming_route_cashu_balance_msat("sat", 2).unwrap(),
        2_000
    );
    assert_eq!(
        super::streaming_route_cashu_balance_for_msat("msat", 1_001).unwrap(),
        1_001
    );
    assert_eq!(
        super::streaming_route_cashu_capacity_for_sat("msat", 2).unwrap(),
        2_000
    );
    assert_eq!(
        super::streaming_route_cashu_capacity_sat("msat", 2_001).unwrap(),
        3
    );
}

#[test]
fn route_cashu_payment_builder_signs_open_with_funding() {
    let signer = FakeSigner;
    let result = create_streaming_route_cashu_payment(
        &signer,
        StreamingRouteCashuPaymentRequest {
            kind: StreamingRouteCashuPaymentKind::ChannelOpen,
            channel_id: "channel-1".to_string(),
            unit: "sat".to_string(),
            paid_msat: 1,
            previous_paid_msat: 0,
            capacity_sat: 10,
        },
    )
    .expect("create payment");

    assert_eq!(result.balance, 1);
    assert_eq!(result.paid_msat, 1_000);
    assert!(result.include_funding);
    assert!(result.payment.has_funding());
    assert_eq!(result.payment.signature, "sig-channel-1-1-funding");
}

#[test]
fn route_cashu_payment_builder_signs_updates_without_funding() {
    let signer = FakeSigner;
    let result = create_streaming_route_cashu_payment(
        &signer,
        StreamingRouteCashuPaymentRequest {
            kind: StreamingRouteCashuPaymentKind::BalanceUpdate,
            channel_id: "channel-1".to_string(),
            unit: "msat".to_string(),
            paid_msat: 1_500,
            previous_paid_msat: 1_000,
            capacity_sat: 2,
        },
    )
    .expect("create payment");

    assert_eq!(result.balance, 1_500);
    assert_eq!(result.paid_msat, 1_500);
    assert!(!result.include_funding);
    assert!(!result.payment.has_funding());
    assert_eq!(result.payment.signature, "sig-channel-1-1500-update");
}

#[test]
fn route_cashu_payment_builder_rejects_regressions_and_over_capacity() {
    let signer = FakeSigner;
    let regression = create_streaming_route_cashu_payment(
        &signer,
        StreamingRouteCashuPaymentRequest {
            kind: StreamingRouteCashuPaymentKind::BalanceUpdate,
            channel_id: "channel-1".to_string(),
            unit: "sat".to_string(),
            paid_msat: 999,
            previous_paid_msat: 1_000,
            capacity_sat: 2,
        },
    )
    .expect_err("regression should fail");
    assert!(regression.contains("regressed"));

    let over_capacity = create_streaming_route_cashu_payment(
        &signer,
        StreamingRouteCashuPaymentRequest {
            kind: StreamingRouteCashuPaymentKind::BalanceUpdate,
            channel_id: "channel-1".to_string(),
            unit: "sat".to_string(),
            paid_msat: 2_001,
            previous_paid_msat: 0,
            capacity_sat: 2,
        },
    )
    .expect_err("over capacity should fail");
    assert!(over_capacity.contains("exceeds channel capacity"));
}

#[test]
fn route_cashu_payment_progress_validation_rejects_replay_and_capacity() {
    let ok = super::validate_streaming_route_cashu_payment_progress(
        "paid route balance update",
        2_000,
        1_000,
        2,
    )
    .expect("progress is valid");
    assert_eq!(ok.previous_paid_msat, 1_000);
    assert_eq!(ok.paid_msat, 2_000);
    assert_eq!(ok.capacity_msat, 2_000);

    let replay = super::validate_streaming_route_cashu_payment_progress(
        "paid route balance update",
        999,
        1_000,
        2,
    )
    .expect_err("replay/regression should fail");
    assert!(replay.contains("paid route balance update amount regressed"));

    let over_capacity = super::validate_streaming_route_cashu_payment_progress(
        "paid route balance update",
        2_001,
        1_000,
        2,
    )
    .expect_err("over capacity should fail");
    assert!(over_capacity.contains("exceeds channel capacity"));
}

#[test]
fn route_cashu_payment_claim_validation_matches_signed_balance() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-1".to_string(),
        balance: 2,
        signature: "sig-2".to_string(),
        params: Some(serde_json::json!({"ok": true})),
        funding_proofs: Some(serde_json::json!([])),
    };
    let validated =
        validate_streaming_route_cashu_payment_claim(&payment, "channel-1", "sat", 2_000, 2, true)
            .expect("valid claim");

    assert_eq!(validated.channel_id, "channel-1");
    assert_eq!(validated.unit, "sat");
    assert_eq!(validated.balance, 2);
    assert_eq!(validated.paid_msat, 2_000);
    assert_eq!(validated.capacity_msat, 2_000);
    assert!(validated.has_funding);
}

#[test]
fn route_cashu_payment_claim_validation_rejects_mismatches() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-1".to_string(),
        balance: 1,
        signature: "sig-1".to_string(),
        params: None,
        funding_proofs: None,
    };

    let claimed_too_much =
        validate_streaming_route_cashu_payment_claim(&payment, "channel-1", "sat", 2_000, 2, false)
            .expect_err("over-claimed payment should fail");
    assert!(claimed_too_much.contains("does not match"));

    let missing_funding =
        validate_streaming_route_cashu_payment_claim(&payment, "channel-1", "sat", 1_000, 2, true)
            .expect_err("opening without funding should fail");
    assert!(missing_funding.contains("missing funding"));
}

#[test]
fn route_cashu_payment_receiver_validation_combines_claim_and_receiver_result() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-1".to_string(),
        balance: 2,
        signature: "sig-2".to_string(),
        params: Some(serde_json::json!({"ok": true})),
        funding_proofs: Some(serde_json::json!([])),
    };
    let receiver = FakeReceiver {
        channel_id: "channel-1".to_string(),
        balance: 2,
        amount_due: 1,
        capacity: 10,
    };
    let context = "route-usage".to_string();

    let validated = validate_streaming_route_cashu_payment_with_receiver(
        &receiver,
        &payment,
        "channel-1",
        "sat",
        2_000,
        10,
        true,
        &context,
    )
    .expect("validate with receiver");

    assert_eq!(validated.claim.paid_msat, 2_000);
    assert_eq!(validated.receiver.channel_id, "channel-1");
    assert_eq!(validated.receiver.balance, 2);
    assert_eq!(validated.receiver.amount_due, 1);
    assert_eq!(validated.receiver.capacity, 10);
}

#[test]
fn route_cashu_payment_receiver_processing_combines_claim_and_receiver_result() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-2".to_string(),
        balance: 2_500,
        signature: "sig-2500".to_string(),
        params: None,
        funding_proofs: None,
    };
    let receiver = FakeReceiver {
        channel_id: "channel-2".to_string(),
        balance: 2_500,
        amount_due: 2_000,
        capacity: 10_000,
    };
    let context = "route-usage".to_string();

    let processed = process_streaming_route_cashu_payment_with_receiver(
        &receiver,
        &payment,
        "channel-2",
        "msat",
        2_500,
        10,
        false,
        &context,
    )
    .expect("process with receiver");

    assert_eq!(processed.claim.unit, "msat");
    assert_eq!(processed.claim.paid_msat, 2_500);
    assert_eq!(processed.receiver.amount_due, 2_000);
}

#[test]
fn route_cashu_payment_receiver_validation_rejects_receiver_mismatch() {
    let payment = CashuSpilmanPayment {
        channel_id: "channel-1".to_string(),
        balance: 2,
        signature: "sig-2".to_string(),
        params: Some(serde_json::json!({"ok": true})),
        funding_proofs: Some(serde_json::json!([])),
    };
    let receiver = FakeReceiver {
        channel_id: "channel-1".to_string(),
        balance: 1,
        amount_due: 1,
        capacity: 10,
    };
    let context = "route-usage".to_string();

    let error = validate_streaming_route_cashu_payment_with_receiver(
        &receiver,
        &payment,
        "channel-1",
        "sat",
        2_000,
        10,
        true,
        &context,
    )
    .expect_err("receiver mismatch should fail");

    assert!(error.contains("receiver validated balance"));
}

#[test]
fn spilman_upstream_base_is_recorded() {
    assert_eq!(
        CASHU_SPILMAN_CHANNELS_REV,
        "d3032af0096a8db9770dbfc59db63e8a45dfde23"
    );
}

struct FakeSigner;

impl CashuSpilmanPaymentSigner for FakeSigner {
    fn sign_cashu_spilman_payment(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        Ok(CashuSpilmanPayment {
            channel_id: channel_id.to_string(),
            balance,
            signature: format!(
                "sig-{channel_id}-{balance}-{}",
                if include_funding { "funding" } else { "update" }
            ),
            params: include_funding.then(|| serde_json::json!({"ok": true})),
            funding_proofs: include_funding.then(|| serde_json::json!([])),
        })
    }
}

struct FakeReceiver {
    channel_id: String,
    balance: u64,
    amount_due: u64,
    capacity: u64,
}

impl CashuSpilmanPaymentReceiver<String> for FakeReceiver {
    fn validate_cashu_spilman_payment(
        &self,
        _payment: &CashuSpilmanPayment,
        _context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        Ok(CashuSpilmanPaymentReceiverValidation {
            channel_id: self.channel_id.clone(),
            balance: self.balance,
            amount_due: self.amount_due,
            capacity: self.capacity,
        })
    }

    fn process_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.validate_cashu_spilman_payment(payment, context)
    }
}
