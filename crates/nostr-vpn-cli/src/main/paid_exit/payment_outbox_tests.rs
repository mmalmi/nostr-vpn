use super::*;
use cashu_service::{CashuSpilmanPayment, StreamingRouteBalanceUpdate};

struct Outbox {
    app: AppConfig,
    config: PathBuf,
    seller: String,
    seller_app: AppConfig,
}

impl Outbox {
    fn new() -> Self {
        let mut app = AppConfig::generated();
        let seller_app = AppConfig::generated_without_networks();
        let seller = seller_app.nostr_keys().unwrap().public_key().to_hex();
        app.select_public_paid_exit_node(&seller).unwrap();
        let directory = std::env::temp_dir().join(format!("nvpn-outbox-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        Self {
            app,
            config: directory.join("config.toml"),
            seller,
            seller_app,
        }
    }

    fn payment(&self, channel: &str, balance: u64) -> StreamingRoutePaymentEnvelope {
        StreamingRoutePaymentEnvelope::new(
            "internet-exit",
            format!("lease-{channel}"),
            self.app.nostr_keys().unwrap().public_key().to_hex(),
            self.seller.clone(),
            100 + balance,
            StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                delivered_units: balance * 100,
                amount_due_msat: balance * 1000,
                paid_msat: balance * 1000,
                payment: CashuSpilmanPayment {
                    channel_id: channel.into(),
                    balance,
                    signature: "ab".repeat(64),
                    params: None,
                    funding_proofs: None,
                },
            }),
        )
    }

    fn queue(&self, envelope: &StreamingRoutePaymentEnvelope) {
        queue_paid_exit_payment(&self.app, &self.config, envelope).unwrap();
    }
}

impl Drop for Outbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.config.parent().unwrap());
    }
}

#[test]
fn payment_outbox_recovery_reads_past_sixteen_stale_channels() {
    let outbox = Outbox::new();
    for n in 0..32 {
        outbox.queue(&outbox.payment(&format!("channel-{n}"), n));
    }
    let pending = load_paid_exit_payment_outbox(&outbox.config);
    assert_eq!(
        pending.len(),
        32,
        "every channel remains eligible for delivery"
    );
    assert_eq!(
        pending[0].envelope.channel_id(),
        "channel-31",
        "fresh payments go first"
    );
}

#[test]
fn payment_outbox_recovery_coalesces_only_superseded_balances() {
    let outbox = Outbox::new();
    for balance in 0..32 {
        outbox.queue(&outbox.payment("channel", balance));
    }
    let newest = outbox.payment("channel", 31);
    let mut stale = outbox.payment("channel", 3);
    stale.sent_at_unix = 999; // Retry arrival order cannot regress the signed balance.
    outbox.queue(&stale);
    outbox.queue(&outbox.payment("another-channel", 1));

    let pending = load_paid_exit_payment_outbox(&outbox.config);
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(|entry| entry.envelope == newest));
    assert_eq!(
        fs::read_dir(paid_exit_payment_outbox_directory(&outbox.config))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        load_paid_exit_payment_outbox(&outbox.config).len(),
        2,
        "survives restart"
    );

    let id = nostr_vpn_core::paid_route_store::paid_route_payment_id(&newest).unwrap();
    let stranger = nostr_sdk::Keys::generate().public_key().to_hex();
    assert!(acknowledge_paid_exit_payment(&outbox.config, &stranger, &id).is_err());
    assert!(acknowledge_paid_exit_payment(&outbox.config, &outbox.seller, &id).unwrap());
    assert_eq!(load_paid_exit_payment_outbox(&outbox.config).len(), 1);
}

fn backdate_paid_exit_outbox_entry(config: &Path, envelope: &StreamingRoutePaymentEnvelope) {
    let id = nostr_vpn_core::paid_route_store::paid_route_payment_id(envelope).unwrap();
    let path = paid_exit_payment_outbox_directory(config).join(format!("{id}.json"));
    let file = OpenOptions::new().write(true).open(path).unwrap();
    let stale = SystemTime::now() - Duration::from_secs(PAYMENT_OUTBOX_RETENTION_SECS + 3_600);
    file.set_times(std::fs::FileTimes::new().set_modified(stale)).unwrap();
}

#[test]
fn payment_outbox_recovery_expires_dead_seller_backlog() {
    let outbox = Outbox::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let fresh = outbox.payment("fresh", 2);
    outbox.queue(&fresh);
    let StreamingRoutePaymentPayload::BalanceUpdate(fresh_update) = &fresh.payload else {
        unreachable!()
    };

    // Once the refund lifetime is unreachable, an unresponsive seller stops
    // accumulating balance updates and closes across restarts.
    let expired = outbox.payment("expired", 3);
    outbox.queue(&expired);
    backdate_paid_exit_outbox_entry(&outbox.config, &expired);
    let StreamingRoutePaymentPayload::BalanceUpdate(expired_update) = &expired.payload else {
        unreachable!()
    };
    let mut expired_close = expired.clone();
    expired_close.payload = StreamingRoutePaymentPayload::CooperativeClose(
        cashu_service::StreamingRouteCooperativeClose {
            final_paid_msat: expired_update.paid_msat,
            payment: expired_update.payment.clone(),
        },
    );
    outbox.queue(&expired_close);
    backdate_paid_exit_outbox_entry(&outbox.config, &expired_close);

    // Repeated close attempts for a live binding collapse to the newest retry.
    let mut close_old = fresh.clone();
    close_old.sent_at_unix = now - 60;
    close_old.payload = StreamingRoutePaymentPayload::CooperativeClose(
        cashu_service::StreamingRouteCooperativeClose {
            final_paid_msat: fresh_update.paid_msat,
            payment: fresh_update.payment.clone(),
        },
    );
    let mut close_new = close_old.clone();
    close_new.sent_at_unix = now;
    outbox.queue(&close_old);
    outbox.queue(&close_new);

    let pending = load_paid_exit_payment_outbox(&outbox.config);
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(|entry| entry.envelope == fresh));
    assert!(pending.iter().any(|entry| entry.envelope == close_new));
    assert_eq!(
        fs::read_dir(paid_exit_payment_outbox_directory(&outbox.config))
            .unwrap()
            .count(),
        2,
        "expired and superseded files leave the outbox"
    );
    assert_eq!(
        load_paid_exit_payment_outbox(&outbox.config).len(),
        2,
        "survives restart"
    );
}

#[test]
fn payment_outbox_recovery_preserves_funding_close_and_other_bindings() {
    let outbox = Outbox::new();
    let balance = outbox.payment("channel", 5);
    outbox.queue(&balance);
    let StreamingRoutePaymentPayload::BalanceUpdate(update) = &balance.payload else {
        unreachable!()
    };
    let mut open = balance.clone();
    open.sent_at_unix = 90;
    open.payload =
        StreamingRoutePaymentPayload::ChannelOpen(cashu_service::StreamingRouteChannelOpen {
            mint_url: "https://mint.example".into(),
            unit: "sat".into(),
            capacity: 10,
            expires_unix: 500,
            receiver_pubkey_hex: outbox.seller.clone(),
            paid_msat: 0,
            payment: CashuSpilmanPayment {
                balance: 0,
                ..update.payment.clone()
            },
        });
    outbox.queue(&open);
    let mut close = balance.clone();
    close.sent_at_unix = 110;
    close.payload = StreamingRoutePaymentPayload::CooperativeClose(
        cashu_service::StreamingRouteCooperativeClose {
            final_paid_msat: update.paid_msat,
            payment: update.payment.clone(),
        },
    );
    outbox.queue(&close);
    let mut other_lease = outbox.payment("channel", 1);
    other_lease.lease_id = "another-lease".into();
    outbox.queue(&other_lease);
    let pending = load_paid_exit_payment_outbox(&outbox.config);
    assert_eq!(pending.len(), 4);
    for envelope in [balance, open, close, other_lease] {
        assert!(pending.iter().any(|entry| entry.envelope == envelope));
    }
}

#[test]
fn payment_outbox_recovery_acks_old_payment_through_persisted_seller_path() {
    let mut outbox = Outbox::new();
    let seller_dir = outbox.config.parent().unwrap().join("seller");
    fs::create_dir(&seller_dir).unwrap();
    let seller_config = seller_dir.join("config.toml");
    let mint = "http://127.0.0.1:1";
    outbox.seller_app.paid_exit.enabled = true;
    outbox.seller_app.paid_exit.channel.accepted_mints = vec![mint.into()];
    let receiver = FileSpilmanPaymentReceiver::load(
        &seller_dir,
        FileSpilmanPaymentReceiverConfig::new([mint.to_owned()]),
    )
    .unwrap();
    let receiver_key = receiver.receiver_pubkey_hex().to_owned();
    let mut old = outbox.payment("channel", 0);
    let StreamingRoutePaymentPayload::BalanceUpdate(update) = &old.payload else {
        unreachable!()
    };
    let opening_payment = CashuSpilmanPayment {
        params: Some(serde_json::json!({ "mint": mint, "capacity": 10,
            "expiry_timestamp": 500, "receiver_pubkey": receiver_key, "unit": "sat" })),
        funding_proofs: Some(serde_json::json!({"proofs": []})),
        ..update.payment.clone()
    };
    old.payload =
        StreamingRoutePaymentPayload::ChannelOpen(cashu_service::StreamingRouteChannelOpen {
            mint_url: mint.into(),
            unit: "sat".into(),
            capacity: 10,
            expires_unix: 500,
            receiver_pubkey_hex: receiver_key,
            paid_msat: 0,
            payment: opening_payment,
        });
    let store_path = paid_route_store_file_path(&seller_config);
    // Persist a previously validated payment. The replay must never contact
    // the deliberately unreachable mint or replace this stronger claim.
    update_paid_route_store(&store_path, |store| {
        for envelope in [old.clone(), outbox.payment("channel", 1)] {
            store.apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
                envelope,
                seller_npub: outbox.seller.clone(),
                config: outbox.seller_app.paid_exit.clone(),
                now_unix: 100,
            })?;
        }
        store.channels.get_mut("channel").unwrap().status = PaidRouteLifecycleStatus::Closed;
        store.leases.get_mut("lease-channel").unwrap().status = PaidRouteLifecycleStatus::Closed;
        Ok(())
    })
    .unwrap();
    let before = fs::read(&store_path).unwrap();
    let buyer = outbox.app.nostr_keys().unwrap().public_key().to_hex();
    let mut pending = Vec::new();
    for envelope in [old, outbox.payment("channel", 0)] {
        outbox.queue(&envelope);
        let id = nostr_vpn_core::paid_route_store::paid_route_payment_id(&envelope).unwrap();
        pending.push((buyer.clone(), id, envelope));
    }
    let mut forged = pending[0].clone();
    forged.0 = nostr_sdk::Keys::generate().public_key().to_hex();
    pending.push(forged);
    let result = paid_exit_apply_fips_payments(
        &outbox.seller_app,
        &seller_config,
        pending,
        Some(&receiver),
        None,
    )
    .unwrap();
    assert_eq!(result.applied_count, 2);
    assert_eq!(result.error_count, 1);
    assert!(!result.changed);
    assert_eq!(fs::read(&store_path).unwrap(), before);
    for (recipient, id) in result.acknowledgments {
        assert_eq!(recipient, buyer);
        assert!(acknowledge_paid_exit_payment(&outbox.config, &outbox.seller, &id).unwrap());
    }
    assert!(load_paid_exit_payment_outbox(&outbox.config).is_empty());
}
