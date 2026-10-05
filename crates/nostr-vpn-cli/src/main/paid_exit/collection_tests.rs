use super::*;
use cdk_spilman::configurable_host::{ClosedDataView, SpilmanStorage, SqliteStorage};
use nostr_vpn_core::paid_route_store::{PaidRouteLeaseRecord, PaidRouteSessionRecord};
use nostr_vpn_core::paid_routes::{PaidRouteLease, PaidRoutePaymentState, PaidRouteSession};

const MINT: &str = "http://127.0.0.1:1";

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    app: AppConfig,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("nvpn-seller-collection-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("config.toml");
        let app = AppConfig::generated_without_networks();
        fs::write(&config, app.plaintext_toml().unwrap()).unwrap();
        FileSpilmanPaymentReceiver::load(
            &directory,
            FileSpilmanPaymentReceiverConfig::new([MINT.to_owned()]),
        )
        .unwrap();
        Self {
            directory,
            config,
            app,
        }
    }

    fn add(&self, id: &str, expires: u64, role: PaidRouteChannelRole, closed_receipt: bool) {
        let created = unix_timestamp().min(expires.saturating_sub(1));
        let payment = PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: id.into(),
            paid_msat: 1000,
            cashu_spilman_payment: Some(CashuSpilmanPayment {
                channel_id: id.into(),
                balance: 1,
                signature: "fixture".into(),
                params: None,
                funding_proofs: None,
            }),
            ..Default::default()
        };
        update_paid_route_store(&paid_route_store_file_path(&self.config), |store| {
            store.channels.insert(
                id.into(),
                PaidRouteChannelRecord {
                    channel_id: id.into(),
                    offer_id: "offer".into(),
                    role,
                    status: PaidRouteLifecycleStatus::Active,
                    payment: payment.clone(),
                    accepted_terms: None,
                    mint_url: MINT.into(),
                    counterparty_npub: String::new(),
                    created_at_unix: created,
                    expires_at_unix: expires,
                    updated_at_unix: 1,
                    error: String::new(),
                },
            );
            store.leases.insert(
                id.into(),
                PaidRouteLeaseRecord {
                    lease: PaidRouteLease {
                        lease_id: id.into(),
                        offer_id: "offer".into(),
                        quote_id: String::new(),
                        buyer_npub: Keys::generate().public_key().to_bech32().unwrap(),
                        starts_at_unix: created,
                        expires_at_unix: expires,
                    },
                    status: PaidRouteLifecycleStatus::Active,
                    created_at_unix: created,
                    updated_at_unix: 1,
                },
            );
            store.sessions.insert(
                id.into(),
                PaidRouteSessionRecord {
                    session: PaidRouteSession {
                        session_id: id.into(),
                        lease_id: id.into(),
                        payment,
                        usage: Default::default(),
                        realized_exit_ip: None,
                        observed_country_code: None,
                        observed_asn: None,
                        quality: None,
                    },
                    funding_required_balance_sat: 0,
                    funding_started_unix: 0,
                    last_successful_probe_unix: 0,
                    created_at_unix: created,
                    updated_at_unix: 1,
                },
            );
            Ok(())
        })
        .unwrap();
        if closed_receipt {
            let storage = SqliteStorage::open(
                cashu_service::spilman_receiver_store_path(&self.directory)
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            storage
                .save_funding(
                    id,
                    cdk_spilman::ChannelFunding {
                        params_json: serde_json::json!({"mint":MINT,"unit":"sat"}).to_string(),
                        funding_proofs_json: "[]".into(),
                        channel_secret_hex: "aa".into(),
                        keyset_info_json: "{}".into(),
                    },
                )
                .unwrap();
            storage
                .update_balance(
                    id,
                    cdk_spilman::PaymentProof {
                        balance: 1,
                        signature: "synthetic-signature".into(),
                    },
                )
                .unwrap();
            let proof = serde_json::json!([{
                "id":"009a1f293253e41e", "amount":1, "secret":format!("synthetic-{id}"),
                "C":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            }]);
            storage
                .mark_closed(
                    id,
                    ClosedDataView {
                        expiry_timestamp: expires,
                        closed_amount: 1,
                        value_after_stage1: 1,
                        receiver_sum: 1,
                        sender_sum: 0,
                        receiver_proofs_json: proof.to_string(),
                        sender_proofs_json: "[]".into(),
                    },
                )
                .unwrap();
        }
    }

    fn store(&self) -> PaidRouteStore {
        load_paid_route_store(&paid_route_store_file_path(&self.config)).unwrap()
    }

    async fn wait_closed(&self, collector: &mut PaidExitSellerCollector, id: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let started = Instant::now();
            let changed = collector.poll(&self.app, &self.config, true).unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "collector blocked daemon tick"
            );
            if changed && self.store().channels[id].status == PaidRouteLifecycleStatus::Closed {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "collection did not finish: {}",
                self.store().channels[id].error
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn seller_collection_rejects_incomplete_wallet_receipt() {
    let f = Fixture::new();
    f.add("channel", 2, PaidRouteChannelRole::Seller, true);
    let receiver = FileSpilmanPaymentReceiver::load(
        &f.directory,
        FileSpilmanPaymentReceiverConfig::new([MINT.to_owned()]),
    )
    .unwrap();
    let mut close = receiver
        .close_cashu_spilman_channel("channel")
        .await
        .unwrap();
    close.receiver_proofs_json = "[]".into();
    let result = paid_exit_finish_seller_collection(
        close,
        &f.config,
        &paid_route_store_file_path(&f.config),
        true,
    )
    .await;
    assert!(result.err().unwrap().to_string().contains("does not match"));
    assert_ne!(
        f.store().channels["channel"].status,
        PaidRouteLifecycleStatus::Closed
    );
    assert!(!crate::cashu_wallet_daemon::daemon_cashu_wallet_requests_pending(&f.config));
}

#[tokio::test]
async fn seller_collection_wallet_failure_remains_retryable() {
    let f = Fixture::new();
    f.add("channel", 2, PaidRouteChannelRole::Seller, true);
    let receiver = FileSpilmanPaymentReceiver::load(
        &f.directory,
        FileSpilmanPaymentReceiverConfig::new([MINT.to_owned()]),
    )
    .unwrap();
    let result = paid_exit_collect_channel_with_receiver(
        &receiver,
        &f.config,
        &paid_route_store_file_path(&f.config),
        "channel",
    )
    .await;
    assert!(
        result.is_err(),
        "no wallet daemon is running in this fixture"
    );
    assert_ne!(
        f.store().channels["channel"].status,
        PaidRouteLifecycleStatus::Closed,
        "wallet import failure must not remove the channel from collection retries"
    );

    // Real wallet worker and file-backed wallet; synthetic close receipts only.
    let _wallet =
        crate::cashu_wallet_daemon::DaemonCashuWalletWorker::start(f.config.clone()).unwrap();
    let mut collector = PaidExitSellerCollector::new();
    f.wait_closed(&mut collector, "channel").await;
    assert_eq!(f.store().wallet.mints[0].balance_msat, Some(1000));

    // A crash after import but before the route-store commit must not double credit.
    update_paid_route_store(&paid_route_store_file_path(&f.config), |store| {
        store.channels.get_mut("channel").unwrap().status = PaidRouteLifecycleStatus::Active;
        store.leases.get_mut("channel").unwrap().status = PaidRouteLifecycleStatus::Active;
        Ok(())
    })
    .unwrap();
    let mut restarted = PaidExitSellerCollector::new();
    f.wait_closed(&mut restarted, "channel").await;
    assert_eq!(f.store().wallet.mints[0].balance_msat, Some(1000));
}

#[tokio::test]
async fn seller_collection_failure_does_not_starve_other_channels_or_close_live_ones() {
    let f = Fixture::new();
    f.add(
        "a-missing-receiver-data",
        2,
        PaidRouteChannelRole::Seller,
        false,
    );
    let now = unix_timestamp();
    f.add(
        "b-paid",
        now + 12 * 3600,
        PaidRouteChannelRole::Seller,
        true,
    );
    update_paid_route_store(&paid_route_store_file_path(&f.config), |store| {
        store.channels.get_mut("b-paid").unwrap().created_at_unix = now - 12 * 3600;
        Ok(())
    })
    .unwrap();
    assert!(
        f.store().channels["b-paid"].expires_at_unix > now,
        "automatic collection must run before refund eligibility"
    );
    f.add(
        "c-still-live",
        unix_timestamp() + 3600,
        PaidRouteChannelRole::Seller,
        true,
    );
    f.add("d-buyer", 2, PaidRouteChannelRole::Buyer, true);
    assert!(
        !f.app.paid_exit.enabled,
        "disabled sales must not strand existing seller proceeds"
    );
    let _wallet =
        crate::cashu_wallet_daemon::DaemonCashuWalletWorker::start(f.config.clone()).unwrap();
    let mut collector = PaidExitSellerCollector::new();
    f.wait_closed(&mut collector, "b-paid").await;
    let store = f.store();
    assert!(
        store.channels["a-missing-receiver-data"]
            .error
            .starts_with("Automatic collection failed:")
    );
    assert_eq!(
        store.channels["c-still-live"].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(
        store.channels["d-buyer"].status,
        PaidRouteLifecycleStatus::Active
    );
    assert_eq!(store.wallet.mints[0].balance_msat, Some(1000));
}
