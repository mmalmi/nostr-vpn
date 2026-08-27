    use super::*;

    use cashu::nuts::{CurrencyUnit, Id, Keys, Proof, SecretKey};
    use cashu::{Amount, secret::Secret};
    use cashu_service::{
        FileSpilmanClientStorage, load_or_create_cashu_spilman_sender_key,
        spilman_client_store_path,
    };
    use cdk_spilman::{ChannelParameters, ClientChannelFunding, ClientStorage, KeysetInfo};
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "nvpn-paid-exit-refund-worker-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create refund worker test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn channel(
        channel_id: &str,
        role: PaidRouteChannelRole,
        status: PaidRouteLifecycleStatus,
    ) -> PaidRouteChannelRecord {
        PaidRouteChannelRecord {
            channel_id: channel_id.to_string(),
            offer_id: "offer".to_string(),
            role,
            status,
            payment: nostr_vpn_core::paid_routes::PaidRoutePaymentState {
                mode: PaidRoutePaymentMode::CashuSpilman,
                channel_id: channel_id.to_string(),
                cashu_spilman_payment: Some(CashuSpilmanPayment {
                    channel_id: channel_id.to_string(),
                    balance: 1,
                    signature: "signature".to_string(),
                    params: None,
                    funding_proofs: None,
                }),
                ..nostr_vpn_core::paid_routes::PaidRoutePaymentState::default()
            },
            accepted_terms: None,
            mint_url: "https://mint.example".to_string(),
            counterparty_npub: "seller".to_string(),
            created_at_unix: 1,
            expires_at_unix: 2,
            updated_at_unix: 1,
            error: String::new(),
        }
    }

    fn test_spilman_funding(wallet_data_dir: &Path, mint_url: &str) -> ClientChannelFunding {
        let sender = load_or_create_cashu_spilman_sender_key(wallet_data_dir)
            .expect("create Spilman sender key");
        let sender_secret =
            SecretKey::from_hex(&sender.secret_hex).expect("parse Spilman sender key");
        let receiver_secret = SecretKey::generate();
        let mint_secret = SecretKey::generate();
        let mut key_map = BTreeMap::new();
        key_map.insert(Amount::from(1), mint_secret.public_key());
        let active_keys = Keys::new(key_map);
        let keyset_id = Id::v1_from_keys(&active_keys);
        let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, active_keys, 0, None);
        let params = ChannelParameters::new(
            sender_secret.public_key(),
            receiver_secret.public_key(),
            mint_url.to_string(),
            CurrencyUnit::Sat,
            1,
            1,
            2_000_000_000,
            1_900_000_000,
            keyset_info.clone(),
            1,
            [7; 32],
        )
        .expect("create Spilman channel parameters");
        let proof = Proof::new(
            Amount::from(1),
            keyset_id,
            Secret::new("refund-worker-proof"),
            mint_secret.public_key(),
        );
        ClientChannelFunding {
            params_json: params.get_channel_id_params_json(),
            funding_proofs_json: serde_json::to_string(&vec![proof]).expect("encode funding proof"),
            channel_secret_hex: hex::encode(params.channel_secret),
            keyset_info_json: serde_json::to_string(&keyset_info).expect("encode keyset info"),
            sender_pubkey_hex: sender.public_key_hex,
            capacity: 1,
            funding_token_amount: 1,
            mint_url: mint_url.to_string(),
            created_at: 1_900_000_000,
        }
    }

    async fn wait_for_recovery(
        runtime: &mut PaidExitBuyerRefundRuntime,
        config_path: &Path,
    ) -> PaidExitBuyerRefundRecovery {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(recovery) = runtime.poll(config_path, true).expect("poll refund worker") {
                return recovery;
            }
            assert!(
                Instant::now() < deadline,
                "refund worker did not finish before deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn refund_recovery_selects_pending_and_legacy_closed_buyer_channels() {
        let mut store = PaidRouteStore::default();
        store.upsert_channel(channel(
            "pending",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closing,
        ));
        store.upsert_channel(channel(
            "legacy-closed",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closed,
        ));
        store.upsert_channel(channel(
            "active",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Active,
        ));
        store.upsert_channel(channel(
            "seller",
            PaidRouteChannelRole::Seller,
            PaidRouteLifecycleStatus::Closing,
        ));

        assert_eq!(
            paid_exit_buyer_refund_channel_ids(&store),
            vec!["legacy-closed".to_string(), "pending".to_string()]
        );
    }

    #[test]
    fn network_deadline_suppresses_refund_background_but_still_takes_control() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let mut store = PaidRouteStore::default();
        store.upsert_channel(channel(
            "pending",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closing,
        ));
        update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
            *target = store;
            Ok(())
        })
        .expect("write paid route fixture");
        write_daemon_control_request(&config_path, DaemonControlRequest::Pause)
            .expect("queue daemon control request");
        let mut runtime = PaidExitBuyerRefundRuntime::with_timings(
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .expect("start refund runtime");

        assert_eq!(
            runtime.before_tick(&config_path, false),
            Some(DaemonControlRequest::Pause),
            "an active network deadline must not hide local control"
        );
        assert!(
            runtime.active_channel_id.is_none(),
            "refund background work started while the network deadline was active"
        );
        assert_eq!(
            runtime.before_tick(&config_path, false),
            None,
            "the control request was not consumed exactly once"
        );
        assert!(
            runtime.active_channel_id.is_none(),
            "a control-free state tick started refund work during the network deadline"
        );
    }

    #[tokio::test]
    async fn finished_refund_does_not_hide_control_when_background_is_suppressed() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let channel_id = "finished-before-control";
        let (mut client_storage, storage_errors) = FileSpilmanClientStorage::load(
            spilman_client_store_path(&paid_exit_wallet_data_dir(&config_path)),
        )
        .expect("load Spilman client storage");
        client_storage.save_funding(
            channel_id,
            test_spilman_funding(&directory.0, "http://127.0.0.1:1"),
        );
        client_storage.set_closed(channel_id);
        client_storage.mark_refund_witnesses_persisted(channel_id);
        client_storage.mark_refund_proofs_validated(channel_id);
        client_storage.mark_refund_proofs_repaired(channel_id);
        storage_errors
            .ensure_ok()
            .expect("persist closed Spilman fixture");
        drop(client_storage);

        let mut store = PaidRouteStore::default();
        store.upsert_channel(channel(
            channel_id,
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closing,
        ));
        update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
            *target = store;
            Ok(())
        })
        .expect("write paid route fixture");

        let mut runtime = PaidExitBuyerRefundRuntime::with_timings(
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .expect("start refund runtime");
        assert!(
            runtime
                .poll(&config_path, true)
                .expect("start refund worker")
                .is_none()
        );
        assert_eq!(runtime.active_channel_id.as_deref(), Some(channel_id));
        tokio::time::sleep(Duration::from_millis(100)).await;
        write_daemon_control_request(&config_path, DaemonControlRequest::Reload)
            .expect("queue daemon control request");

        assert_eq!(
            runtime.before_tick(&config_path, false),
            Some(DaemonControlRequest::Reload),
            "a completed background refund kept the daemon control file stuck"
        );
        assert!(runtime.active_channel_id.is_none());
    }

    #[tokio::test]
    async fn hanging_mint_does_not_block_daemon_poll_or_next_refund_channel() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hanging mint");
        let mint_url = format!(
            "http://{}",
            listener.local_addr().expect("hanging mint address")
        );
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let hanging_mint = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mint request");
            let _ = accepted_tx.send(());
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            std::future::pending::<()>().await;
        });

        let (mut client_storage, storage_errors) =
            FileSpilmanClientStorage::load(spilman_client_store_path(&directory.0))
                .expect("load Spilman client storage");
        client_storage.save_funding("a-hanging", test_spilman_funding(&directory.0, &mint_url));
        client_storage.save_funding(
            "b-complete",
            test_spilman_funding(&directory.0, "http://127.0.0.1:1"),
        );
        client_storage.set_closed("b-complete");
        client_storage.mark_refund_witnesses_persisted("b-complete");
        client_storage.mark_refund_proofs_validated("b-complete");
        client_storage.mark_refund_proofs_repaired("b-complete");
        storage_errors
            .ensure_ok()
            .expect("persist Spilman fixtures");
        drop(client_storage);

        let mut store = PaidRouteStore::default();
        store.upsert_channel(channel(
            "a-hanging",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closing,
        ));
        store.upsert_channel(channel(
            "b-complete",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Closing,
        ));
        update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
            *target = store;
            Ok(())
        })
        .expect("write paid route fixtures");

        let attempt_timeout = Duration::from_millis(750);
        let mut runtime =
            PaidExitBuyerRefundRuntime::with_timings(attempt_timeout, Duration::from_secs(5))
                .expect("start refund runtime");
        let poll_started = Instant::now();
        assert!(
            runtime
                .poll(&config_path, true)
                .expect("start first refund")
                .is_none(),
            "starting a refund should not synchronously finish it"
        );
        assert!(
            poll_started.elapsed() < attempt_timeout / 2,
            "daemon poll blocked on the hanging mint"
        );
        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .expect("production refund path did not reach the hanging HTTP mint")
            .expect("hanging mint acceptance signal dropped");
        let client_store_path = spilman_client_store_path(&paid_exit_wallet_data_dir(&config_path));
        assert!(
            SharedSpilmanClientStoreLock::try_acquire(&client_store_path)
                .expect("probe Spilman client lock")
                .is_none(),
            "daemon Cashu operations must not race the refund worker"
        );
        let control_tick_started = Instant::now();
        assert!(
            runtime
                .poll(&config_path, false)
                .expect("poll during hanging refund")
                .is_none()
        );
        assert!(
            control_tick_started.elapsed() < attempt_timeout / 2,
            "an in-flight refund blocked a control or roaming tick"
        );

        let first = wait_for_recovery(&mut runtime, &config_path).await;
        assert_eq!(first.error_count, 1);
        let second = wait_for_recovery(&mut runtime, &config_path).await;
        assert_eq!(second.complete_count, 1);
        assert_eq!(second.error_count, 0);

        let store = load_paid_route_store(&paid_route_store_file_path(&config_path))
            .expect("reload paid route store");
        let hanging = store.channels.get("a-hanging").expect("hanging channel");
        assert_eq!(hanging.status, PaidRouteLifecycleStatus::Closing);
        assert!(hanging.error.contains("timed out after 750 ms"));
        let complete = store.channels.get("b-complete").expect("complete channel");
        assert_eq!(complete.status, PaidRouteLifecycleStatus::Closed);
        assert!(complete.error.is_empty());
        let released = SharedSpilmanClientStoreLock::try_acquire(&client_store_path)
            .expect("probe released Spilman client lock")
            .expect("refund worker did not release Cashu client storage");
        drop(released);

        hanging_mint.abort();
    }
