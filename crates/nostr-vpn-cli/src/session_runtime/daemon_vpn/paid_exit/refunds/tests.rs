    use super::*;

    use cashu::nuts::{CurrencyUnit, Id, Keys, Proof, SecretKey};
    use cashu::{Amount, secret::Secret};
    use cashu_service::{
        FileSpilmanClientStorage, load_or_create_cashu_spilman_sender_key,
        spilman_client_store_path,
    };
    use cdk_spilman::{ChannelParameters, ClientChannelFunding, ClientStorage, KeysetInfo};
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "nvpn-paid-exit-refund-worker-{}", uuid::Uuid::new_v4()
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
            "expired-active",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Active,
        ));
        store.upsert_channel(channel(
            "seller",
            PaidRouteChannelRole::Seller,
            PaidRouteLifecycleStatus::Closing,
        ));

        store.upsert_channel(channel("failed", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Failed));
        store.upsert_channel(channel("expired", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Expired));
        let mut active = channel("active", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Active);
        active.expires_at_unix = unix_timestamp() + 3600;
        store.upsert_channel(active);
        let mut unfunded = channel("unfunded", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Failed);
        unfunded.payment.cashu_spilman_payment = None;
        store.upsert_channel(unfunded);

        assert_eq!(
            paid_exit_buyer_refund_channel_ids(&store),
            vec!["expired", "expired-active", "failed", "legacy-closed", "pending"]
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
            runtime.before_tick(&config_path, false, false),
            Some(DaemonControlRequest::Pause),
            "an active network deadline must not hide local control"
        );
        assert!(
            runtime.active_channel_id.is_none(),
            "refund background work started while the network deadline was active"
        );
        assert_eq!(
            runtime.before_tick(&config_path, false, false),
            None,
            "the control request was not consumed exactly once"
        );
        assert!(
            runtime.active_channel_id.is_none(),
            "a control-free state tick started refund work during the network deadline"
        );
    }

    #[tokio::test]
    async fn ready_connection_funding_gets_the_wallet_before_refund_maintenance() {
        use nostr_vpn_core::paid_route_store::OpenPaidRouteBuyerSessionRequest;
        use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let path = paid_route_store_file_path(&config_path);
        let now = unix_timestamp();
        let mint = "https://mint.example";
        let mut offer = PaidExitConfig { enabled: true, ..Default::default() };
        offer.channel.accepted_mints = vec![mint.into()];
        offer.channel.free_probe_units = 0;
        let seller = nostr_sdk::Keys::generate();
        let signed = signed_paid_exit_offer_from_config("exit", &seller, &offer, None, now).unwrap();
        let session = update_paid_route_store(&path, |store| {
            store.upsert_signed_offer(signed, vec![], now)?;
            store.upsert_wallet_mint(mint, "mint", Some(10_000), now);
            let session = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                offer_selector: "exit".into(), buyer_npub: seller.public_key().to_bech32()?,
                mint_url: Some(mint.into()), channel_capacity_sat: Some(3),
                initial_paid_msat: 0, now_unix: now,
            })?;
            store.selected_buyer_session_id = session.session_id.clone();
            store.begin_buyer_session_funding(&session.session_id, now)?;
            store.upsert_channel(channel("refund", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Closing));
            // The shared cooldown has just expired. A refund must not grab
            // the store lock and renew that cooldown before funding can run.
            store.defer_buyer_mint_retry(mint, now - 12, Some("Mint unavailable"), None)?;
            Ok(session)
        }).unwrap();
        let mut runtime = PaidExitBuyerRefundRuntime::new().unwrap();
        assert!(runtime.before_tick(&config_path, true, true).is_none());
        assert!(runtime.active_channel_id.is_none(), "background refund starved ready funding");
        let lock = SharedSpilmanClientStoreLock::try_acquire(spilman_client_store_path(&directory.0))
            .unwrap().expect("funding must be able to acquire the wallet lock");
        drop(lock);
        // A genuine shortfall needs refund recovery to remain available.
        update_paid_route_store(&path, |store| store.record_buyer_session_funding_shortfall(&session.session_id, 20)).unwrap();
        runtime.before_tick(&config_path, true, true);
        assert!(runtime.active_channel_id.is_some());
        wait_for_recovery(&mut runtime, &config_path).await;
        // A fresh worker with Direct/VPN-off context also resumes recovery,
        // even while the selected paid session is still awaiting funding.
        update_paid_route_store(&path, |store| store.record_buyer_session_funding_shortfall(&session.session_id, 0)).unwrap();
        drop(runtime);
        let mut direct = PaidExitBuyerRefundRuntime::new().unwrap();
        direct.before_tick(&config_path, true, false);
        assert!(direct.active_channel_id.is_some());
        wait_for_recovery(&mut direct, &config_path).await;
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
        // Establish that the worker has finished before testing how a
        // suppressed background tick reaps it. TLS setup need not fit 100 ms.
        let finished = runtime.result_rx.recv_timeout(Duration::from_secs(2))
            .expect("refund worker finished");
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        finished_tx.send(finished).unwrap();
        runtime.result_rx = finished_rx;
        write_daemon_control_request(&config_path, DaemonControlRequest::Reload)
            .expect("queue daemon control request");

        assert_eq!(
            runtime.before_tick(&config_path, false, false),
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
        store.channels.get_mut("a-hanging").unwrap().mint_url = mint_url.clone();
        store.channels.get_mut("b-complete").unwrap().mint_url = "http://127.0.0.1:1".to_string();
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
                .is_some(),
            "an HTTP refund request must not prevent foreground channel funding"
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
        write_daemon_control_request(&config_path, DaemonControlRequest::Reload).unwrap();
        assert_eq!(
            runtime.before_tick(&config_path, false, false),
            Some(DaemonControlRequest::Reload),
            "an in-flight mint request must not delay Internet mode changes"
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
        assert_eq!(
            store.buyer_mint_failure_retry_at(&mint_url),
            0,
            "the local refund deadline must not label the mint unavailable for new payments"
        );
        let complete = store.channels.get("b-complete").expect("complete channel");
        assert_eq!(complete.status, PaidRouteLifecycleStatus::Closed);
        assert!(complete.error.is_empty());
        let released = SharedSpilmanClientStoreLock::try_acquire(&client_store_path)
            .expect("probe released Spilman client lock")
            .expect("refund worker did not release Cashu client storage");
        drop(released);

        hanging_mint.abort();
    }

    #[tokio::test]
    async fn mint_retry_after_survives_restart_and_coordinates_refund_channels() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let mint = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            // Keep listening so a mistaken retry reaches a real socket.
            std::future::pending::<()>().await;
        });
        let (mut storage, errors) =
            FileSpilmanClientStorage::load(spilman_client_store_path(&directory.0)).unwrap();
        let mut store = PaidRouteStore::default();
        for id in ["a-refund", "b-refund"] {
            storage.save_funding(id, test_spilman_funding(&directory.0, &mint_url));
            let mut record = channel(
                id,
                PaidRouteChannelRole::Buyer,
                PaidRouteLifecycleStatus::Closing,
            );
            record.mint_url = mint_url.clone();
            store.upsert_channel(record);
        }
        errors.ensure_ok().unwrap();
        drop(storage);
        update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
            *target = store;
            Ok(())
        })
        .unwrap();
        let mut runtime = PaidExitBuyerRefundRuntime::new().unwrap();
        let recovery = wait_for_recovery(&mut runtime, &config_path).await;
        assert_eq!(recovery.error_count, 1);
        assert!(
            runtime.active_channel_id.is_none(),
            "another channel bypassed the mint cooldown"
        );
        drop(runtime);
        let store = load_paid_route_store(&paid_route_store_file_path(&config_path)).unwrap();
        assert!(
            store
                .channels
                .values()
                .all(|c| c.status == PaidRouteLifecycleStatus::Closing)
        );
        let mut restarted = PaidExitBuyerRefundRuntime::new().unwrap();
        restarted.poll(&config_path, true).unwrap();
        assert!(
            restarted.active_channel_id.is_none(),
            "restart discarded Retry-After"
        );
        mint.abort();
    }

    #[test]
    fn mint_failures_back_off_persistently_and_healthy_polling_does_not_starve_funding() {
        let directory = TestDirectory::new();
        let path = paid_route_store_file_path(&directory.0.join("config.toml"));
        let mint = "https://mint.example/Bitcoin";
        let mut now = 1_900_000_000;
        for delay in [10, 20, 40, 80, 160, 320, 600, 600] {
            update_paid_route_store(&path, |store| {
                store.defer_buyer_mint_retry(mint, now, Some("Mint unavailable"), None)
            })
            .unwrap();
            let store = load_paid_route_store(&path).unwrap();
            let deadline = store.buyer_mint_failure_retry_at("https://MINT.example/Bitcoin/");
            assert_eq!(deadline, now + delay + 1);
            assert_eq!(store.buyer_mint_retry_at("https://another.example"), 0);
            now = deadline;
        }
        update_paid_route_store(&path, |store| {
            store.defer_buyer_mint_retry(mint, now, Some("Mint unavailable"), Some(3600))?;
            store.clear_buyer_mint_retry(mint, now + 1)?;
            store.defer_buyer_mint_retry(mint, now + 2, None, None)
        })
        .unwrap();
        let store = load_paid_route_store(&path).unwrap();
        assert_eq!(
            store.buyer_mint_failure_retry_at(mint),
            now + 3601,
            "an overlapping success must not shorten Retry-After"
        );
        now += 3601;
        update_paid_route_store(&path, |store| {
            store.defer_buyer_mint_retry(mint, now, None, None)
        })
        .unwrap();
        let store = load_paid_route_store(&path).unwrap();
        assert_eq!(
            store.buyer_mint_failure_retry_at(mint),
            0,
            "healthy polling must allow funding"
        );
        assert_eq!(store.buyer_mint_retry_at(mint), now + 61);
        now += 61;
        update_paid_route_store(&path, |store| {
            store.defer_buyer_mint_retry(mint, now, Some("Mint unavailable"), None)
        })
        .unwrap();
        assert_eq!(
            load_paid_route_store(&path)
                .unwrap()
                .buyer_mint_failure_retry_at(mint),
            now + 11,
            "successful recovery resets the failure count"
        );
    }

    #[tokio::test]
    async fn refund_http_preserves_retry_after_dates_and_rejects_invalid_values() {
        for (header, expected) in [
            ("120", Some(120)),
            (
                "Thu, 01 Jan 2099 00:00:00 GMT",
                Some(4_070_908_800_u64.saturating_sub(unix_timestamp())),
            ),
            ("Thu, 01 Jan 1970 00:00:00 GMT", Some(0)),
            ("not-a-date", None),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                let response = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nRetry-After: {header}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let error = cashu_service::send_mint_request(
                reqwest::Client::new().post(format!("{url}/v1/restore"))
                    .json(&serde_json::json!({"outputs": []})),
            ).await.and_then(cashu_service::check_mint_response).unwrap_err();
            let delay = error
                .downcast_ref::<cashu_service::MintRetryAfter>()
                .map(|delay| delay.0);
            match (delay, expected) {
                (Some(actual), Some(expected)) => assert!(actual.abs_diff(expected) <= 1),
                (None, None) => {}
                _ => panic!("lost Retry-After {header}: {error:#}"),
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn healthy_multi_request_refund_can_finish_after_three_seconds() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let funding = test_spilman_funding(&directory.0, &mint_url);
        let keyset: serde_json::Value = serde_json::from_str(&funding.keyset_info_json).unwrap();
        let keyset_id = keyset["keysetId"].as_str().unwrap().to_string();
        let mint = tokio::spawn(async move {
            let mut paths = Vec::new();
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (header_end, length) = loop {
                    let mut chunk = [0; 4096];
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&chunk[..read]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        }).unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&chunk[..read]);
                }
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let path = headers.split_whitespace().nth(1).unwrap().to_string();
                let response = if path == "/v1/checkstate" {
                    let body: serde_json::Value = serde_json::from_slice(&bytes[header_end..]).unwrap();
                    let states = body["Ys"].as_array().unwrap().iter()
                        .map(|y| serde_json::json!({"Y": y, "state": "SPENT"}))
                        .collect::<Vec<_>>();
                    serde_json::json!({"states": states})
                } else if path == "/v1/keysets" {
                    serde_json::json!({"keysets": [{"id": keyset_id, "unit": "sat", "active": true, "input_fee_ppk": 0}]})
                } else if path.starts_with("/v1/keys/") {
                    serde_json::json!({"keysets": [{"id": keyset_id, "unit": "sat", "keys": keyset["keys"]}]})
                } else {
                    assert_eq!(path, "/v1/restore");
                    serde_json::json!({"outputs": [], "signatures": []})
                };
                paths.push(path);
                // Each request is healthy; their total exceeds the old whole-work budget.
                tokio::time::sleep(Duration::from_millis(700)).await;
                let body = response.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
            paths
        });
        let (mut storage, errors) = FileSpilmanClientStorage::load(spilman_client_store_path(&directory.0)).unwrap();
        storage.save_funding("slow-healthy", funding);
        errors.ensure_ok().unwrap();
        drop(storage);
        let mut record = channel("slow-healthy", PaidRouteChannelRole::Buyer, PaidRouteLifecycleStatus::Closing);
        record.mint_url = mint_url.clone();
        update_paid_route_store(&paid_route_store_file_path(&config_path), |store| {
            store.upsert_channel(record);
            Ok(())
        }).unwrap();
        let mut runtime = PaidExitBuyerRefundRuntime::new().unwrap();
        let deadline = Instant::now() + Duration::from_secs(12);
        let recovery = loop {
            if let Some(result) = runtime.poll(&config_path, true).unwrap() { break result; }
            assert!(Instant::now() < deadline, "healthy refund never completed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(recovery.complete_count, 1);
        assert_eq!(recovery.error_count, 0);
        let paths = mint.await.unwrap();
        assert_eq!(paths.first().unwrap(), "/v1/checkstate");
        let store = load_paid_route_store(&paid_route_store_file_path(&config_path)).unwrap();
        assert_eq!(store.channels["slow-healthy"].status, PaidRouteLifecycleStatus::Closed);
        assert_eq!(store.buyer_mint_failure_retry_at(&mint_url), 0);
    }

    #[test]
    fn refund_retry_delay_waits_for_funding_expiry_and_retries_otherwise() {
        let interval = Duration::from_secs(60);
        let now = 1_900_000_000;
        assert_eq!(
            paid_exit_buyer_refund_retry_delay(
                &PaidExitBuyerRefundOutcome::Pending {
                    wait_until_unix: now + 3600
                },
                interval,
                now,
            ),
            Duration::from_secs(3600),
            "an unexpired funding deadline must be honored"
        );
        assert_eq!(
            paid_exit_buyer_refund_retry_delay(
                &PaidExitBuyerRefundOutcome::Pending {
                    wait_until_unix: now
                },
                interval,
                now,
            ),
            interval,
            "a lapsed deadline falls back to the retry interval"
        );
        assert_eq!(
            paid_exit_buyer_refund_retry_delay(
                &PaidExitBuyerRefundOutcome::Pending { wait_until_unix: 0 },
                interval,
                now,
            ),
            interval,
            "a pending state without a deadline is a genuine retry"
        );
        assert_eq!(
            paid_exit_buyer_refund_retry_delay(
                &PaidExitBuyerRefundOutcome::Failed(anyhow!("mint unreachable")),
                interval,
                now,
            ),
            interval
        );
    }

    #[tokio::test]
    async fn expired_channel_checks_once_and_waits_for_funding_expiry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint_url = format!("http://{}", listener.local_addr().unwrap());
        let checks = std::sync::Arc::new(AtomicUsize::new(0));
        let serving = checks.clone();
        let mint = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (header_end, length) = loop {
                    let mut chunk = [0; 4096];
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&chunk[..read]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        }).unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    bytes.extend_from_slice(&chunk[..read]);
                }
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let path = headers.split_whitespace().nth(1).unwrap().to_string();
                assert_eq!(path, "/v1/checkstate", "unexpected mint request {path}");
                serving.fetch_add(1, Ordering::SeqCst);
                let body: serde_json::Value =
                    serde_json::from_slice(&bytes[header_end..]).unwrap();
                let states = body["Ys"].as_array().unwrap().iter()
                    .map(|y| serde_json::json!({"Y": y, "state": "UNSPENT"}))
                    .collect::<Vec<_>>();
                let response = serde_json::json!({ "states": states }).to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
            }
        });

        // Routing already expired the channel, while the Spilman funding in
        // the shared fixture does not expire until 2_000_000_000.
        let (mut storage, errors) = FileSpilmanClientStorage::load(spilman_client_store_path(&directory.0))
            .unwrap();
        storage.save_funding("expired-early", test_spilman_funding(&directory.0, &mint_url));
        errors.ensure_ok().unwrap();
        drop(storage);
        let mut record = channel(
            "expired-early",
            PaidRouteChannelRole::Buyer,
            PaidRouteLifecycleStatus::Expired,
        );
        record.mint_url = mint_url.clone();
        update_paid_route_store(&paid_route_store_file_path(&config_path), |store| {
            store.upsert_channel(record);
            Ok(())
        })
        .unwrap();

        let retry_interval = Duration::from_secs(60);
        let mut runtime = PaidExitBuyerRefundRuntime::with_timings(
            Duration::from_secs(1),
            retry_interval,
        )
        .unwrap();
        let recovery = wait_for_recovery(&mut runtime, &config_path).await;
        assert_eq!(recovery.pending_count, 1);
        assert_eq!(recovery.error_count, 0);
        assert_eq!(
            checks.load(Ordering::SeqCst),
            1,
            "one mint check before the funding expiry"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        for _ in 0..3 {
            runtime.poll(&config_path, true).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(runtime.active_channel_id.is_none());
        assert_eq!(
            checks.load(Ordering::SeqCst),
            1,
            "the refund retried before the funding expiry"
        );

        let scheduled = runtime
            .retry_after
            .get("expired-early")
            .expect("channel scheduled for a retry");
        let wait = scheduled
            .checked_duration_since(Instant::now())
            .expect("retry scheduled in the past");
        assert!(
            wait > retry_interval,
            "the funding expiry must outlast the 60s retry interval"
        );
        let expected = Duration::from_secs(2_000_000_000 - unix_timestamp());
        assert!(
            wait <= expected + Duration::from_secs(5),
            "the retry was not scheduled at the funding expiry"
        );
        mint.abort();
    }
