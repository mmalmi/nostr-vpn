    use super::*;

    fn pending_send(
        operation_id: &str,
        amount_sat: u64,
        created_at_unix: u64,
    ) -> cashu_service::CashuWalletActivityEntry {
        cashu_service::CashuWalletActivityEntry {
            id: format!("activity-{operation_id}"),
            kind: cashu_service::CashuWalletActivityKind::TokenSend,
            status: cashu_service::CashuWalletActivityStatus::Pending,
            mint_url: "https://mint.example/Bitcoin".to_string(),
            unit: "sat".to_string(),
            amount_sat,
            fee_sat: Some(0),
            created_at_unix,
            expires_at_unix: None,
            quote_id: None,
            operation_id: Some(operation_id.to_string()),
            payment_request: None,
            token: Some("cashu-token-redacted-in-test".to_string()),
        }
    }

    fn expired_unfunded_buyer_channel(
        created_at_unix: u64,
    ) -> nostr_vpn_core::paid_route_store::PaidRouteChannelRecord {
        nostr_vpn_core::paid_route_store::PaidRouteChannelRecord {
            channel_id: "route-channel".to_string(),
            offer_id: "offer".to_string(),
            role: nostr_vpn_core::paid_route_store::PaidRouteChannelRole::Buyer,
            status: nostr_vpn_core::paid_route_store::PaidRouteLifecycleStatus::Probing,
            payment: nostr_vpn_core::paid_routes::PaidRoutePaymentState {
                capacity_sat: 20,
                cashu_unit: "sat".to_string(),
                ..Default::default()
            },
            accepted_terms: None,
            mint_url: "https://mint.example/Bitcoin/".to_string(),
            counterparty_npub: "npub-test".to_string(),
            created_at_unix,
            expires_at_unix: created_at_unix + 60,
            updated_at_unix: created_at_unix,
            error: String::new(),
        }
    }

    fn recoverable_unfunded_route_store(
        expires_at_unix: u64,
    ) -> nostr_vpn_core::paid_route_store::PaidRouteStore {
        use nostr_vpn_core::paid_route_store::{
            PaidRouteLeaseRecord, PaidRouteQuoteRecord, PaidRouteSessionRecord,
        };
        use nostr_vpn_core::paid_routes::{
            PaidRouteLease, PaidRoutePaymentMode, PaidRoutePaymentState, PaidRouteQuote,
            PaidRouteSession, PaidRouteUsage,
        };

        let mut store = nostr_vpn_core::paid_route_store::PaidRouteStore::default();
        let mut channel = expired_unfunded_buyer_channel(1_000);
        channel.expires_at_unix = expires_at_unix;
        channel.status = nostr_vpn_core::paid_route_store::PaidRouteLifecycleStatus::Failed;
        channel.payment.channel_id = "route-channel".to_string();
        channel.counterparty_npub = "npub-seller".to_string();
        store.channels.insert("route-channel".to_string(), channel);
        store.quotes.insert(
            "quote-1".to_string(),
            PaidRouteQuoteRecord {
                quote: PaidRouteQuote {
                    quote_id: "quote-1".to_string(),
                    offer_id: "offer".to_string(),
                    payment_mode: PaidRoutePaymentMode::CashuSpilman,
                    channel_capacity_sat: 20,
                    expires_at_unix,
                    receiver_pubkey_hex: "22".repeat(32),
                },
                created_at_unix: 1_000,
                updated_at_unix: 1_000,
            },
        );
        store.leases.insert(
            "lease-1".to_string(),
            PaidRouteLeaseRecord {
                lease: PaidRouteLease {
                    lease_id: "lease-1".to_string(),
                    offer_id: "offer".to_string(),
                    quote_id: "quote-1".to_string(),
                    buyer_npub: "npub-buyer".to_string(),
                    starts_at_unix: 1_000,
                    expires_at_unix,
                },
                status: nostr_vpn_core::paid_route_store::PaidRouteLifecycleStatus::Failed,
                created_at_unix: 1_000,
                updated_at_unix: 1_000,
            },
        );
        store.sessions.insert(
            "session-1".to_string(),
            PaidRouteSessionRecord {
                session: PaidRouteSession {
                    session_id: "session-1".to_string(),
                    lease_id: "lease-1".to_string(),
                    usage: PaidRouteUsage::default(),
                    payment: PaidRoutePaymentState {
                        mode: PaidRoutePaymentMode::CashuSpilman,
                        channel_id: "route-channel".to_string(),
                        cashu_unit: "sat".to_string(),
                        capacity_sat: 20,
                        ..Default::default()
                    },
                    realized_exit_ip: None,
                    observed_country_code: None,
                    observed_asn: None,
                    quality: None,
                },
                created_at_unix: 1_000,
                updated_at_unix: 1_000,
            },
        );
        store
    }

    #[test]
    fn startup_recovery_selects_unexpired_unattached_buyer_channels() {
        let store = recoverable_unfunded_route_store(10_000);

        let requests = legacy_route_open_recovery_requests(&store, 2_000);

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "session-1");
        assert_eq!(
            requests[0].1.client_request_id.as_deref(),
            Some("session-1")
        );
        assert_eq!(requests[0].1.route_created_at_unix, Some(1_000));
        assert_eq!(requests[0].1.capacity_sat, 20);
        assert_eq!(requests[0].1.mint_url, "https://mint.example/Bitcoin/");
    }

    #[test]
    fn startup_recovery_ignores_expired_channels() {
        let store = recoverable_unfunded_route_store(1_500);

        assert!(legacy_route_open_recovery_requests(&store, 2_000).is_empty());
    }

    #[test]
    fn startup_recovery_retries_signature_only_channel_state() {
        let mut store = recoverable_unfunded_route_store(10_000);
        let payment = cashu_service::CashuSpilmanPayment {
            channel_id: "route-channel".to_string(),
            balance: 1,
            signature: "signed-update".to_string(),
            params: None,
            funding_proofs: None,
        };
        let mut session_payment = store.sessions["session-1"].session.payment.clone();
        session_payment.paid_msat = 1_000;
        session_payment.cashu_spilman_payment = Some(payment.clone());
        store
            .sessions
            .get_mut("session-1")
            .expect("buyer session")
            .session
            .payment = session_payment;
        let channel = store
            .channels
            .get_mut("route-channel")
            .expect("buyer channel");
        channel.payment.paid_msat = 1_000;
        channel.payment.cashu_spilman_payment = Some(payment);

        let requests = legacy_route_open_recovery_requests(&store, 2_000);

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "session-1");
        assert_eq!(requests[0].1.opening_paid_msat, 1_000);
    }

    #[test]
    fn upgrade_reclaims_only_pending_send_matching_expired_unfunded_channel() {
        let mut store = nostr_vpn_core::paid_route_store::PaidRouteStore::default();
        store.channels.insert(
            "route-channel".to_string(),
            expired_unfunded_buyer_channel(1_000),
        );
        let activity = vec![
            pending_send("matching", 20, 1_002),
            pending_send("manual-send", 20, 900),
            pending_send("wrong-amount", 21, 1_002),
        ];

        let candidates = legacy_orphaned_channel_sends(&store, &activity, 2_000);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.operation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["matching"]
        );
    }

    #[test]
    fn failed_channel_cleanup_selects_only_sends_created_by_that_attempt() {
        let pending_before = BTreeSet::from(["already-pending".to_string()]);
        let mut completed = pending_send("completed", 20, 1_003);
        completed.status = cashu_service::CashuWalletActivityStatus::Complete;
        let activity_after = vec![
            pending_send("already-pending", 20, 900),
            pending_send("new-channel-send", 20, 1_002),
            completed,
        ];

        let created = newly_pending_cashu_sends(&pending_before, &activity_after);

        assert_eq!(created.len(), 1);
        assert_eq!(created[0].operation_id, "new-channel-send");
    }

    #[derive(Debug)]
    struct FixedSeedStore;

    impl cashu_service::CashuWalletSeedStore for FixedSeedStore {
        fn load_seed(&self) -> Result<Option<[u8; 64]>> {
            Ok(Some([42; 64]))
        }

        fn store_seed(&self, seed: &[u8; 64]) -> Result<()> {
            if *seed != [42; 64] {
                return Err(anyhow!("test wallet attempted to replace its seed"));
            }
            Ok(())
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "nvpn-daemon-cashu-wallet-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create daemon wallet test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn daemon_is_the_single_cdk_sqlite_owner_and_handles_private_requests() {
        let directory = TestDirectory::new();
        let config_path = directory.0.join("config.toml");
        fs::write(&config_path, "").expect("create config ownership anchor");
        let worker = DaemonCashuWalletWorker::start(config_path.clone())
            .expect("start daemon CDK SQLite wallet worker");
        let second_owner =
            CashuWalletService::open_with_seed_store(&directory.0, Arc::new(FixedSeedStore))
                .await
                .expect_err("a second wallet owner must be rejected");
        assert!(second_owner.to_string().contains("already in use"));

        let in_process_overview = decode_daemon_cashu_wallet_overview(
            request_daemon_cashu_wallet_worker(
                &config_path,
                DaemonCashuWalletCommand::Overview {
                    refresh_quotes: false,
                },
            )
            .await
            .expect("daemon process can request its wallet worker"),
        )
        .expect("decode in-process wallet overview");
        assert!(in_process_overview.entries.is_empty());

        let request = DaemonCashuWalletRequest {
            id: "00000000000000000000000000000042".to_string(),
            command: DaemonCashuWalletCommand::Overview {
                refresh_quotes: false,
            },
        };
        let request_path =
            cashu_wallet_request_dir(&config_path).join("00000000000000000000000000000042.json");
        nostr_vpn_core::config::write_private_file_preserving_user_owner(
            &request_path,
            &serde_json::to_vec(&request).expect("encode wallet request"),
        )
        .expect("write wallet request");

        let response_path =
            cashu_wallet_response_dir(&config_path).join("00000000000000000000000000000042.json");
        let deadline = Instant::now() + Duration::from_secs(2);
        while (!response_path.exists() || daemon_cashu_wallet_requests_pending(&config_path))
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(response_path.exists(), "daemon wallet worker did not reply");
        assert!(!daemon_cashu_wallet_requests_pending(&config_path));
        let response: DaemonCashuWalletResponse =
            serde_json::from_slice(&fs::read(&response_path).expect("read daemon wallet response"))
                .expect("decode daemon wallet response");
        assert!(response.error.is_none());
        let overview =
            decode_daemon_cashu_wallet_overview(response.result.expect("wallet overview response"))
                .expect("decode wallet overview");
        assert!(overview.entries.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(response_path)
                    .expect("wallet response metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        worker.stop();
    }
