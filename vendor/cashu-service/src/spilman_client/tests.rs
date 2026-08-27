    use super::*;

    #[cfg(feature = "spilman-wallet")]
    fn recoverable_open_request(
        request_id: &str,
    ) -> StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
        StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
            token: String::new(),
            receiver_pubkey_hex: format!("02{}", "22".repeat(32)),
            sender_secret_hex: None,
            expiry_unix: 10_000,
            keyset_info_json: "{}".to_string(),
            max_amount_per_output: 0,
            unit: "sat".to_string(),
            opening_paid_msat: 0,
            client_request_id: Some(request_id.to_string()),
            route_created_at_unix: Some(1_000),
            route_mint_url: Some("https://mint.example/Bitcoin".to_string()),
            route_capacity_sat: Some(10),
        }
    }

    #[cfg(feature = "spilman-wallet")]
    fn recoverable_funding() -> cdk_spilman::ClientChannelFunding {
        cdk_spilman::ClientChannelFunding {
            params_json: serde_json::json!({
                "mint": "https://mint.example/Bitcoin",
                "unit": "sat",
                "capacity": 10,
                "maximum_amount": 0,
                "receiver_pubkey": format!("02{}", "22".repeat(32)),
                "expiry_timestamp": 10_000,
            })
            .to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "11".repeat(32),
            keyset_info_json: "{}".to_string(),
            sender_pubkey_hex: format!("02{}", "33".repeat(32)),
            capacity: 10,
            funding_token_amount: 10,
            mint_url: "https://mint.example/Bitcoin/".to_string(),
            created_at: 5_000,
        }
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn channel_open_request_is_durable_and_idempotent_before_caller_attachment() {
        use cdk_spilman::ClientStorage as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.json");
        let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        storage.begin_open_request(Some("route-session-1")).unwrap();
        storage.save_funding("cashu-channel-1", recoverable_funding());
        storage.save_payment_state(
            "cashu-channel-1",
            cdk_spilman::ClientPaymentState {
                balance: 0,
                signature: "opening-signature".to_string(),
                payment_count: 1,
                last_payment_at: 5_000,
            },
        );
        errors.ensure_ok().unwrap();
        drop(storage);

        // This reload models cancellation after the daemon committed the
        // channel but before the route task attached the returned payment.
        let (mut storage, _) = FileSpilmanClientStorage::load(&path).unwrap();
        let recovered = recover_opened_channel_from_storage(
            &mut storage,
            &recoverable_open_request("route-session-1"),
        )
        .unwrap()
        .expect("the retry must recover the committed channel");

        assert_eq!(recovered.channel_id, "cashu-channel-1");
        assert_eq!(recovered.capacity_sat, 10);
        assert!(recovered.payment.has_funding());
        assert_eq!(storage.state.funding.len(), 1);
        assert_eq!(
            storage.state.open_requests["route-session-1"],
            "cashu-channel-1"
        );
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn upgrade_claims_one_exact_delayed_legacy_channel() {
        use cdk_spilman::ClientStorage as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.json");
        let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        storage.save_funding("legacy-channel", recoverable_funding());
        storage.save_payment_state(
            "legacy-channel",
            cdk_spilman::ClientPaymentState {
                balance: 0,
                signature: "opening-signature".to_string(),
                payment_count: 1,
                last_payment_at: 5_000,
            },
        );
        errors.ensure_ok().unwrap();

        let mut wrong_session = recoverable_open_request("newer-route-session");
        wrong_session.expiry_unix = 11_000;
        assert!(
            recover_opened_channel_from_storage(&mut storage, &wrong_session)
                .unwrap()
                .is_none(),
            "a newer session with different immutable expiry must not claim the channel"
        );

        let recovered = recover_opened_channel_from_storage(
            &mut storage,
            &recoverable_open_request("upgraded-route-session"),
        )
        .unwrap()
        .expect("the exact legacy match should be claimed");

        assert_eq!(recovered.channel_id, "legacy-channel");
        assert_eq!(
            storage.state.open_requests["upgraded-route-session"],
            "legacy-channel"
        );
        errors.ensure_ok().unwrap();
    }

    #[test]
    fn file_spilman_client_storage_persists_refund_witness_migration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.json");
        let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        assert!(!storage.refund_witnesses_persisted("channel-1"));
        storage.mark_refund_witnesses_persisted("channel-1");
        assert!(!storage.refund_proofs_validated("channel-1"));
        storage.mark_refund_proofs_validated("channel-1");
        assert!(!storage.refund_proofs_repaired("channel-1"));
        storage.mark_refund_proofs_repaired("channel-1");
        errors.ensure_ok().unwrap();
        drop(storage);

        let (storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        assert!(storage.refund_witnesses_persisted("channel-1"));
        assert!(storage.refund_proofs_validated("channel-1"));
        assert!(storage.refund_proofs_repaired("channel-1"));
        errors.ensure_ok().unwrap();
    }

    #[cfg(feature = "spilman-wallet-http")]
    #[test]
    fn automatic_spilman_keyset_selection_matches_wallet_fee_policy() {
        let keysets = serde_json::json!([
            {"id": "expensive", "unit": "sat", "active": true, "input_fee_ppk": 200},
            {"id": "inactive", "unit": "sat", "active": false, "input_fee_ppk": 0},
            {"id": "cheap", "unit": "sat", "active": true, "input_fee_ppk": 100}
        ]);
        let keysets = keysets.as_array().unwrap();

        assert_eq!(
            select_spilman_keyset(keysets, "sat", None)
                .unwrap()
                .get("id")
                .unwrap(),
            "cheap"
        );
        assert_eq!(
            select_spilman_keyset(keysets, "sat", Some("inactive"))
                .unwrap()
                .get("id")
                .unwrap(),
            "inactive"
        );
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn spilman_sender_key_is_created_and_reused() {
        let temp = tempfile::tempdir().unwrap();
        let first = load_or_create_cashu_spilman_sender_key(temp.path()).unwrap();
        let second = load_or_create_cashu_spilman_sender_key(temp.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version, SPILMAN_SENDER_KEY_VERSION);
        assert_eq!(first.secret_hex.len(), 64);
        assert!(!first.public_key_hex.is_empty());
    }

    #[cfg(all(feature = "spilman-wallet", unix))]
    #[test]
    fn spilman_sender_key_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, spilman_sender_key_path(temp.path())).unwrap();

        assert!(load_or_create_cashu_spilman_sender_key(temp.path()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn receiver_pubkey_normalization_accepts_x_only_keys() {
        let x_only = "ab".repeat(32);

        assert_eq!(
            normalize_spilman_receiver_pubkey_hex(&x_only),
            format!("02{x_only}")
        );
        assert_eq!(
            normalize_spilman_receiver_pubkey_hex(&format!("03{x_only}")),
            format!("03{x_only}")
        );
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn file_spilman_payment_signer_reports_missing_channel() {
        let temp = tempfile::tempdir().unwrap();
        let signer = FileSpilmanPaymentSigner::load(temp.path()).unwrap();
        let error = signer
            .sign_cashu_spilman_payment("missing-channel", 1, false)
            .expect_err("signing a missing channel should fail");

        assert!(error.contains("Channel not found: missing-channel"));
        assert!(spilman_sender_key_path(temp.path()).exists());
    }

    #[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
    #[tokio::test]
    async fn wallet_channel_open_rejects_non_sat_units() {
        let temp = tempfile::tempdir().unwrap();
        let error = open_streaming_route_cashu_spilman_channel_from_wallet(
            temp.path(),
            StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url: "https://mint.example".to_string(),
                receiver_pubkey_hex: "receiver".to_string(),
                capacity_sat: 1,
                expiry_unix: 123,
                max_amount_per_output: 64,
                unit: "msat".to_string(),
                opening_paid_msat: 1,
                keyset_id: None,
                keyset_info_json: Some("{}".to_string()),
                client_request_id: None,
                route_created_at_unix: None,
            },
        )
        .await
        .expect_err("msat wallet-open should fail before touching wallet storage");

        assert!(error
            .to_string()
            .contains("wallet-backed Cashu Spilman channel opening currently supports sat only"));
    }
