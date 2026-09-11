use super::*;

#[tokio::test]
async fn funding_shortfall_survives_ipc_and_restart_without_retrying_unchanged_funds() {
    use crate::session_runtime::daemon_vpn_paid_exit::fund_paid_exit_session;
    use nostr_vpn_core::paid_route_store::{
        load_paid_route_store, paid_route_store_file_path, update_paid_route_store,
    };
    let directory =
        std::env::temp_dir().join(format!("nvpn-funding-balance-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let config_path = directory.join("config.toml");
    let store_path = paid_route_store_file_path(&config_path);
    let now = crate::unix_timestamp();
    let mint = "https://mint.example/Bitcoin";
    update_paid_route_store(&store_path, |store| {
        *store = tests::recoverable_unfunded_route_store(now + 3600);
        store.upsert_wallet_mint(mint, "Test mint", Some(20_000), now);
        Ok(())
    })
    .unwrap();
    prepare_ipc_directories(&config_path).unwrap();
    let responder_config = config_path.clone();
    let responder = tokio::spawn(async move {
        loop {
            if let Some(entry) = fs::read_dir(cashu_wallet_request_dir(&responder_config))
                .unwrap()
                .next()
            {
                let path = entry.unwrap().path();
                let request: DaemonCashuWalletRequest =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let response = serde_json::json!({
                    "id": request.id, "result": null,
                    "error": "Insufficient funds including mint fees",
                    "insufficient_funds": {"available_sat": 20, "required_sat": 22}
                });
                fs::write(
                    cashu_wallet_response_dir(&responder_config)
                        .join(format!("{}.json", request.id)),
                    serde_json::to_vec(&response).unwrap(),
                )
                .unwrap();
                fs::remove_file(path).unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let app = crate::AppConfig::generated();
    tokio::time::timeout(
        Duration::from_secs(2),
        fund_paid_exit_session(&app, &config_path, "session-1", now),
    )
    .await
    .unwrap()
    .unwrap_err();
    responder.await.unwrap();
    let stored = load_paid_route_store(&store_path).unwrap();
    assert_eq!(
        stored.buyer_mint_failure_retry_at(mint),
        0,
        "low funds must not mark a healthy mint offline"
    );
    assert_eq!(stored.buyer_session_funding_retry_at("session-1"), u64::MAX);
    tokio::time::timeout(
        Duration::from_millis(100),
        fund_paid_exit_session(&app, &config_path, "session-1", now + 601),
    )
    .await
    .expect("low funds must not submit a wallet request")
    .unwrap_err();
    assert_eq!(
        fs::read_dir(cashu_wallet_request_dir(&config_path))
            .unwrap()
            .count(),
        0
    );
    update_paid_route_store(&store_path, |store| {
        store.upsert_wallet_mint(mint, "Test mint", Some(21_000), now + 602);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        load_paid_route_store(&store_path)
            .unwrap()
            .buyer_session_funding_retry_at("session-1"),
        u64::MAX
    );
    update_paid_route_store(&store_path, |store| {
        store.upsert_wallet_mint(mint, "Test mint", Some(22_000), now + 603);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        load_paid_route_store(&store_path)
            .unwrap()
            .buyer_session_funding_retry_at("session-1"),
        0
    );
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn wallet_updates_balances_after_refunds_and_failed_funding_without_network() {
    use nostr_vpn_core::paid_route_store::{
        load_paid_route_store, paid_route_store_file_path, update_paid_route_store,
    };
    let directory =
        std::env::temp_dir().join(format!("nvpn-wallet-balances-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let config_path = directory.join("config.toml");
    let store_path = paid_route_store_file_path(&config_path);
    let wallet = DaemonCashuWallet {
        service: CashuWalletService::open_file_backed(&paid_exit_wallet_data_dir(&config_path))
            .await
            .unwrap(),
    };
    let mint = "http://127.0.0.1:1";
    let proofs = serde_json::json!([{
        "id": "009a1f293253e41e", "amount": 2, "secret": "test-refund",
        "C": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }]);
    wallet
        .execute_and_sync(
            &config_path,
            DaemonCashuWalletCommand::ImportProofs {
                mint_url: mint.into(),
                unit: "sat".into(),
                proofs_json: proofs.to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        load_paid_route_store(&store_path).unwrap().wallet.mints[0].balance_msat,
        Some(2000)
    );
    update_paid_route_store(&store_path, |store| {
        store.upsert_wallet_mint(mint, "Test", Some(10_000), 1);
        Ok(())
    })
    .unwrap();
    let error = wallet
        .execute_and_sync(
            &config_path,
            DaemonCashuWalletCommand::SendToken {
                mint_url: mint.into(),
                amount_sat: 3,
            },
        )
        .await
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<cashu_service::CashuInsufficientFunds>()
            .is_some(),
        "{error:#}"
    );
    assert_eq!(
        load_paid_route_store(&store_path).unwrap().wallet.mints[0].balance_msat,
        Some(2000)
    );
    drop(wallet);
    fs::remove_dir_all(directory).unwrap();
}
