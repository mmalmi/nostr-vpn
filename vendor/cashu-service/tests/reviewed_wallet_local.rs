#![cfg(feature = "wallet")]
//! Explicit owned CDK FakeWallet acceptance. Never contacts a public mint.
use cashu_service::{CashuWalletSeedStore, CashuWalletService, FileCashuWalletSeedStore};
use std::str::FromStr;

#[tokio::test]
#[ignore = "requires explicitly started owned local CDK FakeWallet mint"]
async fn reviewed_send_restart_redeem_reclaim_and_backup() {
    tokio::time::timeout(std::time::Duration::from_secs(240), run_owned_flow())
        .await
        .expect("owned mint flow timed out");
}
async fn run_owned_flow() {
    let mint = std::env::var("CASHU_OWNED_TEST_MINT").expect("owned local mint URL required");
    let parsed = url::Url::parse(&mint).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert!(parsed.port().is_some() && parsed.path() == "/" && parsed.query().is_none());
    let source = tempfile::tempdir().unwrap();
    let receiver = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let service = CashuWalletService::open_file_backed(source.path())
        .await
        .unwrap();
    service.create_topup_quote(&mint, 256).await.unwrap();
    for _ in 0..50 {
        service.load_wallet_overview(true).await.unwrap();
        if service.load_mint_balance(&mint).await.unwrap().balance_sat > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    eprintln!("stage: funded");
    let review = service
        .preview_payment_token_reviewed(&mint, 128, "order:local")
        .await
        .unwrap();
    eprintln!("stage: reviewed");
    let payment = service
        .send_payment_token_reviewed(&mint, 128, review.fee_sat, "order:local")
        .await
        .unwrap();
    assert_eq!(
        cdk::nuts::Token::from_str(&payment.token)
            .unwrap()
            .value()
            .unwrap()
            .to_u64(),
        128
    );
    eprintln!("stage: sent");
    drop(service);
    let service = CashuWalletService::open_file_backed(source.path())
        .await
        .unwrap();
    eprintln!("stage: reopened");
    let retry = service
        .send_payment_token_reviewed(&mint, 128, review.fee_sat, "order:local")
        .await
        .unwrap();
    assert_eq!(retry.token, payment.token);
    eprintln!("stage: retry-same-token");
    let recipient = CashuWalletService::open_file_backed(receiver.path())
        .await
        .unwrap();
    assert!(
        recipient
            .receive_payment_token(&payment.token)
            .await
            .unwrap()
            .amount_sat
            > 0
    );
    assert!(recipient
        .receive_payment_token(&payment.token)
        .await
        .is_err());
    eprintln!("stage: redeemed");
    let reclaim_review = service
        .preview_payment_token_reviewed(&mint, 16, "order:reclaim")
        .await
        .unwrap();
    eprintln!("stage: reclaim-reviewed");
    let reclaim = service
        .send_payment_token_reviewed(&mint, 16, reclaim_review.fee_sat, "order:reclaim")
        .await
        .unwrap();
    assert!(
        service
            .revoke_pending_payment(&mint, &reclaim.operation_id)
            .await
            .unwrap()
            > 0
    );
    assert!(service
        .send_payment_token_reviewed(&mint, 16, reclaim_review.fee_sat, "order:reclaim")
        .await
        .is_err());
    // Explicit reviewed Lightning operation against this same owned FakeWallet backend.
    eprintln!("stage: reclaimed");
    let invoice = std::env::var("CASHU_OWNED_TEST_INVOICE")
        .expect("invoice from second owned FakeWallet mint required");
    eprintln!("stage: invoice-created");
    let lightning = service
        .preview_lightning_payment_reviewed(&mint, &invoice)
        .await
        .unwrap();
    eprintln!("stage: lightning-reviewed");
    let mut attempts = 0;
    let paid = loop {
        match service
            .confirm_lightning_payment_reviewed(&mint, &lightning.quote_id, lightning.fee_sat)
            .await
        {
            Ok(result) => break result,
            Err(error)
                if error
                    .to_string()
                    .starts_with("Lightning payment is pending")
                    && attempts < 2 =>
            {
                attempts += 1;
                eprintln!("stage: retry-original-pending-lightning");
            }
            Err(error) => panic!("owned Lightning confirm failed: {error}"),
        }
    };
    assert_eq!(paid.state, "paid");
    let retried = service
        .confirm_lightning_payment_reviewed(&mint, &lightning.quote_id, lightning.fee_sat)
        .await
        .unwrap();
    assert_eq!(retried.operation_id, paid.operation_id);
    eprintln!("stage: lightning-paid");
    let snapshot = service.export_wallet_database().await.unwrap();
    let seed = FileCashuWalletSeedStore::for_data_dir(source.path())
        .load_seed()
        .unwrap()
        .unwrap();
    std::fs::create_dir_all(cashu_service::cashu_wallet_dir(target.path())).unwrap();
    FileCashuWalletSeedStore::for_data_dir(target.path())
        .store_seed(&seed)
        .unwrap();
    cashu_service::restore_wallet_database(target.path(), &snapshot).unwrap();
    let restored = CashuWalletService::open_file_backed(target.path())
        .await
        .unwrap();
    assert!(restored.restored_review_required());
    assert!(restored
        .send_payment_token_reviewed(&mint, 1, 5, "blocked")
        .await
        .is_err());
    eprintln!("stage: restored");
    restored.review_restored_wallet().await.unwrap();
    assert_eq!(
        restored.load_mint_balance(&mint).await.unwrap().balance_sat,
        service.load_mint_balance(&mint).await.unwrap().balance_sat
    );
    assert!(restored
        .send_payment_token_reviewed(&mint, 16, reclaim_review.fee_sat, "order:reclaim")
        .await
        .is_err());
}
