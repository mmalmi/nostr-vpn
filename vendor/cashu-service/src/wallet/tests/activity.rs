use super::*;

#[tokio::test]
async fn test_wallet_activity_pending_topup_syncs_to_complete() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mint_url: MintUrl = "https://mint.example".parse().unwrap();
    let service = CashuWalletService::open_file_backed(temp_dir.path())
        .await
        .unwrap();
    let wallet = ensure_sat_wallet(service.repository(), &mint_url)
        .await
        .unwrap();

    let mut quote = cdk::wallet::MintQuote::new(
        "quote-1".to_string(),
        mint_url.clone(),
        PaymentMethod::BOLT11,
        Some(Amount::from(5_u64)),
        CurrencyUnit::Sat,
        "lnbc5n1p0test".to_string(),
        wallet_activity_now_unix() + 300,
        None,
    );
    quote.state = MintQuoteState::Issued;
    wallet.localstore.add_mint_quote(quote).await.unwrap();

    append_wallet_activity_entry(
        service.localstore().as_ref(),
        CashuWalletActivityEntry {
            id: "entry-topup".to_string(),
            kind: CashuWalletActivityKind::TopUp,
            status: CashuWalletActivityStatus::Pending,
            mint_url: mint_url.to_string(),
            unit: "sat".to_string(),
            amount_sat: 5,
            fee_sat: None,
            created_at_unix: wallet_activity_now_unix(),
            expires_at_unix: Some(wallet_activity_now_unix() + 300),
            quote_id: Some("quote-1".to_string()),
            operation_id: None,
            payment_request: Some("lnbc5n1p0test".to_string()),
            token: None,
        },
    )
    .await
    .unwrap();

    let history = service.load_wallet_activity().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, CashuWalletActivityStatus::Complete);
}

#[tokio::test]
async fn test_wallet_activity_pending_send_syncs_to_complete_without_saga() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mint_url: MintUrl = "https://mint.example".parse().unwrap();
    let service = CashuWalletService::open_file_backed(temp_dir.path())
        .await
        .unwrap();
    ensure_sat_wallet(service.repository(), &mint_url)
        .await
        .unwrap();

    append_wallet_activity_entry(
        service.localstore().as_ref(),
        CashuWalletActivityEntry {
            id: "entry-send".to_string(),
            kind: CashuWalletActivityKind::TokenSend,
            status: CashuWalletActivityStatus::Pending,
            mint_url: mint_url.to_string(),
            unit: "sat".to_string(),
            amount_sat: 3,
            fee_sat: Some(1),
            created_at_unix: wallet_activity_now_unix(),
            expires_at_unix: None,
            quote_id: None,
            operation_id: Some(Uuid::new_v4().to_string()),
            payment_request: None,
            token: Some("cashuBtoken".to_string()),
        },
    )
    .await
    .unwrap();

    let history = service.load_wallet_activity().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, CashuWalletActivityStatus::Complete);
}

