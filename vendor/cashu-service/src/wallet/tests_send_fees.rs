use super::*;

#[tokio::test]
async fn payment_token_covers_recipient_fees_with_fragmented_wallet_proofs() {
    use cdk::nuts::Token;
    for denomination in [1, 2, 4, 8, 16, 32] {
        let mut keyset = build_test_keyset(128);
        keyset.input_fee_ppk = 400;
        let mint: MintUrl = "https://fee-mint.example".parse().unwrap();
        let db = Arc::new(cdk_sqlite::wallet::memory::empty().await.unwrap());
        let mut proofs: Vec<_> = (0..32 / denomination)
            .map(|_| make_proof_info(keyset.id, denomination, mint.clone()))
            .collect();
        proofs.push(make_proof_info(keyset.id, 32, mint.clone()));
        db.update_proofs(proofs, vec![]).await.unwrap();
        let mock = LightningMockMintConnector::new(keyset.clone(), "quote", "00");
        let wallet = WalletBuilder::new()
            .mint_url(mint)
            .unit(CurrencyUnit::Sat)
            .localstore(db)
            .seed([7; 64])
            .client(mock)
            .build()
            .unwrap();
        refresh_active_keyset_id(&wallet).await.unwrap();
        let token: Token = super::super::send::prepare_payment_token(&wallet, 14, 64)
            .await
            .unwrap()
            .0
            .confirm(None)
            .await
            .unwrap();
        let proofs = token
            .proofs(&[KeySetInfo {
                id: keyset.id,
                unit: CurrencyUnit::Sat,
                active: true,
                input_fee_ppk: 400,
                final_expiry: None,
            }])
            .unwrap();
        let nominal: u64 = proofs.iter().map(|p| p.amount.to_u64()).sum();
        let fee = (proofs.len() as u64 * 400).div_ceil(1000);
        assert!(
            nominal - fee >= 14,
            "denomination {denomination}: {nominal} sat across {} proofs leaves {} sat",
            proofs.len(),
            nominal - fee
        );
    }
}
