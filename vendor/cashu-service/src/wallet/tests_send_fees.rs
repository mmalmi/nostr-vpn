use super::*;

#[tokio::test]
async fn lightning_withdraw_covers_the_reported_600_sat_fee_boundary() {
    use cdk::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    use cdk_common::bitcoin::hashes::{sha256, Hash};
    use cdk_common::bitcoin::secp256k1::{Secp256k1, SecretKey as InvoiceSecretKey};

    let preimage = [3_u8; 32];
    let invoice = InvoiceBuilder::new(Currency::Bitcoin)
        .description("withdrawal fee regression".to_string())
        .payment_hash(sha256::Hash::hash(&preimage))
        .payment_secret(PaymentSecret([9; 32]))
        .amount_milli_satoshis(600_000)
        .duration_since_epoch(std::time::Duration::from_secs(wallet_activity_now_unix()))
        .expiry_time(std::time::Duration::from_secs(3600))
        .min_final_cltv_expiry_delta(18)
        .build_signed(|message| {
            Secp256k1::new()
                .sign_ecdsa_recoverable(message, &InvoiceSecretKey::from_slice(&[5; 32]).unwrap())
        })
        .unwrap()
        .to_string();
    let mut keyset = build_test_keyset(2048);
    keyset.input_fee_ppk = 150;
    let mint: MintUrl = "https://fee-mint.example".parse().unwrap();
    let db = Arc::new(cdk_sqlite::wallet::memory::empty().await.unwrap());
    db.update_proofs(binary_proof_infos(mint.clone(), keyset.id, 1220), vec![])
        .await
        .unwrap();
    let mut mock = LightningMockMintConnector::new(keyset, "fee-quote", &hex::encode(preimage));
    mock.melt_fee_reserve = 6;
    let mock = Arc::new(mock);
    let wallet = WalletBuilder::new()
        .mint_url(mint)
        .unit(CurrencyUnit::Sat)
        .localstore(db.clone())
        .seed([7; 64])
        .shared_client(mock.clone())
        .build()
        .unwrap();

    let payment = send_lightning_payment_with_wallet(&wallet, &invoice)
        .await
        .unwrap();
    let (input_total, fee) = {
        let inputs = mock.melt_inputs.lock().unwrap();
        (
            inputs
                .iter()
                .map(|proof| proof.amount.to_u64())
                .sum::<u64>(),
            (inputs.len() as u64 * 150).div_ceil(1000),
        )
    };
    assert!(input_total >= 600 + 6 + fee);
    assert_eq!(payment.amount_sat, 600);
    assert_eq!(payment.preimage, hex::encode(preimage));
    assert_eq!(payment.fee_paid_sat, 6 + fee);
    assert_eq!(mock.swap_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        wallet.total_balance().await.unwrap().to_u64(),
        1220 - 600 - 6 - fee
    );
    assert!(wallet.get_reserved_proofs().await.unwrap().is_empty());
}

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
