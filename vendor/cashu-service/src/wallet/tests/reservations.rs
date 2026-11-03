use super::super::reservations::recover_orphaned_reservations;
use super::*;
use cdk::nuts::ProofState;

async fn fixture(
    unit: CurrencyUnit,
) -> (
    tempfile::TempDir,
    CashuWalletService,
    cdk::Wallet,
    Arc<LightningMockMintConnector>,
    Id,
) {
    let directory = tempfile::tempdir().unwrap();
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    let mut keyset = build_test_keyset(2048);
    keyset.unit = unit.clone();
    let id = keyset.id;
    let mint: MintUrl = "https://reservation-mint.example".parse().unwrap();
    let mock = Arc::new(LightningMockMintConnector::new(keyset, "quote", "00"));
    let wallet = WalletBuilder::new()
        .mint_url(mint)
        .unit(unit)
        .localstore(service.localstore().clone())
        .seed([7; 64])
        .shared_client(mock.clone())
        .build()
        .unwrap();
    (directory, service, wallet, mock, id)
}

fn reserved(id: Id, amount: u64, wallet: &cdk::Wallet) -> ProofInfo {
    let mut proof = make_proof_info(id, amount, wallet.mint_url.clone());
    proof.state = State::Reserved;
    proof
}

fn legacy(id: Id, wallet: &cdk::Wallet) -> ProofInfo {
    let mut proof = make_test_proof(id, 256);
    proof.secret = Secret::new(
        serde_json::json!(["P2PK", {
            "nonce": "legacy-reservation",
            "data": SecretKey::generate().public_key().to_hex(), "tags": null
        }])
        .to_string(),
    );
    ProofInfo::new(
        proof,
        wallet.mint_url.clone(),
        State::Reserved,
        CurrencyUnit::Sat,
    )
    .unwrap()
}

fn mint_state(proof: &ProofInfo, state: State) -> ProofState {
    ProofState {
        y: proof.y,
        state,
        witness: None,
    }
}

#[tokio::test]
async fn normal_wallet_poll_recovers_the_reported_607_sat_reservation() {
    let (_directory, service, wallet, mock, id) = fixture(CurrencyUnit::Sat).await;
    let mut proofs = binary_proof_infos(wallet.mint_url.clone(), id, 607);
    assert_eq!(proofs.len(), 7);
    for proof in &mut proofs {
        proof.state = State::Reserved;
    }
    proofs.extend(binary_proof_infos(wallet.mint_url.clone(), id, 613));
    wallet
        .localstore
        .update_proofs(proofs, vec![])
        .await
        .unwrap();
    assert_eq!(wallet.total_balance().await.unwrap().to_u64(), 613);

    let _guard = service.lock_operation().await;
    let report = service.refresh_pending_wallet(&wallet).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(
        report.recovered_reserved_amounts,
        std::collections::BTreeMap::from([("sat".to_string(), 607)])
    );
    assert_eq!(wallet.total_balance().await.unwrap().to_u64(), 1220);
    assert!(wallet.get_reserved_proofs().await.unwrap().is_empty());

    // A newly discovered reservation must still respect the shared mint poll
    // interval; recovery must not introduce a new polling loop.
    let additional = reserved(id, 8, &wallet);
    wallet
        .localstore
        .update_proofs(vec![additional.clone()], vec![])
        .await
        .unwrap();
    let next = service.refresh_pending_wallet(&wallet).await.unwrap();
    assert!(next.recovered_reserved_amounts.is_empty());
    assert_eq!(mock.check_requests.lock().unwrap().len(), 1);
    let stored = wallet
        .localstore
        .get_proofs_by_ys(vec![additional.y])
        .await
        .unwrap();
    assert_eq!(stored[0].state, State::Reserved);
}

#[tokio::test]
async fn recovery_preserves_exports_active_operations_legacy_refunds_and_other_wallets() {
    let (_directory, service, wallet, mock, id) = fixture(CurrencyUnit::Sat).await;
    let unspent = reserved(id, 8, &wallet);
    let spent = reserved(id, 16, &wallet);
    let pending = reserved(id, 32, &wallet);
    let mut owned = reserved(id, 64, &wallet);
    owned.used_by_operation = Some(Uuid::new_v4());
    let mut exported = reserved(id, 128, &wallet);
    exported.state = State::PendingSpent;
    let held = legacy(id, &wallet);
    let ordinary = make_proof_info(id, 512, wallet.mint_url.clone());
    let mut other_mint = reserved(id, 1024, &wallet);
    other_mint.mint_url = "https://other-mint.example".parse().unwrap();
    let mut other_unit = reserved(id, 2, &wallet);
    other_unit.unit = CurrencyUnit::Msat;
    let originals = vec![
        unspent.clone(),
        spent.clone(),
        pending.clone(),
        owned,
        exported,
        held,
        ordinary,
        other_mint,
        other_unit,
    ];
    wallet
        .localstore
        .update_proofs(originals.clone(), vec![])
        .await
        .unwrap();
    *mock.check_response.lock().unwrap() = Some(vec![
        mint_state(&unspent, State::Unspent),
        mint_state(&spent, State::Spent),
        mint_state(&pending, State::Pending),
    ]);

    let _guard = service.lock_operation().await;
    assert_eq!(recover_orphaned_reservations(&wallet).await.unwrap(), 8);
    let stored = wallet
        .localstore
        .get_proofs_by_ys(originals.iter().map(|p| p.y).collect())
        .await
        .unwrap();
    assert_eq!(stored.len(), originals.len());
    for original in originals {
        let current = stored.iter().find(|p| p.y == original.y).unwrap();
        let expected = if original.y == unspent.y {
            State::Unspent
        } else if original.y == spent.y {
            State::Spent
        } else {
            original.state
        };
        assert_eq!(current.state, expected);
        assert_eq!(current.used_by_operation, original.used_by_operation);
        assert_eq!(current.proof, original.proof);
    }
    let requested: std::collections::HashSet<_> = mock.check_requests.lock().unwrap()[0]
        .iter()
        .copied()
        .collect();
    assert_eq!(
        requested,
        [unspent.y, spent.y, pending.y].into_iter().collect()
    );
    *mock.check_response.lock().unwrap() = Some(vec![mint_state(&pending, State::Unspent)]);
    assert_eq!(recover_orphaned_reservations(&wallet).await.unwrap(), 32);
    assert_eq!(recover_orphaned_reservations(&wallet).await.unwrap(), 0);
    assert_eq!(mock.check_requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn incomplete_duplicate_unrelated_invalid_and_failed_mint_checks_change_nothing() {
    for mode in ["missing", "duplicate", "unrelated", "invalid", "offline"] {
        let (_directory, service, wallet, mock, id) = fixture(CurrencyUnit::Sat).await;
        let orphan = reserved(id, 8, &wallet);
        let other = make_proof_info(id, 16, wallet.mint_url.clone());
        wallet
            .localstore
            .update_proofs(vec![orphan.clone(), other.clone()], vec![])
            .await
            .unwrap();
        let response = match mode {
            "missing" => vec![],
            "duplicate" => vec![
                mint_state(&orphan, State::Unspent),
                mint_state(&orphan, State::Spent),
            ],
            "unrelated" => vec![
                mint_state(&orphan, State::Unspent),
                mint_state(&other, State::Spent),
            ],
            "invalid" => vec![mint_state(&orphan, State::Reserved)],
            _ => {
                mock.fail_check_state
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                vec![]
            }
        };
        *mock.check_response.lock().unwrap() = Some(response);
        let _guard = service.lock_operation().await;
        assert!(
            recover_orphaned_reservations(&wallet).await.is_err(),
            "{mode}"
        );
        let stored = wallet
            .localstore
            .get_proofs_by_ys(vec![orphan.y, other.y])
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(
            stored.iter().find(|p| p.y == orphan.y).unwrap().state,
            State::Reserved,
            "{mode}"
        );
        assert_eq!(
            stored.iter().find(|p| p.y == other.y).unwrap().state,
            State::Unspent,
            "{mode}"
        );
    }
}

#[tokio::test]
async fn mint_failure_retains_reservations_and_uses_existing_backoff() {
    let (_directory, service, wallet, mock, id) = fixture(CurrencyUnit::Sat).await;
    let orphan = reserved(id, 8, &wallet);
    wallet
        .localstore
        .update_proofs(vec![orphan.clone()], vec![])
        .await
        .unwrap();
    mock.fail_check_state
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let _guard = service.lock_operation().await;
    let failed = service.refresh_pending_wallet(&wallet).await.unwrap();
    assert!(failed.recovered_reserved_amounts.is_empty());
    assert_eq!(failed.warnings.len(), 1);
    mock.fail_check_state
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let deferred = service.refresh_pending_wallet(&wallet).await.unwrap();
    assert!(deferred.recovered_reserved_amounts.is_empty());
    assert_eq!(mock.check_requests.lock().unwrap().len(), 1);
    assert_eq!(
        wallet
            .localstore
            .get_proofs_by_ys(vec![orphan.y])
            .await
            .unwrap()[0]
            .state,
        State::Reserved
    );
}

#[tokio::test]
async fn protected_or_exported_proofs_do_not_trigger_a_mint_request() {
    let (_directory, service, wallet, mock, id) = fixture(CurrencyUnit::Sat).await;
    let mut owned = reserved(id, 8, &wallet);
    owned.used_by_operation = Some(Uuid::new_v4());
    let mut exported = reserved(id, 16, &wallet);
    exported.state = State::PendingSpent;
    wallet
        .localstore
        .update_proofs(vec![owned, exported, legacy(id, &wallet)], vec![])
        .await
        .unwrap();
    let _guard = service.lock_operation().await;
    assert_eq!(recover_orphaned_reservations(&wallet).await.unwrap(), 0);
    assert!(mock.check_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reservation_recovery_reports_millisats_in_their_own_unit() {
    let (_directory, service, wallet, _mock, id) = fixture(CurrencyUnit::Msat).await;
    let mut proof = reserved(id, 8, &wallet);
    proof.unit = CurrencyUnit::Msat;
    wallet
        .localstore
        .update_proofs(vec![proof], vec![])
        .await
        .unwrap();
    let _guard = service.lock_operation().await;
    let report = service.refresh_pending_wallet(&wallet).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(
        report.recovered_reserved_amounts,
        std::collections::BTreeMap::from([("msat".to_string(), 8)])
    );
    assert_eq!(wallet.total_balance().await.unwrap().to_u64(), 8);
}
