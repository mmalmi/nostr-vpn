#![cfg(feature = "credit-store")]

use cashu_credit::{
    AcceptanceMode, AccountPolicy, BackingDeposit, CreditAccount, IssuerPolicy,
    ServiceReceiptClaim, ValueClass,
};
use cashu_service::{CreditAccountStore, CreditStoreError};

const NOW: u64 = 1_000;

fn account_for(counterparty: &str) -> CreditAccount {
    CreditAccount::new(AccountPolicy {
        counterparty: counterparty.into(),
        max_total_peer_credit_sat: 100,
        issuers: vec![IssuerPolicy {
            issuer: "alice".into(),
            max_peer_credit_sat: 100,
            max_offline_peer_credit_sat: 10,
            max_closed_loop_sat: 100,
            max_withdrawable_sat: 100,
            expires_at_unix: None,
        }],
    })
    .unwrap()
}

fn account() -> CreditAccount {
    account_for("bob")
}

fn receipt(id: &str, amount_sat: u64) -> ServiceReceiptClaim {
    ServiceReceiptClaim {
        receipt_id: id.into(),
        issuer: "alice".into(),
        counterparty: "bob".into(),
        service: "pubsub_delivery".into(),
        resource: "fsp:destination:service:budget".into(),
        useful_service_units: 4_096,
        amount_sat,
        value_class: ValueClass::PeerCredit,
        issued_at_unix: NOW - 1,
        expires_at_unix: NOW + 10,
    }
}

#[test]
fn sqlite_store_creates_loads_and_reopens_one_opaque_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("credit.sqlite");
    let mut expected = account();
    expected
        .apply_receipt(
            &receipt("receipt", 10),
            "alice",
            AcceptanceMode::Online,
            NOW,
        )
        .unwrap();

    {
        let mut store = CreditAccountStore::open(&path).unwrap();
        assert!(store.load("bob-account").unwrap().is_none());
        store.create("bob-account", &expected).unwrap();
        assert!(matches!(
            store.create("bob-account", &expected),
            Err(CreditStoreError::AlreadyExists)
        ));
    }

    let reopened = CreditAccountStore::open(&path).unwrap();
    assert_eq!(reopened.load("bob-account").unwrap(), Some(expected));
}

#[test]
fn sqlite_store_compare_and_swap_rejects_stale_writer() {
    let mut store = CreditAccountStore::open_in_memory().unwrap();
    store.create("bob-account", &account()).unwrap();
    let mut first = store.load("bob-account").unwrap().unwrap();
    let mut stale = first.clone();

    first
        .apply_receipt(&receipt("first", 10), "alice", AcceptanceMode::Online, NOW)
        .unwrap();
    stale
        .apply_receipt(&receipt("stale", 20), "alice", AcceptanceMode::Online, NOW)
        .unwrap();
    store.save("bob-account", 0, &first).unwrap();

    assert!(matches!(
        store.save("bob-account", 0, &stale),
        Err(CreditStoreError::CasConflict {
            expected_revision: 0,
            actual_revision: 1,
        })
    ));
    assert_eq!(
        store
            .load("bob-account")
            .unwrap()
            .unwrap()
            .peer_credit("alice")
            .unwrap()
            .outstanding_sat(),
        10
    );
}

#[test]
fn sqlite_store_rejects_empty_ids_missing_rows_and_non_monotonic_saves() {
    let mut store = CreditAccountStore::open_in_memory().unwrap();
    let account = account();
    assert!(matches!(
        store.create(" ", &account),
        Err(CreditStoreError::InvalidAccountId)
    ));
    assert!(matches!(
        store.save("missing", 0, &account),
        Err(CreditStoreError::NonMonotonicRevision {
            expected_revision: 0,
            snapshot_revision: 0,
        })
    ));
    store.create("bob-account", &account).unwrap();
    assert!(matches!(
        store.save("bob-account", 0, &account),
        Err(CreditStoreError::NonMonotonicRevision {
            expected_revision: 0,
            snapshot_revision: 0,
        })
    ));

    let mut advanced = account.clone();
    advanced
        .apply_receipt(&receipt("advance", 1), "alice", AcceptanceMode::Online, NOW)
        .unwrap();
    assert!(matches!(
        store.save("missing", 0, &advanced),
        Err(CreditStoreError::NotFound)
    ));
}

#[test]
fn sqlite_store_binds_one_backing_operation_to_one_account_atomically() {
    let mut store = CreditAccountStore::open_in_memory().unwrap();
    let backing = BackingDeposit {
        deposit_id: "shared-proof".into(),
        issuer: "alice".into(),
        amount_sat: 25,
        value_class: ValueClass::ReserveBackedWithdrawable,
    };

    let mut bob = account_for("bob");
    bob.record_backing_deposit(&backing, "alice").unwrap();
    store.create("bob-account", &bob).unwrap();

    let mut carol = account_for("carol");
    carol.record_backing_deposit(&backing, "alice").unwrap();
    assert!(matches!(
        store.create("carol-account", &carol),
        Err(CreditStoreError::BackingClaimConflict {
            issuer,
            deposit_id,
            claimed_account_id,
        }) if issuer == "alice"
            && deposit_id == "shared-proof"
            && claimed_account_id == "bob-account"
    ));
    assert!(store.load("carol-account").unwrap().is_none());

    store
        .create("carol-account", &account_for("carol"))
        .unwrap();
    assert!(matches!(
        store.save("carol-account", 0, &carol),
        Err(CreditStoreError::BackingClaimConflict { .. })
    ));
    let stored_carol = store.load("carol-account").unwrap().unwrap();
    assert_eq!(stored_carol.revision(), 0);
    assert_eq!(
        stored_carol
            .sat_reserve("alice")
            .unwrap()
            .total_deposited_sat(),
        0
    );

    bob.apply_receipt(
        &receipt("same-account-replay", 1),
        "alice",
        AcceptanceMode::Online,
        NOW,
    )
    .unwrap();
    store.save("bob-account", 1, &bob).unwrap();
}
