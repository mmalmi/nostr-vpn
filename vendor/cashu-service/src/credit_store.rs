use cashu_credit::{CreditAccount, CreditError, SnapshotError};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;

const CREATE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credit_account_snapshots (
    account_id TEXT PRIMARY KEY NOT NULL,
    revision BLOB NOT NULL CHECK(length(revision) = 8),
    snapshot_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credit_account_backing_claims (
    issuer TEXT NOT NULL,
    deposit_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    PRIMARY KEY (issuer, deposit_id)
);
";

/// Optional server-side storage for authoritative, versioned credit-account snapshots.
///
/// The accounting schema remains the versioned JSON owned by `cashu-credit`.
/// SQLite contributes durable single-row writes, revision CAS, and a global
/// `(issuer, deposit_id)` binding that prevents one backing operation from being
/// reused across accounts. Other stores can persist the JSON directly but must
/// provide the same atomic backing binding when they hold multiple accounts.
pub struct CreditAccountStore {
    connection: Connection,
}

#[derive(Debug, thiserror::Error)]
pub enum CreditStoreError {
    #[error("credit account id is empty")]
    InvalidAccountId,
    #[error("credit account already exists")]
    AlreadyExists,
    #[error("credit account does not exist")]
    NotFound,
    #[error(
        "credit account snapshot revision {snapshot_revision} does not advance expected revision {expected_revision}"
    )]
    NonMonotonicRevision {
        expected_revision: u64,
        snapshot_revision: u64,
    },
    #[error(
        "credit account CAS failed: expected revision {expected_revision}, stored revision is {actual_revision}"
    )]
    CasConflict {
        expected_revision: u64,
        actual_revision: u64,
    },
    #[error("stored credit account revision is malformed")]
    CorruptStoredRevision,
    #[error(
        "stored credit account revision {stored_revision} does not match snapshot revision {snapshot_revision}"
    )]
    SnapshotRevisionMismatch {
        stored_revision: u64,
        snapshot_revision: u64,
    },
    #[error(
        "backing operation {issuer}/{deposit_id} is already claimed by account {claimed_account_id}"
    )]
    BackingClaimConflict {
        issuer: String,
        deposit_id: String,
        claimed_account_id: String,
    },
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Credit(#[from] CreditError),
}

impl CreditAccountStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CreditStoreError> {
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, CreditStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, CreditStoreError> {
        connection.execute_batch(CREATE_SCHEMA)?;
        Ok(Self { connection })
    }

    /// Atomically create one account row containing its authoritative snapshot.
    pub fn create(
        &mut self,
        account_id: &str,
        account: &CreditAccount,
    ) -> Result<(), CreditStoreError> {
        validate_account_id(account_id)?;
        let snapshot = account.snapshot();
        let encoded = snapshot.encode_json()?;
        let revision = revision_bytes(snapshot.revision());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO credit_account_snapshots
             (account_id, revision, snapshot_json) VALUES (?1, ?2, ?3)",
            params![account_id, revision.as_slice(), encoded],
        )?;
        if inserted == 0 {
            return Err(CreditStoreError::AlreadyExists);
        }
        bind_backing_deposits(&transaction, account_id, account)?;
        transaction.commit()?;
        Ok(())
    }

    /// Load and validate the opaque JSON before returning an account.
    pub fn load(&self, account_id: &str) -> Result<Option<CreditAccount>, CreditStoreError> {
        validate_account_id(account_id)?;
        let stored: Option<(Vec<u8>, String)> = self
            .connection
            .query_row(
                "SELECT revision, snapshot_json FROM credit_account_snapshots WHERE account_id = ?1",
                [account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((revision, encoded)) = stored else {
            return Ok(None);
        };
        let stored_revision = decode_revision(&revision)?;
        let snapshot = cashu_credit::CreditAccountSnapshotV1::decode_json(&encoded)?;
        if snapshot.revision() != stored_revision {
            return Err(CreditStoreError::SnapshotRevisionMismatch {
                stored_revision,
                snapshot_revision: snapshot.revision(),
            });
        }
        Ok(Some(CreditAccount::from_snapshot(snapshot)?))
    }

    /// Replace one row only when its stored revision equals `expected_revision`.
    pub fn save(
        &mut self,
        account_id: &str,
        expected_revision: u64,
        account: &CreditAccount,
    ) -> Result<(), CreditStoreError> {
        validate_account_id(account_id)?;
        if account.revision() <= expected_revision {
            return Err(CreditStoreError::NonMonotonicRevision {
                expected_revision,
                snapshot_revision: account.revision(),
            });
        }
        let snapshot = account.snapshot();
        let encoded = snapshot.encode_json()?;
        let expected = revision_bytes(expected_revision);
        let next = revision_bytes(snapshot.revision());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE credit_account_snapshots
             SET revision = ?1, snapshot_json = ?2
             WHERE account_id = ?3 AND revision = ?4",
            params![next.as_slice(), encoded, account_id, expected.as_slice()],
        )?;
        if updated == 0 {
            return match load_revision(&transaction, account_id)? {
                Some(actual_revision) => Err(CreditStoreError::CasConflict {
                    expected_revision,
                    actual_revision,
                }),
                None => Err(CreditStoreError::NotFound),
            };
        }
        bind_backing_deposits(&transaction, account_id, account)?;
        transaction.commit()?;
        Ok(())
    }
}

fn bind_backing_deposits(
    transaction: &Transaction<'_>,
    account_id: &str,
    account: &CreditAccount,
) -> Result<(), CreditStoreError> {
    for deposit in account.backing_deposits() {
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO credit_account_backing_claims
             (issuer, deposit_id, account_id) VALUES (?1, ?2, ?3)",
            params![deposit.issuer, deposit.deposit_id, account_id],
        )?;
        if inserted == 1 {
            continue;
        }
        let claimed_account_id: String = transaction.query_row(
            "SELECT account_id FROM credit_account_backing_claims
             WHERE issuer = ?1 AND deposit_id = ?2",
            params![deposit.issuer, deposit.deposit_id],
            |row| row.get(0),
        )?;
        if claimed_account_id != account_id {
            return Err(CreditStoreError::BackingClaimConflict {
                issuer: deposit.issuer.clone(),
                deposit_id: deposit.deposit_id.clone(),
                claimed_account_id,
            });
        }
    }
    Ok(())
}

fn load_revision(
    connection: &Connection,
    account_id: &str,
) -> Result<Option<u64>, CreditStoreError> {
    let revision: Option<Vec<u8>> = connection
        .query_row(
            "SELECT revision FROM credit_account_snapshots WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )
        .optional()?;
    revision.map(|bytes| decode_revision(&bytes)).transpose()
}

fn validate_account_id(account_id: &str) -> Result<(), CreditStoreError> {
    if account_id.trim().is_empty() {
        return Err(CreditStoreError::InvalidAccountId);
    }
    Ok(())
}

fn revision_bytes(revision: u64) -> [u8; 8] {
    revision.to_be_bytes()
}

fn decode_revision(encoded: &[u8]) -> Result<u64, CreditStoreError> {
    let bytes: [u8; 8] = encoded
        .try_into()
        .map_err(|_| CreditStoreError::CorruptStoredRevision)?;
    Ok(u64::from_be_bytes(bytes))
}
