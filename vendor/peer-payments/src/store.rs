use crate::{book::MAX_STATE_BYTES, Book, Buyer, Error};
use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::path::Path;

/// One owner per account. SQLite serializes competing writers; revision CAS
/// prevents a stale process from duplicating allowance. A failed transaction
/// never publishes either its financial state or its returned service grant.
pub trait DurableState: Clone {
    fn owner(&self) -> &str;
    fn revision(&self) -> u64;
    fn encode(&self) -> Result<String, Error>;
    fn decode(encoded: &str) -> Result<Self, Error>;
    fn revoke_allowances(&self) {}
}

macro_rules! durable_state {
    ($state:ty, $identity:ident) => {
        impl DurableState for $state {
            fn owner(&self) -> &str {
                self.$identity()
            }
            fn revision(&self) -> u64 {
                self.revision()
            }
            fn encode(&self) -> Result<String, Error> {
                self.encode()
            }
            fn decode(encoded: &str) -> Result<Self, Error> {
                Self::decode(encoded)
            }
        }
    };
}
durable_state!(Buyer, payer);

impl DurableState for Book {
    fn owner(&self) -> &str {
        self.provider()
    }
    fn revision(&self) -> u64 {
        self.revision()
    }
    fn encode(&self) -> Result<String, Error> {
        self.encode()
    }
    fn decode(json: &str) -> Result<Self, Error> {
        Self::decode(json)
    }
    fn revoke_allowances(&self) {
        self.revoke_all();
    }
}

pub type PaymentStore = Journal<Book>;
pub type BuyerStore = Journal<Buyer>;
pub type AccountStore = Journal<crate::Account>;

pub struct Journal<S: DurableState> {
    connection: Connection,
    book: S,
    _owner: std::fs::File,
}

impl<S: DurableState> Drop for Journal<S> {
    fn drop(&mut self) {
        self.book.revoke_allowances();
    }
}

impl<S: DurableState> Journal<S> {
    pub fn create(path: impl AsRef<Path>, book: S) -> Result<Self, Error> {
        let path = path.as_ref();
        let encoded = book.encode()?;
        S::decode(&encoded)?;
        // Never initialize into another owner's file or overwrite recovery state.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(path)?);
        let owner = owner_lock(path, true)?;
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&connection)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS peer_payment_book (
            id INTEGER PRIMARY KEY CHECK(id=1), revision BLOB NOT NULL CHECK(length(revision)=8),
            state TEXT NOT NULL)",
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO peer_payment_book VALUES (1,?1,?2)",
            params![book.revision().to_be_bytes().as_slice(), encoded],
        )?;
        if inserted != 1 {
            return Err(Error::StoreConflict);
        }
        tx.commit()?;
        Ok(Self {
            connection,
            book,
            _owner: owner,
        })
    }

    /// Missing or corrupt state is an error; reopening never creates an account.
    pub fn open(path: impl AsRef<Path>, provider: &str) -> Result<Self, Error> {
        let metadata = std::fs::symlink_metadata(path.as_ref())?;
        if !metadata.is_file() {
            return Err(Error::Invalid("database file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                return Err(Error::Invalid("database permissions"));
            }
        }
        let owner = owner_lock(path.as_ref(), false)?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&connection)?;
        let book = load::<S>(&connection)?;
        if book.owner() != provider {
            return Err(Error::StoreConflict);
        }
        Ok(Self {
            connection,
            book,
            _owner: owner,
        })
    }

    pub fn book(&self) -> &S {
        &self.book
    }

    pub fn transact<T>(
        &mut self,
        change: impl FnOnce(&mut S) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut candidate = self.book.clone();
        let result = change(&mut candidate)?;
        let encoded = candidate.encode()?;
        // Validate the same authoritative representation used during recovery.
        S::decode(&encoded)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE peer_payment_book SET revision=?1,state=?2 WHERE id=1 AND revision=?3",
            params![
                candidate.revision().to_be_bytes().as_slice(),
                encoded,
                self.book.revision().to_be_bytes().as_slice()
            ],
        )?;
        if updated != 1 {
            return Err(Error::StoreConflict);
        }
        tx.commit()?;
        self.book = candidate;
        Ok(result)
    }
}

fn configure(connection: &Connection) -> Result<(), Error> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(std::time::Duration::from_secs(1))?;
    Ok(())
}

// Separate from SQLite's own platform-specific byte-range locks. Keep the file
// permanently: unlinking it could let two processes lock different inodes.
fn owner_lock(path: &Path, create: bool) -> Result<std::fs::File, Error> {
    let mut name = path.as_os_str().to_owned();
    name.push(".owner");
    let path = std::path::PathBuf::from(name);
    if !create && !std::fs::symlink_metadata(&path)?.is_file() {
        return Err(Error::Invalid("owner lock file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(Error::Invalid("owner lock permissions"));
        }
    }
    file.try_lock_exclusive()?;
    Ok(file)
}

fn load<S: DurableState>(connection: &Connection) -> Result<S, Error> {
    let row: Option<(Vec<u8>, Option<String>)> = connection
        .query_row(
            "SELECT revision, CASE WHEN length(CAST(state AS BLOB))<=?1 THEN state ELSE NULL END
         FROM peer_payment_book WHERE id=1",
            [MAX_STATE_BYTES],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (revision, encoded) = row.ok_or(Error::StoreConflict)?;
    let book = S::decode(&encoded.ok_or(Error::Limit)?)?;
    if revision != book.revision().to_be_bytes() {
        return Err(Error::StoreConflict);
    }
    Ok(book)
}
