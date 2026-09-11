use std::sync::RwLock;

use super::*;

// ============================================================================
// MemoryStorage
// ============================================================================

/// Thread-safe in-memory storage using `RwLock<HashMap>`.
#[derive(Default)]
pub struct MemoryStorage {
    funding: RwLock<HashMap<ChannelId, ChannelFunding>>,
    balance: RwLock<HashMap<ChannelId, PaymentProof>>,
    usage: RwLock<HashMap<ChannelId, UsageMap>>,
    closing: RwLock<HashMap<ChannelId, ClosingData>>,
    closed: RwLock<HashMap<ChannelId, ClosedDataView>>,
    keysets: RwLock<HashMap<(String, Id), KeysetCacheEntry>>,
}

impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage").finish_non_exhaustive()
    }
}

impl MemoryStorage {
    /// Create a new, empty in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SpilmanStorage for MemoryStorage {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.funding
            .read()
            .expect("funding lock")
            .get(channel_id)
            .cloned()
    }

    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String> {
        let mut store = self.funding.write().expect("funding lock");
        if !store.contains_key(channel_id) {
            store.insert(channel_id.to_string(), funding);
        }
        Ok(())
    }

    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.balance
            .read()
            .expect("balance lock")
            .get(channel_id)
            .cloned()
    }

    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String> {
        let mut store = self.balance.write().expect("balance lock");
        let should_update = store
            .get(channel_id)
            .map(|b| payment.balance > b.balance)
            .unwrap_or(true);
        if should_update {
            store.insert(channel_id.to_string(), payment);
        }
        Ok(())
    }

    fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        let store = self.usage.read().expect("usage lock");
        let map = store.get(channel_id)?;
        if map.is_empty() {
            None
        } else {
            Some(map.clone())
        }
    }

    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String> {
        let mut store = self.usage.write().expect("usage lock");
        let usage = store.entry(channel_id.to_string()).or_default();
        for (var, delta) in increments {
            *usage.entry(var.clone()).or_insert(0) += delta;
        }
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> ChannelState {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            ChannelState::Closed
        } else if self
            .closing
            .read()
            .expect("closing lock")
            .contains_key(channel_id)
        {
            ChannelState::Closing
        } else {
            ChannelState::Open
        }
    }

    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String> {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        self.closing
            .write()
            .expect("closing lock")
            .insert(channel_id.to_string(), closing);
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.closing
            .read()
            .expect("closing lock")
            .get(channel_id)
            .cloned()
    }

    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String> {
        if self
            .closed
            .read()
            .expect("closed lock")
            .contains_key(channel_id)
        {
            return Err("channel already closed".to_string());
        }
        // Insert into closed before removing from closing, so that
        // get_state (which checks closed first) never sees the channel
        // in neither store and briefly reports it as Open.
        self.closed
            .write()
            .expect("closed lock")
            .insert(channel_id.to_string(), data);
        self.closing
            .write()
            .expect("closing lock")
            .remove(channel_id);
        Ok(())
    }

    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.closed
            .read()
            .expect("closed lock")
            .get(channel_id)
            .cloned()
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        self.keysets
            .read()
            .expect("keysets lock")
            .get(&(mint.to_string(), *keyset_id))
            .cloned()
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String> {
        self.keysets
            .write()
            .expect("keysets lock")
            .insert((mint.to_string(), keyset_id), entry);
        Ok(())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        // There is no requirement that this be 'up-to-date'. So this is
        // the set of keysets were active the last time the server updated
        // its records of the keysets
        self.keysets
            .read()
            .expect("keysets lock")
            .iter()
            .filter(|((m, _), entry)| m == mint && entry.unit == *unit && entry.active)
            .map(|((_, kid), _)| *kid)
            .collect()
    }

    /// Returns `{ mint_url: { unit: [keyset_id, …] } }` for all active keysets.
    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let store = self.keysets.read().expect("keysets lock");
        for ((mint, keyset_id), entry) in store.iter() {
            if !entry.active {
                continue;
            }
            result
                .entry(mint.clone())
                .or_default()
                .entry(entry.unit.to_string())
                .or_default()
                .push(keyset_id.to_string());
        }
        result
    }

    /// Returns the set of units that have at least one active keyset.
    fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.keysets
            .read()
            .expect("keysets lock")
            .values()
            .filter(|e| e.active)
            .map(|e| e.unit.to_string())
            .collect()
    }
}

// ============================================================================
// SqliteStorage
// ============================================================================

/// SQLite-backed persistent storage.
///
/// Schema:
/// - `spilman_channels` — funding, balance, state, closing/closed JSON
/// - `spilman_usage` — normalized: one row per (channel, variable) with atomic
///   `INSERT ... ON CONFLICT DO UPDATE SET count = count + excluded.count`
/// - `spilman_keysets` — cached mint keyset metadata (JSON)
pub struct SqliteStorage {
    conn: std::sync::Mutex<rusqlite::Connection>,
    /// Write-once cache: funding data is never updated or deleted, so cache
    /// entries are populated lazily on first access and never invalidated.
    funding_cache: std::sync::Mutex<HashMap<String, ChannelFunding>>,
}

impl std::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStorage").finish_non_exhaustive()
    }
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("failed to open SQLite at {path}: {e}"))?;
        let storage = Self {
            conn: std::sync::Mutex::new(conn),
            funding_cache: std::sync::Mutex::new(HashMap::new()),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database (useful for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| format!("failed to open in-memory SQLite: {e}"))?;
        let storage = Self {
            conn: std::sync::Mutex::new(conn),
            funding_cache: std::sync::Mutex::new(HashMap::new()),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS spilman_channels (
                channel_id    TEXT NOT NULL PRIMARY KEY,
                funding_json  TEXT NOT NULL,
                balance       INTEGER NOT NULL DEFAULT 0,
                signature     TEXT NOT NULL DEFAULT '',
                state         TEXT NOT NULL DEFAULT 'Open',
                closing_json  TEXT,
                closed_json   TEXT
            );

            CREATE TABLE IF NOT EXISTS spilman_usage (
                channel_id TEXT NOT NULL,
                var_name   TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (channel_id, var_name)
            );

            CREATE TABLE IF NOT EXISTS spilman_keysets (
                mint_url   TEXT NOT NULL,
                keyset_id  TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                PRIMARY KEY (mint_url, keyset_id)
            );
            ",
        )
        .map_err(|e| format!("failed to initialize SQLite schema: {e}"))
    }
}

impl SpilmanStorage for SqliteStorage {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        // Check the in-memory cache first.
        {
            let cache = self.funding_cache.lock().expect("funding_cache lock");
            if let Some(f) = cache.get(channel_id) {
                return Some(f.clone());
            }
        }
        // Cache miss — query SQLite and populate on hit.
        let conn = self.conn.lock().expect("sqlite lock");
        let funding: Option<ChannelFunding> = conn
            .query_row(
                "SELECT funding_json FROM spilman_channels WHERE channel_id = ?1",
                [channel_id],
                |row| {
                    let json: String = row.get(0)?;
                    Ok(json)
                },
            )
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());
        if let Some(ref f) = funding {
            drop(conn);
            self.funding_cache
                .lock()
                .expect("funding_cache lock")
                .insert(channel_id.to_string(), f.clone());
        }
        funding
    }

    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&funding).expect("ChannelFunding serialization failed");
        conn.execute(
            "INSERT INTO spilman_channels (channel_id, funding_json)
             VALUES (?1, ?2)
             ON CONFLICT(channel_id) DO NOTHING",
            rusqlite::params![channel_id, json],
        )
        .map_err(|e| format!("save_funding: {e}"))?;
        // Populate the cache (write-once, so first insert wins — matches the SQL).
        self.funding_cache
            .lock()
            .expect("funding_cache lock")
            .entry(channel_id.to_string())
            .or_insert(funding);
        Ok(())
    }

    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT balance, signature FROM spilman_channels
             WHERE channel_id = ?1 AND signature != ''",
            [channel_id],
            |row| {
                let balance: i64 = row.get(0)?;
                let signature: String = row.get(1)?;
                Ok(PaymentProof {
                    balance: balance as u64,
                    signature,
                })
            },
        )
        .ok()
    }

    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        // Monotonic: only update if strictly greater, OR if this is the
        // first real balance (signature is still the empty-string default).
        // Returns Ok(()) even if 0 rows affected (monotonic no-op).
        conn.execute(
            "UPDATE spilman_channels
             SET balance = ?2, signature = ?3
             WHERE channel_id = ?1
               AND (balance < ?2 OR signature = '')",
            rusqlite::params![channel_id, payment.balance as i64, payment.signature],
        )
        .map_err(|e| format!("update_balance: {e}"))?;
        Ok(())
    }

    fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt =
            match conn.prepare("SELECT var_name, count FROM spilman_usage WHERE channel_id = ?1") {
                Ok(s) => s,
                Err(_) => return None,
            };
        let map: UsageMap = stmt
            .query_map([channel_id], |row| {
                let var: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((var, count as u64))
            })
            .ok()?
            .filter_map(|r| r.ok())
            .collect();

        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }

    /// Atomically increment usage counters for a channel.
    ///
    /// `increments` maps variable names to their deltas for this request,
    /// e.g. `{"chars": 42, "requests": 1}`.  Each entry produces one
    /// SQL upsert against the `spilman_usage` table (keyed by
    /// `(channel_id, var_name)`): the row is created if it doesn't exist,
    /// or its `count` is bumped by the delta if it does.  All upserts
    /// for the channel run in a single transaction.
    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String> {
        let mut conn = self.conn.lock().expect("sqlite lock");
        let tx = conn
            .transaction()
            .map_err(|e| format!("increment_usage: begin transaction: {e}"))?;
        for (var, delta) in increments {
            tx.execute(
                "INSERT INTO spilman_usage (channel_id, var_name, count)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(channel_id, var_name)
                 DO UPDATE SET count = count + excluded.count",
                rusqlite::params![channel_id, var, *delta as i64],
            )
            .map_err(|e| format!("increment_usage({var}): {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("increment_usage: commit: {e}"))?;
        Ok(())
    }

    fn get_state(&self, channel_id: &str) -> ChannelState {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT state FROM spilman_channels WHERE channel_id = ?1",
            [channel_id],
            |row| {
                let state: String = row.get(0)?;
                Ok(state)
            },
        )
        .ok()
        .map(|s| match s.as_str() {
            "Closing" => ChannelState::Closing,
            "Closed" => ChannelState::Closed,
            _ => ChannelState::Open,
        })
        .unwrap_or(ChannelState::Open)
    }

    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&closing).expect("ClosingData serialization failed");
        let rows = conn
            .execute(
                "UPDATE spilman_channels
                 SET state = 'Closing', closing_json = ?2
                 WHERE channel_id = ?1 AND state != 'Closed'",
                rusqlite::params![channel_id, json],
            )
            .map_err(|e| format!("mark_closing: {e}"))?;
        if rows == 0 {
            return Err("channel not found or already closed".to_string());
        }
        Ok(())
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT closing_json FROM spilman_channels
             WHERE channel_id = ?1 AND state = 'Closing'",
            [channel_id],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&data).expect("ClosedDataView serialization failed");
        // Single UPDATE with WHERE guard: only transitions non-Closed channels.
        let rows = conn
            .execute(
                "UPDATE spilman_channels
                 SET state = 'Closed', closed_json = ?2, closing_json = NULL
                 WHERE channel_id = ?1 AND state != 'Closed'",
                rusqlite::params![channel_id, json],
            )
            .map_err(|e| format!("mark_closed: {e}"))?;
        if rows == 0 {
            return Err("channel already closed or not found".to_string());
        }
        Ok(())
    }

    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT closed_json FROM spilman_channels
             WHERE channel_id = ?1 AND state = 'Closed'",
            [channel_id],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.query_row(
            "SELECT entry_json FROM spilman_keysets WHERE mint_url = ?1 AND keyset_id = ?2",
            rusqlite::params![mint, keyset_id.to_string()],
            |row| {
                let json: String = row.get(0)?;
                Ok(json)
            },
        )
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let json = serde_json::to_string(&entry).expect("KeysetCacheEntry serialization failed");
        conn.execute(
            "INSERT INTO spilman_keysets (mint_url, keyset_id, entry_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(mint_url, keyset_id) DO UPDATE SET entry_json = ?3",
            rusqlite::params![mint, keyset_id.to_string(), json],
        )
        .map_err(|e| format!("set_keyset: {e}"))?;
        Ok(())
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = match conn
            .prepare("SELECT keyset_id, entry_json FROM spilman_keysets WHERE mint_url = ?1")
        {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let unit_str = unit.to_string();
        stmt.query_map([mint], |row| {
            let kid_str: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((kid_str, json))
        })
        .ok()
        .map(|rows| {
            rows.filter_map(|r| r.ok())
                .filter_map(|(kid_str, json)| {
                    let entry: KeysetCacheEntry = serde_json::from_str(&json).ok()?;
                    if entry.active && entry.unit.to_string() == unit_str {
                        kid_str.parse::<Id>().ok()
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt =
            match conn.prepare("SELECT mint_url, keyset_id, entry_json FROM spilman_keysets") {
                Ok(s) => s,
                Err(_) => return HashMap::new(),
            };

        let mut result: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        if let Ok(rows) = stmt.query_map([], |row| {
            let mint: String = row.get(0)?;
            let kid: String = row.get(1)?;
            let json: String = row.get(2)?;
            Ok((mint, kid, json))
        }) {
            for row in rows.flatten() {
                let (mint, kid, json) = row;
                if let Ok(entry) = serde_json::from_str::<KeysetCacheEntry>(&json) {
                    // Only active keysets: inactive ones still work for
                    // existing channels, but we don't advertise them to
                    // new clients.
                    if entry.active {
                        result
                            .entry(mint)
                            .or_default()
                            .entry(entry.unit.to_string())
                            .or_default()
                            .push(kid);
                    }
                }
            }
        }
        result
    }

    fn get_active_units(&self) -> std::collections::HashSet<String> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = match conn.prepare("SELECT entry_json FROM spilman_keysets") {
            Ok(s) => s,
            Err(_) => return std::collections::HashSet::new(),
        };

        stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })
        .ok()
        .map(|rows| {
            rows.filter_map(|r| r.ok())
                .filter_map(|json| {
                    let entry: KeysetCacheEntry = serde_json::from_str(&json).ok()?;
                    if entry.active {
                        Some(entry.unit.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
    }
}
