//! Client-side Cashu Spilman helpers for paid-route buyers.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
    rc::Rc,
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "spilman-wallet")]
use crate::private_file::create_atomic_private;
use crate::private_file::{
    open_private_lock_file, read_private_regular_to_string, write_atomic_private,
};

#[cfg(feature = "spilman-wallet")]
use crate::spilman::{
    create_streaming_route_cashu_payment, CashuSpilmanPayment, CashuSpilmanPaymentSigner,
    StreamingRouteCashuPaymentRequest, StreamingRouteCashuPaymentResult, StreamingRouteCashuUnit,
};

const SPILMAN_CLIENT_STORE_VERSION: u16 = 1;
#[cfg(feature = "spilman-wallet")]
const SPILMAN_SENDER_KEY_VERSION: u16 = 1;

pub fn spilman_client_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("spilman-client.json")
}

pub fn spilman_client_store_lock_path(data_dir: &Path) -> PathBuf {
    lock_path_for_store(&spilman_client_store_path(data_dir))
}

pub fn spilman_sender_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("spilman-sender-key.json")
}

fn lock_path_for_store(store_path: &Path) -> PathBuf {
    let mut path = store_path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

#[allow(dead_code)]
pub(crate) fn require_lock_for_data_dir(
    data_dir: &Path,
    lock: SharedSpilmanClientStoreLock,
) -> Result<SharedSpilmanClientStoreLock, String> {
    let expected = spilman_client_store_path(data_dir);
    if lock.store_path() != expected {
        return Err(format!(
            "Spilman client store lock is for {}, expected {}",
            lock.store_path().display(),
            expected.display()
        ));
    }
    Ok(lock)
}

/// Exclusive process lock held until this guard or its consuming storage drops.
#[derive(Debug)]
pub struct SharedSpilmanClientStoreLock {
    store_path: PathBuf,
    _file: File,
}

impl SharedSpilmanClientStoreLock {
    pub fn acquire(store_path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::acquire_inner(store_path.into(), false)?.ok_or_else(|| {
            "blocking Spilman client store lock unexpectedly reported busy".to_string()
        })
    }

    pub fn try_acquire(store_path: impl Into<PathBuf>) -> Result<Option<Self>, String> {
        Self::acquire_inner(store_path.into(), true)
    }

    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    fn acquire_inner(store_path: PathBuf, nonblocking: bool) -> Result<Option<Self>, String> {
        let lock_path = lock_path_for_store(&store_path);
        let file = open_private_lock_file(&lock_path, &store_path).map_err(|error| {
            format!(
                "failed to open Spilman client store lock {}: {error}",
                lock_path.display()
            )
        })?;
        let result = if nonblocking {
            fs2::FileExt::try_lock_exclusive(&file)
        } else {
            fs2::FileExt::lock_exclusive(&file)
        };
        match result {
            Ok(()) => Ok(Some(Self {
                store_path,
                _file: file,
            })),
            Err(error) if nonblocking && error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(format!(
                "failed to lock Spilman client store {}: {error}",
                store_path.display()
            )),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SpilmanClientStoreFile {
    version: u16,
    #[serde(default)]
    funding: BTreeMap<String, cdk_spilman::ClientChannelFunding>,
    #[serde(default)]
    payments: BTreeMap<String, cdk_spilman::ClientPaymentState>,
    #[serde(default)]
    closed: BTreeSet<String>,
    #[serde(default)]
    refund_witnesses_persisted: BTreeSet<String>,
    #[serde(default)]
    refund_proofs_validated: BTreeSet<String>,
    #[serde(default)]
    refund_proofs_repaired: BTreeSet<String>,
    /// Durable idempotency keys for wallet-backed channel opens.
    ///
    /// A route session can be cancelled after the channel has been persisted
    /// but before the route store is updated. Keeping this association beside
    /// the funding lets the retry recover the same channel instead of sending
    /// another Cashu token.
    #[serde(default)]
    open_requests: BTreeMap<String, String>,
}

impl SpilmanClientStoreFile {
    fn new() -> Self {
        Self {
            version: SPILMAN_CLIENT_STORE_VERSION,
            funding: BTreeMap::new(),
            payments: BTreeMap::new(),
            closed: BTreeSet::new(),
            refund_witnesses_persisted: BTreeSet::new(),
            refund_proofs_validated: BTreeSet::new(),
            refund_proofs_repaired: BTreeSet::new(),
            open_requests: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileSpilmanClientStorageErrorHandle {
    last_error: Rc<RefCell<Option<String>>>,
}

impl FileSpilmanClientStorageErrorHandle {
    pub fn last_error(&self) -> Option<String> {
        self.last_error.borrow().clone()
    }

    pub fn take_error(&self) -> Option<String> {
        self.last_error.borrow_mut().take()
    }

    pub fn ensure_ok(&self) -> Result<(), String> {
        match self.last_error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// JSON-backed client-side channel storage for the upstream Spilman bridge.
///
/// The upstream `ClientStorage` trait is synchronous and does not return write
/// errors, so this implementation records the latest persistence error in a
/// handle that callers can check after bridge operations.
#[derive(Debug)]
pub struct FileSpilmanClientStorage {
    path: PathBuf,
    state: SpilmanClientStoreFile,
    errors: FileSpilmanClientStorageErrorHandle,
    current_open_request_id: Option<String>,
    _lock: SharedSpilmanClientStoreLock,
}

impl FileSpilmanClientStorage {
    pub fn load(
        path: impl Into<PathBuf>,
    ) -> Result<(Self, FileSpilmanClientStorageErrorHandle), String> {
        let lock = SharedSpilmanClientStoreLock::acquire(path)?;
        Self::load_with_lock(lock)
    }

    pub fn try_load(
        path: impl Into<PathBuf>,
    ) -> Result<Option<(Self, FileSpilmanClientStorageErrorHandle)>, String> {
        SharedSpilmanClientStoreLock::try_acquire(path)?
            .map(Self::load_with_lock)
            .transpose()
    }

    pub fn load_with_lock(
        lock: SharedSpilmanClientStoreLock,
    ) -> Result<(Self, FileSpilmanClientStorageErrorHandle), String> {
        let path = lock.store_path.clone();
        let state = match read_private_regular_to_string(&path) {
            Ok(content) if content.trim().is_empty() => SpilmanClientStoreFile::new(),
            Ok(content) => {
                let state: SpilmanClientStoreFile = serde_json::from_str(&content)
                    .map_err(|error| format!("failed to decode Spilman client store: {error}"))?;
                if state.version != SPILMAN_CLIENT_STORE_VERSION {
                    return Err(format!(
                        "unsupported Spilman client store version {}",
                        state.version
                    ));
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                SpilmanClientStoreFile::new()
            }
            Err(error) => return Err(format!("failed to read Spilman client store: {error}")),
        };
        let errors = FileSpilmanClientStorageErrorHandle::default();
        Ok((
            Self {
                path,
                state,
                errors: errors.clone(),
                current_open_request_id: None,
                _lock: lock,
            },
            errors,
        ))
    }

    fn persist(&mut self) {
        match self.write_snapshot() {
            Ok(()) => {
                *self.errors.last_error.borrow_mut() = None;
            }
            Err(error) => {
                *self.errors.last_error.borrow_mut() = Some(error);
            }
        }
    }

    fn write_snapshot(&self) -> Result<(), String> {
        let content = serde_json::to_string_pretty(&self.state)
            .map_err(|error| format!("failed to encode Spilman client store: {error}"))?;
        write_atomic_private(&self.path, content.as_bytes())
            .map_err(|error| format!("failed to write Spilman client store: {error}"))
    }

    pub fn refund_witnesses_persisted(&self, channel_id: &str) -> bool {
        self.state.refund_witnesses_persisted.contains(channel_id)
    }

    pub fn mark_refund_witnesses_persisted(&mut self, channel_id: &str) {
        if self
            .state
            .refund_witnesses_persisted
            .insert(channel_id.to_string())
        {
            self.persist();
        }
    }

    pub fn refund_proofs_validated(&self, channel_id: &str) -> bool {
        self.state.refund_proofs_validated.contains(channel_id)
    }

    pub fn mark_refund_proofs_validated(&mut self, channel_id: &str) {
        if self
            .state
            .refund_proofs_validated
            .insert(channel_id.to_string())
        {
            self.persist();
        }
    }

    pub fn refund_proofs_repaired(&self, channel_id: &str) -> bool {
        self.state.refund_proofs_repaired.contains(channel_id)
    }

    pub fn mark_refund_proofs_repaired(&mut self, channel_id: &str) {
        if self
            .state
            .refund_proofs_repaired
            .insert(channel_id.to_string())
        {
            self.persist();
        }
    }

    #[cfg(feature = "spilman-wallet")]
    fn begin_open_request(&mut self, request_id: Option<&str>) -> Result<(), String> {
        self.current_open_request_id = request_id
            .map(str::trim)
            .filter(|request_id| !request_id.is_empty())
            .map(ToOwned::to_owned);
        if self
            .current_open_request_id
            .as_ref()
            .is_some_and(|request_id| request_id.len() > 256)
        {
            return Err("Cashu Spilman channel request id is too long".to_string());
        }
        Ok(())
    }

    #[cfg(feature = "spilman-wallet")]
    fn remember_open_request(&mut self, request_id: &str, channel_id: &str) {
        self.state
            .open_requests
            .insert(request_id.to_string(), channel_id.to_string());
        self.persist();
    }
}

impl cdk_spilman::ClientStorage for FileSpilmanClientStorage {
    fn save_funding(&mut self, channel_id: &str, funding: cdk_spilman::ClientChannelFunding) {
        self.state.funding.insert(channel_id.to_string(), funding);
        self.persist();
    }

    fn get_funding(&self, channel_id: &str) -> Option<&cdk_spilman::ClientChannelFunding> {
        self.state.funding.get(channel_id)
    }

    fn get_payment_state(&self, channel_id: &str) -> Option<&cdk_spilman::ClientPaymentState> {
        self.state.payments.get(channel_id)
    }

    fn save_payment_state(&mut self, channel_id: &str, state: cdk_spilman::ClientPaymentState) {
        self.state.payments.insert(channel_id.to_string(), state);
        if let Some(request_id) = self.current_open_request_id.take() {
            self.state
                .open_requests
                .insert(request_id, channel_id.to_string());
        }
        self.persist();
    }

    fn get_state(&self, channel_id: &str) -> cdk_spilman::ClientChannelState {
        if self.state.closed.contains(channel_id) {
            cdk_spilman::ClientChannelState::Closed
        } else if self.state.funding.contains_key(channel_id) {
            cdk_spilman::ClientChannelState::Open
        } else {
            cdk_spilman::ClientChannelState::Closed
        }
    }

    fn set_closed(&mut self, channel_id: &str) {
        self.state.closed.insert(channel_id.to_string());
        self.persist();
    }

    fn list_channel_ids(&self) -> Vec<String> {
        self.state.funding.keys().cloned().collect()
    }

    fn delete(&mut self, channel_id: &str) {
        self.state.funding.remove(channel_id);
        self.state.payments.remove(channel_id);
        self.state.closed.remove(channel_id);
        self.state
            .open_requests
            .retain(|_, remembered_channel_id| remembered_channel_id != channel_id);
        self.persist();
    }
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSpilmanSenderKeyFile {
    pub version: u16,
    pub secret_hex: String,
    pub public_key_hex: String,
}

#[cfg(feature = "spilman-wallet")]
pub fn load_or_create_cashu_spilman_sender_key(
    data_dir: &Path,
) -> Result<CashuSpilmanSenderKeyFile, String> {
    let path = spilman_sender_key_path(data_dir);
    loop {
        match read_private_regular_to_string(&path) {
            Ok(content) => return decode_cashu_spilman_sender_key(&content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = generate_cashu_spilman_sender_key()?;
                if write_cashu_spilman_sender_key(&path, &key)? {
                    return Ok(key);
                }
            }
            Err(error) => return Err(format!("failed to read Spilman sender key: {error}")),
        }
    }
}

#[cfg(feature = "spilman-wallet")]
fn decode_cashu_spilman_sender_key(content: &str) -> Result<CashuSpilmanSenderKeyFile, String> {
    let key: CashuSpilmanSenderKeyFile = serde_json::from_str(content)
        .map_err(|error| format!("failed to decode Spilman sender key: {error}"))?;
    if key.version != SPILMAN_SENDER_KEY_VERSION {
        return Err(format!(
            "unsupported Spilman sender key version {}",
            key.version
        ));
    }
    let mut host =
        cdk_spilman::ConfigurableClientHost::new(cdk_spilman::MemoryClientStorage::new());
    let public_key_hex = host.add_key_from_hex(&key.secret_hex)?;
    if public_key_hex != key.public_key_hex {
        return Err("Spilman sender key public key does not match secret".to_string());
    }
    Ok(key)
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug)]
pub struct FileSpilmanPaymentSigner {
    bridge: cdk_spilman::SpilmanClientBridge<
        cdk_spilman::ConfigurableClientHost<FileSpilmanClientStorage>,
        NoopSpilmanClientNetworking,
    >,
    storage_errors: FileSpilmanClientStorageErrorHandle,
}

#[cfg(feature = "spilman-wallet")]
impl FileSpilmanPaymentSigner {
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let store_path = spilman_client_store_path(data_dir);
        let lock = SharedSpilmanClientStoreLock::acquire(store_path)?;
        Self::load_with_lock(data_dir, lock)
    }

    pub fn try_load(data_dir: &Path) -> Result<Option<Self>, String> {
        let store_path = spilman_client_store_path(data_dir);
        SharedSpilmanClientStoreLock::try_acquire(store_path)?
            .map(|lock| Self::load_with_lock(data_dir, lock))
            .transpose()
    }

    pub fn load_with_lock(
        data_dir: &Path,
        lock: SharedSpilmanClientStoreLock,
    ) -> Result<Self, String> {
        let lock = require_lock_for_data_dir(data_dir, lock)?;
        let (storage, storage_errors) = FileSpilmanClientStorage::load_with_lock(lock)?;
        let sender = load_or_create_cashu_spilman_sender_key(data_dir)?;
        let mut host = cdk_spilman::ConfigurableClientHost::new(storage);
        let public_key_hex = host.add_key_from_hex(&sender.secret_hex)?;
        if public_key_hex != sender.public_key_hex {
            return Err("Spilman sender key public key does not match secret".to_string());
        }
        Ok(Self {
            bridge: cdk_spilman::SpilmanClientBridge::new(host, NoopSpilmanClientNetworking),
            storage_errors,
        })
    }

    pub fn create_streaming_route_payment(
        &self,
        request: StreamingRouteCashuPaymentRequest,
    ) -> Result<StreamingRouteCashuPaymentResult, String> {
        let result = create_streaming_route_cashu_payment(self, request)?;
        self.storage_errors.ensure_ok()?;
        Ok(result)
    }
}

#[cfg(feature = "spilman-wallet")]
impl CashuSpilmanPaymentSigner for FileSpilmanPaymentSigner {
    fn sign_cashu_spilman_payment(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        let payment =
            self.bridge
                .sign_cashu_spilman_payment(channel_id, balance, include_funding)?;
        self.storage_errors.ensure_ok()?;
        Ok(payment)
    }

    fn sign_cashu_spilman_close(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<CashuSpilmanPayment, String> {
        let payment = self
            .bridge
            .sign_cashu_spilman_close(channel_id, final_balance)?;
        self.storage_errors.ensure_ok()?;
        Ok(payment)
    }
}

#[cfg(feature = "spilman-wallet")]
pub fn create_streaming_route_cashu_payment_from_client_store(
    data_dir: &Path,
    request: StreamingRouteCashuPaymentRequest,
) -> Result<StreamingRouteCashuPaymentResult, String> {
    FileSpilmanPaymentSigner::load(data_dir)?.create_streaming_route_payment(request)
}

#[cfg(feature = "spilman-wallet")]
fn generate_cashu_spilman_sender_key() -> Result<CashuSpilmanSenderKeyFile, String> {
    use rand::RngCore;

    let mut host =
        cdk_spilman::ConfigurableClientHost::new(cdk_spilman::MemoryClientStorage::new());
    loop {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let secret_hex = hex::encode(secret);
        if let Ok(public_key_hex) = host.add_key_from_hex(&secret_hex) {
            return Ok(CashuSpilmanSenderKeyFile {
                version: SPILMAN_SENDER_KEY_VERSION,
                secret_hex,
                public_key_hex,
            });
        }
    }
}

#[cfg(feature = "spilman-wallet")]
fn write_cashu_spilman_sender_key(
    path: &Path,
    key: &CashuSpilmanSenderKeyFile,
) -> Result<bool, String> {
    let content = serde_json::to_string_pretty(key)
        .map_err(|error| format!("failed to encode Spilman sender key: {error}"))?;
    create_atomic_private(path, content.as_bytes())
        .map_err(|error| format!("failed to write Spilman sender key: {error}"))
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
    pub token: String,
    pub receiver_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_secret_hex: Option<String>,
    pub expiry_unix: u64,
    pub keyset_info_json: String,
    #[serde(default)]
    pub max_amount_per_output: u64,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    #[serde(default)]
    pub opening_paid_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_request_id: Option<String>,
    /// Creation time of the owning route record. Used only to recover channels
    /// opened by versions that predate `client_request_id` persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_created_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_mint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_capacity_sat: Option<u64>,
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelResult {
    pub channel_id: String,
    pub mint_url: String,
    pub sender_pubkey_hex: String,
    pub receiver_pubkey_hex: String,
    pub unit: String,
    pub capacity: u64,
    pub capacity_sat: u64,
    pub funding_token_amount: u64,
    pub expires_unix: u64,
    pub opening_paid_msat: u64,
    pub payment: CashuSpilmanPayment,
}

#[cfg(feature = "spilman-wallet")]
pub async fn open_streaming_route_cashu_spilman_channel_from_token_with_networking<N>(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
    async_networking: &N,
) -> Result<StreamingRouteOpenCashuSpilmanChannelResult, String>
where
    N: cdk_spilman::SpilmanClientAsyncNetworking,
{
    let store_path = spilman_client_store_path(data_dir);
    let lock = SharedSpilmanClientStoreLock::acquire(store_path)?;
    open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_lock(
        data_dir,
        request,
        async_networking,
        lock,
    )
    .await
}

#[cfg(feature = "spilman-wallet")]
pub async fn open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_lock<N>(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
    async_networking: &N,
    lock: SharedSpilmanClientStoreLock,
) -> Result<StreamingRouteOpenCashuSpilmanChannelResult, String>
where
    N: cdk_spilman::SpilmanClientAsyncNetworking,
{
    let lock = require_lock_for_data_dir(data_dir, lock)?;
    let (storage, storage_errors) = FileSpilmanClientStorage::load_with_lock(lock)?;
    open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_storage(
        data_dir,
        request,
        async_networking,
        storage,
        storage_errors,
    )
    .await
}

#[cfg(feature = "spilman-wallet")]
async fn open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_storage<N>(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
    async_networking: &N,
    mut storage: FileSpilmanClientStorage,
    storage_errors: FileSpilmanClientStorageErrorHandle,
) -> Result<StreamingRouteOpenCashuSpilmanChannelResult, String>
where
    N: cdk_spilman::SpilmanClientAsyncNetworking,
{
    if let Some(recovered) = recover_opened_channel_from_storage(&mut storage, &request)? {
        return Ok(recovered);
    }
    storage.begin_open_request(request.client_request_id.as_deref())?;
    let sender = match request.sender_secret_hex.as_deref() {
        Some(secret_hex) => {
            let mut host =
                cdk_spilman::ConfigurableClientHost::new(cdk_spilman::MemoryClientStorage::new());
            let public_key_hex = host.add_key_from_hex(secret_hex)?;
            CashuSpilmanSenderKeyFile {
                version: SPILMAN_SENDER_KEY_VERSION,
                secret_hex: secret_hex.to_string(),
                public_key_hex,
            }
        }
        None => load_or_create_cashu_spilman_sender_key(data_dir)?,
    };

    let mut host = cdk_spilman::ConfigurableClientHost::new(storage);
    let sender_pubkey_hex = host.add_key_from_hex(&sender.secret_hex)?;
    let bridge = cdk_spilman::SpilmanClientBridge::new(host, NoopSpilmanClientNetworking);
    let receiver_pubkey_hex = normalize_spilman_receiver_pubkey_hex(&request.receiver_pubkey_hex);
    let opened = bridge
        .open_channel_from_token_async(
            &request.token,
            &receiver_pubkey_hex,
            &sender_pubkey_hex,
            request.expiry_unix,
            &request.keyset_info_json,
            request.max_amount_per_output,
            async_networking,
        )
        .await?;
    let unit = StreamingRouteCashuUnit::parse(&request.unit)?;
    let opening_balance = unit.balance_from_msat(request.opening_paid_msat);
    let payment: CashuSpilmanPayment = bridge
        .create_payment_with_funding(&opened.channel_id, opening_balance)?
        .into();
    storage_errors.ensure_ok()?;

    Ok(StreamingRouteOpenCashuSpilmanChannelResult {
        channel_id: opened.channel_id,
        mint_url: opened.mint_url,
        sender_pubkey_hex: opened.sender_pubkey_hex,
        receiver_pubkey_hex,
        unit: unit.as_str().to_string(),
        capacity: opened.capacity,
        capacity_sat: unit.capacity_to_sat(opened.capacity),
        funding_token_amount: opened.funding_token_amount,
        expires_unix: request.expiry_unix,
        opening_paid_msat: unit.balance_to_msat(payment.balance),
        payment,
    })
}

#[cfg(feature = "spilman-wallet")]
fn normalize_spilman_receiver_pubkey_hex(value: &str) -> String {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        format!("02{hex}")
    } else {
        trimmed.to_string()
    }
}

#[cfg(feature = "spilman-wallet")]
fn normalized_spilman_mint_url(value: &str) -> &str {
    value.trim().trim_end_matches('/')
}

#[cfg(feature = "spilman-wallet")]
fn funding_matches_open_request(
    funding: &cdk_spilman::ClientChannelFunding,
    request: &StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
    require_legacy_time_match: bool,
) -> Result<bool, String> {
    let params: serde_json::Value = serde_json::from_str(&funding.params_json)
        .map_err(|error| format!("failed to decode stored Spilman channel parameters: {error}"))?;
    let unit = params
        .get("unit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("sat");
    let unit = StreamingRouteCashuUnit::parse(unit)?;
    let receiver = params
        .get("receiver_pubkey")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expiry_unix = params
        .get("expiry_timestamp")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let maximum_amount = params
        .get("maximum_amount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let Some(route_mint_url) = request.route_mint_url.as_deref() else {
        return Ok(false);
    };
    let Some(route_capacity_sat) = request.route_capacity_sat else {
        return Ok(false);
    };
    if normalized_spilman_mint_url(&funding.mint_url) != normalized_spilman_mint_url(route_mint_url)
        || unit.as_str() != request.unit.trim().to_ascii_lowercase()
        || unit.capacity_to_sat(funding.capacity) != route_capacity_sat
        || normalize_spilman_receiver_pubkey_hex(receiver)
            != normalize_spilman_receiver_pubkey_hex(&request.receiver_pubkey_hex)
        || expiry_unix != request.expiry_unix
        || maximum_amount != request.max_amount_per_output
    {
        return Ok(false);
    }
    if !require_legacy_time_match {
        return Ok(true);
    }
    let Some(route_created_at_unix) = request.route_created_at_unix else {
        return Ok(false);
    };
    // Old daemon requests could remain inside a slow mint operation long
    // after the route task was cancelled. The immutable expiry is part of the
    // channel id and identifies the owning route precisely; only require that
    // funding happened during that route's lifetime.
    Ok(funding.created_at >= route_created_at_unix && funding.created_at < expiry_unix)
}

#[cfg(feature = "spilman-wallet")]
fn recover_opened_channel_from_storage(
    storage: &mut FileSpilmanClientStorage,
    request: &StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
) -> Result<Option<StreamingRouteOpenCashuSpilmanChannelResult>, String> {
    let Some(request_id) = request
        .client_request_id
        .as_deref()
        .map(str::trim)
        .filter(|request_id| !request_id.is_empty())
    else {
        return Ok(None);
    };
    if request_id.len() > 256 {
        return Err("Cashu Spilman channel request id is too long".to_string());
    }

    let mapped_channel_id = storage.state.open_requests.get(request_id).cloned();
    let should_remember_legacy_match = mapped_channel_id.is_none();
    let channel_id = if let Some(channel_id) = mapped_channel_id.as_ref() {
        let funding = storage.state.funding.get(channel_id).ok_or_else(|| {
            format!("remembered Cashu Spilman channel {channel_id} is missing its funding")
        })?;
        if !funding_matches_open_request(funding, request, false)? {
            return Err(format!(
                "Cashu Spilman channel request id {request_id} was reused with different terms"
            ));
        }
        channel_id.clone()
    } else {
        let mapped_channels = storage
            .state
            .open_requests
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut candidates = Vec::new();
        for (channel_id, funding) in &storage.state.funding {
            if !storage.state.closed.contains(channel_id)
                && !mapped_channels.contains(channel_id)
                && funding_matches_open_request(funding, request, true)?
            {
                candidates.push(channel_id.clone());
            }
        }
        candidates.sort();
        if candidates.len() > 1 {
            return Err(format!(
                "multiple legacy Cashu Spilman channels match route request {request_id}"
            ));
        }
        let Some(channel_id) = candidates.pop() else {
            return Ok(None);
        };
        channel_id
    };

    if storage.state.closed.contains(&channel_id) {
        return Err(format!(
            "remembered Cashu Spilman channel {channel_id} is already closed"
        ));
    }
    let funding = storage
        .state
        .funding
        .get(&channel_id)
        .cloned()
        .ok_or_else(|| format!("Cashu Spilman channel {channel_id} has no funding"))?;
    let payment_state = storage
        .state
        .payments
        .get(&channel_id)
        .cloned()
        .ok_or_else(|| format!("Cashu Spilman channel {channel_id} has no signed payment"))?;
    let params: serde_json::Value = serde_json::from_str(&funding.params_json)
        .map_err(|error| format!("failed to decode stored Spilman channel parameters: {error}"))?;
    let funding_proofs: serde_json::Value = serde_json::from_str(&funding.funding_proofs_json)
        .map_err(|error| format!("failed to decode stored Spilman funding proofs: {error}"))?;
    let unit = params
        .get("unit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("sat");
    let unit = StreamingRouteCashuUnit::parse(unit)?;
    let expected_opening_balance = unit.balance_from_msat(request.opening_paid_msat);
    if payment_state.balance != expected_opening_balance {
        return Err(format!(
            "remembered Cashu Spilman channel {channel_id} has advanced beyond its opening payment"
        ));
    }
    let receiver_pubkey_hex = params
        .get("receiver_pubkey")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let expires_unix = params
        .get("expiry_timestamp")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(request.expiry_unix);
    if should_remember_legacy_match {
        storage.remember_open_request(request_id, &channel_id);
        storage.errors.ensure_ok()?;
    }
    Ok(Some(StreamingRouteOpenCashuSpilmanChannelResult {
        channel_id: channel_id.clone(),
        mint_url: funding.mint_url,
        sender_pubkey_hex: funding.sender_pubkey_hex,
        receiver_pubkey_hex,
        unit: unit.as_str().to_string(),
        capacity: funding.capacity,
        capacity_sat: unit.capacity_to_sat(funding.capacity),
        funding_token_amount: funding.funding_token_amount,
        expires_unix,
        opening_paid_msat: unit.balance_to_msat(payment_state.balance),
        payment: CashuSpilmanPayment {
            channel_id,
            balance: payment_state.balance,
            signature: payment_state.signature,
            params: Some(params),
            funding_proofs: Some(funding_proofs),
        },
    }))
}

include!("spilman_client/wallet.rs");

#[cfg(test)]
mod tests {
    include!("spilman_client/tests.rs");
}
