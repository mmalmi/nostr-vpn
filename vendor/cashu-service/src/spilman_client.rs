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

#[cfg(feature = "spilman-wallet-http")]
#[derive(Debug, Clone)]
pub struct HttpSpilmanClientNetworking {
    client: reqwest::Client,
}

#[cfg(feature = "spilman-wallet-http")]
impl Default for HttpSpilmanClientNetworking {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "spilman-wallet-http")]
impl HttpSpilmanClientNetworking {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "spilman-wallet-http")]
#[async_trait::async_trait]
impl cdk_spilman::SpilmanClientAsyncNetworking for HttpSpilmanClientNetworking {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let url = format!("{}/v1/swap", mint_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|error| format!("Cashu mint swap request failed: {error}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("failed to read Cashu mint swap response: {error}"))?;
        if !status.is_success() {
            return Err(format!("Cashu mint swap failed with {status}: {body}"));
        }
        Ok(body)
    }
}

#[cfg(feature = "spilman-wallet-http")]
pub async fn fetch_spilman_keyset_ids(mint_url: &str, unit: &str) -> Result<Vec<String>, String> {
    let mint_url = mint_url.trim_end_matches('/');
    let response: serde_json::Value = reqwest::Client::new()
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keysets: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keysets: {error}"))?;
    let unit = unit.trim().to_ascii_lowercase();
    let mut ids = response
        .get("keysets")
        .and_then(|value| value.as_array())
        .ok_or("Cashu mint keysets response is missing keysets")?
        .iter()
        .filter(|entry| {
            entry
                .get("unit")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(&unit))
        })
        .filter_map(|entry| entry.get("id").and_then(|value| value.as_str()))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

#[cfg(feature = "spilman-wallet-http")]
pub async fn fetch_spilman_keyset_info_json(
    mint_url: &str,
    unit: &str,
    keyset_id: Option<&str>,
) -> Result<String, String> {
    let mint_url = mint_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let keysets_url = format!("{mint_url}/v1/keysets");
    let keysets_response: serde_json::Value = client
        .get(keysets_url)
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keysets: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keysets: {error}"))?;
    let keysets = keysets_response
        .get("keysets")
        .and_then(|value| value.as_array())
        .ok_or("Cashu mint keysets response is missing keysets")?;
    let unit = unit.trim().to_ascii_lowercase();
    let selected = select_spilman_keyset(keysets, &unit, keyset_id).ok_or_else(|| {
        keyset_id.map_or_else(
            || format!("Cashu mint has no active {unit} keyset"),
            |id| format!("Cashu mint has no {unit} keyset {id}"),
        )
    })?;
    let selected_id = selected
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or("selected Cashu mint keyset is missing id")?;
    let input_fee_ppk = selected
        .get("input_fee_ppk")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let final_expiry = selected
        .get("final_expiry")
        .and_then(|value| value.as_u64());
    let keys_url = format!("{mint_url}/v1/keys/{selected_id}");
    let keys_response: serde_json::Value = client
        .get(keys_url)
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keys: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keys: {error}"))?;
    let keys = keys_response
        .get("keysets")
        .and_then(|value| value.as_array())
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("keys"))
        .cloned()
        .ok_or("Cashu mint keys response is missing keys")?;
    let mut keyset_info = serde_json::json!({
        "keysetId": selected_id,
        "unit": unit,
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    });
    if let Some(final_expiry) = final_expiry {
        keyset_info["finalExpiry"] = serde_json::json!(final_expiry);
    }
    Ok(keyset_info.to_string())
}

#[cfg(feature = "spilman-wallet-http")]
fn select_spilman_keyset<'a>(
    keysets: &'a [serde_json::Value],
    unit: &str,
    keyset_id: Option<&str>,
) -> Option<&'a serde_json::Value> {
    keysets
        .iter()
        .filter(|entry| {
            let entry_id = entry.get("id").and_then(|value| value.as_str());
            let entry_unit = entry
                .get("unit")
                .and_then(|value| value.as_str())
                .map(|value| value.to_ascii_lowercase());
            let active = entry
                .get("active")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            entry_unit.as_deref() == Some(unit)
                && keyset_id.map_or(active, |expected| entry_id == Some(expected))
        })
        .min_by_key(|entry| {
            entry
                .get("input_fee_ppk")
                .and_then(|value| value.as_u64())
                .unwrap_or_default()
        })
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
    pub mint_url: String,
    pub receiver_pubkey_hex: String,
    pub capacity_sat: u64,
    pub expiry_unix: u64,
    #[serde(default)]
    pub max_amount_per_output: u64,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    #[serde(default)]
    pub opening_paid_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset_info_json: Option<String>,
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelFromWalletResult {
    pub channel: StreamingRouteOpenCashuSpilmanChannelResult,
    pub wallet_send: crate::CashuSentPayment,
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
pub async fn open_streaming_route_cashu_spilman_channel_from_wallet(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
    let lock = SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(data_dir))
        .map_err(|error| anyhow::anyhow!(error))?;
    open_streaming_route_cashu_spilman_channel_from_wallet_with_lock(data_dir, request, lock).await
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
pub async fn open_streaming_route_cashu_spilman_channel_from_wallet_with_lock(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    lock: SharedSpilmanClientStoreLock,
) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
    let lock = require_lock_for_data_dir(data_dir, lock).map_err(|error| anyhow::anyhow!(error))?;
    crate::wallet::CashuWalletService::open_file_backed(data_dir)
        .await?
        .open_streaming_route_cashu_spilman_channel_with_lock(request, lock)
        .await
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
impl crate::wallet::CashuWalletService {
    pub async fn open_streaming_route_cashu_spilman_channel(
        &self,
        request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    ) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        let lock =
            SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(self.data_dir()))
                .map_err(|error| anyhow::anyhow!(error))?;
        self.open_streaming_route_cashu_spilman_channel_with_lock(request, lock)
            .await
    }

    pub async fn open_streaming_route_cashu_spilman_channel_with_lock(
        &self,
        request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
        lock: SharedSpilmanClientStoreLock,
    ) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        let lock = require_lock_for_data_dir(self.data_dir(), lock)
            .map_err(|error| anyhow::anyhow!(error))?;
        if request.capacity_sat == 0 {
            anyhow::bail!("Cashu Spilman channel capacity must be greater than zero");
        }
        let unit = StreamingRouteCashuUnit::parse(&request.unit)
            .map_err(|error| anyhow::anyhow!(error))?;
        if unit != StreamingRouteCashuUnit::Sat {
            anyhow::bail!(
                "wallet-backed Cashu Spilman channel opening currently supports sat only"
            );
        }
        let keyset_info_json = match request.keyset_info_json {
            Some(json) => json,
            None => fetch_spilman_keyset_info_json(
                &request.mint_url,
                unit.as_str(),
                request.keyset_id.as_deref(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))?,
        };
        let funding_token_amount = cdk_spilman::compute_funding_token_amount(
            request.capacity_sat,
            &keyset_info_json,
            request.max_amount_per_output,
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        let funding_keyset_id = cdk_spilman::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(|error| anyhow::anyhow!(error))?
            .keyset_id;
        let wallet_send = self
            .send_payment_token_for_keyset(
                &request.mint_url,
                funding_token_amount,
                funding_keyset_id,
            )
            .await?;
        let networking = HttpSpilmanClientNetworking::new();
        let channel =
            open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_lock(
                self.data_dir(),
                StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
                    token: wallet_send.token.clone(),
                    receiver_pubkey_hex: request.receiver_pubkey_hex,
                    sender_secret_hex: None,
                    expiry_unix: request.expiry_unix,
                    keyset_info_json,
                    max_amount_per_output: request.max_amount_per_output,
                    unit: unit.as_str().to_string(),
                    opening_paid_msat: request.opening_paid_msat,
                },
                &networking,
                lock,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(StreamingRouteOpenCashuSpilmanChannelFromWalletResult {
            channel,
            wallet_send,
        })
    }
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug, Clone, Copy)]
struct NoopSpilmanClientNetworking;

#[cfg(feature = "spilman-wallet")]
impl cdk_spilman::SpilmanClientNetworking for NoopSpilmanClientNetworking {
    fn call_mint_swap(&self, _mint_url: &str, _swap_request_json: &str) -> Result<String, String> {
        Err("synchronous Cashu Spilman client networking is not configured".to_string())
    }
}

#[cfg(feature = "spilman-wallet")]
fn default_streaming_route_cashu_unit() -> String {
    StreamingRouteCashuUnit::Sat.as_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_spilman_client_storage_persists_refund_witness_migration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.json");
        let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        assert!(!storage.refund_witnesses_persisted("channel-1"));
        storage.mark_refund_witnesses_persisted("channel-1");
        assert!(!storage.refund_proofs_validated("channel-1"));
        storage.mark_refund_proofs_validated("channel-1");
        errors.ensure_ok().unwrap();
        drop(storage);

        let (storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
        assert!(storage.refund_witnesses_persisted("channel-1"));
        assert!(storage.refund_proofs_validated("channel-1"));
        errors.ensure_ok().unwrap();
    }

    #[cfg(feature = "spilman-wallet-http")]
    #[test]
    fn automatic_spilman_keyset_selection_matches_wallet_fee_policy() {
        let keysets = serde_json::json!([
            {"id": "expensive", "unit": "sat", "active": true, "input_fee_ppk": 200},
            {"id": "inactive", "unit": "sat", "active": false, "input_fee_ppk": 0},
            {"id": "cheap", "unit": "sat", "active": true, "input_fee_ppk": 100}
        ]);
        let keysets = keysets.as_array().unwrap();

        assert_eq!(
            select_spilman_keyset(keysets, "sat", None)
                .unwrap()
                .get("id")
                .unwrap(),
            "cheap"
        );
        assert_eq!(
            select_spilman_keyset(keysets, "sat", Some("inactive"))
                .unwrap()
                .get("id")
                .unwrap(),
            "inactive"
        );
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn spilman_sender_key_is_created_and_reused() {
        let temp = tempfile::tempdir().unwrap();
        let first = load_or_create_cashu_spilman_sender_key(temp.path()).unwrap();
        let second = load_or_create_cashu_spilman_sender_key(temp.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version, SPILMAN_SENDER_KEY_VERSION);
        assert_eq!(first.secret_hex.len(), 64);
        assert!(!first.public_key_hex.is_empty());
    }

    #[cfg(all(feature = "spilman-wallet", unix))]
    #[test]
    fn spilman_sender_key_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, spilman_sender_key_path(temp.path())).unwrap();

        assert!(load_or_create_cashu_spilman_sender_key(temp.path()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn receiver_pubkey_normalization_accepts_x_only_keys() {
        let x_only = "ab".repeat(32);

        assert_eq!(
            normalize_spilman_receiver_pubkey_hex(&x_only),
            format!("02{x_only}")
        );
        assert_eq!(
            normalize_spilman_receiver_pubkey_hex(&format!("03{x_only}")),
            format!("03{x_only}")
        );
    }

    #[cfg(feature = "spilman-wallet")]
    #[test]
    fn file_spilman_payment_signer_reports_missing_channel() {
        let temp = tempfile::tempdir().unwrap();
        let signer = FileSpilmanPaymentSigner::load(temp.path()).unwrap();
        let error = signer
            .sign_cashu_spilman_payment("missing-channel", 1, false)
            .expect_err("signing a missing channel should fail");

        assert!(error.contains("Channel not found: missing-channel"));
        assert!(spilman_sender_key_path(temp.path()).exists());
    }

    #[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
    #[tokio::test]
    async fn wallet_channel_open_rejects_non_sat_units() {
        let temp = tempfile::tempdir().unwrap();
        let error = open_streaming_route_cashu_spilman_channel_from_wallet(
            temp.path(),
            StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url: "https://mint.example".to_string(),
                receiver_pubkey_hex: "receiver".to_string(),
                capacity_sat: 1,
                expiry_unix: 123,
                max_amount_per_output: 64,
                unit: "msat".to_string(),
                opening_paid_msat: 1,
                keyset_id: None,
                keyset_info_json: Some("{}".to_string()),
            },
        )
        .await
        .expect_err("msat wallet-open should fail before touching wallet storage");

        assert!(error
            .to_string()
            .contains("wallet-backed Cashu Spilman channel opening currently supports sat only"));
    }
}
