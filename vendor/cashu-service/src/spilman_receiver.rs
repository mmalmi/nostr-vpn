//! Seller-side file-backed Cashu Spilman receiver helpers.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "spilman-configurable-host")]
use cashu::nuts::{CurrencyUnit, Id, PublicKey};
#[cfg(feature = "spilman-configurable-host")]
use cdk_spilman::{ChannelFunding, ChannelPolicy, ChannelState, ClosingData, PaymentProof};

#[cfg(feature = "spilman-configurable-host")]
use crate::spilman::{
    CashuSpilmanPayment, CashuSpilmanPaymentReceiver, CashuSpilmanPaymentReceiverValidation,
    StreamingRouteCashuUnit,
};

#[cfg(feature = "spilman-configurable-host")]
const SPILMAN_RECEIVER_KEY_VERSION: u16 = 1;

#[cfg(feature = "spilman-configurable-host")]
pub fn spilman_receiver_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("spilman-receiver-key.json")
}

#[cfg(feature = "spilman-configurable-host")]
pub fn spilman_receiver_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("spilman-receiver.sqlite")
}

#[cfg(feature = "spilman-configurable-host")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSpilmanReceiverKeyFile {
    pub version: u16,
    pub secret_hex: String,
    pub public_key_hex: String,
}

#[cfg(feature = "spilman-configurable-host")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpilmanPaymentReceiverConfig {
    pub accepted_mints: Vec<String>,
    #[serde(default = "default_spilman_receiver_units")]
    pub units: Vec<String>,
    #[serde(default = "default_spilman_receiver_min_capacity")]
    pub min_capacity: u64,
    #[serde(default)]
    pub max_amount_per_output: u64,
    #[serde(default)]
    pub min_expiry_seconds: u64,
}

#[cfg(feature = "spilman-configurable-host")]
impl FileSpilmanPaymentReceiverConfig {
    pub fn new(accepted_mints: impl IntoIterator<Item = String>) -> Self {
        Self {
            accepted_mints: accepted_mints.into_iter().collect(),
            units: default_spilman_receiver_units(),
            min_capacity: default_spilman_receiver_min_capacity(),
            max_amount_per_output: 0,
            min_expiry_seconds: 0,
        }
    }

    fn normalized(&self) -> Result<Self, String> {
        let mut accepted_mints = self
            .accepted_mints
            .iter()
            .map(|mint| normalize_mint_url(mint))
            .filter(|mint| !mint.is_empty())
            .collect::<Vec<_>>();
        accepted_mints.sort();
        accepted_mints.dedup();
        if accepted_mints.is_empty() {
            return Err("Cashu Spilman receiver requires at least one accepted mint".to_string());
        }

        let mut units = self
            .units
            .iter()
            .map(|unit| StreamingRouteCashuUnit::parse(unit).map(|unit| unit.as_str().to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        units.sort();
        units.dedup();
        if units.is_empty() {
            units = default_spilman_receiver_units();
        }

        Ok(Self {
            accepted_mints,
            units,
            min_capacity: self.min_capacity.max(1),
            max_amount_per_output: self.max_amount_per_output,
            min_expiry_seconds: self.min_expiry_seconds,
        })
    }
}

#[cfg(feature = "spilman-configurable-host")]
#[derive(Debug)]
pub struct FileSpilmanPaymentReceiver {
    host: Arc<cdk_spilman::configurable_host::ConfigurableHost>,
    bridge: cdk_spilman::SpilmanBridge<SharedConfigurableHost, String>,
    receiver_pubkey_hex: String,
}

#[cfg(feature = "spilman-configurable-host")]
#[derive(Debug, Clone)]
struct SharedConfigurableHost(Arc<cdk_spilman::configurable_host::ConfigurableHost>);

#[cfg(feature = "spilman-configurable-host")]
impl cdk_spilman::SpilmanHost<String> for SharedConfigurableHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        cdk_spilman::SpilmanHost::receiver_key_is_acceptable(&*self.0, receiver_pubkey)
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        cdk_spilman::SpilmanHost::mint_and_keyset_is_acceptable(&*self.0, mint, keyset_id)
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        cdk_spilman::SpilmanHost::get_funding(&*self.0, channel_id)
    }

    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) -> Result<(), String> {
        cdk_spilman::SpilmanHost::save_funding(&*self.0, channel_id, funding, initial_payment)
    }

    fn get_amount_due(&self, channel_id: &str, context: Option<&String>) -> u64 {
        cdk_spilman::SpilmanHost::get_amount_due(&*self.0, channel_id, context)
    }

    fn record_payment(
        &self,
        channel_id: &str,
        payment: PaymentProof,
        context: &String,
    ) -> Result<(), String> {
        cdk_spilman::SpilmanHost::record_payment(&*self.0, channel_id, payment, context)
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        cdk_spilman::SpilmanHost::get_channel_state(&*self.0, channel_id)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        cdk_spilman::SpilmanHost::mark_channel_closing(
            &*self.0,
            channel_id,
            expiry_timestamp,
            payment,
        )
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        cdk_spilman::SpilmanHost::get_closing_data(&*self.0, channel_id)
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        cdk_spilman::SpilmanHost::get_channel_policy(&*self.0, unit)
    }

    fn now_seconds(&self) -> u64 {
        cdk_spilman::SpilmanHost::now_seconds(&*self.0)
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        cdk_spilman::SpilmanHost::get_balance_and_signature_for_unilateral_exit(
            &*self.0, channel_id,
        )
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        cdk_spilman::SpilmanHost::get_active_keyset_ids(&*self.0, mint, unit)
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        cdk_spilman::SpilmanHost::get_keyset_info(&*self.0, mint, keyset_id)
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        cdk_spilman::SpilmanHost::mark_channel_closed(
            &*self.0,
            channel_id,
            expiry_timestamp,
            balance,
            receiver_proofs_json,
            sender_proofs_json,
            receiver_sum,
            sender_sum,
        )
    }

    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        cdk_spilman::SpilmanHost::compute_channel_secret(
            &*self.0,
            receiver_pubkey_hex,
            sender_pubkey_hex,
        )
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        cdk_spilman::SpilmanHost::sign_with_tweaked_key(
            &*self.0,
            signer_pubkey_hex,
            message_hex,
            tweak_scalar_hex,
        )
    }
}

#[cfg(feature = "spilman-configurable-host")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSpilmanReceiverCloseResult {
    pub channel_id: String,
    pub mint_url: String,
    pub unit: String,
    pub closed_amount: u64,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub receiver_proofs_json: String,
    pub sender_proofs_json: String,
    pub already_closed: bool,
}

#[cfg(feature = "spilman-configurable-host")]
fn cashu_spilman_receiver_close_result_from_closed_data(
    channel_id: &str,
    mint_url: String,
    unit: String,
    closed: cdk_spilman::configurable_host::ClosedDataView,
    already_closed: bool,
) -> CashuSpilmanReceiverCloseResult {
    CashuSpilmanReceiverCloseResult {
        channel_id: channel_id.to_string(),
        mint_url,
        unit,
        closed_amount: closed.closed_amount,
        total_value: closed.value_after_stage1,
        receiver_sum: closed.receiver_sum,
        sender_sum: closed.sender_sum,
        receiver_proofs_json: closed.receiver_proofs_json,
        sender_proofs_json: closed.sender_proofs_json,
        already_closed,
    }
}

#[cfg(feature = "spilman-configurable-host")]
fn cashu_spilman_receiver_channel_mint_unit(
    host: &cdk_spilman::configurable_host::ConfigurableHost,
    channel_id: &str,
) -> (String, String) {
    host.get_funding_data(channel_id)
        .and_then(|funding| serde_json::from_str::<serde_json::Value>(&funding.params_json).ok())
        .map(|params| {
            let mint_url = params
                .get("mint")
                .or_else(|| params.get("mint_url"))
                .and_then(|mint| mint.as_str())
                .map(normalize_mint_url)
                .unwrap_or_default();
            let unit = params
                .get("unit")
                .and_then(|unit| unit.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| StreamingRouteCashuUnit::Sat.as_str().to_string());
            (mint_url, unit)
        })
        .unwrap_or_else(|| {
            (
                String::new(),
                StreamingRouteCashuUnit::Sat.as_str().to_string(),
            )
        })
}

#[cfg(feature = "spilman-configurable-host")]
impl FileSpilmanPaymentReceiver {
    pub fn load(data_dir: &Path, config: FileSpilmanPaymentReceiverConfig) -> Result<Self, String> {
        let (host, receiver_pubkey_hex) = file_spilman_receiver_host(data_dir, config)?;
        Ok(Self {
            bridge: cdk_spilman::SpilmanBridge::new(SharedConfigurableHost(Arc::clone(&host))),
            host,
            receiver_pubkey_hex,
        })
    }

    #[cfg(feature = "spilman-configurable-host-reqwest")]
    pub async fn load_with_keyset_refresh(
        data_dir: &Path,
        config: FileSpilmanPaymentReceiverConfig,
    ) -> Result<Self, String> {
        let (host, receiver_pubkey_hex) = file_spilman_receiver_host(data_dir, config)?;
        host.initialize_keysets().await?;
        Ok(Self {
            bridge: cdk_spilman::SpilmanBridge::new(SharedConfigurableHost(Arc::clone(&host))),
            host,
            receiver_pubkey_hex,
        })
    }

    pub fn receiver_pubkey_hex(&self) -> &str {
        &self.receiver_pubkey_hex
    }

    #[cfg(feature = "spilman-configurable-host-reqwest")]
    pub async fn close_cashu_spilman_channel(
        &self,
        channel_id: &str,
    ) -> Result<CashuSpilmanReceiverCloseResult, String> {
        let channel_id = channel_id.trim();
        if channel_id.is_empty() {
            return Err("missing Cashu Spilman channel id".to_string());
        }
        let (mint_url, unit) = cashu_spilman_receiver_channel_mint_unit(&self.host, channel_id);
        if let Some(closed) = self.host.get_closed_data(channel_id) {
            return Ok(cashu_spilman_receiver_close_result_from_closed_data(
                channel_id, mint_url, unit, closed, true,
            ));
        }

        let networking =
            cdk_spilman::configurable_networking::ReqwestNetworking::new(Arc::clone(&self.host));
        let closed = self
            .bridge
            .execute_unilateral_close_async(channel_id, &networking)
            .await
            .map_err(|error| error.to_string())?;
        match self.host.get_closed_data(channel_id) {
            Some(closed_data) => Ok(cashu_spilman_receiver_close_result_from_closed_data(
                channel_id,
                mint_url,
                unit,
                closed_data,
                closed.already_closed,
            )),
            None => Ok(CashuSpilmanReceiverCloseResult {
                channel_id: closed.channel_id,
                mint_url,
                unit,
                closed_amount: closed.receiver_sum,
                total_value: closed.total_value,
                receiver_sum: closed.receiver_sum,
                sender_sum: closed.sender_sum,
                receiver_proofs_json: String::new(),
                sender_proofs_json: closed.sender_proofs,
                already_closed: closed.already_closed,
            }),
        }
    }
}

#[cfg(feature = "spilman-configurable-host")]
impl CashuSpilmanPaymentReceiver<String> for FileSpilmanPaymentReceiver {
    fn validate_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.bridge.validate_cashu_spilman_payment(payment, context)
    }

    fn process_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &String,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.bridge.process_cashu_spilman_payment(payment, context)
    }
}

#[cfg(feature = "spilman-configurable-host")]
pub fn load_or_create_cashu_spilman_receiver_key(
    data_dir: &Path,
) -> Result<CashuSpilmanReceiverKeyFile, String> {
    let path = spilman_receiver_key_path(data_dir);
    match fs::read_to_string(&path) {
        Ok(content) => {
            let key: CashuSpilmanReceiverKeyFile = serde_json::from_str(&content)
                .map_err(|error| format!("failed to decode Spilman receiver key: {error}"))?;
            if key.version != SPILMAN_RECEIVER_KEY_VERSION {
                return Err(format!(
                    "unsupported Spilman receiver key version {}",
                    key.version
                ));
            }
            let public_key_hex = receiver_public_key_hex(&key.secret_hex)?;
            if public_key_hex != key.public_key_hex {
                return Err("Spilman receiver key public key does not match secret".to_string());
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = generate_cashu_spilman_receiver_key()?;
            write_cashu_spilman_receiver_key(&path, &key)?;
            Ok(key)
        }
        Err(error) => Err(format!("failed to read Spilman receiver key: {error}")),
    }
}

#[cfg(feature = "spilman-configurable-host")]
fn file_spilman_receiver_host(
    data_dir: &Path,
    config: FileSpilmanPaymentReceiverConfig,
) -> Result<
    (
        Arc<cdk_spilman::configurable_host::ConfigurableHost>,
        String,
    ),
    String,
> {
    let key = load_or_create_cashu_spilman_receiver_key(data_dir)?;
    let config = config.normalized()?;
    let host_config = spilman_host_config(data_dir, &config);
    let host = Arc::new(cdk_spilman::configurable_host::ConfigurableHost::new(
        host_config,
        &key.secret_hex,
    )?);
    let receiver_pubkey_hex = host.server_pubkey().to_hex();
    if receiver_pubkey_hex != key.public_key_hex {
        return Err("Spilman receiver key public key does not match host".to_string());
    }
    Ok((host, receiver_pubkey_hex))
}

#[cfg(feature = "spilman-configurable-host")]
fn spilman_host_config(
    data_dir: &Path,
    config: &FileSpilmanPaymentReceiverConfig,
) -> cdk_spilman::configurable_host::ConfigurableHostConfig {
    let mut mints = HashMap::new();
    for mint in &config.accepted_mints {
        mints.insert(mint.clone(), config.units.clone());
    }

    let mut pricing = HashMap::new();
    for unit in &config.units {
        pricing.insert(
            unit.clone(),
            cdk_spilman::configurable_host::UnitPricingConfig {
                min_capacity: config.min_capacity,
                max_amount_per_output: (config.max_amount_per_output > 0)
                    .then_some(config.max_amount_per_output),
                variables: HashMap::new(),
            },
        );
    }

    cdk_spilman::configurable_host::ConfigurableHostConfig {
        mints,
        min_expiry_seconds: config.min_expiry_seconds,
        pricing_scale: 1,
        storage: cdk_spilman::configurable_host::StorageConfig::Sqlite {
            path: spilman_receiver_store_path(data_dir)
                .to_string_lossy()
                .to_string(),
        },
        pricing,
    }
}

#[cfg(feature = "spilman-configurable-host")]
fn receiver_public_key_hex(secret_hex: &str) -> Result<String, String> {
    let config = cdk_spilman::configurable_host::ConfigurableHostConfig {
        mints: HashMap::new(),
        min_expiry_seconds: 0,
        pricing_scale: 1,
        storage: cdk_spilman::configurable_host::StorageConfig::Memory,
        pricing: HashMap::new(),
    };
    let host = cdk_spilman::configurable_host::ConfigurableHost::new(config, secret_hex)?;
    Ok(host.server_pubkey().to_hex())
}

#[cfg(feature = "spilman-configurable-host")]
fn generate_cashu_spilman_receiver_key() -> Result<CashuSpilmanReceiverKeyFile, String> {
    use rand::RngCore;

    loop {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let secret_hex = hex::encode(secret);
        if let Ok(public_key_hex) = receiver_public_key_hex(&secret_hex) {
            return Ok(CashuSpilmanReceiverKeyFile {
                version: SPILMAN_RECEIVER_KEY_VERSION,
                secret_hex,
                public_key_hex,
            });
        }
    }
}

#[cfg(feature = "spilman-configurable-host")]
fn write_cashu_spilman_receiver_key(
    path: &Path,
    key: &CashuSpilmanReceiverKeyFile,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create Spilman receiver key dir: {error}"))?;
    }
    let content = serde_json::to_string_pretty(key)
        .map_err(|error| format!("failed to encode Spilman receiver key: {error}"))?;
    fs::write(path, content)
        .map_err(|error| format!("failed to write Spilman receiver key: {error}"))?;
    secure_owner_only(path)
        .map_err(|error| format!("failed to secure Spilman receiver key permissions: {error}"))?;
    Ok(())
}

#[cfg(feature = "spilman-configurable-host")]
fn normalize_mint_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

#[cfg(feature = "spilman-configurable-host")]
fn default_spilman_receiver_units() -> Vec<String> {
    vec![StreamingRouteCashuUnit::Sat.as_str().to_string()]
}

#[cfg(feature = "spilman-configurable-host")]
fn default_spilman_receiver_min_capacity() -> u64 {
    1
}

#[cfg(all(test, feature = "spilman-configurable-host"))]
mod tests {
    use super::*;

    #[test]
    fn receiver_key_is_created_and_reused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = load_or_create_cashu_spilman_receiver_key(dir.path()).expect("first key");
        let second = load_or_create_cashu_spilman_receiver_key(dir.path()).expect("second key");

        assert_eq!(first, second);
        assert_eq!(first.version, SPILMAN_RECEIVER_KEY_VERSION);
        assert_eq!(first.public_key_hex.len(), 66);
        assert!(spilman_receiver_key_path(dir.path()).exists());
    }

    #[test]
    fn receiver_config_normalizes_mints_and_units() {
        let config = FileSpilmanPaymentReceiverConfig {
            accepted_mints: vec![
                "https://mint.example/".to_string(),
                " https://mint.example ".to_string(),
            ],
            units: vec!["SAT".to_string(), "sat".to_string()],
            min_capacity: 0,
            max_amount_per_output: 64,
            min_expiry_seconds: 30,
        }
        .normalized()
        .expect("normalize receiver config");

        assert_eq!(config.accepted_mints, vec!["https://mint.example"]);
        assert_eq!(config.units, vec!["sat"]);
        assert_eq!(config.min_capacity, 1);
    }

    #[test]
    fn file_receiver_loads_with_persistent_sqlite_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let receiver = FileSpilmanPaymentReceiver::load(
            dir.path(),
            FileSpilmanPaymentReceiverConfig::new(["https://mint.example".to_string()]),
        )
        .expect("load receiver");

        assert_eq!(receiver.receiver_pubkey_hex().len(), 66);
        assert!(spilman_receiver_store_path(dir.path()).exists());
    }
}

#[cfg(unix)]
fn secure_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
