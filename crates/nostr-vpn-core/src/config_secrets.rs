#[cfg(target_os = "macos")]
use crate::macos_file_io as fs;
use std::collections::BTreeMap;
#[cfg(not(target_os = "macos"))]
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::Keys;
#[cfg(any(target_os = "ios", target_os = "android"))]
use sha2::{Digest as _, Sha256};

use crate::config::{AppConfig, normalize_nostr_pubkey};
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use crate::join_requests::{PENDING_NOSTR_JOIN_REQUEST_VERSION, PendingNostrJoinRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretPersistence {
    Platform,
    Plaintext,
}

pub(crate) fn hydrate_config_secrets(path: &Path, config: &mut AppConfig) -> Result<()> {
    platform::hydrate_config_secrets(path, config)
}

pub(crate) fn prepare_config_secrets_for_save(
    path: &Path,
    config: &mut AppConfig,
    persistence: SecretPersistence,
) -> Result<()> {
    if persistence == SecretPersistence::Plaintext {
        return Ok(());
    }
    persist_field(path, ConfigSecret::Nostr, &mut config.nostr.secret_key)?;
    persist_field(
        path,
        ConfigSecret::WireGuardExitPrivate,
        &mut config.wireguard_exit.private_key,
    )?;
    persist_field(
        path,
        ConfigSecret::WireGuardExitPeerPreshared,
        &mut config.wireguard_exit.peer_preshared_key,
    )?;
    persist_network_join_secrets(path, config)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        config.pending_nostr_join_request = None;
        platform::delete_secret(path, ConfigSecret::PendingJoinRequest)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    persist_pending_join_request(path, config)
}

pub(crate) fn delete_config_secrets(path: &Path) -> Result<()> {
    let mut result = Ok(());
    for kind in [
        ConfigSecret::Nostr,
        ConfigSecret::WireGuardExitPrivate,
        ConfigSecret::WireGuardExitPeerPreshared,
        ConfigSecret::JoinSecret,
        ConfigSecret::PendingJoinRequest,
    ] {
        if let Err(error) = platform::delete_secret(path, kind) {
            result = Err(error);
        }
    }
    result
}

pub(crate) fn config_file_needs_secret_migration(path: &Path) -> Result<bool> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw).context("failed to parse config TOML")?;

    if nostr_secret_needs_migration(&value) {
        return Ok(true);
    }

    for field in ["private_key", "peer_preshared_key"] {
        if plaintext_secret_field(&value, "wireguard_exit", field) {
            return Ok(true);
        }
    }

    if plaintext_network_join_secret(&value) {
        return Ok(true);
    }

    if plaintext_pending_join_request(&value) {
        return Ok(true);
    }

    Ok(false)
}

#[derive(Debug, Clone, Copy)]
enum ConfigSecret {
    Nostr,
    WireGuardExitPrivate,
    WireGuardExitPeerPreshared,
    JoinSecret,
    PendingJoinRequest,
    #[cfg(feature = "cashu-wallet")]
    CashuWalletSeed,
}

impl ConfigSecret {
    fn account_suffix(self) -> &'static str {
        match self {
            Self::Nostr => "nostr-secret-key",
            Self::WireGuardExitPrivate => "wireguard-exit-private-key",
            Self::WireGuardExitPeerPreshared => "wireguard-exit-peer-preshared-key",
            Self::JoinSecret => "network-join-secrets",
            Self::PendingJoinRequest => "pending-join-request",
            #[cfg(feature = "cashu-wallet")]
            Self::CashuWalletSeed => "cashu-wallet-seed",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Nostr => "Nostr secret key",
            Self::WireGuardExitPrivate => "WireGuard exit private key",
            Self::WireGuardExitPeerPreshared => "WireGuard exit peer preshared key",
            Self::JoinSecret => "Network join secret",
            Self::PendingJoinRequest => "pending Nostr join request",
            #[cfg(feature = "cashu-wallet")]
            Self::CashuWalletSeed => "Cashu wallet seed",
        }
    }
}

/// CDK seed adapter backed by Nostr VPN's existing platform secret facility.
///
/// On iOS this uses the same generic-password Keychain service as the app's
/// existing secrets. On Android the backing key is created with user
/// authentication disabled, so wallet startup adds no biometric or passcode
/// prompt. The wallet database itself remains ordinary CDK SQLite.
#[cfg(feature = "cashu-wallet")]
#[derive(Debug, Clone)]
pub struct PlatformCashuWalletSeedStore {
    config_path: std::path::PathBuf,
}

#[cfg(feature = "cashu-wallet")]
impl PlatformCashuWalletSeedStore {
    #[must_use]
    pub fn new(config_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }
}

#[cfg(feature = "cashu-wallet")]
impl cashu_service::CashuWalletSeedStore for PlatformCashuWalletSeedStore {
    fn load_seed(&self) -> Result<Option<[u8; 64]>> {
        platform::read_secret(&self.config_path, ConfigSecret::CashuWalletSeed)?
            .map(|encoded| decode_cashu_wallet_seed(&encoded))
            .transpose()
    }

    fn store_seed(&self, seed: &[u8; 64]) -> Result<()> {
        if let Some(existing) = self.load_seed()? {
            if existing != *seed {
                return Err(anyhow!(
                    "refusing to replace the existing Cashu wallet seed in {}",
                    platform::store_name()
                ));
            }
            return Ok(());
        }

        platform::write_secret(
            &self.config_path,
            ConfigSecret::CashuWalletSeed,
            &hex::encode(seed),
        )?;
        if self.load_seed()? != Some(*seed) {
            return Err(anyhow!(
                "{} did not preserve the Cashu wallet seed exactly",
                platform::store_name()
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "cashu-wallet")]
fn decode_cashu_wallet_seed(encoded: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(encoded.trim()).context("Cashu wallet seed is not valid hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("Cashu wallet seed must be exactly 64 bytes"))
}

const REDACTED_SECRET_MARKERS: &[&str] = &[
    "stored-in-ios-keychain",
    "stored-in-android-keystore",
    "stored-in-windows-dpapi",
    "stored-in-private-secret-file",
];
#[cfg(any(target_os = "ios", target_os = "android"))]
const SERVICE: &str = "to.nostrvpn.nvpn.config-secrets";

fn hydrate_config_secret_fields(path: &Path, config: &mut AppConfig) -> Result<()> {
    if is_redacted_secret(&config.nostr.secret_key) {
        config.nostr.secret_key = read_required_secret(path, ConfigSecret::Nostr)?;
    } else if config.nostr.secret_key.trim().is_empty()
        && normalize_nostr_pubkey(&config.nostr.public_key).is_ok()
        && let Some(value) = platform::read_secret(path, ConfigSecret::Nostr)?
    {
        config.nostr.secret_key = value;
    }
    if is_redacted_secret(&config.wireguard_exit.private_key) {
        config.wireguard_exit.private_key =
            read_required_secret(path, ConfigSecret::WireGuardExitPrivate)?;
    }
    if is_redacted_secret(&config.wireguard_exit.peer_preshared_key) {
        config.wireguard_exit.peer_preshared_key =
            read_required_secret(path, ConfigSecret::WireGuardExitPeerPreshared)?;
    }
    hydrate_network_join_secrets(path, config)?;
    hydrate_pending_join_request(path, config)?;

    if config.nostr.secret_key.trim().is_empty()
        && normalize_nostr_pubkey(&config.nostr.public_key).is_ok()
    {
        return Err(anyhow!(
            "config {} references a Nostr public key but its secret key is missing from {}",
            path.display(),
            platform::store_name()
        ));
    }

    validate_nostr_secret_matches_public_key(path, config)?;
    let invalid_pending = if let Some(pending) = &config.pending_nostr_join_request {
        pending
            .validate_for_device(&config.own_nostr_pubkey_hex()?)
            .is_err()
    } else {
        false
    };
    if invalid_pending {
        config.pending_nostr_join_request = None;
    }
    Ok(())
}

fn hydrate_pending_join_request(path: &Path, config: &mut AppConfig) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        config.pending_nostr_join_request = None;
        let _ = platform::delete_secret(path, ConfigSecret::PendingJoinRequest);
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let Some(redacted) = config.pending_nostr_join_request.as_ref() else {
            return Ok(());
        };
        if redacted.version != PENDING_NOSTR_JOIN_REQUEST_VERSION {
            config.pending_nostr_join_request = None;
            return Ok(());
        }
        let secret_redacted = is_redacted_secret(&redacted.request.request_secret);
        let key_redacted = is_redacted_secret(&redacted.request_private_key);
        match (secret_redacted, key_redacted) {
            (false, false) => return Ok(()),
            (true, true) => {}
            _ => {
                return Err(anyhow!(
                    "pending Nostr join request has partially redacted secret material"
                ));
            }
        }

        let raw = read_required_secret(path, ConfigSecret::PendingJoinRequest)?;
        let hydrated: PendingNostrJoinRequest = serde_json::from_str(&raw)
            .context("failed to parse pending Nostr join request from secret storage")?;
        let mut expected_public = hydrated.clone();
        expected_public.request.request_secret.clear();
        expected_public.request_private_key.clear();
        let mut configured_public = redacted.clone();
        configured_public.request.request_secret.clear();
        configured_public.request_private_key.clear();
        if configured_public != expected_public {
            return Err(anyhow!(
                "pending Nostr join request in config does not match secret storage"
            ));
        }
        config.pending_nostr_join_request = Some(hydrated);
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn persist_pending_join_request(path: &Path, config: &mut AppConfig) -> Result<()> {
    let Some(pending) = config.pending_nostr_join_request.as_mut() else {
        return platform::delete_secret(path, ConfigSecret::PendingJoinRequest);
    };
    let secret_redacted = is_redacted_secret(&pending.request.request_secret);
    let key_redacted = is_redacted_secret(&pending.request_private_key);
    match (secret_redacted, key_redacted) {
        (true, true) => return Ok(()),
        (false, false) => {}
        _ => {
            return Err(anyhow!(
                "pending Nostr join request has partially redacted secret material"
            ));
        }
    }
    let device_pubkey = normalize_nostr_pubkey(&config.nostr.public_key)?;
    pending.validate_for_device(&device_pubkey)?;
    let mut encoded = serde_json::to_string(pending)
        .context("failed to encode pending Nostr join request for secret storage")?;
    persist_field(path, ConfigSecret::PendingJoinRequest, &mut encoded)?;
    if !is_redacted_secret(&encoded) {
        return Err(anyhow!(
            "pending Nostr join request was not stored securely"
        ));
    }
    pending.request.request_secret = platform::REDACTED_SECRET_MARKER.to_string();
    pending.request_private_key = platform::REDACTED_SECRET_MARKER.to_string();
    Ok(())
}

// One storage slot maps every network entry id to its join secret, since a
// config can hold several networks with distinct secrets.
fn hydrate_network_join_secrets(path: &Path, config: &mut AppConfig) -> Result<()> {
    if !config
        .networks
        .iter()
        .any(|network| is_redacted_secret(&network.join_secret))
    {
        return Ok(());
    }
    let raw = read_required_secret(path, ConfigSecret::JoinSecret)?;
    let stored: BTreeMap<String, String> =
        serde_json::from_str(&raw).context("failed to parse stored network join secrets")?;
    for network in &mut config.networks {
        if !is_redacted_secret(&network.join_secret) {
            continue;
        }
        network.join_secret = stored.get(&network.id).cloned().ok_or_else(|| {
            anyhow!(
                "{} for network {} is marked as stored in {}, but no matching secret exists",
                ConfigSecret::JoinSecret.display_name(),
                network.id,
                platform::store_name()
            )
        })?;
    }
    Ok(())
}

fn persist_network_join_secrets(path: &Path, config: &mut AppConfig) -> Result<()> {
    let mut stored: BTreeMap<String, String> =
        platform::read_secret(path, ConfigSecret::JoinSecret)?
            .map(|raw| {
                serde_json::from_str(&raw).context("failed to parse stored network join secrets")
            })
            .transpose()?
            .unwrap_or_default();
    let mut stored_ids = Vec::new();
    for network in &mut config.networks {
        let value = network.join_secret.trim();
        if is_redacted_secret(value) {
            continue;
        }
        if value.is_empty() {
            stored.remove(&network.id);
            continue;
        }
        stored.insert(network.id.clone(), value.to_string());
        stored_ids.push(network.id.clone());
    }
    let mut encoded = if stored.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&stored).context("failed to encode network join secrets")?
    };
    persist_field(path, ConfigSecret::JoinSecret, &mut encoded)?;
    for id in stored_ids {
        if let Some(network) = config.networks.iter_mut().find(|network| network.id == id) {
            network.join_secret = platform::REDACTED_SECRET_MARKER.to_string();
        }
    }
    Ok(())
}

fn validate_nostr_secret_matches_public_key(path: &Path, config: &mut AppConfig) -> Result<()> {
    let public_key = match normalize_nostr_pubkey(&config.nostr.public_key) {
        Ok(public_key) => public_key,
        Err(_) => return Ok(()),
    };
    let secret_key = config.nostr.secret_key.trim();
    if secret_key.is_empty() || is_redacted_secret(secret_key) {
        return Ok(());
    }
    let keys = Keys::parse(secret_key).with_context(|| {
        format!(
            "config {} has a Nostr public key but its secret key is invalid",
            path.display()
        )
    })?;
    let derived_public_key = keys.public_key().to_hex();
    if derived_public_key != public_key {
        #[cfg(target_os = "ios")]
        if let Some(recovered) = platform::recover_nostr_secret_for_public_key(&public_key)? {
            config.nostr.secret_key = recovered;
            return Ok(());
        }
        #[cfg(target_os = "ios")]
        if adopt_stored_nostr_identity_for_unjoined_config(config, &derived_public_key) {
            return Ok(());
        }
        return Err(anyhow!(
            "config {} has mismatched Nostr identity: secret key derives to a different public key than nostr.public_key; refusing to run with split identity",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "ios", test))]
fn adopt_stored_nostr_identity_for_unjoined_config(
    config: &mut AppConfig,
    stored_public_key: &str,
) -> bool {
    if !config.networks.is_empty() {
        return false;
    }
    config.nostr.public_key = stored_public_key.to_string();
    config.pending_nostr_join_request = None;
    true
}

#[cfg(any(target_os = "ios", test))]
fn select_nostr_secret_for_public_key(
    expected_public_key: &str,
    candidates: impl IntoIterator<Item = String>,
) -> Result<Option<String>> {
    let expected_public_key = normalize_nostr_pubkey(expected_public_key)?;
    let mut matches = candidates
        .into_iter()
        .filter(|candidate| {
            Keys::parse(candidate)
                .is_ok_and(|keys| keys.public_key().to_hex() == expected_public_key)
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [] => Ok(None),
        [matching] => Ok(Some(matching.clone())),
        _ => Err(anyhow!(
            "multiple stored Nostr secrets match the configured public key"
        )),
    }
}

fn persist_field(path: &Path, kind: ConfigSecret, value: &mut String) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        let _ = platform::delete_secret(path, kind);
        return Ok(());
    }
    if is_redacted_secret(trimmed) {
        return Ok(());
    }
    if trimmed.starts_with("stored-in-") {
        return Err(anyhow!(
            "{} uses unsupported secret storage marker {trimmed:?}",
            kind.display_name()
        ));
    }

    let secret = trimmed.to_string();
    match platform::write_secret(path, kind, &secret) {
        Ok(()) => {
            *value = platform::REDACTED_SECRET_MARKER.to_string();
            Ok(())
        }
        Err(write_error) => match platform::read_secret(path, kind) {
            Ok(Some(existing)) if existing == secret => {
                *value = platform::REDACTED_SECRET_MARKER.to_string();
                Ok(())
            }
            Ok(Some(_)) => Err(write_error).with_context(|| {
                format!(
                    "{} changed but updating {} failed",
                    kind.display_name(),
                    platform::store_name()
                )
            }),
            Ok(None) | Err(_) if platform::allows_plaintext_fallback() => {
                *value = secret;
                Ok(())
            }
            Ok(None) | Err(_) => Err(write_error).with_context(|| {
                format!(
                    "failed to store {} in {}; refusing to write it to the config file",
                    kind.display_name(),
                    platform::store_name()
                )
            }),
        },
    }
}

fn read_required_secret(path: &Path, kind: ConfigSecret) -> Result<String> {
    platform::read_secret(path, kind)?.ok_or_else(|| {
        anyhow!(
            "{} is marked as stored in {}, but no matching secret exists",
            kind.display_name(),
            platform::store_name()
        )
    })
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn scoped_account_name(path: &Path, kind: ConfigSecret) -> String {
    format!("{}:{}", config_scope(path), kind.account_suffix())
}

#[cfg(target_os = "ios")]
fn stable_account_name(kind: ConfigSecret) -> String {
    kind.account_suffix().to_string()
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn config_scope(path: &Path) -> String {
    let canonical = canonical_config_path(path);
    let mut hasher = Sha256::new();
    hasher.update(config_path_bytes(&canonical));
    hex::encode(hasher.finalize())
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn canonical_config_path(path: &Path) -> std::path::PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name())
        && let Ok(parent) = fs::canonicalize(parent)
    {
        return parent.join(file_name);
    }
    path.to_path_buf()
}

#[cfg(all(unix, any(target_os = "ios", target_os = "android")))]
fn config_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(all(windows, any(target_os = "ios", target_os = "android")))]
fn config_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(all(not(any(unix, windows)), any(target_os = "ios", target_os = "android")))]
fn config_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn is_redacted_secret(value: &str) -> bool {
    let value = value.trim();
    REDACTED_SECRET_MARKERS.contains(&value)
}

fn nostr_secret_needs_migration(value: &toml::Value) -> bool {
    let Some(nostr) = value.get("nostr").and_then(toml::Value::as_table) else {
        return false;
    };

    let Some(secret_key) = nostr.get("secret_key").and_then(toml::Value::as_str) else {
        return false;
    };
    let secret_key = secret_key.trim();
    if secret_key.is_empty() {
        return false;
    }

    let public_key = nostr
        .get("public_key")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .trim();

    public_key.is_empty() || !is_redacted_secret(secret_key)
}

fn plaintext_secret_field(value: &toml::Value, table: &str, field: &str) -> bool {
    value
        .get(table)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(field))
        .and_then(toml::Value::as_str)
        .is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && !is_redacted_secret(value)
        })
}

fn plaintext_network_join_secret(value: &toml::Value) -> bool {
    value
        .get("networks")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .any(|network| {
            network
                .get("join_secret")
                .and_then(toml::Value::as_str)
                .is_some_and(|secret| {
                    let secret = secret.trim();
                    !secret.is_empty() && !is_redacted_secret(secret)
                })
        })
}

fn plaintext_pending_join_request(value: &toml::Value) -> bool {
    let Some(pending) = value
        .get("pending_nostr_join_request")
        .and_then(toml::Value::as_table)
    else {
        return false;
    };
    let request_secret = pending
        .get("request")
        .and_then(toml::Value::as_table)
        .and_then(|request| request.get("requestSecret"))
        .and_then(toml::Value::as_str);
    let request_private_key = pending
        .get("request_private_key")
        .and_then(toml::Value::as_str);
    [request_secret, request_private_key]
        .into_iter()
        .flatten()
        .any(|value| !value.trim().is_empty() && !is_redacted_secret(value))
}

include!("config_secrets/platform_macos.rs");
include!("config_secrets/platform_ios.rs");
include!("config_secrets/platform_android.rs");
include!("config_secrets/platform_windows.rs");
include!("config_secrets/platform_linux.rs");
include!("config_secrets/platform_fallback_and_tests.rs");
