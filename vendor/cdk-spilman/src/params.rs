//! Spilman Channel Parameters
//!
//! Contains the protocol parameters for a Spilman payment channel

/// Type alias for channel identifiers (hex-encoded).
pub type ChannelId = String;

use serde::{Deserialize, Serialize};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{Parity, Scalar};
use cashu::nuts::{CurrencyUnit, SecretKey};
#[cfg(test)]
use cashu::nuts::{Id, Keys, PublicKey};
use cashu::util::hex;
#[cfg(test)]
use cashu::Amount;
use cashu::SECP256K1;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::str::FromStr;

use super::deterministic::DeterministicSecretWithBlinding;
use super::keysets_and_amounts::KeysetInfo;

pub(crate) struct Stage2P2bkTweakInfo {
    #[allow(dead_code)]
    pub(crate) ephemeral_secret: SecretKey,
    #[allow(dead_code)]
    pub(crate) ephemeral_pubkey: cashu::nuts::PublicKey,
    #[allow(dead_code)]
    pub(crate) ephemeral_shared_secret_x: [u8; 32],
    #[allow(dead_code)]
    pub(crate) stage2_tweak_scalar: Scalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage2Role {
    Sender,
    Receiver,
}

impl Stage2Role {
    fn stage2_context(self) -> &'static str {
        match self {
            Self::Sender => "sender_stage2",
            Self::Receiver => "receiver_stage2",
        }
    }

    fn pubkey(self, params: &ChannelParameters) -> &cashu::nuts::PublicKey {
        match self {
            Self::Sender => &params.sender_pubkey,
            Self::Receiver => &params.receiver_pubkey,
        }
    }
}

/// Parameters for a Spilman payment channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelParameters {
    /// Alice's public key (sender)
    pub sender_pubkey: cashu::nuts::PublicKey,
    /// Charlie's public key (receiver)
    pub receiver_pubkey: cashu::nuts::PublicKey,
    /// Mint URL (or "local" for in-process mint)
    pub mint: String,
    /// Currency unit for the channel
    pub unit: CurrencyUnit,
    /// Channel capacity: maximum final value (after both fee stages) that Charlie can receive
    pub capacity: u64,
    /// Total nominal value of the funding token (must satisfy: capacity <= forward(forward(funding_token_amount)))
    pub funding_token_amount: u64,
    /// Expiry timestamp after which Alice can reclaim funds (unix timestamp)
    pub expiry_timestamp: u64,
    /// Setup timestamp (unix timestamp when channel was created)
    pub setup_timestamp: u64,
    /// Keyset information (ID, keys, amounts, fees)
    pub keyset_info: KeysetInfo,
    /// Maximum amount for one output (amounts larger than this are filtered out)
    pub maximum_amount_for_one_output: u64,
    /// Channel secret: a domain-separated hash of the ECDH shared secret between Alice and Charlie
    pub channel_secret: [u8; 32],
}

/// Compute the channel secret from a secret key and counterparty's public key
///
/// Performs ECDH and then hashes the result with a domain separator so that
/// the raw Diffie-Hellman shared secret never leaves this function.
///
/// Returns: SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(my_secret, their_pubkey))
pub fn compute_channel_secret(
    my_secret: &cashu::nuts::SecretKey,
    their_pubkey: &cashu::nuts::PublicKey,
) -> [u8; 32] {
    let raw_ecdh = SharedSecret::new(their_pubkey, my_secret).secret_bytes();
    let mut input = Vec::new();
    input.extend_from_slice(b"Cashu_Spilman_channel_secret_v1");
    input.extend_from_slice(&raw_ecdh);
    sha256::Hash::hash(&input).to_byte_array()
}

/// Helper to create a simple KeysetInfo for testing
#[cfg(test)]
pub(crate) fn mock_keyset_info(amounts: Vec<u64>, input_fee_ppk: u64) -> KeysetInfo {
    let mut keys_map = BTreeMap::new();
    let dummy_pubkey =
        PublicKey::from_str("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
            .unwrap();
    for &amt in &amounts {
        keys_map.insert(Amount::from(amt), dummy_pubkey);
    }

    let mut amounts_largest_first = amounts;
    amounts_largest_first.sort_by(|a, b| b.cmp(a));

    let active_keys = Keys::new(keys_map);
    let keyset_id = Id::v1_from_keys(&active_keys);

    KeysetInfo::new(
        keyset_id,
        CurrencyUnit::Sat,
        active_keys,
        input_fee_ppk,
        None,
    )
}

/// Derive a blinded secret key for P2BK signing
///
/// Computes k = p + r (mod n), handling BIP-340 parity.
/// If the pubkey has odd Y, we use k = -p + r instead.
///
/// This ensures that signing with k produces a valid signature for the blinded pubkey P' = P + r*G.
fn derive_blinded_secret_key(secret: &SecretKey, r: &Scalar) -> anyhow::Result<SecretKey> {
    // Get parity of the public key by accessing the underlying secp256k1 pubkey
    // Our wrapper's x_only_public_key() only returns XOnlyPublicKey, but the inner
    // secp256k1::PublicKey::x_only_public_key() returns (XOnlyPublicKey, Parity)
    let pubkey = secret.public_key();
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // Get the underlying secp256k1 secret key
    // We need to clone because negate() consumes self
    let inner_secret: bitcoin::secp256k1::SecretKey = **secret;

    // If parity is odd, negate the secret key before adding the tweak
    // This is because BIP-340 signing will use the negated key for odd-Y pubkeys
    let effective_secret = if parity == Parity::Odd {
        inner_secret.negate()
    } else {
        inner_secret
    };

    // Add the blinding scalar: k = p + r (or k = -p + r if odd parity)
    let blinded = effective_secret
        .add_tweak(r)
        .map_err(|e| anyhow::anyhow!("Failed to add blinding tweak: {}", e))?;

    Ok(blinded.into())
}

/// Derive a blinded pubkey for P2BK verification
///
/// This is the pubkey-side counterpart to `derive_blinded_secret_key`.
/// It computes the pubkey that corresponds to the blinded secret key.
///
/// For BIP-340 compatibility:
/// - If pubkey has even Y: P' = P + r*G
/// - If pubkey has odd Y:  P' = -P + r*G
///
/// This ensures that `k*G = P'` where `k` is the blinded secret key.
fn derive_blinded_pubkey(
    pubkey: &cashu::nuts::PublicKey,
    r: &Scalar,
) -> anyhow::Result<cashu::nuts::PublicKey> {
    // Get parity of the public key
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    // If parity is odd, negate the pubkey before adding the tweak
    // This matches what derive_blinded_secret_key does with the secret key
    let effective_pubkey = if parity == Parity::Odd {
        inner_pubkey.negate(&SECP256K1)
    } else {
        *inner_pubkey
    };

    // Add the tweak: P' = P + r*G (or P' = -P + r*G if odd parity)
    let blinded = effective_pubkey
        .add_exp_tweak(&SECP256K1, r)
        .map_err(|e| anyhow::anyhow!("Failed to blind pubkey: {}", e))?;

    Ok(blinded.into())
}

impl ChannelParameters {
    /// Create new channel parameters with a pre-computed channel secret
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_pubkey: cashu::nuts::PublicKey,
        receiver_pubkey: cashu::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        funding_token_amount: u64,
        expiry_timestamp: u64,
        setup_timestamp: u64,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        channel_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        if unit != keyset_info.unit {
            anyhow::bail!(
                "Channel unit {} does not match keyset unit {}",
                unit,
                keyset_info.unit
            );
        }

        // Validate input_fee_ppk is in valid range
        if keyset_info.input_fee_ppk > 999 {
            anyhow::bail!(
                "input_fee_ppk must be between 0 and 999 (inclusive), got {}",
                keyset_info.input_fee_ppk
            );
        }

        // Validate capacity <= forward(forward(funding_token_amount))
        let max_capacity = {
            let after_stage1 = keyset_info.deterministic_value_after_fees(
                funding_token_amount,
                maximum_amount_for_one_output,
            )?;
            keyset_info
                .deterministic_value_after_fees(after_stage1, maximum_amount_for_one_output)?
        };
        if capacity > max_capacity {
            anyhow::bail!(
                "capacity {} exceeds maximum achievable capacity {} for funding_token_amount {} \
                 (capacity must be <= forward(forward(funding_token_amount)))",
                capacity,
                max_capacity,
                funding_token_amount
            );
        }

        Ok(Self {
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        })
    }

    /// Create new channel parameters by computing the channel secret from a secret key
    ///
    /// This constructor computes the channel secret (hashed ECDH) automatically.
    /// It auto-detects whether the provided secret key belongs to Alice or Charlie by checking
    /// if its public key matches either party, then uses the counterparty's public key for ECDH.
    ///
    /// # Arguments
    /// * `my_secret` - Either Alice's or Charlie's secret key
    /// * All other arguments are the same as `new`
    ///
    /// # Errors
    /// Returns an error if the secret key's public key doesn't match either sender_pubkey or receiver_pubkey
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_secret_key(
        sender_pubkey: cashu::nuts::PublicKey,
        receiver_pubkey: cashu::nuts::PublicKey,
        mint: String,
        unit: CurrencyUnit,
        capacity: u64,
        funding_token_amount: u64,
        expiry_timestamp: u64,
        setup_timestamp: u64,
        keyset_info: KeysetInfo,
        maximum_amount_for_one_output: u64,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        let my_pubkey = my_secret.public_key();

        // Determine which party we are and get the counterparty's pubkey
        let their_pubkey = if my_pubkey == sender_pubkey {
            // We are Alice, use Charlie's pubkey
            &receiver_pubkey
        } else if my_pubkey == receiver_pubkey {
            // We are Charlie, use Alice's pubkey
            &sender_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either sender_pubkey or receiver_pubkey"
            );
        };

        // Compute channel secret (hashed ECDH)
        let channel_secret = compute_channel_secret(my_secret, their_pubkey);

        Self::new(
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        )
    }

    /// Create channel parameters from a JSON string and a secret key
    ///
    /// The JSON should contain: mint, unit, capacity, keyset_id, input_fee_ppk,
    /// maximum_amount, setup_timestamp, sender_pubkey, receiver_pubkey, expiry_timestamp
    /// (as produced by `get_channel_id_params_json`)
    ///
    /// Additional parameters needed:
    /// * `keyset_info` - Keyset information from the mint (keyset_id and input_fee_ppk must match JSON)
    /// * `my_secret` - Either Alice's or Charlie's secret key for ECDH
    pub fn from_json_with_secret_key(
        json_str: &str,
        keyset_info: KeysetInfo,
        my_secret: &SecretKey,
    ) -> anyhow::Result<Self> {
        // Parse JSON to get pubkeys for ECDH
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        let sender_pubkey_hex = json["sender_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'sender_pubkey' field"))?;
        let sender_pubkey: cashu::nuts::PublicKey = sender_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid sender_pubkey: {}", e))?;

        let receiver_pubkey_hex = json["receiver_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'receiver_pubkey' field"))?;
        let receiver_pubkey: cashu::nuts::PublicKey = receiver_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver_pubkey: {}", e))?;

        // Determine counterparty and compute channel secret
        let my_pubkey = my_secret.public_key();
        let their_pubkey = if my_pubkey == sender_pubkey {
            &receiver_pubkey
        } else if my_pubkey == receiver_pubkey {
            &sender_pubkey
        } else {
            anyhow::bail!(
                "Secret key's public key doesn't match either sender_pubkey or receiver_pubkey"
            );
        };

        let channel_secret = compute_channel_secret(my_secret, their_pubkey);

        Self::from_json_with_channel_secret(json_str, keyset_info, channel_secret)
    }

    /// Create channel parameters from a JSON string with a pre-computed channel secret
    ///
    /// Same as `from_json` but takes the channel secret directly instead of computing it.
    pub fn from_json_with_channel_secret(
        json_str: &str,
        keyset_info: KeysetInfo,
        channel_secret: [u8; 32],
    ) -> anyhow::Result<Self> {
        let json: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

        // Parse keyset_id and input_fee_ppk first to validate against keyset_info
        let keyset_id_str = json["keyset_id"]
            .as_str()
            .or_else(|| json["keysetId"].as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'keyset_id' field"))?;
        let json_keyset_id: cashu::nuts::Id = keyset_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid keyset_id: {}", e))?;

        let json_input_fee_ppk = json["input_fee_ppk"]
            .as_u64()
            .or_else(|| json["inputFeePpk"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'input_fee_ppk' field"))?;

        // Validate keyset_info matches JSON
        if keyset_info.keyset_id != json_keyset_id {
            anyhow::bail!(
                "keyset_id mismatch: JSON has {}, KeysetInfo has {}",
                json_keyset_id,
                keyset_info.keyset_id
            );
        }
        if keyset_info.input_fee_ppk != json_input_fee_ppk {
            anyhow::bail!(
                "input_fee_ppk mismatch: JSON has {}, KeysetInfo has {}",
                json_input_fee_ppk,
                keyset_info.input_fee_ppk
            );
        }

        // Parse remaining fields
        let mint = json["mint"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'mint' field"))?
            .to_string();

        let unit_str = json["unit"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'unit' field"))?;
        let unit = match unit_str {
            "sat" => CurrencyUnit::Sat,
            "msat" => CurrencyUnit::Msat,
            "usd" => CurrencyUnit::Usd,
            "eur" => CurrencyUnit::Eur,
            _ => anyhow::bail!("Unknown unit: {}", unit_str),
        };

        let capacity = json["capacity"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'capacity' field"))?;

        let funding_token_amount = json["funding_token_amount"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'funding_token_amount' field"))?;

        let maximum_amount_for_one_output = json["maximum_amount"]
            .as_u64()
            .or_else(|| json["maximum_amount_for_one_output"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'maximum_amount' field"))?;

        let setup_timestamp = json["setup_timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'setup_timestamp' field"))?;

        let sender_pubkey_hex = json["sender_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'sender_pubkey' field"))?;
        let sender_pubkey: cashu::nuts::PublicKey = sender_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid sender_pubkey: {}", e))?;

        let receiver_pubkey_hex = json["receiver_pubkey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'receiver_pubkey' field"))?;
        let receiver_pubkey: cashu::nuts::PublicKey = receiver_pubkey_hex
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid receiver_pubkey: {}", e))?;

        let expiry_timestamp = json["expiry_timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'expiry_timestamp' field"))?;

        Self::new(
            sender_pubkey,
            receiver_pubkey,
            mint,
            unit,
            capacity,
            funding_token_amount,
            expiry_timestamp,
            setup_timestamp,
            keyset_info,
            maximum_amount_for_one_output,
            channel_secret,
        )
    }

    /// Get channel capacity
    /// Returns the maximum final value (after both fee stages) that Charlie can receive
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get channel ID as raw bytes (32-byte SHA256 hash)
    /// The hash is computed over: mint|unit|capacity|funding_token_amount|keyset_id|input_fee_ppk|maximum_amount|setup_timestamp|sender_pubkey|receiver_pubkey|expiry_timestamp|channel_secret
    ///
    /// The channel_secret (channel_secret) is included implicitly — it does not
    /// appear in `get_channel_id_params_json()`. This means the channel ID can
    /// only be computed by the two parties who know the channel secret.
    pub fn get_channel_id_bytes(&self) -> [u8; 32] {
        let params_string = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.mint,
            self.unit_name(),
            self.capacity,
            self.funding_token_amount,
            self.keyset_info.keyset_id,
            self.keyset_info.input_fee_ppk,
            self.maximum_amount_for_one_output,
            self.setup_timestamp,
            self.sender_pubkey.to_hex(),
            self.receiver_pubkey.to_hex(),
            self.expiry_timestamp,
            hex::encode(self.channel_secret)
        );
        sha256::Hash::hash(params_string.as_bytes()).to_byte_array()
    }

    /// Get channel ID as a hex string
    pub fn get_channel_id(&self) -> String {
        hex::encode(self.get_channel_id_bytes())
    }

    /// Get a JSON string representation of the data that contributes to the channel ID
    /// This includes all parameters that define the channel unique identity.
    pub fn get_channel_id_params_json(&self) -> String {
        serde_json::json!({
            "mint": self.mint,
            "unit": self.unit_name(),
            "capacity": self.capacity,
            "funding_token_amount": self.funding_token_amount,
            "keyset_id": self.keyset_info.keyset_id.to_string(),
            "input_fee_ppk": self.keyset_info.input_fee_ppk,
            "maximum_amount": self.maximum_amount_for_one_output,
            "setup_timestamp": self.setup_timestamp,
            "sender_pubkey": self.sender_pubkey.to_hex(),
            "receiver_pubkey": self.receiver_pubkey.to_hex(),
            "expiry_timestamp": self.expiry_timestamp
        })
        .to_string()
    }
}

mod blinding;

#[cfg(test)]
mod tests;
