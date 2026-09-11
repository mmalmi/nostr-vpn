#![allow(missing_docs)]
//! Spilman Protocol Bridge
//!
//! This module provides a high-level bridge for implementing Spilman payment channels
//! in any service provider. It handles the core protocol logic, validation, and
//! signature verification, while delegating storage and pricing to a host hook.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use super::params::Stage2Role;
use super::{
    verify_valid_channel, ChannelParameters, CommitmentOutputs, DeterministicSecretWithBlinding,
    EstablishedChannel, KeysetInfo,
};
use async_trait::async_trait;
use cashu::nuts::{BlindSignature, CurrencyUnit, Id, Proof, PublicKey, SwapRequest};
use cashu::util::hex;
use std::str::FromStr;

/// Funding data for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFunding {
    /// Serialized channel parameters
    pub params_json: String,
    /// Serialized funding proofs
    pub funding_proofs_json: String,
    /// Hex-encoded channel secret
    pub channel_secret_hex: String,
    /// Serialized keyset info
    pub keyset_info_json: String,
}

/// Payment proof for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// Current balance
    pub balance: u64,
    /// Alice's signature over the balance
    pub signature: String,
}

/// Channel lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Channel is open and accepting payments
    Open,
    /// Channel is closing (swap pending, no more payments accepted)
    Closing,
    /// Channel is closed (swap completed, proofs stored)
    Closed,
}

/// Data stored when a channel enters CLOSING state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingData {
    /// The channel's expiry timestamp
    pub expiry_timestamp: u64,
    /// The balance at close
    pub balance: u64,
    /// The client's Schnorr signature authorizing this balance
    pub signature: String,
}

/// Host hooks for the Spilman bridge
///
/// Implement this trait to provide storage and pricing logic for your service.
/// The generic type `C` allows for a custom request context used in pricing.
pub trait SpilmanHost<C = String> {
    /// Check if the receiver pubkey in the channel params is acceptable
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Check if the mint and keyset are acceptable
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &cashu::nuts::Id) -> bool;

    /// Get fully persisted funding data for a channel.
    ///
    /// Return `None` while an interrupted initial save is missing its signed
    /// initial payment so the original funding request can repair it.
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Save funding data for a channel, including the initial payment proof.
    /// An error suppresses payment success and must cover any failed funding
    /// or initial-balance persistence.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) -> Result<(), String>;

    /// Get the current amount due for a channel
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;

    /// Persist an accepted payment and its usage update.
    /// Return an error if either write fails; the bridge will not acknowledge
    /// the payment as successful.
    fn record_payment(
        &self,
        channel_id: &str,
        payment: PaymentProof,
        context: &C,
    ) -> Result<(), String>;

    /// Get the current state of a channel.
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing (pre-swap state).
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String>;

    /// Get the stored closing data for a channel in CLOSING state.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

    /// Get channel policy for a given unit: funding-time validation thresholds.
    /// Returns `None` if the unit is not supported.
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;

    /// Get the current time in seconds
    fn now_seconds(&self) -> u64;

    /// Get the balance and signature for a unilateral exit
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof>;

    /// Get active keyset IDs for a mint and unit
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Get full KeysetInfo JSON for a specific keyset
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    /// Mark a channel as closed and persist the final state
    #[allow(clippy::too_many_arguments)]
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    /// Compute the ECDH-derived channel secret.
    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Sign a message with the tweaked (P2BK-blinded) server key.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

/// Sync networking hooks for the Spilman bridge
pub trait SpilmanNetworking {
    /// Call the mint's /v1/swap endpoint
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Async networking hooks for the Spilman bridge
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SpilmanAsyncNetworking {
    /// Call the mint's /v1/swap endpoint
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String>;

    /// Refresh the keyset cache for a mint
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

/// Bridge for processing Spilman payments
#[derive(Debug)]
pub struct SpilmanBridge<H: SpilmanHost<C>, C = String> {
    host: H,
    _phantom: std::marker::PhantomData<C>,
}

/// A signed payment for a Spilman channel.
///
/// This is the core protocol message exchanged between client and server.
/// The client creates it via `SpilmanClientBridge::create_payment()`,
/// the server validates it via `SpilmanBridge::process_payment()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// Channel identifier
    pub channel_id: String,
    /// Cumulative balance the receiver can claim (monotonically increasing)
    pub balance: u64,
    /// BIP-340 Schnorr signature over the balance commitment
    pub signature: String,
    /// Channel parameters (required on first payment to register channel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// Funding proofs (required on first payment to register channel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding_proofs: Option<Vec<Proof>>,
}

impl Payment {
    /// Create a payment without funding data (for subsequent payments)
    pub fn new(channel_id: String, balance: u64, signature: String) -> Self {
        Self {
            channel_id,
            balance,
            signature,
            params: None,
            funding_proofs: None,
        }
    }

    /// Create a payment with funding data (for first payment)
    pub fn with_funding(
        channel_id: String,
        balance: u64,
        signature: String,
        params: serde_json::Value,
        funding_proofs: Vec<Proof>,
    ) -> Self {
        Self {
            channel_id,
            balance,
            signature,
            params: Some(params),
            funding_proofs: Some(funding_proofs),
        }
    }

    /// Check if this payment includes funding data
    pub fn has_funding(&self) -> bool {
        self.params.is_some() && self.funding_proofs.is_some()
    }
}

/// Result of a successful payment
#[derive(Debug, Clone, Serialize)]
pub struct PaymentSuccess {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
}

/// Data needed to close a channel
#[derive(Debug)]
pub struct CloseData {
    pub swap_request: SwapRequest,
    pub expected_total: u64,
    pub secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    pub output_keyset_info: KeysetInfo,
}

impl CloseData {
    pub fn to_json_value(self) -> serde_json::Value {
        let swap_request_json =
            serde_json::to_value(&self.swap_request).unwrap_or(serde_json::Value::Null);

        let secrets_with_blinding: Vec<serde_json::Value> = self
            .secrets_with_blinding
            .into_iter()
            .map(|(s, is_receiver)| {
                serde_json::json!({
                    "secret": s.secret.to_string(),
                    "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()),
                    "amount": s.amount,
                    "index": s.index,
                    "is_receiver": is_receiver
                })
            })
            .collect();

        serde_json::json!({
            "success": true,
            "swap_request": swap_request_json,
            "expected_total": self.expected_total,
            "secrets_with_blinding": secrets_with_blinding,
            "output_keyset_info": serde_json::to_value(&self.output_keyset_info).unwrap_or(serde_json::Value::Null)
        })
    }
}

/// A proof with its (amount, index) metadata from the commitment outputs
#[derive(Debug)]
pub struct ProofWithMeta {
    pub proof: Proof,
    pub amount: u64,
    pub index: usize,
    pub is_receiver: bool,
}

/// Result of unblinding and verifying stage 1 swap response
#[derive(Debug)]
pub struct UnblindResult {
    pub receiver_proofs: Vec<ProofWithMeta>,
    pub sender_proofs: Vec<ProofWithMeta>,
    pub receiver_sum: u64,
    pub sender_sum: u64,
}

/// Everything needed to execute a close operation after sync validation.
#[derive(Debug)]
pub struct PreparedClose {
    pub channel_id: String,
    pub balance: u64,
    pub mint_url: String,
    pub swap_request: serde_json::Value,
    pub secrets_with_blinding: serde_json::Value,
    pub output_keyset_info: serde_json::Value,
    pub params_json: String,
    pub keyset_info_json: String,
    pub channel_secret: String,
}

/// HTTP-friendly error for close preparation.
#[derive(Debug, Clone, Serialize)]
pub struct ClosePreparationError {
    pub error: String,
    pub reason: String,
    pub status: u16,
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ClosePreparationError {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            error: "Bad request".into(),
            reason: reason.into(),
            status: 400,
            extra: None,
        }
    }

    pub fn payment_required(reason: impl Into<String>) -> Self {
        Self {
            error: "Payment required".into(),
            reason: reason.into(),
            status: 402,
            extra: None,
        }
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            error: reason.clone(),
            reason,
            status: 404,
            extra: None,
        }
    }

    pub fn internal(reason: impl Into<String>) -> Self {
        Self {
            error: "Internal error".into(),
            reason: reason.into(),
            status: 500,
            extra: None,
        }
    }

    pub fn conflict(reason: impl Into<String>) -> Self {
        Self {
            error: "Channel closing".into(),
            reason: reason.into(),
            status: 409,
            extra: None,
        }
    }

    pub fn gone(reason: impl Into<String>) -> Self {
        Self {
            error: "Channel closed".into(),
            reason: reason.into(),
            status: 410,
            extra: None,
        }
    }

    pub fn with_extra(mut self, extra: serde_json::Map<String, serde_json::Value>) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn from_bridge_error(err: BridgeError) -> Self {
        let reason = err.to_string();
        match &err {
            BridgeError::ChannelClosed => Self::gone(reason),
            BridgeError::ChannelClosing => Self::conflict(reason),
            BridgeError::UnknownChannel => Self::not_found(reason),
            BridgeError::InvalidRequest(msg) if msg.contains("no payment proof") => {
                Self::bad_request(reason)
            }
            BridgeError::Internal(_) | BridgeError::ServerMisconfigured(_) => {
                Self::internal(reason)
            }
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut extra = serde_json::Map::new();
                extra.insert("expected".into(), serde_json::json!(expected));
                extra.insert("actual".into(), serde_json::json!(actual));
                Self::payment_required(reason).with_extra(extra)
            }
            _ => Self::payment_required(reason),
        }
    }
}

/// HTTP-friendly error for payment/validation failures.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeErrorResponse {
    pub error: String,
    pub reason: String,
    pub status: u16,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl BridgeErrorResponse {
    pub fn from_bridge_error(err: &BridgeError) -> Self {
        let reason = err.to_string();
        let mut extra: Option<serde_json::Map<String, serde_json::Value>> = None;

        let (status, error, code) = match err {
            BridgeError::InvalidRequest(_) => (400, "Bad request", "invalid_request"),
            BridgeError::UnknownChannel => (404, "Not found", "unknown_channel"),
            BridgeError::ChannelClosing => (409, "Channel closing", "channel_closing"),
            BridgeError::ChannelClosed => (410, "Channel closed", "channel_closed"),
            BridgeError::ServerMisconfigured(_) => (500, "Internal error", "server_misconfigured"),
            BridgeError::Internal(_) => (500, "Internal error", "internal"),
            BridgeError::BalanceMismatch { expected, actual } => {
                let mut map = serde_json::Map::new();
                map.insert("expected".into(), serde_json::json!(expected));
                map.insert("actual".into(), serde_json::json!(actual));
                extra = Some(map);
                (402, "Payment required", "balance_mismatch")
            }
            BridgeError::BalanceExceedsCapacity { balance, capacity } => {
                let mut map = serde_json::Map::new();
                map.insert("balance".into(), serde_json::json!(balance));
                map.insert("capacity".into(), serde_json::json!(capacity));
                extra = Some(map);
                (402, "Payment required", "balance_exceeds_capacity")
            }
            BridgeError::InsufficientBalance {
                balance,
                amount_due,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("balance".into(), serde_json::json!(balance));
                map.insert("amount_due".into(), serde_json::json!(amount_due));
                extra = Some(map);
                (402, "Payment required", "insufficient_balance")
            }
            BridgeError::CapacityTooSmall {
                capacity,
                min_capacity,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("capacity".into(), serde_json::json!(capacity));
                map.insert("min_capacity".into(), serde_json::json!(min_capacity));
                extra = Some(map);
                (402, "Payment required", "capacity_too_small")
            }
            BridgeError::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry,
                now,
            } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "expiry_timestamp".into(),
                    serde_json::json!(expiry_timestamp),
                );
                map.insert("min_expiry".into(), serde_json::json!(min_expiry));
                map.insert("now".into(), serde_json::json!(now));
                extra = Some(map);
                (402, "Payment required", "expiry_too_soon")
            }
            BridgeError::MaxAmountExceeded {
                amount,
                max_allowed,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("amount".into(), serde_json::json!(amount));
                map.insert("max_allowed".into(), serde_json::json!(max_allowed));
                extra = Some(map);
                (402, "Payment required", "max_amount_exceeded")
            }
            BridgeError::UnsupportedUnit(_) => (402, "Payment required", "unsupported_unit"),
            BridgeError::ChannelIdMismatch => (402, "Payment required", "channel_id_mismatch"),
            BridgeError::ValidationFailed(_) => (402, "Payment required", "validation_failed"),
            BridgeError::InvalidSignature(_) => (402, "Payment required", "invalid_signature"),
            BridgeError::ReceiverKeyNotAcceptable => {
                (402, "Payment required", "receiver_key_not_acceptable")
            }
            BridgeError::MintOrKeysetNotAcceptable => {
                (402, "Payment required", "mint_or_keyset_not_acceptable")
            }
        };

        Self {
            error: error.to_string(),
            reason,
            status,
            code: code.to_string(),
            extra,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            "{\"error\":\"Internal error\",\"reason\":\"failed to serialize bridge error\",\"status\":500,\"code\":\"internal\"}"
                .to_string()
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentValidationResult {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
    pub sender_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundChannelResult {
    pub channel_id: String,
    pub capacity: u64,
    pub already_known: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseSuccess {
    pub channel_id: String,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub sender_proofs: String,
    pub already_closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum CloseError {
    #[serde(rename = "validation_failed")]
    ValidationFailed {
        reason: String,
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_balance: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        actual_balance: Option<u64>,
    },
    #[serde(rename = "unknown_channel")]
    UnknownChannel { status: u16 },
    #[serde(rename = "already_closed")]
    AlreadyClosed {
        closed_balance: u64,
        requested_balance: u64,
        status: u16,
    },
    #[serde(rename = "mint_rejected")]
    MintRejected {
        mint_error: serde_json::Value,
        status: u16,
    },
    #[serde(rename = "mint_rejected_after_retry")]
    MintRejectedAfterRetry {
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
        status: u16,
    },
    #[serde(rename = "unblind_failed")]
    UnblindFailed { reason: String, status: u16 },
    #[serde(rename = "storage_failed")]
    StorageFailed { reason: String, status: u16 },
}

impl CloseError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationFailed { status, .. }
            | Self::UnknownChannel { status }
            | Self::AlreadyClosed { status, .. }
            | Self::MintRejected { status, .. }
            | Self::MintRejectedAfterRetry { status, .. }
            | Self::UnblindFailed { status, .. }
            | Self::StorageFailed { status, .. } => *status,
        }
    }

    pub fn from_preparation_error(err: ClosePreparationError) -> Self {
        let (expected_balance, actual_balance) = if let Some(extra) = &err.extra {
            (
                extra.get("expected").and_then(|v| v.as_u64()),
                extra.get("actual").and_then(|v| v.as_u64()),
            )
        } else {
            (None, None)
        };
        Self::ValidationFailed {
            reason: err.reason,
            status: err.status,
            expected_balance,
            actual_balance,
        }
    }

    pub fn unknown_channel() -> Self {
        Self::UnknownChannel { status: 404 }
    }
    pub fn mint_rejected(mint_error: serde_json::Value) -> Self {
        Self::MintRejected {
            mint_error,
            status: 502,
        }
    }
    pub fn mint_rejected_after_retry(
        original_error: serde_json::Value,
        retry_error: serde_json::Value,
    ) -> Self {
        Self::MintRejectedAfterRetry {
            original_error,
            retry_error,
            status: 502,
        }
    }
    pub fn unblind_failed(reason: impl Into<String>) -> Self {
        Self::UnblindFailed {
            reason: reason.into(),
            status: 500,
        }
    }
    pub fn storage_failed(reason: impl Into<String>) -> Self {
        Self::StorageFailed {
            reason: reason.into(),
            status: 500,
        }
    }
}

fn parse_mint_error_value(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()))
}

/// Extract the NUT-00 error code from a raw error string.
/// Returns None if the string is not valid JSON or lacks a "code" field.
fn extract_nut00_error_code(raw: &str) -> Option<u32> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v.get("code")?.as_u64())
        .map(|c| c as u32)
}

/// Returns true if the error code is in the keyset error range (12xxx).
/// These errors may be recoverable by refreshing keysets and retrying.
///
/// Workaround: also treats code 99999 as retryable. Nutmix returns this
/// catch-all code instead of the spec-standard 12001 ("Keyset is not known").
/// This can be removed once nutmix is fixed:
/// <https://github.com/lescuer97/nutmix/issues/237>
fn is_keyset_error_code(code: u32) -> bool {
    (12000..13000).contains(&code) || code == 99999
}

/// Determine if a swap error should trigger a retry (refresh keysets + re-attempt).
/// Keyset errors (12xxx) and code 99999 (nutmix workaround) are retryable.
/// All other errors fail immediately. If the error can't be parsed, fail immediately.
fn should_retry_swap_error(raw: &str) -> bool {
    match extract_nut00_error_code(raw) {
        Some(code) => {
            let retryable = is_keyset_error_code(code);
            if retryable {
                tracing::debug!(
                    code,
                    "Keyset error detected, will retry after refreshing keysets"
                );
            } else {
                tracing::debug!(code, "Non-retryable NUT-00 error code, failing immediately");
            }
            retryable
        }
        None => {
            tracing::debug!(error = %raw, "Could not parse NUT-00 error code, failing immediately");
            false
        }
    }
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed { reason, .. } => write!(f, "validation failed: {}", reason),
            Self::UnknownChannel { .. } => write!(f, "unknown channel"),
            Self::AlreadyClosed {
                closed_balance,
                requested_balance,
                ..
            } => write!(
                f,
                "channel already closed with balance {} (requested {})",
                closed_balance, requested_balance
            ),
            Self::MintRejected { mint_error, .. } => {
                write!(f, "mint rejected swap: {}", mint_error)
            }
            Self::MintRejectedAfterRetry {
                original_error,
                retry_error,
                ..
            } => write!(
                f,
                "mint rejected swap after retry: original={}, retry={}",
                original_error, retry_error
            ),
            Self::UnblindFailed { reason, .. } => write!(f, "unblind failed: {}", reason),
            Self::StorageFailed { reason, .. } => write!(f, "storage failed: {}", reason),
        }
    }
}

impl std::error::Error for CloseError {}

/// Funding-time validation thresholds for a given unit, returned by
/// [`SpilmanHost::get_channel_policy`].
#[derive(Debug, Clone)]
pub struct ChannelPolicy {
    /// Minimum seconds between now and the channel expiry timestamp.
    pub min_expiry_in_seconds: u64,
    /// Minimum channel capacity (in the unit's base denomination).
    pub min_capacity: u64,
    /// Optional cap on the largest single proof denomination.
    pub max_amount_per_output: Option<u64>,
}

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String),
    ChannelClosed,
    ChannelClosing,
    ServerMisconfigured(String),
    CapacityTooSmall {
        capacity: u64,
        min_capacity: u64,
    },
    ExpiryTooSoon {
        expiry_timestamp: u64,
        min_expiry: u64,
        now: u64,
    },
    MaxAmountExceeded {
        amount: u64,
        max_allowed: u64,
    },
    BalanceExceedsCapacity {
        balance: u64,
        capacity: u64,
    },
    UnsupportedUnit(String),
    ChannelIdMismatch,
    ValidationFailed(String),
    UnknownChannel,
    InvalidSignature(String),
    InsufficientBalance {
        balance: u64,
        amount_due: u64,
    },
    BalanceMismatch {
        expected: u64,
        actual: u64,
    },
    Internal(String),
    ReceiverKeyNotAcceptable,
    MintOrKeysetNotAcceptable,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(s) => write!(f, "{}", s),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::ChannelClosing => write!(f, "channel closing, swap pending"),
            Self::ServerMisconfigured(s) => write!(f, "server misconfigured: {}", s),
            Self::CapacityTooSmall {
                capacity,
                min_capacity,
            } => write!(f, "capacity too small: {} < {}", capacity, min_capacity),
            Self::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry,
                now,
            } => write!(
                f,
                "expiry too soon: {} < {} ({}s remaining)",
                expiry_timestamp,
                min_expiry,
                expiry_timestamp.saturating_sub(*now)
            ),
            Self::MaxAmountExceeded {
                amount,
                max_allowed,
            } => write!(
                f,
                "max_amount_per_output exceeded: {} > {}",
                amount, max_allowed
            ),
            Self::BalanceExceedsCapacity { balance, capacity } => {
                write!(f, "balance exceeds capacity: {} > {}", balance, capacity)
            }
            Self::UnsupportedUnit(u) => write!(f, "unsupported unit: {}", u),
            Self::ChannelIdMismatch => write!(f, "channel_id mismatch"),
            Self::ValidationFailed(s) => write!(f, "channel validation failed: {}", s),
            Self::UnknownChannel => write!(f, "unknown channel"),
            Self::InvalidSignature(s) => write!(f, "invalid signature: {}", s),
            Self::InsufficientBalance {
                balance,
                amount_due,
            } => write!(f, "insufficient balance: {} < {}", balance, amount_due),
            Self::BalanceMismatch { expected, actual } => {
                write!(f, "balance mismatch: expected {}, got {}", expected, actual)
            }
            Self::Internal(s) => write!(f, "internal error: {}", s),
            Self::ReceiverKeyNotAcceptable => write!(f, "receiver key not acceptable"),
            Self::MintOrKeysetNotAcceptable => write!(f, "mint or keyset not acceptable"),
        }
    }
}

impl BridgeError {
    pub fn to_response(&self) -> BridgeErrorResponse {
        BridgeErrorResponse::from_bridge_error(self)
    }

    pub fn to_response_json(&self) -> String {
        self.to_response().to_json()
    }
}


mod unblind;
pub use unblind::unblind_and_verify_stage1_response;

mod close;
mod payment;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "bridge_persistence_tests.rs"]
mod persistence_tests;
