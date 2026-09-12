//! Client-side Spilman channel bridge
//!
//! This module provides a high-level client-side API for managing Spilman payment channels,
//! mirroring the server-side `SpilmanBridge` / `SpilmanHost` pattern.
//!
//! The `SpilmanClientHost` trait handles storage and crypto callbacks, while
//! `SpilmanClientNetworking` handles mint communication. The `SpilmanClientBridge`
//! orchestrates channel creation, payment signing, and header construction.
//!
//! # Example (pseudocode)
//! ```ignore
//! let host = MyClientHost::new();
//! let networking = MyNetworking::new();
//! let bridge = SpilmanClientBridge::new(host, networking);
//!
//! // Open a channel from an existing Cashu token
//! let result = bridge.open_channel_from_token(...)?;
//!
//! // Make payments
//! let payment = bridge.create_payment(&result.channel_id, 10)?;
//! let payment_with_funding = bridge.create_payment_with_funding(&result.channel_id, 10)?;
//! ```

use base64::Engine;
use cashu::nuts::{Proof, SwapRequest};
use serde::{Deserialize, Serialize};

use super::balance_update::{
    encode_sig_all_signature_bundle, nutshell_0_20_sig_all_message_hash_hex, BalanceUpdateMessage,
    UnsignedBalanceUpdate,
};
#[cfg(feature = "wallet")]
use super::bindings::{complete_funding_swap, compute_channel_from_token, create_funding_swap};
use super::bridge::Payment;
use super::client_storage::{ClientChannelFunding, ClientChannelState, ClientPaymentState};

// ============================================================================
// SpilmanClientHost trait
// ============================================================================

/// Trait for client-side host callbacks.
///
/// Provides storage and crypto operations. This is the client-side
/// counterpart of the server-side `SpilmanHost` trait.
///
/// The trait separates immutable funding data from mutable payment state,
/// mirroring the server-side pattern. Networking is handled by a separate
/// `SpilmanClientNetworking` trait.
pub trait SpilmanClientHost {
    // ========================================================================
    // Funding Data (immutable after creation)
    // ========================================================================

    /// Save funding data for a newly created channel.
    ///
    /// Called once after successful channel creation. The funding data
    /// is immutable after this point.
    fn save_channel_funding(&self, channel_id: &str, funding: ClientChannelFunding);

    /// Get funding data for a channel.
    ///
    /// Returns `None` if the channel does not exist.
    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding>;

    // ========================================================================
    // Payment State (mutable)
    // ========================================================================

    /// Get the current payment state for a channel.
    ///
    /// Returns `None` if no payments have been made yet.
    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState>;

    /// Record a new payment state.
    ///
    /// Called after each successful payment signing. Updates the stored
    /// balance, signature, payment count, and timestamp.
    fn record_payment(&self, channel_id: &str, state: ClientPaymentState);

    // ========================================================================
    // Channel Lifecycle
    // ========================================================================

    /// Get the lifecycle state of a channel.
    fn get_channel_state(&self, channel_id: &str) -> ClientChannelState;

    /// Mark a channel as closed.
    ///
    /// After this, the channel cannot accept new payments.
    fn mark_channel_closed(&self, channel_id: &str);

    /// List all stored channel IDs.
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel and all its data.
    fn delete_channel(&self, channel_id: &str);

    // ========================================================================
    // Time
    // ========================================================================

    /// Get the current time in seconds since Unix epoch.
    fn now_seconds(&self) -> u64;

    // ========================================================================
    // Crypto (delegated to host)
    // ========================================================================

    /// Compute the hashed ECDH channel secret for a channel.
    ///
    /// The host performs ECDH between the sender's secret key (identified by
    /// `sender_pubkey_hex`) and the receiver's public key, then hashes the result
    /// with a domain separator:
    ///   SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(sender_secret, receiver_pubkey))
    ///
    /// For hosts that hold raw secret keys, the convenience function
    /// `crate::bindings::compute_channel_secret_from_hex()` provides
    /// a standard implementation.
    ///
    /// # Arguments
    /// * `sender_pubkey_hex` - Sender's public key (identifies which secret key to use)
    /// * `receiver_pubkey_hex` - Receiver's public key
    ///
    /// # Returns
    /// The hashed channel secret as a 64-char hex string (32 bytes).
    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Sign a message with a tweaked key (BIP-340 Schnorr).
    ///
    /// The bridge computes the tweak (P2BK blinding scalar) and message hash,
    /// then asks the host to produce a BIP-340 Schnorr signature using
    /// the key `(secret + tweak)` where `secret` is the key corresponding
    /// to `signer_pubkey_hex`.
    ///
    /// The host must handle BIP-340 parity: if the public key has odd Y,
    /// negate the secret key before adding the tweak.
    ///
    /// For hosts that hold raw secret keys, the convenience function
    /// `crate::bindings::sign_with_tweaked_key_util()` provides
    /// a standard implementation.
    ///
    /// # Arguments
    /// * `signer_pubkey_hex` - Identifies which key to use (Alice's pubkey for this channel)
    /// * `message_hex` - SHA-256 hash of the SIG_ALL message (32 bytes, hex-encoded)
    /// * `tweak_scalar_hex` - The P2BK blinding scalar to add to the secret key (32 bytes, hex)
    ///
    /// # Returns
    /// The BIP-340 Schnorr signature as a 64-byte hex string.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String>;
}

// ============================================================================
// SpilmanClientNetworking trait
// ============================================================================

/// Networking trait for client-side mint communication.
///
/// Separated from `SpilmanClientHost` to allow different networking
/// implementations (sync, async, mock for testing).
pub trait SpilmanClientNetworking {
    /// Execute a swap with the mint.
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
}

// ============================================================================
// SpilmanClientAsyncNetworking trait (for WASM)
// ============================================================================

/// Async networking trait for client-side mint communication.
///
/// This is the async counterpart of `SpilmanClientNetworking`, designed for
/// environments like WASM where networking must be asynchronous.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SpilmanClientAsyncNetworking {
    /// Execute a swap with the mint (async version).
    ///
    /// Posts `swap_request_json` to `{mint_url}/v1/swap` and returns the
    /// response body as a JSON string.
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String>;
}

// ============================================================================
// Result/info types
// ============================================================================

/// Result of opening a new channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannelResult {
    /// Stable identifier for the newly opened channel.
    pub channel_id: String,
    /// Maximum final value the receiver can claim from the channel.
    pub capacity: u64,
    /// Nominal funding token amount required to support `capacity`.
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel's funding proofs.
    pub mint_url: String,
    /// Sender public key used for this channel.
    pub sender_pubkey_hex: String,
}

/// Information about a stored channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelInfo {
    /// Stable identifier for the stored channel.
    pub channel_id: String,
    /// Maximum final value the receiver can claim from the channel.
    pub capacity: u64,
    /// Nominal funding token amount backing the channel.
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel.
    pub mint_url: String,
    /// Current balance (last signed amount).
    pub current_balance: u64,
    /// Number of payments made through this channel.
    pub payment_count: u64,
    /// Channel state (Open/Closed).
    pub state: ClientChannelState,
}

// ============================================================================
// SpilmanClientBridge
// ============================================================================

/// Client-side bridge for managing Spilman payment channels.
///
/// This is the client-side counterpart of `SpilmanBridge`. It orchestrates
/// channel creation from tokens, payment signing, and HTTP header construction.
///
/// The bridge itself is stateless — all channel state is stored via the host.
/// The bridge never holds or sees Alice's secret key; all operations requiring
/// the key are delegated to the host via callbacks.
#[derive(Debug)]
pub struct SpilmanClientBridge<H: SpilmanClientHost, N: SpilmanClientNetworking> {
    host: H,
    #[allow(dead_code)] // Used only with "wallet" feature for open_channel_from_token
    networking: N,
}

#[cfg(feature = "wallet")]
fn normalize_mint_error_string(raw: String) -> String {
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(|value| value.to_string())
        .unwrap_or(raw)
}

impl<H: SpilmanClientHost, N: SpilmanClientNetworking> SpilmanClientBridge<H, N> {
    /// Create a new client bridge.
    ///
    /// The bridge is stateless and keyless — it delegates all key operations
    /// to the host. The caller passes `sender_pubkey_hex` per channel when
    /// opening channels.
    pub fn new(host: H, networking: N) -> Self {
        Self { host, networking }
    }

    /// Open a new channel from a Cashu token.
    ///
    /// This performs the full funding flow:
    /// 1. Compute ECDH channel secret via `host.compute_channel_secret()`
    /// 2. Parse the token and compute channel parameters
    /// 3. Create a funding swap request (deterministic 2-of-2 locked outputs)
    /// 4. Submit the swap to the mint via `networking.call_mint_swap()`
    /// 5. Unblind signatures and verify DLEQ proofs
    /// 6. Save the channel via `host.save_channel_funding()`
    ///
    /// # Arguments
    /// * `token_string` - Cashu token (cashuA... or cashuB...)
    /// * `receiver_pubkey_hex` - Receiver's public key (from server's `/channel/params`)
    /// * `sender_pubkey_hex` - Sender's public key (caller chooses which key for this channel)
    /// * `expiry_timestamp` - Unix timestamp for channel expiry (refund becomes available)
    /// * `keyset_info_json` - Keyset info JSON (from mint's `/v1/keys/{id}`)
    /// * `max_amount` - Maximum amount per output (from server policy, 0 = no limit)
    #[cfg(feature = "wallet")]
    pub fn open_channel_from_token(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> Result<OpenChannelResult, String> {
        // Step 1: Compute channel secret via host (ECDH delegation)
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)?;

        // Step 2: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
            None,
        )?;

        let compute_json: serde_json::Value = serde_json::from_str(&compute_result)
            .map_err(|e| format!("Failed to parse compute result: {}", e))?;

        let capacity = compute_json["capacity"]
            .as_u64()
            .ok_or("Missing 'capacity' in compute result")?;
        let funding_token_amount = compute_json["funding_token_amount"]
            .as_u64()
            .ok_or("Missing 'funding_token_amount' in compute result")?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or("Missing 'mint_url' in compute result")?
            .to_string();
        let params_json = compute_json["params_json"]
            .as_str()
            .ok_or("Missing 'params_json' in compute result")?;
        let proofs_json = compute_json["proofs_json"]
            .as_str()
            .ok_or("Missing 'proofs_json' in compute result")?;

        // Step 3: Create funding swap request
        let swap_result = create_funding_swap(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
            proofs_json,
        )?;

        let swap_json: serde_json::Value = serde_json::from_str(&swap_result)
            .map_err(|e| format!("Failed to parse swap result: {}", e))?;

        let swap_request_json = swap_json["swap_request_json"]
            .as_str()
            .ok_or("Missing 'swap_request_json' in swap result")?;
        let funding_secrets_json = swap_json["funding_secrets_json"]
            .as_str()
            .ok_or("Missing 'funding_secrets_json' in swap result")?;

        // Step 4: Submit swap to mint
        let swap_response_json = self
            .networking
            .call_mint_swap(&mint_url, swap_request_json)
            .map_err(normalize_mint_error_string)?;

        // Step 5: Unblind signatures and verify DLEQ
        let complete_result =
            complete_funding_swap(&swap_response_json, funding_secrets_json, keyset_info_json)?;

        let complete_json: serde_json::Value = serde_json::from_str(&complete_result)
            .map_err(|e| format!("Failed to parse complete result: {}", e))?;

        let funding_proofs_json = complete_json["funding_proofs_json"]
            .as_str()
            .ok_or("Missing 'funding_proofs_json' in complete result")?;

        // Compute channel ID
        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )?;

        // Step 6: Save channel funding data
        let funding = ClientChannelFunding {
            params_json: params_json.to_string(),
            funding_proofs_json: funding_proofs_json.to_string(),
            channel_secret_hex: channel_secret_hex.clone(),
            keyset_info_json: keyset_info_json.to_string(),
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
            created_at: self.host.now_seconds(),
        };

        self.host.save_channel_funding(&channel_id, funding);

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
        })
    }

    /// Open a channel from a Cashu token (async version for WASM).
    ///
    /// This is the async counterpart of `open_channel_from_token`, designed for
    /// environments like WASM where networking must be asynchronous.
    ///
    /// Takes an async networking implementation instead of using the bridge's
    /// sync networking.
    #[cfg(feature = "wallet")]
    #[allow(clippy::too_many_arguments)]
    pub async fn open_channel_from_token_async<AN: SpilmanClientAsyncNetworking>(
        &self,
        token_string: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
        requested_capacity: Option<u64>,
        async_networking: &AN,
    ) -> Result<OpenChannelResult, String> {
        // Step 1: Compute channel secret via host (ECDH delegation)
        let channel_secret_hex = self
            .host
            .compute_channel_secret(sender_pubkey_hex, receiver_pubkey_hex)?;

        // Step 2: Parse token and compute channel parameters
        let compute_result = compute_channel_from_token(
            token_string,
            receiver_pubkey_hex,
            sender_pubkey_hex,
            &channel_secret_hex,
            expiry_timestamp,
            keyset_info_json,
            max_amount,
            requested_capacity,
        )?;

        let compute_json: serde_json::Value = serde_json::from_str(&compute_result)
            .map_err(|e| format!("Failed to parse compute result: {}", e))?;

        let capacity = compute_json["capacity"]
            .as_u64()
            .ok_or("Missing 'capacity' in compute result")?;
        let funding_token_amount = compute_json["funding_token_amount"]
            .as_u64()
            .ok_or("Missing 'funding_token_amount' in compute result")?;
        let mint_url = compute_json["mint_url"]
            .as_str()
            .ok_or("Missing 'mint_url' in compute result")?
            .to_string();
        let params_json = compute_json["params_json"]
            .as_str()
            .ok_or("Missing 'params_json' in compute result")?;
        let proofs_json = compute_json["proofs_json"]
            .as_str()
            .ok_or("Missing 'proofs_json' in compute result")?;

        // Step 3: Create funding swap request
        let swap_result = create_funding_swap(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
            proofs_json,
        )?;

        let swap_json: serde_json::Value = serde_json::from_str(&swap_result)
            .map_err(|e| format!("Failed to parse swap result: {}", e))?;

        let swap_request_json = swap_json["swap_request_json"]
            .as_str()
            .ok_or("Missing 'swap_request_json' in swap result")?;
        let funding_secrets_json = swap_json["funding_secrets_json"]
            .as_str()
            .ok_or("Missing 'funding_secrets_json' in swap result")?;

        // Step 4: Submit swap to mint (async)
        let swap_response_json = async_networking
            .call_mint_swap(&mint_url, swap_request_json)
            .await
            .map_err(normalize_mint_error_string)?;

        // Step 5: Unblind signatures and verify DLEQ
        let complete_result =
            complete_funding_swap(&swap_response_json, funding_secrets_json, keyset_info_json)?;

        let complete_json: serde_json::Value = serde_json::from_str(&complete_result)
            .map_err(|e| format!("Failed to parse complete result: {}", e))?;

        let funding_proofs_json = complete_json["funding_proofs_json"]
            .as_str()
            .ok_or("Missing 'funding_proofs_json' in complete result")?;

        // Compute channel ID
        let channel_id = super::bindings::channel_parameters_get_channel_id(
            params_json,
            &channel_secret_hex,
            keyset_info_json,
        )?;

        // Step 6: Save channel funding data
        let funding = ClientChannelFunding {
            params_json: params_json.to_string(),
            funding_proofs_json: funding_proofs_json.to_string(),
            channel_secret_hex: channel_secret_hex.clone(),
            keyset_info_json: keyset_info_json.to_string(),
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
            capacity,
            funding_token_amount,
            mint_url: mint_url.clone(),
            created_at: self.host.now_seconds(),
        };

        self.host.save_channel_funding(&channel_id, funding);

        Ok(OpenChannelResult {
            channel_id,
            capacity,
            funding_token_amount,
            mint_url,
            sender_pubkey_hex: sender_pubkey_hex.to_string(),
        })
    }

    /// Create a payment for a channel (without funding data).
    ///
    /// Returns a `Payment` struct ready to send to the server.
    /// Use this for subsequent payments after the channel is registered.
    ///
    /// The `balance` is the cumulative amount the receiver can claim.
    ///
    /// # Errors
    /// - Returns an error if the channel doesn't exist or is closed
    /// - Returns an error if `balance` exceeds the channel capacity
    pub fn create_payment(&self, channel_id: &str, balance: u64) -> Result<Payment, String> {
        self.create_payment_internal(channel_id, balance, false, false)
    }

    /// Create a payment with funding data (for first payment).
    ///
    /// Returns a `Payment` struct with `params` and `funding_proofs` included.
    /// Use this for the first payment when registering a channel with the server.
    ///
    /// The same validation rules apply as `create_payment()`.
    pub fn create_payment_with_funding(
        &self,
        channel_id: &str,
        balance: u64,
    ) -> Result<Payment, String> {
        self.create_payment_internal(channel_id, balance, true, false)
    }

    /// Internal implementation for creating payments.
    fn create_payment_internal(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
        include_nutshell_0_20_signature: bool,
    ) -> Result<Payment, String> {
        // Load channel funding data
        let funding = self
            .host
            .get_channel_funding(channel_id)
            .ok_or_else(|| format!("Channel not found: {}", channel_id))?;

        // Check channel state
        if self.host.get_channel_state(channel_id) == ClientChannelState::Closed {
            return Err(format!("Channel is closed: {}", channel_id));
        }

        // Validate balance doesn't exceed capacity
        if balance > funding.capacity {
            return Err(format!(
                "Balance {} exceeds channel capacity {}",
                balance, funding.capacity
            ));
        }

        // Create unsigned balance update and sign it
        let unsigned = self.create_unsigned_balance_update(channel_id, balance, &funding)?;
        let balance_update = self.sign_balance_update(unsigned, &funding.sender_pubkey_hex)?;

        let mut signature = balance_update.signature.to_string();
        if include_nutshell_0_20_signature {
            let compatibility_signature = self.create_nutshell_0_20_signature(balance, &funding)?;
            signature = encode_sig_all_signature_bundle(&signature, &compatibility_signature);
        }

        // Record the payment state
        let payment_state = self.host.get_payment_state(channel_id);
        let payment_count = payment_state.map(|s| s.payment_count).unwrap_or(0) + 1;

        self.host.record_payment(
            channel_id,
            ClientPaymentState {
                balance,
                signature: signature.clone(),
                payment_count,
                last_payment_at: self.host.now_seconds(),
            },
        );

        // Build the Payment struct
        if include_funding {
            let params: serde_json::Value = serde_json::from_str(&funding.params_json)
                .map_err(|e| format!("Failed to parse params: {}", e))?;
            let funding_proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)
                .map_err(|e| format!("Failed to parse funding proofs: {}", e))?;

            Ok(Payment::with_funding(
                channel_id.to_string(),
                balance,
                signature,
                params,
                funding_proofs,
            ))
        } else {
            Ok(Payment::new(channel_id.to_string(), balance, signature))
        }
    }

    /// Build a complete `X-Cashu-Channel` payment header value.
    ///
    /// Returns a base64-encoded JSON string ready to use as the header value.
    ///
    /// If `include_funding` is true, the header includes `params` and `funding_proofs`
    /// (needed for the first request, or when the server doesn't know this channel yet).
    pub fn build_payment_header(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<String, String> {
        let payment = self.create_payment_internal(channel_id, balance, include_funding, false)?;
        let header_json =
            serde_json::to_string(&payment).map_err(|e| format!("Failed to serialize: {}", e))?;
        Ok(base64::prelude::BASE64_STANDARD.encode(header_json))
    }

    /// Get information about a stored channel.
    pub fn get_channel_info(&self, channel_id: &str) -> Option<ClientChannelInfo> {
        let funding = self.host.get_channel_funding(channel_id)?;
        let payment_state = self.host.get_payment_state(channel_id);
        let current_balance = payment_state.as_ref().map(|s| s.balance).unwrap_or(0);
        let payment_count = payment_state.as_ref().map(|s| s.payment_count).unwrap_or(0);

        Some(ClientChannelInfo {
            channel_id: channel_id.to_string(),
            capacity: funding.capacity,
            funding_token_amount: funding.funding_token_amount,
            mint_url: funding.mint_url,
            current_balance,
            payment_count,
            state: self.host.get_channel_state(channel_id),
        })
    }

    /// List all stored channel IDs.
    pub fn list_channels(&self) -> Vec<String> {
        self.host.list_channel_ids()
    }

    /// Close a channel locally.
    ///
    /// Marks the channel as closed so no more payments can be made.
    /// Does not communicate with the server.
    pub fn close_channel(&self, channel_id: &str) {
        self.host.mark_channel_closed(channel_id);
    }

    /// Delete a channel from storage.
    ///
    /// Removes all data associated with the channel.
    pub fn delete_channel(&self, channel_id: &str) {
        self.host.delete_channel(channel_id);
    }

    /// Create a cooperative close request for a channel.
    ///
    /// Creates a payment at the final balance that can be sent to the
    /// server's close endpoint.
    pub fn create_cooperative_close_request(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<Payment, String> {
        self.create_payment_internal(channel_id, final_balance, false, true)
    }

    /// Process a cooperative close response from the server.
    ///
    /// Marks the channel as closed locally.
    pub fn process_cooperative_close_response(&self, response_json: &str) -> Result<(), String> {
        let response: serde_json::Value = serde_json::from_str(response_json)
            .map_err(|e| format!("Failed to parse close response: {}", e))?;

        let channel_id = response["channel_id"]
            .as_str()
            .ok_or("Missing 'channel_id' in close response")?;

        self.host.mark_channel_closed(channel_id);

        Ok(())
    }

    // ========================================================================
    // Balance Update Helpers
    // ========================================================================

    /// Create an unsigned balance update for a channel.
    ///
    /// This computes the message hash and tweak scalar needed for signing.
    /// The caller can inspect the `UnsignedBalanceUpdate`, then call
    /// `sign_balance_update()` to produce a `BalanceUpdateMessage`.
    ///
    /// For most use cases, prefer `create_payment()` which handles signing
    /// automatically via the host.
    pub fn create_unsigned_balance_update(
        &self,
        channel_id: &str,
        balance: u64,
        funding: &ClientChannelFunding,
    ) -> Result<UnsignedBalanceUpdate, String> {
        UnsignedBalanceUpdate::new(channel_id, balance, funding)
    }

    /// Sign an unsigned balance update using the host.
    ///
    /// Delegates to `host.sign_with_tweaked_key()` to produce the signature,
    /// then assembles the final `BalanceUpdateMessage`.
    pub fn sign_balance_update(
        &self,
        unsigned: UnsignedBalanceUpdate,
        sender_pubkey_hex: &str,
    ) -> Result<BalanceUpdateMessage, String> {
        let signature_hex = self.host.sign_with_tweaked_key(
            sender_pubkey_hex,
            &unsigned.message_hex,
            &unsigned.tweak_scalar_hex,
        )?;

        unsigned.sign(&signature_hex)
    }

    fn create_nutshell_0_20_signature(
        &self,
        balance: u64,
        funding: &ClientChannelFunding,
    ) -> Result<String, String> {
        let unsigned = super::bindings::create_unsigned_balance_update(
            &funding.params_json,
            &funding.keyset_info_json,
            &funding.channel_secret_hex,
            &funding.funding_proofs_json,
            balance,
        )?;
        let unsigned: serde_json::Value = serde_json::from_str(&unsigned)
            .map_err(|error| format!("Failed to parse unsigned update: {error}"))?;
        let swap: SwapRequest = serde_json::from_str(
            unsigned["unsigned_swap_request_json"]
                .as_str()
                .ok_or("Missing unsigned_swap_request_json")?,
        )
        .map_err(|error| format!("Failed to parse unsigned swap request: {error}"))?;
        let tweak_scalar_hex = unsigned["tweak_scalar_hex"]
            .as_str()
            .ok_or("Missing tweak_scalar_hex")?;
        self.host.sign_with_tweaked_key(
            &funding.sender_pubkey_hex,
            &nutshell_0_20_sig_all_message_hash_hex(&swap),
            tweak_scalar_hex,
        )
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Base64 decode a string (standard encoding).
pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = base64::prelude::BASE64_STANDARD
        .decode(input.trim())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in base64 decode: {}", e))
}
