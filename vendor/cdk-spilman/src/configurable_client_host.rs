//! Configurable client host implementation
//!
//! This module provides a batteries-included implementation of `SpilmanClientHost`
//! that holds raw secret keys and uses pluggable storage.
//!
//! # Example
//! ```ignore
//! use cdk_spilman::{ConfigurableClientHost, MemoryClientStorage};
//! use cashu::nuts::SecretKey;
//!
//! let storage = MemoryClientStorage::new();
//! let mut host = ConfigurableClientHost::new(storage);
//!
//! // Add a keypair
//! let secret = SecretKey::generate();
//! host.add_key(secret);
//!
//! // Use with SpilmanClientBridge
//! let bridge = SpilmanClientBridge::new(host, networking);
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::SecretKey;

use super::bindings::{compute_channel_secret_from_hex, sign_with_tweaked_key_util};
use super::client_bridge::SpilmanClientHost;
use super::client_storage::{
    ClientChannelFunding, ClientChannelState, ClientPaymentState, ClientStorage,
    MemoryClientStorage,
};

// ============================================================================
// ConfigurableClientHost
// ============================================================================

/// A configurable client host that holds raw secret keys and uses pluggable storage.
///
/// This provides a batteries-included implementation of `SpilmanClientHost` for
/// applications that want to manage keys directly. For hardware wallet integration
/// or external signers, implement `SpilmanClientHost` directly instead.
///
/// # Key Management
///
/// Keys are stored in a HashMap indexed by their public key (hex-encoded).
/// When signing operations are requested, the host looks up the corresponding
/// secret key by the provided public key.
///
/// # Storage
///
/// Channel data is stored via a `ClientStorage` implementation. The default
/// `MemoryClientStorage` keeps everything in memory. For persistence, implement
/// `ClientStorage` for your preferred backend.
///
/// # Thread Safety
///
/// The storage is wrapped in `RefCell` for interior mutability, allowing
/// the trait methods (which take `&self`) to modify storage. This means
/// `ConfigurableClientHost` is not `Sync` and cannot be shared across threads.
/// For multi-threaded use, wrap in `Mutex` or use a thread-safe storage backend.
#[derive(Debug)]
pub struct ConfigurableClientHost<S: ClientStorage> {
    /// Secret keys indexed by public key (hex-encoded)
    keys: HashMap<String, SecretKey>,
    /// Channel storage (interior mutability for &self trait methods)
    storage: RefCell<S>,
}

impl<S: ClientStorage> ConfigurableClientHost<S> {
    /// Create a new configurable client host with the given storage.
    pub fn new(storage: S) -> Self {
        Self {
            keys: HashMap::new(),
            storage: RefCell::new(storage),
        }
    }

    /// Add a keypair to the host.
    ///
    /// The key is indexed by its public key (hex-encoded). If a key with the
    /// same public key already exists, it is replaced.
    pub fn add_key(&mut self, secret: SecretKey) {
        let pubkey = secret.public_key();
        let pubkey_hex = pubkey.to_hex();
        self.keys.insert(pubkey_hex, secret);
    }

    /// Add a keypair from hex-encoded secret key.
    ///
    /// Returns an error if the hex string is invalid.
    pub fn add_key_from_hex(&mut self, secret_hex: &str) -> Result<String, String> {
        let secret =
            SecretKey::from_hex(secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;
        let pubkey_hex = secret.public_key().to_hex();
        self.keys.insert(pubkey_hex.clone(), secret);
        Ok(pubkey_hex)
    }

    /// Get the public keys of all stored keys.
    pub fn get_pubkeys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Check if a key exists for the given public key.
    pub fn has_key(&self, pubkey_hex: &str) -> bool {
        self.keys.contains_key(pubkey_hex)
    }

    /// Remove a key by public key.
    ///
    /// Returns `true` if a key was removed, `false` if no key existed.
    pub fn remove_key(&mut self, pubkey_hex: &str) -> bool {
        self.keys.remove(pubkey_hex).is_some()
    }

    /// Get mutable access to the underlying storage.
    ///
    /// Use with caution - this bypasses the normal host interface.
    pub fn storage_mut(&mut self) -> &mut S {
        self.storage.get_mut()
    }

    /// Get the number of stored channels.
    pub fn channel_count(&self) -> usize {
        self.storage.borrow().list_channel_ids().len()
    }

    /// Get the secret key for a public key (for internal use).
    fn get_secret(&self, pubkey_hex: &str) -> Result<&SecretKey, String> {
        self.keys
            .get(pubkey_hex)
            .ok_or_else(|| format!("No key found for pubkey: {}", pubkey_hex))
    }
}

impl ConfigurableClientHost<MemoryClientStorage> {
    /// Create a new configurable client host with in-memory storage.
    ///
    /// This is a convenience constructor for the common case of using
    /// `MemoryClientStorage`.
    pub fn new_in_memory() -> Self {
        Self::new(MemoryClientStorage::new())
    }
}

// ============================================================================
// SpilmanClientHost implementation
// ============================================================================

impl<S: ClientStorage> SpilmanClientHost for ConfigurableClientHost<S> {
    // ========================================================================
    // Funding Data
    // ========================================================================

    fn save_channel_funding(&self, channel_id: &str, funding: ClientChannelFunding) {
        self.storage.borrow_mut().save_funding(channel_id, funding);
    }

    fn get_channel_funding(&self, channel_id: &str) -> Option<ClientChannelFunding> {
        self.storage.borrow().get_funding(channel_id).cloned()
    }

    // ========================================================================
    // Payment State
    // ========================================================================

    fn get_payment_state(&self, channel_id: &str) -> Option<ClientPaymentState> {
        self.storage.borrow().get_payment_state(channel_id).cloned()
    }

    fn record_payment(&self, channel_id: &str, state: ClientPaymentState) {
        self.storage
            .borrow_mut()
            .save_payment_state(channel_id, state);
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    fn get_channel_state(&self, channel_id: &str) -> ClientChannelState {
        self.storage.borrow().get_state(channel_id)
    }

    fn mark_channel_closed(&self, channel_id: &str) {
        self.storage.borrow_mut().set_closed(channel_id);
    }

    fn list_channel_ids(&self) -> Vec<String> {
        self.storage.borrow().list_channel_ids()
    }

    fn delete_channel(&self, channel_id: &str) {
        self.storage.borrow_mut().delete(channel_id);
    }

    // ========================================================================
    // Time
    // ========================================================================

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    // ========================================================================
    // Crypto
    // ========================================================================

    fn compute_channel_secret(
        &self,
        sender_pubkey_hex: &str,
        receiver_pubkey_hex: &str,
    ) -> Result<String, String> {
        let secret = self.get_secret(sender_pubkey_hex)?;
        let secret_hex = secret.to_secret_hex();
        compute_channel_secret_from_hex(&secret_hex, receiver_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        let secret = self.get_secret(signer_pubkey_hex)?;
        let secret_hex = secret.to_secret_hex();
        sign_with_tweaked_key_util(&secret_hex, message_hex, tweak_scalar_hex)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_management() {
        let mut host = ConfigurableClientHost::new_in_memory();

        // Initially no keys
        assert!(host.get_pubkeys().is_empty());

        // Add a key
        let secret = SecretKey::generate();
        let pubkey = secret.public_key();
        let pubkey_hex = pubkey.to_hex();

        host.add_key(secret);

        assert_eq!(host.get_pubkeys().len(), 1);
        assert!(host.has_key(&pubkey_hex));

        // Remove the key
        assert!(host.remove_key(&pubkey_hex));
        assert!(!host.has_key(&pubkey_hex));
        assert!(host.get_pubkeys().is_empty());
    }

    #[test]
    fn test_add_key_from_hex() {
        let mut host = ConfigurableClientHost::new_in_memory();

        // Generate a key and get its hex
        let secret = SecretKey::generate();
        let secret_hex = secret.to_secret_hex();
        let expected_pubkey = secret.public_key().to_hex();

        // Add via hex
        let pubkey_hex = host.add_key_from_hex(&secret_hex).unwrap();
        assert_eq!(pubkey_hex, expected_pubkey);
        assert!(host.has_key(&pubkey_hex));
    }

    #[test]
    fn test_storage_delegation() {
        let host = ConfigurableClientHost::new_in_memory();

        let channel_id = "test_channel";

        // Initially no channel
        assert!(host.get_channel_funding(channel_id).is_none());
        assert_eq!(
            host.get_channel_state(channel_id),
            ClientChannelState::Closed
        );

        // Save funding
        let funding = ClientChannelFunding {
            params_json: "{}".to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".repeat(32),
            keyset_info_json: "{}".to_string(),
            sender_pubkey_hex: "02".to_string() + &"bb".repeat(32),
            capacity: 1000,
            funding_token_amount: 1100,
            mint_url: "https://mint.example.com".to_string(),
            created_at: 12345,
        };

        host.save_channel_funding(channel_id, funding.clone());

        // Now retrievable
        let retrieved = host.get_channel_funding(channel_id).unwrap();
        assert_eq!(retrieved.capacity, 1000);
        assert_eq!(host.get_channel_state(channel_id), ClientChannelState::Open);

        // Record payment
        assert!(host.get_payment_state(channel_id).is_none());

        let payment = ClientPaymentState {
            balance: 100,
            signature: "sig".to_string(),
            payment_count: 1,
            last_payment_at: 12346,
        };

        host.record_payment(channel_id, payment);

        let state = host.get_payment_state(channel_id).unwrap();
        assert_eq!(state.balance, 100);

        // Close channel
        host.mark_channel_closed(channel_id);
        assert_eq!(
            host.get_channel_state(channel_id),
            ClientChannelState::Closed
        );

        // List channels
        assert_eq!(host.list_channel_ids(), vec![channel_id]);

        // Delete channel
        host.delete_channel(channel_id);
        assert!(host.get_channel_funding(channel_id).is_none());
    }

    #[test]
    fn test_now_seconds() {
        let host = ConfigurableClientHost::new_in_memory();
        let now = host.now_seconds();

        // Should be a reasonable timestamp (after year 2020)
        assert!(now > 1577836800); // 2020-01-01

        // Should be relatively stable
        let now2 = host.now_seconds();
        assert!(now2 >= now);
        assert!(now2 - now < 2); // Less than 2 seconds difference
    }

    #[test]
    fn test_compute_channel_secret() {
        let mut host = ConfigurableClientHost::new_in_memory();

        // Add sender key
        let sender_secret = SecretKey::generate();
        let sender_pubkey_hex = sender_secret.public_key().to_hex();
        host.add_key(sender_secret);

        // Generate receiver key
        let receiver_secret = SecretKey::generate();
        let receiver_pubkey_hex = receiver_secret.public_key().to_hex();

        // Compute channel secret
        let secret = host
            .compute_channel_secret(&sender_pubkey_hex, &receiver_pubkey_hex)
            .unwrap();

        // Should be 64 hex chars (32 bytes)
        assert_eq!(secret.len(), 64);

        // Should be deterministic
        let secret2 = host
            .compute_channel_secret(&sender_pubkey_hex, &receiver_pubkey_hex)
            .unwrap();
        assert_eq!(secret, secret2);
    }

    #[test]
    fn test_sign_with_tweaked_key() {
        let mut host = ConfigurableClientHost::new_in_memory();

        // Add a key
        let secret = SecretKey::generate();
        let pubkey_hex = secret.public_key().to_hex();
        host.add_key(secret);

        // Create test message and tweak
        let message_hex = "aa".repeat(32); // 32-byte message hash
        let tweak_hex = "bb".repeat(32); // 32-byte tweak

        // Sign
        let signature = host
            .sign_with_tweaked_key(&pubkey_hex, &message_hex, &tweak_hex)
            .unwrap();

        // Should be 128 hex chars (64 bytes Schnorr signature)
        assert_eq!(signature.len(), 128);
    }

    #[test]
    fn test_missing_key_error() {
        let host = ConfigurableClientHost::new_in_memory();

        let fake_pubkey = "02".to_string() + &"cc".repeat(32);
        let message_hex = "aa".repeat(32);
        let tweak_hex = "bb".repeat(32);

        // Should fail with missing key error
        let result = host.sign_with_tweaked_key(&fake_pubkey, &message_hex, &tweak_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No key found"));
    }
}
