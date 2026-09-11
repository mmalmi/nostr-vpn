//! Client-side storage abstraction for Spilman payment channels
//!
//! This module provides storage traits and implementations for managing
//! client-side channel state. It separates immutable funding data from
//! mutable payment state, mirroring the server-side pattern.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Data Structures
// ============================================================================

/// Immutable funding data (saved once when channel is opened)
///
/// This data is set at channel creation time and never changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChannelFunding {
    /// Serialized channel parameters (JSON)
    pub params_json: String,
    /// Serialized funding proofs (JSON array)
    pub funding_proofs_json: String,
    /// Hex-encoded hashed ECDH channel secret (32 bytes)
    pub channel_secret_hex: String,
    /// Serialized keyset info (JSON)
    pub keyset_info_json: String,
    /// Sender's public key for this channel (hex)
    pub sender_pubkey_hex: String,
    /// Maximum value the receiver can claim
    pub capacity: u64,
    /// Nominal funding token amount
    pub funding_token_amount: u64,
    /// Mint URL associated with the channel
    pub mint_url: String,
    /// Unix timestamp when channel was created
    pub created_at: u64,
}

/// Mutable payment state (updated on each payment)
///
/// This tracks the current state of payments made through the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPaymentState {
    /// Last signed balance (cumulative, monotonically increasing)
    pub balance: u64,
    /// Last signature corresponding to the balance
    pub signature: String,
    /// Number of payments made through this channel
    pub payment_count: u64,
    /// Unix timestamp of the last payment
    pub last_payment_at: u64,
}

/// Channel lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClientChannelState {
    /// Channel is open and can accept payments
    #[default]
    Open,
    /// Channel is closed, no more payments allowed
    Closed,
}

// ============================================================================
// Storage Trait
// ============================================================================

/// Storage trait for client channel data
///
/// Implementations handle persistence of channel funding data and payment state.
/// The trait separates immutable funding data from mutable payment state.
pub trait ClientStorage {
    // === Funding Data (immutable after creation) ===

    /// Save funding data for a new channel
    fn save_funding(&mut self, channel_id: &str, funding: ClientChannelFunding);

    /// Get funding data for a channel
    fn get_funding(&self, channel_id: &str) -> Option<&ClientChannelFunding>;

    // === Payment State (mutable) ===

    /// Get the current payment state for a channel
    fn get_payment_state(&self, channel_id: &str) -> Option<&ClientPaymentState>;

    /// Save/update payment state for a channel
    fn save_payment_state(&mut self, channel_id: &str, state: ClientPaymentState);

    // === Lifecycle ===

    /// Get the lifecycle state of a channel
    fn get_state(&self, channel_id: &str) -> ClientChannelState;

    /// Mark a channel as closed
    fn set_closed(&mut self, channel_id: &str);

    // === Management ===

    /// List all stored channel IDs
    fn list_channel_ids(&self) -> Vec<String>;

    /// Delete a channel and all its data
    fn delete(&mut self, channel_id: &str);
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// In-memory storage implementation
///
/// Stores all channel data in HashMaps. Data is lost when the process exits.
/// Suitable for testing, demos, and short-lived applications.
#[derive(Debug, Default)]
pub struct MemoryClientStorage {
    funding: HashMap<String, ClientChannelFunding>,
    payments: HashMap<String, ClientPaymentState>,
    closed: HashSet<String>,
}

impl MemoryClientStorage {
    /// Create a new empty in-memory storage
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of stored channels
    pub fn channel_count(&self) -> usize {
        self.funding.len()
    }
}

impl ClientStorage for MemoryClientStorage {
    fn save_funding(&mut self, channel_id: &str, funding: ClientChannelFunding) {
        self.funding.insert(channel_id.to_string(), funding);
    }

    fn get_funding(&self, channel_id: &str) -> Option<&ClientChannelFunding> {
        self.funding.get(channel_id)
    }

    fn get_payment_state(&self, channel_id: &str) -> Option<&ClientPaymentState> {
        self.payments.get(channel_id)
    }

    fn save_payment_state(&mut self, channel_id: &str, state: ClientPaymentState) {
        self.payments.insert(channel_id.to_string(), state);
    }

    fn get_state(&self, channel_id: &str) -> ClientChannelState {
        if self.closed.contains(channel_id) {
            ClientChannelState::Closed
        } else if self.funding.contains_key(channel_id) {
            ClientChannelState::Open
        } else {
            // Channel doesn't exist, treat as closed
            ClientChannelState::Closed
        }
    }

    fn set_closed(&mut self, channel_id: &str) {
        self.closed.insert(channel_id.to_string());
    }

    fn list_channel_ids(&self) -> Vec<String> {
        self.funding.keys().cloned().collect()
    }

    fn delete(&mut self, channel_id: &str) {
        self.funding.remove(channel_id);
        self.payments.remove(channel_id);
        self.closed.remove(channel_id);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_funding() -> ClientChannelFunding {
        ClientChannelFunding {
            params_json: r#"{"test": true}"#.to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".repeat(32),
            keyset_info_json: "{}".to_string(),
            sender_pubkey_hex: "02".to_string() + &"bb".repeat(32),
            capacity: 1000,
            funding_token_amount: 1100,
            mint_url: "https://mint.example.com".to_string(),
            created_at: 1234567890,
        }
    }

    fn make_test_payment_state(balance: u64) -> ClientPaymentState {
        ClientPaymentState {
            balance,
            signature: "sig".to_string(),
            payment_count: 1,
            last_payment_at: 1234567890,
        }
    }

    #[test]
    fn test_memory_storage_funding() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        // Initially empty
        assert!(storage.get_funding(channel_id).is_none());
        assert_eq!(storage.channel_count(), 0);

        // Save funding
        storage.save_funding(channel_id, make_test_funding());

        // Now retrievable
        let funding = storage.get_funding(channel_id).unwrap();
        assert_eq!(funding.capacity, 1000);
        assert_eq!(storage.channel_count(), 1);

        // State should be Open
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Open);
    }

    #[test]
    fn test_memory_storage_payments() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        storage.save_funding(channel_id, make_test_funding());

        // Initially no payment state
        assert!(storage.get_payment_state(channel_id).is_none());

        // Save payment state
        storage.save_payment_state(channel_id, make_test_payment_state(100));

        let state = storage.get_payment_state(channel_id).unwrap();
        assert_eq!(state.balance, 100);
        assert_eq!(state.payment_count, 1);

        // Update payment state
        storage.save_payment_state(channel_id, make_test_payment_state(200));

        let state = storage.get_payment_state(channel_id).unwrap();
        assert_eq!(state.balance, 200);
    }

    #[test]
    fn test_memory_storage_lifecycle() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        // Unknown channel is Closed
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);

        // After funding, it's Open
        storage.save_funding(channel_id, make_test_funding());
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Open);

        // Mark closed
        storage.set_closed(channel_id);
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);
    }

    #[test]
    fn test_memory_storage_delete() {
        let mut storage = MemoryClientStorage::new();
        let channel_id = "test_channel_1";

        storage.save_funding(channel_id, make_test_funding());
        storage.save_payment_state(channel_id, make_test_payment_state(100));
        storage.set_closed(channel_id);

        assert_eq!(storage.channel_count(), 1);

        // Delete
        storage.delete(channel_id);

        assert_eq!(storage.channel_count(), 0);
        assert!(storage.get_funding(channel_id).is_none());
        assert!(storage.get_payment_state(channel_id).is_none());
        assert_eq!(storage.get_state(channel_id), ClientChannelState::Closed);
    }

    #[test]
    fn test_memory_storage_list() {
        let mut storage = MemoryClientStorage::new();

        storage.save_funding("channel_1", make_test_funding());
        storage.save_funding("channel_2", make_test_funding());
        storage.save_funding("channel_3", make_test_funding());

        let mut ids = storage.list_channel_ids();
        ids.sort();

        assert_eq!(ids, vec!["channel_1", "channel_2", "channel_3"]);
    }
}
