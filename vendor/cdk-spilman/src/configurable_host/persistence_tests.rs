use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::test_support::{TEST_SECRET_KEY, TEST_YAML};
use super::*;

#[derive(Default)]
struct FailingStorage {
    inner: MemoryStorage,
    fail_save_funding: AtomicBool,
    fail_update_balance: AtomicBool,
    fail_increment_usage: AtomicBool,
}

impl SpilmanStorage for FailingStorage {
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.inner.get_funding(channel_id)
    }

    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String> {
        if self.fail_save_funding.swap(false, Ordering::SeqCst) {
            return Err("injected save_funding failure".to_string());
        }
        self.inner.save_funding(channel_id, funding)
    }

    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.inner.get_balance(channel_id)
    }

    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String> {
        if self.fail_update_balance.swap(false, Ordering::SeqCst) {
            return Err("injected update_balance failure".to_string());
        }
        self.inner.update_balance(channel_id, payment)
    }

    fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        self.inner.get_usage(channel_id)
    }

    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String> {
        if self.fail_increment_usage.swap(false, Ordering::SeqCst) {
            return Err("injected increment_usage failure".to_string());
        }
        self.inner.increment_usage(channel_id, increments)
    }

    fn get_state(&self, channel_id: &str) -> ChannelState {
        self.inner.get_state(channel_id)
    }

    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String> {
        self.inner.mark_closing(channel_id, closing)
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.inner.get_closing_data(channel_id)
    }

    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String> {
        self.inner.mark_closed(channel_id, data)
    }

    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.inner.get_closed_data(channel_id)
    }

    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry> {
        self.inner.get_keyset(mint, keyset_id)
    }

    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String> {
        self.inner.set_keyset(mint, keyset_id, entry)
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.inner.get_active_keyset_ids(mint, unit)
    }

    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        self.inner.get_mints_units_keysets()
    }

    fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.inner.get_active_units()
    }
}

fn funding() -> ChannelFunding {
    ChannelFunding {
        params_json: r#"{"unit":"sat","capacity":1000}"#.to_string(),
        funding_proofs_json: "[]".to_string(),
        channel_secret_hex: "00".repeat(32),
        keyset_info_json: "{}".to_string(),
    }
}

fn payment() -> PaymentProof {
    PaymentProof {
        balance: 10,
        signature: "signature".to_string(),
    }
}

fn host_with(storage: Arc<FailingStorage>) -> ConfigurableHost {
    let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
    ConfigurableHost::with_storage(config, TEST_SECRET_KEY, storage).unwrap()
}

#[test]
fn save_funding_propagates_funding_write_failure() {
    let storage = Arc::new(FailingStorage::default());
    storage.fail_save_funding.store(true, Ordering::SeqCst);
    let host = host_with(Arc::clone(&storage));

    let error = host
        .save_funding("channel", funding(), payment())
        .unwrap_err();

    assert!(error.contains("save_funding"));
    assert!(storage.get_funding("channel").is_none());
    assert!(storage.get_balance("channel").is_none());
}

#[test]
fn save_funding_retries_an_interrupted_initial_balance_write() {
    let storage = Arc::new(FailingStorage::default());
    storage.fail_update_balance.store(true, Ordering::SeqCst);
    let host = host_with(Arc::clone(&storage));
    let expected_funding = funding();
    let expected_payment = payment();

    let error = host
        .save_funding(
            "channel",
            expected_funding.clone(),
            expected_payment.clone(),
        )
        .unwrap_err();

    assert!(error.contains("update_balance"));
    assert!(storage.get_funding("channel").is_some());
    assert!(storage.get_balance("channel").is_none());
    assert!(host.get_funding("channel").is_none());
    assert!(host.get_funding_data("channel").is_none());

    host.save_funding(
        "channel",
        expected_funding.clone(),
        expected_payment.clone(),
    )
    .unwrap();

    assert_eq!(
        host.get_funding("channel").unwrap().params_json,
        expected_funding.params_json
    );
    assert!(host.get_funding_data("channel").is_some());
    let recovered = storage.get_balance("channel").unwrap();
    assert_eq!(recovered.balance, expected_payment.balance);
    assert_eq!(recovered.signature, expected_payment.signature);
}

#[test]
fn record_payment_balance_failure_does_not_increment_usage() {
    let storage = Arc::new(FailingStorage::default());
    storage.save_funding("channel", funding()).unwrap();
    storage.fail_update_balance.store(true, Ordering::SeqCst);
    let host = host_with(Arc::clone(&storage));
    let context = r#"{"requests":1}"#.to_string();

    let error = host
        .record_payment("channel", payment(), &context)
        .unwrap_err();

    assert!(error.contains("update_balance"));
    assert!(storage.get_balance("channel").is_none());
    assert!(storage.get_usage("channel").is_none());
}

#[test]
fn record_payment_usage_failure_suppresses_success() {
    let storage = Arc::new(FailingStorage::default());
    storage.save_funding("channel", funding()).unwrap();
    storage.fail_increment_usage.store(true, Ordering::SeqCst);
    let host = host_with(Arc::clone(&storage));
    let context = r#"{"requests":1}"#.to_string();

    let error = host
        .record_payment("channel", payment(), &context)
        .unwrap_err();

    assert!(error.contains("increment_usage"));
    assert_eq!(storage.get_balance("channel").unwrap().balance, 10);
    assert!(storage.get_usage("channel").is_none());
}
