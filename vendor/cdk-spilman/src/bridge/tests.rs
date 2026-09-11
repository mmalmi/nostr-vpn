use super::*;
use cashu::nuts::{Id, PublicKey, SecretKey};
struct MockHost {
    ra: bool,
    ma: bool,
}
impl SpilmanHost<String> for MockHost {
    fn receiver_key_is_acceptable(&self, _: &PublicKey) -> bool {
        self.ra
    }
    fn mint_and_keyset_is_acceptable(&self, _: &str, _: &Id) -> bool {
        self.ma
    }
    fn get_funding(&self, _: &str) -> Option<ChannelFunding> {
        None
    }
    fn save_funding(&self, _: &str, _: ChannelFunding, _: PaymentProof) -> Result<(), String> {
        Ok(())
    }
    fn get_amount_due(&self, _: &str, _: Option<&String>) -> u64 {
        0
    }
    fn record_payment(&self, _: &str, _: PaymentProof, _: &String) -> Result<(), String> {
        Ok(())
    }
    fn get_channel_state(&self, _: &str) -> ChannelState {
        ChannelState::Open
    }
    fn mark_channel_closing(&self, _: &str, _: u64, _: PaymentProof) -> Result<(), String> {
        Ok(())
    }
    fn get_closing_data(&self, _: &str) -> Option<ClosingData> {
        None
    }
    fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
        Some(ChannelPolicy {
            min_expiry_in_seconds: 3600,
            min_capacity: 100,
            max_amount_per_output: None,
        })
    }
    fn now_seconds(&self) -> u64 {
        1700000000
    }
    fn get_balance_and_signature_for_unilateral_exit(&self, _: &str) -> Option<PaymentProof> {
        None
    }
    fn get_active_keyset_ids(&self, _: &str, _: &CurrencyUnit) -> Vec<Id> {
        Vec::new()
    }
    fn get_keyset_info(&self, _: &str, _: &Id) -> Option<String> {
        None
    }
    fn mark_channel_closed(
        &self,
        _: &str,
        _: u64,
        _: u64,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Result<(), String> {
        Ok(())
    }
    fn compute_channel_secret(&self, _: &str, _: &str) -> Result<String, String> {
        Err("N/A".into())
    }
    fn sign_with_tweaked_key(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
        Err("N/A".into())
    }
}
impl SpilmanNetworking for MockHost {
    fn call_mint_swap(&self, _: &str, _: &str) -> Result<String, String> {
        Err("N/A".into())
    }
    fn refresh_all_keysets(&self, _: &str) -> Result<(), String> {
        Err("N/A".into())
    }
}
#[test]
fn test_bridge_rejects_unacceptable_receiver() {
    let b = SpilmanBridge::new(MockHost {
        ra: false,
        ma: true,
    });
    let p = serde_json::json!({ "sender_pubkey": SecretKey::generate().public_key().to_hex(), "receiver_pubkey": SecretKey::generate().public_key().to_hex(), "mint": "https://m", "unit": "sat", "capacity": 1000, "funding_token_amount": 1000, "maximum_amount": 64, "expiry_timestamp": 1700007200, "setup_timestamp": 1700000000, "keyset_id": "00" });
    let pay = serde_json::json!({ "channel_id": "i", "balance": 100, "signature": "s", "params": p, "funding_proofs": [] });
    assert!(b
        .process_payment_via_json(&pay.to_string(), &"{}".to_string())
        .unwrap_err()
        .to_string()
        .contains("receiver key not acceptable"));
}
