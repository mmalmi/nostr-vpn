use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use cashu::dhke::{construct_proofs, sign_message};
use cashu::nuts::{BlindSignature, CurrencyUnit, Id, Keys, Proof, PublicKey, SecretKey};
use cashu::Amount;

use super::*;
use crate::{
    compute_channel_secret_from_hex, create_signed_balance_update, create_unsigned_balance_update,
    sign_with_tweaked_key_util, DeterministicOutputsForOneContext,
};

struct PaymentFixture {
    funding: ChannelFunding,
    params: serde_json::Value,
    proofs: Vec<Proof>,
    channel_id: String,
    balance: u64,
    signature: String,
    compatibility_signature: String,
    keyset_id: Id,
    receiver_secret: SecretKey,
}

#[test]
fn new_channel_checks_funding_amounts_before_deriving_outputs() {
    let fixture = PaymentFixture::new();
    let bridge = SpilmanBridge::new(fixture.host(false));
    for claimed_amount in [200, u64::MAX] {
        let mut params = fixture.params.clone();
        params["funding_token_amount"] = serde_json::json!(claimed_amount);
        let result = bridge.process_payment(
            &fixture.channel_id,
            fixture.balance,
            &fixture.signature,
            Some(&params),
            Some(&fixture.proofs),
            &(),
        );
        assert!(
            matches!(result, Err(BridgeError::InvalidRequest(ref error))
            if error.contains("funding proof total")),
            "{result:?}"
        );
        assert!(bridge.host().funding.borrow().is_none());
    }
    let mut params = fixture.params.clone();
    params["maximum_amount"] = serde_json::json!(1);
    let result = bridge.process_payment(
        &fixture.channel_id,
        fixture.balance,
        &fixture.signature,
        Some(&params),
        Some(&fixture.proofs),
        &(),
    );
    assert!(
        matches!(result, Err(BridgeError::InvalidRequest(ref error))
        if error.contains("denomination")),
        "{result:?}"
    );
}

impl PaymentFixture {
    fn new() -> Self {
        let sender_secret = SecretKey::generate();
        let receiver_secret = SecretKey::generate();
        let mint_secret = SecretKey::generate();
        let mut keys = BTreeMap::new();
        for amount in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
            keys.insert(Amount::from(amount), mint_secret.public_key());
        }
        let active_keys = Keys::new(keys);
        let keyset_id = Id::v1_from_keys(&active_keys);
        let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, active_keys, 0, None);
        let capacity = 100;
        let maximum_amount = 64;
        let funding_amount = ChannelParameters::get_minimum_funding_token_amount(
            capacity,
            &keyset_info,
            maximum_amount,
        )
        .unwrap();
        let params = ChannelParameters::new_with_secret_key(
            sender_secret.public_key(),
            receiver_secret.public_key(),
            "https://test-mint".to_string(),
            CurrencyUnit::Sat,
            capacity,
            funding_amount,
            2_000_000_000,
            1_999_990_000,
            keyset_info.clone(),
            maximum_amount,
            &sender_secret,
        )
        .unwrap();
        let funding_outputs = DeterministicOutputsForOneContext::new(
            "funding".to_string(),
            funding_amount,
            params.clone(),
        )
        .unwrap();
        let secrets = funding_outputs.get_secrets_with_blinding().unwrap();
        let messages = funding_outputs.get_blinded_messages(None).unwrap();
        let signatures = messages
            .iter()
            .map(|message| {
                let mut signature = BlindSignature {
                    amount: message.amount,
                    keyset_id: message.keyset_id,
                    c: sign_message(&mint_secret, &message.blinded_secret).unwrap(),
                    dleq: None,
                };
                signature
                    .add_dleq_proof(&message.blinded_secret, &mint_secret)
                    .unwrap();
                signature
            })
            .collect();
        let proofs = construct_proofs(
            signatures,
            secrets
                .iter()
                .map(|secret| secret.blinding_factor.clone())
                .collect(),
            secrets.iter().map(|secret| secret.secret.clone()).collect(),
            &keyset_info.active_keys,
        )
        .unwrap();
        let params_json = params.get_channel_id_params_json();
        let keyset_info_json = serde_json::to_string(&keyset_info).unwrap();
        let proofs_json = serde_json::to_string(&proofs).unwrap();
        let balance = 10;
        let signed = create_signed_balance_update(
            &params_json,
            &keyset_info_json,
            &sender_secret.to_secret_hex(),
            &proofs_json,
            balance,
        )
        .unwrap();
        let signed: serde_json::Value = serde_json::from_str(&signed).unwrap();
        let unsigned = create_unsigned_balance_update(
            &params_json,
            &keyset_info_json,
            &cashu::util::hex::encode(params.channel_secret),
            &proofs_json,
            balance,
        )
        .unwrap();
        let unsigned: serde_json::Value = serde_json::from_str(&unsigned).unwrap();
        let swap: cashu::nuts::SwapRequest =
            serde_json::from_str(unsigned["unsigned_swap_request_json"].as_str().unwrap()).unwrap();
        let nutshell_0_20_signature = sign_with_tweaked_key_util(
            &sender_secret.to_secret_hex(),
            &crate::balance_update::nutshell_0_20_sig_all_message_hash_hex(&swap),
            unsigned["tweak_scalar_hex"].as_str().unwrap(),
        )
        .unwrap();
        let compatibility_signature = crate::balance_update::encode_sig_all_signature_bundle(
            signed["signature"].as_str().unwrap(),
            &nutshell_0_20_signature,
        );
        let channel_id = params.get_channel_id();
        let funding = ChannelFunding {
            params_json: params_json.clone(),
            funding_proofs_json: proofs_json,
            channel_secret_hex: cashu::util::hex::encode(params.channel_secret),
            keyset_info_json,
        };

        Self {
            funding,
            params: serde_json::from_str(&params_json).unwrap(),
            proofs,
            channel_id,
            balance,
            signature: signed["signature"].as_str().unwrap().to_string(),
            compatibility_signature,
            keyset_id,
            receiver_secret,
        }
    }

    fn host(&self, known: bool) -> PersistenceHost {
        PersistenceHost {
            now: Cell::new(1_999_990_000),
            funding: RefCell::new(known.then(|| self.funding.clone())),
            last_payment: RefCell::new(None),
            fail_save: Cell::new(false),
            fail_record: Cell::new(false),
            successful_records: Cell::new(0),
            state: Cell::new(ChannelState::Open),
            closing: RefCell::new(None),
            keyset_id: self.keyset_id,
            keyset_info_json: self.funding.keyset_info_json.clone(),
            receiver_secret: self.receiver_secret.clone(),
        }
    }
}

struct PersistenceHost {
    now: Cell<u64>,
    funding: RefCell<Option<ChannelFunding>>,
    last_payment: RefCell<Option<PaymentProof>>,
    fail_save: Cell<bool>,
    fail_record: Cell<bool>,
    successful_records: Cell<u64>,
    state: Cell<ChannelState>,
    closing: RefCell<Option<ClosingData>>,
    keyset_id: Id,
    keyset_info_json: String,
    receiver_secret: SecretKey,
}

struct RejectingCloseNetwork {
    witness_signature_count: Cell<usize>,
}

impl SpilmanNetworking for RejectingCloseNetwork {
    fn call_mint_swap(&self, _mint_url: &str, swap_request_json: &str) -> Result<String, String> {
        let swap: cashu::nuts::SwapRequest = serde_json::from_str(swap_request_json).unwrap();
        let count = match swap.inputs()[0].witness.as_ref() {
            Some(cashu::nuts::Witness::P2PKWitness(witness)) => witness.signatures.len(),
            _ => 0,
        };
        self.witness_signature_count.set(count);
        Err(r#"{"code":11000,"detail":"injected rejection"}"#.to_string())
    }

    fn refresh_all_keysets(&self, _mint: &str) -> Result<(), String> {
        Ok(())
    }
}

impl SpilmanHost<()> for PersistenceHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        receiver_pubkey == &self.receiver_secret.public_key()
    }

    fn mint_and_keyset_is_acceptable(&self, _mint: &str, keyset_id: &Id) -> bool {
        keyset_id == &self.keyset_id
    }

    fn get_funding(&self, _channel_id: &str) -> Option<ChannelFunding> {
        self.funding.borrow().clone()
    }

    fn save_funding(
        &self,
        _channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) -> Result<(), String> {
        if self.fail_save.replace(false) {
            return Err("injected funding persistence failure".to_string());
        }
        *self.funding.borrow_mut() = Some(funding);
        *self.last_payment.borrow_mut() = Some(initial_payment);
        Ok(())
    }

    fn get_amount_due(&self, _channel_id: &str, _context: Option<&()>) -> u64 {
        0
    }

    fn record_payment(
        &self,
        _channel_id: &str,
        payment: PaymentProof,
        _context: &(),
    ) -> Result<(), String> {
        if self.fail_record.replace(false) {
            return Err("injected payment persistence failure".to_string());
        }
        *self.last_payment.borrow_mut() = Some(payment);
        self.successful_records
            .set(self.successful_records.get() + 1);
        Ok(())
    }

    fn get_channel_state(&self, _channel_id: &str) -> ChannelState {
        self.state.get()
    }

    fn mark_channel_closing(
        &self,
        _channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.state.set(ChannelState::Closing);
        *self.closing.borrow_mut() = Some(ClosingData {
            expiry_timestamp,
            balance: payment.balance,
            signature: payment.signature,
        });
        Ok(())
    }

    fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
        self.closing.borrow().clone()
    }

    fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
        Some(ChannelPolicy {
            min_expiry_in_seconds: 60,
            min_capacity: 1,
            max_amount_per_output: Some(64),
        })
    }

    fn now_seconds(&self) -> u64 {
        self.now.get()
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        _channel_id: &str,
    ) -> Option<PaymentProof> {
        self.last_payment.borrow().clone()
    }

    fn get_active_keyset_ids(&self, _mint: &str, _unit: &CurrencyUnit) -> Vec<Id> {
        vec![self.keyset_id]
    }

    fn get_keyset_info(&self, _mint: &str, keyset_id: &Id) -> Option<String> {
        (keyset_id == &self.keyset_id).then(|| self.keyset_info_json.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_channel_closed(
        &self,
        _channel_id: &str,
        _expiry_timestamp: u64,
        _balance: u64,
        _receiver_proofs_json: &str,
        _sender_proofs_json: &str,
        _receiver_sum: u64,
        _sender_sum: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn compute_channel_secret(
        &self,
        _receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        compute_channel_secret_from_hex(&self.receiver_secret.to_secret_hex(), sender_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        _signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        sign_with_tweaked_key_util(
            &self.receiver_secret.to_secret_hex(),
            message_hex,
            tweak_scalar_hex,
        )
    }
}

#[test]
fn existing_channel_rejects_changed_supplied_params() {
    for state in [ChannelState::Open, ChannelState::Closing] {
        let fixture = PaymentFixture::new();
        let host = fixture.host(true);
        if state == ChannelState::Closing {
            host.mark_channel_closing(
                &fixture.channel_id,
                fixture.params["expiry_timestamp"].as_u64().unwrap(),
                PaymentProof {
                    balance: fixture.balance,
                    signature: fixture.compatibility_signature.clone(),
                },
            )
            .unwrap();
        }
        let bridge = SpilmanBridge::new(host);
        bridge
            .process_payment(
                &fixture.channel_id,
                fixture.balance,
                &fixture.compatibility_signature,
                Some(&fixture.params),
                Some(&fixture.proofs),
                &(),
            )
            .expect("replaying unchanged funding parameters is supported");

        let mut changed = fixture.params.clone();
        changed["unit"] = serde_json::json!("msat");
        let result = bridge.process_payment(
            &fixture.channel_id,
            fixture.balance,
            &fixture.compatibility_signature,
            Some(&changed),
            Some(&fixture.proofs),
            &(),
        );
        assert!(result.is_err(), "{state:?} channel accepted changed unit");
        if state == ChannelState::Open {
            assert!(bridge
                .validate_payment(
                    &fixture.channel_id,
                    fixture.balance,
                    &fixture.signature,
                    Some(&changed),
                    None,
                    &(),
                )
                .is_err());
            assert!(bridge
                .fund_channel(
                    &fixture.channel_id,
                    fixture.balance,
                    &fixture.signature,
                    Some(&changed),
                    None,
                )
                .is_err());
        }
    }
}

#[test]
fn process_payment_rejects_initial_funding_persistence_failure() {
    let fixture = PaymentFixture::new();
    let host = fixture.host(false);
    host.fail_save.set(true);
    let bridge = SpilmanBridge::new(host);

    let result = bridge.process_payment(
        &fixture.channel_id,
        fixture.balance,
        &fixture.signature,
        Some(&fixture.params),
        Some(&fixture.proofs),
        &(),
    );

    assert!(result.is_err(), "failed save must suppress payment success");
    assert_eq!(bridge.host().successful_records.get(), 0);
}

#[test]
fn process_payment_rejects_accepted_payment_persistence_failure() {
    let fixture = PaymentFixture::new();
    let host = fixture.host(true);
    host.fail_record.set(true);
    let bridge = SpilmanBridge::new(host);

    let result = bridge.process_payment(
        &fixture.channel_id,
        fixture.balance,
        &fixture.signature,
        None,
        None,
        &(),
    );

    assert!(
        result.is_err(),
        "failed record must suppress payment success"
    );
    assert_eq!(bridge.host().successful_records.get(), 0);
}

#[test]
fn multi_proof_close_carries_current_and_legacy_signatures_on_first_input() {
    let fixture = PaymentFixture::new();
    assert!(
        fixture.proofs.len() > 1,
        "regression fixture must exercise a multi-proof channel"
    );
    let bridge = SpilmanBridge::new(fixture.host(true));
    bridge
        .process_payment(
            &fixture.channel_id,
            fixture.balance,
            &fixture.compatibility_signature,
            None,
            None,
            &(),
        )
        .expect("record payment");

    let close = bridge
        .create_unilateral_close_data(&fixture.channel_id)
        .expect("prepare close");

    let Some(cashu::nuts::Witness::P2PKWitness(witness)) =
        close.swap_request.inputs()[0].witness.as_ref()
    else {
        panic!("first funding proof must carry the SIG_ALL witness");
    };
    assert_eq!(witness.signatures.len(), 4);
    assert!(
        close.swap_request.inputs()[1..]
            .iter()
            .all(|input| input.witness.is_none()),
        "SIG_ALL witness belongs only on the first input"
    );

    let funding_params = ChannelParameters::from_json_with_channel_secret(
        &fixture.funding.params_json,
        crate::parse_keyset_info_from_json(&fixture.funding.keyset_info_json).unwrap(),
        hex::decode(&fixture.funding.channel_secret_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let sender = funding_params
        .get_sender_blinded_pubkey_for_stage1()
        .unwrap();
    let receiver = funding_params
        .get_receiver_blinded_pubkey_for_stage1()
        .unwrap();
    let signatures: Vec<bitcoin::secp256k1::schnorr::Signature> = witness
        .signatures
        .iter()
        .map(|signature| signature.parse().unwrap())
        .collect();
    let current =
        cashu::nuts::SpendingConditionVerification::sig_all_msg_to_sign(&close.swap_request);
    let legacy = crate::balance_update::nutshell_0_20_sig_all_message(&close.swap_request);
    sender.verify(current.as_bytes(), &signatures[0]).unwrap();
    sender.verify(legacy.as_bytes(), &signatures[1]).unwrap();
    receiver.verify(current.as_bytes(), &signatures[2]).unwrap();
    receiver.verify(legacy.as_bytes(), &signatures[3]).unwrap();
}

#[test]
fn closing_channel_accepts_same_balance_compatibility_signature_without_recording_usage() {
    let fixture = PaymentFixture::new();
    let host = fixture.host(true);
    host.state.set(ChannelState::Closing);
    *host.closing.borrow_mut() = Some(ClosingData {
        expiry_timestamp: 2_000_000_000,
        balance: fixture.balance,
        signature: fixture.signature.clone(),
    });
    let bridge = SpilmanBridge::new(host);

    bridge
        .process_payment(
            &fixture.channel_id,
            fixture.balance,
            &fixture.compatibility_signature,
            None,
            None,
            &(),
        )
        .expect("refresh closing authorization");

    assert_eq!(bridge.host().successful_records.get(), 0);
    assert_eq!(
        bridge.host().closing.borrow().as_ref().unwrap().signature,
        fixture.compatibility_signature
    );
}

#[test]
fn unilateral_retry_preserves_refreshed_closing_authorization() {
    let fixture = PaymentFixture::new();
    let host = fixture.host(true);
    host.state.set(ChannelState::Closing);
    *host.last_payment.borrow_mut() = Some(PaymentProof {
        balance: fixture.balance,
        signature: fixture.signature.clone(),
    });
    *host.closing.borrow_mut() = Some(ClosingData {
        expiry_timestamp: 2_000_000_000,
        balance: fixture.balance,
        signature: fixture.compatibility_signature.clone(),
    });
    let bridge = SpilmanBridge::new(host);
    let network = RejectingCloseNetwork {
        witness_signature_count: Cell::new(0),
    };

    let result = bridge.execute_unilateral_close(&fixture.channel_id, &network);

    assert!(result.is_err(), "injected mint rejection should surface");
    assert_eq!(
        network.witness_signature_count.get(),
        4,
        "the retry must submit the preserved current and compatibility signatures"
    );
    assert_eq!(
        bridge.host().closing.borrow().as_ref().unwrap().signature,
        fixture.compatibility_signature,
        "the older unilateral payment must not replace a refreshed close authorization"
    );
}

#[test]
fn closing_channel_rejects_compatibility_signature_for_a_different_balance() {
    let fixture = PaymentFixture::new();
    let host = fixture.host(true);
    host.state.set(ChannelState::Closing);
    *host.closing.borrow_mut() = Some(ClosingData {
        expiry_timestamp: 2_000_000_000,
        balance: fixture.balance + 1,
        signature: fixture.signature.clone(),
    });
    let bridge = SpilmanBridge::new(host);

    let result = bridge.process_payment(
        &fixture.channel_id,
        fixture.balance,
        &fixture.compatibility_signature,
        None,
        None,
        &(),
    );

    assert!(matches!(result, Err(BridgeError::BalanceMismatch { .. })));
    assert_eq!(bridge.host().successful_records.get(), 0);
}

#[test]
fn existing_channel_stops_accepting_payments_at_refund_expiry() {
    let fixture = PaymentFixture::new();
    let bridge = SpilmanBridge::new(fixture.host(true));
    let expiry = fixture.params["expiry_timestamp"].as_u64().unwrap();
    bridge.host().now.set(expiry - 1);
    bridge
        .process_payment(
            &fixture.channel_id,
            fixture.balance,
            &fixture.signature,
            None,
            None,
            &(),
        )
        .unwrap();
    bridge.host().now.set(expiry);
    let result = bridge.process_payment(
        &fixture.channel_id,
        fixture.balance,
        &fixture.signature,
        None,
        None,
        &(),
    );
    assert!(
        matches!(result, Err(BridgeError::ExpiryTooSoon { .. })),
        "{result:?}"
    );
    assert_eq!(bridge.host().successful_records.get(), 1);
}
