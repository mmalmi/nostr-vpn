//! Regression coverage for channel funding and settlement validation.

use std::collections::BTreeMap;

use cashu::dhke::sign_message;
use cashu::nuts::{BlindSignature, CurrencyUnit, Id, Keys, Proof, SecretKey, Token};
use cashu::secret::Secret;
use cashu::Amount;
use cdk_spilman::{
    compute_channel_from_token, unblind_and_verify_stage1_response, ChannelParameters,
    CommitmentOutputs, DeterministicSecretWithBlinding, KeysetInfo,
};

fn keyset(secret: &SecretKey, fee: u64) -> KeysetInfo {
    let keys = Keys::new(BTreeMap::from_iter(
        [1, 2, 4, 8, 16, 32, 64, 128].map(|amount| (Amount::from(amount), secret.public_key())),
    ));
    KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, fee, None)
}

fn params(keyset: KeysetInfo) -> ChannelParameters {
    let sender = SecretKey::generate();
    let receiver = SecretKey::generate();
    ChannelParameters::new_with_secret_key(
        sender.public_key(),
        receiver.public_key(),
        "https://mint.example".into(),
        CurrencyUnit::Sat,
        100,
        100,
        2_000_000_000,
        1_999_990_000,
        keyset,
        64,
        &sender,
    )
    .unwrap()
}

fn signed_outputs(
    params: &ChannelParameters,
    output_keyset: &KeysetInfo,
    mint_secret: &SecretKey,
    balance: u64,
) -> (
    Vec<BlindSignature>,
    Vec<(DeterministicSecretWithBlinding, bool)>,
) {
    let commitment = CommitmentOutputs::for_balance(balance, params).unwrap();
    let mut outputs: Vec<_> = commitment
        .receiver_outputs
        .get_secrets_with_blinding()
        .unwrap()
        .into_iter()
        .map(|output| (output, true))
        .chain(
            commitment
                .sender_outputs
                .get_secrets_with_blinding()
                .unwrap()
                .into_iter()
                .map(|output| (output, false)),
        )
        .collect();
    outputs.sort_by_key(|(output, _)| output.amount);
    let signatures = outputs
        .iter()
        .map(|(output, _)| {
            let message = output
                .to_blinded_message(Amount::from(output.amount), output_keyset.keyset_id)
                .unwrap();
            let mut signature = BlindSignature {
                amount: message.amount,
                keyset_id: message.keyset_id,
                c: sign_message(mint_secret, &message.blinded_secret).unwrap(),
                dleq: None,
            };
            signature
                .add_dleq_proof(&message.blinded_secret, mint_secret)
                .unwrap();
            signature
        })
        .collect();
    (signatures, outputs)
}

#[test]
fn channel_rejects_unit_that_differs_from_mint_keyset() {
    let mint_secret = SecretKey::generate();
    let params = params(keyset(&mint_secret, 0));
    let mut json: serde_json::Value =
        serde_json::from_str(&params.get_channel_id_params_json()).unwrap();
    json["unit"] = serde_json::json!("msat");

    let result = ChannelParameters::from_json_with_channel_secret(
        &json.to_string(),
        params.keyset_info.clone(),
        params.channel_secret,
    );
    assert!(result.is_err(), "a sat keyset cannot fund an msat channel");
}

#[test]
fn close_preserves_signed_allocation_when_rotated_keyset_fees_change() {
    let params = params(keyset(&SecretKey::generate(), 0));
    let mint_secret = SecretKey::generate();
    let output_keyset = keyset(&mint_secret, 100);
    let (signatures, outputs) = signed_outputs(&params, &output_keyset, &mint_secret, 5);

    let result =
        unblind_and_verify_stage1_response(signatures, outputs, &params, &output_keyset, 5)
            .expect("a valid close must remain recoverable after keyset fees change");
    assert_eq!(result.receiver_sum, 5);
    assert_eq!(result.sender_sum, 95);
}

#[test]
fn close_rejects_signature_with_wrong_keyset_id() {
    let mint_secret = SecretKey::generate();
    let keyset = keyset(&mint_secret, 0);
    let params = params(keyset.clone());
    let (mut signatures, outputs) = signed_outputs(&params, &keyset, &mint_secret, 5);
    signatures[0].keyset_id = Id::from_bytes(&[0; 8]).unwrap();

    assert!(unblind_and_verify_stage1_response(signatures, outputs, &params, &keyset, 5).is_err());
}

#[test]
fn close_rejects_wrong_sender_amount_even_with_valid_dleq() {
    let mint_secret = SecretKey::generate();
    let keyset = keyset(&mint_secret, 0);
    let params = params(keyset.clone());
    let (mut signatures, outputs) = signed_outputs(&params, &keyset, &mint_secret, 5);
    let sender_index = outputs.iter().position(|(_, receiver)| !receiver).unwrap();
    // This fixture uses the same mint key for each denomination, so changing the
    // amount keeps the DLEQ valid while violating the signed output allocation.
    signatures[sender_index].amount = Amount::from(128);

    assert!(unblind_and_verify_stage1_response(signatures, outputs, &params, &keyset, 5).is_err());
}

#[test]
fn funding_swap_charges_for_actual_input_proof_count() {
    let mint_secret = SecretKey::generate();
    let keyset = keyset(&mint_secret, 500);
    let token = Token::new(
        "https://mint.example".parse().unwrap(),
        (0..4)
            .map(|index| {
                Proof::new(
                    Amount::from(2),
                    keyset.keyset_id,
                    Secret::new(format!("input-{index}")),
                    mint_secret.public_key(),
                )
            })
            .collect(),
        None,
        CurrencyUnit::Sat,
    );
    let result = compute_channel_from_token(
        &token.to_string(),
        &SecretKey::generate().public_key().to_hex(),
        &SecretKey::generate().public_key().to_hex(),
        &"11".repeat(32),
        2_000_000_000,
        &serde_json::to_string(&keyset).unwrap(),
        64,
        None,
    )
    .unwrap();
    let result: serde_json::Value = serde_json::from_str(&result).unwrap();
    // Four input proofs cost two sats, regardless of their denominations.
    // The remainder also covers both close stages, leaving a usable channel.
    assert_eq!(result["input_value"], 8);
    assert_eq!(result["funding_token_amount"], 6);
}

fn version_fixture() -> (ChannelParameters, SecretKey, SecretKey, SecretKey) {
    let sender = SecretKey::from_hex(&"01".repeat(32)).unwrap();
    let receiver = SecretKey::from_hex(&"02".repeat(32)).unwrap();
    let mint = SecretKey::from_hex(&"03".repeat(32)).unwrap();
    let params = ChannelParameters::new_with_secret_key(
        sender.public_key(),
        receiver.public_key(),
        "https://mint.example".into(),
        CurrencyUnit::Sat,
        100,
        100,
        2_000_000_000,
        1_999_990_000,
        keyset(&mint, 0),
        64,
        &sender,
    )
    .unwrap();
    (params, sender, receiver, mint)
}

fn output_fingerprint(params: &ChannelParameters) -> String {
    use bitcoin::hashes::{sha256, Hash};
    let mut bytes = Vec::new();
    bytes.extend_from_slice(params.get_channel_id_params_json().as_bytes());
    bytes.extend_from_slice(&params.get_channel_id_bytes());
    for context in ["funding", "sender", "receiver"] {
        for (amount, index) in [(1, 0), (2, 0), (64, 0), (64, 1)] {
            let output = params
                .create_deterministic_output_with_blinding(context, amount, index)
                .unwrap();
            bytes.extend_from_slice(output.secret.to_string().as_bytes());
            bytes.extend_from_slice(output.blinding_factor.to_secret_hex().as_bytes());
            bytes.extend_from_slice(
                serde_json::to_string(
                    &output
                        .to_blinded_message(Amount::from(amount), params.keyset_info.keyset_id)
                        .unwrap(),
                )
                .unwrap()
                .as_bytes(),
            );
        }
    }
    sha256::Hash::hash(&bytes).to_string()
}

#[test]
fn legacy_channel_output_bytes_survive_storage_and_close() {
    let (params, _, receiver, mint) = version_fixture();
    // Freeze this vector before adding the opt-in format. It covers the channel
    // identity, funding, both payout roles, repeated denominations and blinding.
    assert_eq!(
        output_fingerprint(&params),
        "2fdfa3b3b32e617eb45cd187b624a07843c15a3db0458dfbc1d564e01eff0bdc"
    );
    let json = params.get_channel_id_params_json();
    assert!(!json.contains("output_version"));
    let mut explicit_legacy: serde_json::Value = serde_json::from_str(&json).unwrap();
    explicit_legacy["output_version"] = serde_json::json!(1);
    let explicit_legacy = ChannelParameters::from_json_with_channel_secret(
        &explicit_legacy.to_string(),
        params.keyset_info.clone(),
        params.channel_secret,
    )
    .unwrap();
    assert_eq!(
        output_fingerprint(&params),
        output_fingerprint(&explicit_legacy)
    );
    let restarted: ChannelParameters =
        serde_json::from_str(&serde_json::to_string(&params).unwrap()).unwrap();
    let seller =
        ChannelParameters::from_json_with_secret_key(&json, params.keyset_info.clone(), &receiver)
            .unwrap();
    assert_eq!(output_fingerprint(&params), output_fingerprint(&restarted));
    assert_eq!(output_fingerprint(&params), output_fingerprint(&seller));
    let (signatures, outputs) = signed_outputs(&seller, &seller.keyset_info, &mint, 5);
    let close = unblind_and_verify_stage1_response(
        signatures,
        outputs,
        &restarted,
        &restarted.keyset_info,
        5,
    )
    .unwrap();
    assert_eq!((close.receiver_sum, close.sender_sum), (5, 95));
    for proof in close.receiver_proofs.iter().chain(&close.sender_proofs) {
        let json: serde_json::Value =
            serde_json::from_str(&proof.proof.secret.to_string()).unwrap();
        assert!(
            json[1]["tags"].is_null(),
            "funded legacy secrets must never be rewritten"
        );
    }
}

#[test]
fn versioned_close_outputs_use_nut10_lists_after_peer_and_storage_roundtrips() {
    let (legacy, sender, receiver, mint) = version_fixture();
    let mut wire: serde_json::Value =
        serde_json::from_str(&legacy.get_channel_id_params_json()).unwrap();
    wire["output_version"] = serde_json::json!(2);
    let buyer = ChannelParameters::from_json_with_channel_secret(
        &wire.to_string(),
        legacy.keyset_info.clone(),
        legacy.channel_secret,
    )
    .unwrap();
    let seller = ChannelParameters::from_json_with_secret_key(
        &wire.to_string(),
        legacy.keyset_info.clone(),
        &receiver,
    )
    .unwrap();
    let restarted: ChannelParameters =
        serde_json::from_str(&serde_json::to_string(&buyer).unwrap()).unwrap();
    let (signatures, outputs) = signed_outputs(&seller, &seller.keyset_info, &mint, 5);
    let close = unblind_and_verify_stage1_response(
        signatures,
        outputs,
        &restarted,
        &restarted.keyset_info,
        5,
    )
    .unwrap();
    assert_eq!((close.receiver_sum, close.sender_sum), (5, 95));
    for proof in close.receiver_proofs.iter().chain(&close.sender_proofs) {
        // Unlike CDK's permissive optional field, this is the NUT-10 list
        // contract enforced by the affected Nutshell mints. No live funds.
        #[derive(serde::Deserialize)]
        struct StrictTags {
            #[serde(default)]
            tags: Vec<Vec<String>>,
        }
        let (_, secret): (String, StrictTags) =
            serde_json::from_str(&proof.proof.secret.to_string())
                .expect("new payout must pass strict NUT-10 tags parsing");
        assert!(secret.tags.is_empty());
        let spending_key = if proof.is_receiver {
            restarted.get_receiver_blinded_secret_key_for_stage2_output(
                &receiver,
                proof.amount,
                proof.index,
            )
        } else {
            restarted.get_sender_blinded_secret_key_for_stage2_output(
                &sender,
                proof.amount,
                proof.index,
            )
        }
        .unwrap();
        let mut spend = proof.proof.clone();
        spend.sign_p2pk(spending_key).unwrap();
        spend
            .verify_p2pk()
            .expect("both parties can authorize spending their output");
    }
    assert_ne!(
        buyer.get_channel_id(),
        legacy.get_channel_id(),
        "format must be bound to the signed contract"
    );
    assert_eq!(output_fingerprint(&buyer), output_fingerprint(&seller));
    assert_eq!(output_fingerprint(&buyer), output_fingerprint(&restarted));
    let wire: serde_json::Value =
        serde_json::from_str(&buyer.get_channel_id_params_json()).unwrap();
    assert_eq!(wire["output_version"], 2);
}

#[test]
fn funded_channel_cannot_be_reinterpreted_as_another_output_version() {
    use cdk_spilman::{
        verify_valid_channel, ChannelOutputVersion, DeterministicOutputsForOneContext,
    };
    let (legacy, _, _, mint) = version_fixture();
    let mut nut10 = legacy.clone();
    nut10.output_version = ChannelOutputVersion::Nut10;
    for (agreed, other) in [(&legacy, &nut10), (&nut10, &legacy)] {
        let outputs = DeterministicOutputsForOneContext::new("funding".into(), 100, agreed.clone())
            .unwrap()
            .get_secrets_with_blinding()
            .unwrap();
        let signatures = outputs
            .iter()
            .map(|output| {
                let message = output
                    .to_blinded_message(Amount::from(output.amount), agreed.keyset_info.keyset_id)
                    .unwrap();
                let mut signature = BlindSignature {
                    amount: message.amount,
                    keyset_id: message.keyset_id,
                    c: sign_message(&mint, &message.blinded_secret).unwrap(),
                    dleq: None,
                };
                signature
                    .add_dleq_proof(&message.blinded_secret, &mint)
                    .unwrap();
                signature
            })
            .collect();
        let proofs = cashu::dhke::construct_proofs(
            signatures,
            outputs
                .iter()
                .map(|output| output.blinding_factor.clone())
                .collect(),
            outputs.into_iter().map(|output| output.secret).collect(),
            &agreed.keyset_info.active_keys,
        )
        .unwrap();
        assert!(verify_valid_channel(&proofs, agreed).valid);
        assert!(
            !verify_valid_channel(&proofs, other).valid,
            "removing/changing a format marker cannot reassign already signed funds"
        );
    }
}

#[test]
fn channel_output_version_rejects_unknown_or_malformed_values() {
    let (params, _, _, _) = version_fixture();
    for invalid in [
        serde_json::json!(0),
        serde_json::json!(3),
        serde_json::json!(null),
        serde_json::json!("2"),
        serde_json::json!(-1),
        serde_json::json!(256),
    ] {
        let mut wire: serde_json::Value =
            serde_json::from_str(&params.get_channel_id_params_json()).unwrap();
        wire["output_version"] = invalid.clone();
        assert!(
            ChannelParameters::from_json_with_channel_secret(
                &wire.to_string(),
                params.keyset_info.clone(),
                params.channel_secret
            )
            .is_err(),
            "invalid wire version: {invalid}"
        );
        let mut stored = serde_json::to_value(&params).unwrap();
        stored["output_version"] = invalid.clone();
        assert!(
            serde_json::from_value::<ChannelParameters>(stored).is_err(),
            "invalid stored version: {invalid}"
        );
    }
}
