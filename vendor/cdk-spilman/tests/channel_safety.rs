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
                    Amount::from(1),
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
    assert_eq!(result["input_value"], 4);
    assert_eq!(result["funding_token_amount"], 2);
}
