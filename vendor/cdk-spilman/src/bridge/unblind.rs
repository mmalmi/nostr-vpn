use super::*;

pub fn unblind_and_verify_stage1_response(
    blind_signatures: Vec<BlindSignature>,
    secrets_with_blinding: Vec<(DeterministicSecretWithBlinding, bool)>,
    params: &ChannelParameters,
    output_keyset_info: &KeysetInfo,
    balance: u64,
) -> Result<UnblindResult, BridgeError> {
    if blind_signatures.len() != secrets_with_blinding.len() {
        return Err(BridgeError::Internal(
            "Length mismatch between signatures and secrets".into(),
        ));
    }
    if output_keyset_info.unit != params.unit {
        return Err(BridgeError::ValidationFailed(
            "Output keyset unit does not match channel unit".into(),
        ));
    }
    for (signature, (output, _)) in blind_signatures.iter().zip(&secrets_with_blinding) {
        if signature.keyset_id != output_keyset_info.keyset_id
            || u64::from(signature.amount) != output.amount
        {
            return Err(BridgeError::ValidationFailed(
                "Blind signature does not match requested output amount and keyset".into(),
            ));
        }
    }
    let mut secrets = Vec::with_capacity(secrets_with_blinding.len());
    let mut blinding_factors = Vec::with_capacity(secrets_with_blinding.len());
    let mut is_receiver_flags = Vec::with_capacity(secrets_with_blinding.len());
    let mut amount_index_pairs = Vec::with_capacity(secrets_with_blinding.len());

    for (swb, is_receiver) in secrets_with_blinding {
        secrets.push(swb.secret);
        blinding_factors.push(swb.blinding_factor);
        is_receiver_flags.push(is_receiver);
        amount_index_pairs.push((swb.amount, swb.index));
    }

    let proofs = cashu::dhke::construct_proofs(
        blind_signatures,
        blinding_factors,
        secrets,
        &output_keyset_info.active_keys,
    )
    .map_err(|e| BridgeError::Internal(format!("Failed to construct proofs: {}", e)))?;

    for (i, proof) in proofs.iter().enumerate() {
        let mint_pubkey = output_keyset_info
            .active_keys
            .amount_key(proof.amount)
            .ok_or_else(|| BridgeError::Internal("Missing mint key".into()))?;
        proof.verify_dleq(mint_pubkey).map_err(|e| {
            BridgeError::ValidationFailed(format!("DLEQ failed for proof {}: {}", i, e))
        })?;
    }

    let mut receiver_proofs = Vec::new();
    let mut sender_proofs = Vec::new();
    let mut receiver_sum = 0u64;
    let mut sender_sum = 0u64;

    for ((mut proof, is_receiver), (amount, index)) in proofs
        .into_iter()
        .zip(is_receiver_flags)
        .zip(amount_index_pairs)
    {
        let role = if is_receiver {
            Stage2Role::Receiver
        } else {
            Stage2Role::Sender
        };
        params
            .attach_stage2_p2pk_e(&mut proof, role, amount, index)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;

        if is_receiver {
            let expected_pubkey = params
                .get_receiver_blinded_pubkey_for_stage2_output(amount, index)
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
            let secret_json: serde_json::Value = serde_json::from_str(&proof.secret.to_string())
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
            if secret_json.get(0).and_then(|v| v.as_str()) != Some("P2PK")
                || secret_json
                    .get(1)
                    .and_then(|v| v.get("data"))
                    .and_then(|v| v.as_str())
                    != Some(&expected_pubkey.to_hex())
            {
                return Err(BridgeError::ValidationFailed(
                    "Receiver proof locked to wrong pubkey".into(),
                ));
            }
            receiver_sum = receiver_sum
                .checked_add(u64::from(proof.amount))
                .ok_or_else(|| {
                    BridgeError::ValidationFailed("Receiver proof amount overflow".into())
                })?;
            receiver_proofs.push(ProofWithMeta {
                proof,
                amount,
                index,
                is_receiver: true,
            });
        } else {
            sender_sum = sender_sum
                .checked_add(u64::from(proof.amount))
                .ok_or_else(|| {
                    BridgeError::ValidationFailed("Sender proof amount overflow".into())
                })?;
            sender_proofs.push(ProofWithMeta {
                proof,
                amount,
                index,
                is_receiver: false,
            });
        }
    }

    // The sender signed the allocation using the funding keyset's fee schedule.
    // Rotation changes where outputs are issued, but cannot change their amounts.
    let commitment = CommitmentOutputs::for_balance(balance, params)
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
    let expected_nominal = commitment.receiver_outputs.amount;
    if receiver_sum != expected_nominal {
        return Err(BridgeError::ValidationFailed(format!(
            "Receiver nominal mismatch: expected {}, got {}",
            expected_nominal, receiver_sum
        )));
    }
    if sender_sum != commitment.sender_outputs.amount {
        return Err(BridgeError::ValidationFailed(format!(
            "Sender nominal mismatch: expected {}, got {}",
            commitment.sender_outputs.amount, sender_sum
        )));
    }

    Ok(UnblindResult {
        receiver_proofs,
        sender_proofs,
        receiver_sum,
        sender_sum,
    })
}

