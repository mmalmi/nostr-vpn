use super::*;

/// Parse KeysetInfo from JSON
///
/// Expected format:
/// {
///   "keysetId": "00...",
///   "unit": "sat",
///   "keys": { "1": "02...", "2": "02...", ... },
///   "inputFeePpk": 100,
///   "amounts": [1048576, 524288, ...]  // optional, computed from keys if missing
/// }
pub fn parse_keyset_info_from_json(json_str: &str) -> Result<KeysetInfo, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid keyset JSON: {}", e))?;

    // Parse keyset_id (handle both camelCase and snake_case)
    let keyset_id_str = json["keysetId"]
        .as_str()
        .or_else(|| json["keyset_id"].as_str())
        .ok_or("Missing or invalid 'keysetId' field")?;
    let keyset_id: Id = keyset_id_str
        .parse()
        .map_err(|e| format!("Invalid keyset_id: {}", e))?;

    // Parse unit
    let unit_str = json["unit"]
        .as_str()
        .ok_or("Missing or invalid 'unit' field")?;
    let unit = CurrencyUnit::from_str(unit_str).map_err(|e| format!("Invalid unit: {}", e))?;

    // Parse input_fee_ppk (handle both camelCase and snake_case)
    let input_fee_ppk = json["inputFeePpk"]
        .as_u64()
        .or_else(|| json["input_fee_ppk"].as_u64())
        .ok_or("Missing or invalid 'inputFeePpk' field")?;

    // Parse final_expiry (handle both camelCase and snake_case)
    let final_expiry = json["finalExpiry"]
        .as_u64()
        .or_else(|| json["final_expiry"].as_u64());

    // Parse keys map: { "1": "02...", "2": "02...", ... }
    let keys_obj = json["keys"]
        .as_object()
        .ok_or("Missing or invalid 'keys' field")?;

    let mut keys_map: BTreeMap<Amount, PublicKey> = BTreeMap::new();
    for (amount_str, pubkey_val) in keys_obj {
        let amount: u64 = amount_str
            .parse()
            .map_err(|e| format!("Invalid amount '{}': {}", amount_str, e))?;
        let pubkey_hex = pubkey_val
            .as_str()
            .ok_or_else(|| format!("Invalid pubkey for amount {}", amount))?;
        let pubkey = PublicKey::from_str(pubkey_hex)
            .map_err(|e| format!("Invalid pubkey hex for amount {}: {}", amount, e))?;
        keys_map.insert(Amount::from(amount), pubkey);
    }

    let active_keys = Keys::new(keys_map);

    Ok(KeysetInfo::new(
        keyset_id,
        unit,
        active_keys,
        input_fee_ppk,
        final_expiry,
    ))
}

/// Get channel_id from params JSON, channel secret, and keyset info (all as strings)
///
/// This is effectively a method on ChannelParameters, but takes JSON input
/// for FFI compatibility.
pub fn channel_parameters_get_channel_id(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the channel secret
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;

    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Shared secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }

    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    // Parse real KeysetInfo from JSON
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Use from_json_with_channel_secret to construct params
    let params =
        ChannelParameters::from_json_with_channel_secret(params_json, keyset_info, channel_secret)
            .map_err(|e| format!("Failed to parse params: {}", e))?;

    Ok(params.get_channel_id())
}

/// Compute channel secret from hex-encoded secret key and public key
///
/// Returns the channel secret as a hex string (32 bytes).
pub fn compute_channel_secret_from_hex(
    my_secret_hex: &str,
    their_pubkey_hex: &str,
) -> Result<String, String> {
    let my_secret =
        SecretKey::from_hex(my_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    let their_pubkey: PublicKey = their_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid pubkey: {}", e))?;

    let channel_secret = ecdh(&my_secret, &their_pubkey);
    Ok(hex::encode(channel_secret))
}

/// Compute the minimum funding_token_amount needed for a given capacity
///
/// Uses the double-inverse computation:
/// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
/// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
///
/// Clients should call this before building channel params to determine the
/// funding_token_amount field value.
///
/// Returns the minimum funding_token_amount as a u64 (JSON number string).
pub fn compute_funding_token_amount(
    capacity: u64,
    keyset_info_json: &str,
    maximum_amount: u64,
) -> Result<u64, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, maximum_amount)
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))
}

/// Create plain (non-P2PK) blinded messages for a given amount
///
/// This creates standard blinded messages with random secrets, suitable for
/// minting via `/v1/mint/bolt11`. The resulting proofs can then be wrapped
/// in a Cashu token and passed to `open_channel_from_token` for funding.
///
/// Returns JSON with:
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
#[cfg(feature = "wallet")]
pub fn create_plain_blinded_messages(
    amount_sat: u64,
    keyset_info_json: &str,
) -> Result<String, String> {
    use cashu::amount::SplitTarget;
    use cashu::nuts::PreMintSecrets;

    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // amounts must be ascending (smallest first) for FeeAndAmounts::split() to work correctly
    let mut amounts_asc = keyset_info.amounts_largest_first.clone();
    amounts_asc.reverse();
    let fee_and_amounts: cashu::amount::FeeAndAmounts =
        (keyset_info.input_fee_ppk, amounts_asc).into();

    let premint_secrets = PreMintSecrets::random(
        keyset_info.keyset_id,
        Amount::from(amount_sat),
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .map_err(|e| format!("Failed to create blinded messages: {}", e))?;

    // Serialize blinded messages (same format as create_funding_outputs)
    let blinded_messages_json: Vec<serde_json::Value> = premint_secrets
        .blinded_messages()
        .iter()
        .map(|bm| {
            serde_json::json!({
                "amount": u64::from(bm.amount),
                "id": bm.keyset_id.to_string(),
                "B_": bm.blinded_secret.to_hex()
            })
        })
        .collect();

    // Serialize secrets with blinding factors (same format as create_funding_outputs)
    let secrets_json: Vec<serde_json::Value> = premint_secrets
        .secrets
        .iter()
        .map(|pm| {
            serde_json::json!({
                "secret": pm.secret.to_string(),
                "blinding_factor": pm.r.to_secret_hex(),
                "amount": u64::from(pm.amount)
            })
        })
        .collect();

    let result = serde_json::json!({
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Create funding outputs from params and keyset info
///
/// Returns JSON with:
/// - `funding_token_nominal`: Total nominal value needed
/// - `blinded_messages`: Array of blinded messages (ready for mint request)
/// - `secrets_with_blinding`: Array of {secret, blinding_factor, amount} for unblinding later
pub fn create_funding_outputs(
    params_json: &str,
    alice_secret_hex: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse the keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse Alice's secret key
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Create ChannelParameters from JSON
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic outputs for "funding" context
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        params,
    )
    .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get blinded messages
    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get blinded messages: {}", e))?;

    // Get secrets with blinding factors
    let secrets_with_blinding = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get secrets with blinding: {}", e))?;

    // Serialize blinded messages to JSON
    let blinded_messages_json: Vec<serde_json::Value> = blinded_messages
        .iter()
        .map(|bm| {
            serde_json::json!({
                "amount": u64::from(bm.amount),
                "id": bm.keyset_id.to_string(),
                "B_": bm.blinded_secret.to_hex()
            })
        })
        .collect();

    // Serialize secrets with blinding to JSON
    let secrets_json: Vec<serde_json::Value> = secrets_with_blinding
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    // Build result JSON
    let result = serde_json::json!({
        "funding_token_nominal": funding_token_nominal,
        "blinded_messages": blinded_messages_json,
        "secrets_with_blinding": secrets_json
    });

    Ok(result.to_string())
}

/// Construct proofs from blind signatures and secrets with blinding
///
/// Returns JSON array of proofs ready for use
#[cfg(feature = "wallet")]
pub fn construct_proofs(
    blind_signatures_json: &str,
    secrets_with_blinding_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info to get the keys
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse blind signatures from mint
    let blind_sigs_raw: Vec<serde_json::Value> = serde_json::from_str(blind_signatures_json)
        .map_err(|e| format!("Failed to parse blind signatures: {}", e))?;

    let mut blind_signatures: Vec<BlindSignature> = Vec::new();
    for sig in blind_sigs_raw {
        let amount = sig["amount"]
            .as_u64()
            .ok_or("Missing 'amount' in blind signature")?;
        let id_str = sig["id"]
            .as_str()
            .ok_or("Missing 'id' in blind signature")?;
        let c_str = sig["C_"]
            .as_str()
            .ok_or("Missing 'C_' in blind signature")?;

        let keyset_id: Id = id_str
            .parse()
            .map_err(|e| format!("Invalid keyset id: {}", e))?;
        let c = PublicKey::from_str(c_str).map_err(|e| format!("Invalid C_ pubkey: {}", e))?;

        // Parse DLEQ - required for Spilman channels
        let dleq_obj = sig["dleq"]
            .as_object()
            .ok_or("Missing 'dleq' in blind signature - DLEQ proofs are required")?;
        let e_str = dleq_obj
            .get("e")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'e' in dleq")?;
        let s_str = dleq_obj
            .get("s")
            .and_then(|v| v.as_str())
            .ok_or("Missing 's' in dleq")?;
        let e = SecretKey::from_hex(e_str).map_err(|e| format!("Invalid dleq.e: {}", e))?;
        let s = SecretKey::from_hex(s_str).map_err(|e| format!("Invalid dleq.s: {}", e))?;
        let dleq = BlindSignatureDleq { e, s };

        blind_signatures.push(BlindSignature {
            amount: Amount::from(amount),
            keyset_id,
            c,
            dleq: Some(dleq),
        });
    }

    // Parse secrets with blinding factors
    let secrets_raw: Vec<serde_json::Value> = serde_json::from_str(secrets_with_blinding_json)
        .map_err(|e| format!("Failed to parse secrets with blinding: {}", e))?;

    let mut secrets: Vec<Secret> = Vec::new();
    let mut rs: Vec<SecretKey> = Vec::new();

    for swb in secrets_raw {
        let secret_str = swb["secret"]
            .as_str()
            .ok_or("Missing 'secret' in secrets_with_blinding")?;
        let blinding_factor_hex = swb["blinding_factor"]
            .as_str()
            .ok_or("Missing 'blinding_factor' in secrets_with_blinding")?;

        let secret: Secret = secret_str
            .parse()
            .map_err(|e| format!("Invalid secret: {}", e))?;
        let r = SecretKey::from_hex(blinding_factor_hex)
            .map_err(|e| format!("Invalid blinding factor: {}", e))?;

        secrets.push(secret);
        rs.push(r);
    }

    // Construct the proofs
    let proofs = dhke_construct_proofs(blind_signatures, rs, secrets, &keys)
        .map_err(|e| format!("Failed to construct proofs: {}", e))?;

    // Serialize proofs to JSON
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    Ok(proofs_json)
}

/// Create a signed balance update for a channel
pub fn create_signed_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    alice_secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let alice_secret =
        SecretKey::from_hex(alice_secret_hex).map_err(|e| format!("Invalid secret key: {}", e))?;
    let params =
        ChannelParameters::from_json_with_secret_key(params_json, keyset_info, &alice_secret)
            .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;
    let channel = EstablishedChannel::new(params, funding_proofs)
        .map_err(|e| format!("EstablishedChannel::new failed: {}", e))?;
    let sender = SpilmanChannelSender::new(alice_secret, channel);

    let (balance_update, _) = sender
        .create_signed_balance_update(balance)
        .map_err(|e| format!("create_signed_balance_update failed: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}
