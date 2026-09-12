use super::*;

// ============================================================================
// SWAP-TO-FUNDING FUNCTIONS
// ============================================================================
// These functions allow creating channel funding from existing wallet tokens
// (via swap) instead of minting fresh tokens.

/// Compute channel parameters from a Cashu token
///
/// Given a token string (cashuA.../cashuB...), computes the channel capacity,
/// funding token nominal amount, and change amount. Also builds the channel
/// parameters ready for use.
///
/// # Arguments
/// * `token_string` - The Cashu token (cashuA... or cashuB...)
/// * `receiver_pubkey_hex` - Receiver's public key (hex)
/// * `sender_pubkey_hex` - Sender's public key (hex)
/// * `channel_secret_hex` - Pre-computed ECDH channel secret (32 bytes, hex)
/// * `expiry_timestamp` - Unix timestamp for channel expiry (refund becomes available)
/// * `keyset_info_json` - Keyset info from mint (JSON)
/// * `maximum_amount_for_one_output` - Max amount per output from server policy
/// * `requested_capacity` - Agreed capacity; None uses all spendable token value
///
/// # Returns
/// JSON with:
/// - `capacity`: Channel capacity (final value after all fees)
/// - `funding_token_amount`: Nominal value of the funding token
/// - `input_value`: Total value of input proofs
/// - `mint_url`: Mint URL from the token
/// - `params_json`: Serialized channel params for use in later functions
/// - `proofs_json`: The parsed proofs from the token (for create_funding_swap)
#[allow(clippy::too_many_arguments)]
pub fn compute_channel_from_token(
    token_string: &str,
    receiver_pubkey_hex: &str,
    sender_pubkey_hex: &str,
    channel_secret_hex: &str,
    expiry_timestamp: u64,
    keyset_info_json: &str,
    maximum_amount_for_one_output: u64,
    requested_capacity: Option<u64>,
) -> Result<String, String> {
    // Parse the token
    let token: Token = token_string
        .parse()
        .map_err(|e| format!("Failed to parse token: {}", e))?;

    // Get total value from token (doesn't need keyset info)
    let input_value: u64 = token
        .value()
        .map_err(|e| format!("Failed to get token value: {}", e))?
        .into();

    // Get mint URL
    let mint_url = token
        .mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    // Get unit from token
    let unit = token.unit().unwrap_or(CurrencyUnit::Sat);

    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse proofs using keyset info
    // We need to create a KeySetInfo (nut02) for the token's proofs() method
    let nut02_keyset_info = cashu::nuts::KeySetInfo {
        id: keyset_info.keyset_id,
        unit: unit.clone(),
        active: true,
        input_fee_ppk: keyset_info.input_fee_ppk,
        final_expiry: None,
    };
    let proofs = token
        .proofs(&[nut02_keyset_info])
        .map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Assert all proofs are from the same keyset
    for proof in &proofs {
        if proof.keyset_id != keyset_info.keyset_id {
            return Err(format!(
                "All proofs must be from the same keyset. Expected {}, got {}",
                keyset_info.keyset_id, proof.keyset_id
            ));
        }
    }

    let max_amt = maximum_amount_for_one_output;

    // Input fees apply to the proofs actually spent, regardless of how their
    // combined value will be split into deterministic funding outputs.
    let input_fee = (u128::from(keyset_info.input_fee_ppk) * proofs.len() as u128).div_ceil(1000);
    let input_fee =
        u64::try_from(input_fee).map_err(|_| "Funding swap input fee overflow".to_string())?;
    let funding_token_amount = input_value
        .checked_sub(input_fee)
        .ok_or_else(|| "Input proofs do not cover the funding swap fee".to_string())?;

    // Step 2: capacity = forward(forward(funding_token_amount)) - value after both close stages
    let v2 = keyset_info
        .deterministic_value_after_fees(funding_token_amount, max_amt)
        .map_err(|e| format!("Failed to compute v2: {}", e))?;
    let available_capacity = keyset_info
        .deterministic_value_after_fees(v2, max_amt)
        .map_err(|e| format!("Failed to compute capacity: {}", e))?;
    // Funding proofs include fee reserves and may exceed the agreed capacity.
    // Bind the requested limit into the signed parameters before the mint swap;
    // settlement returns any remainder to the sender under the existing format.
    let capacity = requested_capacity.unwrap_or(available_capacity);
    if capacity == 0 || capacity > available_capacity {
        return Err(format!(
            "Requested channel capacity {capacity} is not covered by available capacity {available_capacity}"
        ));
    }

    // Parse sender pubkey
    let sender_pubkey: PublicKey = sender_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid sender pubkey: {}", e))?;

    // Parse receiver pubkey
    let receiver_pubkey: PublicKey = receiver_pubkey_hex
        .parse()
        .map_err(|e| format!("Invalid receiver pubkey: {}", e))?;

    // Parse channel secret
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    // Create channel parameters with pre-computed channel secret
    let params = ChannelParameters::new(
        sender_pubkey,
        receiver_pubkey,
        mint_url.to_string(),
        unit,
        capacity,
        funding_token_amount,
        expiry_timestamp,
        unix_time(),
        keyset_info.clone(),
        max_amt,
        channel_secret,
    )
    .map_err(|e| format!("Failed to create channel params: {}", e))?;

    // Serialize proofs
    let proofs_json =
        serde_json::to_string(&proofs).map_err(|e| format!("Failed to serialize proofs: {}", e))?;

    // Serialize params
    let params_json = params.get_channel_id_params_json();

    // Build result
    let result = serde_json::json!({
        "capacity": capacity,
        "funding_token_amount": funding_token_amount,
        "input_value": input_value,
        "mint_url": mint_url.to_string(),
        "params_json": params_json,
        "proofs_json": proofs_json
    });

    Ok(result.to_string())
}

/// Create a swap request for funding a channel from existing proofs
///
/// Takes input proofs and creates a swap request with deterministic
/// funding outputs (2-of-2 locked).
///
/// # Arguments
/// * `params_json` - Channel params JSON (from compute_channel_from_token)
/// * `channel_secret_hex` - Pre-computed ECDH channel secret (32 bytes, hex)
/// * `keyset_info_json` - Keyset info (JSON)
/// * `input_proofs_json` - Input proofs from the token (JSON array)
///
/// # Returns
/// JSON with:
/// - `swap_request_json`: The swap request to send to mint (JSON)
/// - `funding_secrets_json`: Secrets for unblinding funding outputs (JSON array)
/// - `funding_count`: Number of funding outputs
pub fn create_funding_swap(
    params_json: &str,
    channel_secret_hex: &str,
    keyset_info_json: &str,
    input_proofs_json: &str,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;

    // Parse channel secret
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret = [0u8; 32];
    channel_secret.copy_from_slice(&channel_secret_bytes);

    // Create ChannelParameters from JSON with pre-computed channel secret
    let params = ChannelParameters::from_json_with_channel_secret(
        params_json,
        keyset_info.clone(),
        channel_secret,
    )
    .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;

    // Parse input proofs
    let input_proofs: Vec<Proof> = serde_json::from_str(input_proofs_json)
        .map_err(|e| format!("Failed to parse input proofs: {}", e))?;

    // Get the funding token nominal amount
    let funding_token_nominal = params
        .get_total_funding_token_amount()
        .map_err(|e| format!("Failed to compute funding token amount: {}", e))?;

    // Create deterministic funding outputs
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        funding_token_nominal,
        params,
    )
    .map_err(|e| format!("Failed to create funding outputs: {}", e))?;

    // Get funding blinded messages
    let funding_blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .map_err(|e| format!("Failed to get funding blinded messages: {}", e))?;

    // Get funding secrets with blinding
    let funding_secrets = funding_outputs
        .get_secrets_with_blinding()
        .map_err(|e| format!("Failed to get funding secrets: {}", e))?;

    // Create swap request
    let swap_request = SwapRequest::new(input_proofs, funding_blinded_messages);

    // Serialize swap request
    let swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    // Serialize funding secrets
    let funding_secrets_json: Vec<serde_json::Value> = funding_secrets
        .iter()
        .map(|swb| {
            serde_json::json!({
                "secret": swb.secret.to_string(),
                "blinding_factor": swb.blinding_factor.to_secret_hex(),
                "amount": swb.amount
            })
        })
        .collect();

    let funding_secrets_str = serde_json::to_string(&funding_secrets_json)
        .map_err(|e| format!("Failed to serialize funding secrets: {}", e))?;

    // Build result
    let result = serde_json::json!({
        "swap_request_json": swap_request_json,
        "funding_secrets_json": funding_secrets_str,
        "funding_count": funding_secrets.len()
    });

    Ok(result.to_string())
}

/// Complete a funding swap by unblinding the mint's response
///
/// Takes the mint's swap response and unblinding the funding proofs.
/// Also verifies DLEQ proofs on all signatures.
///
/// # Arguments
/// * `swap_response_json` - Mint's swap response (JSON with "signatures" array)
/// * `funding_secrets_json` - Funding secrets from create_funding_swap (JSON array)
/// * `keyset_info_json` - Keyset info (JSON)
///
/// # Returns
/// JSON with:
/// - `funding_proofs_json`: Funding proofs for channel (JSON array)
#[cfg(feature = "wallet")]
pub fn complete_funding_swap(
    swap_response_json: &str,
    funding_secrets_json: &str,
    keyset_info_json: &str,
) -> Result<String, String> {
    // Parse keyset info
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let keys = keyset_info.active_keys.clone();

    // Parse swap response to get signatures
    let response: serde_json::Value = serde_json::from_str(swap_response_json)
        .map_err(|e| format!("Failed to parse swap response: {}", e))?;

    let signatures_raw = response["signatures"]
        .as_array()
        .ok_or("Missing 'signatures' in swap response")?;

    // Parse funding secrets
    let funding_secrets_raw: Vec<serde_json::Value> = serde_json::from_str(funding_secrets_json)
        .map_err(|e| format!("Failed to parse funding secrets: {}", e))?;

    let funding_count = funding_secrets_raw.len();

    // Verify signature count matches
    if signatures_raw.len() != funding_count {
        return Err(format!(
            "Signature count mismatch: expected {}, got {}",
            funding_count,
            signatures_raw.len()
        ));
    }

    // Helper to parse and verify signatures
    let parse_signatures = |sigs: &[serde_json::Value]| -> Result<Vec<BlindSignature>, String> {
        let mut result = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            let amount = sig["amount"]
                .as_u64()
                .ok_or_else(|| format!("Missing 'amount' in signature {}", i))?;
            let id_str = sig["id"]
                .as_str()
                .ok_or_else(|| format!("Missing 'id' in signature {}", i))?;
            let c_str = sig["C_"]
                .as_str()
                .ok_or_else(|| format!("Missing 'C_' in signature {}", i))?;

            let keyset_id: Id = id_str
                .parse()
                .map_err(|e| format!("Invalid keyset id in signature {}: {}", i, e))?;
            let c = PublicKey::from_str(c_str)
                .map_err(|e| format!("Invalid C_ in signature {}: {}", i, e))?;

            // Parse DLEQ - required for Spilman channels
            let dleq_obj = sig["dleq"].as_object().ok_or_else(|| {
                format!(
                    "Missing 'dleq' in signature {} - DLEQ proofs are required",
                    i
                )
            })?;
            let e_str = dleq_obj
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 'e' in dleq for signature {}", i))?;
            let s_str = dleq_obj
                .get("s")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing 's' in dleq for signature {}", i))?;
            let e = SecretKey::from_hex(e_str)
                .map_err(|e| format!("Invalid dleq.e in signature {}: {}", i, e))?;
            let s = SecretKey::from_hex(s_str)
                .map_err(|e| format!("Invalid dleq.s in signature {}: {}", i, e))?;
            let dleq = BlindSignatureDleq { e, s };

            result.push(BlindSignature {
                amount: Amount::from(amount),
                keyset_id,
                c,
                dleq: Some(dleq),
            });
        }
        Ok(result)
    };

    // Helper to parse secrets
    let parse_secrets =
        |secrets: &[serde_json::Value]| -> Result<(Vec<Secret>, Vec<SecretKey>), String> {
            let mut result_secrets = Vec::new();
            let mut result_rs = Vec::new();
            for (i, swb) in secrets.iter().enumerate() {
                let secret_str = swb["secret"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'secret' in secrets {}", i))?;
                let blinding_factor_hex = swb["blinding_factor"]
                    .as_str()
                    .ok_or_else(|| format!("Missing 'blinding_factor' in secrets {}", i))?;

                let secret: Secret = secret_str
                    .parse()
                    .map_err(|e| format!("Invalid secret {}: {}", i, e))?;
                let r = SecretKey::from_hex(blinding_factor_hex)
                    .map_err(|e| format!("Invalid blinding factor {}: {}", i, e))?;

                result_secrets.push(secret);
                result_rs.push(r);
            }
            Ok((result_secrets, result_rs))
        };

    // Parse funding signatures and secrets
    let funding_blind_sigs = parse_signatures(signatures_raw)?;
    let (funding_secrets, funding_rs) = parse_secrets(&funding_secrets_raw)?;

    // Construct funding proofs (includes DLEQ verification)
    #[cfg(feature = "wallet")]
    let funding_proofs =
        dhke_construct_proofs(funding_blind_sigs, funding_rs, funding_secrets, &keys).map_err(
            |e| {
                format!(
                    "Failed to construct funding proofs (DLEQ verification failed?): {}",
                    e
                )
            },
        )?;

    #[cfg(not(feature = "wallet"))]
    let funding_proofs: Vec<Proof> = Vec::new(); // Stub for non-wallet builds
    #[cfg(not(feature = "wallet"))]
    let _ = (funding_blind_sigs, funding_rs, funding_secrets, keys); // suppress unused warnings

    // Serialize results
    let funding_proofs_json = serde_json::to_string(&funding_proofs)
        .map_err(|e| format!("Failed to serialize funding proofs: {}", e))?;

    let result = serde_json::json!({
        "funding_proofs_json": funding_proofs_json
    });

    Ok(result.to_string())
}
