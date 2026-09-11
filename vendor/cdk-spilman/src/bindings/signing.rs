use super::*;

// ============================================================================
// EXTERNAL SIGNER SUPPORT
// ============================================================================
// These functions support the SpilmanClientBridge's delegated signing flow,
// where the host provides a signing callback instead of the bridge holding
// a secret key directly.

/// Utility function for SpilmanClientHost implementations to sign with a tweaked key.
///
/// Given a secret key, a message hash, and a tweak scalar, computes:
///   tweaked_key = effective_secret + tweak
/// where effective_secret handles BIP-340 parity (negated if pubkey has odd Y),
/// then produces a BIP-340 Schnorr signature over the message.
///
/// This is a convenience function — hosts can implement signing however they want,
/// but this provides the standard implementation for hosts that hold raw secret keys.
///
/// # Arguments
/// * `secret_key_hex` - The signer's secret key (32 bytes, hex-encoded)
/// * `message_hex` - SHA-256 hash of the message to sign (32 bytes, hex-encoded)
/// * `tweak_scalar_hex` - The P2BK blinding scalar to add (32 bytes, hex-encoded)
///
/// # Returns
/// The BIP-340 Schnorr signature (64 bytes, hex-encoded)
pub fn sign_with_tweaked_key_util(
    secret_key_hex: &str,
    message_hex: &str,
    tweak_scalar_hex: &str,
) -> Result<String, String> {
    use bitcoin::secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1};

    let secp = Secp256k1::new();

    // Parse the secret key
    let secret =
        SecretKey::from_hex(secret_key_hex).map_err(|e| format!("Invalid secret key: {}", e))?;

    // Parse the tweak scalar
    let tweak_bytes =
        hex::decode(tweak_scalar_hex).map_err(|e| format!("Invalid tweak hex: {}", e))?;
    if tweak_bytes.len() != 32 {
        return Err(format!("Tweak must be 32 bytes, got {}", tweak_bytes.len()));
    }
    let mut tweak_arr = [0u8; 32];
    tweak_arr.copy_from_slice(&tweak_bytes);
    let tweak =
        Scalar::from_be_bytes(tweak_arr).map_err(|e| format!("Invalid tweak scalar: {}", e))?;

    // Parse the message hash
    let msg_bytes = hex::decode(message_hex).map_err(|e| format!("Invalid message hex: {}", e))?;
    if msg_bytes.len() != 32 {
        return Err(format!(
            "Message hash must be 32 bytes, got {}",
            msg_bytes.len()
        ));
    }
    let msg = Message::from_digest_slice(&msg_bytes)
        .map_err(|e| format!("Invalid message digest: {}", e))?;

    // Handle BIP-340 parity: if pubkey has odd Y, negate secret before adding tweak
    let pubkey = secret.public_key();
    let inner_pubkey: &bitcoin::secp256k1::PublicKey = &pubkey;
    let (_, parity) = inner_pubkey.x_only_public_key();

    let inner_secret: bitcoin::secp256k1::SecretKey = *secret;
    let effective_secret = if parity == Parity::Odd {
        inner_secret.negate()
    } else {
        inner_secret
    };

    // Add the tweak: tweaked_key = effective_secret + tweak
    let tweaked = effective_secret
        .add_tweak(&tweak)
        .map_err(|e| format!("Failed to add tweak: {}", e))?;

    // Sign with the tweaked key
    let keypair = Keypair::from_secret_key(&secp, &tweaked);
    let signature = secp.sign_schnorr(&msg, &keypair);

    Ok(signature.to_string())
}

/// Create an unsigned balance update for a channel.
///
/// Like `create_signed_balance_update`, but stops before signing.
/// Returns the unsigned swap request along with the message hash and tweak scalar
/// needed for external signing.
///
/// # Arguments
/// * `params_json` - Channel parameters JSON
/// * `keyset_info_json` - Keyset info JSON
/// * `channel_secret_hex` - The hashed ECDH channel secret (32 bytes, hex)
/// * `proofs_json` - Funding proofs JSON
/// * `balance` - New balance for Charlie
///
/// # Returns
/// JSON with:
/// - `channel_id`: Channel ID string
/// - `amount`: The balance amount
/// - `unsigned_swap_request_json`: The unsigned swap request (JSON)
/// - `message_hex`: SHA-256 hash of the SIG_ALL message (32 bytes, hex)
/// - `tweak_scalar_hex`: The P2BK blinding scalar for sender_stage1 (32 bytes, hex)
pub fn create_unsigned_balance_update(
    params_json: &str,
    keyset_info_json: &str,
    channel_secret_hex: &str,
    proofs_json: &str,
    balance: u64,
) -> Result<String, String> {
    let keyset_info = parse_keyset_info_from_json(keyset_info_json)?;
    let channel_secret_bytes = hex::decode(channel_secret_hex)
        .map_err(|e| format!("Invalid channel secret hex: {}", e))?;
    if channel_secret_bytes.len() != 32 {
        return Err(format!(
            "Channel secret must be 32 bytes, got {}",
            channel_secret_bytes.len()
        ));
    }
    let mut channel_secret_arr = [0u8; 32];
    channel_secret_arr.copy_from_slice(&channel_secret_bytes);
    let params = ChannelParameters::from_json_with_channel_secret(
        params_json,
        keyset_info,
        channel_secret_arr,
    )
    .map_err(|e| format!("Failed to create ChannelParameters: {}", e))?;
    let funding_proofs: Vec<Proof> =
        serde_json::from_str(proofs_json).map_err(|e| format!("Failed to parse proofs: {}", e))?;

    // Create commitment outputs for this balance
    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)
        .map_err(|e| format!("CommitmentOutputs::for_balance failed: {}", e))?;

    // Create the unsigned swap request
    let channel = EstablishedChannel::new(params.clone(), funding_proofs)
        .map_err(|e| format!("EstablishedChannel::new failed: {}", e))?;
    let swap_request = commitment_outputs
        .create_swap_request(channel.funding_proofs.clone(), None)
        .map_err(|e| format!("create_swap_request failed: {}", e))?;

    // Compute the SIG_ALL message hash
    let message_hex = crate::balance_update::sig_all_message_hash_hex(&swap_request);

    // Compute the tweak scalar (P2BK blinding for sender_stage1)
    let tweak = params
        .derive_sender_blinding_scalar_for_stage1()
        .map_err(|e| format!("Failed to derive blinding scalar: {}", e))?;
    let tweak_scalar_hex = hex::encode(tweak.to_be_bytes());

    // Serialize the unsigned swap request
    let unsigned_swap_request_json = serde_json::to_string(&swap_request)
        .map_err(|e| format!("Failed to serialize swap request: {}", e))?;

    let channel_id = params.get_channel_id();

    let result = serde_json::json!({
        "channel_id": channel_id,
        "amount": balance,
        "unsigned_swap_request_json": unsigned_swap_request_json,
        "message_hex": message_hex,
        "tweak_scalar_hex": tweak_scalar_hex,
    });

    Ok(result.to_string())
}

/// Attach an externally-produced signature to an unsigned balance update.
///
/// Takes an unsigned swap request and a BIP-340 Schnorr signature, attaches
/// the signature to the first input's witness, and returns a BalanceUpdateMessage.
///
/// # Arguments
/// * `unsigned_swap_request_json` - The unsigned swap request (from `create_unsigned_balance_update`)
/// * `signature_hex` - BIP-340 Schnorr signature (64 bytes, hex-encoded)
/// * `channel_id` - Channel ID string
/// * `amount` - The balance amount
///
/// # Returns
/// JSON with:
/// - `channel_id`: Channel ID string
/// - `amount`: The balance amount
/// - `signature`: The composite signature string (from the BalanceUpdateMessage)
pub fn attach_signature_to_balance_update(
    unsigned_swap_request_json: &str,
    signature_hex: &str,
    channel_id: &str,
    amount: u64,
) -> Result<String, String> {
    // Parse the unsigned swap request
    let mut swap_request: SwapRequest = serde_json::from_str(unsigned_swap_request_json)
        .map_err(|e| format!("Failed to parse swap request: {}", e))?;

    // Validate the signature string (must parse as a valid Schnorr signature)
    let _sig: bitcoin::secp256k1::schnorr::Signature = signature_hex.parse().map_err(
        |e: <bitcoin::secp256k1::schnorr::Signature as FromStr>::Err| {
            format!("Invalid signature hex: {}", e)
        },
    )?;

    crate::balance_update::attach_signature_to_first_input(&mut swap_request, signature_hex)
        .map_err(|e| format!("attach_signature_to_first_input failed: {}", e))?;

    // Extract the composite signature from the now-signed swap request
    let balance_update = crate::balance_update::BalanceUpdateMessage::from_signed_swap_request(
        channel_id.to_string(),
        amount,
        &swap_request,
    )
    .map_err(|e| format!("from_signed_swap_request failed: {}", e))?;

    let result = serde_json::json!({
        "channel_id": balance_update.channel_id,
        "amount": balance_update.amount,
        "signature": balance_update.signature.to_string()
    });

    Ok(result.to_string())
}
