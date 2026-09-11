//! Balance Update Message
//!
//! Represents signed and unsigned balance updates in a Spilman payment channel.
//!
//! The typical flow is:
//! 1. Create an `UnsignedBalanceUpdate` from channel funding data
//! 2. Sign it using a host/signer (using `message_hex` and `tweak_scalar_hex`)
//! 3. Call `sign()` to produce a `BalanceUpdateMessage`

use bitcoin::secp256k1::schnorr::Signature;
use cashu::nuts::nut10::SpendingConditionVerification;
use cashu::nuts::{P2PKWitness, SwapRequest, Witness};
use std::str::FromStr;

use super::client_storage::ClientChannelFunding;
use super::deterministic::CommitmentOutputs;
use super::established_channel::EstablishedChannel;

const SIG_ALL_COMPAT_BUNDLE_PREFIX: &str = "sigall-compat-v1";

pub(crate) struct SigAllSignatureBundle {
    pub(crate) current: Signature,
    pub(crate) nutshell_0_20: Option<Signature>,
}

/// Extract signatures from a swap request's first proof witness
pub fn get_signatures_from_swap_request(
    swap_request: &SwapRequest,
) -> Result<Vec<Signature>, anyhow::Error> {
    let first_proof = swap_request
        .inputs()
        .first()
        .ok_or_else(|| anyhow::anyhow!("No inputs in swap request"))?;

    let signatures =
        if let Some(cashu::nuts::Witness::P2PKWitness(p2pk_witness)) = &first_proof.witness {
            // Parse all signature strings into Signature objects
            p2pk_witness
                .signatures
                .iter()
                .filter_map(|sig_str| sig_str.parse::<Signature>().ok())
                .collect()
        } else {
            vec![]
        };

    Ok(signatures)
}

pub(crate) fn sig_all_message_hash_hex<T>(value: &T) -> String
where
    T: SpendingConditionVerification,
{
    message_hash_hex(&value.sig_all_msg_to_sign())
}

pub(crate) fn nutshell_0_20_sig_all_message(swap_request: &SwapRequest) -> String {
    let mut message = String::new();
    for proof in swap_request.inputs() {
        message.push_str(&proof.secret.to_string());
    }
    for output in swap_request.outputs() {
        message.push_str(&output.blinded_secret.to_hex());
    }
    message
}

pub(crate) fn nutshell_0_20_sig_all_message_hash_hex(swap_request: &SwapRequest) -> String {
    message_hash_hex(&nutshell_0_20_sig_all_message(swap_request))
}

fn message_hash_hex(message: &str) -> String {
    use bitcoin::hashes::{sha256, Hash};

    let hash = sha256::Hash::hash(message.as_bytes());

    cashu::util::hex::encode(hash.to_byte_array())
}

pub(crate) fn encode_sig_all_signature_bundle(current: &str, nutshell_0_20: &str) -> String {
    format!("{SIG_ALL_COMPAT_BUNDLE_PREFIX}:{current}:{nutshell_0_20}")
}

pub(crate) fn parse_sig_all_signature_bundle(value: &str) -> Result<SigAllSignatureBundle, String> {
    let parse = |signature: &str| {
        Signature::from_str(signature).map_err(|error| format!("Invalid signature: {error}"))
    };
    let Some(encoded) = value.strip_prefix(&format!("{SIG_ALL_COMPAT_BUNDLE_PREFIX}:")) else {
        return Ok(SigAllSignatureBundle {
            current: parse(value)?,
            nutshell_0_20: None,
        });
    };
    let (current, nutshell_0_20) = encoded
        .split_once(':')
        .ok_or_else(|| "invalid SIG_ALL compatibility signature bundle".to_string())?;
    if nutshell_0_20.contains(':') {
        return Err("invalid SIG_ALL compatibility signature bundle".to_string());
    }
    Ok(SigAllSignatureBundle {
        current: parse(current)?,
        nutshell_0_20: Some(parse(nutshell_0_20)?),
    })
}

pub(crate) fn verify_sender_signature_bundle(
    channel: &EstablishedChannel,
    balance: u64,
    encoded: &str,
) -> Result<SigAllSignatureBundle, String> {
    let signatures = parse_sig_all_signature_bundle(encoded)?;
    BalanceUpdateMessage {
        channel_id: channel.params.get_channel_id(),
        amount: balance,
        signature: signatures.current,
    }
    .verify_sender_signature(channel)
    .map_err(|error| error.to_string())?;

    if let Some(signature) = signatures.nutshell_0_20 {
        let commitment = CommitmentOutputs::for_balance(balance, &channel.params)
            .map_err(|error| error.to_string())?;
        let swap = commitment
            .create_swap_request(channel.funding_proofs.clone(), None)
            .map_err(|error| error.to_string())?;
        channel
            .params
            .get_sender_blinded_pubkey_for_stage1()
            .map_err(|error| error.to_string())?
            .verify(nutshell_0_20_sig_all_message(&swap).as_bytes(), &signature)
            .map_err(|_| {
                "Invalid signature: Alice did not authorize the Nutshell 0.20 balance update"
                    .to_string()
            })?;
    }

    Ok(signatures)
}

pub(crate) fn attach_signature_to_first_input(
    swap_request: &mut SwapRequest,
    sig_hex: &str,
) -> Result<(), anyhow::Error> {
    let first_input = swap_request
        .inputs_mut()
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("Swap request has no inputs"))?;

    match first_input.witness.as_mut() {
        Some(witness) => witness.add_signatures(vec![sig_hex.to_string()]),
        None => {
            let mut p2pk_witness = Witness::P2PKWitness(P2PKWitness::default());
            p2pk_witness.add_signatures(vec![sig_hex.to_string()]);
            first_input.witness = Some(p2pk_witness);
        }
    }

    Ok(())
}

/// A balance update message from Alice to Charlie
///
/// This represents a signed commitment to a new channel balance.
/// Alice signs a swap request that distributes the channel funds according to the new balance.
#[derive(Debug, Clone)]
pub struct BalanceUpdateMessage {
    /// Channel ID to identify which channel this update is for
    pub channel_id: String,
    /// New balance for the receiver (Charlie)
    pub amount: u64,
    /// Alice's signature over the swap request
    pub signature: Signature,
}

impl BalanceUpdateMessage {
    /// Used by Alice to create a balance update message from a swap request
    /// which is signed by her. She then sends the resulting message to Charlie.
    pub fn from_signed_swap_request(
        channel_id: String,
        amount: u64,
        swap_request: &SwapRequest,
    ) -> Result<Self, anyhow::Error> {
        // Extract Alice's signature from the swap request
        let signatures = get_signatures_from_swap_request(swap_request)?;

        // Ensure there is exactly one signature (Alice's only)
        if signatures.len() != 1 {
            anyhow::bail!(
                "Expected exactly 1 signature (Alice's), but found {}",
                signatures.len()
            );
        }

        let signature = signatures[0];

        Ok(Self {
            channel_id,
            amount,
            signature,
        })
    }

    /// Verify the signature using the established channel
    /// Charlie reconstructs the swap request from the amount to verify the signature
    /// Throws an error if the signature is invalid
    pub fn verify_sender_signature(
        &self,
        channel: &EstablishedChannel,
    ) -> Result<(), anyhow::Error> {
        // Reconstruct the commitment outputs for this balance
        let commitment_outputs = CommitmentOutputs::for_balance(self.amount, &channel.params)?;

        // Reconstruct the unsigned swap request
        let swap_request =
            commitment_outputs.create_swap_request(channel.funding_proofs.clone(), None)?;

        // Extract the SIG_ALL message from the swap request
        let msg_to_sign = swap_request.sig_all_msg_to_sign();

        // Verify the signature using Alice's BLINDED pubkey
        // Alice signs with her blinded secret key (the funding token uses blinded pubkeys for privacy)
        let blinded_sender_pubkey = channel.params.get_sender_blinded_pubkey_for_stage1()?;
        blinded_sender_pubkey
            .verify(msg_to_sign.as_bytes(), &self.signature)
            .map_err(|_| {
                anyhow::anyhow!("Invalid signature: Alice did not authorize this balance update")
            })?;

        Ok(())
    }
}

// ============================================================================
// UnsignedBalanceUpdate
// ============================================================================

/// An unsigned balance update, ready for signing.
///
/// Contains the precomputed message hash and tweak scalar needed for signing.
/// Once signed, use `sign()` to produce a `BalanceUpdateMessage`.
///
/// # Example
/// ```ignore
/// let unsigned = UnsignedBalanceUpdate::new(channel_id, balance, &funding)?;
/// let signature = host.sign_with_tweaked_key(
///     &funding.sender_pubkey_hex,
///     &unsigned.message_hex,
///     &unsigned.tweak_scalar_hex,
/// )?;
/// let balance_update = unsigned.sign(&signature)?;
/// ```
#[derive(Debug, Clone)]
pub struct UnsignedBalanceUpdate {
    /// Channel ID
    pub channel_id: String,
    /// Balance (cumulative amount receiver can claim)
    pub balance: u64,
    /// SHA-256 hash of the SIG_ALL message (32 bytes, hex-encoded)
    pub message_hex: String,
    /// P2BK blinding scalar for the sender (32 bytes, hex-encoded)
    pub tweak_scalar_hex: String,
}

impl UnsignedBalanceUpdate {
    /// Create an unsigned balance update from channel funding data.
    ///
    /// Computes the message hash and tweak scalar needed for signing.
    pub fn new(
        channel_id: &str,
        balance: u64,
        funding: &ClientChannelFunding,
    ) -> Result<Self, String> {
        // Use the existing bindings function (Option B: pragmatic approach)
        let unsigned_json = super::bindings::create_unsigned_balance_update(
            &funding.params_json,
            &funding.keyset_info_json,
            &funding.channel_secret_hex,
            &funding.funding_proofs_json,
            balance,
        )?;

        let unsigned: serde_json::Value = serde_json::from_str(&unsigned_json)
            .map_err(|e| format!("Failed to parse unsigned update: {}", e))?;

        let message_hex = unsigned["message_hex"]
            .as_str()
            .ok_or("Missing 'message_hex'")?
            .to_string();

        let tweak_scalar_hex = unsigned["tweak_scalar_hex"]
            .as_str()
            .ok_or("Missing 'tweak_scalar_hex'")?
            .to_string();

        Ok(Self {
            channel_id: channel_id.to_string(),
            balance,
            message_hex,
            tweak_scalar_hex,
        })
    }

    /// Attach a signature and produce a `BalanceUpdateMessage`.
    ///
    /// The signature should be a BIP-340 Schnorr signature (64 bytes, hex-encoded)
    /// produced by signing `message_hex` with the tweaked key.
    pub fn sign(self, signature_hex: &str) -> Result<BalanceUpdateMessage, String> {
        let signature =
            Signature::from_str(signature_hex).map_err(|e| format!("Invalid signature: {}", e))?;

        Ok(BalanceUpdateMessage {
            channel_id: self.channel_id,
            amount: self.balance,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::nuts::{Id, Proof, PublicKey};
    use cashu::secret::Secret;
    use cashu::Amount;

    fn proof(amount: u64, secret: &str) -> Proof {
        Proof::new(
            Amount::from(amount),
            Id::from_bytes(&[0; 8]).expect("keyset id"),
            Secret::new(secret.to_string()),
            PublicKey::from_str(
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            )
            .expect("public key"),
        )
    }

    #[test]
    fn compatibility_bundle_round_trips_both_signatures() {
        let mut swap = SwapRequest::new(
            vec![proof(4, "funding-4"), proof(16, "funding-16")],
            Vec::new(),
        );
        let current = "0b63f13bf77bb0fcd27e252641258eb9f631aa5b52ef1496671660f410b828a763b9bbed98c00dcb7c4d098ede9b9c4d93f87f7490f7a40fe5a8781e83c40390";
        let nutshell_0_20 = "a640c4bf20075a3f94ba72a7ef520510f3f86fae0272386be255d35ff9803f4141850de3d13afaf44d1b066bfb00f9bfcfd9f659bd09d8679fe8e99f12cc4fd4";

        let encoded = encode_sig_all_signature_bundle(current, nutshell_0_20);
        let parsed = parse_sig_all_signature_bundle(&encoded).expect("parse bundle");
        assert_eq!(parsed.current.to_string(), current);
        assert_eq!(
            parsed
                .nutshell_0_20
                .expect("compatibility signature")
                .to_string(),
            nutshell_0_20
        );

        attach_signature_to_first_input(&mut swap, current).expect("attach signature");
        assert!(swap.inputs()[0].witness.is_some());
        assert!(swap.inputs()[1].witness.is_none());
    }
}
