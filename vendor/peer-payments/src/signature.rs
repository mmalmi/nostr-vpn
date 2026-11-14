//! BIP340 signatures over the SHA256 of the versioned payment message.
//! Keys are supplied by the embedding application; this crate creates no identity.
use crate::{Error, Verifier, WireMessage};
use secp256k1::{schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default)]
pub struct SchnorrVerifier;

impl Verifier for SchnorrVerifier {
    fn verify(&self, identity: &str, message: &[u8], signature: &str) -> bool {
        // A single spelling prevents aliases from bypassing per-peer limits.
        if !canonical_hex(identity, 64) || !canonical_hex(signature, 128) {
            return false;
        }
        let (Ok(public), Ok(signature)) = (
            XOnlyPublicKey::from_str(identity),
            Signature::from_str(signature),
        ) else {
            return false;
        };
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &digest(message), &public)
            .is_ok()
    }
}

/// Sign only after durably reserving the corresponding obligation. This function
/// is deliberately separate from journal mutation so a failed save cannot send it.
pub fn sign_message(key: &Keypair, message: &WireMessage) -> Result<String, Error> {
    Ok(Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(&digest(&message.signing_bytes()?), key)
        .to_string())
}

fn digest(message: &[u8]) -> Message {
    Message::from_digest(Sha256::digest(message).into())
}

fn canonical_hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
