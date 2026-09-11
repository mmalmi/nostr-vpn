#![allow(missing_docs)]
//! Spilman Channel Sender and Receiver
//!
//! This module contains the sender's (Alice's) and receiver's (Charlie's) views
//! of a Spilman payment channel, plus standalone verification functions.

use serde::Serialize;

use cashu::nuts::{Proof, PublicKey, RestoreRequest, SecretKey, SwapRequest};
use cashu::Amount;

use super::balance_update::BalanceUpdateMessage;
use super::deterministic::{CommitmentOutputs, DeterministicOutputsForOneContext, MintConnection};
use super::established_channel::EstablishedChannel;
use super::keysets_and_amounts::KeysetInfo;
use super::params::{ChannelParameters, Stage2Role};

// ============================================================================
// Channel Verification
// ============================================================================

/// Errors that can occur during channel verification
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ChannelVerificationError {
    /// DLEQ proof is missing for a proof
    MissingDleq { proof_index: usize, amount: u64 },
    /// DLEQ proof is invalid (cryptographic verification failed)
    InvalidDleq {
        proof_index: usize,
        amount: u64,
        reason: String,
    },
    /// No mint public key found for this amount in the keyset
    MissingMintKey { proof_index: usize, amount: u64 },
    /// Keyset ID doesn't match the keys (keys may have been tampered with)
    InvalidKeysetId { expected: String, computed: String },
    /// Total value of funding proofs doesn't match funding_token_amount
    ValueMismatch { expected: u64, actual: u64 },
    /// Number of funding proofs doesn't match expected count
    CountMismatch { expected: usize, actual: usize },
    /// A proof's secret doesn't match the deterministic derivation
    SecretMismatch {
        proof_index: usize,
        expected: String,
        actual: String,
    },
    /// A proof's amount doesn't match the deterministic derivation
    AmountMismatch {
        proof_index: usize,
        expected: u64,
        actual: u64,
    },
    /// Internal error during verification
    InternalError(String),
}

/// Result of verifying a channel
#[derive(Debug, Serialize)]
pub struct ChannelVerificationResult {
    /// Whether all verifications passed
    pub valid: bool,
    /// List of errors found (empty if valid)
    pub errors: Vec<ChannelVerificationError>,
}

impl ChannelVerificationResult {
    /// Create a successful result
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    /// Create a failed result with errors
    pub fn failed(errors: Vec<ChannelVerificationError>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }

    /// Check if verification passed
    pub fn is_ok(&self) -> bool {
        self.valid
    }
}

/// Verify that a channel is valid
///
/// This function verifies everything about a channel that the receiver (Charlie)
/// needs to check before accepting it:
///
/// 1. Keyset ID matches the keys (prevents key substitution attacks)
/// 2. DLEQ proofs - the mint actually signed each funding proof (offline verification)
/// 3. Total value matches expected funding amount
/// 4. Secret structure matches expected deterministic derivation
///
/// Returns a result containing all verification errors found (if any)
pub fn verify_valid_channel(
    funding_proofs: &[Proof],
    params: &ChannelParameters,
) -> ChannelVerificationResult {
    use cashu::nuts::Id;

    let mut errors = Vec::new();

    // 1. Verify keyset ID matches the keys
    // This prevents an attacker from providing fake keys while claiming a legitimate keyset ID
    let expected_keyset_id = params.keyset_info.keyset_id;
    let computed_keyset_id = match expected_keyset_id.get_version() {
        cashu::nuts::nut02::KeySetVersion::Version00 => {
            Id::v1_from_keys(&params.keyset_info.active_keys)
        }
        cashu::nuts::nut02::KeySetVersion::Version01 => Id::v2_from_data(
            &params.keyset_info.active_keys,
            &params.keyset_info.unit,
            params.keyset_info.input_fee_ppk,
            params.keyset_info.final_expiry,
        ),
    };

    if expected_keyset_id != computed_keyset_id {
        errors.push(ChannelVerificationError::InvalidKeysetId {
            expected: expected_keyset_id.to_string(),
            computed: computed_keyset_id.to_string(),
        });
        // Continue to collect other errors
    }

    // 2. Verify DLEQ for each funding proof
    for (i, proof) in funding_proofs.iter().enumerate() {
        let amount = u64::from(proof.amount);

        // Check that DLEQ is present
        if proof.dleq.is_none() {
            errors.push(ChannelVerificationError::MissingDleq {
                proof_index: i,
                amount,
            });
            continue;
        }

        // Get the mint's public key for this amount
        let mint_pubkey: Option<PublicKey> =
            params.keyset_info.active_keys.amount_key(proof.amount);

        let mint_pubkey = match mint_pubkey {
            Some(key) => key,
            None => {
                errors.push(ChannelVerificationError::MissingMintKey {
                    proof_index: i,
                    amount,
                });
                continue;
            }
        };

        // Verify the DLEQ cryptographically
        if let Err(e) = proof.verify_dleq(mint_pubkey) {
            errors.push(ChannelVerificationError::InvalidDleq {
                proof_index: i,
                amount,
                reason: e.to_string(),
            });
        }
    }

    // 3. Verify total value
    let total_value: u64 = funding_proofs.iter().map(|p| u64::from(p.amount)).sum();
    if total_value != params.funding_token_amount {
        errors.push(ChannelVerificationError::ValueMismatch {
            expected: params.funding_token_amount,
            actual: total_value,
        });
    }

    // 4. Verify structural consistency
    let expected_outputs = match DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        params.funding_token_amount,
        params.clone(),
    ) {
        Ok(outputs) => match outputs.get_secrets_with_blinding() {
            Ok(secrets) => secrets,
            Err(e) => {
                errors.push(ChannelVerificationError::InternalError(e.to_string()));
                return ChannelVerificationResult::failed(errors);
            }
        },
        Err(e) => {
            errors.push(ChannelVerificationError::InternalError(e.to_string()));
            return ChannelVerificationResult::failed(errors);
        }
    };

    if funding_proofs.len() != expected_outputs.len() {
        errors.push(ChannelVerificationError::CountMismatch {
            expected: expected_outputs.len(),
            actual: funding_proofs.len(),
        });
    } else {
        for (i, (proof, expected)) in funding_proofs
            .iter()
            .zip(expected_outputs.iter())
            .enumerate()
        {
            if proof.secret != expected.secret {
                errors.push(ChannelVerificationError::SecretMismatch {
                    proof_index: i,
                    expected: expected.secret.to_string(),
                    actual: proof.secret.to_string(),
                });
            }
            if u64::from(proof.amount) != expected.amount {
                errors.push(ChannelVerificationError::AmountMismatch {
                    proof_index: i,
                    expected: expected.amount,
                    actual: u64::from(proof.amount),
                });
            }
        }
    }

    if errors.is_empty() {
        ChannelVerificationResult::ok()
    } else {
        ChannelVerificationResult::failed(errors)
    }
}

// ============================================================================
// Sender and Receiver
// ============================================================================

/// The sender's view of a Spilman payment channel
///
/// This struct holds Alice's secret key and the established channel state.
/// It provides high-level methods for Alice's operations.
#[derive(Debug)]
pub struct SpilmanChannelSender {
    /// Alice's secret key for signing
    pub alice_secret: SecretKey,
    /// The established channel state
    pub channel: EstablishedChannel,
}

impl SpilmanChannelSender {
    /// Create a new sender instance
    pub fn new(alice_secret: SecretKey, channel: EstablishedChannel) -> Self {
        Self {
            alice_secret,
            channel,
        }
    }

    /// Create and sign a balance update for the given amount to Charlie
    ///
    /// Returns (BalanceUpdateMessage, SwapRequest with Alice's signature)
    pub fn create_signed_balance_update(
        &self,
        charlie_balance: u64,
    ) -> anyhow::Result<(BalanceUpdateMessage, SwapRequest)> {
        // Create commitment outputs for this balance
        let commitment_outputs =
            CommitmentOutputs::for_balance(charlie_balance, &self.channel.params)?;

        // Create unsigned swap request
        let mut swap_request =
            commitment_outputs.create_swap_request(self.channel.funding_proofs.clone(), None)?;

        // Alice signs the swap request with her BLINDED secret key
        // (The funding token P2PK uses blinded pubkeys for privacy)
        let blinded_secret = self
            .channel
            .params
            .get_sender_blinded_secret_key_for_stage1(&self.alice_secret)?;

        swap_request.sign_sig_all(blinded_secret)?;

        // Create the balance update message
        let balance_update = BalanceUpdateMessage::from_signed_swap_request(
            self.channel.params.get_channel_id(),
            charlie_balance,
            &swap_request,
        )?;

        Ok((balance_update, swap_request))
    }

    /// Get the de facto balance (after fee rounding) for an intended balance
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        self.channel.params.get_de_facto_balance(intended_balance)
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> u64 {
        self.channel.params.capacity
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> String {
        self.channel.params.get_channel_id()
    }

    /// Get the channel secret (stored in channel params)
    pub fn get_channel_secret(&self) -> &[u8; 32] {
        &self.channel.params.channel_secret
    }

    /// Restore sender's proofs after Charlie has exited the channel
    ///
    /// When Charlie exits by submitting the commitment transaction, Alice may not
    /// receive her blind signatures directly. This method uses NUT-09 restore to
    /// recover Alice's proofs by iterating over all possible (amount, index) pairs.
    ///
    /// The algorithm:
    /// - For each amount in the keyset (ascending, filtered by max_amount unless max_amount == 0):
    ///   - For index starting at 0:
    ///     - Try to restore the deterministic output for ("sender", amount, index)
    ///     - If restore fails (no signature), break to next amount
    ///     - If restore succeeds, unblind and collect the proof, increment index
    ///
    /// Returns all recovered proofs for Alice.
    pub async fn restore_sender_proofs<M: MintConnection + ?Sized>(
        &self,
        mint_connection: &M,
    ) -> anyhow::Result<Vec<Proof>> {
        self.restore_sender_proofs_with_keyset(mint_connection, &self.channel.params.keyset_info)
            .await
    }

    /// Restore sender proofs issued under the keyset used by the close swap.
    ///
    /// A mint can rotate keysets while a channel is open. The deterministic
    /// output secrets remain tied to the original channel parameters, but the
    /// close swap's blinded messages and signatures use the active output
    /// keyset selected at settlement time.
    pub async fn restore_sender_proofs_with_keyset<M: MintConnection + ?Sized>(
        &self,
        mint_connection: &M,
        output_keyset_info: &KeysetInfo,
    ) -> anyhow::Result<Vec<Proof>> {
        let params = &self.channel.params;
        let keyset_id = output_keyset_info.keyset_id;
        let max_amount = params.maximum_amount_for_one_output;

        // Get amounts in ascending order (smallest first).
        // A max_amount of 0 means "no limit", so we must not filter in that case.
        let mut amounts: Vec<u64> = params
            .keyset_info
            .amounts_largest_first
            .iter()
            .copied()
            .filter(|&amt| max_amount == 0 || amt <= max_amount)
            .collect();
        amounts.reverse(); // Now smallest first

        let mut recovered_proofs = Vec::new();

        for amount in amounts {
            let mut index = 0usize;

            loop {
                // Create deterministic output for this (amount, index)
                let det_output =
                    params.create_deterministic_output_with_blinding("sender", amount, index)?;

                // Create blinded message for restore request
                let blinded_message =
                    det_output.to_blinded_message(Amount::from(amount), keyset_id)?;

                // Try to restore this single output
                let restore_request = RestoreRequest {
                    outputs: vec![blinded_message.clone()],
                };

                let mut response = mint_connection.post_restore(restore_request).await?;
                if response.outputs.len() != response.signatures.len()
                    || response.signatures.len() > 1
                {
                    anyhow::bail!(
                        "mint restore response has invalid output/signature counts for amount {} index {}",
                        amount,
                        index
                    );
                }
                let Some(blind_signature) = response.signatures.pop() else {
                    // No signature found for this (amount, index), move to next amount.
                    break;
                };
                if response.outputs[0].blinded_secret != blinded_message.blinded_secret
                    || u64::from(blind_signature.amount) != amount
                {
                    anyhow::bail!(
                        "mint restore response does not match requested output for amount {} index {}",
                        amount,
                        index
                    );
                }
                // A restore lookup is by blinded secret. The signature may reveal
                // a different issuing keyset after rotation; callers use that ID
                // to resolve the correct keys and repeat restoration.
                let mut proofs = cashu::dhke::construct_proofs(
                    vec![blind_signature],
                    vec![det_output.blinding_factor.clone()],
                    vec![det_output.secret.clone()],
                    &output_keyset_info.active_keys,
                )?;
                let mut proof = proofs
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("construct_proofs returned no proofs"))?;

                params.attach_stage2_p2pk_e(&mut proof, Stage2Role::Sender, amount, index)?;

                recovered_proofs.push(proof);
                index += 1;
            }
        }

        Ok(recovered_proofs)
    }
}

// SpilmanChannelReceiver has been removed.
// Server-side signing is now delegated to the SpilmanHost via sign_with_tweaked_key().

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::params::mock_keyset_info;
    use cashu::nuts::{CheckStateResponse, CurrencyUnit, RestoreResponse, SwapResponse};

    struct RecordingMintConnection {
        attempted_amounts: Mutex<Vec<u64>>,
        attempted_keysets: Mutex<Vec<cashu::nuts::Id>>,
    }

    impl RecordingMintConnection {
        fn new() -> Self {
            Self {
                attempted_amounts: Mutex::new(Vec::new()),
                attempted_keysets: Mutex::new(Vec::new()),
            }
        }

        fn attempted_amounts(&self) -> Vec<u64> {
            self.attempted_amounts.lock().unwrap().clone()
        }

        fn attempted_keysets(&self) -> Vec<cashu::nuts::Id> {
            self.attempted_keysets.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MintConnection for RecordingMintConnection {
        async fn process_swap(
            &self,
            _request: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<SwapResponse> {
            unreachable!("process_swap is not used in these tests")
        }

        async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            let amount = request
                .outputs
                .first()
                .map(|output| u64::from(output.amount))
                .expect("restore request should contain one output");
            self.attempted_amounts.lock().unwrap().push(amount);
            self.attempted_keysets
                .lock()
                .unwrap()
                .push(request.outputs[0].keyset_id);

            Ok(RestoreResponse {
                outputs: vec![],
                signatures: vec![],
            })
        }

        async fn check_state(
            &self,
            _ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            unreachable!("check_state is not used in these tests")
        }
    }

    struct FailingRestoreMintConnection;

    #[async_trait]
    impl MintConnection for FailingRestoreMintConnection {
        async fn process_swap(
            &self,
            _request: cashu::nuts::SwapRequest,
        ) -> anyhow::Result<SwapResponse> {
            unreachable!("process_swap is not used in these tests")
        }

        async fn post_restore(&self, _request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            anyhow::bail!("restore transport failed")
        }

        async fn check_state(
            &self,
            _ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            unreachable!("check_state is not used in these tests")
        }
    }

    fn create_test_sender(maximum_amount_for_one_output: u64) -> SpilmanChannelSender {
        let alice_secret = SecretKey::generate();
        let sender_pubkey = alice_secret.public_key();

        let charlie_secret = SecretKey::generate();
        let receiver_pubkey = charlie_secret.public_key();

        let keyset_info = mock_keyset_info(vec![1, 2, 4, 8], 0);
        let capacity = 8;
        let funding_token_amount = ChannelParameters::get_minimum_funding_token_amount(
            capacity,
            &keyset_info,
            maximum_amount_for_one_output,
        )
        .unwrap();

        let params = ChannelParameters::new_with_secret_key(
            sender_pubkey,
            receiver_pubkey,
            "local".to_string(),
            CurrencyUnit::Sat,
            capacity,
            funding_token_amount,
            0,
            0,
            keyset_info,
            maximum_amount_for_one_output,
            &alice_secret,
        )
        .unwrap();

        let channel = EstablishedChannel {
            params,
            funding_proofs: vec![],
        };

        SpilmanChannelSender::new(alice_secret, channel)
    }

    #[tokio::test]
    async fn test_restore_sender_proofs_max_amount_zero_means_no_filtering() {
        let sender = create_test_sender(0);
        let mint = RecordingMintConnection::new();

        let proofs = sender.restore_sender_proofs(&mint).await.unwrap();

        assert!(proofs.is_empty(), "mock restore returns no proofs");
        assert_eq!(mint.attempted_amounts(), vec![1, 2, 4, 8]);
    }

    #[tokio::test]
    async fn test_restore_sender_proofs_respects_nonzero_max_amount() {
        let sender = create_test_sender(4);
        let mint = RecordingMintConnection::new();

        let proofs = sender.restore_sender_proofs(&mint).await.unwrap();

        assert!(proofs.is_empty(), "mock restore returns no proofs");
        assert_eq!(mint.attempted_amounts(), vec![1, 2, 4]);
    }

    #[tokio::test]
    async fn test_restore_sender_proofs_uses_close_output_keyset() {
        let sender = create_test_sender(4);
        let mint = RecordingMintConnection::new();
        let mut close_output_keyset = sender.channel.params.keyset_info.clone();
        close_output_keyset.keyset_id = "00107937db0cc865".parse().unwrap();

        let proofs = sender
            .restore_sender_proofs_with_keyset(&mint, &close_output_keyset)
            .await
            .unwrap();

        assert!(proofs.is_empty(), "mock restore returns no proofs");
        assert_eq!(
            mint.attempted_keysets(),
            vec![close_output_keyset.keyset_id; 3]
        );
    }

    #[tokio::test]
    async fn test_restore_sender_proofs_propagates_mint_failures() {
        let sender = create_test_sender(4);

        let error = sender
            .restore_sender_proofs(&FailingRestoreMintConnection)
            .await
            .expect_err("mint failures must remain retryable");

        assert!(error.to_string().contains("restore transport failed"));
    }
}
