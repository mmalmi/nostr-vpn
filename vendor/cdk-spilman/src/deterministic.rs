#![allow(missing_docs)]
//! Deterministic P2PK Output Generation
//!
//! Types for creating deterministic P2PK outputs for Spilman payment channels.
//! Contains a hierarchy of output types:
//! - `DeterministicSecretWithBlinding` - single output (secret + blinding + amount)
//! - `DeterministicOutputsForOneContext` - all outputs for one party
//! - `CommitmentOutputs` - outputs for both parties (receiver + sender)

use async_trait::async_trait;

use cashu::dhke::blind_message;
use cashu::nuts::nut10::spending_conditions::Conditions;
use cashu::nuts::nut11::SigFlag;
use cashu::nuts::{BlindSignature, BlindedMessage, Id, RestoreRequest, SecretKey};
use cashu::secret::Secret;
use cashu::Amount;

use super::keysets_and_amounts::OrderedListOfAmounts;
use super::params::{ChannelParameters, Stage2Role};

/// Trait for mint connection operations needed by Spilman channels
#[async_trait]
pub trait MintConnection: Send + Sync {
    /// Process a swap request
    async fn process_swap(
        &self,
        request: cashu::nuts::SwapRequest,
    ) -> anyhow::Result<cashu::nuts::SwapResponse>;
    /// Post a restore request
    async fn post_restore(
        &self,
        request: RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse>;
    /// Check proof state
    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse>;
}

#[cfg(test)]
mod tests;

/// Deterministic secret with blinding factor
/// Can hold any type of secret (simple P2PK, P2PK with conditions, HTLC, etc.)
#[derive(Debug, Clone)]
pub struct DeterministicSecretWithBlinding {
    /// The secret (can be any NUT-10 secret with specified nonce)
    pub secret: Secret,
    /// The blinding factor
    pub blinding_factor: SecretKey,
    /// The amount for this output
    pub amount: u64,
    /// The index within outputs of the same amount (for per-proof blinding)
    pub index: usize,
}

impl DeterministicSecretWithBlinding {
    /// Create a simple P2PK output (1-of-1 signature)
    /// Used for commitment outputs (sender or receiver)
    pub fn new_p2pk(
        pubkey: &cashu::nuts::PublicKey,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
        index: usize,
    ) -> Result<Self, anyhow::Error> {
        // Manually construct the NUT-10 P2PK secret JSON
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": null}]
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": pubkey.to_hex(),
                "tags": null
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
            index,
        })
    }

    /// Create a funding output with 2-of-2 multisig + expiry conditions
    /// Used for the funding token that both parties must sign to spend,
    /// or Alice alone can reclaim after expiry.
    ///
    /// Uses BLINDED pubkeys for privacy - the mint cannot correlate
    /// the funding token to Alice and Charlie's real identities.
    ///
    /// Note: Funding outputs use SHARED blinding (same pubkey for all proofs)
    /// because SIG_ALL requires identical keys in every proof. The index
    /// is stored but not used for blinding derivation in the funding context.
    pub fn new_funding(
        params: &ChannelParameters,
        nonce: String,
        blinding_factor: SecretKey,
        amount: u64,
        index: usize,
    ) -> Result<Self, anyhow::Error> {
        // Get blinded pubkeys for privacy
        // The 2-of-2 path uses one set of blinded keys
        let blinded_sender_pubkey = params.get_sender_blinded_pubkey_for_stage1()?;
        let blinded_receiver_pubkey = params.get_receiver_blinded_pubkey_for_stage1()?;
        // The refund path uses a DIFFERENT blinded key for Alice (unlinkable to 2-of-2)
        let blinded_sender_pubkey_refund = params.get_sender_blinded_pubkey_for_stage1_refund()?;

        // Create the spending conditions: 2-of-2 multisig (Alice + Charlie) before expiry
        // After expiry, Alice can refund with just her signature
        // All pubkeys are BLINDED for privacy, with refund using a separate tweak
        let conditions = Conditions::new(
            Some(params.expiry_timestamp), // Expiry timestamp for Alice's refund
            Some(vec![blinded_receiver_pubkey]), // Charlie's blinded key for 2-of-2
            Some(vec![blinded_sender_pubkey_refund]), // Alice's REFUND blinded key (different tweak)
            Some(2),                                  // Require 2 signatures before expiry
            Some(SigFlag::SigAll),                    // SigAll: signatures commit to outputs
            Some(1),                                  // Only 1 signature needed for refund (Alice)
        )?;

        // Convert conditions to proper NUT-10/11 tag array format
        let tags: Vec<Vec<String>> = conditions.into();
        let tags_json = serde_json::to_value(tags)
            .map_err(|e| anyhow::anyhow!("Failed to serialize spending conditions: {}", e))?;

        // Manually construct the NUT-10 P2PK secret JSON with spending conditions
        // Format: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...conditions...]}]
        // The "data" field contains Alice's BLINDED pubkey
        let secret_json = serde_json::json!([
            "P2PK",
            {
                "nonce": nonce,
                "data": blinded_sender_pubkey.to_hex(),
                "tags": tags_json
            }
        ]);

        // Create a Secret from the JSON string
        let secret = Secret::new(secret_json.to_string());

        Ok(Self {
            secret,
            blinding_factor,
            amount,
            index,
        })
    }

    /// Create a BlindedMessage from this deterministic output
    pub fn to_blinded_message(
        &self,
        amount: Amount,
        keyset_id: Id,
    ) -> Result<BlindedMessage, anyhow::Error> {
        // Blind the secret using the deterministic blinding factor
        let (blinded_point, _) =
            blind_message(&self.secret.to_bytes(), Some(self.blinding_factor.clone()))?;

        Ok(BlindedMessage::new(amount, keyset_id, blinded_point))
    }
}

/// A set of deterministic outputs for a specific pubkey and amount
/// This represents all the deterministic blinded messages, secrets, and blinding factors
/// for splitting a given amount into ecash outputs
#[derive(Debug, Clone)]
pub struct DeterministicOutputsForOneContext {
    /// The context for these outputs: "sender", "receiver", or "funding"
    pub context: String,
    /// The total amount to allocate
    pub amount: u64,
    /// The breakdown of amounts (largest-first)
    pub ordered_amounts: OrderedListOfAmounts,
    /// Channel parameters (includes shared_secret)
    pub params: ChannelParameters,
}

impl DeterministicOutputsForOneContext {
    /// Create a new set of deterministic outputs
    pub fn new(context: String, amount: u64, params: ChannelParameters) -> anyhow::Result<Self> {
        // Get the ordered list of amounts for this target
        let ordered_amounts = OrderedListOfAmounts::from_target(
            amount,
            params.maximum_amount_for_one_output,
            &params.keyset_info,
        )?;

        Ok(Self {
            context,
            amount,
            ordered_amounts,
            params,
        })
    }

    /// Calculate the value after stage 2 fees
    pub fn value_after_fees(&self) -> u64 {
        self.ordered_amounts.value_after_fees()
    }

    /// Get the secrets with blinding for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Returns full DeterministicSecretWithBlinding objects (secret + blinding factor)
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_secrets_with_blinding(
        &self,
    ) -> Result<Vec<DeterministicSecretWithBlinding>, anyhow::Error> {
        if self.amount == 0 {
            return Ok(vec![]);
        }

        let mut outputs = Vec::new();

        // Use iter_smallest_first to track index per amount (Cashu protocol recommendation)
        for (&single_amount, &count) in self.ordered_amounts.iter_smallest_first() {
            for index in 0..count {
                let det_output = self.params.create_deterministic_output_with_blinding(
                    &self.context,
                    single_amount,
                    index,
                )?;
                outputs.push(det_output);
            }
        }

        Ok(outputs)
    }

    /// Get the blinded messages for these outputs
    /// Works for all contexts: "sender", "receiver", and "funding"
    /// Outputs are ordered smallest-first per Cashu protocol recommendation
    pub fn get_blinded_messages(
        &self,
        override_keyset_id: Option<Id>,
    ) -> Result<Vec<BlindedMessage>, anyhow::Error> {
        // Get the secrets with blinding factors (already in smallest-first order)
        let secrets = self.get_secrets_with_blinding()?;

        // Build parallel vector of amounts in the same order as the secrets (smallest-first)
        let amounts: Vec<u64> = self
            .ordered_amounts
            .iter_smallest_first()
            .flat_map(|(&amount, &count)| std::iter::repeat_n(amount, count))
            .collect();

        // Use override keyset if provided, otherwise use the one from params
        let keyset_id = override_keyset_id.unwrap_or(self.params.keyset_info.keyset_id);

        // Convert each secret to a blinded message
        secrets
            .iter()
            .zip(amounts.iter())
            .map(|(secret, &amount)| secret.to_blinded_message(Amount::from(amount), keyset_id))
            .collect()
    }
}

/// Commitment outputs for a specific balance distribution
/// Contains the deterministic outputs for both sender (Alice) and receiver (Charlie)
/// at a specific balance point in the channel
#[derive(Debug, Clone)]
pub struct CommitmentOutputs {
    /// Receiver's (Charlie's) deterministic outputs
    pub receiver_outputs: DeterministicOutputsForOneContext,
    /// Sender's (Alice's) deterministic outputs
    pub sender_outputs: DeterministicOutputsForOneContext,
}

/// A proof with its associated metadata from the channel
///
/// Used when unblinding proofs to track which party owns each proof
/// and the (amount, index) needed for per-proof blinded key derivation.
#[derive(Debug, Clone)]
pub struct ProofWithMetadata {
    /// The unblinded proof
    pub proof: cashu::nuts::Proof,
    /// The nominal amount of this proof
    pub amount: u64,
    /// The index within proofs of the same amount (for per-proof blinding)
    pub index: usize,
    /// Whether this proof belongs to the receiver (Charlie) or sender (Alice)
    pub is_receiver: bool,
}

impl CommitmentOutputs {
    /// Create new commitment outputs
    pub fn new(
        receiver_outputs: DeterministicOutputsForOneContext,
        sender_outputs: DeterministicOutputsForOneContext,
    ) -> Self {
        Self {
            receiver_outputs,
            sender_outputs,
        }
    }

    /// Create commitment outputs for a given receiver balance
    ///
    /// Given the receiver's (Charlie's) desired final balance, this creates:
    /// - One DeterministicOutputsForOneContext for the receiver (Charlie)
    /// - One DeterministicOutputsForOneContext for the sender (Alice) with the remainder
    ///
    /// The process:
    /// 1. Use inverse function to find nominal value for receiver's deterministic outputs
    /// 2. Calculate sender's nominal value as: amount_after_stage1 - receiver_nominal
    /// 3. Create both sets of outputs wrapped in CommitmentOutputs
    ///
    /// Parameters:
    /// - receiver_balance: The desired final balance for the receiver (after stage 2 fees)
    /// - params: Channel parameters
    ///
    /// Returns CommitmentOutputs containing both receiver and sender outputs
    pub fn for_balance(receiver_balance: u64, params: &ChannelParameters) -> anyhow::Result<Self> {
        // Validate that receiver balance doesn't exceed channel capacity
        if receiver_balance > params.capacity {
            anyhow::bail!(
                "Receiver balance {} exceeds channel capacity {}",
                receiver_balance,
                params.capacity
            );
        }

        let max_amount = params.maximum_amount_for_one_output;

        // Get the amount available after stage 1 fees
        let amount_after_stage1 = params.get_value_after_stage1()?;

        // Find the nominal value needed for Charlie's deterministic outputs
        let inverse_result = params
            .keyset_info
            .inverse_deterministic_value_after_fees(receiver_balance, max_amount)?;
        let charlie_nominal = inverse_result.nominal_value;

        // Check if there's enough left for Alice (alice_nominal would be negative otherwise)
        if charlie_nominal > amount_after_stage1 {
            anyhow::bail!(
                "Receiver balance {} requires nominal value {} which exceeds available amount {} after stage 1 fees",
                receiver_balance,
                charlie_nominal,
                amount_after_stage1
            );
        }

        let alice_nominal = amount_after_stage1 - charlie_nominal;

        // Create outputs for Charlie (receiver)
        let charlie_outputs = DeterministicOutputsForOneContext::new(
            "receiver".to_string(),
            charlie_nominal,
            params.clone(),
        )?;

        // Create outputs for Alice (sender)
        let alice_outputs = DeterministicOutputsForOneContext::new(
            "sender".to_string(),
            alice_nominal,
            params.clone(),
        )?;

        Ok(Self::new(charlie_outputs, alice_outputs))
    }

    /// Create an unsigned swap request from this commitment
    ///
    /// Takes the funding proofs and creates a SwapRequest with:
    /// - Inputs: all funding proofs
    /// - Outputs: all outputs sorted by amount (stable) for privacy
    ///
    /// The swap request is unsigned and needs to be signed by the sender (Alice) before sending
    pub fn create_swap_request(
        &self,
        funding_proofs: Vec<cashu::nuts::Proof>,
        override_keyset_id: Option<Id>,
    ) -> Result<cashu::nuts::SwapRequest, anyhow::Error> {
        // Get blinded messages for receiver (Charlie)
        let mut outputs = self
            .receiver_outputs
            .get_blinded_messages(override_keyset_id)?;

        // Get blinded messages for sender (Alice)
        let sender_outputs = self
            .sender_outputs
            .get_blinded_messages(override_keyset_id)?;

        // Concatenate (receiver first, then sender)
        outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - mixes receiver and sender outputs
        outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create swap request with all funding proofs as inputs
        Ok(cashu::nuts::SwapRequest::new(funding_proofs, outputs))
    }

    /// Unblind all outputs from a swap response
    ///
    /// Takes the blind signatures from the swap response and returns
    /// a vector of `ProofWithMetadata` containing each proof along with
    /// its amount, index, and ownership flag.
    ///
    /// The caller can filter by `is_receiver` to separate receiver/sender proofs.
    pub fn unblind_all(
        &self,
        blind_signatures: Vec<BlindSignature>,
        active_keys: &cashu::nuts::Keys,
    ) -> Result<Vec<ProofWithMetadata>, anyhow::Error> {
        // Assert the number of signatures matches the expected number of outputs
        let expected_count =
            self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Expected {} blind signatures but received {}",
                expected_count,
                blind_signatures.len()
            );
        }

        // Get outputs for receiver and sender
        let receiver_outputs = self.receiver_outputs.get_secrets_with_blinding()?;
        let sender_outputs = self.sender_outputs.get_secrets_with_blinding()?;

        // Create vector with all outputs paired with ownership flag
        // Format: (DeterministicSecretWithBlinding, is_receiver)
        let mut all_outputs: Vec<(DeterministicSecretWithBlinding, bool)> =
            receiver_outputs.into_iter().map(|o| (o, true)).collect();

        // Extend with sender outputs with flag = false
        all_outputs.extend(sender_outputs.into_iter().map(|o| (o, false)));

        // Sort by amount (stable) to match create_swap_request ordering, i.e.
        // smallest amounts first, tie-breaking by the partner (Charlie first,
        // then Alice). For a given amount and partner, they are ordered by 'index'
        all_outputs.sort_by_key(|(output, _)| output.amount);

        if all_outputs.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} outputs for {} blind signatures",
                all_outputs.len(),
                blind_signatures.len()
            );
        }

        // Extract secrets and blinding factors in sorted order
        let sorted_secrets: Vec<_> = all_outputs.iter().map(|(o, _)| o.secret.clone()).collect();
        let sorted_blinding: Vec<_> = all_outputs
            .iter()
            .map(|(o, _)| o.blinding_factor.clone())
            .collect();

        if sorted_secrets.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} secrets for {} blind signatures",
                sorted_secrets.len(),
                blind_signatures.len()
            );
        }
        if sorted_blinding.len() != blind_signatures.len() {
            anyhow::bail!(
                "Internal mismatch: derived {} blinding factors for {} blind signatures",
                sorted_blinding.len(),
                blind_signatures.len()
            );
        }

        // Unblind all proofs in sorted order
        let all_proofs = cashu::dhke::construct_proofs(
            blind_signatures,
            sorted_blinding,
            sorted_secrets,
            active_keys,
        )?;

        if all_proofs.len() != all_outputs.len() {
            anyhow::bail!(
                "Internal mismatch: unblinded {} proofs for {} outputs",
                all_proofs.len(),
                all_outputs.len()
            );
        }

        // Build result with metadata for each proof
        all_proofs
            .into_iter()
            .zip(all_outputs.iter())
            .map(|(mut proof, (output, is_receiver))| {
                let role = if *is_receiver {
                    Stage2Role::Receiver
                } else {
                    Stage2Role::Sender
                };
                self.receiver_outputs.params.attach_stage2_p2pk_e(
                    &mut proof,
                    role,
                    output.amount,
                    output.index,
                )?;

                Ok(ProofWithMetadata {
                    proof,
                    amount: output.amount,
                    index: output.index,
                    is_receiver: *is_receiver,
                })
            })
            .collect()
    }

    /// Restore blind signatures from the mint using NUT-09
    ///
    /// This allows recovering the blind signatures for a commitment transaction
    /// without needing to have received them from the original swap.
    /// Since outputs are deterministic, we can recreate the blinded messages
    /// and ask the mint to restore the corresponding blind signatures.
    ///
    /// Returns the blind signatures in the same order as create_swap_request:
    /// sorted by amount (stable) for privacy
    pub async fn restore_all_blind_signatures<M>(
        &self,
        mint_connection: &M,
    ) -> Result<Vec<BlindSignature>, anyhow::Error>
    where
        M: MintConnection + ?Sized,
    {
        // Get all blinded messages in the same order as create_swap_request
        // (receiver first, then sender)
        let mut all_outputs = self.receiver_outputs.get_blinded_messages(None)?;
        let sender_outputs = self.sender_outputs.get_blinded_messages(None)?;
        all_outputs.extend(sender_outputs);

        // Sort by amount (stable) for privacy - matches create_swap_request ordering
        all_outputs.sort_by_key(|bm| u64::from(bm.amount));

        // Create restore request
        let restore_request = RestoreRequest {
            outputs: all_outputs,
        };

        // Call mint restore endpoint
        let restore_response = mint_connection
            .post_restore(restore_request)
            .await
            .map_err(|e| anyhow::anyhow!("Restore failed: {}", e))?;

        // Extract blind signatures from the response
        let blind_signatures: Vec<BlindSignature> = restore_response.signatures;

        // Verify we got the expected number of signatures
        let expected_count =
            self.receiver_outputs.ordered_amounts.len() + self.sender_outputs.ordered_amounts.len();
        if blind_signatures.len() != expected_count {
            anyhow::bail!(
                "Restore returned {} blind signatures but expected {}",
                blind_signatures.len(),
                expected_count
            );
        }

        Ok(blind_signatures)
    }
}
