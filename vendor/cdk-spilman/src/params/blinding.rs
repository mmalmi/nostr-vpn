use super::*;

impl ChannelParameters {
    /// Derive a blinding scalar for P2BK
    ///
    /// The `context` parameter specifies which blinded key to derive:
    /// - "sender_stage1" / "receiver_stage1" - for funding token 2-of-2
    /// - "sender_stage1_refund" - for funding token expiry refund
    ///
    /// Computes: SHA256("Cashu_Spilman_P2BK_v1" || channel_secret || "{channel_id}|{context}|{retry_counter}")
    /// Retries with incrementing retry_counter until a valid scalar in [1, n-1] is found.
    ///
    /// Note: This produces a SHARED blinding scalar for all proofs with the same context.
    /// For per-proof blinding (stage2), use `stage2_tweak_info_for_role()` instead.
    fn derive_blinding_scalar(&self, context: &str) -> anyhow::Result<Scalar> {
        let channel_id = self.get_channel_id();

        for retry_counter in 0u8..=255 {
            let text = format!("{}|{}|{}", channel_id, context, retry_counter);
            let mut input = Vec::new();
            input.extend_from_slice(b"Cashu_Spilman_P2BK_v1");
            input.extend_from_slice(&self.channel_secret);
            input.extend_from_slice(text.as_bytes());

            let hash = sha256::Hash::hash(&input);
            let bytes: [u8; 32] = hash.to_byte_array();

            // Try to create a valid scalar (must be in range [1, n-1])
            if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
                // Scalar::from_be_bytes rejects values >= n, and we also reject zero
                if scalar != Scalar::ZERO {
                    return Ok(scalar);
                }
            }
        }

        anyhow::bail!("Failed to derive valid blinding scalar after 256 attempts")
    }

    /// Derive stage 2 P2BK tweak info for a specific output
    ///
    /// Uses the per-output ephemeral secret to compute a NUT-28 shared-secret tweak
    /// alongside the deterministic ephemeral key material for later metadata use.
    pub(crate) fn stage2_tweak_info_for_role(
        &self,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<Stage2P2bkTweakInfo> {
        let role_pubkey = role.pubkey(self);
        let ephemeral_secret = self.derive_stage2_p2bk_ephemeral_secret_for_output(
            role.stage2_context(),
            amount,
            index,
        )?;
        let ephemeral_pubkey = ephemeral_secret.public_key();
        let ephemeral_shared_secret_x =
            Self::derive_nut28_shared_secret_x(role_pubkey, &ephemeral_secret)?;
        let stage2_tweak_scalar =
            Self::derive__nut28_P2KB_shared_secret_scalar(&ephemeral_shared_secret_x, 0x00)?;

        Ok(Stage2P2bkTweakInfo {
            ephemeral_secret,
            ephemeral_pubkey,
            ephemeral_shared_secret_x,
            stage2_tweak_scalar,
        })
    }

    /// Derive a per-output ephemeral secret for stage 2 contexts
    ///
    /// Computes: SHA256("Cashu_Spilman_P2BK_ephemeral_v1" || channel_secret || "{channel_id}|{context}|{amount}|{index}|{retry_counter}")
    /// Retries with incrementing retry_counter until a valid secret key is found.
    fn derive_stage2_p2bk_ephemeral_secret_for_output(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let channel_id = self.get_channel_id();

        for retry_counter in 0u8..=255 {
            let text = format!(
                "{}|{}|{}|{}|{}",
                channel_id, context, amount, index, retry_counter
            );
            let mut input = Vec::new();
            input.extend_from_slice(b"Cashu_Spilman_P2BK_ephemeral_v1");
            input.extend_from_slice(&self.channel_secret);
            input.extend_from_slice(text.as_bytes());

            let hash = sha256::Hash::hash(&input);
            let bytes: [u8; 32] = hash.to_byte_array();

            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(secret);
            }
        }

        anyhow::bail!("Failed to derive valid ephemeral secret for output after 256 attempts")
    }

    /// Derive the raw x-coordinate used by NUT-28 before the KDF step.
    pub(super) fn derive_nut28_shared_secret_x(
        pubkey: &cashu::nuts::PublicKey,
        secret: &SecretKey,
    ) -> anyhow::Result<[u8; 32]> {
        let shared_point = pubkey.mul_tweak(&SECP256K1, &secret.as_scalar())?;
        Ok(shared_point.x_only_public_key().0.serialize())
    }

    /// Derive NUT-28 P2BK scalar from ephemeral shared secret x-coordinate.
    ///
    /// Spec: https://raw.githubusercontent.com/cashubtc/nuts/refs/heads/main/28.md
    #[allow(non_snake_case)]
    fn derive__nut28_P2KB_shared_secret_scalar(
        zx: &[u8; 32],
        i_byte: u8,
    ) -> anyhow::Result<Scalar> {
        let mut input = Vec::new();
        input.extend_from_slice(b"Cashu_P2BK_v1");
        input.extend_from_slice(zx);
        input.push(i_byte);

        let hash = sha256::Hash::hash(&input);
        let bytes: [u8; 32] = hash.to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }

        input.push(0xff);
        let hash = sha256::Hash::hash(&input);
        let bytes: [u8; 32] = hash.to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }

        anyhow::bail!("Failed to derive valid P2BK scalar")
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Alice's blinded secret key.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_sender_blinded_pubkey_for_stage1(&self) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_pubkey(&self.sender_pubkey, &r)
    }

    /// Get the blinded receiver (Charlie) pubkey for stage 1 P2BK
    ///
    /// Computes the blinded pubkey that corresponds to Charlie's blinded secret key.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate it first.
    ///
    /// The formula matches `derive_blinded_secret_key`:
    /// - If even Y: P' = P + r*G (matches k = p + r)
    /// - If odd Y:  P' = -P + r*G (matches k = -p + r)
    pub fn get_receiver_blinded_pubkey_for_stage1(&self) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_pubkey(&self.receiver_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 signing
    ///
    /// For P2BK, Alice must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Alice's pubkey has odd Y, we negate her
    /// private key before adding the blinding scalar.
    pub fn get_sender_blinded_secret_key_for_stage1(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Get the sender's P2BK blinding scalar for stage 1 signing.
    ///
    /// This is the tweak scalar that must be added to Alice's secret key
    /// (with BIP-340 parity handling) to produce the blinded signing key.
    /// Used by the external signer flow in SpilmanClientBridge.
    pub fn derive_sender_blinding_scalar_for_stage1(&self) -> anyhow::Result<Scalar> {
        self.derive_blinding_scalar("sender_stage1")
    }

    /// Get the receiver's P2BK blinding scalar for stage 1 signing.
    ///
    /// This is the tweak scalar that must be added to Charlie's secret key
    /// (with BIP-340 parity handling) to produce the blinded signing key.
    /// Used by the external signer flow in SpilmanBridge.
    pub fn derive_receiver_blinding_scalar_for_stage1(&self) -> anyhow::Result<Scalar> {
        self.derive_blinding_scalar("receiver_stage1")
    }

    /// Get the blinded sender (Alice) pubkey for stage 1 expiry refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path, so the mint
    /// cannot correlate Alice's refund to the normal channel close.
    pub fn get_sender_blinded_pubkey_for_stage1_refund(
        &self,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_pubkey(&self.sender_pubkey, &r)
    }

    /// Derive the blinded sender secret key for stage 1 expiry refund
    ///
    /// Uses a DIFFERENT blinding tweak than the 2-of-2 spending path.
    /// Alice uses this to sign when reclaiming funds after expiry.
    pub fn get_sender_blinded_secret_key_for_stage1_refund(
        &self,
        alice_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("sender_stage1_refund")?;
        derive_blinded_secret_key(alice_secret, &r)
    }

    /// Derive the blinded receiver secret key for stage 1 signing
    ///
    /// For P2BK, Charlie must sign with a blinded private key k such that k*G = P'.
    /// This handles BIP-340 parity: if Charlie's pubkey has odd Y, we negate his
    /// private key before adding the blinding scalar.
    pub fn get_receiver_blinded_secret_key_for_stage1(
        &self,
        charlie_secret: &SecretKey,
    ) -> anyhow::Result<SecretKey> {
        let r = self.derive_blinding_scalar("receiver_stage1")?;
        derive_blinded_secret_key(charlie_secret, &r)
    }

    /// Get the blinded sender (Alice) pubkey for a specific stage 2 output
    ///
    /// Used for stage 1 outputs - each of Alice's proofs is locked to a UNIQUE
    /// blinded pubkey derived from (amount, index). She'll need to sign with
    /// the corresponding secret key in stage 2.
    ///
    /// This provides better privacy than a shared pubkey - the mint cannot
    /// trivially link proofs from the same channel closure.
    pub fn get_sender_blinded_pubkey_for_stage2_output(
        &self,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Sender, amount, index)?;
        derive_blinded_pubkey(&self.sender_pubkey, &tweak_info.stage2_tweak_scalar)
    }

    /// Get the blinded receiver (Charlie) pubkey for a specific stage 2 output
    ///
    /// Used for stage 1 outputs - each of Charlie's proofs is locked to a UNIQUE
    /// blinded pubkey derived from (amount, index). He'll need to sign with
    /// the corresponding secret key in stage 2.
    ///
    /// This provides better privacy than a shared pubkey - the mint cannot
    /// trivially link proofs from the same channel closure.
    pub fn get_receiver_blinded_pubkey_for_stage2_output(
        &self,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<cashu::nuts::PublicKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Receiver, amount, index)?;
        derive_blinded_pubkey(&self.receiver_pubkey, &tweak_info.stage2_tweak_scalar)
    }

    /// Derive the blinded sender secret key for a specific stage 2 output
    ///
    /// Alice uses this to sign when spending a specific stage 1 proof in stage 2.
    /// Each proof has a unique blinded secret key derived from (amount, index).
    pub fn get_sender_blinded_secret_key_for_stage2_output(
        &self,
        alice_secret: &SecretKey,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Sender, amount, index)?;
        derive_blinded_secret_key(alice_secret, &tweak_info.stage2_tweak_scalar)
    }

    /// Derive the blinded receiver secret key for a specific stage 2 output
    ///
    /// Charlie uses this to sign when spending a specific stage 1 proof in stage 2.
    /// Each proof has a unique blinded secret key derived from (amount, index).
    pub fn get_receiver_blinded_secret_key_for_stage2_output(
        &self,
        charlie_secret: &SecretKey,
        amount: u64,
        index: usize,
    ) -> anyhow::Result<SecretKey> {
        let tweak_info = self.stage2_tweak_info_for_role(Stage2Role::Receiver, amount, index)?;
        derive_blinded_secret_key(charlie_secret, &tweak_info.stage2_tweak_scalar)
    }

    /// Get a string representation of the unit
    pub fn unit_name(&self) -> &str {
        match self.unit {
            CurrencyUnit::Sat => "sat",
            CurrencyUnit::Msat => "msat",
            CurrencyUnit::Usd => "usd",
            CurrencyUnit::Eur => "eur",
            _ => "units",
        }
    }

    /// Get the STAGE2 blinded pubkey for a stage 1 output context ("sender" or "receiver")
    ///
    /// Returns the stage2 blinded pubkey for use in stage 1 commitment outputs:
    /// - "receiver" → Charlie's per-proof blinded pubkey (stage2 context)
    /// - "sender" → Alice's per-proof blinded pubkey (stage2 context)
    /// - "funding" → error (funding uses 2-of-2 with stage1 blinded pubkeys)
    ///
    /// Uses "stage2" blinding context because these are the keys needed to sign in stage 2.
    /// Each proof gets a UNIQUE blinded pubkey derived from (amount, index) for better privacy.
    pub fn get_stage2_blinded_pubkey_for_stage1_output(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<cashu::nuts::PublicKey, anyhow::Error> {
        match context {
            "receiver" => self.get_receiver_blinded_pubkey_for_stage2_output(amount, index),
            "sender" => self.get_sender_blinded_pubkey_for_stage2_output(amount, index),
            "funding" => anyhow::bail!(
                "Funding context requires 2-of-2 blinded pubkeys, use new_funding() instead"
            ),
            _ => anyhow::bail!("Unknown context: {}", context),
        }
    }

    pub(crate) fn stage2_p2pk_e_for_role(
        &self,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> Result<cashu::nuts::PublicKey, anyhow::Error> {
        let tweak_info = self.stage2_tweak_info_for_role(role, amount, index)?;

        Ok(tweak_info.ephemeral_pubkey)
    }

    pub(crate) fn attach_stage2_p2pk_e(
        &self,
        proof: &mut cashu::nuts::Proof,
        role: Stage2Role,
        amount: u64,
        index: usize,
    ) -> Result<(), anyhow::Error> {
        proof.p2pk_e = Some(self.stage2_p2pk_e_for_role(role, amount, index)?);
        Ok(())
    }

    /// Create a deterministic output with blinding using the channel ID and channel secret
    /// Uses channel_secret, channel_id, context, amount, and index in the derivation per NUT-XX spec
    ///
    /// The context parameter specifies the role: "sender", "receiver", or "funding"
    /// - "sender"/"receiver" create simple P2PK outputs for commitments using stage2 blinded pubkeys
    /// - "funding" creates P2PK outputs with 2-of-2 multisig + expiry conditions
    pub fn create_deterministic_output_with_blinding(
        &self,
        context: &str,
        amount: u64,
        index: usize,
    ) -> Result<DeterministicSecretWithBlinding, anyhow::Error> {
        let channel_id = self.get_channel_id();

        // Derive deterministic nonce: SHA256(channel_secret || "{channel_id}|{context}|{amount}|nonce|{index}")
        let nonce_text = format!("{}|{}|{}|nonce|{}", channel_id, context, amount, index);
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&self.channel_secret);
        nonce_input.extend_from_slice(nonce_text.as_bytes());

        let hash = sha256::Hash::hash(&nonce_input);
        let nonce = hex::encode(hash.to_byte_array());

        // Derive deterministic blinding factor: SHA256(channel_secret || "{channel_id}|{context}|{amount}|blinding|{index}")
        let blinding_text = format!("{}|{}|{}|blinding|{}", channel_id, context, amount, index);
        let mut blinding_input = Vec::new();
        blinding_input.extend_from_slice(&self.channel_secret);
        blinding_input.extend_from_slice(blinding_text.as_bytes());

        let hash = sha256::Hash::hash(&blinding_input);
        let blinding_factor = SecretKey::from_slice(hash.as_byte_array())?;

        // Handle funding context separately (requires 2-of-2 blinded pubkeys + expiry)
        if context == "funding" {
            DeterministicSecretWithBlinding::new_funding(
                self,
                nonce,
                blinding_factor,
                amount,
                index,
            )
        } else {
            // For sender/receiver contexts, create simple P2PK outputs with BLINDED pubkeys
            // Each proof gets a UNIQUE blinded pubkey derived from (amount, index)
            let pubkey =
                self.get_stage2_blinded_pubkey_for_stage1_output(context, amount, index)?;
            DeterministicSecretWithBlinding::new_p2pk(
                &pubkey,
                nonce,
                blinding_factor,
                amount,
                index,
            )
        }
    }

    /// Get the minimum funding token amount for a given capacity using double inverse
    ///
    /// This computes the minimum funding_token_amount needed to achieve at least
    /// the specified capacity after both fee stages, using the given keyset.
    ///
    /// Applies the inverse fee calculation twice to the capacity:
    /// 1. capacity → post-stage-1 nominal (accounting for stage 2 fees)
    /// 2. post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
    pub fn get_minimum_funding_token_amount(
        capacity: u64,
        keyset_info: &KeysetInfo,
        maximum_amount_for_one_output: u64,
    ) -> anyhow::Result<u64> {
        let max_amt = maximum_amount_for_one_output;

        // First inverse: capacity → post-stage-1 nominal (accounting for stage 2 fees)
        let first_inverse =
            keyset_info.inverse_deterministic_value_after_fees(capacity, max_amt)?;
        let post_stage1_nominal = first_inverse.nominal_value;

        // Second inverse: post-stage-1 nominal → funding token nominal (accounting for stage 1 fees)
        let second_inverse =
            keyset_info.inverse_deterministic_value_after_fees(post_stage1_nominal, max_amt)?;
        let funding_token_nominal = second_inverse.nominal_value;

        Ok(funding_token_nominal)
    }

    /// Get the total funding token amount
    ///
    /// Returns the explicit funding_token_amount field.
    pub fn get_total_funding_token_amount(&self) -> anyhow::Result<u64> {
        Ok(self.funding_token_amount)
    }

    /// Get the value available after stage 1 fees with a specific keyset
    pub fn get_value_after_stage1_with_keyset(
        &self,
        keyset_info: &KeysetInfo,
    ) -> anyhow::Result<u64> {
        // Apply forward to get actual value after stage 1 fees (spending the funding token)
        // using the provided keyset for the outputs
        let value_after_stage1 = keyset_info.deterministic_value_after_fees(
            self.funding_token_amount,
            self.maximum_amount_for_one_output,
        )?;

        Ok(value_after_stage1)
    }

    /// Get the value available after stage 1 fees
    ///
    /// Takes the funding token amount and applies the forward fee calculation
    /// to determine the actual amount available after the swap transaction (stage 1).
    ///
    /// This represents the total amount that will be distributed between Alice and Charlie
    /// in the commitment transaction outputs.
    ///
    /// Returns the actual value after stage 1 fees
    pub fn get_value_after_stage1(&self) -> anyhow::Result<u64> {
        self.get_value_after_stage1_with_keyset(&self.keyset_info)
    }

    /// Compute the actual de facto balance from an intended balance
    ///
    /// Due to output denomination constraints and fee rounding, the actual balance
    /// that can be created may differ slightly from the intended balance.
    ///
    /// This method:
    /// 1. Applies inverse to find the nominal value needed for the intended balance
    /// 2. Applies deterministic_value to that nominal to get the actual de facto balance
    ///
    /// Returns the actual balance that will be created
    pub fn get_de_facto_balance(&self, intended_balance: u64) -> anyhow::Result<u64> {
        let max_amt = self.maximum_amount_for_one_output;

        // Apply inverse to get nominal value needed
        let inverse_result = self
            .keyset_info
            .inverse_deterministic_value_after_fees(intended_balance, max_amt)?;
        let nominal_value = inverse_result.nominal_value;

        // Apply deterministic_value to get actual balance
        let actual_balance = self
            .keyset_info
            .deterministic_value_after_fees(nominal_value, max_amt)?;

        Ok(actual_balance)
    }
}
