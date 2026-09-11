use super::*;

impl<H: SpilmanHost<C>, C> SpilmanBridge<H, C> {
    fn prepare_close_data_impl(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        funding: ChannelFunding,
        validate_due: bool,
    ) -> Result<CloseData, BridgeError> {
        let secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .try_into()
            .map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &funding.params_json,
            crate::parse_keyset_info_from_json(&funding.keyset_info_json)
                .map_err(|e| BridgeError::Internal(e.to_string()))?,
            secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let active = self.host.get_active_keyset_ids(&params.mint, &params.unit);
        let out_keyset = if active.contains(&params.keyset_info.keyset_id) {
            params.keyset_info.clone()
        } else {
            let nid = active
                .first()
                .ok_or_else(|| BridgeError::Internal("No active keysets".into()))?;
            crate::parse_keyset_info_from_json(
                &self
                    .host
                    .get_keyset_info(&params.mint, nid)
                    .ok_or_else(|| BridgeError::Internal("Missing keyset info".into()))?,
            )
            .map_err(|e| BridgeError::Internal(e.to_string()))?
        };
        if balance > params.capacity {
            return Err(BridgeError::BalanceExceedsCapacity {
                balance,
                capacity: params.capacity,
            });
        }
        if validate_due && balance != self.host.get_amount_due(channel_id, None) {
            return Err(BridgeError::BalanceMismatch {
                expected: self.host.get_amount_due(channel_id, None),
                actual: balance,
            });
        }
        let commitment = CommitmentOutputs::for_balance(balance, &params)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swap = commitment
            .create_swap_request(proofs.clone(), Some(out_keyset.keyset_id))
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let channel = EstablishedChannel::new(params.clone(), proofs)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let signatures =
            crate::balance_update::verify_sender_signature_bundle(&channel, balance, signature)
                .map_err(BridgeError::InvalidSignature)?;
        crate::balance_update::attach_signature_to_first_input(
            &mut swap,
            &signatures.current.to_string(),
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
        if let Some(signature) = signatures.nutshell_0_20 {
            crate::balance_update::attach_signature_to_first_input(
                &mut swap,
                &signature.to_string(),
            )
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        }
        let tweak = hex::encode(
            params
                .derive_receiver_blinding_scalar_for_stage1()
                .map_err(|e| BridgeError::Internal(e.to_string()))?
                .to_be_bytes(),
        );
        let server_sig = self
            .host
            .sign_with_tweaked_key(
                &params.receiver_pubkey.to_hex(),
                &crate::balance_update::sig_all_message_hash_hex(&swap),
                &tweak,
            )
            .map_err(BridgeError::ServerMisconfigured)?;
        crate::balance_update::attach_signature_to_first_input(&mut swap, &server_sig)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        if signatures.nutshell_0_20.is_some() {
            let server_compatibility_sig = self
                .host
                .sign_with_tweaked_key(
                    &params.receiver_pubkey.to_hex(),
                    &crate::balance_update::nutshell_0_20_sig_all_message_hash_hex(&swap),
                    &tweak,
                )
                .map_err(BridgeError::ServerMisconfigured)?;
            crate::balance_update::attach_signature_to_first_input(
                &mut swap,
                &server_compatibility_sig,
            )
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        }
        let expected_total = params
            .get_value_after_stage1()
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let mut swb: Vec<_> = commitment
            .receiver_outputs
            .get_secrets_with_blinding()
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .into_iter()
            .map(|s| (s, true))
            .chain(
                commitment
                    .sender_outputs
                    .get_secrets_with_blinding()
                    .map_err(|e| BridgeError::Internal(e.to_string()))?
                    .into_iter()
                    .map(|s| (s, false)),
            )
            .collect();
        swb.sort_by_key(|(s, _)| s.amount);
        Ok(CloseData {
            swap_request: swap,
            expected_total,
            secrets_with_blinding: swb,
            output_keyset_info: out_keyset,
        })
    }

    fn prepare_close_data(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        validate_due: bool,
    ) -> Result<CloseData, BridgeError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closed {
            return Err(BridgeError::ChannelClosed);
        }
        let funding = match self.host.get_funding(channel_id) {
            Some(f) => {
                Self::verify_supplied_params(&f, params)?;
                f
            }
            None => self.validate_and_save_new_channel(
                channel_id,
                params.ok_or(BridgeError::UnknownChannel)?,
                funding_proofs.ok_or(BridgeError::UnknownChannel)?,
                balance,
                signature,
            )?,
        };
        self.prepare_close_data_impl(channel_id, balance, signature, funding, validate_due)
    }

    pub fn validate_and_prepare_cooperative_close(
        &self,
        json: &str,
    ) -> Result<CloseData, BridgeError> {
        let p: Payment =
            serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if p.channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if p.signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        self.prepare_close_data(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            true,
        )
    }

    pub fn create_unilateral_close_data(&self, channel_id: &str) -> Result<CloseData, BridgeError> {
        if self.host.get_funding(channel_id).is_none() {
            return Err(BridgeError::UnknownChannel);
        }
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| BridgeError::InvalidRequest("No payment proof".into()))?;
        self.prepare_close_data(channel_id, p.balance, &p.signature, None, None, false)
    }

    pub fn prepare_cooperative_close_for_execution(
        &self,
        json: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let p: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| ClosePreparationError::bad_request(e.to_string()))?;
        let channel_id = p["channel_id"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::bad_request("Missing ID"))?
            .to_string();
        let close_data = self
            .validate_and_prepare_cooperative_close(json)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let balance = p["balance"].as_u64().unwrap_or(0);
        let funding = self
            .host
            .get_funding(&channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        Self::wrap_close_data(close_data, &channel_id, balance, funding)
    }

    pub fn prepare_unilateral_close_for_execution(
        &self,
        channel_id: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let close_data = self
            .create_unilateral_close_data(channel_id)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self
            .host
            .get_funding(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing payment"))?;
        Self::wrap_close_data(close_data, channel_id, p.balance, funding)
    }

    /// Prepare a close using explicit balance/signature (used by the unified Closing→Closed path).
    fn prepare_close_for_closing_channel(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let close_data = self
            .prepare_close_data(channel_id, balance, signature, None, None, false)
            .map_err(ClosePreparationError::from_bridge_error)?;
        let funding = self
            .host
            .get_funding(channel_id)
            .ok_or_else(|| ClosePreparationError::internal("Missing funding"))?;
        Self::wrap_close_data(close_data, channel_id, balance, funding)
    }

    /// Wrap a CloseData + funding into a PreparedClose struct.
    fn wrap_close_data(
        close_data: CloseData,
        channel_id: &str,
        balance: u64,
        funding: ChannelFunding,
    ) -> Result<PreparedClose, ClosePreparationError> {
        let mint_url = serde_json::from_str::<serde_json::Value>(&funding.params_json)
            .map_err(|e| ClosePreparationError::internal(e.to_string()))?["mint"]
            .as_str()
            .ok_or_else(|| ClosePreparationError::internal("Missing mint"))?
            .to_string();
        Ok(PreparedClose { channel_id: channel_id.to_string(), balance, mint_url, swap_request: serde_json::to_value(&close_data.swap_request).unwrap_or(serde_json::Value::Null), secrets_with_blinding: close_data.secrets_with_blinding.iter().map(|(s, is_r)| serde_json::json!({ "secret": s.secret.to_string(), "blinding_factor": hex::encode(s.blinding_factor.secret_bytes()), "amount": s.amount, "index": s.index, "is_receiver": is_r })).collect(), output_keyset_info: serde_json::to_value(&close_data.output_keyset_info).unwrap_or(serde_json::Value::Null), params_json: funding.params_json, keyset_info_json: funding.keyset_info_json, channel_secret: funding.channel_secret_hex })
    }

    fn sign_receiver_close_proof(
        &self,
        params: &ChannelParameters,
        proof_meta: &ProofWithMeta,
    ) -> Result<Proof, CloseError> {
        use bitcoin::hashes::{sha256::Hash as Sha256Hash, Hash};

        let mut proof = proof_meta.proof.clone();
        params
            .attach_stage2_p2pk_e(
                &mut proof,
                Stage2Role::Receiver,
                proof_meta.amount,
                proof_meta.index,
            )
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to attach stage2 metadata: {}", e))
            })?;
        let tweak_info = params
            .stage2_tweak_info_for_role(Stage2Role::Receiver, proof_meta.amount, proof_meta.index)
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to derive stage2 tweak: {}", e))
            })?;
        let tweak_hex = hex::encode(tweak_info.stage2_tweak_scalar.to_be_bytes());
        let msg_hash = Sha256Hash::hash(&proof.secret.to_bytes());
        let msg_hex = hex::encode(msg_hash.as_byte_array());
        let sig = self
            .host
            .sign_with_tweaked_key(&params.receiver_pubkey.to_hex(), &msg_hex, &tweak_hex)
            .map_err(|e| {
                CloseError::unblind_failed(format!("Failed to sign receiver proof: {}", e))
            })?;
        proof.witness = Some(cashu::nuts::Witness::P2PKWitness(
            cashu::nuts::P2PKWitness {
                signatures: vec![sig],
            },
        ));

        Ok(proof)
    }

    fn finalize_close(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
        resp_json: &str,
        prep: &PreparedClose,
    ) -> Result<CloseSuccess, CloseError> {
        use crate::parse_keyset_info_from_json;
        use cashu::nuts::SecretKey;
        use cashu::secret::Secret;

        let resp: serde_json::Value =
            serde_json::from_str(resp_json).map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
        let sigs_value = resp
            .get("signatures")
            .ok_or_else(|| CloseError::UnblindFailed {
                reason: "Missing signatures".into(),
                status: 500,
            })?;

        // Parse inputs for the internal unblind function
        let keyset_info = parse_keyset_info_from_json(&prep.keyset_info_json)
            .map_err(CloseError::unblind_failed)?;
        let output_keyset_info = parse_keyset_info_from_json(&prep.output_keyset_info.to_string())
            .map_err(CloseError::unblind_failed)?;
        let channel_secret_bytes =
            hex::decode(&prep.channel_secret).map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
        let channel_secret: [u8; 32] =
            channel_secret_bytes
                .try_into()
                .map_err(|_| CloseError::UnblindFailed {
                    reason: "Invalid channel secret length".into(),
                    status: 500,
                })?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &prep.params_json,
            keyset_info,
            channel_secret,
        )
        .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;

        let blind_signatures: Vec<BlindSignature> = serde_json::from_str(&sigs_value.to_string())
            .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;
        let swb_raw: Vec<serde_json::Value> =
            serde_json::from_str(&prep.secrets_with_blinding.to_string()).map_err(|e| {
                CloseError::UnblindFailed {
                    reason: e.to_string(),
                    status: 500,
                }
            })?;

        let mut secrets_with_blinding = Vec::new();
        for swb in swb_raw {
            let secret = Secret::new(
                swb["secret"]
                    .as_str()
                    .ok_or_else(|| CloseError::UnblindFailed {
                        reason: "Missing secret".into(),
                        status: 500,
                    })?
                    .to_string(),
            );
            let blinding_factor = SecretKey::from_slice(
                &hex::decode(swb["blinding_factor"].as_str().ok_or_else(|| {
                    CloseError::UnblindFailed {
                        reason: "Missing blinding".into(),
                        status: 500,
                    }
                })?)
                .map_err(|e| CloseError::UnblindFailed {
                    reason: e.to_string(),
                    status: 500,
                })?,
            )
            .map_err(|e| CloseError::UnblindFailed {
                reason: e.to_string(),
                status: 500,
            })?;
            let amount = swb["amount"]
                .as_u64()
                .ok_or_else(|| CloseError::UnblindFailed {
                    reason: "Missing amount".into(),
                    status: 500,
                })?;
            let index = swb["index"]
                .as_u64()
                .ok_or_else(|| CloseError::UnblindFailed {
                    reason: "Missing index".into(),
                    status: 500,
                })? as usize;
            let is_receiver =
                swb["is_receiver"]
                    .as_bool()
                    .ok_or_else(|| CloseError::UnblindFailed {
                        reason: "Missing is_receiver".into(),
                        status: 500,
                    })?;
            secrets_with_blinding.push((
                DeterministicSecretWithBlinding {
                    secret,
                    blinding_factor,
                    amount,
                    index,
                },
                is_receiver,
            ));
        }

        // Unblind and verify (returns enriched proofs with amount/index metadata)
        let result = unblind_and_verify_stage1_response(
            blind_signatures,
            secrets_with_blinding,
            &params,
            &output_keyset_info,
            payment.balance,
        )
        .map_err(|e| CloseError::UnblindFailed {
            reason: e.to_string(),
            status: 500,
        })?;

        // Sign each receiver proof with P2PK witness using the host's tweaked signing
        let mut signed_receiver_proofs: Vec<Proof> =
            Vec::with_capacity(result.receiver_proofs.len());
        for pm in &result.receiver_proofs {
            signed_receiver_proofs.push(self.sign_receiver_close_proof(&params, pm)?);
        }

        let sender_proofs: Vec<&Proof> = result.sender_proofs.iter().map(|pm| &pm.proof).collect();
        let r_sum = result.receiver_sum;
        let s_sum = result.sender_sum;

        let receiver_proofs_json =
            serde_json::to_string(&signed_receiver_proofs).unwrap_or_default();
        let sender_proofs_json = serde_json::to_string(&sender_proofs).unwrap_or_default();

        self.host
            .mark_channel_closed(
                channel_id,
                expiry_timestamp,
                payment.balance,
                &receiver_proofs_json,
                &sender_proofs_json,
                r_sum,
                s_sum,
            )
            .map_err(CloseError::storage_failed)?;
        Ok(CloseSuccess {
            channel_id: channel_id.to_string(),
            total_value: r_sum + s_sum,
            receiver_sum: r_sum,
            sender_sum: s_sum,
            sender_proofs: sender_proofs_json,
            already_closed: false,
        })
    }

    pub fn execute_close_for_closing_channel<N: SpilmanNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing {
            return Err(CloseError::ValidationFailed {
                reason: "Not closing".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            });
        }
        let cd =
            self.host
                .get_closing_data(channel_id)
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "Missing closing data".into(),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                })?;
        let prep = self
            .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
            .map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net.call_mint_swap(&prep.mint_url, &prep.swap_request.to_string())
        {
            Ok(r) => (prep, r),
            Err(e) => {
                // Only retry on keyset errors (12xxx); fail immediately otherwise
                if !should_retry_swap_error(&e) {
                    return Err(CloseError::mint_rejected(parse_mint_error_value(&e)));
                }
                let _ = net.refresh_all_keysets(&prep.mint_url);
                let retry = self
                    .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
                    .map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .map_err(|re| {
                        CloseError::mint_rejected_after_retry(
                            parse_mint_error_value(&e),
                            parse_mint_error_value(&re),
                        )
                    })?;
                (retry, resp)
            }
        };
        self.finalize_close(
            channel_id,
            cd.expiry_timestamp,
            PaymentProof {
                balance: cd.balance,
                signature: cd.signature,
            },
            &resp,
            &prep,
        )
    }

    pub async fn execute_close_for_closing_channel_async<N: SpilmanAsyncNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) != ChannelState::Closing {
            return Err(CloseError::ValidationFailed {
                reason: "Not closing".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            });
        }
        let cd =
            self.host
                .get_closing_data(channel_id)
                .ok_or_else(|| CloseError::ValidationFailed {
                    reason: "Missing closing data".into(),
                    status: 500,
                    expected_balance: None,
                    actual_balance: None,
                })?;
        let prep = self
            .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
            .map_err(CloseError::from_preparation_error)?;
        let (prep, resp) = match net
            .call_mint_swap(&prep.mint_url, &prep.swap_request.to_string())
            .await
        {
            Ok(r) => (prep, r),
            Err(e) => {
                // Only retry on keyset errors (12xxx); fail immediately otherwise
                if !should_retry_swap_error(&e) {
                    return Err(CloseError::mint_rejected(parse_mint_error_value(&e)));
                }
                let _ = net.refresh_all_keysets(&prep.mint_url).await;
                let retry = self
                    .prepare_close_for_closing_channel(channel_id, cd.balance, &cd.signature)
                    .map_err(CloseError::from_preparation_error)?;
                let resp = net
                    .call_mint_swap(&retry.mint_url, &retry.swap_request.to_string())
                    .await
                    .map_err(|re| {
                        CloseError::mint_rejected_after_retry(
                            parse_mint_error_value(&e),
                            parse_mint_error_value(&re),
                        )
                    })?;
                (retry, resp)
            }
        };
        self.finalize_close(
            channel_id,
            cd.expiry_timestamp,
            PaymentProof {
                balance: cd.balance,
                signature: cd.signature,
            },
            &resp,
            &prep,
        )
    }

    pub fn execute_cooperative_close<N: SpilmanNetworking>(
        &self,
        json: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_cooperative_close_for_execution(json)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.host
            .mark_channel_closing(
                &prep.channel_id,
                expiry_timestamp,
                PaymentProof {
                    balance: prep.balance,
                    signature: sig,
                },
            )
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(&prep.channel_id, net)
    }

    pub async fn execute_cooperative_close_async<N: SpilmanAsyncNetworking>(
        &self,
        json: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        let prep = self
            .prepare_cooperative_close_for_execution(json)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let sig = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default()["signature"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.host
            .mark_channel_closing(
                &prep.channel_id,
                expiry_timestamp,
                PaymentProof {
                    balance: prep.balance,
                    signature: sig,
                },
            )
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(&prep.channel_id, net)
            .await
    }

    pub fn execute_unilateral_close<N: SpilmanNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closing {
            return self.execute_close_for_closing_channel(channel_id, net);
        }
        let prep = self
            .prepare_unilateral_close_for_execution(channel_id)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "No payment".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;
        self.host
            .mark_channel_closing(channel_id, expiry_timestamp, p)
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel(channel_id, net)
    }

    pub async fn execute_unilateral_close_async<N: SpilmanAsyncNetworking>(
        &self,
        channel_id: &str,
        net: &N,
    ) -> Result<CloseSuccess, CloseError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closing {
            return self
                .execute_close_for_closing_channel_async(channel_id, net)
                .await;
        }
        let prep = self
            .prepare_unilateral_close_for_execution(channel_id)
            .map_err(CloseError::from_preparation_error)?;
        let expiry_timestamp = serde_json::from_str::<serde_json::Value>(&prep.params_json)
            .unwrap_or_default()["expiry_timestamp"]
            .as_u64()
            .unwrap_or(0);
        let p = self
            .host
            .get_balance_and_signature_for_unilateral_exit(channel_id)
            .ok_or_else(|| CloseError::ValidationFailed {
                reason: "No payment".into(),
                status: 400,
                expected_balance: None,
                actual_balance: None,
            })?;
        self.host
            .mark_channel_closing(channel_id, expiry_timestamp, p)
            .map_err(CloseError::storage_failed)?;
        self.execute_close_for_closing_channel_async(channel_id, net)
            .await
    }
}
