use super::*;

impl<H: SpilmanHost<C>, C> SpilmanBridge<H, C> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            _phantom: std::marker::PhantomData,
        }
    }
    pub fn host(&self) -> &H {
        &self.host
    }

    fn decode_payment_header(base64_header: &str) -> Result<Payment, BridgeError> {
        let decoded = BASE64
            .decode(base64_header)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let json =
            String::from_utf8(decoded).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))
    }

    pub fn process_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        if self.host.get_channel_state(channel_id) == ChannelState::Closing {
            return self.refresh_closing_payment(channel_id, balance, signature, params, context);
        }
        let val = self.validate_payment(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        )?;
        self.host
            .record_payment(
                &val.channel_id,
                PaymentProof {
                    balance: val.balance,
                    signature: val.sender_signature.clone(),
                },
                context,
            )
            .map_err(|e| {
                BridgeError::Internal(format!("record payment persistence failed: {e}"))
            })?;
        Ok(PaymentSuccess {
            channel_id: val.channel_id,
            balance: val.balance,
            amount_due: val.amount_due,
            capacity: val.capacity,
        })
    }

    fn refresh_closing_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        let closing = self
            .host
            .get_closing_data(channel_id)
            .ok_or_else(|| BridgeError::Internal("closing channel has no close data".into()))?;
        if balance != closing.balance {
            return Err(BridgeError::BalanceMismatch {
                expected: closing.balance,
                actual: balance,
            });
        }
        let funding = self
            .host
            .get_funding(channel_id)
            .ok_or(BridgeError::UnknownChannel)?;
        Self::verify_supplied_params(&funding, params)?;
        self.verify_signature(
            &funding.params_json,
            &funding.funding_proofs_json,
            &funding.channel_secret_hex,
            &funding.keyset_info_json,
            channel_id,
            balance,
            signature,
        )
        .map_err(BridgeError::InvalidSignature)?;
        if crate::balance_update::parse_sig_all_signature_bundle(signature)
            .map_err(BridgeError::InvalidSignature)?
            .nutshell_0_20
            .is_none()
        {
            return Err(BridgeError::InvalidSignature(
                "closing-channel refresh requires a compatibility signature".into(),
            ));
        }

        self.host
            .mark_channel_closing(
                channel_id,
                closing.expiry_timestamp,
                PaymentProof {
                    balance,
                    signature: signature.to_string(),
                },
            )
            .map_err(|error| {
                BridgeError::Internal(format!("closing payment persistence failed: {error}"))
            })?;

        let params: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|error| BridgeError::Internal(error.to_string()))?;
        Ok(PaymentSuccess {
            channel_id: channel_id.to_string(),
            balance,
            amount_due: self.host.get_amount_due(channel_id, Some(context)),
            capacity: params["capacity"].as_u64().unwrap_or(0),
        })
    }

    pub fn process_payment_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        let p: Payment = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.process_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn process_payment_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<PaymentSuccess, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.process_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn validate_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }
        let (funding, is_new) = match self.host.get_funding(channel_id) {
            Some(f) => {
                Self::verify_supplied_params(&f, params)?;
                (f, false)
            }
            None => (
                self.validate_and_save_new_channel(
                    channel_id,
                    params.ok_or(BridgeError::UnknownChannel)?,
                    funding_proofs.ok_or(BridgeError::UnknownChannel)?,
                    balance,
                    signature,
                )?,
                true,
            ),
        };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        let expiry_timestamp = params_val["expiry_timestamp"].as_u64().unwrap_or(0);
        let now = self.host.now_seconds();
        if expiry_timestamp <= now {
            return Err(BridgeError::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry: now.saturating_add(1),
                now,
            });
        }
        if !is_new {
            if balance > capacity {
                return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
            }
            self.verify_signature(
                &funding.params_json,
                &funding.funding_proofs_json,
                &funding.channel_secret_hex,
                &funding.keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }
        let amount_due = self.host.get_amount_due(channel_id, Some(context));
        if balance < amount_due {
            return Err(BridgeError::InsufficientBalance {
                balance,
                amount_due,
            });
        }
        Ok(PaymentValidationResult {
            channel_id: channel_id.to_string(),
            balance,
            amount_due,
            capacity,
            sender_signature: signature.to_string(),
        })
    }

    pub(super) fn verify_supplied_params(
        funding: &ChannelFunding,
        supplied: Option<&serde_json::Value>,
    ) -> Result<(), BridgeError> {
        if let Some(supplied) = supplied {
            let stored: serde_json::Value = serde_json::from_str(&funding.params_json)
                .map_err(|e| BridgeError::Internal(e.to_string()))?;
            if supplied != &stored {
                return Err(BridgeError::InvalidRequest(
                    "Supplied channel parameters differ from stored funding".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_payment_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let p: Payment = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.validate_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn validate_payment_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<PaymentValidationResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.validate_payment(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    /// Verify that a payment covers the current amount due.
    ///
    /// This performs full validation (including signature checks) and returns the
    /// computed amount_due on success. It does NOT record usage, but may save
    /// funding data for new channels (same behavior as validate_payment).
    pub fn verify_payment_covers_amount_due(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let val = self.validate_payment(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        )?;
        Ok(val.amount_due)
    }

    pub fn verify_payment_covers_amount_due_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let p: Payment = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.verify_payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn verify_payment_covers_amount_due_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<u64, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.verify_payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    /// Return true if the payment covers the amount due.
    ///
    /// Returns Ok(false) only for insufficient balance. Other validation errors
    /// are returned as Err.
    pub fn payment_covers_amount_due(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
        context: &C,
    ) -> Result<bool, BridgeError> {
        match self.verify_payment_covers_amount_due(
            channel_id,
            balance,
            signature,
            params,
            funding_proofs,
            context,
        ) {
            Ok(_) => Ok(true),
            Err(BridgeError::InsufficientBalance { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn payment_covers_amount_due_via_json(
        &self,
        payment_json: &str,
        context: &C,
    ) -> Result<bool, BridgeError> {
        let p: Payment = serde_json::from_str(payment_json)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn payment_covers_amount_due_via_base64_header(
        &self,
        base64_header: &str,
        context: &C,
    ) -> Result<bool, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.payment_covers_amount_due(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
            context,
        )
    }

    pub fn fund_channel(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
        params: Option<&serde_json::Value>,
        funding_proofs: Option<&[Proof]>,
    ) -> Result<FundChannelResult, BridgeError> {
        if channel_id.is_empty() {
            return Err(BridgeError::InvalidRequest("missing channel_id".into()));
        }
        if signature.is_empty() {
            return Err(BridgeError::InvalidRequest("missing signature".into()));
        }
        match self.host.get_channel_state(channel_id) {
            ChannelState::Closed => return Err(BridgeError::ChannelClosed),
            ChannelState::Closing => return Err(BridgeError::ChannelClosing),
            ChannelState::Open => {}
        }
        let (funding, already_known) = match self.host.get_funding(channel_id) {
            Some(f) => {
                Self::verify_supplied_params(&f, params)?;
                (f, true)
            }
            None => (
                self.validate_and_save_new_channel(
                    channel_id,
                    params.ok_or(BridgeError::InvalidRequest("Missing params".into()))?,
                    funding_proofs.ok_or(BridgeError::InvalidRequest("Missing proofs".into()))?,
                    balance,
                    signature,
                )?,
                false,
            ),
        };
        let params_val: serde_json::Value = serde_json::from_str(&funding.params_json)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let capacity = params_val["capacity"].as_u64().unwrap_or(0);
        if already_known {
            self.verify_signature(
                &funding.params_json,
                &funding.funding_proofs_json,
                &funding.channel_secret_hex,
                &funding.keyset_info_json,
                channel_id,
                balance,
                signature,
            )
            .map_err(BridgeError::InvalidSignature)?;
        }
        Ok(FundChannelResult {
            channel_id: channel_id.to_string(),
            capacity,
            already_known,
        })
    }

    pub fn fund_channel_via_json(&self, json: &str) -> Result<FundChannelResult, BridgeError> {
        let p: Payment =
            serde_json::from_str(json).map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        self.fund_channel(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
        )
    }

    pub fn fund_channel_via_base64_header(
        &self,
        base64_header: &str,
    ) -> Result<FundChannelResult, BridgeError> {
        let p = Self::decode_payment_header(base64_header)?;
        self.fund_channel(
            &p.channel_id,
            p.balance,
            &p.signature,
            p.params.as_ref(),
            p.funding_proofs.as_deref(),
        )
    }

    pub(super) fn validate_and_save_new_channel(
        &self,
        channel_id: &str,
        params_val: &serde_json::Value,
        proofs: &[Proof],
        balance: u64,
        signature: &str,
    ) -> Result<ChannelFunding, BridgeError> {
        let unit = params_val["unit"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing unit".into()))?;
        let capacity = params_val["capacity"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("Missing capacity".into()))?;
        let expiry_timestamp =
            params_val["expiry_timestamp"]
                .as_u64()
                .ok_or(BridgeError::InvalidRequest(
                    "Missing expiry_timestamp".into(),
                ))?;
        let maximum_amount = params_val["maximum_amount"]
            .as_u64()
            .ok_or(BridgeError::InvalidRequest("Missing maximum_amount".into()))?;
        let receiver_pubkey_hex =
            params_val["receiver_pubkey"]
                .as_str()
                .ok_or(BridgeError::InvalidRequest(
                    "Missing receiver_pubkey".into(),
                ))?;
        let receiver_pubkey = PublicKey::from_hex(receiver_pubkey_hex)
            .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        if !self.host.receiver_key_is_acceptable(&receiver_pubkey) {
            return Err(BridgeError::ReceiverKeyNotAcceptable);
        }
        let sender_pubkey_hex = params_val["sender_pubkey"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing sender_pubkey".into()))?;
        let keyset_id = Id::from_str(
            params_val["keyset_id"]
                .as_str()
                .ok_or(BridgeError::InvalidRequest("Missing keyset_id".into()))?,
        )
        .map_err(|e| BridgeError::InvalidRequest(e.to_string()))?;
        let mint = params_val["mint"]
            .as_str()
            .ok_or(BridgeError::InvalidRequest("Missing mint".into()))?;
        if !self.host.mint_and_keyset_is_acceptable(mint, &keyset_id) {
            return Err(BridgeError::MintOrKeysetNotAcceptable);
        }
        let keyset_info_json = self
            .host
            .get_keyset_info(mint, &keyset_id)
            .ok_or(BridgeError::MintOrKeysetNotAcceptable)?;
        let policy = self
            .host
            .get_channel_policy(unit)
            .ok_or(BridgeError::UnsupportedUnit(unit.to_string()))?;
        if capacity < policy.min_capacity {
            return Err(BridgeError::CapacityTooSmall {
                capacity,
                min_capacity: policy.min_capacity,
            });
        }
        if let Some(max) = policy.max_amount_per_output {
            if max > 0 && maximum_amount > max {
                return Err(BridgeError::MaxAmountExceeded {
                    amount: maximum_amount,
                    max_allowed: max,
                });
            }
        }
        let now = self.host.now_seconds();
        let min_expiry = now.saturating_add(policy.min_expiry_in_seconds.max(1));
        if expiry_timestamp < min_expiry {
            return Err(BridgeError::ExpiryTooSoon {
                expiry_timestamp,
                min_expiry,
                now,
            });
        }
        if balance > capacity {
            return Err(BridgeError::BalanceExceedsCapacity { balance, capacity });
        }
        // Reject impossible funding before parameter construction expands the
        // claimed value into deterministic outputs. A tiny untrusted request
        // must not cause work proportional to an arbitrary declared amount.
        let keyset_info = crate::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(BridgeError::InvalidRequest)?;
        let funding_total = proofs.iter().try_fold(0u64, |total, proof| {
            let amount = u64::from(proof.amount);
            if amount == 0
                || proof.keyset_id != keyset_id
                || keyset_info.active_keys.amount_key(proof.amount).is_none()
                || (maximum_amount > 0 && amount > maximum_amount)
            {
                return Err(BridgeError::InvalidRequest(
                    "Invalid funding proof denomination or keyset".into(),
                ));
            }
            total.checked_add(amount).ok_or_else(|| {
                BridgeError::InvalidRequest("Cashu funding proof total overflow".into())
            })
        })?;
        if funding_total == 0 || Some(funding_total) != params_val["funding_token_amount"].as_u64()
        {
            return Err(BridgeError::InvalidRequest(
                "Cashu funding proof total does not match channel parameters".into(),
            ));
        }
        let channel_secret_hex = self
            .host
            .compute_channel_secret(receiver_pubkey_hex, sender_pubkey_hex)
            .map_err(BridgeError::ServerMisconfigured)?;
        let channel_secret: [u8; 32] = hex::decode(&channel_secret_hex)
            .map_err(|e| BridgeError::Internal(e.to_string()))?
            .try_into()
            .map_err(|_| BridgeError::Internal("Invalid secret length".into()))?;
        let params = ChannelParameters::from_json_with_channel_secret(
            &params_val.to_string(),
            keyset_info,
            channel_secret,
        )
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
        if params.get_channel_id() != channel_id {
            return Err(BridgeError::ChannelIdMismatch);
        }
        let verif = verify_valid_channel(proofs, &params);
        if !verif.valid {
            let errors_json =
                serde_json::to_string(&verif.errors).unwrap_or_else(|_| "[]".to_string());
            return Err(BridgeError::ValidationFailed(errors_json));
        }
        let proofs_json =
            serde_json::to_string(proofs).map_err(|e| BridgeError::Internal(e.to_string()))?;
        self.verify_signature(
            &params_val.to_string(),
            &proofs_json,
            &channel_secret_hex,
            &keyset_info_json,
            channel_id,
            balance,
            signature,
        )
        .map_err(BridgeError::InvalidSignature)?;
        let funding = ChannelFunding {
            params_json: params_val.to_string(),
            funding_proofs_json: proofs_json,
            channel_secret_hex,
            keyset_info_json,
        };
        self.host
            .save_funding(
                channel_id,
                funding.clone(),
                PaymentProof {
                    balance,
                    signature: signature.to_string(),
                },
            )
            .map_err(|e| BridgeError::Internal(format!("funding persistence failed: {e}")))?;
        Ok(funding)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_signature(
        &self,
        params_json: &str,
        proofs_json: &str,
        secret_hex: &str,
        keyset_json: &str,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<(), String> {
        let secret: [u8; 32] = hex::decode(secret_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "Invalid secret length")?;
        let params = ChannelParameters::from_json_with_channel_secret(
            params_json,
            crate::parse_keyset_info_from_json(keyset_json).map_err(|e| e.to_string())?,
            secret,
        )
        .map_err(|e| e.to_string())?;
        let channel = EstablishedChannel::new(
            params,
            serde_json::from_str(proofs_json).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if channel.params.get_channel_id() != channel_id {
            return Err("channel id does not match funding".to_string());
        }
        crate::balance_update::verify_sender_signature_bundle(&channel, balance, signature)
            .map(|_| ())
    }
}
