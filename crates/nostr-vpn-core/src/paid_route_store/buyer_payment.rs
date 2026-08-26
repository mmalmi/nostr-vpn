use super::{persistence::*, *};

impl PaidRouteStore {
    pub(super) fn attach_buyer_spilman_channel_inner(
        &mut self,
        request: AttachPaidRouteBuyerSpilmanChannelRequest,
    ) -> Result<AttachPaidRouteBuyerSpilmanChannelResult> {
        let session_id = trimmed_required(&request.session_id, "paid route session id")?;
        let channel_id = trimmed_required(&request.channel_id, "Cashu Spilman channel id")?;
        let unit = request.cashu_unit.trim();
        if unit.is_empty() {
            return Err(anyhow!("missing Cashu Spilman channel unit"));
        }
        if request.payment.channel_id.trim() != channel_id {
            return Err(anyhow!(
                "Cashu Spilman payment channel {} does not match attached channel {}",
                request.payment.channel_id,
                channel_id
            ));
        }
        let inferred_paid_msat = cashu_payment_balance_msat(unit, request.payment.balance)?;
        let paid_msat = request.paid_msat.unwrap_or(inferred_paid_msat);
        validate_cashu_spilman_payment_claim(
            &request.payment,
            &channel_id,
            unit,
            paid_msat,
            request.capacity_sat,
            true,
        )?;
        let session_record = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or_else(|| anyhow!("paid route buyer session {session_id} does not exist"))?;
        let lease_record = self
            .leases
            .get(&session_record.session.lease_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "paid route lease {} does not exist",
                    session_record.session.lease_id
                )
            })?;
        let previous_channel_id = session_record.session.payment.channel_id.clone();
        let mut channel = self
            .channels
            .remove(&previous_channel_id)
            .or_else(|| self.channels.remove(&channel_id))
            .ok_or_else(|| anyhow!("paid route channel {previous_channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {} is not a buyer channel",
                channel.channel_id
            ));
        }
        let offer = self.buyer_offer_for_session(&lease_record, &channel)?;
        validate_paid_route_payment_progress(
            "paid route payment",
            paid_msat,
            session_record.session.payment.paid_msat,
            request.capacity_sat,
        )?;
        let status = preserve_terminal_status(
            channel.status,
            initial_buyer_session_status(&offer, paid_msat),
        );
        let payment = PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: channel_id.to_string(),
            cashu_unit: unit.to_string(),
            capacity_sat: request.capacity_sat,
            paid_msat,
            updated_at_unix: request.now_unix,
            cashu_spilman_payment: Some(request.payment),
            cashu_token_lease: None,
        };

        channel.channel_id = channel_id.to_string();
        channel.status = status;
        channel.payment = payment.clone();
        channel.updated_at_unix = request.now_unix;
        self.channels.insert(channel_id.to_string(), channel);

        let mut session = session_record;
        session.session.payment = payment;
        session.updated_at_unix = request.now_unix;
        self.sessions.insert(session_id.clone(), session);

        if let Some(lease) = self.leases.get_mut(&lease_record.lease.lease_id) {
            lease.status = preserve_terminal_status(lease.status, status);
            lease.updated_at_unix = request.now_unix;
        }

        Ok(AttachPaidRouteBuyerSpilmanChannelResult {
            previous_channel_id,
            channel_id: channel_id.to_string(),
            session_id,
            lease_id: lease_record.lease.lease_id,
            paid_msat,
            changed: false,
        })
    }

    pub(super) fn buyer_payment_signing_plan(
        &self,
        request: &BuildPaidRouteBuyerSignedPaymentEnvelopeRequest,
    ) -> Result<PaidRouteBuyerPaymentSigningPlan> {
        let session_id = trimmed_required(&request.session_id, "paid route session id")?;
        let buyer_npub = normalize_paid_route_npub(&request.buyer_npub, "buyer")?;
        let session_record = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route buyer session {session_id} does not exist"))?;
        let lease_record = self
            .leases
            .get(&session_record.session.lease_id)
            .ok_or_else(|| {
                anyhow!(
                    "paid route lease {} does not exist",
                    session_record.session.lease_id
                )
            })?;
        let channel_id = session_record.session.payment.channel_id.clone();
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {channel_id} is not a buyer channel"
            ));
        }
        if normalize_paid_route_npub(&lease_record.lease.buyer_npub, "buyer")? != buyer_npub {
            return Err(anyhow!(
                "paid route payment buyer does not match lease buyer"
            ));
        }
        ensure_buyer_channel_accepts_payment(channel, lease_record, request.kind)?;

        let offer = self.buyer_offer_for_session(lease_record, channel)?;
        let config = PaidExitConfig::from_paid_route_offer(&offer);
        let current_units = session_record.session.usage.billable_bytes;
        let delivered_units = request.delivered_units.unwrap_or(current_units);
        if delivered_units < current_units {
            return Err(anyhow!(
                "paid route buyer payment delivered units regressed: {} < {}",
                delivered_units,
                current_units
            ));
        }

        let amount_due_msat = paid_route_amount_due_for_delivered_units(
            &config,
            &session_record.session.usage,
            delivered_units,
        );
        let previous_paid_msat = session_record.session.payment.paid_msat;
        let paid_msat = request
            .paid_msat
            .unwrap_or_else(|| previous_paid_msat.max(amount_due_msat));
        validate_paid_route_payment_progress(
            "paid route buyer payment",
            paid_msat,
            previous_paid_msat,
            session_record.session.payment.capacity_sat,
        )?;

        Ok(PaidRouteBuyerPaymentSigningPlan {
            channel_id,
            unit: paid_route_payment_cashu_unit(&session_record.session.payment),
            previous_paid_msat,
            capacity_sat: session_record.session.payment.capacity_sat,
            delivered_units,
            paid_msat,
        })
    }

    pub(super) fn build_buyer_payment_envelope_inner(
        &mut self,
        request: BuildPaidRouteBuyerPaymentEnvelopeRequest,
    ) -> Result<BuildPaidRouteBuyerPaymentEnvelopeResult> {
        let session_id = trimmed_required(&request.session_id, "paid route session id")?;
        let buyer_npub = normalize_paid_route_npub(&request.buyer_npub, "buyer")?;
        let session_record = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or_else(|| anyhow!("paid route buyer session {session_id} does not exist"))?;
        let lease_record = self
            .leases
            .get(&session_record.session.lease_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "paid route lease {} does not exist",
                    session_record.session.lease_id
                )
            })?;
        let channel_id = session_record.session.payment.channel_id.clone();
        let channel = self
            .channels
            .get(&channel_id)
            .cloned()
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {channel_id} is not a buyer channel"
            ));
        }
        if normalize_paid_route_npub(&lease_record.lease.buyer_npub, "buyer")? != buyer_npub {
            return Err(anyhow!(
                "paid route payment buyer does not match lease buyer"
            ));
        }
        if request.payment.channel_id.trim() != channel_id {
            return Err(anyhow!(
                "paid route payment channel {} does not match session channel {}",
                request.payment.channel_id,
                channel_id
            ));
        }
        ensure_buyer_channel_accepts_payment(&channel, &lease_record, request.kind)?;

        let offer = self.buyer_offer_for_session(&lease_record, &channel)?;
        let config = PaidExitConfig::from_paid_route_offer(&offer);
        let unit = paid_route_payment_cashu_unit(&session_record.session.payment);
        let current_units = session_record.session.usage.billable_bytes;
        let delivered_units = request.delivered_units.unwrap_or(current_units);
        if delivered_units < current_units {
            return Err(anyhow!(
                "paid route buyer payment delivered units regressed: {} < {}",
                delivered_units,
                current_units
            ));
        }
        let inferred_paid_msat = cashu_payment_balance_msat(&unit, request.payment.balance)?;
        let paid_msat = request.paid_msat.unwrap_or(inferred_paid_msat);
        validate_paid_route_payment_progress(
            "paid route buyer payment",
            paid_msat,
            session_record.session.payment.paid_msat,
            session_record.session.payment.capacity_sat,
        )?;
        validate_cashu_spilman_payment_claim(
            &request.payment,
            &channel_id,
            &unit,
            paid_msat,
            session_record.session.payment.capacity_sat,
            request.kind == BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
        )?;

        let amount_due_msat = paid_route_amount_due_for_delivered_units(
            &config,
            &session_record.session.usage,
            delivered_units,
        );
        let expires_at_unix = channel
            .expires_at_unix
            .min(lease_record.lease.expires_at_unix);
        let payload = match request.kind {
            BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen => {
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: channel.mint_url.clone(),
                    unit: unit.clone(),
                    capacity: cashu_channel_capacity_for_unit(
                        session_record.session.payment.capacity_sat,
                        &unit,
                    )?,
                    expires_unix: expires_at_unix,
                    receiver_pubkey_hex: self
                        .quotes
                        .get(&lease_record.lease.quote_id)
                        .map(|record| record.quote.receiver_pubkey_hex.clone())
                        .unwrap_or_else(|| {
                            normalize_nostr_pubkey(&offer.seller_npub).unwrap_or_default()
                        }),
                    paid_msat,
                    payment: request.payment.clone(),
                })
            }
            BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate => {
                StreamingRoutePaymentPayload::BalanceUpdate(StreamingRouteBalanceUpdate {
                    delivered_units,
                    amount_due_msat,
                    paid_msat,
                    payment: request.payment.clone(),
                })
            }
            BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose => {
                StreamingRoutePaymentPayload::CooperativeClose(StreamingRouteCooperativeClose {
                    final_paid_msat: paid_msat,
                    payment: request.payment.clone(),
                })
            }
        };
        let payload_type = request.kind.as_str().to_string();

        self.apply_buyer_payment_state(
            &BuyerPaymentApplyContext {
                session_id: &session_id,
                channel_id: &channel_id,
                lease_id: &lease_record.lease.lease_id,
                kind: request.kind,
                delivered_units,
                paid_msat,
                unit: &unit,
                now_unix: request.now_unix,
            },
            request.payment.clone(),
        )?;

        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} was not updated"))?;
        let decision = session.session.routing_decision(&config);
        let envelope = StreamingRoutePaymentEnvelope::new(
            offer.offer_id.clone(),
            lease_record.lease.lease_id.clone(),
            buyer_npub.clone(),
            offer.seller_npub.clone(),
            request.now_unix,
            payload,
        );

        Ok(BuildPaidRouteBuyerPaymentEnvelopeResult {
            envelope,
            session_id,
            lease_id: lease_record.lease.lease_id,
            channel_id,
            offer_id: offer.offer_id,
            buyer_npub,
            seller_npub: offer.seller_npub,
            payload_type,
            paid_msat,
            delivered_units: decision.delivered_units,
            amount_due_msat: decision.amount_due_msat,
            unpaid_msat: decision.unpaid_msat,
            allow_routing: decision.allow_routing,
            state: decision.state,
            changed: false,
        })
    }

    pub(super) fn build_buyer_token_lease_envelope_inner(
        &mut self,
        request: BuildPaidRouteBuyerTokenLeaseEnvelopeRequest,
    ) -> Result<BuildPaidRouteBuyerPaymentEnvelopeResult> {
        let session_id = trimmed_required(&request.session_id, "paid route session id")?;
        let buyer_npub = normalize_paid_route_npub(&request.buyer_npub, "buyer")?;
        let session_record = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or_else(|| anyhow!("paid route buyer session {session_id} does not exist"))?;
        let lease_record = self
            .leases
            .get(&session_record.session.lease_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "paid route lease {} does not exist",
                    session_record.session.lease_id
                )
            })?;
        let channel_id = session_record.session.payment.channel_id.clone();
        let channel = self
            .channels
            .get(&channel_id)
            .cloned()
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {channel_id} is not a buyer channel"
            ));
        }
        if normalize_paid_route_npub(&lease_record.lease.buyer_npub, "buyer")? != buyer_npub {
            return Err(anyhow!(
                "paid route payment buyer does not match lease buyer"
            ));
        }
        ensure_open_buyer_channel(&channel, &lease_record)?;

        let offer = self.buyer_offer_for_session(&lease_record, &channel)?;
        let config = PaidExitConfig::from_paid_route_offer(&offer);
        let mint_url = if request.mint_url.trim().is_empty() {
            channel.mint_url.clone()
        } else {
            request.mint_url.trim().to_string()
        };
        let cashu_unit = if request.cashu_unit.trim().is_empty() {
            "sat".to_string()
        } else {
            request.cashu_unit.trim().to_string()
        };
        let expires_at_unix = request.expires_at_unix.unwrap_or_else(|| {
            channel
                .expires_at_unix
                .min(lease_record.lease.expires_at_unix)
        });
        if expires_at_unix <= request.now_unix {
            return Err(anyhow!("paid route token lease is already expired"));
        }
        let token_lease =
            create_streaming_route_cashu_token_lease(StreamingRouteCashuTokenLeaseRequest {
                channel_id: channel_id.clone(),
                mint_url,
                unit: cashu_unit,
                amount: request.amount,
                paid_msat: request.paid_msat,
                expires_unix: expires_at_unix,
                token: request.token.clone(),
            })
            .map_err(|error| anyhow!("{error}"))?;
        validate_paid_route_payment_progress(
            "paid route token lease",
            token_lease.paid_msat,
            session_record.session.payment.paid_msat,
            session_record.session.payment.capacity_sat,
        )?;
        let capacity_sat = paid_route_channel_capacity_sat(&token_lease.unit, token_lease.amount)?;
        let status = preserve_terminal_status(
            channel.status,
            initial_buyer_session_status(&offer, token_lease.paid_msat),
        );
        let payment = PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuTokenLease,
            channel_id: channel_id.clone(),
            cashu_unit: token_lease.unit.clone(),
            capacity_sat,
            paid_msat: token_lease.paid_msat,
            updated_at_unix: request.now_unix,
            cashu_spilman_payment: None,
            cashu_token_lease: Some(token_lease.clone()),
        };

        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.status = status;
            channel.payment = payment.clone();
            channel.mint_url = token_lease.mint_url.clone();
            channel.updated_at_unix = request.now_unix;
        }
        if let Some(lease) = self.leases.get_mut(&lease_record.lease.lease_id) {
            lease.status = preserve_terminal_status(lease.status, status);
            lease.updated_at_unix = request.now_unix;
        }
        {
            let record = self
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| anyhow!("paid route session {session_id} does not exist"))?;
            record.session.payment = payment;
            record.updated_at_unix = request.now_unix;
        }

        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} was not updated"))?;
        let decision = session.session.routing_decision(&config);
        let envelope = StreamingRoutePaymentEnvelope::new(
            offer.offer_id.clone(),
            lease_record.lease.lease_id.clone(),
            buyer_npub.clone(),
            offer.seller_npub.clone(),
            request.now_unix,
            StreamingRoutePaymentPayload::CashuTokenLease(token_lease),
        );

        Ok(BuildPaidRouteBuyerPaymentEnvelopeResult {
            envelope,
            session_id,
            lease_id: lease_record.lease.lease_id,
            channel_id,
            offer_id: offer.offer_id,
            buyer_npub,
            seller_npub: offer.seller_npub,
            payload_type: "cashu_token_lease".to_string(),
            paid_msat: decision.paid_msat,
            delivered_units: decision.delivered_units,
            amount_due_msat: decision.amount_due_msat,
            unpaid_msat: decision.unpaid_msat,
            allow_routing: decision.allow_routing,
            state: decision.state,
            changed: false,
        })
    }

    pub(super) fn apply_buyer_payment_state(
        &mut self,
        context: &BuyerPaymentApplyContext<'_>,
        payment: CashuSpilmanPayment,
    ) -> Result<()> {
        let previous_payment = self
            .sessions
            .get(context.session_id)
            .and_then(|record| record.session.payment.cashu_spilman_payment.as_ref())
            .or_else(|| {
                self.channels
                    .get(context.channel_id)
                    .and_then(|channel| channel.payment.cashu_spilman_payment.as_ref())
            });
        let mut stored_payment = payment;
        if let Some(previous) =
            previous_payment.filter(|previous| previous.channel_id == stored_payment.channel_id)
        {
            if stored_payment.params.is_none() {
                stored_payment.params = previous.params.clone();
            }
            if stored_payment.funding_proofs.is_none() {
                stored_payment.funding_proofs = previous.funding_proofs.clone();
            }
        }
        if let Some(channel) = self.channels.get_mut(context.channel_id) {
            channel.payment.cashu_unit = context.unit.to_string();
            channel.payment.paid_msat = context.paid_msat;
            channel.payment.updated_at_unix = context.now_unix;
            channel.payment.cashu_spilman_payment = Some(stored_payment.clone());
            channel.payment.cashu_token_lease = None;
            channel.updated_at_unix = context.now_unix;
            if context.kind == BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose {
                channel.status = PaidRouteLifecycleStatus::Closing;
            }
        }
        if context.kind == BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose
            && let Some(lease) = self.leases.get_mut(context.lease_id)
        {
            lease.status = PaidRouteLifecycleStatus::Closing;
            lease.updated_at_unix = context.now_unix;
        }
        let record = self
            .sessions
            .get_mut(context.session_id)
            .ok_or_else(|| anyhow!("paid route session {} does not exist", context.session_id))?;
        apply_delivered_bytes(&mut record.session.usage, context.delivered_units);
        record.session.payment.cashu_unit = context.unit.to_string();
        record.session.payment.paid_msat = context.paid_msat;
        record.session.payment.updated_at_unix = context.now_unix;
        record.session.payment.cashu_spilman_payment = Some(stored_payment);
        record.session.payment.cashu_token_lease = None;
        record.updated_at_unix = context.now_unix;
        Ok(())
    }

    pub(super) fn buyer_offer_for_session(
        &self,
        lease_record: &PaidRouteLeaseRecord,
        channel: &PaidRouteChannelRecord,
    ) -> Result<PaidRouteOffer> {
        if channel.role != PaidRouteChannelRole::Buyer
            || channel.offer_id != lease_record.lease.offer_id
        {
            return Err(anyhow!("paid route buyer channel does not match its lease"));
        }
        let terms = channel.accepted_terms.as_ref().ok_or_else(|| {
            anyhow!(
                "paid route buyer channel {} has no accepted terms",
                channel.channel_id
            )
        })?;
        if !terms.enabled {
            return Err(anyhow!(
                "paid route buyer channel {} has disabled accepted terms",
                channel.channel_id
            ));
        }
        let seller_npub = normalize_paid_route_npub(&channel.counterparty_npub, "seller")?;
        Ok(PaidRouteOffer::from_paid_exit_config(
            lease_record.lease.offer_id.clone(),
            seller_npub,
            terms,
            None,
        ))
    }

    pub(super) fn buyer_usage_session_for_seller(
        &self,
        seller_npub: &str,
        now_unix: u64,
    ) -> Option<PaidRouteBuyerUsageSession> {
        let mut best = None::<(u64, PaidRouteBuyerUsageSession)>;
        for record in self.sessions.values() {
            let Some(lease_record) = self.leases.get(&record.session.lease_id) else {
                continue;
            };
            let Some(channel) = self.channels.get(&record.session.payment.channel_id) else {
                continue;
            };
            if channel.role != PaidRouteChannelRole::Buyer {
                continue;
            }
            if !paid_route_lifecycle_allows_routing(lease_record.status)
                || !paid_route_lifecycle_allows_routing(channel.status)
            {
                continue;
            }
            if lease_record
                .lease
                .expires_at_unix
                .min(channel.expires_at_unix)
                <= now_unix
            {
                continue;
            }
            let Some(channel_seller_npub) =
                normalize_paid_route_npub(&channel.counterparty_npub, "seller").ok()
            else {
                continue;
            };
            if channel_seller_npub != seller_npub {
                continue;
            }
            let Some(offer) = self.buyer_offer_for_session(lease_record, channel).ok() else {
                continue;
            };
            let Some(offer_seller_npub) =
                normalize_paid_route_npub(&offer.seller_npub, "seller").ok()
            else {
                continue;
            };
            if offer_seller_npub != seller_npub {
                continue;
            }
            let Some(seller_pubkey) = normalize_nostr_pubkey(&offer_seller_npub).ok() else {
                continue;
            };
            let updated_at = record.updated_at_unix.max(channel.updated_at_unix);
            let candidate = PaidRouteBuyerUsageSession {
                seller_pubkey,
                seller_npub: offer_seller_npub,
                session_id: record.session.session_id.clone(),
                lease_id: lease_record.lease.lease_id.clone(),
                channel_id: channel.channel_id.clone(),
                config: PaidExitConfig::from_paid_route_offer(&offer),
            };
            if best
                .as_ref()
                .is_none_or(|(best_updated_at, _)| updated_at > *best_updated_at)
            {
                best = Some((updated_at, candidate));
            }
        }
        best.map(|(_, candidate)| candidate)
    }
}
