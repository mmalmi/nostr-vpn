use super::{persistence::*, *};

impl PaidRouteStore {
    pub fn apply_seller_payment(
        &mut self,
        request: ApplyPaidRouteSellerPaymentRequest,
    ) -> Result<ApplyPaidRouteSellerPaymentResult> {
        let before = self.clone();
        let mut next = before.clone();
        let mut result = next.apply_seller_payment_inner(request)?;
        result.changed = next != before;
        *self = next;
        Ok(result)
    }

    pub fn apply_seller_payment_with_spilman_receiver<R, C>(
        &mut self,
        request: ApplyPaidRouteSellerPaymentRequest,
        receiver: &R,
        context: &C,
    ) -> Result<ApplyPaidRouteSellerPaymentResult>
    where
        R: CashuSpilmanPaymentReceiver<C>,
    {
        let before = self.clone();
        let mut next = before.clone();
        let repairs_pending_close = matches!(
            &request.envelope.payload,
            StreamingRoutePaymentPayload::CooperativeClose(_)
        );
        let mut result = next.apply_seller_payment_inner(request.clone())?;
        result.changed = next != before;
        if !result.changed && !repairs_pending_close {
            return Ok(result);
        }
        next.process_seller_spilman_receiver_payment(&request, receiver, context)?;
        *self = next;
        Ok(result)
    }

    pub(super) fn process_seller_spilman_receiver_payment<R, C>(
        &self,
        request: &ApplyPaidRouteSellerPaymentRequest,
        receiver: &R,
        context: &C,
    ) -> Result<()>
    where
        R: CashuSpilmanPaymentReceiver<C>,
    {
        let envelope = &request.envelope;
        if envelope.version != STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION {
            return Err(anyhow!(
                "unsupported paid route payment protocol version {}",
                envelope.version
            ));
        }

        let seller_npub = normalize_paid_route_npub(&request.seller_npub, "seller")?;
        let envelope_seller = normalize_paid_route_npub(&envelope.seller, "seller")?;
        if envelope_seller != seller_npub {
            return Err(anyhow!(
                "paid route payment seller does not match local seller"
            ));
        }
        let seller_pubkey_hex = normalize_nostr_pubkey(&seller_npub)?;
        let buyer_npub = normalize_paid_route_npub(&envelope.buyer, "buyer")?;
        let service_id = trimmed_required(&envelope.service_id, "paid route service id")?;
        let lease_id = trimmed_required(&envelope.lease_id, "paid route lease id")?;
        let channel_id = trimmed_required(envelope.channel_id(), "paid route channel id")?;
        let config = accepted_channel_terms(
            self.channels
                .get(&channel_id)
                .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?,
            PaidRouteChannelRole::Seller,
        )?;

        match &envelope.payload {
            StreamingRoutePaymentPayload::ChannelOpen(open) => {
                validate_seller_open_payment(config, &seller_pubkey_hex, &channel_id, open)?;
                let capacity_sat = paid_route_channel_capacity_sat(&open.unit, open.capacity)?;
                process_streaming_route_cashu_payment_with_receiver(
                    receiver,
                    &open.payment,
                    &channel_id,
                    &open.unit,
                    open.paid_msat,
                    capacity_sat,
                    true,
                    context,
                )
                .map_err(|error| anyhow!("{error}"))?;
            }
            StreamingRoutePaymentPayload::BalanceUpdate(update) => {
                self.ensure_existing_seller_session(
                    &service_id,
                    &lease_id,
                    &channel_id,
                    &buyer_npub,
                    false,
                )?;
                let channel = self.channels.get(&channel_id).expect("validated channel");
                let cashu_unit = paid_route_payment_cashu_unit(&channel.payment);
                process_streaming_route_cashu_payment_with_receiver(
                    receiver,
                    &update.payment,
                    &channel_id,
                    &cashu_unit,
                    update.paid_msat,
                    channel.payment.capacity_sat,
                    false,
                    context,
                )
                .map_err(|error| anyhow!("{error}"))?;
            }
            StreamingRoutePaymentPayload::CooperativeClose(close) => {
                let lease = self
                    .leases
                    .get(&lease_id)
                    .ok_or_else(|| anyhow!("paid route lease {lease_id} does not exist"))?;
                if lease.lease.offer_id != service_id
                    || normalize_paid_route_npub(&lease.lease.buyer_npub, "buyer")? != buyer_npub
                {
                    return Err(anyhow!(
                        "paid route close does not match existing seller lease"
                    ));
                }
                let channel = self
                    .channels
                    .get(&channel_id)
                    .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
                ensure_seller_channel_matches(channel, &service_id, &buyer_npub)?;
                let cashu_unit = paid_route_payment_cashu_unit(&channel.payment);
                process_streaming_route_cashu_payment_with_receiver(
                    receiver,
                    &close.payment,
                    &channel_id,
                    &cashu_unit,
                    close.final_paid_msat,
                    channel.payment.capacity_sat,
                    false,
                    context,
                )
                .map_err(|error| anyhow!("{error}"))?;
            }
            StreamingRoutePaymentPayload::CashuTokenLease(_)
            | StreamingRoutePaymentPayload::CooperativeCloseAck(_) => {}
        }

        Ok(())
    }

    pub(super) fn apply_seller_payment_inner(
        &mut self,
        request: ApplyPaidRouteSellerPaymentRequest,
    ) -> Result<ApplyPaidRouteSellerPaymentResult> {
        let mut config = request.config;
        config.normalize();
        let envelope = request.envelope;
        if envelope.version != STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION {
            return Err(anyhow!(
                "unsupported paid route payment protocol version {}",
                envelope.version
            ));
        }

        let seller_npub = normalize_paid_route_npub(&request.seller_npub, "seller")?;
        let envelope_seller = normalize_paid_route_npub(&envelope.seller, "seller")?;
        if envelope_seller != seller_npub {
            return Err(anyhow!(
                "paid route payment seller does not match local seller"
            ));
        }
        let seller_pubkey_hex = normalize_nostr_pubkey(&seller_npub)?;
        let buyer_npub = normalize_paid_route_npub(&envelope.buyer, "buyer")?;
        let service_id = trimmed_required(&envelope.service_id, "paid route service id")?;
        let lease_id = trimmed_required(&envelope.lease_id, "paid route lease id")?;
        let channel_id = trimmed_required(envelope.channel_id(), "paid route channel id")?;
        let accepted_terms =
            self.seller_payment_accepted_terms(&service_id, &lease_id, &channel_id, &buyer_npub)?;
        if accepted_terms.is_none() && !config.enabled {
            return Err(anyhow!("paid exit selling is disabled"));
        }
        let config = accepted_terms.unwrap_or(config);
        let payload_type = paid_route_payment_payload_type(&envelope.payload).to_string();
        let apply_context = SellerPaymentApplyContext {
            config: &config,
            service_id: &service_id,
            lease_id: &lease_id,
            channel_id: &channel_id,
            buyer_npub: &buyer_npub,
            now_unix: request.now_unix,
        };

        let already_applied = self.channels.get(&channel_id).is_some_and(|channel| {
            channel.offer_id == service_id
                && normalize_paid_route_npub(&channel.counterparty_npub, "buyer")
                    .is_ok_and(|counterparty| counterparty == buyer_npub)
                && match &envelope.payload {
                    StreamingRoutePaymentPayload::ChannelOpen(open) => {
                        channel.payment.paid_msat == open.paid_msat
                            && channel.payment.cashu_spilman_payment.as_ref() == Some(&open.payment)
                    }
                    StreamingRoutePaymentPayload::BalanceUpdate(update) => {
                        channel.payment.paid_msat == update.paid_msat
                            && channel.payment.cashu_spilman_payment.as_ref()
                                == Some(&update.payment)
                    }
                    StreamingRoutePaymentPayload::CooperativeClose(close) => {
                        channel.status == PaidRouteLifecycleStatus::Closing
                            && channel.payment.paid_msat == close.final_paid_msat
                            && channel.payment.cashu_spilman_payment.as_ref()
                                == Some(&close.payment)
                    }
                    StreamingRoutePaymentPayload::CashuTokenLease(_)
                    | StreamingRoutePaymentPayload::CooperativeCloseAck(_) => false,
                }
        });

        if !already_applied {
            match &envelope.payload {
                StreamingRoutePaymentPayload::ChannelOpen(open) => {
                    validate_seller_open_payment(&config, &seller_pubkey_hex, &channel_id, open)?;
                    let capacity_sat = paid_route_channel_capacity_sat(&open.unit, open.capacity)?;
                    self.apply_seller_channel_open(&apply_context, open, capacity_sat)?;
                }
                StreamingRoutePaymentPayload::BalanceUpdate(update) => {
                    self.apply_seller_balance_update(&apply_context, update)?;
                }
                StreamingRoutePaymentPayload::CooperativeClose(close) => {
                    self.apply_seller_cooperative_close(
                        &apply_context,
                        close.final_paid_msat,
                        &close.payment,
                    )?;
                }
                StreamingRoutePaymentPayload::CashuTokenLease(token_lease) => {
                    validate_seller_token_lease(&config, token_lease, request.now_unix)?;
                    return Err(anyhow!(
                        "paid route Cashu token leases require seller-side token redemption before routing; use Cashu Spilman channel payments"
                    ));
                }
                StreamingRoutePaymentPayload::CooperativeCloseAck(_) => {
                    return Err(anyhow!(
                        "seller cannot apply paid route cooperative close ack from buyer"
                    ));
                }
            }
        }

        let session_id = seller_session_id_for_lease(&lease_id);
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} was not created"))?;
        let decision = session.session.routing_decision(&config);
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or_else(|| anyhow!("paid route channel {channel_id} was not created"))?;
        let lease = self
            .leases
            .get(&lease_id)
            .ok_or_else(|| anyhow!("paid route lease {lease_id} was not created"))?;
        let expires_at_unix = channel.expires_at_unix.min(lease.lease.expires_at_unix);
        let lifecycle_allows = paid_route_lifecycle_allows_routing(channel.status)
            && paid_route_lifecycle_allows_routing(lease.status);
        let allow_routing =
            lifecycle_allows && expires_at_unix > request.now_unix && decision.allow_routing;
        let state = if allow_routing {
            decision.state
        } else {
            PaidRouteAccessState::Suspended
        };

        Ok(ApplyPaidRouteSellerPaymentResult {
            service_id,
            lease_id,
            channel_id,
            session_id,
            buyer_npub,
            seller_npub,
            payload_type,
            paid_msat: session.session.payment.paid_msat,
            delivered_units: decision.delivered_units,
            amount_due_msat: decision.amount_due_msat,
            unpaid_msat: decision.unpaid_msat,
            allow_routing,
            state,
            changed: false,
        })
    }

    pub(super) fn apply_seller_channel_open(
        &mut self,
        context: &SellerPaymentApplyContext<'_>,
        open: &cashu_service::StreamingRouteChannelOpen,
        capacity_sat: u64,
    ) -> Result<()> {
        self.replace_seller_probe_channel_for_payment(
            context.service_id,
            context.lease_id,
            context.channel_id,
            context.buyer_npub,
        )?;
        self.ensure_seller_lease_slot_available(
            context.service_id,
            context.lease_id,
            context.channel_id,
            context.buyer_npub,
        )?;
        let existing_channel_payment = self
            .channels
            .get(context.channel_id)
            .map(|channel| {
                ensure_seller_channel_matches(channel, context.service_id, context.buyer_npub)?;
                Ok::<u64, anyhow::Error>(channel.payment.paid_msat)
            })
            .transpose()?
            .unwrap_or(0);
        let accepted_terms = match self.channels.get(context.channel_id) {
            Some(channel) => accepted_channel_terms(channel, PaidRouteChannelRole::Seller)?.clone(),
            None => context.config.clone(),
        };
        let paid_msat = existing_channel_payment.max(open.paid_msat);
        let status = initial_seller_session_status(context.config, paid_msat);
        let expires_at_unix = seller_channel_open_expiry(
            context.now_unix,
            context.config.channel.channel_expiry_secs,
            open.expires_unix,
        )?;
        let quote_id = seller_quote_id_for_lease(context.lease_id);
        let session_id = seller_session_id_for_lease(context.lease_id);
        let payment = PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: context.channel_id.to_string(),
            cashu_unit: open.unit.trim().to_string(),
            capacity_sat,
            paid_msat,
            updated_at_unix: context.now_unix,
            cashu_spilman_payment: Some(open.payment.clone()),
            cashu_token_lease: None,
        };

        self.upsert_quote(
            PaidRouteQuote {
                quote_id: quote_id.clone(),
                offer_id: context.service_id.to_string(),
                payment_mode: PaidRoutePaymentMode::CashuSpilman,
                channel_capacity_sat: capacity_sat,
                expires_at_unix,
                receiver_pubkey_hex: open.receiver_pubkey_hex.trim().to_string(),
            },
            context.now_unix,
        );
        self.upsert_lease(
            PaidRouteLease {
                lease_id: context.lease_id.to_string(),
                offer_id: context.service_id.to_string(),
                quote_id: quote_id.clone(),
                buyer_npub: context.buyer_npub.to_string(),
                starts_at_unix: context.now_unix,
                expires_at_unix,
            },
            status,
            context.now_unix,
        );

        let created_at_unix = self
            .channels
            .get(context.channel_id)
            .map(|channel| channel.created_at_unix)
            .unwrap_or(context.now_unix);
        let channel_status = self
            .channels
            .get(context.channel_id)
            .map(|channel| preserve_terminal_status(channel.status, status))
            .unwrap_or(status);
        self.upsert_channel(PaidRouteChannelRecord {
            channel_id: context.channel_id.to_string(),
            offer_id: context.service_id.to_string(),
            role: PaidRouteChannelRole::Seller,
            status: channel_status,
            payment: payment.clone(),
            accepted_terms: Some(accepted_terms),
            mint_url: open.mint_url.trim().to_string(),
            counterparty_npub: context.buyer_npub.to_string(),
            created_at_unix,
            expires_at_unix,
            updated_at_unix: context.now_unix,
            error: String::new(),
        });

        if let Some(record) = self.sessions.get_mut(&session_id) {
            record.session.payment = payment;
            record.updated_at_unix = context.now_unix;
        } else {
            self.upsert_session(
                PaidRouteSession {
                    session_id,
                    lease_id: context.lease_id.to_string(),
                    usage: PaidRouteUsage::default(),
                    payment,
                    realized_exit_ip: None,
                    observed_country_code: None,
                    observed_asn: None,
                    quality: None,
                },
                context.now_unix,
            );
        }

        Ok(())
    }

    pub(super) fn apply_seller_balance_update(
        &mut self,
        context: &SellerPaymentApplyContext<'_>,
        update: &cashu_service::StreamingRouteBalanceUpdate,
    ) -> Result<()> {
        let session_id = seller_session_id_for_lease(context.lease_id);
        self.ensure_existing_seller_session(
            context.service_id,
            context.lease_id,
            context.channel_id,
            context.buyer_npub,
            false,
        )?;
        if !self.sessions.contains_key(&session_id) {
            return Err(anyhow!("paid route session {session_id} does not exist"));
        }
        let (cashu_unit, capacity_sat) = {
            let channel = self
                .channels
                .get(context.channel_id)
                .expect("validated channel");
            (
                paid_route_payment_cashu_unit(&channel.payment),
                channel.payment.capacity_sat,
            )
        };
        validate_streaming_route_cashu_payment_claim(
            &update.payment,
            context.channel_id,
            &cashu_unit,
            update.paid_msat,
            capacity_sat,
            false,
        )
        .map_err(|error| anyhow!("{error}"))?;
        let current_units = self.sessions[&session_id].session.usage.billable_bytes;
        // Buyer and seller usage flushes are independent; keep seller-observed
        // usage authoritative. The buyer's delivered_units/amount_due_msat can
        // explain the signed balance update, but they must not inflate or gate
        // seller billing. A lagging update is still useful partial credit; the
        // admission decision below is based on seller-computed unpaid balance.
        let effective_delivered_units = current_units;
        let current_paid = self.sessions[&session_id].session.payment.paid_msat;
        validate_paid_route_payment_progress(
            "paid route balance update",
            update.paid_msat,
            current_paid,
            capacity_sat,
        )?;

        let status = initial_seller_session_status(context.config, update.paid_msat);
        {
            let channel = self
                .channels
                .get_mut(context.channel_id)
                .expect("validated channel");
            channel.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            channel.payment.paid_msat = update.paid_msat;
            channel.payment.updated_at_unix = context.now_unix;
            channel.payment.cashu_spilman_payment = Some(update.payment.clone());
            channel.payment.cashu_token_lease = None;
            channel.status = preserve_terminal_status(channel.status, status);
            channel.updated_at_unix = context.now_unix;
        }
        if let Some(lease) = self.leases.get_mut(context.lease_id) {
            lease.status = preserve_terminal_status(lease.status, status);
            lease.updated_at_unix = context.now_unix;
        }
        {
            let record = self
                .sessions
                .get_mut(&session_id)
                .expect("validated session");
            apply_delivered_bytes(&mut record.session.usage, effective_delivered_units);
            record.session.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            record.session.payment.paid_msat = update.paid_msat;
            record.session.payment.updated_at_unix = context.now_unix;
            record.session.payment.cashu_spilman_payment = Some(update.payment.clone());
            record.session.payment.cashu_token_lease = None;
            record.updated_at_unix = context.now_unix;
        }

        Ok(())
    }

    pub(super) fn apply_seller_cooperative_close(
        &mut self,
        context: &SellerPaymentApplyContext<'_>,
        final_paid_msat: u64,
        payment: &CashuSpilmanPayment,
    ) -> Result<()> {
        let session_id = seller_session_id_for_lease(context.lease_id);
        self.ensure_existing_seller_session(
            context.service_id,
            context.lease_id,
            context.channel_id,
            context.buyer_npub,
            true,
        )?;
        let (cashu_unit, capacity_sat) = {
            let channel = self
                .channels
                .get(context.channel_id)
                .expect("validated channel");
            (
                paid_route_payment_cashu_unit(&channel.payment),
                channel.payment.capacity_sat,
            )
        };
        validate_streaming_route_cashu_payment_claim(
            payment,
            context.channel_id,
            &cashu_unit,
            final_paid_msat,
            capacity_sat,
            false,
        )
        .map_err(|error| anyhow!("{error}"))?;
        let current_paid = self.sessions[&session_id].session.payment.paid_msat;
        validate_paid_route_payment_progress(
            "paid route close",
            final_paid_msat,
            current_paid,
            capacity_sat,
        )?;
        let session_usage = self.sessions[&session_id].session.usage.clone();
        let computed_due = context
            .config
            .amount_due_msat(&session_usage)
            .min(capacity_sat.saturating_mul(1_000));
        if final_paid_msat < computed_due {
            return Err(anyhow!(
                "paid route close underpays amount due: {} msat < {} msat",
                final_paid_msat,
                computed_due
            ));
        }

        {
            let channel = self
                .channels
                .get_mut(context.channel_id)
                .expect("validated channel");
            channel.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            channel.payment.paid_msat = final_paid_msat;
            channel.payment.updated_at_unix = context.now_unix;
            channel.payment.cashu_spilman_payment = Some(payment.clone());
            channel.payment.cashu_token_lease = None;
            channel.status = PaidRouteLifecycleStatus::Closing;
            channel.updated_at_unix = context.now_unix;
        }
        if let Some(lease) = self.leases.get_mut(context.lease_id) {
            lease.status = PaidRouteLifecycleStatus::Closing;
            lease.updated_at_unix = context.now_unix;
        }
        {
            let record = self
                .sessions
                .get_mut(&session_id)
                .expect("validated session");
            record.session.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            record.session.payment.paid_msat = final_paid_msat;
            record.session.payment.updated_at_unix = context.now_unix;
            record.session.payment.cashu_spilman_payment = Some(payment.clone());
            record.session.payment.cashu_token_lease = None;
            record.updated_at_unix = context.now_unix;
        }

        Ok(())
    }

    pub(super) fn ensure_seller_lease_slot_available(
        &self,
        service_id: &str,
        lease_id: &str,
        channel_id: &str,
        buyer_npub: &str,
    ) -> Result<()> {
        let expected_quote_id = seller_quote_id_for_lease(lease_id);
        let expected_session_id = seller_session_id_for_lease(lease_id);

        if let Some(quote) = self.quotes.get(&expected_quote_id)
            && quote.quote.offer_id != service_id
        {
            return Err(anyhow!(
                "paid route lease {lease_id} quote belongs to service {}, not {}",
                quote.quote.offer_id,
                service_id
            ));
        }

        if let Some(lease) = self.leases.get(lease_id) {
            if lease.lease.offer_id != service_id {
                return Err(anyhow!(
                    "paid route lease {} belongs to service {}, not {}",
                    lease_id,
                    lease.lease.offer_id,
                    service_id
                ));
            }
            if lease.lease.quote_id != expected_quote_id {
                return Err(anyhow!(
                    "paid route lease {lease_id} does not match expected seller quote"
                ));
            }
            if normalize_paid_route_npub(&lease.lease.buyer_npub, "buyer")? != buyer_npub {
                return Err(anyhow!(
                    "paid route payment buyer does not match existing lease buyer"
                ));
            }
        }

        if let Some(session) = self.sessions.get(&expected_session_id) {
            if session.session.lease_id != lease_id {
                return Err(anyhow!(
                    "paid route session {expected_session_id} does not match lease"
                ));
            }
            if session.session.payment.channel_id != channel_id {
                return Err(anyhow!(
                    "paid route lease {lease_id} is already bound to channel {}, not {}",
                    session.session.payment.channel_id,
                    channel_id
                ));
            }
        } else if self.leases.contains_key(lease_id) {
            return Err(anyhow!(
                "paid route lease {lease_id} already exists without a matching seller session"
            ));
        }

        for record in self.sessions.values() {
            if record.session.payment.channel_id == channel_id
                && record.session.lease_id != lease_id
            {
                return Err(anyhow!(
                    "paid route channel {channel_id} is already bound to lease {}",
                    record.session.lease_id
                ));
            }
        }

        Ok(())
    }

    fn seller_payment_accepted_terms(
        &self,
        service_id: &str,
        lease_id: &str,
        channel_id: &str,
        buyer_npub: &str,
    ) -> Result<Option<PaidExitConfig>> {
        if let Some(channel) = self.channels.get(channel_id) {
            ensure_seller_channel_matches(channel, service_id, buyer_npub)?;
            return accepted_channel_terms(channel, PaidRouteChannelRole::Seller)
                .cloned()
                .map(Some);
        }
        let session_id = seller_session_id_for_lease(lease_id);
        let Some(session) = self.sessions.get(&session_id) else {
            return Ok(None);
        };
        if session.session.lease_id != lease_id {
            return Err(anyhow!(
                "paid route seller session does not match its lease"
            ));
        }
        let existing_channel = self
            .channels
            .get(&session.session.payment.channel_id)
            .ok_or_else(|| anyhow!("paid route seller session has no channel"))?;
        ensure_seller_channel_matches(existing_channel, service_id, buyer_npub)?;
        accepted_channel_terms(existing_channel, PaidRouteChannelRole::Seller)
            .cloned()
            .map(Some)
    }

    pub(super) fn ensure_existing_seller_session(
        &self,
        service_id: &str,
        lease_id: &str,
        channel_id: &str,
        buyer_npub: &str,
        allow_closing: bool,
    ) -> Result<()> {
        let lease = self
            .leases
            .get(lease_id)
            .ok_or_else(|| anyhow!("paid route lease {lease_id} does not exist"))?;
        if lease.lease.offer_id != service_id {
            return Err(anyhow!(
                "paid route lease {} belongs to service {}, not {}",
                lease_id,
                lease.lease.offer_id,
                service_id
            ));
        }
        if normalize_paid_route_npub(&lease.lease.buyer_npub, "buyer")? != buyer_npub {
            return Err(anyhow!(
                "paid route payment buyer does not match lease buyer"
            ));
        }
        if matches!(
            lease.status,
            PaidRouteLifecycleStatus::Closed
                | PaidRouteLifecycleStatus::Expired
                | PaidRouteLifecycleStatus::Failed
        ) || (!allow_closing && lease.status == PaidRouteLifecycleStatus::Closing)
        {
            return Err(anyhow!("paid route lease {lease_id} is not open"));
        }

        let channel = self
            .channels
            .get(channel_id)
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        ensure_seller_channel_matches(channel, service_id, buyer_npub)?;
        if matches!(
            channel.status,
            PaidRouteLifecycleStatus::Closed
                | PaidRouteLifecycleStatus::Expired
                | PaidRouteLifecycleStatus::Failed
        ) || (!allow_closing && channel.status == PaidRouteLifecycleStatus::Closing)
        {
            return Err(anyhow!("paid route channel {channel_id} is not open"));
        }

        let session_id = seller_session_id_for_lease(lease_id);
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} does not exist"))?;
        if session.session.lease_id != lease_id || session.session.payment.channel_id != channel_id
        {
            return Err(anyhow!(
                "paid route session {session_id} does not match lease/channel"
            ));
        }
        Ok(())
    }
}
