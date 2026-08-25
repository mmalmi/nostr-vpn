use super::{persistence::*, *};

impl PaidRouteStore {
    pub fn open_buyer_session(
        &mut self,
        request: OpenPaidRouteBuyerSessionRequest,
    ) -> Result<OpenPaidRouteBuyerSessionResult> {
        let (offer_key, record) = self.resolve_offer(&request.offer_selector)?;
        if !record.signed_offer.is_live_at(request.now_unix) {
            return Err(anyhow!(
                "paid route offer '{}' expired; discover sellers again",
                request.offer_selector.trim()
            ));
        }
        let offer = record.offer.clone();
        let accepted_terms = PaidExitConfig::from_paid_route_offer(&offer);
        let buyer_npub = normalize_paid_route_npub(&request.buyer_npub, "buyer")?;
        let mint_url = select_buyer_mint(&offer, &self.wallet, request.mint_url.as_deref())?;
        let capacity_sat = requested_channel_capacity(&offer, request.channel_capacity_sat)?;
        let now_unix = request.now_unix;
        let expires_at_unix = now_unix.saturating_add(offer.channel.channel_expiry_secs.max(1));
        let seller_pubkey = PublicKey::parse(&offer.seller_npub)
            .map_err(|error| anyhow!("invalid paid route seller npub: {error}"))?;
        let receiver_pubkey_hex = paid_route_offer_receiver_pubkey_hex(&offer, &seller_pubkey)?;
        let id_suffix = paid_route_buyer_session_id_suffix(&offer_key, &offer.offer_id, now_unix);
        let quote_id = format!("quote-{id_suffix}");
        let lease_id = format!("lease-{id_suffix}");
        let channel_id = format!("channel-{id_suffix}");
        let session_id = format!("session-{id_suffix}");
        let status = initial_buyer_session_status(&offer, request.initial_paid_msat);
        let payment = PaidRoutePaymentState {
            mode: PaidRoutePaymentMode::CashuSpilman,
            channel_id: channel_id.clone(),
            cashu_unit: "sat".to_string(),
            capacity_sat,
            paid_msat: request.initial_paid_msat,
            updated_at_unix: now_unix,
            cashu_spilman_payment: None,
            cashu_token_lease: None,
        };

        let mut changed = self.upsert_quote(
            PaidRouteQuote {
                quote_id: quote_id.clone(),
                offer_id: offer.offer_id.clone(),
                payment_mode: PaidRoutePaymentMode::CashuSpilman,
                channel_capacity_sat: capacity_sat,
                expires_at_unix,
                receiver_pubkey_hex,
            },
            now_unix,
        );
        changed |= self.upsert_lease(
            PaidRouteLease {
                lease_id: lease_id.clone(),
                offer_id: offer.offer_id.clone(),
                quote_id: quote_id.clone(),
                buyer_npub,
                starts_at_unix: now_unix,
                expires_at_unix,
            },
            status,
            now_unix,
        );
        changed |= self.upsert_channel(PaidRouteChannelRecord {
            channel_id: channel_id.clone(),
            offer_id: offer.offer_id.clone(),
            role: PaidRouteChannelRole::Buyer,
            status,
            payment: payment.clone(),
            accepted_terms: Some(accepted_terms),
            mint_url: mint_url.clone(),
            counterparty_npub: offer.seller_npub.clone(),
            created_at_unix: now_unix,
            expires_at_unix,
            updated_at_unix: now_unix,
            error: String::new(),
        });
        changed |= self.upsert_session(
            PaidRouteSession {
                session_id: session_id.clone(),
                lease_id: lease_id.clone(),
                usage: PaidRouteUsage::default(),
                payment,
                realized_exit_ip: None,
                observed_country_code: None,
                observed_asn: None,
                quality: None,
            },
            now_unix,
        );

        Ok(OpenPaidRouteBuyerSessionResult {
            offer_key,
            offer_id: offer.offer_id,
            seller_npub: offer.seller_npub,
            mint_url,
            quote_id,
            lease_id,
            channel_id,
            session_id,
            channel_capacity_sat: capacity_sat,
            expires_at_unix,
            changed,
        })
    }

    pub fn buyer_session_seller_npub(&self, session_id: &str) -> Result<String> {
        let session_id = trimmed_required(session_id, "paid route session id")?;
        let record = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} not found"))?;
        if let Some(channel) = self.channels.get(&record.session.payment.channel_id) {
            if channel.role != PaidRouteChannelRole::Buyer {
                return Err(anyhow!(
                    "paid route session {session_id} is not a buyer session"
                ));
            }
            let seller = channel.counterparty_npub.trim();
            if !seller.is_empty() {
                return normalize_paid_route_npub(seller, "seller");
            }
        }

        let lease = self
            .leases
            .get(&record.session.lease_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} has no lease"))?;
        self.offers
            .values()
            .find(|candidate| candidate.offer.offer_id == lease.lease.offer_id)
            .map(|candidate| candidate.offer.seller_npub.clone())
            .filter(|seller| !seller.trim().is_empty())
            .ok_or_else(|| anyhow!("paid route session {session_id} has no seller offer"))
            .and_then(|seller| normalize_paid_route_npub(&seller, "seller"))
    }

    pub fn buyer_session_seller_fips_endpoints(&self, session_id: &str) -> Result<Vec<String>> {
        let session_id = trimmed_required(session_id, "paid route session id")?;
        let record = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} not found"))?;
        let channel = self
            .channels
            .get(&record.session.payment.channel_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} has no channel"))?;
        let seller_npub = self.buyer_session_seller_npub(&session_id)?;
        Ok(self
            .offers
            .values()
            .find(|candidate| {
                candidate.offer.offer_id == channel.offer_id
                    && candidate.offer.seller_npub == seller_npub
            })
            .map(|candidate| candidate.offer.fips_endpoints.clone())
            .unwrap_or_default())
    }

    pub fn buyer_session_allows_routing(&self, session_id: &str, now_unix: u64) -> Result<bool> {
        let session_id = trimmed_required(session_id, "paid route session id")?;
        let record = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("paid route buyer session {session_id} does not exist"))?;
        let lease_record = self.leases.get(&record.session.lease_id).ok_or_else(|| {
            anyhow!(
                "paid route lease {} does not exist",
                record.session.lease_id
            )
        })?;
        let channel = self
            .channels
            .get(&record.session.payment.channel_id)
            .ok_or_else(|| {
                anyhow!(
                    "paid route channel {} does not exist",
                    record.session.payment.channel_id
                )
            })?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {} is not a buyer channel",
                channel.channel_id
            ));
        }
        let expires_at_unix = lease_record
            .lease
            .expires_at_unix
            .min(channel.expires_at_unix);
        if expires_at_unix <= now_unix {
            return Ok(false);
        }
        let offer = self.buyer_offer_for_session(lease_record, channel)?;
        let config = PaidExitConfig::from_paid_route_offer(&offer);
        let decision = record.session.routing_decision(&config);
        if !paid_route_lifecycle_allows_routing(lease_record.status)
            || !paid_route_lifecycle_allows_routing(channel.status)
            || !decision.allow_routing
        {
            return Ok(false);
        }
        if paid_route_offer_requires_payment_before_routing(&offer)
            && !paid_route_session_has_payment_material(&record.session, channel)
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn build_buyer_payment_envelope(
        &mut self,
        request: BuildPaidRouteBuyerPaymentEnvelopeRequest,
    ) -> Result<BuildPaidRouteBuyerPaymentEnvelopeResult> {
        let before = self.clone();
        let mut next = before.clone();
        let mut result = next.build_buyer_payment_envelope_inner(request)?;
        result.changed = next != before;
        *self = next;
        Ok(result)
    }

    pub fn best_rated_offer_key(&self) -> Result<String> {
        self.offers
            .iter()
            .max_by(|(left_key, left), (right_key, right)| {
                paid_route_offer_autoselect_score(left)
                    .cmp(&paid_route_offer_autoselect_score(right))
                    .then_with(|| left.last_seen_unix.cmp(&right.last_seen_unix))
                    .then_with(|| right_key.cmp(left_key))
            })
            .map(|(key, _)| key.clone())
            .ok_or_else(|| {
                anyhow!("no paid route offers are stored; discover offers before buying")
            })
    }

    pub fn attach_buyer_spilman_channel(
        &mut self,
        request: AttachPaidRouteBuyerSpilmanChannelRequest,
    ) -> Result<AttachPaidRouteBuyerSpilmanChannelResult> {
        let before = self.clone();
        let mut next = before.clone();
        let mut result = next.attach_buyer_spilman_channel_inner(request)?;
        result.changed = next != before;
        *self = next;
        Ok(result)
    }

    pub fn build_buyer_signed_payment_envelope<S: CashuSpilmanPaymentSigner>(
        &mut self,
        signer: &S,
        request: BuildPaidRouteBuyerSignedPaymentEnvelopeRequest,
    ) -> Result<BuildPaidRouteBuyerPaymentEnvelopeResult> {
        let plan = self.buyer_payment_signing_plan(&request)?;
        let signed = create_streaming_route_cashu_payment(
            signer,
            StreamingRouteCashuPaymentRequest {
                kind: request.kind.into(),
                channel_id: plan.channel_id.clone(),
                unit: plan.unit,
                paid_msat: plan.paid_msat,
                previous_paid_msat: plan.previous_paid_msat,
                capacity_sat: plan.capacity_sat,
            },
        )
        .map_err(|error| anyhow!("{error}"))?;

        self.build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: request.session_id,
            buyer_npub: request.buyer_npub,
            kind: request.kind,
            payment: signed.payment,
            delivered_units: Some(plan.delivered_units),
            paid_msat: Some(signed.paid_msat),
            now_unix: request.now_unix,
        })
    }

    pub fn build_buyer_signed_payment_envelope_for_due<S: CashuSpilmanPaymentSigner>(
        &self,
        signer: &S,
        buyer_npub: &str,
        update_due: &PaidRouteBuyerPaymentUpdateDue,
        now_unix: u64,
    ) -> Result<BuildPaidRouteBuyerSignedPaymentEnvelopeForDueResult> {
        let mut store = self.clone();
        let payment = store.build_buyer_signed_payment_envelope(
            signer,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: update_due.session_id.clone(),
                buyer_npub: buyer_npub.to_string(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate,
                delivered_units: Some(update_due.delivered_units),
                paid_msat: Some(update_due.target_paid_msat),
                now_unix,
            },
        )?;
        Ok(BuildPaidRouteBuyerSignedPaymentEnvelopeForDueResult {
            due: update_due.clone(),
            payment,
            store,
        })
    }

    pub fn build_buyer_token_lease_envelope(
        &mut self,
        request: BuildPaidRouteBuyerTokenLeaseEnvelopeRequest,
    ) -> Result<BuildPaidRouteBuyerPaymentEnvelopeResult> {
        let before = self.clone();
        let mut next = before.clone();
        let mut result = next.build_buyer_token_lease_envelope_inner(request)?;
        result.changed = next != before;
        *self = next;
        Ok(result)
    }

    pub fn record_buyer_usage(
        &mut self,
        request: RecordPaidRouteBuyerUsageRequest,
    ) -> Result<Option<RecordPaidRouteBuyerUsageResult>> {
        if request.usage_delta.is_empty() {
            return Ok(None);
        }
        let seller_pubkey = normalize_nostr_pubkey(&request.seller_pubkey)
            .unwrap_or_else(|_| request.seller_pubkey.trim().to_string());
        if seller_pubkey.is_empty() {
            return Err(anyhow!("paid route seller pubkey is empty"));
        }
        let seller_npub = normalize_paid_route_npub(&seller_pubkey, "seller")?;
        let Some(target) = self.buyer_usage_session_for_seller(&seller_npub, request.now_unix)
        else {
            return Ok(None);
        };

        let Some(record) = self.sessions.get_mut(&target.session_id) else {
            return Ok(None);
        };
        let before = record.session.usage.clone();
        apply_usage_delta(&mut record.session.usage, &request.usage_delta);
        let changed = record.session.usage != before;
        if changed {
            record.updated_at_unix = request.now_unix;
        }

        let decision = record.session.routing_decision(&target.config);
        Ok(Some(RecordPaidRouteBuyerUsageResult {
            seller_pubkey: target.seller_pubkey,
            seller_npub: target.seller_npub,
            session_id: target.session_id,
            lease_id: target.lease_id,
            channel_id: target.channel_id,
            usage: record.session.usage.clone(),
            paid_msat: decision.paid_msat,
            amount_due_msat: decision.amount_due_msat,
            unpaid_msat: decision.unpaid_msat,
            allow_routing: decision.allow_routing,
            state: decision.state,
            changed,
        }))
    }

    pub fn buyer_payment_updates_due(
        &self,
        request: PaidRouteBuyerPaymentUpdatesDueRequest,
    ) -> Vec<PaidRouteBuyerPaymentUpdateDue> {
        let mut due = Vec::new();
        for record in self.sessions.values() {
            let Some(lease_record) = self.leases.get(&record.session.lease_id) else {
                continue;
            };
            let Some(channel) = self.channels.get(&record.session.payment.channel_id) else {
                continue;
            };
            if channel.role != PaidRouteChannelRole::Buyer
                || record.session.payment.mode != PaidRoutePaymentMode::CashuSpilman
            {
                continue;
            }
            if !paid_route_lifecycle_allows_routing(lease_record.status)
                || !paid_route_lifecycle_allows_routing(channel.status)
            {
                continue;
            }
            let expires_at_unix = lease_record
                .lease
                .expires_at_unix
                .min(channel.expires_at_unix);
            if expires_at_unix <= request.now_unix {
                continue;
            }
            let Ok(offer) = self.buyer_offer_for_session(lease_record, channel) else {
                continue;
            };
            let config = PaidExitConfig::from_paid_route_offer(&offer);
            let decision = record.session.routing_decision(&config);
            let capacity_msat = record.session.payment.capacity_sat.saturating_mul(1_000);
            let raw_target_paid_msat = if capacity_msat == 0 {
                decision.amount_due_msat
            } else {
                decision.amount_due_msat.min(capacity_msat)
            };
            let unit = paid_route_payment_cashu_unit(&record.session.payment);
            let Ok(target_paid_msat) = cashu_payment_target_msat(&unit, raw_target_paid_msat)
            else {
                continue;
            };
            if target_paid_msat <= record.session.payment.paid_msat {
                continue;
            }
            let payment_increment_msat =
                target_paid_msat.saturating_sub(record.session.payment.paid_msat);
            if payment_increment_msat < request.min_increment_msat {
                continue;
            }
            due.push(PaidRouteBuyerPaymentUpdateDue {
                session_id: record.session.session_id.clone(),
                lease_id: lease_record.lease.lease_id.clone(),
                channel_id: channel.channel_id.clone(),
                offer_id: offer.offer_id,
                seller_npub: offer.seller_npub,
                delivered_units: decision.delivered_units,
                paid_msat: record.session.payment.paid_msat,
                amount_due_msat: decision.amount_due_msat,
                target_paid_msat,
                payment_increment_msat,
                unpaid_msat: decision.unpaid_msat,
                remaining_unpaid_msat: decision.amount_due_msat.saturating_sub(target_paid_msat),
                capacity_msat,
                capacity_exhausted: capacity_msat > 0 && decision.amount_due_msat > capacity_msat,
                allow_routing: decision.allow_routing,
                state: decision.state,
                expires_at_unix,
                updated_at_unix: record.updated_at_unix.max(channel.updated_at_unix),
            });
        }
        due
    }
}
