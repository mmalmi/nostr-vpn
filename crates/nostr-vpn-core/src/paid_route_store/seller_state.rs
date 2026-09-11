use super::{persistence::*, *};

impl PaidRouteStore {
    pub fn live_offer_for_selector(&self, selector: &str, now_unix: u64) -> Result<PaidRouteOffer> {
        let (_, record) = self.resolve_offer(selector)?;
        if !record.signed_offer.is_live_at(now_unix) {
            return Err(anyhow!("paid route offer '{}' expired", selector.trim()));
        }
        record.signed_offer.verify()?;
        Ok(record.offer.clone())
    }

    pub fn record_seller_usage(
        &mut self,
        request: RecordPaidRouteSellerUsageRequest,
    ) -> Result<Option<RecordPaidRouteSellerUsageResult>> {
        if !request.config.enabled || request.usage_delta.is_empty() {
            return Ok(None);
        }
        let buyer_pubkey = normalize_nostr_pubkey(&request.buyer_pubkey)
            .unwrap_or_else(|_| request.buyer_pubkey.trim().to_string());
        if buyer_pubkey.is_empty() {
            return Err(anyhow!("paid route buyer pubkey is empty"));
        }
        let Some(admission) =
            self.seller_admission_for_buyer(&request.config, request.now_unix, &buyer_pubkey)
        else {
            return Ok(None);
        };
        let accepted_terms = self
            .channels
            .get(&admission.channel_id)
            .and_then(|channel| accepted_channel_terms(channel, PaidRouteChannelRole::Seller).ok())
            .cloned()
            .ok_or_else(|| anyhow!("paid route seller channel has no accepted terms"))?;

        let Some(record) = self.sessions.get_mut(&admission.session_id) else {
            return Ok(None);
        };
        let before = record.session.usage.clone();
        apply_usage_delta(&mut record.session.usage, &request.usage_delta);
        let changed = record.session.usage != before;
        if changed {
            record.updated_at_unix = request.now_unix;
        }

        let decision = record.session.routing_decision(&accepted_terms);
        Ok(Some(RecordPaidRouteSellerUsageResult {
            buyer_pubkey,
            buyer_npub: admission.buyer_npub,
            session_id: admission.session_id,
            lease_id: admission.lease_id,
            channel_id: admission.channel_id,
            usage: record.session.usage.clone(),
            paid_msat: decision.paid_msat,
            amount_due_msat: decision.amount_due_msat,
            unpaid_msat: decision.unpaid_msat,
            allow_routing: decision.allow_routing,
            state: decision.state,
            changed,
        }))
    }

    pub fn seller_admissions(
        &self,
        config: &PaidExitConfig,
        now_unix: u64,
    ) -> Vec<PaidRouteSellerAdmission> {
        if !config.enabled {
            return Vec::new();
        }
        let mut by_buyer = BTreeMap::<String, PaidRouteSellerAdmission>::new();
        for record in self.sessions.values() {
            let Some(admission) = self.seller_admission_for_session(config, now_unix, record)
            else {
                continue;
            };
            match by_buyer.get(&admission.buyer_pubkey) {
                None => {
                    by_buyer.insert(admission.buyer_pubkey.clone(), admission);
                }
                Some(existing) if seller_admission_preferred(self, &admission, existing) => {
                    by_buyer.insert(admission.buyer_pubkey.clone(), admission);
                }
                Some(_) => {}
            }
        }
        by_buyer.into_values().collect()
    }

    pub fn seller_collection_states(
        &self,
        config: &PaidExitConfig,
        now_unix: u64,
    ) -> Vec<PaidRouteSellerCollectionState> {
        let mut states = self
            .sessions
            .values()
            .filter_map(|record| self.seller_collection_state_for_record(config, now_unix, record))
            .collect::<Vec<_>>();
        states.sort_by(|left, right| {
            right
                .auto_collect_due
                .cmp(&left.auto_collect_due)
                .then_with(|| right.updated_at_unix.cmp(&left.updated_at_unix))
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        states
    }

    pub fn seller_collection_state_for_session(
        &self,
        config: &PaidExitConfig,
        now_unix: u64,
        session_id: &str,
    ) -> Option<PaidRouteSellerCollectionState> {
        self.sessions
            .get(session_id)
            .and_then(|record| self.seller_collection_state_for_record(config, now_unix, record))
    }

    pub(super) fn seller_admission_for_buyer(
        &self,
        config: &PaidExitConfig,
        now_unix: u64,
        buyer_pubkey: &str,
    ) -> Option<PaidRouteSellerAdmission> {
        let buyer_pubkey = normalize_nostr_pubkey(buyer_pubkey)
            .unwrap_or_else(|_| buyer_pubkey.trim().to_string());
        self.sessions
            .values()
            .filter_map(|record| self.seller_admission_for_session(config, now_unix, record))
            .filter(|admission| admission.buyer_pubkey == buyer_pubkey)
            .max_by(|left, right| {
                if seller_admission_preferred(self, left, right) {
                    std::cmp::Ordering::Greater
                } else if seller_admission_preferred(self, right, left) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
    }

    pub(super) fn seller_admission_for_session(
        &self,
        config: &PaidExitConfig,
        now_unix: u64,
        record: &PaidRouteSessionRecord,
    ) -> Option<PaidRouteSellerAdmission> {
        if !config.enabled {
            return None;
        }
        let session = &record.session;
        let lease_record = self.leases.get(&session.lease_id)?;
        let channel = self.channels.get(&session.payment.channel_id)?;
        if channel.role != PaidRouteChannelRole::Seller {
            return None;
        }
        let accepted_terms = accepted_channel_terms(channel, PaidRouteChannelRole::Seller).ok()?;

        let buyer_npub = normalize_paid_route_npub(&lease_record.lease.buyer_npub, "buyer").ok()?;
        let buyer_pubkey = normalize_nostr_pubkey(&buyer_npub).ok()?;
        let buyer_tunnel_ip = self
            .seller_session_tunnel_ips
            .get(&session.session_id)?
            .clone();
        let decision = session.routing_decision(accepted_terms);
        let expires_at_unix = lease_record
            .lease
            .expires_at_unix
            .min(channel.expires_at_unix);
        let lifecycle_allows = paid_route_lifecycle_allows_routing(lease_record.status)
            && paid_route_lifecycle_allows_routing(channel.status);
        let not_expired = expires_at_unix > now_unix;
        let allow_routing = lifecycle_allows && not_expired && decision.allow_routing;
        let state = if allow_routing {
            decision.state
        } else {
            PaidRouteAccessState::Suspended
        };

        Some(PaidRouteSellerAdmission {
            buyer_pubkey,
            buyer_npub,
            buyer_tunnel_ip,
            session_id: session.session_id.clone(),
            lease_id: session.lease_id.clone(),
            channel_id: session.payment.channel_id.clone(),
            destination_allowed_ips: paid_exit_destination_allowed_ips(accepted_terms),
            state,
            allow_routing,
            amount_due_msat: decision.amount_due_msat,
            paid_msat: decision.paid_msat,
            unpaid_msat: decision.unpaid_msat,
            expires_at_unix,
            updated_at_unix: record.updated_at_unix.max(channel.updated_at_unix),
        })
    }

    pub(super) fn seller_collection_state_for_record(
        &self,
        _config: &PaidExitConfig,
        now_unix: u64,
        record: &PaidRouteSessionRecord,
    ) -> Option<PaidRouteSellerCollectionState> {
        let session = &record.session;
        let lease_record = self.leases.get(&session.lease_id)?;
        let channel = self.channels.get(&session.payment.channel_id)?;
        if channel.role != PaidRouteChannelRole::Seller {
            return None;
        }

        let buyer_npub = normalize_paid_route_npub(&lease_record.lease.buyer_npub, "buyer").ok()?;
        let expires_at_unix = lease_record
            .lease
            .expires_at_unix
            .min(channel.expires_at_unix);
        let expired = expires_at_unix > 0 && expires_at_unix <= now_unix;
        let terminally_collected = matches!(
            channel.status,
            PaidRouteLifecycleStatus::Closed | PaidRouteLifecycleStatus::Failed
        ) || matches!(
            lease_record.status,
            PaidRouteLifecycleStatus::Closed | PaidRouteLifecycleStatus::Failed
        );
        let has_spilman_payment =
            matches!(session.payment.mode, PaidRoutePaymentMode::CashuSpilman)
                && (session.payment.cashu_spilman_payment.is_some()
                    || channel.payment.cashu_spilman_payment.is_some());
        let paid_msat = session.payment.paid_msat.max(channel.payment.paid_msat);
        let collectable = !terminally_collected
            && has_spilman_payment
            && paid_msat > 0
            && !channel.channel_id.trim().is_empty();
        let auto_collect_due = collectable && expired;
        let reason = if auto_collect_due {
            "expired"
        } else if collectable {
            "manual"
        } else if terminally_collected {
            "closed"
        } else {
            ""
        }
        .to_string();

        Some(PaidRouteSellerCollectionState {
            buyer_npub,
            session_id: session.session_id.clone(),
            lease_id: session.lease_id.clone(),
            channel_id: session.payment.channel_id.clone(),
            collectable,
            manual_collect: collectable,
            auto_collect_due,
            reason,
            paid_msat,
            expires_at_unix,
            due_at_unix: if collectable { expires_at_unix } else { 0 },
            updated_at_unix: record.updated_at_unix.max(channel.updated_at_unix),
        })
        .filter(|state| state.collectable)
    }

    pub(super) fn resolve_offer(&self, selector: &str) -> Result<(String, &PaidRouteOfferRecord)> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(anyhow!("paid route offer selector is empty"));
        }
        if let Some(record) = self.offers.get(selector) {
            return Ok((selector.to_string(), record));
        }

        let matches = self
            .offers
            .iter()
            .filter(|(_, record)| {
                record.offer.offer_id == selector || record.offer.seller_npub == selector
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(anyhow!("paid route offer '{selector}' was not found")),
            [(key, record)] => Ok(((*key).clone(), *record)),
            _ => Err(anyhow!(
                "paid route offer selector '{selector}' is ambiguous; use the full offer key"
            )),
        }
    }

    pub(super) fn retain_valid(&mut self) {
        for record in self.offers.values_mut() {
            if let Ok(offer) = record.signed_offer.offer() {
                record.offer = offer;
            }
            record.relay_urls = normalize_relay_list(record.relay_urls.clone());
            if let Some(score) = record.rating_score {
                record.rating_score = Some(score.clamp(-100, 100));
            } else {
                record.rating_updated_at_unix = 0;
            }
        }
        self.offers.retain(|key, record| {
            record.signed_offer.verify().is_ok()
                && record.signed_offer.offer().is_ok_and(|offer| {
                    paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id) == *key
                })
        });
        self.wallet.mints.retain_mut(|mint| {
            let Ok(url) = normalize_paid_route_mint_url(&mint.url) else {
                return false;
            };
            mint.url = url;
            true
        });
        self.wallet
            .mints
            .sort_by(|left, right| left.url.cmp(&right.url));
        self.wallet
            .mints
            .dedup_by(|left, right| left.url == right.url);
        self.wallet.default_mint = normalize_paid_route_mint_url(&self.wallet.default_mint)
            .ok()
            .filter(|url| self.wallet.mints.iter().any(|mint| mint.url == *url))
            .or_else(|| self.wallet.mints.first().map(|mint| mint.url.clone()))
            .unwrap_or_default();
    }
}
