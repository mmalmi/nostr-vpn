use super::{persistence::*, *};
use std::collections::BTreeSet;

/// Terminal records stay this long after their last update before pruning.
/// Collection opens at the 12-hour service cutoff and buyers can reclaim
/// uncollected funds until 24 hours after expiry, so a week covers every
/// collection, refund, and reclaim retry window with margin.
const PAID_ROUTE_TERMINAL_RECORD_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

impl PaidRouteStore {
    /// Retire elapsed free trials without involving a mint or discarding history.
    pub fn expire_unfunded_seller_sessions(&mut self, now_unix: u64) -> bool {
        let expired = self
            .sessions
            .values()
            .filter_map(|record| {
                let session = &record.session;
                let channel = self.channels.get(&session.payment.channel_id)?;
                let lease = self.leases.get(&session.lease_id)?;
                (channel.role == PaidRouteChannelRole::Seller
                    && !paid_route_session_has_payment_material(session, channel)
                    && session.payment.paid_msat.max(channel.payment.paid_msat) == 0
                    && channel.routing_expires_at_unix(lease.lease.expires_at_unix) <= now_unix)
                    .then(|| (channel.channel_id.clone(), session.lease_id.clone()))
            })
            .collect::<Vec<_>>();
        let mut changed = false;
        for (channel_id, lease_id) in expired {
            if let Some(channel) = self.channels.get_mut(&channel_id)
                && paid_route_lifecycle_allows_routing(channel.status)
            {
                channel.status = PaidRouteLifecycleStatus::Expired;
                channel.updated_at_unix = channel.updated_at_unix.max(now_unix);
                if channel.error.is_empty() {
                    channel.error = "Unfunded trial expired".into();
                }
                changed = true;
            }
            if let Some(lease) = self.leases.get_mut(&lease_id)
                && paid_route_lifecycle_allows_routing(lease.status)
            {
                lease.status = PaidRouteLifecycleStatus::Expired;
                lease.updated_at_unix = lease.updated_at_unix.max(now_unix);
                changed = true;
            }
        }
        changed
    }

    pub fn live_offer_for_selector(&self, selector: &str, now_unix: u64) -> Result<PaidRouteOffer> {
        let (_, record) = self.resolve_offer(selector, now_unix)?;
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
        let expires_at_unix = channel.routing_expires_at_unix(lease_record.lease.expires_at_unix);
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
        let scheduled_collection =
            channel.routing_expires_at_unix(lease_record.lease.expires_at_unix);
        let due_at_unix = if channel.status == PaidRouteLifecycleStatus::Closing {
            channel.updated_at_unix.min(scheduled_collection)
        } else {
            scheduled_collection
        };
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
        let auto_collect_due = collectable && due_at_unix <= now_unix;
        let reason = if auto_collect_due {
            "settlement_due"
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
            due_at_unix: if collectable { due_at_unix } else { 0 },
            updated_at_unix: record.updated_at_unix.max(channel.updated_at_unix),
        })
        .filter(|state| state.collectable)
    }

    pub(super) fn resolve_offer(
        &self,
        selector: &str,
        now_unix: u64,
    ) -> Result<(String, &PaidRouteOfferRecord)> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(anyhow!("paid route offer selector is empty"));
        }
        if let Some(record) = self.offers.get(selector) {
            if !record.signed_offer.is_live_at(now_unix) {
                return Err(anyhow!(
                    "paid route offer '{selector}' expired or is not yet live; discover sellers again"
                ));
            }
            return Ok((selector.to_string(), record));
        }

        let matches = self
            .offers
            .iter()
            .filter(|(_, record)| {
                record.offer.offer_id == selector || record.offer.seller_npub == selector
            })
            .filter(|(_, record)| record.signed_offer.is_live_at(now_unix))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] if self.offers.values().any(|record| {
                record.offer.offer_id == selector || record.offer.seller_npub == selector
            }) =>
            {
                Err(anyhow!(
                    "paid route offer '{selector}' expired or is not yet live; discover sellers again"
                ))
            }
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
        self.prune_terminal_records(crate::config_defaults::current_unix_timestamp());
    }

    /// Removes settled history that no live flow can reach anymore: channels,
    /// sessions, leases, quotes, admissions, and renewal markers that are
    /// terminal and older than the retention window, plus everything hanging
    /// off a pruned channel. Without this the store grows without bound and
    /// every store update reparses and rewrites the full history.
    pub(super) fn prune_terminal_records(&mut self, now_unix: u64) {
        let cutoff = now_unix.saturating_sub(PAID_ROUTE_TERMINAL_RECORD_RETENTION_SECS);
        let terminal = |status: PaidRouteLifecycleStatus| {
            matches!(
                status,
                PaidRouteLifecycleStatus::Closed
                    | PaidRouteLifecycleStatus::Expired
                    | PaidRouteLifecycleStatus::Failed
            )
        };
        let aged = |created_at_unix: u64, updated_at_unix: u64| {
            created_at_unix.max(updated_at_unix) <= cutoff
        };

        // Closing stays: settlement and its close receipt are still in flight.
        let pruned_channels = self
            .channels
            .iter()
            .filter(|(_, channel)| {
                terminal(channel.status) && aged(channel.created_at_unix, channel.updated_at_unix)
            })
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<BTreeSet<_>>();
        for channel_id in &pruned_channels {
            self.channels.remove(channel_id);
        }

        // A session dies with its channel, or once its channel and lease are
        // both terminal and the record itself has aged out.
        let pruned_sessions = self
            .sessions
            .iter()
            .filter(|(_, record)| {
                pruned_channels.contains(&record.session.payment.channel_id)
                    || (self
                        .channels
                        .get(&record.session.payment.channel_id)
                        .is_some_and(|channel| terminal(channel.status))
                        && self
                            .leases
                            .get(&record.session.lease_id)
                            .is_some_and(|lease| terminal(lease.status))
                        && aged(record.created_at_unix, record.updated_at_unix))
            })
            .map(|(session_id, _)| session_id.clone())
            .collect::<BTreeSet<_>>();
        let pruned_session_lease_ids = self
            .sessions
            .iter()
            .filter(|(session_id, _)| pruned_sessions.contains(*session_id))
            .map(|(_, record)| record.session.lease_id.clone())
            .collect::<BTreeSet<_>>();
        for session_id in &pruned_sessions {
            self.sessions.remove(session_id);
        }

        // A lease is dropped once nothing live references it: it is terminal
        // itself, or its channel was pruned underneath its last session.
        let live_lease_ids = self
            .sessions
            .values()
            .map(|record| record.session.lease_id.as_str())
            .collect::<BTreeSet<_>>();
        let pruned_leases = self
            .leases
            .iter()
            .filter(|(lease_id, record)| {
                aged(record.created_at_unix, record.updated_at_unix)
                    && !live_lease_ids.contains(lease_id.as_str())
                    && (terminal(record.status)
                        || pruned_session_lease_ids.contains(lease_id.as_str()))
            })
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<BTreeSet<_>>();
        for lease_id in &pruned_leases {
            self.leases.remove(lease_id);
        }

        // Quotes are only reachable through a lease and die once expired.
        let referenced_quote_ids = self
            .leases
            .values()
            .map(|record| record.lease.quote_id.as_str())
            .collect::<BTreeSet<_>>();
        self.quotes.retain(|quote_id, record| {
            referenced_quote_ids.contains(quote_id.as_str())
                || record.quote.expires_at_unix > cutoff
        });

        // Everything keyed by a pruned lease or session has no live reader.
        let lease_ids = self
            .leases
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        self.buyer_session_admissions
            .retain(|lease_id, _| lease_ids.contains(lease_id.as_str()));
        self.buyer_session_renewals.retain(|session_id, next| {
            self.sessions.contains_key(session_id) && self.sessions.contains_key(next)
        });
        self.buyer_session_renewal_starts
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        self.buyer_session_open_attempts
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        self.seller_session_tunnel_ips
            .retain(|session_id, _| self.sessions.contains_key(session_id));
        if !self.sessions.contains_key(&self.selected_buyer_session_id) {
            self.selected_buyer_session_id.clear();
        }
    }
}
