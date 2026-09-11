use super::{persistence::*, *};
use std::collections::BTreeSet;

pub fn normalize_paid_route_mint_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    let mut url = Url::parse(raw).with_context(|| format!("invalid mint URL: {raw}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(anyhow!("unsupported mint URL scheme: {scheme}")),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(anyhow!("mint URL must include a host"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!("mint URL must not include a query or fragment"));
    }

    let trimmed_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&trimmed_path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

impl PaidRouteStore {
    pub fn upsert_wallet_mint(
        &mut self,
        url: impl AsRef<str>,
        label: impl AsRef<str>,
        balance_msat: Option<u64>,
        checked_at_unix: u64,
    ) -> bool {
        let url = url.as_ref().trim();
        if url.is_empty() {
            return false;
        }
        let label = label.as_ref().trim();
        if self.wallet.default_mint.trim().is_empty() {
            self.wallet.default_mint = url.to_string();
        }

        if let Some(existing) = self.wallet.mints.iter_mut().find(|mint| mint.url == url) {
            let before = existing.clone();
            existing.label = label.to_string();
            existing.balance_msat = balance_msat;
            existing.last_checked_unix = checked_at_unix;
            return *existing != before;
        }

        self.wallet.mints.push(PaidRouteWalletMint {
            url: url.to_string(),
            label: label.to_string(),
            balance_msat,
            last_checked_unix: checked_at_unix,
        });
        self.wallet
            .mints
            .sort_by(|left, right| left.url.cmp(&right.url));
        true
    }

    pub fn set_default_mint(&mut self, url: impl AsRef<str>) -> bool {
        let url = url.as_ref().trim();
        if url.is_empty() {
            return false;
        }
        let mut changed = false;
        if !self.wallet.mints.iter().any(|mint| mint.url == url) {
            self.wallet.mints.push(PaidRouteWalletMint {
                url: url.to_string(),
                label: String::new(),
                balance_msat: None,
                last_checked_unix: 0,
            });
            self.wallet
                .mints
                .sort_by(|left, right| left.url.cmp(&right.url));
            changed = true;
        }
        if self.wallet.default_mint != url {
            self.wallet.default_mint = url.to_string();
            changed = true;
        }
        changed
    }

    pub fn remove_wallet_mint(&mut self, url: impl AsRef<str>) -> bool {
        let url = url.as_ref().trim();
        if url.is_empty() {
            return false;
        }
        let before_len = self.wallet.mints.len();
        self.wallet.mints.retain(|mint| mint.url != url);
        let removed = self.wallet.mints.len() != before_len;
        if self.wallet.default_mint == url {
            self.wallet.default_mint = self
                .wallet
                .mints
                .first()
                .map(|mint| mint.url.clone())
                .unwrap_or_default();
            return true;
        }
        removed
    }

    pub fn upsert_signed_offer(
        &mut self,
        signed_offer: SignedPaidRouteOffer,
        relay_urls: Vec<String>,
        seen_at_unix: u64,
    ) -> Result<bool> {
        signed_offer.verify()?;
        let offer = signed_offer.offer()?;
        let key = paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id);
        let relay_urls = normalize_relay_list(relay_urls);
        let incoming_created_at = signed_offer.event.created_at.as_secs();
        let incoming_event_id = signed_offer.event.id.to_string();

        let replace = match self.offers.get(&key) {
            None => true,
            Some(existing) if existing.signed_offer.verify().is_err() => true,
            Some(existing)
                if existing.signed_offer.event.created_at.as_secs() < incoming_created_at =>
            {
                true
            }
            Some(existing) if existing.signed_offer.event.id.to_string() == incoming_event_id => {
                false
            }
            Some(_) => false,
        };

        if let Some(existing) = self.offers.get_mut(&key)
            && !replace
        {
            let before = existing.clone();
            existing.last_seen_unix = existing.last_seen_unix.max(seen_at_unix);
            existing.relay_urls = merge_sorted_strings(&existing.relay_urls, relay_urls);
            return Ok(*existing != before);
        }

        let first_seen_unix = self
            .offers
            .get(&key)
            .map(|record| record.first_seen_unix)
            .unwrap_or(seen_at_unix);
        let (rating_score, rating_updated_at_unix) = self
            .offers
            .get(&key)
            .map(|record| (record.rating_score, record.rating_updated_at_unix))
            .unwrap_or((None, 0));
        self.offers.insert(
            key,
            PaidRouteOfferRecord {
                signed_offer,
                offer,
                relay_urls,
                rating_score,
                rating_updated_at_unix,
                first_seen_unix,
                last_seen_unix: seen_at_unix,
            },
        );
        Ok(true)
    }

    pub fn upsert_offer_rating_score(
        &mut self,
        seller_npub: &str,
        score: i64,
        updated_at_unix: u64,
    ) -> bool {
        let seller_npub = seller_npub.trim();
        if seller_npub.is_empty() {
            return false;
        }
        let score = score.clamp(-100, 100);
        let mut changed = false;
        for record in self.offers.values_mut() {
            if record.offer.seller_npub != seller_npub
                || record.rating_updated_at_unix > updated_at_unix
            {
                continue;
            }
            let before = (record.rating_score, record.rating_updated_at_unix);
            record.rating_score = Some(score);
            record.rating_updated_at_unix = updated_at_unix;
            changed |= before != (record.rating_score, record.rating_updated_at_unix);
        }
        changed
    }

    pub fn upsert_quote(&mut self, quote: PaidRouteQuote, updated_at_unix: u64) -> bool {
        let key = quote.quote_id.trim().to_string();
        if key.is_empty() {
            return false;
        }
        let record = PaidRouteQuoteRecord {
            quote,
            created_at_unix: updated_at_unix,
            updated_at_unix,
        };
        upsert_record(&mut self.quotes, key, record)
    }

    pub fn upsert_lease(
        &mut self,
        lease: PaidRouteLease,
        status: PaidRouteLifecycleStatus,
        updated_at_unix: u64,
    ) -> bool {
        let key = lease.lease_id.trim().to_string();
        if key.is_empty() {
            return false;
        }
        let record = PaidRouteLeaseRecord {
            lease,
            status,
            created_at_unix: updated_at_unix,
            updated_at_unix,
        };
        upsert_record(&mut self.leases, key, record)
    }

    pub fn upsert_channel(&mut self, channel: PaidRouteChannelRecord) -> bool {
        let key = channel.channel_id.trim();
        if key.is_empty() {
            return false;
        }
        upsert_record(&mut self.channels, key.to_string(), channel)
    }

    pub fn upsert_session(&mut self, session: PaidRouteSession, updated_at_unix: u64) -> bool {
        let key = session.session_id.trim().to_string();
        if key.is_empty() {
            return false;
        }
        let record = PaidRouteSessionRecord {
            funding_started_unix: 0,
            last_successful_probe_unix: 0,
            session,
            created_at_unix: updated_at_unix,
            updated_at_unix,
        };
        upsert_record(&mut self.sessions, key, record)
    }

    pub fn mark_seller_channel_closed(
        &mut self,
        channel_id: &str,
        paid_msat: u64,
        updated_at_unix: u64,
    ) -> Result<bool> {
        let channel_id = trimmed_required(channel_id, "paid route channel id")?;
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Seller {
            return Err(anyhow!(
                "paid route channel {channel_id} is not a seller channel"
            ));
        }

        let mut changed = false;
        if channel.status != PaidRouteLifecycleStatus::Closed {
            channel.status = PaidRouteLifecycleStatus::Closed;
            changed = true;
        }
        if paid_msat > channel.payment.paid_msat {
            channel.payment.paid_msat = paid_msat;
            changed = true;
        }
        if channel.payment.mode != PaidRoutePaymentMode::CashuSpilman {
            channel.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            changed = true;
        }
        if changed {
            channel.payment.updated_at_unix = updated_at_unix;
            channel.updated_at_unix = updated_at_unix;
        }

        let mut lease_ids = Vec::new();
        for record in self.sessions.values_mut() {
            if record.session.payment.channel_id != channel_id {
                continue;
            }
            lease_ids.push(record.session.lease_id.clone());
            let before = record.session.payment.clone();
            if paid_msat > record.session.payment.paid_msat {
                record.session.payment.paid_msat = paid_msat;
            }
            record.session.payment.mode = PaidRoutePaymentMode::CashuSpilman;
            if record.session.payment != before {
                record.session.payment.updated_at_unix = updated_at_unix;
                record.updated_at_unix = updated_at_unix;
                changed = true;
            }
        }
        lease_ids.sort();
        lease_ids.dedup();
        for lease_id in lease_ids {
            let Some(lease) = self.leases.get_mut(&lease_id) else {
                continue;
            };
            if lease.status != PaidRouteLifecycleStatus::Closed {
                lease.status = PaidRouteLifecycleStatus::Closed;
                lease.updated_at_unix = updated_at_unix;
                changed = true;
            }
        }

        Ok(changed)
    }

    pub fn mark_buyer_channel_closed(
        &mut self,
        channel_id: &str,
        updated_at_unix: u64,
    ) -> Result<bool> {
        let channel_id = trimmed_required(channel_id, "paid route channel id")?;
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow!("paid route channel {channel_id} does not exist"))?;
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!(
                "paid route channel {channel_id} is not a buyer channel"
            ));
        }

        let mut changed = false;
        if channel.status != PaidRouteLifecycleStatus::Closed {
            channel.status = PaidRouteLifecycleStatus::Closed;
            channel.updated_at_unix = updated_at_unix;
            changed = true;
        }
        if !channel.error.is_empty() {
            channel.error.clear();
            channel.updated_at_unix = updated_at_unix;
            changed = true;
        }

        let lease_ids = self
            .sessions
            .values()
            .filter(|record| record.session.payment.channel_id == channel_id)
            .map(|record| record.session.lease_id.clone())
            .collect::<BTreeSet<_>>();
        for lease_id in lease_ids {
            let Some(lease) = self.leases.get_mut(&lease_id) else {
                continue;
            };
            if lease.status != PaidRouteLifecycleStatus::Closed {
                lease.status = PaidRouteLifecycleStatus::Closed;
                lease.updated_at_unix = updated_at_unix;
                changed = true;
            }
        }

        Ok(changed)
    }

    pub fn update_session_probe(
        &mut self,
        request: UpdatePaidRouteSessionProbeRequest,
    ) -> Result<UpdatePaidRouteSessionProbeResult> {
        let session_id = trimmed_required(&request.session_id, "paid route session id")?;
        let record = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} does not exist"))?;
        let before = record.clone();

        if let Some(realized_exit_ip) = normalize_optional_probe_string(request.realized_exit_ip) {
            record.session.realized_exit_ip = Some(realized_exit_ip);
        }
        if let Some(country) = normalize_optional_country_code(request.observed_country_code) {
            record.session.observed_country_code = Some(country);
        }
        if let Some(asn) = request.observed_asn {
            record.session.observed_asn = Some(asn);
        }
        if let Some(mut quality) = request.quality
            && !quality.is_empty()
        {
            if quality.last_seen_unix.is_none() {
                quality.last_seen_unix = Some(request.now_unix);
            }
            record
                .session
                .quality
                .get_or_insert_with(PaidRouteQualityMetrics::default)
                .merge_patch(quality);
        }

        record.last_successful_probe_unix = record.successful_probe_unix();
        let changed = *record != before;
        if changed {
            record.updated_at_unix = request.now_unix;
        }

        Ok(UpdatePaidRouteSessionProbeResult {
            session_id,
            changed,
            realized_exit_ip: record.session.realized_exit_ip.clone(),
            observed_country_code: record.session.observed_country_code.clone(),
            observed_asn: record.session.observed_asn,
            quality: record.session.quality.clone(),
        })
    }
}
