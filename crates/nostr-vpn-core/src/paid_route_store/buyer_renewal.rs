use super::{persistence::*, *};

impl PaidRouteStore {
    /// Recovery must count delivered traffic, not the last prepaid balance.
    /// A fully prepaid channel can still have unused credit; an exhausted one
    /// cannot become usable again by replaying its opening payment.
    pub fn buyer_session_has_remaining_capacity(&self, session_id: &str) -> Result<bool> {
        let session = self.sessions.get(session_id)
            .ok_or_else(|| anyhow!("missing buyer session"))?;
        let channel = self.channels.get(&session.session.payment.channel_id)
            .ok_or_else(|| anyhow!("missing buyer channel"))?;
        let terms = accepted_channel_terms(channel, PaidRouteChannelRole::Buyer)?;
        Ok(terms.amount_due_msat(&session.session.usage)
            < channel.payment.capacity_sat.saturating_mul(1_000))
    }

    /// Start replacing the channel with half its traffic credit still available.
    /// An opening payment alone must never trigger repeated channel purchases.
    pub fn buyer_session_needs_renewal(&self, session_id: &str, now_unix: u64) -> Result<bool> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("missing buyer session"))?;
        let channel = self
            .channels
            .get(&session.session.payment.channel_id)
            .ok_or_else(|| anyhow!("missing buyer channel"))?;
        let lease = self
            .leases
            .get(&session.session.lease_id)
            .ok_or_else(|| anyhow!("missing buyer lease"))?;
        let terms = accepted_channel_terms(channel, PaidRouteChannelRole::Buyer)?;
        let capacity_msat = channel.payment.capacity_sat.saturating_mul(1_000);
        Ok(capacity_msat > 0
            && (terms.amount_due_msat(&session.session.usage) >= capacity_msat.div_ceil(2)
                || lease.lease.expires_at_unix.min(channel.expires_at_unix)
                    <= now_unix.saturating_add(60)))
    }

    /// Funding starts early; routing/accounting handover waits until the old
    /// channel has just one sat of traffic credit remaining.
    pub fn buyer_session_ready_to_handover(&self, session_id: &str, now_unix: u64) -> Result<bool> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("missing buyer session"))?;
        let channel = self
            .channels
            .get(&session.session.payment.channel_id)
            .ok_or_else(|| anyhow!("missing buyer channel"))?;
        let lease = self
            .leases
            .get(&session.session.lease_id)
            .ok_or_else(|| anyhow!("missing buyer lease"))?;
        let terms = accepted_channel_terms(channel, PaidRouteChannelRole::Buyer)?;
        let capacity_msat = channel.payment.capacity_sat.saturating_mul(1_000);
        Ok(terms.amount_due_msat(&session.session.usage)
            >= capacity_msat
                .saturating_sub(1_000)
                .max(capacity_msat.div_ceil(2))
            || lease.lease.expires_at_unix.min(channel.expires_at_unix)
                <= now_unix.saturating_add(15))
    }

    /// Start charging the replacement before sending its open request. Waiting
    /// for the acknowledgment lets the seller bill the new channel while the
    /// buyer still bills the old one, eventually stranding the next payment.
    pub fn start_buyer_session_renewal_handover(
        &mut self,
        session_id: &str,
        now_unix: u64,
    ) -> Result<()> {
        if self.selected_buyer_session_id != session_id
            || !self.buyer_session_renewals.contains_key(session_id)
        {
            return Err(anyhow!("missing selected buyer renewal"));
        }
        self.buyer_session_renewal_starts
            .entry(session_id.to_string())
            .or_insert(now_unix);
        Ok(())
    }

    /// Persist the replacement before asking the wallet to fund it, so retries
    /// and restarts reuse the same idempotent wallet request.
    pub fn prepare_buyer_session_renewal(
        &mut self,
        session_id: &str,
        now_unix: u64,
    ) -> Result<String> {
        if let Some(next) = self.buyer_session_renewals.get(session_id) {
            return Ok(next.clone());
        }
        if self.selected_buyer_session_id != session_id {
            return Err(anyhow!("only the selected buyer session can renew"));
        }
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("missing buyer session"))?;
        let channel = self
            .channels
            .get(&session.session.payment.channel_id)
            .ok_or_else(|| anyhow!("missing buyer channel"))?;
        let lease = self
            .leases
            .get(&session.session.lease_id)
            .ok_or_else(|| anyhow!("missing buyer lease"))?;
        ensure_open_buyer_channel(channel, lease)?;
        let offer_key = paid_route_offer_store_key(&channel.counterparty_npub, &channel.offer_id);
        let next = self.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: offer_key,
            buyer_npub: lease.lease.buyer_npub.clone(),
            mint_url: Some(channel.mint_url.clone()),
            channel_capacity_sat: Some(channel.payment.capacity_sat),
            initial_paid_msat: 0,
            now_unix: now_unix.max(channel.created_at_unix.saturating_add(1)),
        })?;
        self.buyer_session_renewals
            .insert(session_id.to_string(), next.session_id.clone());
        Ok(next.session_id)
    }

    /// The old route stays selected until the seller admits its replacement.
    /// Both channels use the same authenticated provider and tunnel address.
    pub fn activate_buyer_session_renewal(
        &mut self,
        session_id: &str,
        now_unix: u64,
    ) -> Result<String> {
        let next = self
            .buyer_session_renewals
            .get(session_id)
            .cloned()
            .ok_or_else(|| anyhow!("missing buyer session renewal"))?;
        if self.selected_buyer_session_id != session_id
            || !self.buyer_session_is_seller_admitted(&next)?
        {
            return Err(anyhow!(
                "replacement must be admitted before switching the selected session"
            ));
        }
        let previous = self
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| anyhow!("missing buyer session"))?;
        let replacement = self
            .sessions
            .get_mut(&next)
            .ok_or_else(|| anyhow!("missing replacement session"))?;
        replacement.last_successful_probe_unix = previous.successful_probe_unix();
        replacement.session.quality = previous.session.quality;
        replacement.session.realized_exit_ip = previous.session.realized_exit_ip;
        replacement.updated_at_unix = now_unix;
        self.selected_buyer_session_id = next.clone();
        self.buyer_session_renewal_starts.remove(session_id);
        Ok(next)
    }
}
