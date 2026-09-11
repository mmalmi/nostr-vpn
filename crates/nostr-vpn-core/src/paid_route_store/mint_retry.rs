use super::*;

/// One durable cooldown for buyer funding and refund recovery at a mint.
/// Channel records remain pending throughout outages and rate limiting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteMintRetry {
    pub consecutive_failures: u32,
    pub retry_at_unix: u64,
}

impl PaidRouteStore {
    pub fn buyer_mint_needs_funds(&self, mint_url: &str, capacity_sat: u64) -> bool {
        let Ok(mint) = normalize_paid_route_mint_url(mint_url) else {
            return false;
        };
        let balance = self
            .wallet
            .mints
            .iter()
            .find(|entry| entry.url.trim_end_matches('/') == mint)
            .and_then(|entry| entry.balance_msat)
            .unwrap_or(0)
            / 1_000;
        self.sessions.values().any(|record| {
            record.funding_required_balance_sat > balance
                && record.session.payment.capacity_sat <= capacity_sat
                && self
                    .channels
                    .get(&record.session.payment.channel_id)
                    .is_some_and(|channel| channel.mint_url.trim_end_matches('/') == mint)
        })
    }

    pub fn record_buyer_session_funding_shortfall(
        &mut self,
        session_id: &str,
        required_sat: u64,
    ) -> Result<()> {
        let record = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("paid route session {session_id} does not exist"))?;
        record.funding_required_balance_sat = required_sat;
        Ok(())
    }

    pub fn buyer_mint_retry_at(&self, mint_url: &str) -> u64 {
        normalize_paid_route_mint_url(mint_url)
            .ok()
            .and_then(|mint| self.buyer_mint_retries.get(&mint))
            .map_or(0, |retry| retry.retry_at_unix)
    }

    /// Routine settlement polling must not hold up a new payment channel.
    pub fn buyer_mint_failure_retry_at(&self, mint_url: &str) -> u64 {
        normalize_paid_route_mint_url(mint_url)
            .ok()
            .and_then(|mint| self.buyer_mint_retries.get(&mint))
            .filter(|retry| retry.consecutive_failures > 0)
            .map_or(0, |retry| retry.retry_at_unix)
    }

    /// Replaying an existing payment is local and must remain available during an outage.
    pub fn buyer_session_funding_retry_at(&self, session_id: &str) -> u64 {
        self.sessions
            .get(session_id)
            .filter(|record| {
                record.session.payment.cashu_spilman_payment.is_none()
                    && record.session.payment.cashu_token_lease.is_none()
            })
            .and_then(|record| self.channels.get(&record.session.payment.channel_id))
            .map_or(0, |channel| {
                if self.buyer_mint_needs_funds(&channel.mint_url, channel.payment.capacity_sat) {
                    u64::MAX
                } else {
                    self.buyer_mint_failure_retry_at(&channel.mint_url)
                }
            })
    }

    pub fn defer_buyer_mint_retry(
        &mut self,
        mint_url: &str,
        now_unix: u64,
        failed: bool,
        retry_after_secs: Option<u64>,
    ) -> Result<()> {
        let mint = normalize_paid_route_mint_url(mint_url)?;
        let retry = self.buyer_mint_retries.entry(mint).or_default();
        // A concurrent success cannot shorten a server's outstanding cooldown.
        if !failed && retry.retry_at_unix > now_unix {
            return Ok(());
        }
        retry.consecutive_failures = if failed {
            retry.consecutive_failures.saturating_add(1)
        } else {
            0
        };
        let exponent = retry.consecutive_failures.saturating_sub(1).min(6);
        let delay = (10_u64 << exponent)
            .min(600)
            .max(retry_after_secs.unwrap_or(0));
        // Persistence uses whole Unix seconds; round up to avoid retrying early.
        retry.retry_at_unix = retry
            .retry_at_unix
            .max(now_unix.saturating_add(delay).saturating_add(1));
        Ok(())
    }

    pub fn clear_buyer_mint_retry(&mut self, mint_url: &str, now_unix: u64) -> Result<()> {
        let mint = normalize_paid_route_mint_url(mint_url)?;
        if self
            .buyer_mint_retries
            .get(&mint)
            .is_some_and(|retry| retry.retry_at_unix <= now_unix)
        {
            self.buyer_mint_retries.remove(&mint);
        }
        Ok(())
    }
}
