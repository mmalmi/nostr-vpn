use super::*;

/// One durable cooldown for buyer funding and refund recovery at a mint.
/// Channel records remain pending throughout outages and rate limiting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteMintRetry {
    pub consecutive_failures: u32,
    pub retry_at_unix: u64,
}

impl PaidRouteStore {
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
