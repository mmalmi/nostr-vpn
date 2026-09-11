use super::{persistence::*, *};

impl PaidRouteStore {
    /// Suspend the trial route while the wallet funds this same session. The
    /// mint must remain reachable even when the seller's free allowance ends.
    pub fn begin_buyer_session_funding(&mut self, session_id: &str, now_unix: u64) -> Result<bool> {
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
        if channel.role != PaidRouteChannelRole::Buyer {
            return Err(anyhow!("only buyer sessions can request funding"));
        }
        ensure_open_buyer_channel(channel, lease)?;
        if channel.expires_at_unix.min(lease.lease.expires_at_unix) <= now_unix {
            return Err(anyhow!("buyer session expired before funding"));
        }
        if paid_route_session_has_payment_material(&session.session, channel) {
            return Ok(false);
        }
        let session = self
            .sessions
            .get_mut(session_id)
            .expect("validated session");
        let changed = session.funding_started_unix == 0;
        if changed {
            session.funding_started_unix = now_unix.max(1);
            session.updated_at_unix = now_unix;
        }
        self.buyer_session_open_attempts.remove(session_id);
        Ok(changed)
    }
}
