use std::sync::atomic::Ordering;

use nostr_pubsub::{PubsubPeerSubscriptionSnapshot, Result};

use super::{FipsPubsubClient, poisoned};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FipsPubsubDeliverySnapshot {
    pub req_frames_received: u64,
    pub close_frames_received: u64,
    pub event_frames_received: u64,
    pub inv_frames_received: u64,
    pub want_frames_received: u64,
    pub want_frames_sent: u64,
    pub subscription_events_received: u64,
    pub expired_wants: u64,
    pub provider_cooldowns: u64,
    pub tcp_receive_batches: u64,
    pub tcp_datagrams_received: u64,
    pub tcp_datagrams_rejected: u64,
    pub tcp_poll_turns: u64,
}

impl FipsPubsubClient {
    /// Count failed transport operations and rejected record framing.
    ///
    /// Malformed TCP datagrams are counted separately in the delivery snapshot.
    #[must_use]
    pub fn transport_error_count(&self) -> u64 {
        self.inner.transport_errors.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn delivery_snapshot(&self) -> FipsPubsubDeliverySnapshot {
        FipsPubsubDeliverySnapshot {
            req_frames_received: self.inner.req_frames_received.load(Ordering::Relaxed),
            close_frames_received: self.inner.close_frames_received.load(Ordering::Relaxed),
            event_frames_received: self.inner.event_frames_received.load(Ordering::Relaxed),
            inv_frames_received: self.inner.inv_frames_received.load(Ordering::Relaxed),
            want_frames_received: self.inner.want_frames_received.load(Ordering::Relaxed),
            want_frames_sent: self.inner.want_frames_sent.load(Ordering::Relaxed),
            subscription_events_received: self
                .inner
                .subscription_events_received
                .load(Ordering::Relaxed),
            expired_wants: self.inner.expired_wants.load(Ordering::Relaxed),
            provider_cooldowns: self.inner.provider_cooldowns.load(Ordering::Relaxed),
            tcp_receive_batches: self.inner.tcp_receive_batches.load(Ordering::Relaxed),
            tcp_datagrams_received: self.inner.tcp_datagrams_received.load(Ordering::Relaxed),
            tcp_datagrams_rejected: self.inner.tcp_datagrams_rejected.load(Ordering::Relaxed),
            tcp_poll_turns: self.inner.tcp_poll_turns.load(Ordering::Relaxed),
        }
    }

    /// Returns raw retained state for subscriptions accepted from FIPS peers.
    ///
    /// Encoded byte counts are canonical Nostr JSON sizes. They are useful for
    /// deterministic resource accounting but do not estimate allocator overhead.
    pub fn peer_subscription_snapshot(&self) -> Result<PubsubPeerSubscriptionSnapshot> {
        self.inner
            .peer_subscriptions
            .lock()
            .map_err(|_| poisoned("FIPS peer subscription state"))?
            .retained_snapshot()
    }
}
