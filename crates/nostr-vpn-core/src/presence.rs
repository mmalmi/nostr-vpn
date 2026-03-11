use std::collections::{HashMap, HashSet};

use crate::control::PeerAnnouncement;
use crate::signaling::SignalPayload;

#[derive(Debug, Clone, Default)]
pub struct PeerPresenceBook {
    active: HashMap<String, PeerAnnouncement>,
    last_seen_at: HashMap<String, u64>,
}

impl PeerPresenceBook {
    pub fn apply_signal(
        &mut self,
        sender_pubkey: impl Into<String>,
        payload: SignalPayload,
        seen_at: u64,
    ) -> bool {
        let sender_pubkey = sender_pubkey.into();
        self.last_seen_at.insert(sender_pubkey.clone(), seen_at);

        match payload {
            SignalPayload::Hello => false,
            SignalPayload::Announce(announcement) => {
                let should_update = self
                    .active
                    .get(&sender_pubkey)
                    .is_none_or(|existing| existing.timestamp <= announcement.timestamp);
                if should_update {
                    self.active.insert(sender_pubkey, announcement);
                    true
                } else {
                    false
                }
            }
            SignalPayload::Disconnect { .. } => self.active.remove(&sender_pubkey).is_some(),
        }
    }

    pub fn active(&self) -> &HashMap<String, PeerAnnouncement> {
        &self.active
    }

    pub fn last_seen(&self) -> &HashMap<String, u64> {
        &self.last_seen_at
    }

    pub fn last_seen_at(&self, sender_pubkey: &str) -> Option<u64> {
        self.last_seen_at.get(sender_pubkey).copied()
    }

    pub fn prune_stale(&mut self, now: u64, stale_after_secs: u64) -> Vec<String> {
        if stale_after_secs == 0 {
            return Vec::new();
        }

        let cutoff = now.saturating_sub(stale_after_secs);
        let mut removed = Vec::new();
        self.active.retain(|sender_pubkey, _announcement| {
            let keep = self
                .last_seen_at
                .get(sender_pubkey)
                .copied()
                .is_some_and(|last_seen| last_seen > cutoff);
            if !keep {
                removed.push(sender_pubkey.clone());
            }
            keep
        });
        removed.sort();
        removed
    }

    pub fn retain_participants(&mut self, participants: &HashSet<String>) {
        self.active
            .retain(|participant, _| participants.contains(participant));
        self.last_seen_at
            .retain(|participant, _| participants.contains(participant));
    }
}
