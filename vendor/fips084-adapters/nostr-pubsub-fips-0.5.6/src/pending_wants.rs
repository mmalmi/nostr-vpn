//! Bounded pending inventory provider selection and retry state.

use std::collections::{HashMap, VecDeque};

use crate::now_ms;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InventoryProvider {
    pub(super) peer_npub: String,
    pub(super) subscription_ids: Vec<String>,
}

pub(super) struct PendingInventory {
    pub(super) selected: InventoryProvider,
    pub(super) alternatives: VecDeque<InventoryProvider>,
    pub(super) event_kind: u16,
    pub(super) payload_bytes: u32,
    pub(super) hop_limit: u8,
    pub(super) requested_at_ms: u64,
    pub(super) retry_count: u8,
}

const MAX_WANT_RETRIES: u8 = 5;

#[derive(Default)]
pub(super) struct PendingWantRetryBatch {
    pub(super) retries: Vec<(String, InventoryProvider)>,
    pub(super) expired_providers: Vec<InventoryProvider>,
    pub(super) expired_event_count: usize,
}

pub(super) struct PendingWants {
    pub(super) max_events: usize,
    pub(super) max_alternatives: usize,
    pub(super) entries: HashMap<String, PendingInventory>,
    pub(super) order: VecDeque<String>,
}

impl PendingWants {
    pub(super) fn new(max_events: usize, max_alternatives: usize) -> Self {
        Self {
            max_events,
            max_alternatives,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(super) fn insert(&mut self, event_id: String, incoming: PendingInventory) -> bool {
        if let Some(pending) = self.entries.get_mut(&event_id) {
            if pending.event_kind != incoming.event_kind
                || pending.payload_bytes != incoming.payload_bytes
            {
                return false;
            }
            let mut provider = incoming.selected;
            if provider.peer_npub == pending.selected.peer_npub {
                merge_subscription_ids(
                    &mut pending.selected.subscription_ids,
                    provider.subscription_ids,
                );
                return false;
            }
            if let Some(existing) = pending
                .alternatives
                .iter_mut()
                .find(|existing| existing.peer_npub == provider.peer_npub)
            {
                merge_subscription_ids(&mut existing.subscription_ids, provider.subscription_ids);
            } else if pending.alternatives.len() < self.max_alternatives {
                provider.subscription_ids.sort_unstable();
                provider.subscription_ids.dedup();
                pending.alternatives.push_back(provider);
            }
            return false;
        }

        self.order.push_back(event_id.clone());
        self.entries.insert(event_id, incoming);
        while self.entries.len() > self.max_events {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        true
    }

    pub(super) fn take_matching(
        &mut self,
        event_id: &str,
        source_npub: &str,
        subscription_id: &str,
        event_kind: u16,
        payload_bytes: u32,
    ) -> Option<PendingInventory> {
        let pending = self.entries.get(event_id)?;
        if pending.selected.peer_npub != source_npub
            || !pending
                .selected
                .subscription_ids
                .iter()
                .any(|candidate| candidate == subscription_id)
            || pending.event_kind != event_kind
            || pending.payload_bytes != payload_bytes
        {
            return None;
        }
        self.order.retain(|candidate| candidate != event_id);
        self.entries.remove(event_id)
    }

    pub(super) fn remove_subscription(&mut self, subscription_id: &str) {
        self.entries.retain(|_, pending| {
            pending
                .selected
                .subscription_ids
                .retain(|candidate| candidate != subscription_id);
            for provider in &mut pending.alternatives {
                provider
                    .subscription_ids
                    .retain(|candidate| candidate != subscription_id);
            }
            pending
                .alternatives
                .retain(|provider| !provider.subscription_ids.is_empty());
            if pending.selected.subscription_ids.is_empty()
                && let Some(next) = pending.alternatives.pop_front()
            {
                pending.selected = next;
            }
            !pending.selected.subscription_ids.is_empty()
        });
        self.order
            .retain(|event_id| self.entries.contains_key(event_id));
    }

    pub(super) fn retry_due(&mut self, now_ms: u64, retry_after_ms: u64) -> PendingWantRetryBatch {
        let mut batch = PendingWantRetryBatch::default();
        let mut expired_ids = Vec::new();
        for (event_id, pending) in &mut self.entries {
            let retry_delay = retry_after_ms
                .saturating_mul(1_u64 << u32::from(pending.retry_count.min(MAX_WANT_RETRIES)));
            if now_ms.saturating_sub(pending.requested_at_ms) < retry_delay {
                continue;
            }
            if pending.retry_count >= MAX_WANT_RETRIES {
                batch.expired_event_count += 1;
                batch.expired_providers.push(pending.selected.clone());
                batch
                    .expired_providers
                    .extend(pending.alternatives.iter().cloned());
                expired_ids.push(event_id.clone());
                continue;
            }
            if let Some(next) = pending.alternatives.pop_front() {
                let previous = std::mem::replace(&mut pending.selected, next);
                pending.alternatives.push_back(previous);
            }
            pending.requested_at_ms = now_ms;
            pending.retry_count += 1;
            batch
                .retries
                .push((event_id.clone(), pending.selected.clone()));
        }
        for event_id in expired_ids {
            self.entries.remove(&event_id);
        }
        self.order
            .retain(|event_id| self.entries.contains_key(event_id));
        batch
    }

    pub(super) fn remove_peer(&mut self, peer_npub: &str) {
        self.entries.retain(|_, pending| {
            pending
                .alternatives
                .retain(|provider| provider.peer_npub != peer_npub);
            if pending.selected.peer_npub == peer_npub {
                let Some(next) = pending.alternatives.pop_front() else {
                    return false;
                };
                pending.selected = next;
                pending.retry_count = 0;
                pending.requested_at_ms = now_ms();
            }
            true
        });
        self.order
            .retain(|event_id| self.entries.contains_key(event_id));
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

fn merge_subscription_ids(existing: &mut Vec<String>, incoming: Vec<String>) {
    existing.extend(incoming);
    existing.sort_unstable();
    existing.dedup();
}
