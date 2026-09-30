use std::collections::{HashSet, VecDeque};

use nostr::Filter;
use nostr_pubsub::{
    EventSource, PubsubPeerInterest, QueryEvent, SOURCE_PRIORITY_FIPS_ENDPOINT, VerifiedEvent,
};

use crate::client_inner::ActiveSubscription;

#[derive(Clone)]
pub(super) struct CachedEvent {
    pub(super) event: VerifiedEvent,
    pub(super) source: EventSource,
    pub(super) hop_limit: u8,
}

pub(super) struct RecentEvents {
    pub(super) max_payload_events: usize,
    pub(super) max_seen_ids: usize,
    pub(super) event_ids: HashSet<String>,
    pub(super) event_id_order: VecDeque<String>,
    pub(super) entries: VecDeque<CachedEvent>,
}

impl RecentEvents {
    pub(super) fn new(max_payload_events: usize, max_seen_ids: usize) -> Self {
        Self {
            max_payload_events,
            max_seen_ids,
            event_ids: HashSet::new(),
            event_id_order: VecDeque::new(),
            entries: VecDeque::new(),
        }
    }

    pub(super) fn insert(
        &mut self,
        event: VerifiedEvent,
        source: EventSource,
        hop_limit: u8,
    ) -> bool {
        let event_id = event.as_event().id.to_string();
        if !self.event_ids.insert(event_id.clone()) {
            return false;
        }
        self.event_id_order.push_back(event_id);
        self.entries.push_back(CachedEvent {
            event,
            source,
            hop_limit,
        });
        while self.entries.len() > self.max_payload_events {
            self.entries.pop_front();
        }
        while self.event_ids.len() > self.max_seen_ids {
            let Some(removed) = self.event_id_order.pop_front() else {
                break;
            };
            self.event_ids.remove(&removed);
        }
        true
    }

    /// An application's durable outbox may retry an event whose payload has
    /// left the live window. Refresh that payload and its bounded seen-ID age;
    /// inbound gossip still uses `insert` and cannot undo deduplication.
    pub(super) fn insert_for_publish(
        &mut self,
        event: VerifiedEvent,
        source: EventSource,
        hop_limit: u8,
    ) -> bool {
        let id = event.as_event().id.to_string();
        if self.event(&id).is_none() && self.event_ids.remove(&id) {
            self.event_id_order.retain(|seen| seen != &id);
        }
        self.insert(event, source, hop_limit)
    }

    pub(super) fn contains(&self, event_id: &str) -> bool {
        self.event_ids.contains(event_id)
    }

    pub(super) fn event(&self, event_id: &str) -> Option<&VerifiedEvent> {
        self.entries
            .iter()
            .find(|cached| cached.event.as_event().id.to_string() == event_id)
            .map(|cached| &cached.event)
    }

    pub(super) fn matching(&self, filters: &[Filter]) -> Vec<CachedEvent> {
        self.entries
            .iter()
            .filter(|cached| {
                PubsubPeerInterest::from_filters(filters, &cached.event)
                    == PubsubPeerInterest::Subscribed
            })
            .cloned()
            .collect()
    }
}

pub(super) fn deliver_local(
    active: &mut ActiveSubscription,
    event: VerifiedEvent,
    source: EventSource,
    event_id: &str,
    max_replay_events: usize,
) {
    active.recent_event_ids.insert(event_id.to_string());
    active.recent_event_order.push_back(event_id.to_string());
    while active.recent_event_order.len() > max_replay_events {
        if let Some(oldest) = active.recent_event_order.pop_front() {
            active.recent_event_ids.remove(&oldest);
        }
    }
    let _ = active.sender.try_send(QueryEvent {
        event,
        source,
        priority: SOURCE_PRIORITY_FIPS_ENDPOINT,
    });
}
