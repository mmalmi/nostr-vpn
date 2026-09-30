use super::*;
use crate::pending_wants::{InventoryProvider, PendingInventory};
use crate::recent_events::RecentEvents;

#[test]
fn accepted_event_ids_outlive_full_payload_replay() {
    let mut recent = RecentEvents::new(1, 3);
    let events = (0..4)
        .map(|index| {
            VerifiedEvent::try_from(
                EventBuilder::text_note(format!("event {index}"))
                    .sign_with_keys(&Keys::generate())
                    .expect("sign event"),
            )
            .expect("verify event")
        })
        .collect::<Vec<_>>();
    for event in events.iter().take(3) {
        assert!(recent.insert(event.clone(), EventSource::local_index("test"), 1));
    }
    assert_eq!(recent.entries.len(), 1);
    assert!(recent.contains(&events[0].as_event().id.to_string()));

    assert!(recent.insert(events[3].clone(), EventSource::local_index("test"), 1,));
    assert!(!recent.contains(&events[0].as_event().id.to_string()));
    assert!(recent.contains(&events[1].as_event().id.to_string()));
}

#[test]
fn only_explicit_local_retry_restores_payload_without_weakening_gossip_dedup() {
    let mut recent = RecentEvents::new(1, 3);
    let events = (0..4)
        .map(|i| super::routed::signed_note(&format!("retry {i}")))
        .collect::<Vec<_>>();
    let source = EventSource::local_index("outbox");
    for event in &events[..3] {
        assert!(recent.insert(event.clone(), source.clone(), 1));
    }
    assert!(!recent.insert(events[0].clone(), source.clone(), 1));
    assert!(recent.event(&events[0].as_event().id.to_string()).is_none());
    assert!(recent.insert_for_publish(events[0].clone(), source.clone(), 1));
    assert!(!recent.insert(events[0].clone(), source.clone(), 1));
    assert!(!recent.insert_for_publish(events[0].clone(), source.clone(), 1));
    assert!(recent.insert(events[3].clone(), source, 1));
    assert!(recent.contains(&events[0].as_event().id.to_string()));
    assert!(!recent.contains(&events[1].as_event().id.to_string()));
    assert_eq!(recent.entries.len(), 1);
    assert_eq!(recent.event_ids.len(), 3);
    assert_eq!(recent.event_id_order.len(), 3);
}

#[test]
fn pending_want_retries_with_backoff_then_expires() {
    let provider = InventoryProvider {
        peer_npub: Keys::generate()
            .public_key()
            .to_bech32()
            .expect("encode provider npub"),
        subscription_ids: vec!["live".to_string()],
    };
    let mut pending = PendingWants::new(8, 8);
    assert!(pending.insert(
        "event-id".to_string(),
        PendingInventory {
            selected: provider.clone(),
            alternatives: std::collections::VecDeque::new(),
            event_kind: Kind::TextNote.as_u16(),
            payload_bytes: 128,
            hop_limit: 8,
            requested_at_ms: 100,
            retry_count: 0,
        },
    ));

    assert!(pending.retry_due(599, 500).retries.is_empty());
    assert_eq!(
        pending.retry_due(600, 500).retries,
        vec![("event-id".to_string(), provider.clone())]
    );
    assert!(pending.retry_due(1_599, 500).retries.is_empty());
    assert_eq!(
        pending.retry_due(1_600, 500).retries,
        vec![("event-id".to_string(), provider.clone())]
    );
    for now_ms in [3_600, 7_600, 15_600] {
        assert_eq!(
            pending.retry_due(now_ms, 500).retries,
            vec![("event-id".to_string(), provider.clone())]
        );
    }
    assert!(pending.retry_due(31_599, 500).retries.is_empty());
    let expired = pending.retry_due(31_600, 500);
    assert!(expired.retries.is_empty());
    assert_eq!(expired.expired_event_count, 1);
    assert_eq!(expired.expired_providers, vec![provider]);
    assert!(pending.retry_due(60_000, 500).retries.is_empty());
}
