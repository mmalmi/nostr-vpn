use super::routed::{signed_note, udp_endpoint};
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_outbox_retry_restores_a_payload_evicted_before_peer_arrival() {
    let a = udp_endpoint([91; 32], Vec::new()).await;
    let publisher = FipsPubsubClient::start(a.clone(), FipsPubsubClientOptions::default())
        .await
        .unwrap();
    let events = (0..=FIPS_NOSTR_PUBSUB_MAX_REPLAY_EVENTS)
        .map(|i| signed_note(&format!("offline event {i}")))
        .collect::<Vec<_>>();
    for event in &events {
        publisher
            .publish(event.clone(), EventSource::local_index("durable-outbox"))
            .await
            .unwrap();
    }
    let addr = a.bound_udp_listen_addrs().await.unwrap()[0].to_string();
    let b = udp_endpoint([92; 32], vec![PeerConfig::new(a.npub(), "udp", &addr)]).await;
    let receiver = FipsPubsubClient::start(b.clone(), FipsPubsubClientOptions::default())
        .await
        .unwrap();
    let mut subscription = receiver
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    // The bounded live window only contains the last eight payloads.
    let mut delivered_ids = HashSet::new();
    timeout(Duration::from_secs(5), async {
        while delivered_ids.len() < FIPS_NOSTR_PUBSUB_MAX_REPLAY_EVENTS {
            delivered_ids.insert(subscription.recv().await.unwrap().event.as_event().id);
        }
    })
    .await
    .unwrap();
    assert!(!delivered_ids.contains(&events[0].as_event().id));
    // A durable application retries the exact original signed event. Seen-ID
    // dedup must not permanently discard a payload that was never delivered.
    publisher
        .publish(
            events[0].clone(),
            EventSource::local_index("durable-outbox"),
        )
        .await
        .unwrap();
    let delivery = timeout(Duration::from_secs(5), subscription.recv())
        .await
        .expect("explicit local retry restores and advertises the evicted payload")
        .unwrap();
    assert_eq!(delivery.event, events[0]);
    assert_eq!(
        publisher.inner.recent_events.lock().unwrap().entries.len(),
        FIPS_NOSTR_PUBSUB_MAX_REPLAY_EVENTS
    );
    drop(subscription);
    publisher.shutdown().await;
    receiver.shutdown().await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}
