use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Instant;

struct BurstRelay {
    url: String,
    requests: Arc<StdMutex<Vec<Instant>>>,
    sent: Arc<AtomicUsize>,
    publish: mpsc::Sender<Event>,
    task: JoinHandle<()>,
}

impl BurstRelay {
    async fn start(mut burst: Vec<Event>, retained: Vec<Event>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let sent = Arc::new(AtomicUsize::new(0));
        let delivered = Arc::clone(&sent);
        let (publish, mut publications) = mpsc::channel::<Event>(2);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let mut live_id = None;
            loop {
                let messages = tokio::select! {
                    publication = publications.recv() => {
                        let Some(event) = publication else { break; };
                        vec![RelayMessage::event(live_id.clone().expect("live interest"), event)]
                    }
                    frame = socket.next() => {
                        let Some(Ok(frame)) = frame else { break; };
                        let Ok(ClientMessage::Req { subscription_id, filters }) =
                            ClientMessage::from_json(frame.into_data()) else { continue; };
                        let id = subscription_id.into_owned();
                        let relevant = filters.iter().any(|filter| filter.kinds.as_ref()
                            .is_some_and(|kinds| kinds.contains(&Kind::Custom(FIPS_PEER_ADVERT_KIND))));
                        if !relevant {
                            vec![RelayMessage::eose(id)]
                        } else {
                            let first = live_id.is_none();
                            live_id = Some(id.clone());
                            observed.lock().unwrap().push(Instant::now());
                            let mut messages = Vec::new();
                            if first {
                                // The finite startup live burst can exceed the retained window.
                                messages.push(RelayMessage::eose(id.clone()));
                                messages.extend(std::mem::take(&mut burst).into_iter()
                                    .map(|event| RelayMessage::event(id.clone(), event)));
                            } else {
                                // Reply immediately, including while application ingress is full.
                                for filter in filters {
                                    messages.extend(retained.iter()
                                        .filter(|event| filter.match_event(event, MatchEventOptions::new()))
                                        .take(filter.limit.unwrap_or(RELAY_REPLAY_LIMIT))
                                        .cloned().map(|event| RelayMessage::event(id.clone(), event)));
                                }
                                messages.push(RelayMessage::eose(id));
                            }
                            messages
                        }
                    }
                };
                for message in messages {
                    if matches!(message, RelayMessage::Event { .. }) {
                        delivered.fetch_add(1, Ordering::Relaxed);
                    }
                    if socket
                        .send(Message::Text(message.as_json().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        Self {
            url,
            requests,
            sent,
            publish,
            task,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

#[test]
fn full_relay_ingress_drains_overlapping_replay_through_fips() {
    run_async_test("relay-ingress-overlap", || async {
        tokio::time::timeout(Duration::from_secs(15), overlapping_replay())
            .await
            .expect("bounded startup-pressure discriminator");
    });
}

async fn overlapping_replay() {
    let owner = Keys::generate();
    let publisher = Keys::generate();
    let mut config = endpoint_config(0, &[]);
    config.node.discovery.local.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.system_files_enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.nostr.policy = fips_core::config::NostrDiscoveryPolicy::ConfiguredOnly;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    config.node.discovery.nostr.stun_servers.clear();
    let app = config.node.discovery.nostr.app.clone();
    let endpoint = endpoint(&owner, config).await;
    let updates = update_events(&owner, "releases/ingress-overlap");
    let policy = FipsPubsubPolicy::new(
        Arc::clone(&endpoint),
        std::iter::empty::<&Event>(),
        FipsPubsubPolicyOptions::default(),
    )
    .unwrap();
    let client = FipsPubsubClient::start_with_policy(
        Arc::clone(&endpoint),
        FipsPubsubClientOptions::default(),
        policy.event_policy(),
    )
    .await
    .unwrap();
    let policy = Arc::new(Mutex::new(policy));
    let events = Arc::new(Mutex::new(
        ControlEventStore::load(None, updates.clone()).unwrap(),
    ));
    let capacity = RELAY_REPLAY_LIMIT * 5;
    let count = capacity * 2 + 1;
    let now = now_ms() / 1_000;
    let burst = (0..count).map(|index| {
        EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND),
            r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"udp","addr":"203.0.113.99:51821"}]}"#)
            .tags([
                Tag::identifier(app.clone()),
                Tag::custom(TagKind::custom("protocol"), [app.clone()]),
                Tag::custom(TagKind::custom("version"), ["1"]),
                Tag::expiration(Timestamp::from(now + 3_600)),
            ])
            .custom_created_at(Timestamp::from(now - (count - index) as u64))
            .sign_with_keys(&publisher).unwrap()
    }).collect::<Vec<_>>();
    // Check that the fixture exercises supported FIPS adverts, not rejected JSON.
    assert!(
        endpoint
            .ingest_nostr_discovery_event(burst[0].clone())
            .await
            .unwrap()
    );
    let marker = burst.last().unwrap().clone();
    let retained = burst[count - RELAY_REPLAY_LIMIT..].to_vec();
    let primary = BurstRelay::start(burst, retained).await;
    let secondary = BurstRelay::start(Vec::new(), Vec::new()).await;
    let mut provider = RelayProvider::start(
        None,
        NostrPubsubMode::Relay,
        vec![primary.url.clone(), secondary.url.clone()],
        vec![
            Filter::new()
                .kind(Kind::Custom(FIPS_PEER_ADVERT_KIND))
                .limit(RELAY_REPLAY_LIMIT),
        ],
        owner.public_key(),
    )
    .await
    .unwrap();

    // Deliberately stop downstream consumption through two recovery requests.
    // Unlike the earlier fixture, the relay never gates its replay responses.
    tokio::time::timeout(Duration::from_secs(3), async {
        while primary.request_count() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("replay overlaps full ingress");
    assert_eq!(provider.as_ref().unwrap().notifications.len(), capacity);
    assert!(primary.sent.load(Ordering::Relaxed) > count);
    let requests_before_drain = primary.request_count();

    let mut consumed = Vec::new();
    let drain = tokio::time::sleep(Duration::from_secs(4));
    tokio::pin!(drain);
    loop {
        let delivery = tokio::select! {
            _ = &mut drain => break,
            delivery = relay_notification(&mut provider) => delivery.unwrap(),
        };
        let observation = (delivery.event.as_event().id, delivery.source.clone());
        // Keep the real sequential consumer slow as recovery overlaps its work.
        tokio::time::sleep(Duration::from_millis(3)).await;
        process_relay_delivery(&endpoint, &client, &events, &policy, &updates, delivery).await;
        consumed.push(observation);
    }
    assert!(
        events
            .lock()
            .await
            .snapshot()
            .iter()
            .any(|event| event.id == marker.id)
    );
    assert_eq!(provider.as_ref().unwrap().notifications.len(), 0);
    let settled_requests = [primary.request_count(), secondary.request_count()];
    assert!(
        settled_requests[0] <= 4,
        "replay continued after consumer release: {settled_requests:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(3), relay_notification(&mut provider))
            .await
            .is_err(),
        "retained replay must quiesce after pressure drains"
    );
    assert_eq!(
        settled_requests,
        [primary.request_count(), secondary.request_count()]
    );

    let before_later = consumed.len();
    for relay in [&primary, &secondary] {
        relay.publish.send(marker.clone()).await.unwrap();
        let delivery =
            tokio::time::timeout(Duration::from_secs(1), relay_notification(&mut provider))
                .await
                .expect("later observation deadline")
                .unwrap();
        assert_eq!(delivery.event.as_event().id, marker.id);
        assert_eq!(delivery.source, EventSource::relay(relay.url.clone()));
        assert!(verified_event_is_admitted(&policy, &delivery.event, &delivery.source).await);
        let observation = (delivery.event.as_event().id, delivery.source.clone());
        process_relay_delivery(&endpoint, &client, &events, &policy, &updates, delivery).await;
        consumed.push(observation);
    }
    assert_eq!(consumed.len(), before_later + 2);
    assert_eq!(
        settled_requests,
        [primary.request_count(), secondary.request_count()]
    );
    let times = primary.requests.lock().unwrap().clone();
    let request_ms = times
        .iter()
        .map(|time| time.duration_since(times[0]).as_millis())
        .collect::<Vec<_>>();
    eprintln!(
        "INGRESS_OVERLAP_COUNTS {}",
        serde_json::json!({
            "initialDistinctEvents": count, "queueCapacity": capacity,
            "primaryRequestsBeforeDrain": requests_before_drain, "consumerDelayMilliseconds": 3,
            "primaryRequests": settled_requests[0], "secondaryRequests": settled_requests[1],
            "primaryRequestMilliseconds": request_ms, "primaryEventsSent": primary.sent.load(Ordering::Relaxed),
            "completedConsumerCalls": consumed.len(), "laterObservations": consumed.len() - before_later,
            "uniqueProcessedEvents": consumed.iter().map(|(id, _)| *id).collect::<HashSet<_>>().len(),
            "queueAfterDrain": provider.as_ref().unwrap().notifications.len(),
        })
    );
    let provider = provider.take().unwrap();
    provider._subscription.close().await.unwrap();
    provider.bus.client().shutdown().await;
    client.shutdown_shared().await;
    endpoint.shutdown().await.unwrap();
    primary.stop().await;
    secondary.stop().await;
}
