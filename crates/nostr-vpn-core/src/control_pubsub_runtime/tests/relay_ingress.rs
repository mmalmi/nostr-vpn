use super::*;
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::{ClientMessage, JsonUtil, RelayMessage};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[path = "relay_ingress_overlap.rs"]
mod overlap;

#[test]
fn relay_ingress_preserves_distinct_source_observations() {
    run_async_test("relay-ingress-sources", || async {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND), "same event")
            .sign_with_keys(&keys)
            .expect("signed event");
        let mut urls = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("local relay");
            urls.push(format!("ws://{}", listener.local_addr().unwrap()));
            let event = event.clone();
            servers.push(tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = accept_async(stream).await.unwrap();
                while let Some(Ok(frame)) = socket.next().await {
                    let Ok(ClientMessage::Req {
                        subscription_id,
                        filters,
                    }) = ClientMessage::from_json(frame.into_data())
                    else {
                        continue;
                    };
                    let id = subscription_id.into_owned();
                    if filters
                        .iter()
                        .any(|filter| filter.match_event(&event, MatchEventOptions::new()))
                    {
                        socket
                            .send(Message::Text(
                                RelayMessage::event(id.clone(), event.clone())
                                    .as_json()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                    }
                    socket
                        .send(Message::Text(RelayMessage::eose(id).as_json().into()))
                        .await
                        .unwrap();
                }
            }));
        }
        let mut provider = RelayProvider::start(
            None,
            NostrPubsubMode::Relay,
            urls,
            vec![
                Filter::new()
                    .kind(Kind::Custom(FIPS_PEER_ADVERT_KIND))
                    .limit(RELAY_REPLAY_LIMIT),
            ],
            keys.public_key(),
        )
        .await
        .expect("provider");
        assert!(provider.is_some(), "enabled relay provider");
        tokio::time::timeout(Duration::from_secs(3), async {
            while provider.as_ref().unwrap().notifications.len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("same ID from two sources must occupy two queue slots");
        let mut sources = HashSet::new();
        for _ in 0..2 {
            let delivery = relay_notification(&mut provider)
                .await
                .expect("distinct source delivery");
            assert_eq!(delivery.event.as_event().id, event.id);
            sources.insert(delivery.source);
        }
        assert_eq!(sources.len(), 2);
        let provider = provider.take().unwrap();
        provider
            ._subscription
            .close()
            .await
            .expect("close subscription");
        provider.bus.client().shutdown().await;
        for server in servers {
            server.abort();
            let _ = server.await;
        }
    });
}

#[test]
fn full_relay_ingress_requests_and_admits_retained_control_events() {
    run_async_test("relay-ingress-recovery", || async {
        let keys = Keys::generate();
        let capacity = RELAY_REPLAY_LIMIT * 5;
        let burst = (0..=capacity)
            .map(|index| {
                EventBuilder::new(
                    Kind::Custom(FIPS_PEER_ADVERT_KIND),
                    format!("retained control event {index}"),
                )
                .sign_with_keys(&keys)
                .expect("signed control event")
            })
            .collect::<Vec<_>>();
        let retained = burst.last().expect("overflow event").clone();
        let expected = retained.id;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("local relay");
        let url = format!("ws://{}", listener.local_addr().expect("relay address"));
        let (replayed, replay_request) = oneshot::channel();
        let (resume, replay_ready) = oneshot::channel();
        let (repeat, repeat_ready) = oneshot::channel();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("relay connection");
            let mut socket = accept_async(stream).await.expect("relay websocket");
            let mut first = true;
            let mut replayed = Some(replayed);
            let mut replay_ready = Some(replay_ready);
            let mut repeat_ready = Some(repeat_ready);
            while let Some(Ok(frame)) = socket.next().await {
                let Ok(ClientMessage::Req {
                    subscription_id,
                    filters,
                }) = ClientMessage::from_json(frame.into_data())
                else {
                    continue;
                };
                let id = subscription_id.into_owned();
                let matches = filters
                    .iter()
                    .any(|filter| filter.match_event(&retained, MatchEventOptions::new()));
                let mut messages = Vec::new();
                if matches && first {
                    first = false;
                    // Live events after EOSE are not limited by the initial
                    // retained-history window. Fill the real application queue.
                    messages.push(RelayMessage::eose(id.clone()));
                    // Overlapping interests and retained replay may repeat a
                    // verified event while its first copy is still queued.
                    messages.extend(
                        (0..capacity).map(|_| RelayMessage::event(id.clone(), burst[0].clone())),
                    );
                    messages.extend(
                        burst
                            .iter()
                            .cloned()
                            .map(|event| RelayMessage::event(id.clone(), event)),
                    );
                } else {
                    if matches {
                        replayed.take().expect("one replay signal").send(()).ok();
                        replay_ready
                            .take()
                            .expect("replay gate")
                            .await
                            .expect("drained ingress");
                        messages.push(RelayMessage::event(id.clone(), retained.clone()));
                    }
                    messages.push(RelayMessage::eose(id.clone()));
                }
                for message in messages {
                    if socket
                        .send(Message::Text(message.as_json().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                if matches
                    && replayed.is_none()
                    && let Some(ready) = repeat_ready.take()
                {
                    ready.await.expect("first replay consumed");
                    socket
                        .send(Message::Text(
                            RelayMessage::event(id, retained.clone()).as_json().into(),
                        ))
                        .await
                        .expect("later advert observation");
                }
            }
        });

        let mut provider = RelayProvider::start(
            None,
            NostrPubsubMode::Relay,
            vec![url],
            vec![
                Filter::new()
                    .kind(Kind::Custom(FIPS_PEER_ADVERT_KIND))
                    .limit(RELAY_REPLAY_LIMIT),
            ],
            keys.public_key(),
        )
        .await
        .expect("production relay provider");
        assert!(provider.is_some(), "relay enabled");
        tokio::time::timeout(Duration::from_secs(3), replay_request)
            .await
            .expect("full ingress requests retained-event replay")
            .expect("replay request observed");
        assert_eq!(provider.as_ref().unwrap().notifications.len(), capacity);
        let mut queued_ids = HashSet::new();
        for _ in 0..capacity {
            let delivery = relay_notification(&mut provider)
                .await
                .expect("queued delivery");
            assert_ne!(delivery.event.as_event().id, expected);
            queued_ids.insert(delivery.event.as_event().id);
        }
        assert_eq!(
            queued_ids.len(),
            capacity,
            "duplicate backlog wasted ingress capacity"
        );
        resume
            .send(())
            .expect("allow retained replay after draining");
        let delivery =
            tokio::time::timeout(Duration::from_secs(3), relay_notification(&mut provider))
                .await
                .expect("retained control event is admitted")
                .expect("provider remains live");
        assert_eq!(delivery.event.as_event().id, expected);
        repeat.send(()).expect("allow later advert observation");
        let later = tokio::time::timeout(Duration::from_secs(3), relay_notification(&mut provider))
            .await
            .expect("later repeat is not permanently deduplicated")
            .expect("later delivery");
        assert_eq!(later.event.as_event().id, expected);
        let provider = provider.take().unwrap();
        provider
            ._subscription
            .close()
            .await
            .expect("close subscription");
        provider.bus.client().shutdown().await;
        relay.abort();
        let _ = relay.await;
    });
}
