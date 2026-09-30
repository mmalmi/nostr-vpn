use super::*;
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::{ClientMessage, JsonUtil, RelayMessage};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

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
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("relay connection");
            let mut socket = accept_async(stream).await.expect("relay websocket");
            let mut first = true;
            let mut replayed = Some(replayed);
            let mut replay_ready = Some(replay_ready);
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
                    messages.push(RelayMessage::eose(id));
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
            }
        });

        let mut provider = RelayProvider::start(
            NostrPubsubMode::Relay,
            vec![url],
            &update_events(&keys, "ingress-recovery"),
            &[],
            keys.public_key(),
        )
        .await
        .expect("production relay provider")
        .expect("relay enabled");
        tokio::time::timeout(Duration::from_secs(3), replay_request)
            .await
            .expect("full ingress requests retained-event replay")
            .expect("replay request observed");
        assert_eq!(provider.notifications.len(), capacity);
        while let Ok(delivery) = provider.notifications.try_recv() {
            assert_ne!(delivery.event.as_event().id, expected);
        }
        resume
            .send(())
            .expect("allow retained replay after draining");
        let delivery = tokio::time::timeout(Duration::from_secs(3), provider.notifications.recv())
            .await
            .expect("retained control event is admitted")
            .expect("provider remains live");
        assert_eq!(delivery.event.as_event().id, expected);
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
