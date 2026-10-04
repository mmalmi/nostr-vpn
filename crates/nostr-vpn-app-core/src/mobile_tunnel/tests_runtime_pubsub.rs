#[test]
fn mobile_relay_discovery_uses_shared_pubsub_across_reconnect_and_restart() {
    std::thread::Builder::new()
        .name("mobile-relay-pubsub".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            RuntimeBuilder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(mobile_relay_pubsub_roundtrip());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn mobile_relay_pubsub_roundtrip() {
    use futures_util::{SinkExt, StreamExt};
    use nostr_sdk::prelude::{EventBuilder, Kind, Tag, TagKind, Timestamp};
    use tokio_tungstenite::tungstenite::Message;

    let peer_keys = Keys::generate();
    let advert = EventBuilder::new(
        Kind::Custom(37_195),
        serde_json::json!({
            "identifier": "fips-overlay-v1", "version": 1,
            "endpoints": [{"transport": "udp", "addr": "nat"}],
            "stun_servers": ["stun:127.0.0.1:9"]
        })
        .to_string(),
    )
    .tags([
        Tag::identifier("fips-overlay-v1"),
        Tag::custom(TagKind::custom("protocol"), ["fips-overlay-v1"]),
        Tag::custom(TagKind::custom("version"), ["1"]),
        Tag::expiration(Timestamp::from(unix_timestamp() + 600)),
    ])
    .sign_with_keys(&peer_keys)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let seen_connections = Arc::clone(&connections);
    let replay = advert.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let connection = seen_connections.fetch_add(1, Ordering::SeqCst);
            while let Some(Ok(message)) = socket.next().await {
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message.into_data())
                else {
                    continue;
                };
                match value[0].as_str() {
                    Some("REQ") => {
                        socket
                            .send(Message::Text(
                                serde_json::json!(["EVENT", value[1], replay])
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                        socket
                            .send(Message::Text(
                                serde_json::json!(["EOSE", value[1]]).to_string().into(),
                            ))
                            .await
                            .unwrap();
                        if connection == 0 {
                            socket.close(None).await.unwrap();
                            break;
                        }
                    }
                    Some("EVENT") => {
                        socket
                            .send(Message::Text(
                                serde_json::json!(["OK", value[1]["id"], true, ""])
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let mut app = AppConfig::generated();
    app.nostr.relays = vec![relay_url.clone()];
    app.fips_bootstrap_enabled = false;
    app.fips_bootstrap_peers.clear();
    app.fips_websocket_seed_urls.clear();
    app.fips_webrtc_enabled = false;
    app.lan_discovery_enabled = false;
    let network = app.networks[0].id.clone();
    app.add_participant_to_network(&network, &peer_keys.public_key().to_hex())
        .unwrap();
    for expected_connections in [2, 3] {
        let mut config = MobileTunnelConfig::from_app(&app).unwrap();
        config.listen_port = available_udp_port();
        config.stun_servers = vec!["stun:127.0.0.1:9".to_string()];
        let mobile = Box::pin(MobileTunnel::start_async(config, app.clone()))
            .await
            .unwrap();
        let pubsub = mobile
            .control_pubsub
            .as_ref()
            .expect("mobile owns one shared pubsub runtime");
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let relays = pubsub.relay_statuses().await;
                if connections.load(Ordering::SeqCst) >= expected_connections
                    && relays.iter().any(|relay| {
                        relay.url.trim_end_matches('/') == relay_url && relay.status == "connected"
                    })
                    && pubsub
                        .events()
                        .await
                        .iter()
                        .any(|event| event.id == advert.id)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("historical peer advert and live relay status survive reconnect/restart");
        assert_eq!(
            connections.load(Ordering::SeqCst),
            expected_connections,
            "FIPS must not open a second relay connection"
        );
        shutdown_started_mobile_tunnel(mobile).await;
    }
    server.abort();
    let _ = server.await;
}
