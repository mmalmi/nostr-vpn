use super::routed::signed_note;
use super::*;
use fips_core::config::{RoutingMode, WebSocketConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routed_pubsub_recovers_after_seed_only_websocket_transit_restart() {
    run_restart(1, 1, RoutingMode::Tree).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seventy_event_outbox_recovers_after_seed_only_websocket_transit_restart() {
    run_restart(70, 1, RoutingMode::Tree).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learned_route_outbox_recovers_after_websocket_transit_restart() {
    run_restart(70, 64, RoutingMode::ReplyLearned).await;
}

async fn run_restart(event_count: usize, peer_capacity: usize, mode: RoutingMode) {
    let (address, router_config) = router_config();
    let transit = endpoint([101; 32], router_config.clone(), RoutingMode::Tree).await;
    let leaf_config = WebSocketConfig {
        seed_urls: vec![format!("ws://{address}/fips")],
        ..Default::default()
    };
    let a = endpoint([102; 32], leaf_config.clone(), mode).await;
    let c = endpoint([103; 32], leaf_config, mode).await;
    let options = |npub: &str| FipsPubsubClientOptions {
        routed_peers: vec![npub.to_owned()],
        max_connected_peers: peer_capacity,
        fanout: 1,
        max_replay_events: 64,
        ..Default::default()
    };
    let publisher = FipsPubsubClient::start(a.clone(), options(c.npub()))
        .await
        .unwrap();
    let receiver = FipsPubsubClient::start(c.clone(), options(a.npub()))
        .await
        .unwrap();
    let mut subscription = receiver
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    timeout(Duration::from_secs(30), async {
        while publisher.peer_subscription_count().unwrap() != 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("WebSocket seed-only subscribers connect");
    let first = signed_note(&"warm connection before outage ".repeat(1024));
    publisher
        .publish(first.clone(), EventSource::local_index("outbox"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), subscription.recv())
            .await
            .unwrap()
            .unwrap()
            .event,
        first
    );

    transit.shutdown().await.unwrap();
    let offline = (0..event_count)
        .map(|i| signed_note(&format!("offline event {i} {}", "x".repeat(4096))))
        .collect::<Vec<_>>();
    for event in &offline {
        publisher
            .publish(event.clone(), EventSource::local_index("outbox"))
            .await
            .unwrap();
        if mode == RoutingMode::ReplyLearned {
            // Match application work spread over several transport poll turns.
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
    let transit = endpoint([101; 32], router_config, RoutingMode::Tree).await;
    let mut ids = HashSet::new();
    let delivered = timeout(Duration::from_secs(40), async {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut cursor = 0;
        while ids.len() < event_count {
            tokio::select! {
                event = subscription.recv() => { ids.insert(event.unwrap().event.as_event().id); }
                _ = tick.tick(), if event_count > 1 => {
                    for i in 0..16.min(event_count) {
                        publisher.publish(offline[(cursor+i)%event_count].clone(), EventSource::local_index("outbox")).await.unwrap();
                    }
                    cursor = (cursor+16)%event_count;
                }
            }
        }
    }).await;
    if delivered.is_err() {
        report_failure(&publisher, &receiver, &[&a, &transit, &c]).await;
    }
    delivered.unwrap_or_else(|_| {
        panic!(
            "seed-only routed stream delivered {}/{event_count} events",
            ids.len()
        )
    });
    assert_eq!(
        ids,
        offline.iter().map(|event| event.as_event().id).collect()
    );
    drop(subscription);
    publisher.shutdown().await;
    receiver.shutdown().await;
    for endpoint in [a, transit, c] {
        endpoint.shutdown().await.unwrap();
    }
}

async fn endpoint(
    secret: [u8; 32],
    websocket: WebSocketConfig,
    mode: RoutingMode,
) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.routing.mode = mode;
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.transports.websocket = TransportInstances::Single(websocket);
    Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind(),
        )
        .await
        .unwrap(),
    )
}

async fn report_failure(
    publisher: &FipsPubsubClient,
    receiver: &FipsPubsubClient,
    endpoints: &[&Arc<FipsEndpoint>],
) {
    for endpoint in endpoints {
        eprintln!(
            "peers={:?}",
            endpoint
                .peers()
                .await
                .unwrap()
                .iter()
                .map(|p| (p.connected, p.link_id, p.bytes_sent, p.bytes_recv))
                .collect::<Vec<_>>()
        );
    }
    eprintln!(
        "publisher={:?} receiver={:?} transport_errors={:?}",
        publisher.delivery_snapshot(),
        receiver.delivery_snapshot(),
        (
            publisher.transport_error_count(),
            receiver.transport_error_count()
        )
    );
}

fn router_config() -> (std::net::SocketAddr, WebSocketConfig) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let router_config = WebSocketConfig {
        bind_addr: Some(address.to_string()),
        ..Default::default()
    };
    (address, router_config)
}
