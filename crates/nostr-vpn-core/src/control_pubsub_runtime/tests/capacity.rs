#![cfg(feature = "paid-exit")]

use super::*;

#[test]
fn endpoint_capacity_serves_the_sixty_fifth_connected_peer_without_relays() {
    run_async_test("pubsub-endpoint-capacity", capacity_round_trip);
}

async fn capacity_round_trip() {
    const LEAVES: usize = 65;
    let hub_key = Keys::generate();
    let hub_npub = hub_key.public_key().to_bech32().expect("hub npub");
    let mut leaf_keys = (0..LEAVES)
        .map(|_| {
            let key = Keys::generate();
            let npub = key.public_key().to_bech32().expect("leaf npub");
            (npub, key)
        })
        .collect::<Vec<_>>();
    leaf_keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let sockets = (0..=LEAVES)
        .map(|_| UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port"))
        .collect::<Vec<_>>();
    let ports = sockets
        .iter()
        .map(|socket| socket.local_addr().expect("UDP address").port())
        .collect::<Vec<_>>();
    drop(sockets);

    let peer_hints = leaf_keys
        .iter()
        .zip(&ports[1..])
        .map(|((npub, _), port)| (npub.as_str(), *port))
        .collect::<Vec<_>>();
    let mut hub_config = capacity_endpoint_config(ports[0], &peer_hints);
    hub_config.node.limits.max_peers = LEAVES;
    hub_config.node.limits.max_connections = LEAVES * 2;
    hub_config.node.limits.max_links = LEAVES * 2;
    let hub_pubsub_config = ControlPubsubEndpointConfig::from(&hub_config);
    let hub = endpoint(&hub_key, hub_config).await;
    let mut leaves = Vec::with_capacity(LEAVES);
    let mut leaf_pubsub_config = None;
    for ((_, key), port) in leaf_keys.iter().zip(&ports[1..]) {
        let config = capacity_endpoint_config(*port, &[(&hub_npub, ports[0])]);
        leaf_pubsub_config = Some(ControlPubsubEndpointConfig::from(&config));
        leaves.push(endpoint(key, config).await);
    }
    let connected = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let peers = hub.peers().await.expect("hub peers");
            if peers.iter().filter(|peer| peer.connected).count() == LEAVES {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if connected.is_err() {
        let peers = hub.peers().await.expect("hub peer diagnostics");
        for leaf in &leaves {
            leaf.shutdown().await.expect("shutdown leaf");
        }
        hub.shutdown().await.expect("shutdown hub");
        panic!(
            "only {}/{} physical UDP leaves connected",
            peers.iter().filter(|peer| peer.connected).count(),
            LEAVES
        );
    }

    // Only the hub and the identity sorted after the old 64-peer cutoff run
    // pubsub. The other endpoints exercise physical capacity without creating
    // 65 pubsub services or providing an alternate event-delivery path.
    let last_leaf = leaves.last().expect("last leaf");
    let hub_pubsub = capacity_runtime(Arc::clone(&hub), &hub_pubsub_config).await;
    let leaf_pubsub = capacity_runtime(
        Arc::clone(last_leaf),
        &leaf_pubsub_config.expect("leaf pubsub config"),
    )
    .await;
    let delivered = tokio::time::timeout(Duration::from_secs(30), async {
        for runtime in [&hub_pubsub, &leaf_pubsub] {
            while runtime.connected_peer_count().await? == 0
                || runtime.peer_subscription_count().await? == 0
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        let from_leaf = capacity_offer(&leaf_keys.last().expect("last key").1, "capacity-leaf");
        anyhow::ensure!(
            leaf_pubsub.publish(from_leaf.clone()).await?,
            "leaf publish"
        );
        capacity_wait_for_event(&hub_pubsub, from_leaf.id).await;

        let from_hub = capacity_offer(&hub_key, "capacity-hub");
        anyhow::ensure!(hub_pubsub.publish(from_hub.clone()).await?, "hub publish");
        capacity_wait_for_event(&leaf_pubsub, from_hub.id).await;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    leaf_pubsub.stop().await;
    hub_pubsub.stop().await;
    for leaf in leaves {
        leaf.shutdown().await.expect("shutdown leaf");
    }
    hub.shutdown().await.expect("shutdown hub");
    delivered
        .expect("the 65th physical peer exchanges control events in both directions")
        .expect("control publication succeeds");
}

fn capacity_endpoint_config(port: u16, peers: &[(&str, u16)]) -> Config {
    let mut config = endpoint_config(port, peers);
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config
}

async fn capacity_runtime(
    endpoint: Arc<FipsEndpoint>,
    config: &ControlPubsubEndpointConfig,
) -> ControlPubsubFipsRuntime {
    ControlPubsubFipsRuntime::start_for_peers_with_endpoint_config(
        endpoint,
        config,
        NostrPubsubConfig {
            mode: NostrPubsubMode::Client,
            ..NostrPubsubConfig::default()
        },
        Vec::new(),
        None,
        &[],
    )
    .await
    .expect("start capacity pubsub runtime")
    .expect("pubsub enabled")
}

fn capacity_offer(keys: &Keys, name: &str) -> Event {
    let mut config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    config.pricing.price_msat_per_gb = 25;
    config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    signed_paid_exit_offer_from_config(name, keys, &config, None, Timestamp::now().as_secs())
        .expect("signed capacity offer")
        .event
}

async fn capacity_wait_for_event(runtime: &ControlPubsubFipsRuntime, event_id: EventId) {
    while !runtime
        .events()
        .await
        .iter()
        .any(|event| event.id == event_id)
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
