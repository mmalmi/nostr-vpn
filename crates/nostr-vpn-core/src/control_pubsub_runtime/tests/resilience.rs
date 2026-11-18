use super::*;
use crate::recent_peers::{RecentPeerEndpoints, recent_peers_scope};

struct RelaylessMesh {
    keys: Vec<Keys>,
    npubs: Vec<String>,
    ports: Vec<u16>,
    endpoints: Vec<Arc<FipsEndpoint>>,
    runtimes: Vec<ControlPubsubFipsRuntime>,
}

fn isolated_endpoint_config(port: u16, peers: &[(&str, u16)]) -> Config {
    let mut config = endpoint_config(port, peers);
    // A successful test must use the declared physical graph. Neither ambient
    // adverts, multicast nor same-host rendezvous may introduce a shortcut.
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config
}

async fn default_relayless_runtime(
    endpoint: Arc<FipsEndpoint>,
    updates: UpdateEventCache,
) -> ControlPubsubFipsRuntime {
    relayless_runtime(endpoint, updates, NostrPubsubConfig::default()).await
}

async fn relayless_runtime(
    endpoint: Arc<FipsEndpoint>,
    updates: UpdateEventCache,
    mut config: NostrPubsubConfig,
) -> ControlPubsubFipsRuntime {
    config.mode = NostrPubsubMode::Client;
    ControlPubsubFipsRuntime::start_inner(
        endpoint,
        config,
        Vec::new(),
        None,
        None,
        Some(updates),
        relay_advert_filters(None, &[]),
        MAX_PUBSUB_PEERS,
    )
    .await
    .expect("start default relayless runtime")
    .expect("pubsub enabled")
}

async fn wait_all_control_subscriptions(runtime: &ControlPubsubFipsRuntime, peers: usize) {
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            // Every adjacent runtime owns an advert, owner-graph and control
            // subscription. Wait for all three: late REQ replay must not mask
            // an insufficient live forwarding budget in the chain test.
            if runtime.connected_peer_count().await.unwrap_or_default() >= peers
                && runtime.peer_subscription_count().await.unwrap_or_default() >= peers * 3
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all adjacent peers subscribed to live control events");
}

impl RelaylessMesh {
    async fn start(neighbors: &[&[usize]], updates: UpdateEventCache) -> Self {
        let keys = (0..neighbors.len())
            .map(|_| Keys::generate())
            .collect::<Vec<_>>();
        let npubs = keys
            .iter()
            .map(|key| key.public_key().to_bech32().expect("peer npub"))
            .collect::<Vec<_>>();
        let sockets = (0..neighbors.len())
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port"))
            .collect::<Vec<_>>();
        let ports = sockets
            .iter()
            .map(|socket| socket.local_addr().expect("UDP address").port())
            .collect::<Vec<_>>();
        drop(sockets);
        let mut endpoints = Vec::new();
        for (index, adjacent) in neighbors.iter().enumerate() {
            let peers = adjacent
                .iter()
                .map(|&peer| (npubs[peer].as_str(), ports[peer]))
                .collect::<Vec<_>>();
            endpoints
                .push(endpoint(&keys[index], isolated_endpoint_config(ports[index], &peers)).await);
        }
        for (index, adjacent) in neighbors.iter().enumerate() {
            for &peer in *adjacent {
                wait_connected(&endpoints[index], &npubs[peer]).await;
            }
            let actual = endpoints[index]
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .filter(|peer| peer.connected)
                .count();
            assert_eq!(actual, adjacent.len(), "no undeclared physical links");
        }
        let mut runtimes = Vec::new();
        for endpoint in &endpoints {
            runtimes.push(default_relayless_runtime(Arc::clone(endpoint), updates.clone()).await);
        }
        for (runtime, adjacent) in runtimes.iter().zip(neighbors) {
            wait_all_control_subscriptions(runtime, adjacent.len()).await;
            assert!(runtime.relay_statuses().await.is_empty());
        }
        Self {
            keys,
            npubs,
            ports,
            endpoints,
            runtimes,
        }
    }

    async fn stop(self) {
        for runtime in self.runtimes {
            runtime.stop().await;
        }
        for endpoint in self.endpoints {
            endpoint.shutdown().await.expect("shutdown mesh endpoint");
        }
    }
}

#[test]
fn default_pubsub_delivers_live_updates_across_three_relayless_hops() {
    run_async_test("default-relayless-chain", || async {
        let publisher = Keys::generate();
        let tree = "releases/default-relayless-chain";
        let mut mesh = RelaylessMesh::start(
            &[&[1], &[0, 2], &[1, 3], &[2]],
            update_events(&publisher, tree),
        )
        .await;
        let event = signed_update_root(&publisher, tree, 1, "a1");
        assert!(mesh.runtimes[0].publish(event.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[3], event.id).await;
        // Exercise the same settled subscriptions in both directions.
        let reply = signed_update_root(&publisher, tree, 2, "a2");
        assert!(mesh.runtimes[3].publish(reply.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[0], reply.id).await;
        let source = mesh.runtimes.remove(0);
        source.stop().await;
        let legacy: NostrPubsubConfig = serde_json::from_str(
            r#"{"mode":"client","fanout":4,"max_hops":2,"max_event_bytes":57344}"#,
        )
        .expect("persisted legacy pubsub settings");
        let source = relayless_runtime(
            Arc::clone(&mesh.endpoints[0]),
            update_events(&publisher, tree),
            legacy,
        )
        .await;
        wait_all_control_subscriptions(&source, 1).await;
        let migrated = signed_update_root(&publisher, tree, 3, "a3");
        assert!(source.publish(migrated.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[2], migrated.id).await;
        source.stop().await;
        mesh.stop().await;
    });
}

#[test]
fn relayless_mesh_survives_bootstrap_loss_and_restarts_from_authenticated_peer() {
    run_async_test("relayless-bootstrap-loss", || async {
        let publisher = Keys::generate();
        let tree = "releases/relayless-bootstrap-loss";
        let updates = update_events(&publisher, tree);
        // A--B--C is independent of the bootstrap-like A--seed--C path.
        let mut mesh =
            RelaylessMesh::start(&[&[1, 3], &[0, 2], &[1, 3], &[0, 2]], updates.clone()).await;
        let scope = recent_peers_scope("relayless-bootstrap-loss");
        let mut cache = RecentPeerEndpoints::new(&mesh.npubs[2], &scope).unwrap();
        let neighbor = mesh.endpoints[2]
            .peers()
            .await
            .unwrap()
            .into_iter()
            .find(|peer| peer.npub == mesh.npubs[1] && peer.connected)
            .expect("authenticated alternate peer");
        assert!(
            cache
                .observe_authenticated_peer(&neighbor, now_ms() / 1_000)
                .unwrap()
        );
        let saved_peers = cache.to_json_pretty().unwrap();

        mesh.runtimes.pop().unwrap().stop().await;
        mesh.endpoints.pop().unwrap().shutdown().await.unwrap();
        // Publish only after the seed has stopped. A cached pre-outage event
        // would not establish that the surviving mesh can carry new traffic.
        let after_loss = signed_update_root(&publisher, tree, 1, "b1");
        assert!(mesh.runtimes[0].publish(after_loss.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[2], after_loss.id).await;

        mesh.runtimes.pop().unwrap().stop().await;
        mesh.endpoints.pop().unwrap().shutdown().await.unwrap();
        let offline = signed_update_root(&publisher, tree, 2, "b2");
        assert!(mesh.runtimes[0].publish(offline.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[1], offline.id).await;

        // The already-authorized identity is supplied by the application;
        // only its address comes from the serialized authenticated cache.
        let restored = RecentPeerEndpoints::from_json(&saved_peers, &mesh.npubs[2], &scope)
            .expect("restore owner-bound authenticated peer cache");
        let mut config = isolated_endpoint_config(mesh.ports[2], &[]);
        config.peers.push(PeerConfig {
            npub: mesh.npubs[1].clone(),
            ..PeerConfig::default()
        });
        assert_eq!(
            restored
                .as_recent_peers()
                .merge_into_peer_configs(&mut config.peers),
            1
        );
        let restarted_endpoint = endpoint(&mesh.keys[2], config).await;
        wait_connected(&restarted_endpoint, &mesh.npubs[1]).await;
        let restarted = default_relayless_runtime(Arc::clone(&restarted_endpoint), updates).await;
        wait_all_control_subscriptions(&restarted, 1).await;
        wait_for_event(&restarted, offline.id).await;
        let reply = signed_update_root(&publisher, tree, 3, "b3");
        assert!(restarted.publish(reply.clone()).await.unwrap());
        wait_for_event(&mesh.runtimes[0], reply.id).await;
        assert!(restarted.relay_statuses().await.is_empty());

        restarted.stop().await;
        restarted_endpoint.shutdown().await.unwrap();
        mesh.stop().await;
    });
}

#[test]
fn default_relay_mode_delivers_peer_events_when_every_relay_is_unreachable() {
    run_async_test("default-mode-relay-outage", || async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // Keep the TCP ports bound without listening so every connection
            // is refused and another test cannot claim either relay address.
            let unavailable_relays = (0..2)
                .map(|_| {
                    let socket = tokio::net::TcpSocket::new_v4().unwrap();
                    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                    socket
                })
                .collect::<Vec<_>>();
            let relay_urls = unavailable_relays
                .iter()
                .map(|socket| format!("ws://{}", socket.local_addr().unwrap()))
                .collect::<Vec<_>>();
            let keys = [Keys::generate(), Keys::generate()];
            let npubs = keys
                .each_ref()
                .map(|key| key.public_key().to_bech32().unwrap());
            let [first_port, second_port, _] = available_udp_ports();
            let first = endpoint(
                &keys[0],
                isolated_endpoint_config(first_port, &[(&npubs[1], second_port)]),
            )
            .await;
            let second = endpoint(
                &keys[1],
                isolated_endpoint_config(second_port, &[(&npubs[0], first_port)]),
            )
            .await;
            wait_connected(&first, &npubs[1]).await;
            wait_connected(&second, &npubs[0]).await;
            let publisher = Keys::generate();
            let tree = "releases/default-mode-relay-outage";
            let updates = update_events(&publisher, tree);
            let mut runtimes = Vec::new();
            for endpoint in [&first, &second] {
                let config = NostrPubsubConfig::default();
                assert_eq!(config.mode, NostrPubsubMode::Relay);
                runtimes.push(
                    ControlPubsubFipsRuntime::start_inner(
                        Arc::clone(endpoint),
                        config,
                        relay_urls.clone(),
                        None,
                        None,
                        Some(updates.clone()),
                        relay_advert_filters(None, &[]),
                        MAX_PUBSUB_PEERS,
                    )
                    .await
                    .expect("relay outage must not prevent FIPS pubsub startup")
                    .expect("default pubsub enabled"),
                );
            }
            for runtime in &runtimes {
                wait_all_control_subscriptions(runtime, 1).await;
                let relays = runtime.relay_statuses().await;
                assert_eq!(relays.len(), relay_urls.len());
                assert!(relays.iter().all(|relay| relay.status != "connected"));
            }
            let event = signed_update_root(&publisher, tree, 1, "c1");
            assert!(runtimes[0].publish(event.clone()).await.unwrap());
            wait_for_event(&runtimes[1], event.id).await;
            let reply = signed_update_root(&publisher, tree, 2, "c2");
            assert!(runtimes[1].publish(reply.clone()).await.unwrap());
            wait_for_event(&runtimes[0], reply.id).await;

            for runtime in runtimes {
                runtime.stop().await;
            }
            first.shutdown().await.unwrap();
            second.shutdown().await.unwrap();
            drop(unavailable_relays);
        })
        .await
        .expect("relay outage must not stall peer startup, delivery or shutdown");
    });
}
