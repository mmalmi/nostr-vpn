const FIPS_TEST_EVENTUAL_TIMEOUT: Duration = Duration::from_secs(15);

fn available_udp_ports() -> [u16; 3] {
    let sockets = (0..3)
        .map(|_| UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP port"))
        .collect::<Vec<_>>();
    let ports = [
        sockets[0].local_addr().expect("Alice UDP address").port(),
        sockets[1].local_addr().expect("Bob UDP address").port(),
        sockets[2].local_addr().expect("Carol UDP address").port(),
    ];
    drop(sockets);
    ports
}

fn endpoint_config(local_port: u16, peers: &[(&str, u16)]) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(format!("127.0.0.1:{local_port}")),
        accept_connections: Some(true),
        ..UdpConfig::default()
    });
    config.peers.extend(
        peers
            .iter()
            .map(|(npub, port)| PeerConfig::new(*npub, "udp", format!("127.0.0.1:{port}"))),
    );
    config
}

fn available_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("ephemeral TCP address")
        .port()
}

fn websocket_listener_config(port: u16) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        bind_addr: Some(format!("127.0.0.1:{port}")),
        ..WebSocketConfig::default()
    });
    config
}

fn websocket_seed_config(seed_url: &str) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        seed_urls: vec![seed_url.to_string()],
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(40),
        ..WebSocketConfig::default()
    });
    config
}

async fn endpoint(keys: &Keys, config: Config) -> Arc<FipsEndpoint> {
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .identity_nsec(keys.secret_key().to_bech32().expect("nsec"))
            .without_system_tun()
            .bind()
            .await
            .expect("bind FIPS endpoint"),
    )
}

async fn wait_connected(endpoint: &FipsEndpoint, peer_npub: &str) {
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            if endpoint
                .peers()
                .await
                .unwrap_or_default()
                .iter()
                .any(|peer| peer.connected && peer.npub == peer_npub)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("FIPS peer connected");
}

async fn assert_udp_link(endpoint: &FipsEndpoint, peer_npub: &str) {
    let peers = endpoint.peers().await.expect("FIPS peer snapshot");
    let peer = peers
        .iter()
        .find(|peer| peer.npub == peer_npub && peer.connected)
        .expect("connected FIPS peer");
    assert_eq!(peer.transport_type.as_deref(), Some("udp"));
}

fn update_events(publisher: &Keys, tree_name: &str) -> UpdateEventCache {
    let reference = UpdateRef {
        npub: publisher.public_key().to_bech32().expect("publisher npub"),
        tree_name: tree_name.to_string(),
        path: Some("latest".to_string()),
    };
    UpdateEventCache::new(&reference).expect("update event cache")
}

async fn start_pubsub(
    endpoint: Arc<FipsEndpoint>,
    update_events: UpdateEventCache,
) -> ControlPubsubFipsRuntime {
    ControlPubsubFipsRuntime::start_inner(
        endpoint,
        NostrPubsubConfig {
            mode: NostrPubsubMode::Client,
            fanout: 8,
            max_hops: 4,
            max_event_bytes: CONTROL_PUBSUB_MAX_EVENT_BYTES,
        },
        Vec::new(),
        None,
        None,
        Some(update_events),
        &[],
    )
    .await
    .expect("start FIPS pubsub")
    .expect("FIPS pubsub enabled")
}

async fn wait_for_event(runtime: &ControlPubsubFipsRuntime, event_id: EventId) {
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            if runtime
                .events()
                .await
                .iter()
                .any(|event| event.id == event_id)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("control event arrived over FIPS pubsub");
}

async fn wait_pubsub_connected(runtime: &ControlPubsubFipsRuntime) {
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            let peer_count = runtime.connected_peer_count().await.unwrap_or_default();
            if peer_count > 0
                && runtime.peer_subscription_count().await.unwrap_or_default() >= peer_count
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("reliable TCP/FIPS pubsub stream connected");
}

async fn wait_pubsub_transport_connected(runtime: &ControlPubsubFipsRuntime) {
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            if runtime.connected_peer_count().await.unwrap_or_default() > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("reliable TCP/FIPS pubsub transport connected");
}

fn run_async_test<F, Fut>(name: &str, run: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("local control pubsub test runtime")
                .block_on(run());
        })
        .expect("spawn control pubsub test")
        .join()
        .expect("control pubsub test thread");
}
