use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use fips_core::config::{
    ConnectPolicy, NostrDiscoveryPolicy, PeerConfig, RoutingMode, TransportInstances,
    WebSocketConfig,
};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, encode_nsec};
use nostr_vpn_core::config::DEFAULT_FIPS_WEBSOCKET_SEEDS;
use nostr_vpn_core::fips_control::{FipsControlFrame, PeerCapabilities};
use nostr_vpn_core::fips_control_tcp::FipsControlTcpRuntime;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Match the production FIPS session-handshake retry window instead of
// aborting before its exponential backoff can reach the later retries.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(35);
const PUBLIC_END_TO_END_TIMEOUT: Duration = Duration::from_secs(75);
const LOCAL_CHURN_ROUNDS: usize = 20;
const LOCAL_BUSY_SEED_CLIENTS: usize = 24;

/// Real release probe for the deployed public FIPS transit service.
///
/// The two generated endpoints each know only one public WebSocket seed's
/// identity and URL. They do not advertise, use local discovery, or configure
/// one another, so successful delivery proves cross-seed route-by-npub over
/// authenticated transit rather than a direct transport connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the deployed public FIPS transit service"]
async fn public_transit_routes_fips_control_by_npub_without_direct_peer_config() {
    tokio::time::timeout(PUBLIC_END_TO_END_TIMEOUT, public_transit_round())
        .await
        .expect("public cross-seed FIPS-TCP gate exceeded 75 seconds");
}

async fn public_transit_round() {
    assert!(
        DEFAULT_FIPS_WEBSOCKET_SEEDS.len() >= 2,
        "the cross-transit release probe requires two public seeds"
    );
    let (first, second) = tokio::join!(public_transit_endpoint(0), public_transit_endpoint(1));
    eprintln!(
        "public transit clients: first={} second={}",
        first.npub(),
        second.npub()
    );

    assert_no_direct_physical_peer(&first, second.npub()).await;
    assert_no_direct_physical_peer(&second, first.npub()).await;

    let mut first_control = FipsControlTcpRuntime::start(Arc::clone(&first))
        .await
        .expect("bind first control service");
    let mut second_control = FipsControlTcpRuntime::start(Arc::clone(&second))
        .await
        .expect("bind second control service");

    deliver_ping(
        &first_control,
        &mut second_control,
        first.npub(),
        second.npub(),
        "first-to-second",
    )
    .await;
    deliver_ping(
        &second_control,
        &mut first_control,
        second.npub(),
        first.npub(),
        "second-to-first",
    )
    .await;

    second_control.stop().await;
    first_control.stop().await;
    second.shutdown().await.expect("shutdown second endpoint");
    first.shutdown().await.expect("shutdown first endpoint");
}

/// Production-shaped local regression for the exact state-control transport
/// used by manual join and roster delivery. Seed two has the sole inter-seed
/// adjacency; each fresh client is pinned to a different seed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running persistent WSS/FIPS-TCP churn regression"]
async fn local_two_seed_fips_tcp_transit_survives_client_churn() {
    let first_seed_url = available_websocket_url();
    let second_seed_url = available_websocket_url();
    let first_seed_identity = Identity::generate();
    let first_seed_npub = first_seed_identity.npub();
    let second_seed_identity = Identity::generate();
    let second_seed_npub = second_seed_identity.npub();

    let mut first_seed_config = local_transit_config(Some(&first_seed_url), None);
    first_seed_config.node.identity.nsec =
        Some(encode_nsec(&first_seed_identity.keypair().secret_key()));
    first_seed_config.peers.push(configured_listener_peer(
        &second_seed_npub,
        &second_seed_url,
    ));
    let first_seed = bind_local_transit_endpoint(first_seed_config).await;

    let mut second_seed_config = local_transit_config(
        Some(&second_seed_url),
        Some((&first_seed_npub, &first_seed_url)),
    );
    second_seed_config.node.identity.nsec =
        Some(encode_nsec(&second_seed_identity.keypair().secret_key()));
    let second_seed = bind_local_transit_endpoint(second_seed_config).await;
    tokio::join!(
        wait_for_connected_peer(&first_seed, &second_seed_npub),
        wait_for_connected_peer(&second_seed, &first_seed_npub),
    );

    let mut busy_seed_clients = Vec::with_capacity(LOCAL_BUSY_SEED_CLIENTS);
    for _ in 0..LOCAL_BUSY_SEED_CLIENTS {
        busy_seed_clients
            .push(local_transit_endpoint(None, Some((&first_seed_npub, &first_seed_url))).await);
    }
    for client in &busy_seed_clients {
        wait_for_expected_transit(client, &first_seed_npub).await;
    }

    for round in 0..LOCAL_CHURN_ROUNDS {
        let (first, second) = tokio::join!(
            local_transit_endpoint(None, Some((&first_seed_npub, &first_seed_url))),
            local_transit_endpoint(None, Some((&second_seed_npub, &second_seed_url))),
        );
        wait_for_expected_transit(&first, &first_seed_npub).await;
        wait_for_expected_transit(&second, &second_seed_npub).await;
        assert_no_direct_physical_peer(&first, second.npub()).await;
        assert_no_direct_physical_peer(&second, first.npub()).await;

        let mut first_control = FipsControlTcpRuntime::start(Arc::clone(&first))
            .await
            .expect("bind first local control service");
        let mut second_control = FipsControlTcpRuntime::start(Arc::clone(&second))
            .await
            .expect("bind second local control service");

        deliver_ping(
            &first_control,
            &mut second_control,
            first.npub(),
            second.npub(),
            &format!("local-first-to-second-{round}"),
        )
        .await;
        deliver_ping(
            &second_control,
            &mut first_control,
            second.npub(),
            first.npub(),
            &format!("local-second-to-first-{round}"),
        )
        .await;

        second_control.stop().await;
        first_control.stop().await;
        let (first_shutdown, second_shutdown) = tokio::join!(first.shutdown(), second.shutdown());
        first_shutdown.expect("shutdown first local client");
        second_shutdown.expect("shutdown second local client");
    }

    for client in busy_seed_clients {
        client.shutdown().await.expect("shutdown busy-seed client");
    }
    let (first_shutdown, second_shutdown) =
        tokio::join!(first_seed.shutdown(), second_seed.shutdown());
    first_shutdown.expect("shutdown first local seed");
    second_shutdown.expect("shutdown second local seed");
}

async fn public_transit_endpoint(seed_index: usize) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    let (expected_seed_npub, seed_url) = DEFAULT_FIPS_WEBSOCKET_SEEDS
        .get(seed_index)
        .expect("public seed index");
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        seed_urls: vec![(*seed_url).to_string()],
        max_connections: Some(1),
        ..WebSocketConfig::default()
    });
    config.peers = vec![PeerConfig::new(*expected_seed_npub, "websocket", *seed_url)];

    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .expect("bind public-transit endpoint"),
    );
    wait_for_expected_transit(&endpoint, expected_seed_npub).await;
    endpoint
}

async fn wait_for_expected_transit(endpoint: &FipsEndpoint, expected_seed_npub: &str) {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            let peers = endpoint.peers().await.expect("query endpoint peers");
            if peers
                .iter()
                .any(|peer| peer.connected && peer.npub == expected_seed_npub)
            {
                assert!(
                    peers
                        .iter()
                        .filter(|peer| peer.connected)
                        .all(|peer| peer.npub == expected_seed_npub),
                    "public WebSocket URL authenticated an unexpected seed identity"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("endpoint did not authenticate to the expected public WebSocket seed");
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, expected_npub: &str) {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            if endpoint
                .peers()
                .await
                .expect("query endpoint peers")
                .iter()
                .any(|peer| peer.connected && peer.npub == expected_npub)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("endpoint did not authenticate expected peer {expected_npub}"));
}

async fn assert_no_direct_physical_peer(endpoint: &FipsEndpoint, remote_npub: &str) {
    assert!(
        endpoint
            .peers()
            .await
            .expect("endpoint peers")
            .iter()
            .all(|peer| peer.npub != remote_npub),
        "route-by-npub test established a forbidden direct physical peer"
    );
}

fn available_websocket_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve WebSocket listener port");
    let port = listener
        .local_addr()
        .expect("read reserved WebSocket listener port")
        .port();
    drop(listener);
    format!("ws://127.0.0.1:{port}/fips")
}

async fn local_transit_endpoint(
    bind_url: Option<&str>,
    seed: Option<(&str, &str)>,
) -> Arc<FipsEndpoint> {
    bind_local_transit_endpoint(local_transit_config(bind_url, seed)).await
}

fn local_transit_config(bind_url: Option<&str>, seed: Option<(&str, &str)>) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.nostr.policy = if bind_url.is_some() {
        NostrDiscoveryPolicy::Open
    } else {
        NostrDiscoveryPolicy::ConfiguredOnly
    };
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.rate_limit.handshake_resend_interval_ms = 50;
    config.node.rate_limit.handshake_max_resends = 20;
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        bind_addr: bind_url.map(websocket_bind_address),
        seed_urls: seed
            .map(|(_, seed_url)| vec![seed_url.to_string()])
            .unwrap_or_default(),
        max_connections: bind_url.is_none().then_some(1),
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..WebSocketConfig::default()
    });
    if let Some((seed_npub, seed_url)) = seed {
        config
            .peers
            .push(PeerConfig::new(seed_npub, "websocket", seed_url));
    }
    config
}

async fn bind_local_transit_endpoint(config: Config) -> Arc<FipsEndpoint> {
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .expect("bind local transit endpoint"),
    )
}

fn configured_listener_peer(npub: &str, url: &str) -> PeerConfig {
    let mut peer = PeerConfig::new(npub, "websocket", url);
    peer.connect_policy = ConnectPolicy::Manual;
    peer
}

fn websocket_bind_address(url: &str) -> String {
    url.strip_prefix("ws://")
        .and_then(|url| url.strip_suffix("/fips"))
        .expect("loopback WebSocket URL")
        .to_string()
}

async fn deliver_ping(
    sender: &FipsControlTcpRuntime,
    receiver: &mut FipsControlTcpRuntime,
    sender_npub: &str,
    recipient_npub: &str,
    network_id: &str,
) {
    let recipient = PeerIdentity::from_npub(recipient_npub).expect("recipient identity");
    let frame = FipsControlFrame::Capabilities {
        network_id: network_id.to_string(),
        capabilities: PeerCapabilities::default(),
    };
    tokio::time::timeout(ROUTE_TIMEOUT, sender.send(recipient, &frame))
        .await
        .unwrap_or_else(|_| panic!("{network_id}: route-by-npub send timed out"))
        .unwrap_or_else(|error| panic!("{network_id}: route-by-npub send failed: {error:#}"));
    let received = tokio::time::timeout(ROUTE_TIMEOUT, receiver.recv())
        .await
        .unwrap_or_else(|_| panic!("{network_id}: route-by-npub receive timed out"))
        .unwrap_or_else(|| panic!("{network_id}: control service closed"));
    assert_eq!(received.frame, frame);
    assert_eq!(received.source_peer.npub(), sender_npub);
}
