use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

use fips_core::PeerIdentity;
use fips_endpoint::{
    Config, NostrPeerfindingSource, PeerConfig, RoutingMode, TransportInstances, UdpConfig,
    WebSocketConfig,
};
use nostr_pubsub::MeshPeer;
use nostr_sdk::prelude::{EventBuilder, EventId, Keys, Kind, Tag, TagKind, Timestamp, ToBech32};
use nostr_social_graph::Rating;
use nostr_social_memory::RatingEventExt;
use nostr_vpn_core::config::{NostrPubsubConfig, NostrPubsubMode};
use nostr_vpn_core::paid_routes::{
    PaidExitConfig, SignedPaidRouteOffer, signed_paid_exit_offer_from_config,
};
use nostr_vpn_core::updater::UpdateRef;

use super::*;

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

#[test]
fn relay_subscriptions_bound_retained_replay() {
    let publisher = Keys::generate();
    let target = Keys::generate().public_key();
    let update_events = update_events(&publisher, "releases/bounded-relay-replay");

    let filters = relay_subscription_filters(&update_events, &[target]);

    assert_eq!(filters.len(), 5);
    assert!(
        filters.iter().all(|filter| filter.limit.is_some()),
        "every public-relay subscription must bound retained replay"
    );
    assert_eq!(
        filters[0].authors.as_ref().map(|authors| authors.len()),
        Some(1)
    );
    for kind in [
        FIPS_PEER_ADVERT_KIND,
        PAID_EXIT_OFFER_KIND,
        RATING_FACT_KIND,
    ] {
        assert!(filters.iter().any(|filter| {
            filter
                .kinds
                .as_ref()
                .is_some_and(|kinds| kinds.len() == 1 && kinds.contains(&Kind::Custom(kind)))
        }));
    }
}

#[test]
fn fips_advert_refreshes_at_half_its_signed_lifetime() {
    let publisher = Keys::generate();
    let event = EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND), "")
        .tag(Tag::expiration(Timestamp::from(1_120)))
        .custom_created_at(Timestamp::from(1_000))
        .sign_with_keys(&publisher)
        .expect("signed advert");

    assert_eq!(fips_advert_refresh_delay(&event), Duration::from_secs(60));
}

#[test]
fn standard_fips_pubsub_bounds_retained_replay() {
    let publisher = Keys::generate();
    let update_events = update_events(&publisher, "releases/bounded-fips-replay");
    let options = fips_pubsub_options(CONTROL_PUBSUB_MAX_EVENT_BYTES, 4);
    let filters = fips_subscription_filters(&update_events);

    assert_eq!(options.max_replay_events, FIPS_REPLAY_LIMIT);
    assert_eq!(filters.len(), 2);
    assert_eq!(
        filters[0].kinds.as_ref(),
        Some(&control_kinds().into_iter().collect())
    );
    let update = signed_update_root(&publisher, "releases/bounded-fips-replay", 1, "ab");
    assert!(
        filters[1].match_event(&update, MatchEventOptions::new()),
        "configured hashtree updates must remain in the long-lived FIPS subscription"
    );
    assert!(
        filters
            .iter()
            .all(|filter| filter.limit == Some(FIPS_REPLAY_LIMIT)),
        "every FIPS pubsub subscription must bound retained replay"
    );

    let stored = (0..80)
        .map(|index| {
            EventBuilder::new(Kind::Custom(PAID_EXIT_OFFER_KIND), format!("offer-{index}"))
                .custom_created_at(Timestamp::from(index + 1))
                .sign_with_keys(&publisher)
                .expect("signed peer advert")
        })
        .collect::<Vec<_>>();
    let expected_ids = stored[stored.len() - FIPS_REPLAY_LIMIT..]
        .iter()
        .map(|event| event.id)
        .collect::<Vec<_>>();
    let replay_ids = bounded_fips_replay(stored)
        .into_iter()
        .map(|event| event.id)
        .collect::<Vec<_>>();

    assert_eq!(replay_ids, expected_ids);
}

#[test]
fn offers_ratings_and_updates_are_carried_p2p_without_relays() {
    run_async_test(
        "relayless-control-events",
        offers_ratings_and_updates_are_carried_p2p_without_relays_run,
    );
}

async fn offers_ratings_and_updates_are_carried_p2p_without_relays_run() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let updater = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let [seller_port, buyer_port, _] = available_udp_ports();
    let seller_config = endpoint_config(seller_port, &[(&buyer_npub, buyer_port)]);
    let seller_endpoint = endpoint(&seller, seller_config).await;
    let mut buyer_config = endpoint_config(buyer_port, &[(&seller_npub, seller_port)]);
    buyer_config.node.discovery.nostr.enabled = true;
    buyer_config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    let buyer_endpoint = endpoint(&buyer, buyer_config).await;
    wait_connected(&seller_endpoint, &buyer_npub).await;
    wait_connected(&buyer_endpoint, &seller_npub).await;

    let updates = update_events(&updater, "releases/relayless-control-events");
    let buyer_pubsub = start_pubsub(Arc::clone(&buyer_endpoint), updates.clone()).await;
    let seller_pubsub = start_pubsub(Arc::clone(&seller_endpoint), updates).await;
    wait_pubsub_connected(&buyer_pubsub).await;
    wait_pubsub_connected(&seller_pubsub).await;
    let mut paid_exit = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    paid_exit.pricing.price_msat_per_gb = 25;
    paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
    paid_exit.location.country_code = "FI".to_string();
    paid_exit.normalize();
    let signed_offer = signed_paid_exit_offer_from_config(
        "relayless-exit",
        &seller,
        &paid_exit,
        None,
        Timestamp::now().as_secs(),
    )
    .expect("signed paid-exit offer");
    assert!(
        seller_pubsub
            .publish(signed_offer.event.clone())
            .await
            .expect("publish paid-exit offer")
    );
    wait_for_event(&buyer_pubsub, signed_offer.event.id).await;
    let received_offer = buyer_pubsub
        .events()
        .await
        .into_iter()
        .find(|event| event.id == signed_offer.event.id)
        .and_then(|event| SignedPaidRouteOffer::from_event(event).ok())
        .expect("buyer validates paid-exit offer received over FIPS pubsub");
    assert_eq!(
        received_offer.offer().expect("offer").offer_id,
        "relayless-exit"
    );

    let mut rating = Rating::new(
        buyer.public_key().to_hex(),
        seller.public_key().to_hex(),
        80,
        0,
        100,
    );
    rating.scope = Some("fips.peer".to_string());
    let rating = rating.to_event(&buyer).expect("signed rating event");
    assert!(
        buyer_pubsub
            .publish(rating.clone())
            .await
            .expect("publish rating")
    );
    wait_for_event(&seller_pubsub, rating.id).await;

    let update = signed_update_root(&updater, "releases/relayless-control-events", 1, "cd");
    assert!(
        seller_pubsub
            .publish(update.clone())
            .await
            .expect("publish update announcement")
    );
    wait_for_event(&buyer_pubsub, update.id).await;

    seller_pubsub.stop().await;
    buyer_pubsub.stop().await;
    seller_endpoint.shutdown().await.expect("shutdown seller");
    buyer_endpoint.shutdown().await.expect("shutdown buyer");
}

#[test]
fn retained_paid_exit_offer_replays_to_late_manual_provider_buyer_without_relays() {
    run_async_test(
        "late-manual-paid-provider",
        retained_paid_exit_offer_replays_to_late_buyer_run,
    );
}

async fn retained_paid_exit_offer_replays_to_late_buyer_run() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let [seller_port, buyer_port, _] = available_udp_ports();
    let seller_endpoint = endpoint(&seller, endpoint_config(seller_port, &[])).await;
    let updates = update_events(&seller, "releases/manual-provider-replay");
    let seller_pubsub = start_pubsub(Arc::clone(&seller_endpoint), updates.clone()).await;

    let mut paid_exit = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    paid_exit.pricing.price_msat_per_gb = 25_000;
    paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let signed_offer = signed_paid_exit_offer_from_config(
        "manual-provider-replay",
        &seller,
        &paid_exit,
        None,
        Timestamp::now().as_secs(),
    )
    .expect("signed paid-exit offer");
    assert!(
        seller_pubsub
            .publish(signed_offer.event.clone())
            .await
            .expect("retain standalone offer")
    );

    let buyer_endpoint = endpoint(
        &buyer,
        endpoint_config(buyer_port, &[(seller_npub.as_str(), seller_port)]),
    )
    .await;
    let buyer_pubsub = start_pubsub(Arc::clone(&buyer_endpoint), updates).await;
    seller_endpoint
        .update_peers(vec![PeerConfig::new(
            &buyer_npub,
            "udp",
            format!("127.0.0.1:{buyer_port}"),
        )])
        .await
        .expect("connect retained-offer seller to buyer");
    wait_connected(&seller_endpoint, &buyer_npub).await;
    wait_connected(&buyer_endpoint, &seller_npub).await;
    wait_for_event(&buyer_pubsub, signed_offer.event.id).await;

    let replayed = buyer_pubsub
        .events()
        .await
        .into_iter()
        .find(|event| event.id == signed_offer.event.id)
        .and_then(|event| SignedPaidRouteOffer::from_event(event).ok())
        .expect("buyer validates retained offer replayed over FIPS pubsub");
    assert_eq!(
        replayed.offer().expect("replayed offer").seller_npub,
        seller_npub
    );

    buyer_pubsub.stop().await;
    seller_pubsub.stop().await;
    buyer_endpoint.shutdown().await.expect("shutdown buyer");
    seller_endpoint.shutdown().await.expect("shutdown seller");
}

#[test]
fn existing_subscription_ignores_peer_arrival_and_link_churn() {
    assert!(!should_create_fips_subscription(false, 0));
    assert!(should_create_fips_subscription(false, 1));
    assert!(should_create_fips_subscription(false, 11));
    assert!(!should_create_fips_subscription(true, 1));
    assert!(!should_create_fips_subscription(true, 11));
}

#[test]
fn plain_control_events_are_verified_before_entering_the_verified_path() {
    let publisher = Keys::generate();
    let update_events = update_events(&publisher, "releases/verified-boundary");
    let mut event = signed_update_root(&publisher, "releases/verified-boundary", 1, "aa");
    event.content.push_str("tampered-after-signing");

    let error = verify_control_event(event, &update_events)
        .expect_err("a plain event with an invalid signature must be rejected");

    assert!(error.to_string().contains("invalid Nostr event"));
}

#[test]
fn standard_pubsub_delivers_over_url_only_websocket_first_adjacency() {
    run_async_test(
        "websocket-fips-pubsub",
        standard_pubsub_delivers_over_url_only_websocket_first_adjacency_run,
    );
}

async fn standard_pubsub_delivers_over_url_only_websocket_first_adjacency_run() {
    let seed = Keys::generate();
    let client = Keys::generate();
    let publisher = Keys::generate();
    let seed_npub = seed.public_key().to_bech32().expect("seed npub");
    let client_npub = client.public_key().to_bech32().expect("client npub");
    let port = available_tcp_port();
    let seed_url = format!("ws://127.0.0.1:{port}/fips");

    let seed_endpoint = endpoint(&seed, websocket_listener_config(port)).await;
    let client_endpoint = endpoint(&client, websocket_seed_config(&seed_url)).await;
    wait_connected(&seed_endpoint, &client_npub).await;
    wait_connected(&client_endpoint, &seed_npub).await;

    let updates = update_events(&publisher, "releases/websocket-test");
    let seed_pubsub = start_pubsub(Arc::clone(&seed_endpoint), updates.clone()).await;
    let client_pubsub = start_pubsub(Arc::clone(&client_endpoint), updates).await;
    wait_pubsub_connected(&client_pubsub).await;
    let event = signed_update_root(&publisher, "releases/websocket-test", 1, "cc");
    let event_id = event.id;
    assert!(
        client_pubsub
            .publish(event)
            .await
            .expect("publish over WSS")
    );
    wait_for_event(&seed_pubsub, event_id).await;

    let peers = client_endpoint.peers().await.expect("client peers");
    assert!(peers.iter().any(|peer| {
        peer.npub == seed_npub && peer.transport_type.as_deref() == Some("websocket")
    }));

    client_pubsub.stop().await;
    seed_pubsub.stop().await;
    client_endpoint.shutdown().await.expect("shutdown client");
    seed_endpoint.shutdown().await.expect("shutdown seed");
}

#[test]
fn late_connected_fips_peer_receives_cached_update_root_without_relays() {
    run_async_test(
        "late-fips-update-peer",
        late_connected_fips_peer_receives_cached_update_root_without_relays_run,
    );
}

async fn late_connected_fips_peer_receives_cached_update_root_without_relays_run() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let carol = Keys::generate();
    let publisher = Keys::generate();
    let alice_npub = alice.public_key().to_bech32().expect("Alice npub");
    let bob_npub = bob.public_key().to_bech32().expect("Bob npub");
    let carol_npub = carol.public_key().to_bech32().expect("Carol npub");
    let [alice_port, bob_port, carol_port] = available_udp_ports();

    let alice_endpoint = endpoint(
        &alice,
        endpoint_config(alice_port, &[(&bob_npub, bob_port)]),
    )
    .await;
    let bob_endpoint = endpoint(
        &bob,
        endpoint_config(bob_port, &[(&alice_npub, alice_port)]),
    )
    .await;
    wait_connected(&alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;

    let tree_name = "releases/test-app";
    let update_events = update_events(&publisher, tree_name);
    let alice_pubsub = start_pubsub(Arc::clone(&alice_endpoint), update_events.clone()).await;
    let bob_pubsub = start_pubsub(Arc::clone(&bob_endpoint), update_events.clone()).await;
    wait_pubsub_connected(&alice_pubsub).await;
    let root_event = EventBuilder::new(Kind::Custom(30_064), "")
        .tags([
            Tag::identifier(tree_name),
            Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
            Tag::custom(TagKind::Custom("hash".into()), ["aa".repeat(32)]),
        ])
        .sign_with_keys(&publisher)
        .expect("signed update root");
    let root_event_id = root_event.id;
    assert!(
        alice_pubsub
            .publish(root_event)
            .await
            .expect("publish update root")
    );
    wait_for_event(&bob_pubsub, root_event_id).await;

    let carol_endpoint = endpoint(
        &carol,
        endpoint_config(carol_port, &[(&bob_npub, bob_port)]),
    )
    .await;
    let carol_pubsub = start_pubsub(Arc::clone(&carol_endpoint), update_events).await;
    bob_endpoint
        .update_peers(vec![
            PeerConfig::new(&alice_npub, "udp", format!("127.0.0.1:{alice_port}")),
            PeerConfig::new(&carol_npub, "udp", format!("127.0.0.1:{carol_port}")),
        ])
        .await
        .expect("connect Bob to Carol");
    wait_connected(&bob_endpoint, &carol_npub).await;
    wait_connected(&carol_endpoint, &bob_npub).await;

    wait_for_event(&carol_pubsub, root_event_id).await;

    alice_pubsub.stop().await;
    bob_pubsub.stop().await;
    carol_pubsub.stop().await;
    alice_endpoint.shutdown().await.expect("shutdown Alice");
    bob_endpoint.shutdown().await.expect("shutdown Bob");
    carol_endpoint.shutdown().await.expect("shutdown Carol");
}

#[test]
fn standalone_publish_replays_after_udp_roster_peer_appears() {
    run_async_test(
        "standalone-fips-pubsub",
        standalone_publish_replays_after_udp_roster_peer_appears_run,
    );
}

async fn standalone_publish_replays_after_udp_roster_peer_appears_run() {
    const APPLICATION_SERVICE_PORT: u16 = 47_371;

    let alice = Keys::generate();
    let bob = Keys::generate();
    let publisher = Keys::generate();
    let alice_npub = alice.public_key().to_bech32().expect("Alice npub");
    let bob_npub = bob.public_key().to_bech32().expect("Bob npub");
    let [alice_port, bob_port, _] = available_udp_ports();
    let alice_endpoint = endpoint(&alice, endpoint_config(alice_port, &[])).await;
    let tree_name = "releases/standalone-test";
    let update_events = update_events(&publisher, tree_name);
    let alice_pubsub = start_pubsub(Arc::clone(&alice_endpoint), update_events.clone()).await;
    let root = signed_update_root(&publisher, tree_name, 1, "33");

    assert!(
        alice_pubsub
            .publish(root.clone())
            .await
            .expect("cache standalone update root")
    );
    assert!(
        alice_pubsub
            .events()
            .await
            .iter()
            .any(|event| event.id == root.id),
        "standalone publication remains available for reconnect replay"
    );

    let bob_endpoint = endpoint(
        &bob,
        endpoint_config(bob_port, &[(&alice_npub, alice_port)]),
    )
    .await;
    let application_receiver = bob_endpoint
        .register_service_receiver(APPLICATION_SERVICE_PORT)
        .await
        .expect("register application-owned FIPS service");
    alice_endpoint
        .update_peers(vec![PeerConfig::new(
            &bob_npub,
            "udp",
            format!("127.0.0.1:{bob_port}"),
        )])
        .await
        .expect("add UDP roster peer");
    wait_connected(&alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;
    let bob_pubsub = start_pubsub(Arc::clone(&bob_endpoint), update_events).await;

    wait_pubsub_connected(&alice_pubsub).await;
    wait_pubsub_connected(&bob_pubsub).await;
    wait_for_event(&bob_pubsub, root.id).await;
    assert_udp_link(&alice_endpoint, &bob_npub).await;
    assert_udp_link(&bob_endpoint, &alice_npub).await;

    let application_payload = b"application-owned-route".to_vec();
    alice_endpoint
        .send_datagram(
            PeerIdentity::from_npub(&bob_npub).expect("Bob identity"),
            APPLICATION_SERVICE_PORT,
            APPLICATION_SERVICE_PORT,
            application_payload.clone(),
        )
        .await
        .expect("send application-owned FSP datagram");
    let mut datagrams = Vec::new();
    let count = tokio::time::timeout(
        FIPS_TEST_EVENTUAL_TIMEOUT,
        application_receiver.recv_batch_into(&mut datagrams, 1),
    )
    .await
    .expect("application-owned datagram arrived")
    .expect("application service remained registered");
    assert_eq!(count, 1);
    assert_eq!(datagrams[0].data.as_ref(), application_payload.as_slice());

    alice_pubsub.stop().await;
    bob_pubsub.stop().await;
    alice_endpoint.shutdown().await.expect("shutdown Alice");
    bob_endpoint.shutdown().await.expect("shutdown Bob");
}

#[test]
fn control_pubsub_preserves_56k_event_limit_over_real_udp_fips() {
    run_async_test(
        "bounded-fips-pubsub",
        control_pubsub_preserves_56k_event_limit_over_real_udp_fips_run,
    );
}

async fn control_pubsub_preserves_56k_event_limit_over_real_udp_fips_run() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let publisher = Keys::generate();
    let alice_npub = alice.public_key().to_bech32().expect("Alice npub");
    let bob_npub = bob.public_key().to_bech32().expect("Bob npub");
    let [alice_port, bob_port, _] = available_udp_ports();
    let alice_endpoint = endpoint(
        &alice,
        endpoint_config(alice_port, &[(&bob_npub, bob_port)]),
    )
    .await;
    let bob_endpoint = endpoint(
        &bob,
        endpoint_config(bob_port, &[(&alice_npub, alice_port)]),
    )
    .await;
    wait_connected(&alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;

    let tree_name = "releases/bounded-test";
    let update_events = update_events(&publisher, tree_name);
    let alice_pubsub = start_pubsub(Arc::clone(&alice_endpoint), update_events.clone()).await;
    let bob_pubsub = start_pubsub(Arc::clone(&bob_endpoint), update_events).await;
    wait_pubsub_connected(&alice_pubsub).await;
    let accepted = signed_update_root_with_content(
        &publisher,
        tree_name,
        1,
        "44",
        CONTROL_PUBSUB_MAX_EVENT_BYTES - 1_024,
    );
    assert!(
        serde_json::to_vec(&accepted).expect("event JSON").len() <= CONTROL_PUBSUB_MAX_EVENT_BYTES
    );
    assert!(
        alice_pubsub
            .publish(accepted.clone())
            .await
            .expect("publish near-limit update root")
    );
    wait_for_event(&bob_pubsub, accepted.id).await;

    let oversized = signed_update_root_with_content(
        &publisher,
        tree_name,
        2,
        "55",
        CONTROL_PUBSUB_MAX_EVENT_BYTES,
    );
    assert!(
        serde_json::to_vec(&oversized).expect("event JSON").len() > CONTROL_PUBSUB_MAX_EVENT_BYTES
    );
    let error = alice_pubsub
        .publish(oversized.clone())
        .await
        .expect_err("reject oversized update root");
    assert!(error.to_string().contains("maximum"));
    assert!(
        !alice_pubsub
            .events()
            .await
            .iter()
            .any(|event| event.id == oversized.id)
    );

    alice_pubsub.stop().await;
    bob_pubsub.stop().await;
    alice_endpoint.shutdown().await.expect("shutdown Alice");
    bob_endpoint.shutdown().await.expect("shutdown Bob");
}

struct RejectAllPeers;

impl MeshPeerPolicy for RejectAllPeers {
    fn select_mesh_peer(&self, _peer_id: &str) -> nostr_pubsub::Result<Option<MeshPeer>> {
        Ok(None)
    }
}

#[test]
fn peer_policy_rejects_events_from_authenticated_udp_fips_peer() {
    run_async_test(
        "policy-fips-pubsub",
        peer_policy_rejects_events_from_authenticated_udp_fips_peer_run,
    );
}

async fn peer_policy_rejects_events_from_authenticated_udp_fips_peer_run() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let publisher = Keys::generate();
    let alice_npub = alice.public_key().to_bech32().expect("Alice npub");
    let bob_npub = bob.public_key().to_bech32().expect("Bob npub");
    let [alice_port, bob_port, _] = available_udp_ports();
    let alice_endpoint = endpoint(
        &alice,
        endpoint_config(alice_port, &[(&bob_npub, bob_port)]),
    )
    .await;
    let bob_endpoint = endpoint(
        &bob,
        endpoint_config(bob_port, &[(&alice_npub, alice_port)]),
    )
    .await;
    wait_connected(&alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;

    let tree_name = "releases/policy-test";
    let update_events = update_events(&publisher, tree_name);
    let alice_pubsub = start_pubsub(Arc::clone(&alice_endpoint), update_events.clone()).await;
    let bob_pubsub = ControlPubsubFipsRuntime::start_inner(
        Arc::clone(&bob_endpoint),
        NostrPubsubConfig {
            mode: NostrPubsubMode::Client,
            fanout: 8,
            max_hops: 4,
            max_event_bytes: CONTROL_PUBSUB_MAX_EVENT_BYTES,
        },
        Vec::new(),
        None,
        Some(Arc::new(RejectAllPeers)),
        Some(update_events),
        &[],
    )
    .await
    .expect("start policy-bound FIPS pubsub")
    .expect("FIPS pubsub enabled");
    wait_pubsub_transport_connected(&alice_pubsub).await;
    let root = signed_update_root(&publisher, tree_name, 1, "66");
    assert!(
        alice_pubsub
            .publish(root.clone())
            .await
            .expect("publish policy test event")
    );
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert!(
        !bob_pubsub
            .events()
            .await
            .iter()
            .any(|event| event.id == root.id),
        "peer policy must reject stream records after FIPS authentication"
    );

    alice_pubsub.stop().await;
    bob_pubsub.stop().await;
    alice_endpoint.shutdown().await.expect("shutdown Alice");
    bob_endpoint.shutdown().await.expect("shutdown Bob");
}

#[test]
fn restarted_pubsub_resubscribes_after_tcp_fips_connection_loss() {
    run_async_test(
        "restarted-fips-pubsub",
        restarted_pubsub_resubscribes_after_connection_loss_run,
    );
}

async fn restarted_pubsub_resubscribes_after_connection_loss_run() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let publisher = Keys::generate();
    let alice_npub = alice.public_key().to_bech32().expect("Alice npub");
    let bob_npub = bob.public_key().to_bech32().expect("Bob npub");
    let [alice_port, bob_port, _] = available_udp_ports();
    let alice_config = endpoint_config(alice_port, &[(&bob_npub, bob_port)]);
    let alice_endpoint = endpoint(&alice, alice_config.clone()).await;
    let bob_endpoint = endpoint(
        &bob,
        endpoint_config(bob_port, &[(&alice_npub, alice_port)]),
    )
    .await;
    wait_connected(&alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;

    let tree_name = "releases/reconnect-test";
    let update_events = update_events(&publisher, tree_name);
    let alice_pubsub = start_pubsub(Arc::clone(&alice_endpoint), update_events.clone()).await;
    let bob_pubsub = start_pubsub(Arc::clone(&bob_endpoint), update_events.clone()).await;
    wait_pubsub_connected(&bob_pubsub).await;
    let first = signed_update_root(&publisher, tree_name, 1, "11");
    assert!(
        bob_pubsub
            .publish(first.clone())
            .await
            .expect("publish first update root")
    );
    wait_for_event(&alice_pubsub, first.id).await;

    alice_pubsub.stop().await;
    alice_endpoint
        .shutdown()
        .await
        .expect("stop Alice endpoint");
    drop(alice_endpoint);
    let restarted_alice_endpoint = endpoint(&alice, alice_config).await;
    wait_connected(&restarted_alice_endpoint, &bob_npub).await;
    wait_connected(&bob_endpoint, &alice_npub).await;
    let restarted_alice = start_pubsub(Arc::clone(&restarted_alice_endpoint), update_events).await;
    wait_pubsub_connected(&restarted_alice).await;
    let second = signed_update_root(&publisher, tree_name, 2, "22");
    assert!(
        bob_pubsub
            .publish(second.clone())
            .await
            .expect("publish across stale TCP/FIPS session")
    );
    wait_for_event(&restarted_alice, second.id).await;

    bob_pubsub.stop().await;
    restarted_alice.stop().await;
    restarted_alice_endpoint
        .shutdown()
        .await
        .expect("shutdown restarted Alice");
    bob_endpoint.shutdown().await.expect("shutdown Bob");
}

fn signed_update_root(
    publisher: &Keys,
    tree_name: &str,
    created_at: u64,
    hash_byte: &str,
) -> Event {
    EventBuilder::new(Kind::Custom(30_064), "")
        .tags([
            Tag::identifier(tree_name),
            Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
            Tag::custom(TagKind::Custom("hash".into()), [hash_byte.repeat(32)]),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(publisher)
        .expect("signed update root")
}

fn signed_update_root_with_content(
    publisher: &Keys,
    tree_name: &str,
    created_at: u64,
    hash_byte: &str,
    content_bytes: usize,
) -> Event {
    EventBuilder::new(Kind::Custom(30_064), "x".repeat(content_bytes))
        .tags([
            Tag::identifier(tree_name),
            Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
            Tag::custom(TagKind::Custom("hash".into()), [hash_byte.repeat(32)]),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(publisher)
        .expect("signed update root")
}
