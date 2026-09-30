use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use fips_core::config::{
    NostrDiscoveryConfig, NostrPeerfindingSource, PeerConfig, TcpConfig, TransportInstances,
};
use fips_core::{
    Config, FipsEndpoint, Identity, IdentityConfig, SimNetwork, SimTransportConfig,
    register_sim_network, unregister_sim_network,
};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, SingleLetterTag, Tag, TagKind,
    Timestamp, ToBech32,
};
use nostr_pubsub::{
    EventBus, EventSource, EventSourceKind, InMemoryEventBus, NostrEventSubscriber,
    PubsubPeerSubscriptionSnapshot, VerifiedEvent,
};
use nostr_social_graph::Rating;
use nostr_social_memory::RatingEventExt;
use tokio::time::timeout;

use super::*;
use crate::client_transport::tcp_driver_poll_needed;

mod managed_reputation;
mod peer_policy;
mod replay;
mod reputation;
mod routed;
mod service_retry;
mod shutdown;
mod state;
mod turnover;
mod websocket_restart;

#[test]
fn tcp_timer_poll_matches_the_minimum_retransmission_granularity() {
    assert_eq!(TCP_POLL_INTERVAL, Duration::from_millis(200));
}

#[test]
fn idle_transport_does_not_poll_an_empty_tcp_stack() {
    assert!(!tcp_driver_poll_needed(0));
    assert!(tcp_driver_poll_needed(1));
}

#[test]
fn event_fanout_is_bounded_stable_and_rotates_across_events() {
    let targets = (0..12)
        .map(|index| {
            (
                format!("npub-{index:02}"),
                vec![SubscriptionId::new(format!("sub-{index:02}"))],
            )
        })
        .collect::<Vec<_>>();
    let first_id = EventId::from_hex(&"01".repeat(32)).expect("first event ID");
    let second_id = EventId::from_hex(&"02".repeat(32)).expect("second event ID");

    let first = bounded_delivery_targets(targets.clone(), &first_id, 4);
    let repeated = bounded_delivery_targets(targets.clone(), &first_id, 4);
    let second = bounded_delivery_targets(targets, &second_id, 4);

    assert_eq!(first.len(), 4);
    assert_eq!(first, repeated, "one event must select a stable peer set");
    assert_ne!(first, second, "fresh events should rotate delivery load");
}

#[tokio::test]
async fn client_advertises_only_while_its_fsp_service_is_registered() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("reserve local rendezvous address");
    let SocketAddr::V4(rendezvous_addr) = socket.local_addr().expect("reserved address") else {
        panic!("reserved rendezvous address should be IPv4");
    };
    drop(socket);

    let mut config = Config::new();
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    let endpoint = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(config)
                .local_rendezvous()
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind local FIPS endpoint"),
    );

    let client = FipsPubsubClient::start(Arc::clone(&endpoint), FipsPubsubClientOptions::default())
        .await
        .expect("start FIPS pubsub client");
    wait_for_local_capability(&endpoint, true).await;

    client.shutdown().await;
    wait_for_local_capability(&endpoint, false).await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

async fn wait_for_local_capability(endpoint: &FipsEndpoint, expected: bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            let advertised = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot")
                .iter()
                .any(|advert| {
                    advert.npub == endpoint.npub()
                        && advert.capability(FIPS_NOSTR_PUBSUB_CAPABILITY).is_some_and(
                            |capability| {
                                capability.fsp_port == Some(FIPS_NOSTR_PUBSUB_SERVICE_PORT)
                            },
                        )
                });
            if advertised == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("local pubsub capability state should converge");
}

#[test]
fn fips_discovery_config_converts_to_bounded_pubsub_retention() {
    let config = NostrDiscoveryConfig {
        enabled: true,
        peerfinding_source: NostrPeerfindingSource::External,
        app: "fips-test".to_string(),
        advert_cache_max_entries: 17,
        ..NostrDiscoveryConfig::default()
    };
    let policy = fips_discovery_retention_policy(&config).expect("enabled discovery policy");
    let matching = VerifiedEvent::try_from(
        EventBuilder::new(Kind::Custom(37195), "advert")
            .tags([Tag::identifier("fips-test")])
            .sign_with_keys(&Keys::generate())
            .expect("signed matching event"),
    )
    .expect("verified matching event");
    let other_app = VerifiedEvent::try_from(
        EventBuilder::new(Kind::Custom(37195), "advert")
            .tags([Tag::identifier("other-app")])
            .sign_with_keys(&Keys::generate())
            .expect("signed other-app event"),
    )
    .expect("verified other-app event");

    assert_eq!(policy.max_events, 17);
    assert!(policy.accepts(&matching));
    assert!(!policy.accepts(&other_app));
    assert!(fips_discovery_retention_policy(&NostrDiscoveryConfig::default()).is_none());
}

#[tokio::test]
async fn verified_pubsub_event_ingests_through_neutral_fips_api() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.nostr.advert_relays.clear();
    config.node.discovery.nostr.app = "fips-test".to_string();
    let endpoint = Box::pin(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind(),
    )
    .await
    .expect("endpoint with Nostr discovery");
    let now = Timestamp::now().as_secs();
    let event = EventBuilder::new(
        Kind::Custom(37195),
        r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#,
    )
    .tags([
        Tag::identifier("fips-test"),
        Tag::custom(TagKind::custom("protocol"), ["fips-test"]),
        Tag::custom(TagKind::custom("version"), ["1"]),
        Tag::expiration(Timestamp::from(now.saturating_add(3_600))),
    ])
    .custom_created_at(Timestamp::from(now))
    .sign_with_keys(&Keys::generate())
    .expect("signed FIPS advert");

    assert!(
        ingest_fips_discovery_event(
            &endpoint,
            VerifiedEvent::try_from(event).expect("verified FIPS advert"),
        )
        .await
        .expect("FIPS discovery ingest")
    );
    endpoint.shutdown().await.expect("endpoint shutdown");
}

#[tokio::test]
async fn peerfinder_routes_publication_and_lookup_only_through_event_bus() {
    let (config_a, discovery_a) = peerfinding_endpoint_config([21; 32], "8.8.8.8:443");
    let (config_b, discovery_b) = peerfinding_endpoint_config([22; 32], "8.8.4.4:443");
    let endpoint_a = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(config_a)
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind peerfinder publisher"),
    );
    let endpoint_b = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(config_b)
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind peerfinder consumer"),
    );
    let publisher =
        FipsPeerfinder::new(Arc::clone(&endpoint_a), &discovery_a).expect("external publisher");
    let consumer =
        FipsPeerfinder::new(Arc::clone(&endpoint_b), &discovery_b).expect("external consumer");
    let bus = InMemoryEventBus::new();

    let publish_report = publisher
        .publish_local(&bus)
        .await
        .expect("publish through selected bus")
        .expect("local endpoint is advert eligible");
    assert!(publish_report.accepted);
    let refreshed = consumer
        .refresh(&bus)
        .await
        .expect("query through selected bus");

    assert_eq!(
        refreshed,
        FipsPeerfindingRefresh {
            received: 1,
            accepted: 1,
        }
    );
    assert!(
        endpoint_a
            .relay_statuses()
            .await
            .expect("publisher relays")
            .is_empty()
    );
    assert!(
        endpoint_b
            .relay_statuses()
            .await
            .expect("consumer relays")
            .is_empty()
    );
    endpoint_a.shutdown().await.expect("publisher shutdown");
    endpoint_b.shutdown().await.expect("consumer shutdown");
}

#[tokio::test]
async fn peerfinder_rejects_embedded_relay_peerfinding_mode() {
    let endpoint = Arc::new(
        Box::pin(FipsEndpoint::builder().without_system_tun().bind())
            .await
            .expect("bind endpoint"),
    );
    let config = NostrDiscoveryConfig {
        enabled: true,
        peerfinding_source: NostrPeerfindingSource::Relays,
        ..Default::default()
    };

    assert!(FipsPeerfinder::new(Arc::clone(&endpoint), &config).is_err());
    endpoint.shutdown().await.expect("endpoint shutdown");
}

#[test]
fn client_limits_reject_unbounded_fips_frames() {
    let options = FipsPubsubClientOptions {
        max_frame_bytes: FIPS_NOSTR_PUBSUB_MAX_FRAME_BYTES + 1,
        ..FipsPubsubClientOptions::default()
    };

    assert!(options.validate().is_err());
}

#[test]
fn client_limits_reject_fanout_above_peer_capacity() {
    let options = FipsPubsubClientOptions {
        max_connected_peers: 4,
        fanout: 5,
        ..FipsPubsubClientOptions::default()
    };

    assert!(options.validate().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_excludes_recursive_underlay_transports() {
    let network_id = format!("nostr-pubsub-fips-excluded-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7368));

    let identity_a = Identity::from_secret_bytes(&[21; 32]).expect("identity A");
    let identity_b = Identity::from_secret_bytes(&[22; 32]).expect("identity B");
    let endpoint_a = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(
                    &network_id,
                    "excluded-a",
                    [21; 32],
                    identity_b.npub(),
                    "excluded-b",
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind endpoint A"),
    );
    let endpoint_b = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(
                    &network_id,
                    "excluded-b",
                    [22; 32],
                    identity_a.npub(),
                    "excluded-a",
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind endpoint B"),
    );
    wait_for_connected_peer(&endpoint_a, endpoint_b.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_a.npub()).await;

    let client = FipsPubsubClient::start_excluding_peer_transports(
        Arc::clone(&endpoint_a),
        FipsPubsubClientOptions::default(),
        ["sim"],
    )
    .await
    .expect("start transport-filtered client");
    assert_eq!(client.connected_peer_count().expect("peer count"), 0);

    client.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connected_fips_peers_subscribe_and_receive_cached_update_announcements() {
    let network_id = format!("nostr-pubsub-fips-updates-{}", std::process::id());
    let (endpoint_a, endpoint_b, client_a, client_b) = connected_update_clients(&network_id).await;

    let release_keys = Keys::generate();
    let tree_name = "iris-chat-releases";
    let announcement = VerifiedEvent::try_from(
        EventBuilder::new(Kind::Custom(30_064), "")
            .tags([
                Tag::identifier(tree_name),
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                    ["hashtree"],
                ),
                Tag::custom(TagKind::Custom("hash".into()), ["11".repeat(32)]),
            ])
            .sign_with_keys(&release_keys)
            .expect("sign update announcement"),
    )
    .expect("verify update announcement");
    client_b
        .publish(
            announcement.clone(),
            nostr_pubsub::EventSource::local_index("release"),
        )
        .await
        .expect("publish update announcement");

    let filter = Filter::new()
        .kind(Kind::Custom(30_064))
        .author(release_keys.public_key())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            tree_name.to_string(),
        );
    let mut subscription = client_a
        .subscribe(vec![filter.clone()])
        .await
        .expect("subscribe to release tree");
    let received = timeout(Duration::from_secs(2), subscription.recv())
        .await
        .expect("update announcement timeout")
        .expect("subscription remains open");

    assert_eq!(received.event, announcement);
    assert_eq!(received.source.kind, EventSourceKind::FipsEndpoint);
    assert_eq!(received.source.id.as_str(), endpoint_b.npub());

    timeout(Duration::from_secs(2), async {
        loop {
            if client_b
                .peer_subscription_count()
                .expect("peer subscription count")
                == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("publisher observes peer subscription");

    let retained_filter = filter.clone().limit(FIPS_NOSTR_PUBSUB_MAX_REPLAY_EVENTS);
    assert_peer_subscription_snapshot(&client_b, subscription.id(), &retained_filter);

    let next_announcement = VerifiedEvent::try_from(
        EventBuilder::new(Kind::Custom(30_064), "")
            .tags([
                Tag::identifier(tree_name),
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                    ["hashtree"],
                ),
                Tag::custom(TagKind::Custom("hash".into()), ["22".repeat(32)]),
            ])
            .sign_with_keys(&release_keys)
            .expect("sign next update announcement"),
    )
    .expect("verify next update announcement");
    client_b
        .publish(
            next_announcement.clone(),
            nostr_pubsub::EventSource::local_index("release"),
        )
        .await
        .expect("publish next update announcement");
    let received = timeout(Duration::from_secs(2), subscription.recv())
        .await
        .expect("next update announcement timeout")
        .expect("subscription remains open");
    assert_eq!(received.event, next_announcement);

    subscription.close();
    wait_for_default_peer_subscription(&client_b).await;
    client_a.shutdown().await;
    client_b.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fips_client_is_a_generic_live_router_source() {
    let network_id = format!("nostr-pubsub-fips-live-route-{}", std::process::id());
    let (endpoint_a, endpoint_b, client_a, client_b) = connected_update_clients(&network_id).await;
    let event = VerifiedEvent::try_from(
        EventBuilder::new(Kind::TextNote, "generic FIPS live route")
            .sign_with_keys(&Keys::generate())
            .expect("sign routed event"),
    )
    .expect("verify routed event");
    let (sender, mut events) = tokio::sync::mpsc::unbounded_channel();
    let subscription = NostrEventSubscriber::subscribe(
        &client_a,
        vec![Filter::new().kind(Kind::TextNote)],
        Arc::new(move |incoming| {
            let _ = sender.send(incoming);
        }),
    )
    .await
    .expect("open generic FIPS live route");

    client_b
        .publish(event.clone(), EventSource::local_index("live-route-test"))
        .await
        .expect("publish routed event");
    let incoming = timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("routed event timeout")
        .expect("live route remains open");
    assert_eq!(incoming.event, event);
    assert_eq!(
        incoming.source,
        EventSource::fips_endpoint(endpoint_b.npub())
    );
    subscription
        .close()
        .await
        .expect("close generic FIPS route");

    client_a.shutdown().await;
    client_b.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_duplicate_inventories_fetch_one_event_for_all_matching_subscriptions() {
    let network_id = format!("nostr-pubsub-fips-live-dedup-{}", std::process::id());
    let (endpoint_a, endpoint_b, endpoint_c, client_a, client_b, client_c) =
        connected_live_mesh(&network_id).await;

    let filter = Filter::new().kind(Kind::TextNote);
    let mut first = client_a
        .subscribe(vec![filter.clone()])
        .await
        .expect("first live subscription");
    let mut second = client_a
        .subscribe(vec![filter])
        .await
        .expect("second live subscription");
    wait_for_peer_subscription_count(&client_b, 3).await;
    wait_for_peer_subscription_count(&client_c, 3).await;

    let event = VerifiedEvent::try_from(
        EventBuilder::text_note("one live event from two mesh paths")
            .sign_with_keys(&Keys::generate())
            .expect("sign live event"),
    )
    .expect("verify live event");
    let (published_b, published_c) = tokio::join!(
        client_b.publish(event.clone(), EventSource::local_index("provider-b")),
        client_c.publish(event.clone(), EventSource::local_index("provider-c")),
    );
    assert!(published_b.expect("publish from B").accepted);
    assert!(published_c.expect("publish from C").accepted);

    let received_first = timeout(Duration::from_secs(3), first.recv())
        .await
        .expect("first subscription timeout")
        .expect("first subscription open");
    let received_second = timeout(Duration::from_secs(3), second.recv())
        .await
        .expect("second subscription timeout")
        .expect("second subscription open");
    assert_eq!(received_first.event, event);
    assert_eq!(received_second.event, event);

    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = client_a.delivery_snapshot();
            if snapshot.inv_frames_received >= 2 {
                assert_eq!(snapshot.want_frames_sent, 1);
                assert_eq!(snapshot.event_frames_received, 1);
                assert_eq!(snapshot.subscription_events_received, 1);
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all duplicate inventories should arrive");
    assert!(
        timeout(Duration::from_millis(200), first.recv())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(200), second.recv())
            .await
            .is_err()
    );

    first.close();
    second.close();
    client_a.shutdown().await;
    client_b.shutdown().await;
    client_c.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    endpoint_c.shutdown().await.expect("shutdown endpoint C");
    unregister_sim_network(&network_id);
}

async fn connected_live_mesh(
    network_id: &str,
) -> (
    Arc<FipsEndpoint>,
    Arc<FipsEndpoint>,
    Arc<FipsEndpoint>,
    FipsPubsubClient,
    FipsPubsubClient,
    FipsPubsubClient,
) {
    register_sim_network(network_id, SimNetwork::new(7370));
    let identity_a = Identity::from_secret_bytes(&[31; 32]).expect("identity A");
    let identity_b = Identity::from_secret_bytes(&[32; 32]).expect("identity B");
    let identity_c = Identity::from_secret_bytes(&[33; 32]).expect("identity C");
    let endpoint_a = live_endpoint(
        network_id,
        "live-a",
        [31; 32],
        [(identity_b.npub(), "live-b"), (identity_c.npub(), "live-c")],
    )
    .await;
    let endpoint_b = live_endpoint(
        network_id,
        "live-b",
        [32; 32],
        [(identity_a.npub(), "live-a")],
    )
    .await;
    let endpoint_c = live_endpoint(
        network_id,
        "live-c",
        [33; 32],
        [(identity_a.npub(), "live-a")],
    )
    .await;
    wait_for_connected_peer(&endpoint_a, endpoint_b.npub()).await;
    wait_for_connected_peer(&endpoint_a, endpoint_c.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_a.npub()).await;
    wait_for_connected_peer(&endpoint_c, endpoint_a.npub()).await;

    let client_a = start_sim_client(&endpoint_a, "receiver").await;
    let client_b = start_sim_client(&endpoint_b, "provider B").await;
    let client_c = start_sim_client(&endpoint_c, "provider C").await;
    wait_for_pubsub_connections(&client_a, 2).await;
    wait_for_pubsub_connections(&client_b, 1).await;
    wait_for_pubsub_connections(&client_c, 1).await;
    (
        endpoint_a, endpoint_b, endpoint_c, client_a, client_b, client_c,
    )
}

async fn live_endpoint<const N: usize>(
    network_id: &str,
    address: &str,
    secret: [u8; 32],
    peers: [(String, &str); N],
) -> Arc<FipsEndpoint> {
    Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config_with_peers(
                    network_id, address, secret, peers,
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .unwrap_or_else(|error| panic!("bind endpoint {address}: {error}")),
    )
}

async fn start_sim_client(endpoint: &Arc<FipsEndpoint>, name: &str) -> FipsPubsubClient {
    FipsPubsubClient::start_for_transport(
        Arc::clone(endpoint),
        FipsPubsubClientOptions::default(),
        "sim",
    )
    .await
    .unwrap_or_else(|error| panic!("start {name}: {error}"))
}

fn assert_peer_subscription_snapshot(
    client: &FipsPubsubClient,
    subscription_id: &nostr_pubsub::SubscriptionId,
    filter: &Filter,
) {
    let codec = FipsPubsubWireCodec::new(FIPS_NOSTR_PUBSUB_MAX_FRAME_BYTES).expect("FIPS codec");
    let default_filter = Filter::new()
        .kind(Kind::Custom(fips_core::discovery::nostr::ADVERT_KIND))
        .identifier(fips_core::discovery::nostr::ADVERT_IDENTIFIER)
        .limit(FIPS_NOSTR_PUBSUB_MAX_REPLAY_EVENTS);
    let default_id = nostr_pubsub::SubscriptionId::new("fips-1");
    let encoded_req_bytes = codec
        .encode_frame(&FipsPubsubWireMessage::req(
            default_id,
            vec![default_filter.clone()],
        ))
        .expect("encode default advert REQ")
        .len()
        + codec
            .encode_frame(&FipsPubsubWireMessage::req(
                subscription_id.clone(),
                vec![filter.clone()],
            ))
            .expect("encode canonical REQ")
            .len();
    assert_eq!(
        client
            .peer_subscription_snapshot()
            .expect("retained peer subscriptions"),
        PubsubPeerSubscriptionSnapshot {
            peer_count: 1,
            subscription_count: 2,
            filter_count: 2,
            encoded_filter_bytes: filter.as_json().len() + default_filter.as_json().len(),
            encoded_req_bytes,
        }
    );
}

async fn wait_for_default_peer_subscription(client: &FipsPubsubClient) {
    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = client
                .peer_subscription_snapshot()
                .expect("retained peer subscriptions");
            if snapshot.peer_count == 1
                && snapshot.subscription_count == 1
                && snapshot.filter_count == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("publisher removes closed peer subscription");
}

async fn connected_update_clients(
    network_id: &str,
) -> (
    Arc<FipsEndpoint>,
    Arc<FipsEndpoint>,
    FipsPubsubClient,
    FipsPubsubClient,
) {
    register_sim_network(network_id, SimNetwork::new(7369));
    let identity_a = Identity::from_secret_bytes(&[3; 32]).expect("identity A");
    let identity_b = Identity::from_secret_bytes(&[4; 32]).expect("identity B");
    let endpoint_a = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(
                    network_id,
                    "updates-a",
                    [3; 32],
                    identity_b.npub(),
                    "updates-b",
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind endpoint A"),
    );
    let endpoint_b = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(
                    network_id,
                    "updates-b",
                    [4; 32],
                    identity_a.npub(),
                    "updates-a",
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind endpoint B"),
    );
    wait_for_connected_peer(&endpoint_a, endpoint_b.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_a.npub()).await;
    let client_a = FipsPubsubClient::start_for_transport(
        Arc::clone(&endpoint_a),
        FipsPubsubClientOptions::default(),
        "sim",
    )
    .await
    .expect("start subscriber");
    let client_b = FipsPubsubClient::start_for_transport(
        Arc::clone(&endpoint_b),
        FipsPubsubClientOptions::default(),
        "sim",
    )
    .await
    .expect("start publisher");
    (endpoint_a, endpoint_b, client_a, client_b)
}

fn endpoint_config(
    network_id: &str,
    local_addr: &str,
    secret: [u8; 32],
    peer_npub: String,
    peer_addr: &str,
) -> Config {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_backoff_secs = 1;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(local_addr.to_string()),
        mtu: Some(1280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.peers = vec![PeerConfig::new(peer_npub, "sim", peer_addr)];
    config
}

fn endpoint_config_with_peers<const N: usize>(
    network_id: &str,
    local_addr: &str,
    secret: [u8; 32],
    peers: [(String, &str); N],
) -> Config {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_backoff_secs = 1;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(local_addr.to_string()),
        mtu: Some(1280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.peers = peers
        .into_iter()
        .map(|(npub, addr)| PeerConfig::new(npub, "sim", addr))
        .collect();
    config
}

fn peerfinding_endpoint_config(
    secret: [u8; 32],
    external_addr: &str,
) -> (Config, NostrDiscoveryConfig) {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    config.node.discovery.nostr.app = "fips-pubsub-peerfinding-test".to_string();
    config.transports.tcp = TransportInstances::Single(TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        external_addr: Some(external_addr.to_string()),
        ..Default::default()
    });
    let discovery = config.node.discovery.nostr.clone();
    (config, discovery)
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, expected_npub: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            let connected = endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .any(|peer| {
                    peer.connected
                        && peer.npub == expected_npub
                        && peer.transport_type.as_deref() == Some("sim")
                });
            if connected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("FIPS endpoints connect");
}

async fn wait_for_pubsub_connections(client: &FipsPubsubClient, expected: usize) {
    timeout(Duration::from_secs(5), async {
        loop {
            if client.connected_peer_count().expect("pubsub peers") == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TCP/FIPS pubsub streams connect");
}

async fn wait_for_peer_subscription_count(client: &FipsPubsubClient, expected: usize) {
    timeout(Duration::from_secs(5), async {
        loop {
            if client
                .peer_subscription_count()
                .expect("peer subscriptions")
                == expected
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer subscriptions converge");
}
