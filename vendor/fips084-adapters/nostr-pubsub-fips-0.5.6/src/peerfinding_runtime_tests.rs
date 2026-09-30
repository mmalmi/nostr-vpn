use std::sync::Arc;
use std::time::Duration;

use fips_core::config::{
    NostrPeerfindingSource, PeerConfig, SimTransportConfig, TcpConfig, TransportInstances,
};
use fips_core::{
    Config, FipsEndpoint, Identity, IdentityConfig, SimNetwork, register_sim_network,
    unregister_sim_network,
};
use nostr::{EventBuilder, Filter, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use nostr_pubsub::{EventBus, EventSource, EventSourceKind, VerifiedEvent};
use nostr_social_graph::Rating;
use nostr_social_memory::RatingEventExt;
use tokio::time::timeout;

use super::*;

#[test]
fn advert_refresh_uses_half_of_short_signed_ttl() {
    let keys = Keys::generate();
    let event = EventBuilder::new(
        Kind::Custom(fips_core::discovery::nostr::ADVERT_KIND),
        "advert",
    )
    .tags([Tag::expiration(Timestamp::from(160))])
    .custom_created_at(Timestamp::from(100))
    .sign_with_keys(&keys)
    .expect("signed short-lived advert");

    assert_eq!(fips_advert_refresh_delay(&event), Duration::from_secs(30));
}

#[tokio::test]
async fn default_advert_subscription_is_reserved_beyond_application_limit() {
    let network_id = format!("nostr-pubsub-fips-advert-capacity-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7_367));
    let endpoint = advert_endpoint(&network_id, "capacity-a", [40; 32], [], "8.8.8.40:2121").await;
    let options = FipsPubsubClientOptions {
        max_active_subscriptions: 1,
        ..Default::default()
    };
    let client = FipsPubsubClient::start_for_transport(Arc::clone(&endpoint), options, "sim")
        .await
        .expect("start client with one application subscription slot");

    assert_eq!(
        client
            .inner
            .subscriptions
            .lock()
            .expect("subscription state")
            .len(),
        1,
        "client start must synchronously reserve the default advert stream"
    );
    let application = client
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .expect("application subscription remains available");
    assert!(
        client
            .subscribe(vec![Filter::new().kind(Kind::Metadata)])
            .await
            .is_err(),
        "configured application subscription limit remains enforced"
    );

    application.close();
    client.shutdown().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_fips_adverts_are_default_relayless_multihop_subscriptions() {
    let network_id = format!("nostr-pubsub-fips-default-adverts-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7_368));
    let identity_a = Identity::from_secret_bytes(&[41; 32]).expect("identity A");
    let identity_b = Identity::from_secret_bytes(&[42; 32]).expect("identity B");
    let identity_c = Identity::from_secret_bytes(&[43; 32]).expect("identity C");
    let endpoint_a = advert_endpoint(
        &network_id,
        "advert-a",
        [41; 32],
        [(identity_b.npub(), "advert-b")],
        "8.8.8.1:2121",
    )
    .await;
    let endpoint_b = advert_endpoint(
        &network_id,
        "advert-b",
        [42; 32],
        [
            (identity_a.npub(), "advert-a"),
            (identity_c.npub(), "advert-c"),
        ],
        "8.8.8.2:2121",
    )
    .await;
    let endpoint_c = advert_endpoint(
        &network_id,
        "advert-c",
        [43; 32],
        [(identity_b.npub(), "advert-b")],
        "8.8.8.3:2121",
    )
    .await;
    wait_for_connected_peer(&endpoint_a, endpoint_b.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_a.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_c.npub()).await;
    wait_for_connected_peer(&endpoint_c, endpoint_b.npub()).await;

    let client_a = start_client(&endpoint_a).await;
    let client_b = start_client(&endpoint_b).await;
    let client_c = start_client(&endpoint_c).await;
    wait_for_pubsub_connections(&client_a, 1).await;
    wait_for_pubsub_connections(&client_b, 2).await;
    wait_for_pubsub_connections(&client_c, 1).await;
    wait_for_peer_subscriptions(&client_b, 2).await;

    let author_c = PublicKey::parse(endpoint_c.npub()).expect("C public key");
    let mut late_replay = client_a
        .subscribe(vec![
            Filter::new()
                .kind(Kind::Custom(fips_core::discovery::nostr::ADVERT_KIND))
                .author(author_c),
        ])
        .await
        .expect("late C advert subscription");
    let received = timeout(Duration::from_secs(5), late_replay.recv())
        .await
        .expect("C advert reaches A through B")
        .expect("late advert subscription remains open");

    assert_eq!(received.event.as_event().pubkey, author_c);
    assert!(received.event.as_event().content.contains("8.8.8.3:2121"));
    assert_eq!(received.source.kind, EventSourceKind::FipsEndpoint);
    assert_eq!(received.source.id.as_str(), endpoint_b.npub());
    for endpoint in [&endpoint_a, &endpoint_b, &endpoint_c] {
        assert!(
            endpoint
                .relay_statuses()
                .await
                .expect("relay status snapshot")
                .is_empty(),
            "external peerfinding must not open Nostr relay sockets"
        );
    }

    late_replay.close();
    client_a.shutdown().await;
    client_b.shutdown().await;
    client_c.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    endpoint_c.shutdown().await.expect("shutdown endpoint C");
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_capacity_keeps_a_bounded_working_subset_of_a_larger_mesh() {
    let network_id = format!("nostr-pubsub-fips-peer-capacity-{}", std::process::id());
    let (endpoint_a, endpoint_b, endpoint_c) = policy_advert_mesh(&network_id).await;
    let client_b = FipsPubsubClient::start_for_transport(
        Arc::clone(&endpoint_b),
        FipsPubsubClientOptions {
            max_connected_peers: 1,
            fanout: 1,
            ..Default::default()
        },
        "sim",
    )
    .await
    .expect("extra authenticated mesh peers must not disable pubsub");
    let selected = client_b
        .inner
        .connected_peer_links()
        .await
        .expect("bounded peers");
    assert_eq!(selected.len(), 1);
    let selected_endpoint = if selected[0].npub == endpoint_a.npub() {
        &endpoint_a
    } else {
        assert_eq!(selected[0].npub, endpoint_c.npub());
        &endpoint_c
    };
    let provider = start_client(selected_endpoint).await;
    wait_for_pubsub_connections(&client_b, 1).await;
    wait_for_peer_subscriptions(&provider, 1).await;

    let mut subscription = client_b
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .expect("subscribe while endpoint degree exceeds client capacity");
    wait_for_peer_subscriptions(&provider, 2).await;
    let event = VerifiedEvent::try_from(
        EventBuilder::text_note("delivery at peer capacity")
            .sign_with_keys(&Keys::generate())
            .expect("sign event"),
    )
    .expect("verify event");
    provider
        .publish(event.clone(), EventSource::local_index("capacity-test"))
        .await
        .expect("publish over the retained peer");
    let delivered = timeout(Duration::from_secs(5), subscription.recv())
        .await
        .expect("delivery over bounded peer subset")
        .expect("live subscription");
    assert_eq!(delivered.event, event);
    assert_eq!(
        client_b
            .connected_peer_count()
            .expect("bounded stream count"),
        1
    );
    assert_eq!(
        endpoint_b
            .peers()
            .await
            .expect("FIPS peers")
            .iter()
            .filter(|peer| peer.connected && peer.transport_type.as_deref() == Some("sim"))
            .count(),
        2,
        "pubsub capacity must not disconnect application-owned FIPS links"
    );

    subscription.close();
    client_b.shutdown().await;
    provider.shutdown().await;
    for endpoint in [&endpoint_a, &endpoint_b, &endpoint_c] {
        endpoint.shutdown().await.expect("shutdown endpoint");
    }
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn social_graph_rejected_advert_is_not_cached_or_forwarded() {
    let network_id = format!("nostr-pubsub-fips-advert-policy-{}", std::process::id());
    let (endpoint_a, endpoint_b, endpoint_c) = policy_advert_mesh(&network_id).await;

    let b_keys = Keys::parse(&hex::encode([52; 32])).expect("B signing keys");
    let mut negative = Rating::new(b_keys.public_key().to_hex(), endpoint_c.npub(), 0, 0, 100);
    negative.scope = Some("fips.peer".to_string());
    let negative = negative.to_event(&b_keys).expect("negative C rating");
    let stored = [negative];
    let b_policy = FipsPubsubPolicy::new(
        Arc::clone(&endpoint_b),
        stored.iter(),
        FipsPubsubPolicyOptions::default(),
    )
    .expect("B social policy");

    let client_a = start_client(&endpoint_a).await;
    let client_b = FipsPubsubClient::start_for_transport_with_policy(
        Arc::clone(&endpoint_b),
        FipsPubsubClientOptions::default(),
        "sim",
        b_policy.event_policy(),
    )
    .await
    .expect("start policy-filtered B client");
    let client_c = start_client(&endpoint_c).await;
    wait_for_pubsub_connections(&client_a, 1).await;
    wait_for_pubsub_connections(&client_b, 2).await;
    wait_for_pubsub_connections(&client_c, 1).await;
    wait_for_peer_subscriptions(&client_b, 2).await;
    wait_for_peer_subscriptions(&client_c, 1).await;

    let c_keys = Keys::parse(&hex::encode([53; 32])).expect("C signing keys");
    let author_c = c_keys.public_key();
    let filter = Filter::new()
        .kind(Kind::Custom(fips_core::discovery::nostr::ADVERT_KIND))
        .author(author_c);
    let mut a_subscription = client_a
        .subscribe(vec![filter.clone()])
        .await
        .expect("A subscribes to C adverts through B");
    wait_for_peer_subscriptions(&client_b, 3).await;

    let advert = signed_public_advert(&c_keys, "8.8.4.53:2121");
    let before = client_b.delivery_snapshot().event_frames_received;
    assert!(
        client_c
            .publish(advert, EventSource::local_index("policy-test"))
            .await
            .expect("publish C advert")
            .accepted
    );
    timeout(Duration::from_secs(3), async {
        while client_b.delivery_snapshot().event_frames_received <= before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("B receives the policy-rejected advert frame");

    assert!(
        client_b
            .inner
            .recent_matching_events(&[filter])
            .expect("B recent event cache")
            .is_empty(),
        "policy-rejected adverts must not enter replay or gossip state"
    );
    assert!(
        timeout(Duration::from_millis(300), a_subscription.recv())
            .await
            .is_err(),
        "B must not forward a policy-rejected C advert to A"
    );

    a_subscription.close();
    client_a.shutdown().await;
    client_b.shutdown().await;
    client_c.shutdown().await;
    endpoint_a.shutdown().await.expect("shutdown endpoint A");
    endpoint_b.shutdown().await.expect("shutdown endpoint B");
    endpoint_c.shutdown().await.expect("shutdown endpoint C");
    unregister_sim_network(&network_id);
}

async fn policy_advert_mesh(
    network_id: &str,
) -> (Arc<FipsEndpoint>, Arc<FipsEndpoint>, Arc<FipsEndpoint>) {
    register_sim_network(network_id, SimNetwork::new(7_369));
    let identity_a = Identity::from_secret_bytes(&[51; 32]).expect("identity A");
    let identity_b = Identity::from_secret_bytes(&[52; 32]).expect("identity B");
    let identity_c = Identity::from_secret_bytes(&[53; 32]).expect("identity C");
    let endpoint_a = advert_endpoint(
        network_id,
        "policy-a",
        [51; 32],
        [(identity_b.npub(), "policy-b")],
        "8.8.4.1:2121",
    )
    .await;
    let endpoint_b = advert_endpoint(
        network_id,
        "policy-b",
        [52; 32],
        [
            (identity_a.npub(), "policy-a"),
            (identity_c.npub(), "policy-c"),
        ],
        "8.8.4.2:2121",
    )
    .await;
    let endpoint_c = advert_endpoint(
        network_id,
        "policy-c",
        [53; 32],
        [(identity_b.npub(), "policy-b")],
        "8.8.4.3:2121",
    )
    .await;
    wait_for_connected_peer(&endpoint_a, endpoint_b.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_a.npub()).await;
    wait_for_connected_peer(&endpoint_b, endpoint_c.npub()).await;
    wait_for_connected_peer(&endpoint_c, endpoint_b.npub()).await;
    (endpoint_a, endpoint_b, endpoint_c)
}

fn signed_public_advert(keys: &Keys, addr: &str) -> VerifiedEvent {
    let now = Timestamp::now().as_secs();
    VerifiedEvent::try_from(
        EventBuilder::new(
            Kind::Custom(fips_core::discovery::nostr::ADVERT_KIND),
            format!(
                r#"{{"identifier":"fips-overlay-v1","version":1,"endpoints":[{{"transport":"tcp","addr":"{addr}"}}]}}"#
            ),
        )
        .tags([
            Tag::identifier(fips_core::discovery::nostr::ADVERT_IDENTIFIER),
            Tag::custom(
                TagKind::custom("protocol"),
                [fips_core::discovery::nostr::ADVERT_IDENTIFIER],
            ),
            Tag::custom(TagKind::custom("version"), ["1"]),
            Tag::expiration(Timestamp::from(now.saturating_add(3_600))),
        ])
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(keys)
        .expect("signed public FIPS advert"),
    )
    .expect("verified public FIPS advert")
}

async fn advert_endpoint<const N: usize>(
    network_id: &str,
    address: &str,
    secret: [u8; 32],
    peers: [(String, &str); N],
    external_addr: &str,
) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_backoff_secs = 1;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.peerfinding_source = NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(address.to_string()),
        mtu: Some(1280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.transports.tcp = TransportInstances::Single(TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        external_addr: Some(external_addr.to_string()),
        ..Default::default()
    });
    config.peers = peers
        .into_iter()
        .map(|(npub, peer_addr)| PeerConfig::new(npub, "sim", peer_addr))
        .collect();
    Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind(),
        )
        .await
        .unwrap_or_else(|error| panic!("bind endpoint {address}: {error}")),
    )
}

async fn start_client(endpoint: &Arc<FipsEndpoint>) -> FipsPubsubClient {
    FipsPubsubClient::start_for_transport(
        Arc::clone(endpoint),
        FipsPubsubClientOptions::default(),
        "sim",
    )
    .await
    .expect("start FIPS pubsub client")
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, expected_npub: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            if endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .any(|peer| peer.connected && peer.npub == expected_npub)
            {
                return;
            }
            tokio::task::yield_now().await;
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
    .expect("FIPS pubsub streams connect");
}

async fn wait_for_peer_subscriptions(client: &FipsPubsubClient, expected: usize) {
    timeout(Duration::from_secs(5), async {
        loop {
            if client
                .peer_subscription_count()
                .expect("peer subscription count")
                >= expected
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("default advert subscriptions converge");
}
