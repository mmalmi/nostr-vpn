use super::*;
use std::sync::RwLock;

#[derive(Default)]
struct MutablePeerPolicy(RwLock<HashMap<String, Option<i32>>>);

impl MeshPeerPolicy for MutablePeerPolicy {
    fn select_mesh_peer(&self, peer_id: &str) -> Result<Option<nostr_pubsub::MeshPeer>> {
        Ok(match self.0.read().unwrap().get(peer_id) {
            Some(Some(score)) => Some(nostr_pubsub::MeshPeer::observed(peer_id, *score)),
            Some(None) => None,
            None => Some(nostr_pubsub::MeshPeer::new(peer_id)),
        })
    }
}

#[test]
fn high_level_peer_selection_keeps_unknown_capacity_and_bounds_fanout() {
    let policy = MutablePeerPolicy(RwLock::new(HashMap::from([
        ("best".into(), Some(100)),
        ("second".into(), Some(90)),
        ("blocked".into(), None),
    ])));
    let selected = crate::client_peers::select_policy_peers(
        &policy,
        ["blocked", "second", "unknown", "best", "best"].map(str::to_owned),
        2,
        1,
    )
    .unwrap();
    assert_eq!(selected, ["best", "unknown"]);
    assert!(
        crate::client_peers::select_policy_peers(&policy, ["best".to_owned()], 0, 1,)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn high_level_peer_selection_cannot_substitute_an_authenticated_identity() {
    struct Substitute;
    impl MeshPeerPolicy for Substitute {
        fn select_mesh_peer(&self, _: &str) -> Result<Option<nostr_pubsub::MeshPeer>> {
            Ok(Some(nostr_pubsub::MeshPeer::observed(
                "different-identity",
                100,
            )))
        }
    }
    assert_eq!(
        crate::client_peers::select_policy_peers(
            &Substitute,
            ["authenticated-identity".to_owned()],
            1,
            0,
        )
        .unwrap(),
        ["authenticated-identity"]
    );
}

#[test]
fn link_selection_preserves_rank_metadata_and_fresh_policy() {
    let policy = MutablePeerPolicy(RwLock::new(HashMap::from([
        ("best".into(), Some(100)),
        ("second".into(), Some(90)),
        ("blocked".into(), None),
    ])));
    let select = |links: &[(&str, u64)]| {
        crate::client_peers::select_links(
            Some(&policy),
            links
                .iter()
                .map(|(npub, link_id)| ConnectedPeerLink {
                    npub: (*npub).to_owned(),
                    link_id: *link_id,
                })
                .collect(),
            2,
            1,
        )
        .unwrap()
        .into_iter()
        .map(|link| (link.npub, link.link_id))
        .collect::<Vec<_>>()
    };
    assert_eq!(
        select(&[
            ("second", 2),
            ("best", 1),
            ("blocked", 4),
            ("unknown", 3),
            ("best", 5),
        ]),
        [("best".to_owned(), 5), ("unknown".to_owned(), 3)]
    );

    policy.0.write().unwrap().insert("best".into(), None);
    assert_eq!(
        select(&[("best", 15), ("unknown", 13), ("second", 12)]),
        [("second".to_owned(), 12), ("unknown".to_owned(), 13)]
    );
}

async fn policy_endpoints(network_id: &str) -> [Arc<FipsEndpoint>; 3] {
    let mut provider_secrets = [[82; 32], [83; 32]];
    provider_secrets.sort_by_key(|secret| Identity::from_secret_bytes(secret).unwrap().npub());
    let identities = [[81; 32], provider_secrets[1], provider_secrets[0]]
        .map(|secret| Identity::from_secret_bytes(&secret).unwrap());
    let receiver_endpoint = live_endpoint(
        network_id,
        "policy-receiver",
        [81; 32],
        [
            (identities[1].npub(), "policy-early"),
            (identities[2].npub(), "policy-late"),
        ],
    )
    .await;
    let early_endpoint = live_endpoint(
        network_id,
        "policy-early",
        provider_secrets[1],
        [(identities[0].npub(), "policy-receiver")],
    )
    .await;
    let late_endpoint = live_endpoint(
        network_id,
        "policy-late",
        provider_secrets[0],
        [(identities[0].npub(), "policy-receiver")],
    )
    .await;
    for peer in [&early_endpoint, &late_endpoint] {
        wait_for_connected_peer(&receiver_endpoint, peer.npub()).await;
    }
    [receiver_endpoint, early_endpoint, late_endpoint]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_level_peer_policy_replaces_revoked_peer_without_losing_subscription() {
    let network_id = format!("pubsub-policy-turnover-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7378));
    let [receiver_endpoint, early_endpoint, late_endpoint] = policy_endpoints(&network_id).await;
    let policy = Arc::new(MutablePeerPolicy(RwLock::new(HashMap::from([
        (early_endpoint.npub().to_owned(), Some(100)),
        (late_endpoint.npub().to_owned(), Some(1)),
    ]))));
    let receiver = FipsPubsubClient::start_with_policies(
        receiver_endpoint.clone(),
        FipsPubsubClientOptions {
            max_connected_peers: 1,
            fanout: 1,
            ..Default::default()
        },
        FipsPubsubClientPolicies {
            peers: Some(policy.clone()),
            events: None,
            unknown_peer_reserve: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        receiver.inner.connected_peer_links().await.unwrap()[0].npub,
        early_endpoint.npub(),
        "configured quality must select the provider"
    );
    let early = start_sim_client(&early_endpoint, "policy-early").await;
    let late = start_sim_client(&late_endpoint, "policy-late").await;
    let mut deliveries = receiver
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    wait_for_peer_subscription_count(&early, 2).await;
    policy
        .0
        .write()
        .unwrap()
        .insert(early_endpoint.npub().to_owned(), None);
    timeout(Duration::from_secs(5), async {
        loop {
            if receiver.inner.connected_peer_links().await.unwrap()[0].npub == late_endpoint.npub()
                && late
                    .peer_subscription_snapshot()
                    .unwrap()
                    .subscription_count
                    >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("revocation must switch the existing client to the eligible peer");
    let event = VerifiedEvent::try_from(
        EventBuilder::text_note("policy replacement delivery")
            .sign_with_keys(&Keys::generate())
            .unwrap(),
    )
    .unwrap();
    late.publish(event.clone(), EventSource::local_index("policy-test"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), deliveries.recv())
            .await
            .unwrap()
            .unwrap()
            .event,
        event
    );
    assert_eq!(
        receiver_endpoint
            .peers()
            .await
            .unwrap()
            .iter()
            .filter(|p| p.connected)
            .count(),
        2,
        "pubsub policy must preserve application-owned physical links"
    );
    drop(deliveries);
    receiver.shutdown().await;
    early.shutdown().await;
    late.shutdown().await;
    for endpoint in [receiver_endpoint, early_endpoint, late_endpoint] {
        endpoint.shutdown().await.unwrap();
    }
    unregister_sim_network(&network_id);
}
