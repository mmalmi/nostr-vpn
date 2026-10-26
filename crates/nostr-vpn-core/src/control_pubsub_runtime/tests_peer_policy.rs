struct MutablePeerPolicy(std::sync::atomic::AtomicBool);

impl MeshPeerPolicy for MutablePeerPolicy {
    fn select_mesh_peer(&self, peer_id: &str) -> nostr_pubsub::Result<Option<MeshPeer>> {
        Ok(self
            .0
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| MeshPeer::new(peer_id)))
    }
}

#[test]
fn peer_policy_revokes_and_restores_pubsub_without_dropping_fips_link() {
    run_async_test(
        "policy-fips-pubsub",
        peer_policy_revokes_and_restores_pubsub_without_dropping_fips_link_run,
    );
}

async fn peer_policy_revokes_and_restores_pubsub_without_dropping_fips_link_run() {
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
    let peer_policy = Arc::new(MutablePeerPolicy(std::sync::atomic::AtomicBool::new(true)));
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
        Some(peer_policy.clone()),
        Some(update_events),
        relay_advert_filters(None, &[]),
        MAX_PUBSUB_PEERS,
    )
    .await
    .expect("start policy-bound FIPS pubsub")
    .expect("FIPS pubsub enabled");
    wait_pubsub_connected(&alice_pubsub).await;
    wait_pubsub_connected(&bob_pubsub).await;
    let first = signed_update_root(&publisher, tree_name, 1, "11");
    assert!(
        alice_pubsub
            .publish(first.clone())
            .await
            .expect("publish before policy revocation")
    );
    wait_for_event(&bob_pubsub, first.id).await;

    peer_policy
        .0
        .store(false, std::sync::atomic::Ordering::Relaxed);
    tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, async {
        loop {
            if bob_pubsub.connected_peer_count().await.unwrap() == 0
                && bob_pubsub.peer_subscription_count().await.unwrap() == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("revoked peer releases its pubsub connection and subscriptions");
    assert_udp_link(&bob_endpoint, &alice_npub).await;

    peer_policy
        .0
        .store(true, std::sync::atomic::Ordering::Relaxed);
    wait_pubsub_connected(&alice_pubsub).await;
    wait_pubsub_connected(&bob_pubsub).await;
    let resumed = signed_update_root(&publisher, tree_name, 2, "22");
    assert!(
        alice_pubsub
            .publish(resumed.clone())
            .await
            .expect("publish after policy readmission")
    );
    wait_for_event(&bob_pubsub, resumed.id).await;

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

#[cfg(not(feature = "paid-exit"))]
#[test]
fn peerfinding_without_paid_exit_never_subscribes_to_or_retains_paid_offers() {
    let publisher = Keys::generate();
    let updates = update_events(&publisher, "releases/mobile-peerfinding");
    let offer = EventBuilder::new(Kind::Custom(PAID_EXIT_OFFER_KIND), "offer")
        .sign_with_keys(&publisher)
        .unwrap();
    for filter in relay_subscription_filters(
        &peer_rating_filter(&publisher),
        &updates,
        relay_advert_filters(None, &[]),
    )
    .into_iter()
    .chain(fips_subscription_filters(
        &peer_rating_filter(&publisher),
        &updates,
    )) {
        assert!(!filter.match_event(&offer, MatchEventOptions::new()));
    }
    assert!(!is_control_event(&offer, &updates));
    let mut store = ControlEventStore::load(None, updates).unwrap();
    assert!(!store.insert(offer).unwrap());
    assert!(store.snapshot().is_empty());
}

#[test]
fn subscriptions_do_not_request_untrusted_machine_ratings() {
    let owner = Keys::generate();
    let stranger = Keys::generate();
    let updates = update_events(&owner, "releases/rating-scope");
    let rating = EventBuilder::new(Kind::Custom(RATING_FACT_KIND), "")
        .tag(Tag::custom(TagKind::Custom("i".into()), ["fips.peer"]))
        .sign_with_keys(&stranger)
        .unwrap();
    let own_rating = EventBuilder::new(Kind::Custom(RATING_FACT_KIND), "")
        .tag(Tag::custom(TagKind::Custom("i".into()), ["fips.peer"]))
        .sign_with_keys(&owner)
        .unwrap();
    let exit_rating = EventBuilder::new(Kind::Custom(RATING_FACT_KIND), "")
        .tag(Tag::custom(TagKind::Custom("i".into()), ["vpn.exit"]))
        .sign_with_keys(&stranger)
        .unwrap();
    for filters in [
        relay_subscription_filters(
            &peer_rating_filter(&owner),
            &updates,
            relay_advert_filters(None, &[]),
        ),
        fips_subscription_filters(&peer_rating_filter(&owner), &updates),
    ] {
        assert!(
            filters
                .iter()
                .any(|f| f.match_event(&own_rating, MatchEventOptions::new()))
        );
        assert_eq!(
            filters
                .iter()
                .any(|f| f.match_event(&exit_rating, MatchEventOptions::new())),
            cfg!(feature = "paid-exit")
        );
        assert!(
            filters
                .iter()
                .all(|f| !f.match_event(&rating, MatchEventOptions::new())),
            "untrusted machine ratings must not be requested from relays or peers"
        );
    }
}

#[test]
#[cfg(feature = "paid-exit")]
fn owner_graph_replay_is_not_crowded_out_by_recent_machine_ratings() {
    run_async_test("owner-graph-replay", || async {
        let owner = Keys::generate();
        let provider = Keys::generate();
        let owner_npub = owner.public_key().to_bech32().unwrap();
        let provider_npub = provider.public_key().to_bech32().unwrap();
        let [owner_port, provider_port, _] = available_udp_ports();
        let owner_endpoint = endpoint(
            &owner,
            endpoint_config(owner_port, &[(&provider_npub, provider_port)]),
        )
        .await;
        let provider_endpoint = endpoint(
            &provider,
            endpoint_config(provider_port, &[(&owner_npub, owner_port)]),
        )
        .await;
        wait_connected(&owner_endpoint, &provider_npub).await;
        let provider_bus = FipsPubsubClient::start(
            Arc::clone(&provider_endpoint),
            FipsPubsubClientOptions {
                max_replay_events: 256,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let now = Timestamp::now().as_secs();
        let contacts = EventBuilder::new(Kind::ContactList, "")
            .custom_created_at(Timestamp::from(now - 300))
            .sign_with_keys(&owner)
            .unwrap();
        let mute = EventBuilder::new(Kind::MuteList, "")
            .custom_created_at(Timestamp::from(now - 299))
            .sign_with_keys(&owner)
            .unwrap();
        for index in 0..129 {
            let mut rating = Rating::new(
                owner.public_key().to_hex(),
                Keys::generate().public_key().to_hex(),
                80,
                0,
                100,
            );
            rating.scope = Some("fips.peer".into());
            rating.created_at = now - 129 + index;
            provider_bus
                .publish(
                    VerifiedEvent::try_from(rating.to_event(&owner).unwrap()).unwrap(),
                    EventSource::local_index(&owner_npub),
                )
                .await
                .unwrap();
        }
        for event in [contacts.clone(), mute.clone()] {
            provider_bus
                .publish(
                    VerifiedEvent::try_from(event).unwrap(),
                    EventSource::local_index(&owner_npub),
                )
                .await
                .unwrap();
        }
        let runtime = start_pubsub(
            Arc::clone(&owner_endpoint),
            update_events(&provider, "releases/owner-graph-replay"),
        )
        .await;
        let graph_result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let received = runtime.events().await;
                if received.iter().any(|event| event.id == contacts.id)
                    && received.iter().any(|event| event.id == mute.id)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            graph_result.is_ok(),
            "received kinds: {:?}; provider: {:?}",
            runtime
                .events()
                .await
                .iter()
                .map(|e| e.kind)
                .collect::<Vec<_>>(),
            provider_bus.delivery_snapshot()
        );
        runtime.stop().await;
        provider_bus.shutdown_shared().await;
        owner_endpoint.shutdown().await.unwrap();
        provider_endpoint.shutdown().await.unwrap();
    });
}

#[test]
fn legacy_foreign_ratings_do_not_crowd_out_owner_replay() {
    run_async_test(
        "legacy-rating-replay",
        legacy_foreign_ratings_do_not_crowd_out_owner_replay_run,
    );
}

async fn legacy_foreign_ratings_do_not_crowd_out_owner_replay_run() {
    let owner = Keys::generate();
    let observer = Keys::generate();
    let stranger = Keys::generate();
    let owner_npub = owner.public_key().to_bech32().unwrap();
    let observer_npub = observer.public_key().to_bech32().unwrap();
    let directory = std::env::temp_dir().join(format!("nvpn-legacy-replay-{}", owner.public_key()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("events.json");
    let updates = update_events(&owner, "releases/legacy-ratings");
    let mut store = ControlEventStore::load(Some(path.clone()), updates.clone()).unwrap();
    let mut own = Rating::new(
        owner.public_key().to_hex(),
        stranger.public_key().to_hex(),
        80,
        0,
        100,
    );
    own.scope = Some("fips.peer".to_string());
    let own = own.to_event(&owner).unwrap();
    store.insert(own.clone()).unwrap();
    let mut foreign_ids = HashSet::new();
    for _ in 0..FIPS_REPLAY_LIMIT + 8 {
        let subject = Keys::generate().public_key().to_hex();
        let mut rating = Rating::new(stranger.public_key().to_hex(), subject, 80, 0, 100);
        rating.scope = Some("fips.peer".to_string());
        let event = rating.to_event(&stranger).unwrap();
        foreign_ids.insert(event.id);
        store.insert(event).unwrap();
    }
    drop(store);
    let [owner_port, observer_port, _] = available_udp_ports();
    let owner_endpoint = endpoint(&owner, endpoint_config(owner_port, &[])).await;
    let owner_runtime = ControlPubsubFipsRuntime::start_inner(
        Arc::clone(&owner_endpoint),
        NostrPubsubConfig {
            mode: NostrPubsubMode::Client,
            ..Default::default()
        },
        Vec::new(),
        Some(path),
        None,
        Some(updates),
        relay_advert_filters(None, &[]),
        MAX_PUBSUB_PEERS,
    )
    .await
    .unwrap()
    .unwrap();
    let observer_endpoint = endpoint(
        &observer,
        endpoint_config(observer_port, &[(&owner_npub, owner_port)]),
    )
    .await;
    let observer_pubsub = FipsPubsubClient::start(
        Arc::clone(&observer_endpoint),
        FipsPubsubClientOptions::default(),
    )
    .await
    .unwrap();
    let mut subscription = observer_pubsub
        .subscribe(vec![
            Filter::new()
                .kind(Kind::Custom(RATING_FACT_KIND))
                .limit(128),
        ])
        .await
        .unwrap();
    owner_endpoint
        .update_peers(vec![PeerConfig::new(
            &observer_npub,
            "udp",
            format!("127.0.0.1:{observer_port}"),
        )])
        .await
        .unwrap();
    wait_connected(&owner_endpoint, &observer_npub).await;
    wait_connected(&observer_endpoint, &owner_npub).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = subscription.recv().await.unwrap().event;
            assert!(
                !foreign_ids.contains(&event.as_event().id),
                "obsolete foreign ratings must not be republished from the old cache"
            );
            if event.as_event().id == own.id {
                break;
            }
        }
    })
    .await
    .expect("owner rating survives the legacy cache backlog");
    owner_runtime.stop().await;
    observer_pubsub.shutdown().await;
    owner_endpoint.shutdown().await.unwrap();
    observer_endpoint.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}
