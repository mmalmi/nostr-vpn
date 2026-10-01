use super::*;

#[test]
fn cached_verified_control_replays_skip_policy_work_but_adverts_do_not() {
    run_async_test("verified-control-replay", || async {
        let owner = Keys::generate();
        let peer = Keys::generate();
        let endpoint = endpoint(&owner, endpoint_config(0, &[])).await;
        let updates = update_events(&owner, "releases/verified-replay");
        let mut rating = Rating::new(
            owner.public_key().to_hex(),
            peer.public_key().to_hex(),
            80,
            0,
            100,
        );
        rating.scope = Some("fips.peer".to_string());
        rating.created_at = now_ms() / 1_000;
        let cached = rating.to_event(&owner).expect("signed cached rating");
        rating.created_at += 1;
        let unseen = rating.to_event(&owner).expect("signed unseen rating");
        let advert = EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND), "advert refresh")
            .sign_with_keys(&owner)
            .expect("signed discovery advert envelope");
        let mut store = ControlEventStore::load(None, updates.clone()).expect("event store");
        assert!(store.insert(cached.clone()).expect("cache rating"));
        assert!(store.insert(advert.clone()).expect("cache advert envelope"));
        let policy = Arc::new(Mutex::new(
            FipsPubsubPolicy::new(
                Arc::clone(&endpoint),
                store.snapshot().iter(),
                FipsPubsubPolicyOptions::default(),
            )
            .expect("pubsub policy"),
        ));
        let events = Arc::new(Mutex::new(store));
        let client = FipsPubsubClient::start(
            Arc::clone(&endpoint),
            fips_pubsub_options(CONTROL_PUBSUB_MAX_EVENT_BYTES, 4),
        )
        .await
        .expect("production FIPS pubsub carrier");

        // Exercise both real delivery paths. Holding policy makes repeated
        // work observable without adding production counters or test hooks.
        // Only an authenticated, already-retained non-discovery event may
        // bypass it; unseen events and discovery refreshes must still enter.
        let guard = policy.lock().await;
        for relay in [false, true] {
            for (event, skips_policy) in [(&cached, true), (&unseen, false), (&advert, false)] {
                let delivery = QueryEvent {
                    event: verify_control_event(event.clone(), &updates)
                        .expect("verified delivery"),
                    source: EventSource::relay("ws://127.0.0.1"),
                    priority: 0,
                };
                let processed = tokio::time::timeout(Duration::from_millis(100), async {
                    if relay {
                        process_relay_delivery(
                            &endpoint, &client, &events, &policy, &updates, delivery,
                        )
                        .await;
                    } else {
                        process_fips_delivery(
                            &endpoint, None, &events, &policy, &updates, delivery,
                        )
                        .await;
                    }
                })
                .await;
                assert_eq!(
                    processed.is_ok(),
                    skips_policy,
                    "relay={relay}, kind={}, cached={}",
                    event.kind,
                    event.id != unseen.id,
                );
            }
        }
        drop(guard);
        assert_eq!(events.lock().await.snapshot().len(), 2);
        client.shutdown().await;
        endpoint.shutdown().await.expect("shutdown endpoint");
    });
}

#[test]
fn invalid_replayed_id_cannot_poison_verified_control_deduplication() {
    let publisher = Keys::generate();
    let tree = "releases/reused-id";
    let updates = update_events(&publisher, tree);
    let valid = signed_update_root(&publisher, tree, 1, "aa");
    let mut forged = valid.clone();
    forged.content.push_str("changed without a valid signature");
    assert_eq!(forged.id, valid.id, "attacker reuses a genuine event ID");
    assert!(verify_control_event(forged, &updates).is_err());
    let verified = verify_control_event(valid.clone(), &updates).expect("genuine event");
    let mut store = ControlEventStore::load(None, updates).expect("event store");
    assert!(
        store
            .insert(verified.as_event().clone())
            .expect("first genuine event")
    );
    assert!(
        !store
            .insert(valid)
            .expect("genuine replay is already retained")
    );
    assert_eq!(store.snapshot().len(), 1);
}
