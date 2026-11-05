use super::*;

#[test]
fn mixed_history_and_release_delivery_do_not_wait_for_discovery_control() {
    run_async_test("pubsub-discovery-isolation", || async {
        let owner = Keys::generate();
        let node_keys = owner.clone();
        let (ready, endpoint_rx) = std::sync::mpsc::sync_channel(1);
        let (resume, paused) = std::sync::mpsc::sync_channel(1);
        let node = std::thread::Builder::new()
            .name("paused-discovery-node".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let mut config = endpoint_config(0, &[]);
                config.node.discovery.local.enabled = false;
                config.node.discovery.lan.enabled = false;
                config.node.discovery.nostr.enabled = false;
                config.node.system_files_enabled = false;
                let endpoint = runtime.block_on(endpoint(&node_keys, config));
                ready.send(Arc::clone(&endpoint)).unwrap();
                // Keep the real node/control channel alive but do not drive it.
                // No production test hooks or synthetic discovery implementation.
                let _ = paused.recv_timeout(Duration::from_secs(10));
                runtime.block_on(endpoint.shutdown()).unwrap();
            })
            .unwrap();
        let endpoint = endpoint_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), endpoint.peers())
                .await
                .is_err(),
            "fixture must hold the real endpoint control loop"
        );
        let tree = "releases/discovery-isolation";
        let updates = update_events(&owner, tree);
        let events = Arc::new(Mutex::new(
            ControlEventStore::load(None, updates.clone()).unwrap(),
        ));
        let policy = Arc::new(Mutex::new(
            FipsPubsubPolicy::new(
                Arc::clone(&endpoint),
                std::iter::empty::<&Event>(),
                FipsPubsubPolicyOptions::default(),
            )
            .unwrap(),
        ));
        let now = now_ms() / 1_000;
        let release = signed_update_root(&owner, tree, now, "a1");
        let mut history = (0..96)
            .map(|index| {
                EventBuilder::new(Kind::Custom([0, 3, 10_000][index % 3]), "{}")
                    .custom_created_at(Timestamp::from(now - 96 + index as u64))
                    .sign_with_keys(&owner)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        history.push(release.clone());
        // Include replay of already stored events and a distinct source observation.
        let sources = [
            EventSource::fips_endpoint(owner.public_key().to_hex()),
            EventSource::relay("wss://fixture.invalid"),
        ];
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            for source in sources {
                for event in &history {
                    process_fips_delivery(
                        &endpoint,
                        None,
                        &events,
                        &policy,
                        &updates,
                        QueryEvent {
                            event: VerifiedEvent::try_from(event.clone()).unwrap(),
                            source: source.clone(),
                            priority: 0,
                        },
                    )
                    .await;
                }
            }
        })
        .await;
        let elapsed = started.elapsed();
        let mut discovery_still_uses_node = true;
        for kind in [FIPS_PEER_ADVERT_KIND, RATING_FACT_KIND] {
            let event = EventBuilder::new(Kind::Custom(kind), "{}")
                .sign_with_keys(&owner)
                .unwrap();
            discovery_still_uses_node &= tokio::time::timeout(
                Duration::from_millis(50),
                ingest_into_fips_discovery(&endpoint, &event),
            )
            .await
            .is_err();
        }
        // Always release the node before reporting the regression failure.
        let _ = resume.send(());
        node.join().unwrap();
        result.expect("irrelevant discovery control must not delay profile/release delivery");
        assert!(
            discovery_still_uses_node,
            "discovery and rating validation must remain inside FIPS"
        );
        assert!(
            events
                .lock()
                .await
                .snapshot()
                .iter()
                .any(|event| event.id == release.id)
        );
        eprintln!("194 mixed history/release deliveries with paused discovery: {elapsed:?}");
    });
}
