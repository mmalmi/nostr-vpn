use super::*;
use nostr_pubsub::NostrEventSubscriber;

#[test]
fn updater_reads_retained_root_after_peer_adverts_exhaust_recent_replay() {
    run_async_test("retained-update-root", || async {
        let provider_keys = Keys::generate();
        let updater_keys = Keys::generate();
        let publisher = Keys::generate();
        let tree = "releases/retained-update-test";
        let updates = update_events(&publisher, tree);
        let [provider_port, updater_port, _] = available_udp_ports();
        let provider = endpoint(&provider_keys, endpoint_config(provider_port, &[])).await;
        let runtime = start_pubsub(Arc::clone(&provider), updates.clone()).await;
        let root = signed_update_root(&publisher, tree, 1, "ab");
        assert!(runtime.publish(root.clone()).await.unwrap());
        // The real daemon retains the release while newer advertisements crowd
        // it out of the small transport cache. Restart replay has the same limit.
        for index in 0..FIPS_REPLAY_LIMIT * 2 {
            let advert = EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND), "")
                .custom_created_at(Timestamp::from(index as u64 + 2))
                .sign_with_keys(&Keys::generate())
                .unwrap();
            assert!(runtime.publish(advert).await.unwrap());
        }
        assert!(
            runtime
                .events()
                .await
                .iter()
                .any(|event| event.id == root.id)
        );
        let reader_endpoint = endpoint(
            &updater_keys,
            endpoint_config(updater_port, &[(provider.npub(), provider_port)]),
        )
        .await;
        let reader = Arc::new(
            FipsPubsubClient::start(
                Arc::clone(&reader_endpoint),
                FipsPubsubClientOptions::default(),
            )
            .await
            .unwrap(),
        );
        let (tx, mut rx) = mpsc::channel(1);
        let subscription = reader
            .fresh_subscriber()
            .subscribe(
                vec![updates.filter().clone()],
                Arc::new(move |event| {
                    let _ = tx.try_send(event);
                }),
            )
            .await
            .unwrap();
        let received = tokio::time::timeout(FIPS_TEST_EVENTUAL_TIMEOUT, rx.recv()).await;
        subscription.close().await.unwrap();
        reader.shutdown_shared().await;
        runtime.stop().await;
        reader_endpoint.shutdown().await.unwrap();
        provider.shutdown().await.unwrap();
        let event = received
            .expect("fresh peer must serve the retained release root")
            .unwrap();
        assert_eq!(event.event.as_event().id, root.id);
        assert_ne!(event.source.kind, nostr_pubsub::EventSourceKind::LocalIndex);
    });
}
