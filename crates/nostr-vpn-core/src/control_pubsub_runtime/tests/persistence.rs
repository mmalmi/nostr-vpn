use super::*;

async fn persistent_runtime(
    endpoint: Arc<FipsEndpoint>,
    updates: UpdateEventCache,
    path: PathBuf,
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
        Some(path),
        None,
        Some(updates),
        relay_advert_filters(None, &[]),
        MAX_PUBSUB_PEERS,
    )
    .await
    .unwrap()
    .unwrap()
}

#[test]
fn control_store_async_received_event_survives_runtime_restart() {
    run_async_test("durable-control-runtime", || async {
        let publisher = Keys::generate();
        let receiver_keys = Keys::generate();
        let publisher_npub = publisher.public_key().to_bech32().unwrap();
        let receiver_npub = receiver_keys.public_key().to_bech32().unwrap();
        let [publisher_port, receiver_port, _] = available_udp_ports();
        let sender = endpoint(
            &publisher,
            endpoint_config(publisher_port, &[(&receiver_npub, receiver_port)]),
        )
        .await;
        let receiver = endpoint(
            &receiver_keys,
            endpoint_config(receiver_port, &[(&publisher_npub, publisher_port)]),
        )
        .await;
        wait_connected(&sender, &receiver_npub).await;
        wait_connected(&receiver, &publisher_npub).await;

        let directory = std::env::temp_dir().join(format!(
            "nvpn-durable-pubsub-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("events.json");
        let tree = "releases/durable-control-runtime";
        let updates = update_events(&publisher, tree);
        let receiving =
            persistent_runtime(Arc::clone(&receiver), updates.clone(), path.clone()).await;
        let sending = start_pubsub(Arc::clone(&sender), updates.clone()).await;
        wait_pubsub_connected(&receiving).await;
        wait_pubsub_connected(&sending).await;
        let event = signed_update_root(&publisher, tree, 1, "cd");
        assert!(sending.publish(event.clone()).await.unwrap());
        wait_for_event(&receiving, event.id).await;
        receiving.stop().await;
        let saved: StoredEventsFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(saved.events.iter().any(|stored| stored.id == event.id));

        sending.stop().await;
        sender.shutdown().await.unwrap();
        receiver.shutdown().await.unwrap();
        drop(receiver);
        // The publisher is gone: restart must recover the durable store.
        let receiver = endpoint(&receiver_keys, endpoint_config(receiver_port, &[])).await;
        let restarted = persistent_runtime(Arc::clone(&receiver), updates, path).await;
        assert!(
            restarted
                .events()
                .await
                .iter()
                .any(|stored| stored.id == event.id)
        );
        restarted.stop().await;
        receiver.shutdown().await.unwrap();
        fs::remove_dir_all(directory).unwrap();
    });
}
