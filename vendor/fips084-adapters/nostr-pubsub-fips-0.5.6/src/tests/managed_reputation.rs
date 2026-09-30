use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_reputation_consumes_configured_ratings_and_releases_owned_state() {
    let network_id = format!("pubsub-managed-reputation-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7379));
    let identities =
        [[91; 32], [92; 32]].map(|secret| Identity::from_secret_bytes(&secret).unwrap());
    let receiver_endpoint = live_endpoint(
        &network_id,
        "managed-receiver",
        [91; 32],
        [(identities[1].npub(), "managed-rater")],
    )
    .await;
    let rater_endpoint = live_endpoint(
        &network_id,
        "managed-rater",
        [92; 32],
        [(identities[0].npub(), "managed-receiver")],
    )
    .await;
    wait_for_connected_peer(&receiver_endpoint, rater_endpoint.npub()).await;
    let mut policy_options = FipsPubsubPolicyOptions::default();
    policy_options
        .reputation
        .trusted_raters
        .insert(rater_endpoint.npub().to_owned());
    let mut receiver = FipsPubsubClient::start_with_reputation(
        receiver_endpoint.clone(),
        FipsPubsubClientOptions {
            max_active_subscriptions: 2,
            ..Default::default()
        },
        policy_options,
    )
    .await
    .unwrap();
    let rater = start_sim_client(&rater_endpoint, "managed-rater").await;
    let deliveries = receiver
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    assert_eq!(receiver.active_subscription_count().unwrap(), 3);
    assert!(
        receiver.subscribe(vec![Filter::new()]).await.is_err(),
        "managed subscription consumes bounded capacity"
    );
    wait_for_peer_subscription_count(&rater, 3).await;

    let subject = Identity::from_secret_bytes(&[93; 32]).unwrap().npub();
    let policy = receiver.inner.peer_policy.as_ref().unwrap().clone();
    assert!(policy.select_mesh_peer(&subject).unwrap().is_some());
    let rating = reputation::rating_event(
        &Keys::parse(&hex::encode([92; 32])).unwrap(),
        &subject,
        0,
        Timestamp::now().as_secs(),
    );
    rater
        .publish(
            VerifiedEvent::try_from(rating).unwrap(),
            EventSource::local_index("managed-rating-test"),
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        while policy.select_mesh_peer(&subject).unwrap().is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("configured signed rating must reach the managed projection");
    assert_eq!(receiver.reputation_error_count(), 0);
    assert_eq!(
        receiver_endpoint
            .peers()
            .await
            .unwrap()
            .iter()
            .filter(|p| p.connected)
            .count(),
        1
    );
    failed_publications_must_not_starve_local_observations(&mut receiver, &rater).await;
    let inner = Arc::downgrade(&receiver.inner);
    drop(deliveries);
    receiver.shutdown().await;
    assert!(
        inner.upgrade().is_none(),
        "managed task and subscription must release client state"
    );
    rater.shutdown().await;
    receiver_endpoint.shutdown().await.unwrap();
    rater_endpoint.shutdown().await.unwrap();
    unregister_sim_network(&network_id);
}

async fn failed_publications_must_not_starve_local_observations(
    client: &mut FipsPubsubClient,
    remote: &FipsPubsubClient,
) {
    let sink = remote.subscribe(vec![Filter::new()]).await.unwrap();
    wait_for_peer_subscription_count(client, 2).await;
    let transport = client.tasks.get_mut().transport.take().unwrap();
    transport.abort();
    let _ = transport.await;
    let mut observations = FipsPubsubPolicy::new(
        client.inner.endpoint.clone(),
        std::iter::empty(),
        FipsPubsubPolicyOptions::default(),
    )
    .unwrap();
    let subjects =
        [[94; 32], [95; 32]].map(|secret| Identity::from_secret_bytes(&secret).unwrap().npub());
    let signer = Keys::parse(&hex::encode([91; 32])).unwrap();
    let now = now_ms();
    let events = subjects
        .iter()
        .map(|subject| reputation::rating_event(&signer, subject, 0, now / 1_000))
        .collect();
    assert!(
        crate::client_reputation::publish_ratings(&client.inner, &mut observations, events, now)
            .await
            .is_err(),
        "closed transport must expose publication failure"
    );
    for subject in subjects {
        assert!(
            observations
                .peer_policy()
                .select_mesh_peer(&subject)
                .unwrap()
                .is_none(),
            "every local observation must apply despite an earlier publication failure"
        );
    }
    drop(sink);
}
