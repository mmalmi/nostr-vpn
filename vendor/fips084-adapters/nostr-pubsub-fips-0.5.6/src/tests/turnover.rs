use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capacity_one_turnover_replays_subscriptions_and_rejects_stale_sends() {
    let (network_id, receiver_endpoint, early_endpoint, late_secret) = turnover_endpoints().await;
    let receiver = FipsPubsubClient::start_for_transport(
        receiver_endpoint.clone(),
        FipsPubsubClientOptions {
            max_connected_peers: 1,
            fanout: 1,
            ..Default::default()
        },
        "sim",
    )
    .await
    .unwrap();
    let early = start_sim_client(&early_endpoint, "early provider").await;
    let filter = Filter::new().kind(Kind::TextNote);
    let mut deliveries = receiver.subscribe(vec![filter.clone()]).await.unwrap();
    let early_subscription = early.subscribe(vec![filter.clone()]).await.unwrap();
    wait_for_peer_subscription_count(&receiver, 2).await;
    wait_for_peer_subscription_count(&early, 2).await;

    let late_endpoint = live_endpoint(
        &network_id,
        "turnover-late",
        late_secret,
        [(receiver_endpoint.npub().to_string(), "turnover-receiver")],
    )
    .await;
    wait_for_connected_peer(&receiver_endpoint, late_endpoint.npub()).await;
    let late = start_sim_client(&late_endpoint, "late provider").await;
    let late_subscription = late.subscribe(vec![filter]).await.unwrap();
    let event = VerifiedEvent::try_from(
        EventBuilder::text_note("replacement provider cached announcement")
            .sign_with_keys(&Keys::generate())
            .unwrap(),
    )
    .unwrap();
    late.publish(event.clone(), EventSource::local_index("late-provider"))
        .await
        .unwrap();
    let delivered = timeout(Duration::from_secs(5), deliveries.recv())
        .await
        .expect("replacement peer must deliver without rebuilding the live subscription")
        .expect("live subscription");
    assert_eq!(delivered.event, event);
    assert_eq!(delivered.source.id.as_str(), late_endpoint.npub());
    wait_for_peer_subscription_count(&receiver, 2).await;

    // Commands enqueued for the old peer must not reclaim a connection or queue slot.
    let stale_frame = receiver
        .inner
        .codec
        .encode_frame(&FipsPubsubWireMessage::req(
            SubscriptionId::new("stale-peer-request"),
            vec![Filter::new().kind(Kind::TextNote)],
        ))
        .unwrap();
    receiver
        .inner
        .send_frame(
            PeerIdentity::from_npub(early_endpoint.npub()).unwrap(),
            stale_frame,
        )
        .unwrap();
    let reverse = VerifiedEvent::try_from(
        EventBuilder::text_note("replacement peer subscription remains admitted")
            .sign_with_keys(&Keys::generate())
            .unwrap(),
    )
    .unwrap();
    receiver
        .publish(reverse.clone(), EventSource::local_index("receiver"))
        .await
        .unwrap();
    let mut late_subscription = late_subscription;
    timeout(Duration::from_secs(5), async {
        loop {
            if late_subscription.recv().await.unwrap().event == reverse {
                break;
            }
        }
    })
    .await
    .expect("replacement peer REQ must displace old retained peer metadata");
    assert_eq!(receiver.connected_peer_count().unwrap(), 1);
    assert_eq!(receiver.peer_subscription_snapshot().unwrap().peer_count, 1);
    assert_eq!(
        receiver_endpoint
            .peers()
            .await
            .unwrap()
            .iter()
            .filter(|peer| peer.connected)
            .count(),
        2
    );

    drop((deliveries, early_subscription, late_subscription));
    receiver.shutdown().await;
    early.shutdown().await;
    late.shutdown().await;
    for endpoint in [receiver_endpoint, early_endpoint, late_endpoint] {
        endpoint.shutdown().await.unwrap();
    }
    unregister_sim_network(&network_id);
}

async fn turnover_endpoints() -> (String, Arc<FipsEndpoint>, Arc<FipsEndpoint>, [u8; 32]) {
    let network_id = format!("nostr-pubsub-fips-turnover-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7374));
    let receiver_identity = Identity::from_secret_bytes(&[61; 32]).expect("receiver identity");
    let mut providers = [[62; 32], [63; 32]];
    providers.sort_by_key(|secret| Identity::from_secret_bytes(secret).unwrap().npub());
    let late_identity = Identity::from_secret_bytes(&providers[0]).unwrap();
    let early_identity = Identity::from_secret_bytes(&providers[1]).unwrap();
    let receiver_endpoint = live_endpoint(
        &network_id,
        "turnover-receiver",
        [61; 32],
        [
            (early_identity.npub(), "turnover-early"),
            (late_identity.npub(), "turnover-late"),
        ],
    )
    .await;
    let early_endpoint = live_endpoint(
        &network_id,
        "turnover-early",
        providers[1],
        [(receiver_identity.npub(), "turnover-receiver")],
    )
    .await;
    wait_for_connected_peer(&receiver_endpoint, early_endpoint.npub()).await;
    (network_id, receiver_endpoint, early_endpoint, providers[0])
}
