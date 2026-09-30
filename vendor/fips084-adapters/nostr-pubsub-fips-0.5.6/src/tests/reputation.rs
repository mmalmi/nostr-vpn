use super::*;

#[tokio::test]
async fn reputation_facade_uses_explicit_virtual_time() {
    let network_id = format!("nostr-pubsub-fips-virtual-time-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7370));
    let subject = Keys::parse(&hex::encode([8; 32])).expect("subject key");
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let endpoint = Arc::new(
        Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(
                    &network_id,
                    "virtual-time",
                    [7; 32],
                    subject_npub.clone(),
                    "absent-peer",
                ))
                .without_system_tun()
                .bind(),
        )
        .await
        .expect("bind virtual-time endpoint"),
    );

    exercise_explicit_time_reputation(&endpoint, &subject_npub, [7; 32]).await;

    endpoint.shutdown().await.expect("shutdown endpoint");
    unregister_sim_network(&network_id);
}

async fn exercise_explicit_time_reputation(
    endpoint: &Arc<FipsEndpoint>,
    peer_npub: &str,
    secret: [u8; 32],
) {
    const NOW_SECS: u64 = 1_000_000;
    let signer = Keys::parse(&hex::encode(secret)).expect("FIPS identity signing key");
    assert_eq!(
        signer.public_key().to_bech32().expect("FIPS identity npub"),
        endpoint.npub()
    );
    let event = rating_event(&signer, peer_npub, 0, NOW_SECS);

    let stored = [event.clone()];
    let replayed = FipsPeerReputation::new_at(
        Arc::clone(endpoint),
        &stored,
        FipsPeerReputationOptions::default(),
        NOW_SECS,
    )
    .expect("replay at virtual time");
    assert_eq!(
        replayed
            .peer_policy()
            .select_mesh_peer(peer_npub)
            .expect("replayed peer policy"),
        None
    );

    let mut reputation = FipsPeerReputation::new_at(
        Arc::clone(endpoint),
        std::iter::empty(),
        FipsPeerReputationOptions::default(),
        NOW_SECS,
    )
    .expect("start reputation at virtual time");
    assert!(
        reputation
            .ingest_event_at(&event, NOW_SECS)
            .expect("ingest at virtual time")
    );

    let mut policy = FipsPubsubPolicy::new_at(
        Arc::clone(endpoint),
        std::iter::empty(),
        FipsPubsubPolicyOptions::default(),
        NOW_SECS,
    )
    .expect("start policy at virtual time");
    let source = EventSource::local_index("preverified-policy-test");
    let verified = VerifiedEvent::try_from(event.clone()).expect("verify rating once");
    assert_eq!(
        policy
            .check_event(&event, &source)
            .await
            .expect("plain event policy decision"),
        policy
            .check_verified_event(&verified, &source)
            .await
            .expect("preverified event policy decision"),
        "preverified events must preserve the normal reputation decision"
    );
    assert!(
        policy
            .observe_event_at(&event, NOW_SECS)
            .expect("observe at virtual time")
    );

    let mut completion = FipsPubsubPolicy::new_at(
        Arc::clone(endpoint),
        std::iter::empty(),
        FipsPubsubPolicyOptions::default(),
        NOW_SECS,
    )
    .expect("start completion policy at virtual time");
    completion
        .complete_maintenance_event(&event, true, NOW_SECS * 1_000)
        .expect("complete maintenance at virtual time");
    assert_eq!(
        completion
            .peer_policy()
            .select_mesh_peer(peer_npub)
            .expect("completed peer policy"),
        None
    );

    let mut disconnected = FipsPubsubPolicy::new_at(
        Arc::clone(endpoint),
        std::iter::empty(),
        FipsPubsubPolicyOptions::default(),
        NOW_SECS,
    )
    .expect("disconnected policy");
    disconnected
        .complete_maintenance_event(&event, false, NOW_SECS * 1_000)
        .expect("local observation survives a failed publication");
    assert_eq!(
        disconnected
            .peer_policy()
            .select_mesh_peer(peer_npub)
            .unwrap(),
        None
    );
}

pub(super) fn rating_event(signer: &Keys, subject: &str, value: i64, created_at: u64) -> Event {
    let mut rating = Rating::new(signer.public_key().to_hex(), subject, value, 0, 100);
    rating.scope = Some("fips.peer".to_string());
    rating.created_at = created_at;
    rating.sample_count = Some(3);
    let encoded = rating.to_event(signer).expect("encode peer rating");
    EventBuilder::new(encoded.kind, encoded.content)
        .tags(encoded.tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(signer)
        .expect("sign peer rating at virtual time")
}
