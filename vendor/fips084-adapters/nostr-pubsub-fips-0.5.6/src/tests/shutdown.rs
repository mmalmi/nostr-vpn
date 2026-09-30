use super::*;

#[tokio::test]
async fn retained_client_shutdown_joins_every_owned_task() {
    let (network_id, endpoint) = shutdown_endpoint("retained").await;
    let client = Arc::new(
        FipsPubsubClient::start_with_reputation(
            endpoint.clone(),
            FipsPubsubClientOptions::default(),
            FipsPubsubPolicyOptions::default(),
        )
        .await
        .unwrap(),
    );
    let retained = client.clone();
    let tasks = {
        let tasks = client.tasks.lock().await;
        [
            tasks.transport.as_ref().unwrap().abort_handle(),
            tasks.peerfinding.as_ref().unwrap().abort_handle(),
            tasks.reputation.as_ref().unwrap().abort_handle(),
        ]
    };
    let mut delivery = retained
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    assert_eq!(retained.active_subscription_count().unwrap(), 3);
    client.shutdown_shared().await;
    assert!(tasks.iter().all(tokio::task::AbortHandle::is_finished));
    assert_eq!(retained.active_subscription_count().unwrap(), 0);
    assert!(delivery.recv().await.is_none());
    assert!(retained.subscribe(vec![Filter::new()]).await.is_err());
    assert!(
        retained
            .query(vec![], QueryOptions { limit: Some(0) })
            .await
            .is_err()
    );
    assert!(
        retained
            .publish(shutdown_event(), EventSource::local_index("retained"))
            .await
            .is_err()
    );
    assert!(
        endpoint.peers().await.is_ok(),
        "client shutdown must leave the endpoint usable"
    );
    retained.shutdown_shared().await;
    drop(delivery);
    drop(retained);
    Arc::try_unwrap(client).ok().unwrap().shutdown().await;
    endpoint.shutdown().await.unwrap();
    unregister_sim_network(&network_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_shutdown_preserves_joins_when_the_first_waiter_is_cancelled() {
    let (network_id, endpoint) = shutdown_endpoint("concurrent").await;
    let client = Arc::new(
        FipsPubsubClient::start(endpoint.clone(), FipsPubsubClientOptions::default())
            .await
            .unwrap(),
    );
    let (started_tx, started_rx) = oneshot::channel();
    let (dropping_tx, dropping_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        let _completion = CompletionGate {
            dropping: Some(dropping_tx),
            release: release_rx,
        };
        started_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let completion = task.abort_handle();
    client.tasks.lock().await.reputation = Some(task);
    started_rx.await.unwrap();

    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.shutdown_shared().await });
    timeout(Duration::from_secs(5), dropping_rx)
        .await
        .unwrap()
        .unwrap();
    let second_client = client.clone();
    let (second_started_tx, second_started_rx) = oneshot::channel();
    let mut second = tokio::spawn(async move {
        second_started_tx.send(()).unwrap();
        second_client.shutdown_shared().await;
    });
    second_started_rx.await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), &mut second)
            .await
            .is_err()
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(
        timeout(Duration::from_millis(30), &mut second)
            .await
            .is_err()
    );
    assert!(!completion.is_finished());
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap();
    assert!(completion.is_finished());
    let tasks = client.tasks.lock().await;
    assert!(tasks.transport.is_none() && tasks.peerfinding.is_none() && tasks.reputation.is_none());
    drop(tasks);
    endpoint.shutdown().await.unwrap();
    unregister_sim_network(&network_id);
}

struct CompletionGate {
    dropping: Option<oneshot::Sender<()>>,
    release: std::sync::mpsc::Receiver<()>,
}

impl Drop for CompletionGate {
    fn drop(&mut self) {
        self.dropping.take().unwrap().send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

#[tokio::test]
async fn publication_waiting_for_policy_cannot_reopen_a_stopped_client() {
    let (network_id, endpoint) = shutdown_endpoint("admission").await;
    let policy = Arc::new(PausedPublication::default());
    let client = Arc::new(
        FipsPubsubClient::start_with_policy(
            endpoint.clone(),
            FipsPubsubClientOptions::default(),
            policy.clone(),
        )
        .await
        .unwrap(),
    );
    let publishing_client = client.clone();
    let publish = tokio::spawn(async move {
        publishing_client
            .publish(shutdown_event(), EventSource::local_index("delayed"))
            .await
    });
    timeout(Duration::from_secs(5), policy.entered.notified())
        .await
        .unwrap();
    client.shutdown_shared().await;
    policy.resume.notify_one();
    assert!(publish.await.unwrap().is_err());
    assert!(
        client
            .inner
            .recent_events
            .lock()
            .unwrap()
            .entries
            .is_empty()
    );
    endpoint.shutdown().await.unwrap();
    unregister_sim_network(&network_id);
}

#[derive(Default)]
struct PausedPublication {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[tokio::test]
async fn publication_calls_peer_policy_outside_the_shutdown_admission_lock() {
    let (network_id, endpoint) = shutdown_endpoint("policy-lock").await;
    let policy = Arc::new(AdmissionLockProbe::default());
    let client = FipsPubsubClient::start_with_policies(
        endpoint.clone(),
        FipsPubsubClientOptions::default(),
        FipsPubsubClientPolicies {
            peers: Some(policy.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    policy.client.set(Arc::downgrade(&client.inner)).unwrap();
    let peer = Identity::from_secret_bytes(&[124; 32]).unwrap().npub();
    client
        .inner
        .remember_peer_subscription(
            SourceId::new(peer),
            &SubscriptionId::new("policy-lock"),
            vec![Filter::new()],
        )
        .unwrap();
    let published = client
        .publish(shutdown_event(), EventSource::local_index("policy-lock"))
        .await;
    let checked = policy.checks.load(Ordering::Relaxed);
    client.shutdown_shared().await;
    endpoint.shutdown().await.unwrap();
    unregister_sim_network(&network_id);
    assert!(published.unwrap().accepted);
    assert!(
        checked > 0,
        "the production publication must reach peer selection"
    );
}

#[derive(Default)]
struct AdmissionLockProbe {
    client: std::sync::OnceLock<std::sync::Weak<ClientInner>>,
    checks: AtomicUsize,
}

impl MeshPeerPolicy for AdmissionLockProbe {
    fn select_mesh_peer(&self, peer_id: &str) -> Result<Option<nostr_pubsub::MeshPeer>> {
        if let Some(client) = self.client.get().and_then(std::sync::Weak::upgrade) {
            let _admission = client.admission.try_lock().map_err(|_| {
                PubsubError::Storage("external policy called inside shutdown admission lock".into())
            })?;
            self.checks.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Some(nostr_pubsub::MeshPeer::new(peer_id)))
    }
}

#[async_trait]
impl PubsubPolicy for PausedPublication {
    async fn check_event(&self, context: EventPolicyContext<'_>) -> Result<PolicyDecision> {
        if context.event.as_event().kind == Kind::TextNote {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        Ok(PolicyDecision::allow_with_priority(0))
    }

    async fn check_source(
        &self,
        _context: nostr_pubsub::SourcePolicyContext<'_>,
    ) -> Result<PolicyDecision> {
        Ok(PolicyDecision::allow_with_priority(0))
    }
}

fn shutdown_event() -> VerifiedEvent {
    VerifiedEvent::try_from(
        EventBuilder::text_note("shutdown admission")
            .sign_with_keys(&Keys::parse(&hex::encode([123; 32])).unwrap())
            .unwrap(),
    )
    .unwrap()
}

async fn shutdown_endpoint(suffix: &str) -> (String, Arc<FipsEndpoint>) {
    let network_id = format!("pubsub-shutdown-{suffix}-{}", std::process::id());
    register_sim_network(&network_id, SimNetwork::new(7381));
    let endpoint = live_endpoint(&network_id, "shutdown", [121; 32], []).await;
    (network_id, endpoint)
}
