use super::routed::signed_note;
use super::*;
use fips_tcp::wire::{Flags, Segment};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

static NEXT_NETWORK: AtomicU64 = AtomicU64::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_retry_rst_on_stable_link_is_spaced_and_recovers() {
    rejected_service_recovers(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_retry_accept_close_cannot_be_accelerated_by_send_commands() {
    rejected_service_recovers(true).await;
}

async fn rejected_service_recovers(accept_close: bool) {
    let (network, a, b) = endpoints().await;
    let before = link_id(&a, b.npub()).await;
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::new(AtomicU64::new(0));
    let (stop, rejector) =
        reject_service(b.clone(), accept_close, attempts.clone(), accepted.clone()).await;
    let client = start_sim_client(&a, "client with unavailable service").await;
    let mut retained = client
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        while attempts.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the actual client sent its initial SYN");
    let until = Instant::now() + Duration::from_millis(3_300);
    while Instant::now() < until {
        if accept_close {
            // Public API actions reach TransportCommand::Send independently of
            // the periodic peer synchronization path.
            client
                .subscribe(vec![Filter::new().kind(Kind::Metadata)])
                .await
                .unwrap()
                .close();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let observed = attempts.lock().unwrap().clone();
    let stable_link = link_id(&a, b.npub()).await;
    stop.send(()).unwrap();
    rejector.await.unwrap();

    // Keep the underlying endpoint/link and the original subscription alive.
    // The service receiver unregisters asynchronously when its owner drops.
    let provider = timeout(Duration::from_secs(5), async {
        loop {
            match FipsPubsubClient::start_for_transport(
                b.clone(),
                FipsPubsubClientOptions::default(),
                "sim",
            )
            .await
            {
                Ok(client) => break client,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("late pubsub service binds after the rejector leaves");
    let event = signed_note("original subscription survives unavailable service");
    provider
        .publish(event.clone(), EventSource::local_index("late-service"))
        .await
        .unwrap();
    let delivered = timeout(Duration::from_secs(5), retained.recv()).await;
    drop(retained);
    client.shutdown().await;
    provider.shutdown().await;
    shutdown(&network, a, b).await;

    assert_eq!(
        stable_link, before,
        "test must not manufacture a FIPS link epoch change"
    );
    assert!(
        observed.len() >= 2,
        "closed service must remain retryable: {observed:?}"
    );
    let gaps = observed
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .collect::<Vec<_>>();
    println!(
        "service_retry accept_close={accept_close} link={before}->{stable_link} attempts={} accepted={} gaps={gaps:?} recovered={}",
        observed.len(),
        accepted.load(Ordering::Relaxed),
        matches!(&delivered, Ok(Some(delivery)) if delivery.event == event),
    );
    assert!(
        gaps.iter().all(|gap| *gap >= Duration::from_millis(2_950)),
        "service retries must be at least three seconds apart (50 ms receive scheduling allowance): {gaps:?}"
    );
    if accept_close {
        assert!(
            accepted.load(Ordering::Relaxed) >= 2,
            "exercise established then closed streams"
        );
    }
    assert_eq!(
        delivered
            .expect("late service recovers within the bounded retry window")
            .unwrap()
            .event,
        event
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_retry_simultaneous_healthy_clients_do_not_replay_idle_streams() {
    let (network, a, b) = endpoints().await;
    let (alice, bob) = tokio::join!(start_sim_client(&a, "Alice"), start_sim_client(&b, "Bob"));
    wait_for_pubsub_connections(&alice, 1).await;
    wait_for_pubsub_connections(&bob, 1).await;
    wait_for_default_peer_subscription(&alice).await;
    wait_for_default_peer_subscription(&bob).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let initial = (
        alice.inner.req_frames_received.load(Ordering::Relaxed),
        bob.inner.req_frames_received.load(Ordering::Relaxed),
    );
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    let final_counts = (
        alice.inner.req_frames_received.load(Ordering::Relaxed),
        bob.inner.req_frames_received.load(Ordering::Relaxed),
    );
    let mut subscription = alice
        .subscribe(vec![Filter::new().kind(Kind::TextNote)])
        .await
        .unwrap();
    let event = signed_note("healthy simultaneous stream remains usable");
    bob.publish(event.clone(), EventSource::local_index("healthy"))
        .await
        .unwrap();
    let delivered = timeout(Duration::from_secs(5), subscription.recv()).await;
    drop(subscription);
    alice.shutdown().await;
    bob.shutdown().await;
    shutdown(&network, a, b).await;
    println!("healthy simultaneous client REQs: {initial:?}->{final_counts:?}");
    assert_eq!(
        initial, final_counts,
        "stable healthy streams must not replay their REQs during idle"
    );
    assert_eq!(delivered.unwrap().unwrap().event, event);
}

async fn reject_service(
    endpoint: Arc<FipsEndpoint>,
    accept_close: bool,
    attempts: Arc<Mutex<Vec<Instant>>>,
    accepted: Arc<AtomicU64>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let receiver = endpoint
        .register_service_receiver(FIPS_NOSTR_PUBSUB_SERVICE_PORT)
        .await
        .unwrap();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        // Use the production TCP state machine for valid resets/FINs, not a
        // hand-built approximation of the peer's protocol behavior.
        let mut stack = fips_tcp::Stack::new(fips_tcp::Config::default(), 123);
        if accept_close {
            stack.listen(FIPS_NOSTR_PUBSUB_SERVICE_PORT).unwrap();
        }
        let mut seen = HashSet::new();
        let mut datagrams = Vec::new();
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                count = receiver.recv_batch_into(&mut datagrams, 64) => {
                    assert!(count.is_some());
                    for datagram in datagrams.drain(..) {
                        let segment = Segment::decode(datagram.data.as_slice()).unwrap();
                        if segment.flags.contains(Flags::SYN) && !segment.flags.contains(Flags::ACK)
                            && seen.insert((segment.src_port, segment.seq)) {
                            attempts.lock().unwrap().push(Instant::now());
                        }
                        stack.input(datagram.source_peer.npub(), datagram.data.as_slice(), now_ms()).unwrap();
                        while let Some(id) = stack.accept(FIPS_NOSTR_PUBSUB_SERVICE_PORT) {
                            accepted.fetch_add(1, Ordering::Relaxed);
                            stack.close(id, now_ms()).unwrap();
                        }
                        for packet in stack.drain_outbound() {
                            endpoint.send_datagram(PeerIdentity::from_npub(&packet.peer).unwrap(),
                                FIPS_NOSTR_PUBSUB_SERVICE_PORT, FIPS_NOSTR_PUBSUB_SERVICE_PORT, packet.bytes).await.unwrap();
                        }
                    }
                }
            }
        }
    });
    (stop, task)
}

async fn endpoints() -> (String, Arc<FipsEndpoint>, Arc<FipsEndpoint>) {
    let network = format!(
        "pubsub-service-retry-{}",
        NEXT_NETWORK.fetch_add(1, Ordering::Relaxed)
    );
    register_sim_network(&network, SimNetwork::new(7338));
    let peer_a = Identity::from_secret_bytes(&[111; 32]).unwrap().npub();
    let peer_b = Identity::from_secret_bytes(&[112; 32]).unwrap().npub();
    let a = live_endpoint(&network, "service-a", [111; 32], [(peer_b, "service-b")]).await;
    let b = live_endpoint(&network, "service-b", [112; 32], [(peer_a, "service-a")]).await;
    wait_for_connected_peer(&a, b.npub()).await;
    wait_for_connected_peer(&b, a.npub()).await;
    (network, a, b)
}

async fn link_id(endpoint: &FipsEndpoint, peer: &str) -> u64 {
    endpoint
        .peers()
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.npub == peer && entry.connected)
        .unwrap()
        .link_id
}

async fn shutdown(network: &str, a: Arc<FipsEndpoint>, b: Arc<FipsEndpoint>) {
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    unregister_sim_network(network);
}
