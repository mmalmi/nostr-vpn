use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fips_core::config::{PeerConfig, TransportInstances};
use fips_core::{
    Config, FipsEndpoint, Identity, IdentityConfig, PeerIdentity, SimNetwork, SimTransportConfig,
    register_sim_network, unregister_sim_network,
};
use nostr::{EventBuilder, EventId, Keys, Kind};
use nostr_pubsub::{InvWantMeshOptions, VerifiedEvent};
use nostr_pubsub_fips::{
    FipsInvWantStream, FipsInvWantStreamOptions, FipsInvWantTcpDriver, FipsInvWantTcpDriverOptions,
};
use tokio::time::timeout;

const SERVICE_PORT: u16 = 39_121;
static NEXT_NETWORK: AtomicU64 = AtomicU64::new(1);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_large_and_coalesced_records_roundtrip_over_real_tcp_fips_endpoints() {
    let mut pair = Box::pin(DriverPair::new(driver_options(64, 512 * 1024), 256 * 1024)).await;
    pair.connect().await;
    let large = signed_event(&"x".repeat(128 * 1024));
    let small_a = signed_event("small-a");
    let small_b = signed_event("small-b");
    let expected = BTreeSet::from([
        large.as_event().id,
        small_a.as_event().id,
        small_b.as_event().id,
    ]);

    pair.alice.publish(large, 10).expect("queue large event");
    pair.alice
        .publish(small_a, 11)
        .expect("queue first coalesced event");
    pair.alice
        .publish(small_b, 12)
        .expect("queue second coalesced event");

    let outcome = pair
        .pump_until(13, |outcome| {
            expected
                .iter()
                .all(|event_id| outcome.bob_deliveries.contains(event_id))
        })
        .await;

    assert_eq!(outcome.bob_deliveries, expected);
    assert!(
        outcome.bob_stream_bytes > u16::MAX as usize,
        "the driver must continuously drain a record larger than one FIPS datagram/window"
    );
    pair.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_publish_replays_after_late_connect_and_forced_reconnect() {
    let mut pair = Box::pin(DriverPair::new(driver_options(64, 256 * 1024), 64 * 1024)).await;
    let first = signed_event("published before a stream exists");
    let first_id = first.as_event().id;
    pair.alice
        .publish(first, 1)
        .expect("cache offline publication");

    pair.connect().await;
    let first_outcome = pair
        .pump_until(10, |outcome| outcome.bob_deliveries.contains(&first_id))
        .await;
    assert!(first_outcome.bob_deliveries.contains(&first_id));

    pair.alice
        .abort_peer(pair.bob_identity)
        .await
        .expect("force stream closure");
    pair.pump_until(100, |outcome| {
        outcome.alice_connected == 0 && outcome.bob_connected == 0
    })
    .await;

    let second = signed_event("published while reconnecting");
    let second_id = second.as_event().id;
    pair.alice
        .publish(second, 200)
        .expect("cache reconnect publication");
    pair.alice
        .connect_peer(pair.bob_identity, 201)
        .await
        .expect("reconnect peer");
    let second_outcome = pair
        .pump_until(202, |outcome| outcome.bob_deliveries.contains(&second_id))
        .await;

    assert!(second_outcome.bob_deliveries.contains(&second_id));
    pair.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_pressure_is_rejected_without_exceeding_per_peer_bounds() {
    let mut pair = Box::pin(DriverPair::new(driver_options(1, 1024), 64 * 1024)).await;
    pair.connect().await;

    pair.alice
        .publish(signed_event("fits"), 10)
        .expect("first inventory fits queue");
    let error = pair
        .alice
        .publish(signed_event("must wait"), 11)
        .expect_err("second inventory exceeds one-record queue");
    let queued = pair.alice.queue_snapshot();

    assert!(error.to_string().contains("queue"));
    assert_eq!(queued.records, 1);
    assert!(queued.bytes <= 1024);
    pair.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_connects_converge_on_one_shared_stream() {
    let mut pair = Box::pin(DriverPair::new(driver_options(64, 256 * 1024), 64 * 1024)).await;
    let alice_identity = PeerIdentity::from_npub(pair.endpoint_a.npub()).expect("Alice identity");
    pair.alice
        .connect_peer(pair.bob_identity, 0)
        .await
        .expect("Alice connects");
    pair.bob
        .connect_peer(alice_identity, 0)
        .await
        .expect("Bob connects");

    pair.pump_until(1, |outcome| {
        outcome.alice_connected == 1 && outcome.bob_connected == 1
    })
    .await;
    let event = signed_event("deduplicated stream remains usable");
    let event_id = event.as_event().id;
    pair.alice.publish(event, 50).expect("publish event");
    let outcome = pair
        .pump_until(51, |outcome| outcome.bob_deliveries.contains(&event_id))
        .await;

    assert_eq!(outcome.alice_connected, 1);
    assert_eq!(outcome.bob_connected, 1);
    pair.shutdown().await;
}

struct DriverPair {
    network_id: String,
    endpoint_a: Arc<FipsEndpoint>,
    endpoint_b: Arc<FipsEndpoint>,
    bob_identity: PeerIdentity,
    alice: FipsInvWantTcpDriver,
    bob: FipsInvWantTcpDriver,
}

impl DriverPair {
    async fn new(options: FipsInvWantTcpDriverOptions, max_event_bytes: usize) -> Self {
        let network_id = format!(
            "nostr-pubsub-tcp-driver-{}",
            NEXT_NETWORK.fetch_add(1, Ordering::Relaxed)
        );
        register_sim_network(&network_id, SimNetwork::new(90_000));
        let identity_a = Identity::from_secret_bytes(&[31; 32]).expect("identity A");
        let identity_b = Identity::from_secret_bytes(&[32; 32]).expect("identity B");
        let endpoint_a = Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(endpoint_config(
                        &network_id,
                        "tcp-driver-a",
                        [31; 32],
                        identity_b.npub(),
                        "tcp-driver-b",
                    ))
                    .without_system_tun()
                    .bind(),
            )
            .await
            .expect("bind endpoint A"),
        );
        let endpoint_b = Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(endpoint_config(
                        &network_id,
                        "tcp-driver-b",
                        [32; 32],
                        identity_a.npub(),
                        "tcp-driver-a",
                    ))
                    .without_system_tun()
                    .bind(),
            )
            .await
            .expect("bind endpoint B"),
        );
        wait_for_peer(&endpoint_a, endpoint_b.npub()).await;
        wait_for_peer(&endpoint_b, endpoint_a.npub()).await;

        let alice = FipsInvWantTcpDriver::bind(
            Arc::clone(&endpoint_a),
            stream(max_event_bytes),
            options.clone(),
            0xa11c_e001,
        )
        .await
        .expect("bind Alice driver");
        let bob = FipsInvWantTcpDriver::bind(
            Arc::clone(&endpoint_b),
            stream(max_event_bytes),
            options,
            0xb0b0_e001,
        )
        .await
        .expect("bind Bob driver");
        let bob_identity = PeerIdentity::from_npub(endpoint_b.npub()).expect("Bob identity");
        Self {
            network_id,
            endpoint_a,
            endpoint_b,
            bob_identity,
            alice,
            bob,
        }
    }

    async fn connect(&mut self) {
        self.alice
            .connect_peer(self.bob_identity, 0)
            .await
            .expect("connect Alice to Bob");
        self.pump_until(1, |outcome| {
            outcome.alice_connected == 1 && outcome.bob_connected == 1
        })
        .await;
    }

    async fn pump_until(
        &mut self,
        start_ms: u64,
        complete: impl Fn(&PumpOutcome) -> bool,
    ) -> PumpOutcome {
        let mut outcome = PumpOutcome::default();
        for step in 0..200 {
            let now_ms = start_ms + step;
            outcome.merge_alice(drive_once(&mut self.alice, now_ms).await);
            outcome.merge_bob(drive_once(&mut self.bob, now_ms).await);
            if complete(&outcome) {
                return outcome;
            }
        }
        panic!("TCP/FIPS driver outcome did not converge: {outcome:?}");
    }

    async fn shutdown(self) {
        let Self {
            network_id,
            endpoint_a,
            endpoint_b,
            alice,
            bob,
            ..
        } = self;
        drop(alice);
        drop(bob);
        endpoint_a.shutdown().await.expect("shutdown endpoint A");
        endpoint_b.shutdown().await.expect("shutdown endpoint B");
        unregister_sim_network(&network_id);
    }
}

#[derive(Debug, Default)]
struct PumpOutcome {
    alice_connected: usize,
    bob_connected: usize,
    alice_stream_bytes: usize,
    bob_stream_bytes: usize,
    alice_deliveries: BTreeSet<EventId>,
    bob_deliveries: BTreeSet<EventId>,
}

impl PumpOutcome {
    fn merge_alice(&mut self, report: nostr_pubsub_fips::FipsInvWantTcpDriveReport) {
        self.alice_connected = report.connected_peers;
        self.alice_stream_bytes = self
            .alice_stream_bytes
            .saturating_add(report.stream_bytes_read);
        self.alice_deliveries.extend(
            report
                .deliveries
                .into_iter()
                .map(|event| event.event.as_event().id),
        );
    }

    fn merge_bob(&mut self, report: nostr_pubsub_fips::FipsInvWantTcpDriveReport) {
        self.bob_connected = report.connected_peers;
        self.bob_stream_bytes = self
            .bob_stream_bytes
            .saturating_add(report.stream_bytes_read);
        self.bob_deliveries.extend(
            report
                .deliveries
                .into_iter()
                .map(|event| event.event.as_event().id),
        );
    }
}

async fn drive_once(
    driver: &mut FipsInvWantTcpDriver,
    now_ms: u64,
) -> nostr_pubsub_fips::FipsInvWantTcpDriveReport {
    match timeout(Duration::from_millis(5), driver.receive(now_ms)).await {
        Ok(result) => result.expect("receive TCP/FIPS batch"),
        Err(_) => driver.poll(now_ms).await.expect("poll TCP/FIPS driver"),
    }
}

fn driver_options(
    max_queued_records_per_peer: usize,
    max_queued_bytes_per_peer: usize,
) -> FipsInvWantTcpDriverOptions {
    FipsInvWantTcpDriverOptions {
        service_namespace: "test.nostr.pubsub.stream".to_string(),
        service_version: 1,
        service_port: SERVICE_PORT,
        max_peers: 4,
        max_queued_records_per_peer,
        max_queued_bytes_per_peer,
        max_io_bytes_per_drive: 256 * 1024,
    }
}

fn stream(max_event_bytes: usize) -> FipsInvWantStream {
    FipsInvWantStream::new(FipsInvWantStreamOptions {
        mesh: InvWantMeshOptions {
            max_event_bytes,
            max_cached_event_bytes: max_event_bytes * 4,
            ..InvWantMeshOptions::default()
        },
        max_record_bytes: max_event_bytes + 4096,
        ..FipsInvWantStreamOptions::default()
    })
    .expect("stream")
}

fn signed_event(content: &str) -> VerifiedEvent {
    VerifiedEvent::try_from(
        EventBuilder::new(Kind::TextNote, content)
            .sign_with_keys(&Keys::generate())
            .expect("sign event"),
    )
    .expect("verify event")
}

fn endpoint_config(
    network_id: &str,
    local_addr: &str,
    secret: [u8; 32],
    peer_npub: String,
    peer_addr: &str,
) -> Config {
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(hex::encode(secret)),
        persistent: false,
    };
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(local_addr.to_string()),
        mtu: Some(1280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.peers = vec![PeerConfig::new(peer_npub, "sim", peer_addr)];
    config
}

async fn wait_for_peer(endpoint: &FipsEndpoint, expected_npub: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            if endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .iter()
                .any(|peer| peer.connected && peer.npub == expected_npub)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("FIPS peers connect");
}
