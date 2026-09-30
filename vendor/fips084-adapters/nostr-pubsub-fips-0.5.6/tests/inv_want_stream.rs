use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::{EventBuilder, Keys, Kind};
use nostr_pubsub::{
    EventPolicyContext, InvWantMeshOptions, MeshPeer, MeshPeerPolicy, PolicyDecision, PubsubPolicy,
    Result, SourcePolicyContext, VerifiedEvent,
};
use nostr_pubsub_fips::{FipsInvWantStream, FipsInvWantStreamAction, FipsInvWantStreamOptions};

#[tokio::test]
async fn large_event_roundtrips_as_split_bounded_stream_record() {
    let mut alice = stream(256 * 1024);
    let mut bob = stream(256 * 1024);
    let event = signed_event(&"x".repeat(128 * 1024));

    let inventory = only_record(
        alice
            .publish(event.clone(), ["bob".to_string()], 1)
            .expect("publish inventory"),
        "bob",
    );
    let want = only_record(
        bob.receive_bytes("alice", &inventory, ["alice".to_string()], 2)
            .await
            .expect("receive inventory"),
        "alice",
    );
    let frame = only_record(
        alice
            .receive_bytes("bob", &want, ["bob".to_string()], 3)
            .await
            .expect("receive want"),
        "bob",
    );

    assert!(
        frame.len() > u16::MAX as usize,
        "the production record must prove the path is not FSP-datagram limited"
    );
    let split = frame.len() / 3;
    assert!(
        bob.receive_bytes("alice", &frame[..split], ["alice".to_string()], 4)
            .await
            .expect("receive partial frame")
            .is_empty()
    );
    let delivered = bob
        .receive_bytes("alice", &frame[split..], ["alice".to_string()], 5)
        .await
        .expect("receive completed frame");
    assert_eq!(delivered_event_ids(&delivered), vec![event.as_event().id]);
}

#[tokio::test]
async fn event_policy_runs_before_delivery_cache_or_forwarding() {
    let mut alice = stream(64 * 1024);
    let mut bob = stream(64 * 1024).with_event_policy(Arc::new(DropAllEvents));
    let event = signed_event("blocked");

    let inventory = only_record(
        alice
            .publish(event, ["bob".to_string()], 1)
            .expect("publish inventory"),
        "bob",
    );
    let want = only_record(
        bob.receive_bytes(
            "alice",
            &inventory,
            ["alice".to_string(), "carol".to_string()],
            2,
        )
        .await
        .expect("receive inventory"),
        "alice",
    );
    let frame = only_record(
        alice
            .receive_bytes("bob", &want, ["bob".to_string()], 3)
            .await
            .expect("receive want"),
        "bob",
    );
    let actions = bob
        .receive_bytes(
            "alice",
            &frame,
            ["alice".to_string(), "carol".to_string()],
            4,
        )
        .await
        .expect("policy drop is not a transport error");

    assert!(actions.is_empty(), "a dropped frame must not be amplified");
    assert_eq!(bob.retained_state().cached_events, 0);
}

#[test]
fn seeded_events_replay_to_late_and_reconnected_peers() {
    let mut service = stream(64 * 1024);
    let event = signed_event("persisted update root");
    service.seed(event, 1).expect("seed persistent snapshot");

    let first = service
        .peer_connected("late-peer", 2)
        .expect("replay to late peer");
    let reconnect = service
        .peer_connected("late-peer", 3)
        .expect("replay after reconnect");

    assert_eq!(send_targets(&first), vec!["late-peer"]);
    assert_eq!(send_targets(&reconnect), vec!["late-peer"]);
}

#[test]
fn offline_publish_is_cached_for_the_next_peer_connection() {
    let mut service = stream(64 * 1024);

    assert!(
        service
            .publish(signed_event("offline"), Vec::<String>::new(), 1)
            .expect("offline publish")
            .is_empty()
    );
    let replay = service
        .peer_connected("later", 2)
        .expect("replay offline publication");

    assert_eq!(send_targets(&replay), vec!["later"]);
}

#[test]
fn seeded_replay_uses_the_mesh_cache_bound() {
    let options = FipsInvWantStreamOptions {
        mesh: InvWantMeshOptions {
            max_cached_events: 1,
            ..InvWantMeshOptions::default()
        },
        ..FipsInvWantStreamOptions::default()
    };
    let mut service = FipsInvWantStream::new(options).expect("bounded stream");
    service
        .seed(signed_event("evicted"), 1)
        .expect("seed first event");
    service
        .seed(signed_event("retained"), 2)
        .expect("seed replacement event");

    let replay = service
        .peer_connected("late-peer", 3)
        .expect("bounded replay");

    assert_eq!(send_targets(&replay), vec!["late-peer"]);
    assert_eq!(service.retained_state().cached_events, 1);
}

#[test]
fn peer_policy_filters_fanout_before_records_are_queued() {
    let mut service = stream(64 * 1024).with_peer_policy(Arc::new(AllowNamedPeers {
        allowed: BTreeSet::from(["good".to_string()]),
    }));

    let actions = service
        .publish(
            signed_event("hello"),
            ["bad".to_string(), "good".to_string()],
            1,
        )
        .expect("policy-aware publish");

    assert_eq!(send_targets(&actions), vec!["good"]);
}

#[tokio::test]
async fn stream_input_bounds_peers_and_declared_record_length() {
    let options = FipsInvWantStreamOptions {
        max_record_bytes: 256,
        max_input_peers: 1,
        ..FipsInvWantStreamOptions::default()
    };
    let mut service = FipsInvWantStream::new(options).expect("bounded stream");

    assert!(
        service
            .receive_bytes("alice", &[0, 0], Vec::<String>::new(), 1)
            .await
            .expect("retain partial prefix")
            .is_empty()
    );
    let error = service
        .receive_bytes("bob", &[0], Vec::<String>::new(), 2)
        .await
        .expect_err("second retained input peer must be rejected");
    assert!(error.to_string().contains("input peer"));

    service.disconnect_peer("alice");
    let error = service
        .receive_bytes("alice", &257_u32.to_be_bytes(), Vec::<String>::new(), 3)
        .await
        .expect_err("oversize record declaration must be rejected immediately");
    assert!(error.to_string().contains("record"));
    assert_eq!(service.buffered_input_bytes("alice"), 0);
}

#[tokio::test]
async fn configured_protocol_namespace_can_preserve_a_product_wire_contract() {
    let options = FipsInvWantStreamOptions {
        protocol: "nvpn.control.pubsub".to_string(),
        protocol_version: 1,
        ..FipsInvWantStreamOptions::default()
    };
    let mut alice = FipsInvWantStream::new(options.clone()).expect("alice stream");
    let mut bob = FipsInvWantStream::new(options).expect("bob stream");

    let inventory = only_record(
        alice
            .publish(signed_event("vpn event"), ["bob".to_string()], 1)
            .expect("publish inventory"),
        "bob",
    );
    let actions = bob
        .receive_bytes("alice", &inventory, ["alice".to_string()], 2)
        .await
        .expect("decode configured namespace");

    assert_eq!(send_targets(&actions), vec!["alice"]);
}

#[tokio::test]
async fn coalesced_records_are_drained_in_bounded_receive_turns() {
    let options = FipsInvWantStreamOptions {
        max_records_per_receive: 1,
        ..FipsInvWantStreamOptions::default()
    };
    let mut alice = FipsInvWantStream::new(options.clone()).expect("alice stream");
    let mut bob = FipsInvWantStream::new(options).expect("bob stream");
    let mut records = only_record(
        alice
            .publish(signed_event("one"), ["bob".to_string()], 1)
            .expect("first inventory"),
        "bob",
    );
    records.extend(only_record(
        alice
            .publish(signed_event("two"), ["bob".to_string()], 2)
            .expect("second inventory"),
        "bob",
    ));

    let first = bob
        .receive_bytes("alice", &records, ["alice".to_string()], 3)
        .await
        .expect("first bounded turn");
    assert_eq!(send_targets(&first), vec!["alice"]);
    assert!(bob.has_ready_input("alice"));

    let second = bob
        .receive_bytes("alice", &[], ["alice".to_string()], 4)
        .await
        .expect("second bounded turn");
    assert_eq!(send_targets(&second), vec!["alice"]);
    assert!(!bob.has_ready_input("alice"));
}

#[test]
fn unsendable_seed_is_rejected_before_mutating_the_replay_cache() {
    let options = FipsInvWantStreamOptions {
        max_record_bytes: 256,
        ..FipsInvWantStreamOptions::default()
    };
    let mut service = FipsInvWantStream::new(options).expect("bounded stream");

    let error = service
        .seed(signed_event(&"x".repeat(512)), 1)
        .expect_err("event envelope exceeds record bound");

    assert!(error.to_string().contains("maximum"));
    assert_eq!(service.retained_state().cached_events, 0);
}

fn stream(max_event_bytes: usize) -> FipsInvWantStream {
    let options = FipsInvWantStreamOptions {
        mesh: InvWantMeshOptions {
            max_event_bytes,
            max_cached_event_bytes: max_event_bytes * 4,
            ..InvWantMeshOptions::default()
        },
        max_record_bytes: max_event_bytes + 4096,
        ..FipsInvWantStreamOptions::default()
    };
    FipsInvWantStream::new(options).expect("stream options")
}

fn signed_event(content: &str) -> VerifiedEvent {
    VerifiedEvent::try_from(
        EventBuilder::new(Kind::TextNote, content)
            .sign_with_keys(&Keys::generate())
            .expect("sign event"),
    )
    .expect("verify event")
}

fn only_record(actions: Vec<FipsInvWantStreamAction>, expected_peer: &str) -> Vec<u8> {
    let mut records = actions.into_iter().filter_map(|action| match action {
        FipsInvWantStreamAction::Send { peer_id, record } => Some((peer_id, record)),
        FipsInvWantStreamAction::Deliver(_) => None,
    });
    let (peer, record) = records.next().expect("one outbound record");
    assert_eq!(peer, expected_peer);
    assert!(records.next().is_none(), "expected one outbound record");
    record
}

fn delivered_event_ids(actions: &[FipsInvWantStreamAction]) -> Vec<nostr::EventId> {
    actions
        .iter()
        .filter_map(|action| match action {
            FipsInvWantStreamAction::Deliver(event) => Some(event.event.as_event().id),
            FipsInvWantStreamAction::Send { .. } => None,
        })
        .collect()
}

fn send_targets(actions: &[FipsInvWantStreamAction]) -> Vec<&str> {
    actions
        .iter()
        .filter_map(|action| match action {
            FipsInvWantStreamAction::Send { peer_id, .. } => Some(peer_id.as_str()),
            FipsInvWantStreamAction::Deliver(_) => None,
        })
        .collect()
}

struct DropAllEvents;

#[async_trait]
impl PubsubPolicy for DropAllEvents {
    async fn check_event(&self, _context: EventPolicyContext<'_>) -> Result<PolicyDecision> {
        Ok(PolicyDecision::drop("test policy"))
    }

    async fn check_source(&self, _context: SourcePolicyContext<'_>) -> Result<PolicyDecision> {
        Ok(PolicyDecision::allow_with_priority(0))
    }
}

struct AllowNamedPeers {
    allowed: BTreeSet<String>,
}

impl MeshPeerPolicy for AllowNamedPeers {
    fn select_mesh_peer(&self, peer_id: &str) -> Result<Option<MeshPeer>> {
        Ok(self
            .allowed
            .contains(peer_id)
            .then(|| MeshPeer::new(peer_id)))
    }
}
