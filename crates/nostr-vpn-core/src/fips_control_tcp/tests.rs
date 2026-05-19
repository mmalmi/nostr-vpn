use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fips_core::{FipsEndpoint, PeerIdentity};
use nostr_sdk::prelude::{Keys, ToBech32};

use super::*;

fn test_join_roster() -> (JoinRosterControl, String) {
    let admin = Keys::generate();
    let signed_roster = crate::fips_control::SignedRoster::sign(
        "network",
        crate::fips_control::NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![admin.public_key().to_hex()],
            admins: vec![admin.public_key().to_hex()],
            aliases: Default::default(),
            signed_at: 42,
        },
        &admin,
    )
    .expect("sign roster");
    let roster_event_id = signed_roster.artifact_hash();
    let control =
        JoinRosterControl::new(signed_roster, "request-secret").expect("join roster control");
    (control, roster_event_id)
}

#[tokio::test]
async fn carries_small_and_multichunk_records_over_real_fips_tcp() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let mut control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    for network_id in ["network".to_string(), "n".repeat(IO_CHUNK_BYTES * 3)] {
        let frame = FipsControlFrame::Capabilities {
            network_id,
            capabilities: Default::default(),
        };
        let sent = tokio::time::timeout(Duration::from_secs(3), control.send(local, &frame))
            .await
            .expect("state-control send timed out")
            .expect("send state-control frame");
        assert_eq!(
            sent,
            encode_fips_control_frame(&frame).expect("encode").len()
        );
        let received = tokio::time::timeout(Duration::from_secs(3), control.recv())
            .await
            .expect("state-control receive timed out")
            .expect("receive state-control frame");
        assert_eq!(received.source_peer, local);
        assert_eq!(received.frame, frame);
    }

    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn join_roster_waits_for_matching_application_receipt_and_retries() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let mut control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    let (join_roster, expected_id) = test_join_roster();
    let sender = control.sender();
    let delivery = tokio::spawn(async move {
        send_join_roster_with_receipt(&sender, local, &join_roster, Duration::from_secs(5)).await
    });

    let first = tokio::time::timeout(Duration::from_secs(3), control.recv())
        .await
        .expect("first roster receive timed out")
        .expect("first roster frame");
    assert!(matches!(first.frame, FipsControlFrame::JoinRoster { .. }));
    control
        .send(
            local,
            &FipsControlFrame::JoinRosterAck {
                roster_event_id: "00".repeat(32),
            },
        )
        .await
        .expect("send mismatched receipt");

    let second = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let received = control.recv().await.expect("state-control frame");
            if matches!(received.frame, FipsControlFrame::JoinRoster { .. }) {
                break received;
            }
        }
    })
    .await
    .expect("join roster was not retried");
    assert_eq!(second.source_peer, local);
    control
        .send(
            local,
            &FipsControlFrame::JoinRosterAck {
                roster_event_id: expected_id,
            },
        )
        .await
        .expect("send matching receipt");

    delivery
        .await
        .expect("join delivery task")
        .expect("matching receipt should complete delivery");
    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn join_roster_receipt_survives_a_full_periodic_peer_budget() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let mut control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");

    // Each completed loopback record leaves its client side in TIME-WAIT.
    // Seven ordinary periodic records leave no room for both sides of the
    // next stream under the production eight-connection per-peer budget,
    // matching the startup/control burst that precedes a real approval.
    for index in 0..(MAX_CONNECTIONS_PER_PEER - 1) {
        let frame = FipsControlFrame::Capabilities {
            network_id: format!("periodic-{index}"),
            capabilities: Default::default(),
        };
        tokio::time::timeout(Duration::from_secs(3), control.send(local, &frame))
            .await
            .expect("periodic state-control send timed out")
            .expect("send periodic state-control frame");
        tokio::time::timeout(Duration::from_secs(3), control.recv())
            .await
            .expect("periodic state-control receive timed out")
            .expect("receive periodic state-control frame");
    }

    let (join_roster, expected_id) = test_join_roster();
    let sender = control.sender();
    let delivery = tokio::spawn(async move {
        send_join_roster_with_receipt(&sender, local, &join_roster, Duration::from_secs(3)).await
    });

    let received = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let received = control.recv().await.expect("state-control frame");
            if matches!(received.frame, FipsControlFrame::JoinRoster { .. }) {
                break received;
            }
        }
    })
    .await
    .expect("join roster stayed behind retained periodic connections");
    assert_eq!(received.source_peer, local);
    control
        .send(
            local,
            &FipsControlFrame::JoinRosterAck {
                roster_event_id: expected_id,
            },
        )
        .await
        .expect("send matching receipt");
    delivery
        .await
        .expect("join delivery task")
        .expect("matching receipt should complete delivery");

    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn join_roster_timeout_reports_unacknowledged_real_transport() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    let (join_roster, _) = test_join_roster();
    let unreachable = PeerIdentity::from_npub(
        &Keys::generate()
            .public_key()
            .to_bech32()
            .expect("destination npub"),
    )
    .expect("destination identity");

    let started = Instant::now();
    let error = send_join_roster_with_receipt(
        &control.sender(),
        unreachable,
        &join_roster,
        Duration::from_millis(150),
    )
    .await
    .expect_err("unrouted roster must not look delivered");
    assert!(
        error
            .to_string()
            .contains("transport acknowledgement did not complete"),
        "timeout must expose the real FIPS-TCP delivery state: {error:#}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "caller deadline must cancel the outstanding transport wait"
    );

    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn join_roster_stops_retrying_when_the_runtime_is_closed() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let destination = PeerIdentity::from_npub(endpoint.npub()).expect("peer identity");
    let control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    let sender = control.sender();
    let (join_roster, _) = test_join_roster();
    control.stop().await;

    let started = Instant::now();
    let error = send_join_roster_with_receipt(
        &sender,
        destination,
        &join_roster,
        Duration::from_millis(300),
    )
    .await
    .expect_err("closed runtime must not deliver a roster");
    assert!(
        error.to_string().contains("runtime stopped"),
        "closed runtime error must be preserved: {error:#}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a permanently closed runtime must not consume the delivery deadline"
    );

    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn enqueue_returns_before_stateful_delivery_completes() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let mut control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    let frame = FipsControlFrame::Capabilities {
        network_id: "network".to_string(),
        capabilities: Default::default(),
    };

    let started = Instant::now();
    let queued = control
        .sender()
        .enqueue(local, &frame)
        .expect("queue frame");
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "queue admission must not wait for FIPS-TCP acknowledgement"
    );
    assert_eq!(
        queued,
        encode_fips_control_frame(&frame).expect("encode").len()
    );
    let received = tokio::time::timeout(Duration::from_secs(3), control.recv())
        .await
        .expect("state-control receive timed out")
        .expect("receive queued state-control frame");
    assert_eq!(received.frame, frame);

    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[tokio::test]
async fn rejects_ping_on_the_stateful_stream() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
        .await
        .expect("start state-control runtime");
    let error = control
        .send(
            local,
            &FipsControlFrame::Ping {
                network_id: "network".to_string(),
                sent_at: 1,
            },
        )
        .await
        .expect_err("ping must stay on datagram path");
    assert!(error.to_string().contains("datagram probe"));
    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[test]
fn complete_record_is_ready_without_waiting_for_stream_close() {
    let frame = FipsControlFrame::Capabilities {
        network_id: "network".to_string(),
        capabilities: Default::default(),
    };
    let bytes = encode_fips_control_frame(&frame).expect("encode state-control frame");
    assert_eq!(decode_complete_stateful_record(&bytes), Some(frame));
    assert!(decode_complete_stateful_record(&bytes[..bytes.len() - 1]).is_none());
}

#[tokio::test]
async fn retains_a_record_while_the_local_delivery_queue_is_full() {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind embedded FIPS endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let mut control = FipsControlTcpRuntime::start_with_delivery_capacity(Arc::clone(&endpoint), 1)
        .await
        .expect("start state-control runtime");

    for index in 0..=1 {
        let frame = FipsControlFrame::Capabilities {
            network_id: index.to_string(),
            capabilities: Default::default(),
        };
        tokio::time::timeout(Duration::from_secs(3), control.send(local, &frame))
            .await
            .expect("state-control send timed out")
            .expect("send state-control frame");
    }
    // Let both TCP close-retention deadlines pass. Freeing capacity must wake
    // delivery even when there is no remaining TCP timer or network input.
    tokio::time::sleep(Duration::from_millis(CONTROL_CLOSE_RETENTION_MS * 2)).await;
    for index in 0..=1 {
        let received = tokio::time::timeout(Duration::from_secs(3), control.recv())
            .await
            .expect("state-control receive timed out")
            .expect("receive state-control frame");
        let FipsControlFrame::Capabilities { network_id, .. } = received.frame else {
            panic!("unexpected state-control frame");
        };
        assert_eq!(network_id, index.to_string());
    }

    control.stop().await;
    endpoint.shutdown().await.expect("shutdown endpoint");
}

#[test]
fn restart_uses_a_fresh_tcp_sequence_seed() {
    let first = control_isn_seed("npub-test");
    let second = control_isn_seed("npub-test");
    assert_ne!(first, second);
}

#[test]
fn route_discovery_time_does_not_consume_the_stream_delivery_window() {
    let fips_handshake_timeout = Duration::from_secs(
        fips_core::Config::new()
            .node
            .rate_limit
            .handshake_timeout_secs,
    );
    assert!(
        CONNECTION_TIMEOUT > fips_handshake_timeout,
        "state-control must outlive FIPS route recovery"
    );

    let now = Instant::now();
    let mut record = OutboundRecord {
        bytes: vec![1],
        offset: 0,
        final_marker: None,
        started: now - STREAM_TIMEOUT - Duration::from_secs(1),
        connected_at: None,
        response: None,
    };

    assert_eq!(
        outbound_timeout_reason(&mut record, State::SynSent, now),
        None
    );
    assert_eq!(
        outbound_timeout_reason(&mut record, State::Established, now),
        None
    );
    assert_eq!(record.connected_at, Some(now));
    assert_eq!(
        outbound_timeout_reason(&mut record, State::Established, now + STREAM_TIMEOUT),
        Some("FIPS-TCP state-control send timed out")
    );

    record.connected_at = None;
    record.started = now - CONNECTION_TIMEOUT;
    assert_eq!(
        outbound_timeout_reason(&mut record, State::SynSent, now),
        Some("FIPS-TCP state-control connection timed out")
    );
}

#[test]
fn idle_runtime_has_no_timer_and_tcp_deadlines_keep_their_origin() {
    let origin = Instant::now();
    let outbound = HashMap::new();
    let inbound = HashMap::new();
    assert_eq!(next_drive_deadline(None, origin, &outbound, &inbound), None);
    let due = origin + Duration::from_millis(CONTROL_CLOSE_RETENTION_MS);
    assert_eq!(
        next_drive_deadline(
            Some(CONTROL_CLOSE_RETENTION_MS),
            origin,
            &outbound,
            &inbound
        ),
        Some(due),
        "closed TCP tuples still schedule their canonical expiry"
    );
    assert_eq!(
        next_drive_deadline(Some(0), origin, &outbound, &inbound),
        Some(origin),
        "a due TCP deadline is not delayed to a new polling interval"
    );
}

#[test]
fn record_deadlines_preserve_connection_and_stream_windows() {
    let origin = Instant::now();
    let id = ConnectionId::from_raw(1);
    let mut outbound = HashMap::from([(
        id,
        OutboundRecord {
            bytes: vec![1],
            offset: 0,
            final_marker: None,
            started: origin,
            connected_at: None,
            response: None,
        },
    )]);
    let inbound = HashMap::new();
    assert_eq!(
        next_drive_deadline(None, origin, &outbound, &inbound),
        Some(origin + CONNECTION_TIMEOUT)
    );
    let connected = origin + Duration::from_secs(30);
    outbound.get_mut(&id).unwrap().connected_at = Some(connected);
    assert_eq!(
        next_drive_deadline(None, origin, &outbound, &inbound),
        Some(connected + STREAM_TIMEOUT),
        "route discovery must not consume the post-connect stream window"
    );
    assert_eq!(
        next_drive_deadline(Some(31_000), origin, &outbound, &inbound),
        Some(origin + Duration::from_secs(31)),
        "an earlier TCP retry must still win"
    );
}

#[test]
fn decoded_records_wait_for_capacity_without_an_expired_record_timer() {
    let origin = Instant::now();
    let peer =
        PeerIdentity::from_npub(&Keys::generate().public_key().to_bech32().unwrap()).unwrap();
    let id = ConnectionId::from_raw(1);
    let mut inbound = HashMap::from([(
        id,
        InboundRecord {
            peer,
            bytes: Vec::new(),
            started: origin,
            ready: None,
        },
    )]);
    let outbound = HashMap::new();
    assert_eq!(
        next_drive_deadline(None, origin, &outbound, &inbound),
        Some(origin + STREAM_TIMEOUT)
    );
    inbound.get_mut(&id).unwrap().ready = Some(FipsControlFrame::Capabilities {
        network_id: "network".into(),
        capabilities: Default::default(),
    });
    assert_eq!(next_drive_deadline(None, origin, &outbound, &inbound), None);
}

async fn connected_loopback_tcp() -> (
    Arc<FipsEndpoint>,
    FipsTcpEndpoint,
    ConnectionId,
    ConnectionId,
) {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("bind endpoint"),
    );
    let local = PeerIdentity::from_npub(endpoint.npub()).unwrap();
    let mut tcp = FipsTcpEndpoint::bind(
        Arc::clone(&endpoint),
        FIPS_STATE_CONTROL_SERVICE_PORT,
        Config::default(),
        1,
    )
    .await
    .unwrap();
    let client = tcp.connect(local, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..3 {
            tcp.receive_report(0).await.unwrap();
        }
    })
    .await
    .expect("loopback handshake");
    let server = tcp.accept().expect("accepted loopback connection");
    (endpoint, tcp, client, server)
}

#[tokio::test]
async fn buffered_multichunk_record_drains_before_fin_without_timer_progress() {
    let (endpoint, mut tcp, client, server) = connected_loopback_tcp().await;
    let frame = FipsControlFrame::Capabilities {
        network_id: "n".repeat(IO_CHUNK_BYTES * 2),
        capabilities: Default::default(),
    };
    let bytes = encode_fips_control_frame(&frame).unwrap();
    let (accepted, marker) = tcp.write_with_marker(client, &bytes, 0).await.unwrap();
    assert_eq!(accepted, bytes.len());
    tokio::time::timeout(Duration::from_secs(3), async {
        while matches!(tcp.marker_status(&marker), MarkerStatus::Pending) {
            tcp.receive_report(0).await.unwrap();
        }
    })
    .await
    .expect("buffer and acknowledge the complete record");
    assert_eq!(
        tcp.next_poll_at(0),
        None,
        "buffered reads need no TCP timer"
    );
    tcp.close(client, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        tcp.receive_report(0).await.unwrap();
        tcp.receive_report(0).await.unwrap();
    })
    .await
    .expect("deliver FIN and its ACK");
    assert!(tcp.is_read_closed(server));

    let mut inbound = HashMap::from([(
        server,
        InboundRecord {
            peer: tcp.peer(server).unwrap(),
            bytes: Vec::new(),
            started: Instant::now(),
            ready: None,
        },
    )]);
    let mut outbound = HashMap::new();
    let (received, mut messages) = mpsc::channel(1);
    let (observed, _) = broadcast::channel(1);
    for _ in 0..4 {
        if !drive_ready(
            &mut tcp,
            &received,
            &observed,
            &mut outbound,
            &mut inbound,
            0,
        )
        .await
        {
            break;
        }
    }
    assert!(
        inbound.is_empty(),
        "positive reads must schedule the next chunk"
    );
    assert_eq!(messages.try_recv().unwrap().frame, frame);
    endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn caller_cancellation_wakes_and_aborts_a_stream_without_a_tcp_timer() {
    let (endpoint, mut tcp, client, _) = connected_loopback_tcp().await;
    assert_eq!(tcp.next_poll_at(0), None);
    let (response, receiver) = oneshot::channel();
    let mut outbound = HashMap::from([(
        client,
        OutboundRecord {
            bytes: vec![1],
            offset: 0,
            final_marker: None,
            started: Instant::now(),
            connected_at: Some(Instant::now()),
            response: Some(response),
        },
    )]);
    {
        let cancelled = wait_for_cancelled_send(&mut outbound);
        tokio::pin!(cancelled);
        assert!(futures_util::poll!(&mut cancelled).is_pending());
        drop(receiver);
        tokio::time::timeout(Duration::from_secs(1), &mut cancelled)
            .await
            .expect("caller cancellation must wake the driver");
    }
    let (received, _) = mpsc::channel(1);
    let (observed, _) = broadcast::channel(1);
    assert!(
        !drive_ready(
            &mut tcp,
            &received,
            &observed,
            &mut outbound,
            &mut HashMap::new(),
            0,
        )
        .await
    );
    assert!(outbound.is_empty());
    assert_eq!(
        tcp.state(client),
        None,
        "cancelled TCP slot must be reclaimed"
    );
    endpoint.shutdown().await.unwrap();
}
