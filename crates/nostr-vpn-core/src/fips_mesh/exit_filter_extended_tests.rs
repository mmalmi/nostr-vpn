#[test]
fn default_exit_admits_only_matching_icmp_echo_replies() {
    let exit = TestPeer::generate();
    let local = Ipv4Addr::new(10, 44, 10, 1);
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let runtime = FipsMeshRuntime::with_local_routes(
        vec![FipsMeshPeerConfig {
            participant_pubkey: exit.participant_pubkey,
            endpoint_npub: exit.endpoint_npub.clone(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
        }],
        vec![format!("{local}/32")],
    );
    let admitter = runtime
        .endpoint_source_admitter(&exit.endpoint_node_addr)
        .expect("exit source");
    let reply = ipv4_icmp_echo(remote, local, 0, 7, 11);

    assert!(admitter.receive_owned(reply.clone()).is_none());
    assert!(
        runtime
            .route_outbound_packet_peer(&ipv4_icmp_echo(local, remote, 8, 7, 11))
            .is_some()
    );
    assert!(
        admitter
            .receive_owned(ipv4_icmp_echo(remote, local, 0, 7, 12))
            .is_none()
    );
    assert!(admitter.receive_owned(reply).is_some());
}

#[test]
fn default_exit_filters_ipv6_and_allows_matching_icmp_errors() {
    let exit = TestPeer::generate();
    let local = "2606:4700:4700::1001".parse().expect("local IPv6");
    let remote = "2606:4700:4700::1111".parse().expect("remote IPv6");
    let runtime = FipsMeshRuntime::with_local_routes(
        vec![FipsMeshPeerConfig {
            participant_pubkey: exit.participant_pubkey.clone(),
            endpoint_npub: exit.endpoint_npub.clone(),
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        }],
        vec![format!("{local}/128")],
    );
    let admitter = runtime
        .endpoint_source_admitter(&exit.endpoint_node_addr)
        .expect("exit source");
    let outbound_v6 = ipv6_udp_packet(local, remote, 40_000, 443);
    let reply_v6 = ipv6_udp_packet(remote, local, 443, 40_000);

    assert!(admitter.receive_owned(reply_v6.clone()).is_none());
    assert!(runtime.route_outbound_packet_peer(&outbound_v6).is_some());
    assert!(admitter.receive_owned(reply_v6).is_some());
    assert!(
        admitter
            .receive_owned(ipv6_icmp_error(remote, local, &outbound_v6))
            .is_some()
    );
    let private_v6 = "fd00::1".parse().expect("private IPv6");
    assert!(
        runtime
            .route_outbound_packet_peer(&ipv6_udp_packet(local, private_v6, 40_001, 443))
            .is_some()
    );
    assert!(
        admitter
            .receive_owned(ipv6_udp_packet(private_v6, local, 443, 40_001))
            .is_none()
    );

    let local_v4 = Ipv4Addr::new(10, 44, 10, 1);
    let remote_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let runtime_v4 = FipsMeshRuntime::with_local_routes(
        vec![FipsMeshPeerConfig {
            participant_pubkey: exit.participant_pubkey,
            endpoint_npub: exit.endpoint_npub,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
        }],
        vec![format!("{local_v4}/32")],
    );
    let outbound_v4 = ipv4_udp_packet(local_v4, remote_v4, 40_000, 443);
    let error = ipv4_icmp_error(Ipv4Addr::new(1, 1, 1, 1), local_v4, &outbound_v4);
    let unsolicited = ipv4_icmp_error(
        Ipv4Addr::new(1, 1, 1, 1),
        local_v4,
        &ipv4_udp_packet(local_v4, Ipv4Addr::new(9, 9, 9, 9), 40_001, 443),
    );
    let admitter_v4 = runtime_v4
        .endpoint_source_admitter(&exit.endpoint_node_addr)
        .expect("exit source");

    assert!(admitter_v4.receive_owned(unsolicited).is_none());
    assert!(
        runtime_v4
            .route_outbound_packet_peer(&outbound_v4)
            .is_some()
    );
    assert!(admitter_v4.receive_owned(error).is_some());
}

#[test]
fn default_exit_filter_overhead_smoke() {
    let exit = TestPeer::generate();
    let local = Ipv4Addr::new(10, 44, 10, 1);
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let runtime = FipsMeshRuntime::with_local_routes(
        vec![FipsMeshPeerConfig {
            participant_pubkey: exit.participant_pubkey,
            endpoint_npub: exit.endpoint_npub.clone(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
        }],
        vec![format!("{local}/32")],
    );
    let outbound = ipv4_udp_packet(local, remote, 40_000, 443);
    let inbound = ipv4_udp_packet(remote, local, 443, 40_000);
    let admitter = runtime
        .endpoint_source_admitter(&exit.endpoint_node_addr)
        .expect("exit source");
    let mut cache = FipsEndpointAdmissionCache::default();
    let iterations = 200_000_u32;
    let started = std::time::Instant::now();

    for _ in 0..iterations {
        assert!(runtime.route_outbound_packet_peer(&outbound).is_some());
        assert!(admitter.admit_packet_cached(&inbound, &mut cache));
    }

    let elapsed = started.elapsed();
    eprintln!(
        "exit filter: {} packets in {:?} ({:.1} ns/packet)",
        iterations * 2,
        elapsed,
        elapsed.as_nanos() as f64 / f64::from(iterations * 2)
    );
}

#[test]
fn cached_exit_route_checks_idle_expiry_and_refreshes_activity_in_both_directions() {
    use crate::paid_route_accounting::ExitFlowFilter;
    use std::time::{Duration, Instant};

    let exit = TestPeer::generate();
    let local = Ipv4Addr::new(10, 44, 10, 1);
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let runtime = FipsMeshRuntime::with_local_routes(
        vec![exit.config(&["0.0.0.0/0"])],
        vec![format!("{local}/32")],
    );
    let peer = exit.endpoint_node_addr;
    let admitter = runtime.endpoint_source_admitter(&peer).unwrap();
    let outbound = ipv4_udp_packet(local, remote, 10_000, 443);
    let reply = ipv4_udp_packet(remote, local, 443, 10_000);
    let key = ExitFlowFilter::outbound_key(peer, &outbound).unwrap();
    let mut cache = FipsEndpointAdmissionCache::default();

    runtime.note_cached_exit_outbound(peer, &outbound);
    assert!(admitter.admit_packet_cached(&reply, &mut cache));

    // Keep the route cache warm across a gap longer than the UDP idle timeout.
    let now = Instant::now();
    let note_at = |seen| {
        runtime
            .exit_flows
            .lock()
            .unwrap()
            .note_outbound_key(key, seen)
    };
    note_at(now - Duration::from_secs(181));
    assert!(!admitter.admit_packet_cached(&reply, &mut cache));

    // At the probe time the old timestamp is stale (240s), but a refresh is live (120s).
    let old = now - Duration::from_secs(120);
    let probe = now + Duration::from_secs(120);
    note_at(old);
    assert!(admitter.admit_packet_cached(&reply, &mut cache));
    assert!(
        runtime
            .exit_flows
            .lock()
            .unwrap()
            .admits_inbound_key(key, probe)
    );
    note_at(old);
    runtime.note_cached_exit_outbound(peer, &outbound);
    assert!(
        runtime
            .exit_flows
            .lock()
            .unwrap()
            .admits_inbound_key(key, probe)
    );
}

#[test]
fn capacity_eviction_skips_an_expired_incarnation_of_a_reopened_flow() {
    use crate::paid_route_accounting::ExitFlowFilter;
    use std::time::{Duration, Instant};

    let exit = TestPeer::generate();
    let local = Ipv4Addr::new(10, 44, 10, 1);
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let runtime = FipsMeshRuntime::with_local_routes(
        vec![exit.config(&["0.0.0.0/0"])],
        vec![format!("{local}/32")],
    );
    let peer = exit.endpoint_node_addr;
    let admitter = runtime.endpoint_source_admitter(&peer).unwrap();
    let mut cache = FipsEndpointAdmissionCache::default();
    let reopened = ipv4_udp_packet(local, remote, 10_000, 443);
    let reply = ipv4_udp_packet(remote, local, 443, 10_000);
    let key = ExitFlowFilter::outbound_key(peer, &reopened).unwrap();
    runtime
        .exit_flows
        .lock()
        .unwrap()
        .note_outbound_key(key, Instant::now() - Duration::from_secs(181));
    assert!(!admitter.admit_packet_cached(&reply, &mut cache));

    runtime.note_cached_exit_outbound(peer, &ipv4_udp_packet(local, remote, 10_001, 443));
    runtime.note_cached_exit_outbound(peer, &reopened);
    for port in 10_002..=(10_000 + 16_384_u16) {
        runtime.note_cached_exit_outbound(peer, &ipv4_udp_packet(local, remote, port, 443));
    }

    let oldest_reply = ipv4_udp_packet(remote, local, 443, 10_001);
    assert!(!admitter.admit_packet_cached(&oldest_reply, &mut cache));
    assert!(admitter.admit_packet_cached(&reply, &mut cache));
}
