#[test]
fn credit_exit_caps_cached_packets_and_preserves_cashu_and_private_route_rules() {
    use peer_payments::{
        Agreement, Book, Keypair, Limits, SchnorrVerifier, WireMessage, sign_message,
    };
    let buyer: Keypair = "01".repeat(32).parse().unwrap();
    let seller: Keypair = "02".repeat(32).parse().unwrap();
    let buyer_id = buyer.x_only_public_key().0.to_string();
    let seller_id = seller.x_only_public_key().0.to_string();
    let peer = endpoint_node_addr_from_pubkey_bytes(buyer.x_only_public_key().0.serialize());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let a = Agreement {
        id: "credit-exit".into(),
        payer: buyer_id.clone(),
        provider: seller_id.clone(),
        service: "vpn.exit.upload_bytes".into(),
        resource: "internet-exit-upload:10.77.0.2".into(),
        max_units: 48,
        price_sat: 1,
        price_per_units: 24,
        max_amount_sat: 2,
        created_at: now,
        expires_at: now + 60,
    };
    let mut book = Book::new(&seller_id, Limits::default(), [buyer_id]).unwrap();
    let message = WireMessage::Agreement(a.clone());
    book.accept(
        &a,
        &sign_message(&buyer, &message).unwrap(),
        &sign_message(&seller, &message).unwrap(),
        &SchnorrVerifier,
        now,
    )
    .unwrap();
    let window = book.reserve_window(&a.id, 0, 48, now).unwrap();
    let mut runtime = FipsMeshRuntime::with_local_routes(
        Vec::new(),
        vec!["0.0.0.0/0".into(), "8.8.4.0/24".into()],
    );
    runtime
        .install_credit_exit(&seller_id, "10.77.0.2".parse().unwrap(), window)
        .unwrap();
    let admit = runtime.endpoint_source_admitter(&peer).unwrap();
    let mut cache = FipsEndpointAdmissionCache::default();
    let source = Ipv4Addr::new(10, 77, 0, 2);
    for forbidden in [Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(8, 8, 4, 4)] {
        assert!(!admit.admit_packet_cached(&ipv4_packet(source, forbidden), &mut cache));
    }
    assert!(!admit.admit_packet_cached(
        &ipv4_packet(Ipv4Addr::new(10, 77, 0, 3), Ipv4Addr::new(8, 8, 8, 8)),
        &mut cache
    ));
    let packet = ipv4_packet(source, Ipv4Addr::new(8, 8, 8, 8));
    assert!(admit.admit_packet_cached(&packet, &mut cache));
    assert!(admit.admit_packet_cached(&packet, &mut cache));
    assert!(!admit.admit_packet_cached(&packet, &mut cache));
    // Rebuilding with cached credit admission but no live grant fails closed.
    let saved = runtime.paid_route_admissions.values().cloned().collect();
    let rebuilt = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
        Vec::new(),
        vec!["0.0.0.0/0".into()],
        saved,
    );
    assert!(
        rebuilt
            .receive_endpoint_data_owned_with_source_node_addr(&peer, packet.clone())
            .is_none()
    );
    // A real Cashu session remains governed by its existing admission path.
    let cashu_peer = TestPeer::generate();
    runtime.replace_paid_route_admissions(vec![paid_route_admission(
        &cashu_peer,
        vec!["10.77.0.2/32"],
        true,
    )]);
    assert!(
        runtime
            .receive_endpoint_data_owned_with_source_node_addr(
                &cashu_peer.endpoint_node_addr,
                packet
            )
            .is_some()
    );
}

fn measured_exit(max_bytes: u64) -> (FipsMeshRuntime, peer_payments::Agreement, [u8; 16], Vec<u8>) {
    use peer_payments::{
        Agreement, Book, Keypair, Limits, SchnorrVerifier, WireMessage, sign_message,
    };
    let buyer: Keypair = "03".repeat(32).parse().unwrap();
    let seller: Keypair = "04".repeat(32).parse().unwrap();
    let peer = endpoint_node_addr_from_pubkey_bytes(buyer.x_only_public_key().0.serialize());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let a = Agreement {
        id: "metered-exit".into(),
        payer: buyer.x_only_public_key().0.to_string(),
        provider: seller.x_only_public_key().0.to_string(),
        service: "vpn.exit.upload_bytes".into(),
        resource: "internet-exit-upload:10.77.0.2".into(),
        created_at: now,
        expires_at: now + 120,
        max_units: max_bytes,
        price_sat: 1,
        price_per_units: max_bytes,
        max_amount_sat: 1,
    };
    let mut book = Book::new(&a.provider, Limits::default(), [a.payer.clone()]).unwrap();
    let msg = WireMessage::Agreement(a.clone());
    book.accept(
        &a,
        &sign_message(&buyer, &msg).unwrap(),
        &sign_message(&seller, &msg).unwrap(),
        &SchnorrVerifier,
        now,
    )
    .unwrap();
    let mut mesh = FipsMeshRuntime::with_local_routes(vec![], vec!["0.0.0.0/0".into()]);
    mesh.install_credit_exit(
        &a.provider,
        "10.77.0.2".parse().unwrap(),
        book.reserve_window(&a.id, 0, max_bytes, now).unwrap(),
    )
    .unwrap();
    (
        mesh,
        a,
        peer,
        ipv4_packet(Ipv4Addr::new(10, 77, 0, 2), Ipv4Addr::new(8, 8, 8, 8)),
    )
}

#[test]
fn credit_exit_seal_survives_route_rebuild_and_hides_other_payers_usage() {
    let (mesh, a, peer, packet) = measured_exit(1000);
    let old = mesh.endpoint_source_admitter(&peer).unwrap();
    let mut cache = FipsEndpointAdmissionCache::default();
    assert!(old.admit_packet_cached(&packet, &mut cache));
    assert!(mesh.seal_credit_upload(&a.provider, &a.id).is_err());
    assert!(mesh.seal_credit_upload(&a.payer, "another-id").is_err());
    assert!(old.admit_packet_cached(&packet, &mut cache));
    let mut rebuilt = FipsMeshRuntime::with_local_routes(vec![], vec!["0.0.0.0/0".into()]);
    rebuilt.inherit_exit_flows(&mesh);
    rebuilt.reconcile_credit_exits(&a.provider, false, None, a.created_at);
    assert!(!old.admit_packet_cached(&packet, &mut cache));
    rebuilt.reconcile_credit_exits(&a.provider, true, None, a.created_at);
    assert!(!old.admit_packet_cached(&packet, &mut cache));
    let current = rebuilt.endpoint_source_admitter(&peer).unwrap();
    assert!(current.admit_packet_cached(&packet, &mut cache));
    assert_eq!(
        rebuilt.seal_credit_upload(&a.payer, &a.id).unwrap(),
        3 * packet.len() as u64
    );
    assert!(!current.admit_packet_cached(&packet, &mut cache));
    assert!(!old.admit_packet_cached(&packet, &mut cache));
}

#[test]
#[ignore = "measures two million synthetic IP uploads; run separately for stable timing"]
fn credit_exit_packet_measurement() {
    const PACKETS: u64 = 2_000_000;
    const SIZE: u64 = 1200;
    let (mesh, a, peer, mut packet) = measured_exit(PACKETS * SIZE);
    packet.resize(SIZE as usize, 0);
    packet[2..4].copy_from_slice(&(SIZE as u16).to_be_bytes());
    let admit = mesh.endpoint_source_admitter(&peer).unwrap();
    let mut cache = FipsEndpointAdmissionCache::default();
    let started = std::time::Instant::now();
    for _ in 0..PACKETS {
        assert!(admit.admit_packet_cached(std::hint::black_box(&packet), &mut cache));
    }
    let elapsed = started.elapsed();
    assert!(!admit.admit_packet_cached(&packet, &mut cache));
    assert_eq!(
        mesh.seal_credit_upload(&a.payer, &a.id).unwrap(),
        PACKETS * SIZE
    );
    println!(
        "packets={PACKETS} payload_bytes={} elapsed_ns={} ns_per_packet={:.2}",
        PACKETS * SIZE,
        elapsed.as_nanos(),
        elapsed.as_nanos() as f64 / PACKETS as f64
    );
}
