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
