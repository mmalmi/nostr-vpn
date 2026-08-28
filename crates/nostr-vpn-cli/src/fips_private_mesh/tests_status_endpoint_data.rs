    async fn bind_endpoint_data_test_runtime(
        identity_nsec: impl Into<String>,
        network_id: impl AsRef<str>,
        peers: Vec<FipsMeshPeerConfig>,
    ) -> FipsPrivateMeshRuntime {
        let scope = super::fips_lan_discovery_scope(network_id.as_ref());
        let endpoint_peers = super::fips_endpoint_peers_from_mesh(&peers, Vec::new(), Vec::new());
        let config = super::fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            None,
            super::private_mesh_mtu_from_app(None),
            fips_endpoint::NostrDiscoveryPolicy::ConfiguredOnly,
            super::FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );
        FipsPrivateMeshRuntime::bind_with_config_scoped(
            identity_nsec,
            Some(scope),
            peers,
            config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("runtime should bind")
    }

    #[tokio::test]
    async fn join_roster_receipt_marks_the_new_participant_online() {
        let local_keys = Keys::generate();
        let peer_keys = Keys::generate();
        let peer_pubkey = peer_keys.public_key().to_hex();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &peer_pubkey,
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer config");
        let runtime = bind_endpoint_data_test_runtime(
            local_keys.secret_key().to_bech32().expect("local nsec"),
            "join-receipt-test",
            vec![peer],
        )
        .await;

        runtime
            .note_join_roster_receipt(&peer_pubkey)
            .expect("record receipt liveness");

        let status = runtime
            .peer_statuses()
            .into_iter()
            .find(|status| status.pubkey == peer_pubkey)
            .expect("new participant status");
        assert!(status.connected, "the authenticated receipt is live control traffic");
        assert_eq!(status.last_seen_at, status.last_control_seen_at);
        assert_eq!(status.rx_bytes, 0, "receipt byte accounting happens in FIPS-TCP");
        runtime.endpoint().shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn endpoint_data_runtime_sends_and_receives_raw_packet_batch() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let participant_pubkey = keys.public_key().to_hex();
        let source = Ipv4Addr::new(10, 44, 10, 1);
        let destination = Ipv4Addr::new(10, 44, 22, 44);

        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec![format!("{source}/32"), format!("{destination}/32")],
        )
        .expect("peer config");
        let runtime = bind_endpoint_data_test_runtime(nsec, "test-network", vec![peer]).await;
        let first = ipv4_packet(source, destination);
        let second = ipv4_packet(source, destination);
        let expected_endpoint_data_bytes = (first.len() + second.len()) as u64;

        let sent = send_tunnel_packet_batch_owned_with_capacity(
            &runtime,
            vec![first.clone(), second.clone()],
            2,
        )
        .expect("send packet batch");
        assert_eq!(sent, 2);

        let (mut messages, mut events) = (Vec::with_capacity(4), Vec::with_capacity(4));
        tokio::time::timeout(
            Duration::from_secs(2),
            recv_mesh_event_batch_into(&runtime, &mut messages, &mut events, 4),
        )
        .await
        .expect("packet batch should arrive")
        .expect("receive packet batch")
        .expect("batch should contain admitted packets");
        assert_eq!(events.len(), 2);

        let mut packets = events.into_iter().map(|event| match event {
            FipsPrivateMeshEvent::Packet(packet) => packet,
            event => panic!("expected packet event, got {event:?}"),
        });
        assert_eq!(
            packets.next().map(|packet| packet.as_ref().to_vec()),
            Some(first)
        );
        assert_eq!(
            packets.next().map(|packet| packet.as_ref().to_vec()),
            Some(second)
        );
        assert_peer_data_activity(&runtime, &participant_pubkey, expected_endpoint_data_bytes);
        runtime.endpoint().shutdown().await.expect("shutdown");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn local_tun_pipeline_packets_are_detected_before_mesh_send() {
        let source = Ipv4Addr::new(10, 44, 10, 1);
        let local_destination = Ipv4Addr::new(10, 44, 10, 2);
        let mesh_destination = Ipv4Addr::new(10, 44, 22, 44);
        let mut local_tunnel_ips = HashSet::new();
        local_tunnel_ips.insert(IpAddr::V4(local_destination));

        let local_packet = TunPipelinePacket::new(ipv4_packet(source, local_destination));
        let mesh_packet = TunPipelinePacket::new(ipv4_packet(source, mesh_destination));

        assert!(super::tun_pipeline_packet_targets_local_tunnel(
            &local_tunnel_ips,
            &local_packet
        ));
        assert!(!super::tun_pipeline_packet_targets_local_tunnel(
            &local_tunnel_ips,
            &mesh_packet
        ));
        local_tunnel_ips.clear();
        assert!(!super::tun_pipeline_packet_targets_local_tunnel(
            &local_tunnel_ips,
            &local_packet
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn endpoint_data_runtime_sends_tun_pipeline_batch_without_repacking() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let participant_pubkey = keys.public_key().to_hex();
        let source = Ipv4Addr::new(10, 44, 10, 1);
        let destination = Ipv4Addr::new(10, 44, 22, 44);

        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec![format!("{source}/32"), format!("{destination}/32")],
        )
        .expect("peer config");
        let runtime = bind_endpoint_data_test_runtime(nsec, "test-network", vec![peer]).await;
        let mut first = ipv4_packet(source, destination);
        let mut second = ipv4_packet(source, destination);
        first[20] = 1;
        second[20] = 2;
        let expected_endpoint_data_bytes = (first.len() + second.len()) as u64;

        let mut batch = Vec::with_capacity(4);
        let batch_capacity = batch.capacity();
        batch.push(TunPipelinePacket::new(first.clone()));
        batch.push(TunPipelinePacket::new(second.clone()));

        let turn_capacity = batch.len();
        let mut send_runs = Vec::new();
        let sent = runtime
            .blocking_send_tun_pipeline_packet_turn(
                batch.drain(..),
                turn_capacity,
                &mut send_runs,
            )
            .expect("send TUN pipeline packet batch");
        assert_eq!(sent, 2);
        assert!(batch.is_empty());
        assert_eq!(batch.capacity(), batch_capacity);

        let (mut messages, mut events) = (Vec::with_capacity(4), Vec::with_capacity(4));
        tokio::time::timeout(
            Duration::from_secs(2),
            recv_mesh_event_batch_into(&runtime, &mut messages, &mut events, 4),
        )
        .await
        .expect("packet batch should arrive")
        .expect("receive packet batch")
        .expect("batch should contain admitted packets");
        assert_eq!(events.len(), 2);

        let packets: Vec<_> = events
            .into_iter()
            .map(|event| match event {
                FipsPrivateMeshEvent::Packet(packet) => packet.as_ref().to_vec(),
                event => panic!("expected packet event, got {event:?}"),
            })
            .collect();
        assert_eq!(packets, vec![first, second]);
        assert_peer_data_activity(&runtime, &participant_pubkey, expected_endpoint_data_bytes);
        runtime.endpoint().shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn endpoint_data_runtime_recv_batch_into_reuses_buffers() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("nsec");
        let participant_pubkey = keys.public_key().to_hex();
        let source = Ipv4Addr::new(10, 44, 10, 1);
        let destination = Ipv4Addr::new(10, 44, 22, 44);

        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            &participant_pubkey,
            vec![format!("{source}/32"), format!("{destination}/32")],
        )
        .expect("peer config");
        let runtime = bind_endpoint_data_test_runtime(nsec, "test-network", vec![peer]).await;
        let expected_packets = (0..FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS)
            .map(|index| {
                let mut packet = ipv4_packet(source, destination);
                packet[20] = index as u8;
                packet
            })
            .collect::<Vec<_>>();

        let sent = send_tunnel_packet_batch_owned_with_capacity(
            &runtime,
            expected_packets.clone(),
            FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS,
        )
        .expect("send packet batch");
        assert_eq!(sent, FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS);

        let mut messages = Vec::with_capacity(FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS);
        let mut events = Vec::with_capacity(FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS);
        let message_capacity = messages.capacity();
        let event_capacity = events.capacity();

        let received = tokio::time::timeout(
            Duration::from_secs(2),
            recv_mesh_event_batch_into(
                &runtime,
                &mut messages,
                &mut events,
                FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS,
            ),
        )
        .await
        .expect("packet batch should arrive")
        .expect("receive packet batch")
        .expect("batch should contain admitted packets");
        assert_eq!(received, FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS);
        assert!(messages.is_empty());
        assert_eq!(messages.capacity(), message_capacity);
        assert_eq!(events.capacity(), event_capacity);

        let received_packets: Vec<_> = events
            .drain(..)
            .map(|event| match event {
                FipsPrivateMeshEvent::Packet(packet) => packet.as_ref().to_vec(),
                event => panic!("expected packet event, got {event:?}"),
            })
            .collect();
        assert_eq!(received_packets, expected_packets);
        runtime.endpoint().shutdown().await.expect("shutdown");
    }
