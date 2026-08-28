    #[test]
    fn fips_peer_address_hint_splits_transport_tags_for_live_updates() {
        let tcp = fips_peer_address_from_hint(&FipsPeerAddressHint {
            addr: "tcp:203.0.113.20:443".to_string(),
            seen_at_ms: Some(123_000),
            priority: FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY,
        });
        assert_eq!(tcp.transport, "tcp");
        assert_eq!(tcp.addr, "203.0.113.20:443");
        assert_eq!(tcp.seen_at_ms, Some(123_000));
        assert_eq!(tcp.priority, FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY);

        let udp = fips_peer_address_from_hint(&FipsPeerAddressHint {
            addr: "udp:203.0.113.21:2121".to_string(),
            seen_at_ms: None,
            priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
        });
        assert_eq!(udp.transport, "udp");
        assert_eq!(udp.addr, "203.0.113.21:2121");
        assert_eq!(udp.priority, FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY);
}
    #[test]
    fn fips_private_tunnel_config_uses_non_roster_peer_setting_for_discovery_policy() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let mut app = AppConfig::generated();
        app.fips_host_tunnel_enabled = false;
        app.connect_to_non_roster_fips_peers = false;
        let network_id = app.effective_network_id();
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("configured-only tunnel config");
        assert_eq!(
            config.nostr_discovery_policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );

        app.node.advertise_exit_node = true;
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("advertised exit tunnel config");
        assert_eq!(
            config.nostr_discovery_policy,
            NostrDiscoveryPolicy::Open
        );
        assert_eq!(
            config.open_discovery_max_pending,
            FIPS_NOSTR_EXIT_OPEN_DISCOVERY_MAX_PENDING
        );

        app.node.advertise_exit_node = false;
        app.connect_to_non_roster_fips_peers = true;
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("open tunnel config");
        assert_eq!(config.nostr_discovery_policy, NostrDiscoveryPolicy::Open);
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn fips_private_tunnel_config_opens_discovery_for_paid_exit_sellers() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let mut app = AppConfig::generated();
        app.fips_host_tunnel_enabled = false;
        app.connect_to_non_roster_fips_peers = false;
        app.paid_exit.enabled = true;
        let network_id = app.effective_network_id();
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("paid exit seller tunnel config");

        assert_eq!(config.nostr_discovery_policy, NostrDiscoveryPolicy::Open);
        assert_eq!(
            config.open_discovery_max_pending,
            FIPS_NOSTR_PAID_EXIT_OPEN_DISCOVERY_MAX_PENDING,
            "ambient public peers must not starve first-contact paid buyers"
        );
    }

    #[test]
    fn fips_restart_predicate_includes_nostr_discovery_enabled() {
        let app = AppConfig::generated();
        let network_id = app.effective_network_id();
        let current = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("fips tunnel config");
        let mut next = current.clone();

        next.nostr_discovery_enabled = !current.nostr_discovery_enabled;

        assert!(
            fips_tunnel_requires_endpoint_restart(&current, &next),
            "toggling Nostr discovery must tear down old relay subscriptions"
        );
    }

    #[test]
    fn approving_a_roster_peer_updates_the_existing_endpoint_in_place() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let mut app = AppConfig::generated_without_networks();
        let network_id = app.add_owned_network("Approval test");
        app.set_network_enabled(&network_id, true)
            .expect("enable approval network");
        app.connect_to_non_roster_fips_peers = true;
        let own_pubkey = app.own_nostr_pubkey_hex().expect("own public key");
        let current = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("pre-approval tunnel config");

        let participant = Keys::generate().public_key().to_hex();
        let ambient_peer = Keys::generate().public_key().to_hex();
        let local_keys = Keys::parse(&app.nostr.secret_key).expect("local keys");
        let mut recent = recent_peer_cache(&local_keys, &network_id);
        assert!(recent.note_success(&ambient_peer, "198.51.100.20:51820", 1));
        app.active_network_mut().devices.push(participant);
        let approved = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun100",
            Some(&own_pubkey),
            Some(&recent),
            &[],
        )
        .expect("approved tunnel config");

        assert_ne!(
            current.open_discovery_max_pending,
            approved.open_discovery_max_pending,
            "authenticated ambient transit changes only the live admission budget"
        );
        assert!(
            !fips_tunnel_requires_endpoint_restart(&current, &approved),
            "roster approval must preserve the authenticated join carrier"
        );

        let mut durable_capacity_change = approved.clone();
        durable_capacity_change.open_discovery_restart_max_pending += 1;
        durable_capacity_change.open_discovery_max_pending += 1;
        assert!(
            fips_tunnel_requires_endpoint_restart(&approved, &durable_capacity_change),
            "a durable admission-capacity change must still replace the endpoint"
        );
    }

    #[test]
    fn linux_cap_eff_parsing_detects_net_admin() {
        assert_eq!(
            linux_cap_eff_has_net_admin("CapEff:\t0000000000000000\n"),
            Some(false)
        );
        assert_eq!(
            linux_cap_eff_has_net_admin("CapEff:\t0000000000001000\n"),
            Some(true)
        );
        assert_eq!(linux_cap_eff_has_net_admin("Name:\tnvpn\n"), None);
    }

    #[test]
    fn linux_tun_setup_error_points_to_root_service_or_docker_flags() {
        let message = linux_tun_setup_error("utun100", "current process lacks CAP_NET_ADMIN");

        assert!(message.contains("CAP_NET_ADMIN"));
        assert!(message.contains("/dev/net/tun"));
        assert!(message.contains("utun100"));
        assert!(message.contains("sudo nvpn start --connect"));
        assert!(message.contains("system service"));
        assert!(message.contains("--cap-add NET_ADMIN --device /dev/net/tun"));
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let total_len = 20 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(&payload);
        packet
    }

    fn assert_peer_data_activity(
        runtime: &FipsPrivateMeshRuntime,
        participant_pubkey: &str,
        expected_endpoint_data_bytes: u64,
    ) {
        let status = runtime
            .peer_statuses()
            .into_iter()
            .find(|status| status.pubkey == participant_pubkey)
            .expect("peer status");

        assert_eq!(status.last_seen_at, status.last_data_seen_at);
        assert!(
            status.last_data_seen_at.is_some(),
            "admitted endpoint data should stamp data freshness"
        );
        assert_eq!(status.last_control_seen_at, None);
        assert_eq!(status.tx_bytes, expected_endpoint_data_bytes);
        assert_eq!(status.rx_bytes, expected_endpoint_data_bytes);
    }

    #[test]
    fn drain_event_batch_respects_limit() {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<FipsPrivateMeshEvent>(FIPS_MESH_EVENT_DRAIN_LIMIT + 8);
        for index in 0..(FIPS_MESH_EVENT_DRAIN_LIMIT + 5) {
            tx.try_send(FipsPrivateMeshEvent::Presence {
                participant_pubkey: format!("peer-{index}"),
                last_seen_at: index as u64,
            })
            .expect("queue test event");
        }

        let drained = drain_event_batch(&mut rx, FIPS_MESH_EVENT_DRAIN_LIMIT);

        assert_eq!(drained.len(), FIPS_MESH_EVENT_DRAIN_LIMIT);
        assert_eq!(rx.len(), 5);
    }

    #[test]
    fn stateful_control_datagram_is_recognized_for_drop_before_tunnel_data() {
        let source = Keys::generate();
        let source_npub = source.public_key().to_bech32().expect("source npub");
        let frame = FipsControlFrame::Capabilities {
            network_id: "network".to_string(),
            capabilities: Default::default(),
        };
        let message = FipsEndpointMessage {
            source_peer: PeerIdentity::from_npub(&source_npub).expect("source identity"),
            data: FipsEndpointData::new(
                encode_fips_control_frame(&frame).expect("encode stateful frame"),
            ),
            enqueued_at_ms: 0,
        };

        assert_eq!(
            decode_endpoint_control_frame(&message).expect("decode control datagram"),
            Some(frame)
        );
    }

    #[test]
    fn peer_activity_map_preserves_existing_configured_peer_activity() {
        use std::sync::Arc;

        let alice = Keys::generate().public_key().to_hex();
        let bob = Keys::generate().public_key().to_hex();
        let removed = Keys::generate().public_key().to_hex();
        let alice_key = participant_pubkey_bytes(&alice).expect("alice key");
        let bob_key = participant_pubkey_bytes(&bob).expect("bob key");
        let removed_key = participant_pubkey_bytes(&removed).expect("removed key");
        let alice_activity = Arc::new(FipsPeerActivity::default());
        alice_activity.note_tx(42);
        alice_activity.note_rx(7, 123, FipsPeerRxKind::Control);
        alice_activity.note_rx(11, 130, FipsPeerRxKind::Data);
        let mut previous = HashMap::new();
        previous.insert(alice_key, Arc::clone(&alice_activity));
        previous.insert(removed_key, Arc::new(FipsPeerActivity::default()));

        let next = peer_activity_map(&[alice.clone(), bob.clone()], Some(&previous));

        assert!(Arc::ptr_eq(next.get(&alice_key).unwrap(), &alice_activity));
        assert_eq!(
            next.get(&alice_key).unwrap().snapshot(),
            FipsPeerActivitySnapshot {
                last_seen_at: Some(130),
                last_control_seen_at: Some(123),
                last_data_seen_at: Some(130),
                tx_bytes: 42,
                rx_bytes: 18,
            }
        );
        assert_eq!(
            next.get(&bob_key).unwrap().snapshot(),
            FipsPeerActivitySnapshot::default()
        );
        assert!(!next.contains_key(&removed_key));
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn paid_route_accounting_uses_pubkey_bytes_and_ignores_invalid_identity() {
        use super::{
            FipsPaidRouteAccounting, FipsPaidRouteAccountingPeer, FipsPaidRouteAccountingRole,
        };

        let participant = Keys::generate().public_key().to_hex();
        let participant_key = participant_pubkey_bytes(&participant).expect("participant key");
        let packet = paid_route_test_ipv4_udp_packet(64);
        let mut accounting = FipsPaidRouteAccounting::default();
        accounting.replace_peers([FipsPaidRouteAccountingPeer::parse(
            &participant,
            FipsPaidRouteAccountingRole::LocalBuyer,
        )
        .expect("accounting peer")]);

        accounting.record_outbound(None, Some(&participant_key), &packet);
        let usage = accounting.drain(&participant);

        assert_eq!(usage.tx_bytes, 64);
        assert_eq!(usage.tx_packets, 1);
        assert_eq!(usage.billable_bytes, 64);
        assert!(
            FipsPaidRouteAccountingPeer::parse(
                "not-a-pubkey",
                FipsPaidRouteAccountingRole::LocalBuyer,
            )
            .is_none()
        );

        accounting.record_outbound(Some("not-a-pubkey"), None, &packet);
        let invalid_usage = accounting.drain("not-a-pubkey");
        assert_eq!(invalid_usage.tx_bytes, 0);
        assert_eq!(invalid_usage.billable_bytes, 0);
    }

    #[test]
    fn peer_identity_map_resolves_endpoint_identities_and_skips_invalid_npubs() {
        let participant = Keys::generate().public_key().to_hex();
        let endpoint_keys = Keys::generate();
        let endpoint_hex = endpoint_keys.public_key().to_hex();
        let endpoint_npub = endpoint_keys.public_key().to_bech32().expect("npub");
        let invalid_participant = "invalid-participant".to_string();

        let identities = peer_identity_map(&[
            FipsMeshPeerConfig {
                participant_pubkey: participant.clone(),
                endpoint_npub: format!(" {endpoint_hex} "),
                allowed_ips: Vec::new(),
            },
            FipsMeshPeerConfig {
                participant_pubkey: invalid_participant.clone(),
                endpoint_npub: "not-an-npub".to_string(),
                allowed_ips: Vec::new(),
            },
        ]);

        let endpoint_node_addr = *PeerIdentity::from_npub(&endpoint_npub)
            .expect("endpoint identity")
            .node_addr()
            .as_bytes();
        let participant_key = participant_pubkey_bytes(&participant).expect("participant key");
        assert_eq!(identities.by_participant.len(), 1);
        assert!(identities.by_participant.contains_key(&participant_key));
        assert_eq!(identities.by_endpoint_node_addr.len(), 1);
        assert_eq!(
            identities
                .identity_for_participant(&participant)
                .expect("resolved endpoint identity")
                .npub(),
            endpoint_npub
        );
        assert_eq!(
            identities
                .identity_for_send(Some(&participant_key), &endpoint_node_addr)
                .expect("resolved endpoint identity by node addr")
                .npub(),
            endpoint_npub
        );
        assert_eq!(
            identities
                .identity_for_send(None, &endpoint_node_addr)
                .expect("resolved endpoint identity by node addr without participant")
                .npub(),
            endpoint_npub
        );
        assert_eq!(
            endpoint_identity_for_send(&identities, Some(&participant_key), &endpoint_node_addr)
                .expect("send identity")
                .npub(),
            endpoint_npub
        );
        assert!(
            identities
                .identity_for_participant(&invalid_participant)
                .is_none()
        );
    }
