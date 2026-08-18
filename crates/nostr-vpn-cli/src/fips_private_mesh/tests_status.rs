    #[test]
    fn non_roster_endpoint_peers_surface_as_mesh_statuses() {
        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let npub = keys.public_key().to_bech32().expect("npub");
        let mut peers = HashMap::new();
        peers.insert(
            pubkey.clone(),
            FipsEndpointPeer {
                npub: npub.clone(),
                node_addr: NodeAddr::from_bytes([7; 16]),
                connected: true,
                transport_addr: Some("203.0.113.9:9000".to_string()),
                transport_type: Some("udp".to_string()),
                link_id: 42,
                srtt_ms: Some(7),
                srtt_age_ms: Some(123),
                packets_sent: 11,
                packets_recv: 12,
                bytes_sent: 1300,
                bytes_recv: 1400,
                rekey_in_progress: true,
                rekey_draining: true,
                current_k_bit: Some(true),
                last_outbound_route: None,
                direct_probe_pending: true,
                direct_probe_after_ms: Some(12_345),
                direct_probe_retry_count: 3,
                direct_probe_auto_reconnect: true,
                direct_probe_expires_at_ms: Some(67_890),
                nostr_traversal_consecutive_failures: 3,
                nostr_traversal_in_cooldown: true,
                nostr_traversal_cooldown_until_ms: Some(123_456),
                nostr_traversal_last_observed_skew_ms: Some(-250),
            },
        );

        let statuses = other_endpoint_peer_statuses(&peers, 123);

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].pubkey, pubkey);
        assert_eq!(statuses[0].endpoint_npub, npub);
        assert!(statuses[0].connected);
        assert_eq!(
            statuses[0].transport_addr.as_deref(),
            Some("203.0.113.9:9000")
        );
        assert_eq!(statuses[0].transport_type.as_deref(), Some("udp"));
        assert!(statuses[0].direct_probe_pending);
        assert_eq!(statuses[0].direct_probe_after_ms, Some(12_345));
        assert_eq!(statuses[0].direct_probe_retry_count, 3);
        assert!(statuses[0].direct_probe_auto_reconnect);
        assert_eq!(statuses[0].direct_probe_expires_at_ms, Some(67_890));
        assert_eq!(statuses[0].nostr_traversal_consecutive_failures, 3);
        assert!(statuses[0].nostr_traversal_in_cooldown);
        assert_eq!(statuses[0].nostr_traversal_cooldown_until_ms, Some(123_456));
        assert_eq!(
            statuses[0].nostr_traversal_last_observed_skew_ms,
            Some(-250)
        );
        assert_eq!(statuses[0].srtt_ms, Some(7));
        assert_eq!(statuses[0].srtt_age_ms, Some(123));
        assert_eq!(statuses[0].link_packets_sent, 11);
        assert_eq!(statuses[0].link_packets_recv, 12);
        assert_eq!(statuses[0].link_bytes_sent, 1300);
        assert_eq!(statuses[0].link_bytes_recv, 1400);
        assert!(statuses[0].rekey_in_progress);
        assert!(statuses[0].rekey_draining);
        assert_eq!(statuses[0].current_k_bit, Some(true));
        assert_eq!(statuses[0].last_seen_at, Some(123));
        assert_eq!(statuses[0].error, None);
    }

    #[test]
    fn stale_participant_refreshes_endpoint_path_when_direct_probe_is_pending() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().expect("npub");
        let mut peer = FipsEndpointPeer {
            npub,
            node_addr: NodeAddr::from_bytes([9; 16]),
            connected: false,
            transport_addr: Some("203.0.113.9:9000".to_string()),
            transport_type: Some("udp".to_string()),
            link_id: 42,
            srtt_ms: Some(70),
            srtt_age_ms: Some(120_000),
            packets_sent: 100,
            packets_recv: 20,
            bytes_sent: 8192,
            bytes_recv: 1024,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: true,
            direct_probe_after_ms: Some(12_345),
            direct_probe_retry_count: 3,
            direct_probe_auto_reconnect: true,
            direct_probe_expires_at_ms: Some(67_890),
            nostr_traversal_consecutive_failures: 0,
            nostr_traversal_in_cooldown: false,
            nostr_traversal_cooldown_until_ms: None,
            nostr_traversal_last_observed_skew_ms: None,
        };

        assert!(
            !super::endpoint_path_refresh_due(&peer, Some(120), 123),
            "fresh participant traffic must not churn same-path direct probes"
        );
        assert!(super::endpoint_path_refresh_due(&peer, Some(80), 123));
        assert!(!super::endpoint_path_refresh_due(&peer, None, 123));

        peer.direct_probe_pending = false;
        assert!(!super::endpoint_path_refresh_due(&peer, Some(120), 123));

        peer.connected = true;
        assert!(
            !super::endpoint_path_refresh_due(&peer, Some(80), 123),
            "connected endpoint links should not be refreshed from wrapper-level participant staleness alone"
        );
    }

    #[test]
    fn endpoint_path_refresh_prefers_data_freshness_over_control_freshness() {
        let peer = FipsEndpointPeer {
            npub: Keys::generate()
                .public_key()
                .to_bech32()
                .expect("npub"),
            node_addr: NodeAddr::from_bytes([7; 16]),
            connected: true,
            transport_addr: Some("203.0.113.7:9000".to_string()),
            transport_type: Some("udp".to_string()),
            link_id: 43,
            srtt_ms: Some(50),
            srtt_age_ms: Some(1_000),
            packets_sent: 100,
            packets_recv: 100,
            bytes_sent: 8192,
            bytes_recv: 8192,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: true,
            direct_probe_after_ms: Some(12_345),
            direct_probe_retry_count: 3,
            direct_probe_auto_reconnect: true,
            direct_probe_expires_at_ms: Some(67_890),
            nostr_traversal_consecutive_failures: 0,
            nostr_traversal_in_cooldown: false,
            nostr_traversal_cooldown_until_ms: None,
            nostr_traversal_last_observed_skew_ms: None,
        };

        assert!(
            super::endpoint_path_refresh_due(&peer, Some(80), 123),
            "stale tunnel data should refresh direct probes even if control traffic stayed fresh"
        );
        assert!(
            !super::endpoint_path_refresh_due(&peer, Some(120), 123),
            "fresh tunnel data should not churn direct probes"
        );
    }

    #[test]
    fn retry_only_endpoint_peer_status_keeps_probe_separate_from_link() {
        let status = mesh_status_from_endpoint_peer(
            "peer".to_string(),
            &FipsEndpointPeer {
                npub: "npub1peer".to_string(),
                node_addr: NodeAddr::from_bytes([8; 16]),
                connected: false,
                transport_addr: None,
                transport_type: None,
                link_id: 0,
                srtt_ms: None,
                srtt_age_ms: None,
                packets_sent: 0,
                packets_recv: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                rekey_in_progress: false,
                rekey_draining: false,
                current_k_bit: None,
                last_outbound_route: None,
                direct_probe_pending: true,
                direct_probe_after_ms: Some(12_345),
                direct_probe_retry_count: 2,
                direct_probe_auto_reconnect: false,
                direct_probe_expires_at_ms: Some(67_890),
                nostr_traversal_consecutive_failures: 2,
                nostr_traversal_in_cooldown: true,
                nostr_traversal_cooldown_until_ms: Some(123_456),
                nostr_traversal_last_observed_skew_ms: Some(500),
            },
            123,
        );

        assert!(!status.connected);
        assert!(status.direct_probe_pending);
        assert_eq!(status.direct_probe_after_ms, Some(12_345));
        assert_eq!(status.direct_probe_retry_count, 2);
        assert!(!status.direct_probe_auto_reconnect);
        assert_eq!(status.direct_probe_expires_at_ms, Some(67_890));
        assert_eq!(status.nostr_traversal_consecutive_failures, 2);
        assert!(status.nostr_traversal_in_cooldown);
        assert_eq!(status.nostr_traversal_cooldown_until_ms, Some(123_456));
        assert_eq!(status.nostr_traversal_last_observed_skew_ms, Some(500));
        assert_eq!(status.last_seen_at, None);
        assert_eq!(status.transport_addr, None);
        assert_eq!(status.error.as_deref(), Some("fips link pending"));
    }

    #[test]
    fn private_mesh_mtu_defaults_to_safe_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, None, None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: nostr_vpn_core::MESH_UNDERLAY_UDP_MTU,
                tunnel: nostr_vpn_core::MESH_TUNNEL_MTU,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_lan_profile_uses_larger_paired_budget() {
        let mtu = super::resolve_private_mesh_mtu(Some(" LAN "), None, None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1452,
                tunnel: 1322,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_app_profile_uses_same_resolver() {
        let app = AppConfig {
            mesh_mtu_profile: " LAN ".to_string(),
            ..Default::default()
        };
        let mtu = super::resolve_private_mesh_mtu_from_sources(Some(&app), None, None, None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1452,
                tunnel: 1322,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_env_overrides_app_config() {
        let app = AppConfig {
            mesh_mtu_profile: "lan".to_string(),
            mesh_underlay_udp_mtu: 1420,
            mesh_tunnel_mtu: 1290,
            ..Default::default()
        };
        let mtu = super::resolve_private_mesh_mtu_from_sources(Some(&app), None, Some(1280), None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1280,
                tunnel: 1150,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_underlay_override_derives_tunnel_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, Some(1500), None);

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1500,
                tunnel: 1370,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_caps_tunnel_to_underlay_budget() {
        let mtu = super::resolve_private_mesh_mtu(None, Some(1280), Some(1420));

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1280,
                tunnel: 1150,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_lan_profile_clamps_to_underlay_interface_mtu() {
        let mtu = super::clamp_mesh_mtu_to_underlay_interface_mtu(
            super::resolve_private_mesh_mtu(Some("lan"), None, None),
            Some(1400),
        );

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: 1352,
                tunnel: 1222,
            }
        );
    }

    #[test]
    fn private_mesh_mtu_interface_mtu_does_not_raise_safe_default() {
        let mtu = super::clamp_mesh_mtu_to_underlay_interface_mtu(
            super::resolve_private_mesh_mtu(None, None, None),
            Some(9000),
        );

        assert_eq!(
            mtu,
            super::MeshMtu {
                underlay_udp: nostr_vpn_core::MESH_UNDERLAY_UDP_MTU,
                tunnel: nostr_vpn_core::MESH_TUNNEL_MTU,
            }
        );
    }

    #[test]
    fn peer_endpoint_hint_addr_accepts_only_udp_socket_addresses() {
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22:51820")),
            Some("192.168.50.22:51820".to_string())
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("peer.example.com:51820")),
            Some("peer.example.com:51820".to_string())
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint {
                transport: "tcp".to_string(),
                addr: "192.168.50.22:51820".to_string(),
            }),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("127.0.0.1:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("100.120.94.10:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("198.51.100.10:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("0.0.0.0:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp("localhost:51820")),
            None
        );
        assert_eq!(
            super::peer_endpoint_hint_addr(&PeerEndpointHint::udp(format!(
                "{}:51820",
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            ))),
            None
        );
    }

    #[test]
    fn fips_peer_liveness_uses_fresh_link_when_presence_is_stale() {
        assert_eq!(
            super::fips_peer_liveness(Some(100), true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(None, true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(Some(10), true, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(Some(10), false, None, 120),
            (false, Some("fips participant stale".to_string()))
        );
        assert_eq!(
            super::fips_peer_liveness(None, false, Some("dial failed".to_string()), 120),
            (false, Some("dial failed".to_string()))
        );
    }

    #[test]
    fn fips_peer_liveness_rejects_far_future_presence() {
        assert_eq!(
            super::fips_peer_liveness(Some(122), false, None, 120),
            (true, None)
        );
        assert_eq!(
            super::fips_peer_liveness(Some(180), false, None, 120),
            (false, Some("fips participant stale".to_string()))
        );
        assert_eq!(
            super::fips_peer_liveness(Some(180), true, None, 120),
            (false, Some("fips participant stale".to_string()))
        );
    }

    #[test]
    fn fips_peer_ping_due_uses_peer_state_intervals() {
        assert!(super::fips_peer_ping_due(Some(100), None, true, 120));
        assert!(!super::fips_peer_ping_due(Some(100), Some(111), true, 120));
        assert!(super::fips_peer_ping_due(Some(100), Some(110), true, 120));

        assert!(!super::fips_peer_ping_due(None, Some(116), true, 120));
        assert!(super::fips_peer_ping_due(None, Some(115), true, 120));

        assert_eq!(
            super::fips_peer_ping_interval_secs(Some(90), true, 120),
            super::FIPS_PEER_LINK_PING_INTERVAL_SECS
        );
        assert!(super::fips_peer_ping_due(Some(90), Some(91), true, 120));
        assert!(super::fips_peer_ping_due(Some(90), Some(90), true, 120));

        assert!(!super::fips_peer_ping_due(None, Some(91), false, 120));
        assert!(super::fips_peer_ping_due(None, Some(90), false, 120));
    }

    #[test]
    fn fips_peer_ping_due_recovers_from_future_timestamps() {
        assert_eq!(
            super::fips_peer_ping_interval_secs(Some(122), false, 120),
            super::FIPS_PEER_ACTIVE_PING_INTERVAL_SECS
        );
        assert_eq!(
            super::fips_peer_ping_interval_secs(Some(180), false, 120),
            super::FIPS_PEER_DISCOVERY_PROBE_INTERVAL_SECS
        );
        assert!(!super::fips_peer_ping_due(None, Some(122), false, 120));
        assert!(super::fips_peer_ping_due(None, Some(180), false, 120));
    }

    #[test]
    fn fips_peer_ping_sweep_reaches_every_due_peer() {
        let mut peers = (0..10)
            .map(|index| (format!("peer-{index:02}"), None))
            .collect::<Vec<_>>();

        let now = 120;
        let mut due = peers
            .iter()
            .filter(|(_, last_ping_sent_at)| {
                super::fips_peer_ping_due(Some(now), *last_ping_sent_at, true, now)
            })
            .cloned()
            .collect::<Vec<_>>();
        super::prioritize_fips_peer_pings(&mut due);
        for (participant, _) in due {
            peers
                .iter_mut()
                .find(|(candidate, _)| candidate == &participant)
                .expect("scheduled peer")
                .1 = Some(now);
        }

        assert!(
            peers.iter().all(|(_, last_ping_sent_at)| last_ping_sent_at.is_some()),
            "one heartbeat sweep must not leave due peers unprobed"
        );
    }

    #[test]
    fn control_frames_from_rostered_endpoint_resolve_to_participant() {
        let keys = Keys::generate();
        let participant_pubkey = keys.public_key().to_hex();
        let endpoint_npub = keys.public_key().to_bech32().expect("npub");
        let source_peer = PeerIdentity::from_npub(&endpoint_npub).expect("source peer");
        let mesh = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: participant_pubkey.clone(),
            endpoint_npub: endpoint_npub.clone(),
            allowed_ips: vec!["10.44.1.2/32".to_string()],
        }]);
        let frame = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: 42,
        };

        assert_eq!(
            control_frame_source_pubkey(&mesh, source_peer, &frame),
            Some(participant_pubkey)
        );
    }

    #[test]
    fn control_frames_from_unknown_endpoints_are_limited_to_first_contact_records() {
        let keys = Keys::generate();
        let unknown_pubkey = keys.public_key().to_hex();
        let unknown_npub = keys.public_key().to_bech32().expect("npub");
        let unknown_peer = PeerIdentity::from_npub(&unknown_npub).expect("unknown peer");
        let mesh = FipsMeshRuntime::new(Vec::new());
        let ping = FipsControlFrame::Ping {
            network_id: "network".to_string(),
            sent_at: 42,
        };
        let roster = FipsControlFrame::Roster {
            network_id: "network".to_string(),
            roster: NetworkRoster {
                network_name: "network".to_string(),
                devices: Vec::new(),
                admins: Vec::new(),
                aliases: HashMap::new(),
                signed_at: 42,
            },
            signed_roster: None,
        };
        let join_request = FipsControlFrame::JoinRequest {
            requested_at: 42,
            request: MeshJoinRequest {
                network_id: "network".to_string(),
                join_secret: String::new(),
                requester_node_name: "new-device".to_string(),
            },
        };
        let admin = Keys::generate();
        let signed_roster = SignedRoster::sign(
            "network",
            NetworkRoster {
                network_name: "network".to_string(),
                devices: vec![Keys::generate().public_key().to_hex()],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: 42,
            },
            &admin,
        )
        .expect("signed roster");
        let join_roster = FipsControlFrame::JoinRoster {
            control: Box::new(
                JoinRosterControl::new(signed_roster, "request-secret")
                    .expect("join control"),
            ),
        };

        assert!(control_frame_source_pubkey(&mesh, unknown_peer, &ping).is_none());
        assert!(control_frame_source_pubkey(&mesh, unknown_peer, &roster).is_none());
        assert_eq!(
            control_frame_source_pubkey(&mesh, unknown_peer, &join_request),
            Some(unknown_pubkey.clone())
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, unknown_peer, &join_roster),
            Some(unknown_pubkey)
        );
    }

    #[test]
    fn control_frame_destinations_can_target_pending_join_requester() {
        let keys = Keys::generate();
        let requester_pubkey = keys.public_key().to_hex();
        let requester_npub = keys.public_key().to_bech32().expect("npub");
        let mesh = FipsMeshRuntime::new(Vec::new());

        let identities = FipsPeerIdentityMap::default();
        let destination = control_frame_destination_peer(&mesh, &identities, &requester_pubkey)
            .expect("destination identity");

        assert_eq!(destination.npub(), requester_npub);
    }

    #[test]
    fn control_frame_destinations_use_configured_endpoint_identity() {
        let participant_pubkey = Keys::generate().public_key().to_hex();
        let endpoint_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let endpoint_identity = PeerIdentity::from_npub(&endpoint_npub).expect("peer identity");
        let endpoint_node_addr = *endpoint_identity.node_addr().as_bytes();
        let mesh = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: participant_pubkey.clone(),
            endpoint_npub: endpoint_npub.clone(),
            allowed_ips: Vec::new(),
        }]);
        let mut identities = FipsPeerIdentityMap::default();
        identities
            .by_endpoint_node_addr
            .insert(endpoint_node_addr, endpoint_identity);

        let destination = control_frame_destination_peer(&mesh, &identities, &participant_pubkey)
            .expect("destination identity");

        assert_eq!(destination.npub(), endpoint_npub);
    }

    #[test]
    fn control_frame_destinations_can_ack_independent_paid_route_buyers() {
        let buyer = Keys::generate();
        let buyer_pubkey = buyer.public_key().to_hex();
        let buyer_npub = buyer.public_key().to_bech32().expect("npub");
        let mesh = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            Vec::new(),
            Vec::new(),
            vec![nostr_vpn_core::fips_mesh::FipsPaidRouteAdmission {
                participant_pubkey: buyer_pubkey.clone(),
                session_id: "paid-session".to_string(),
                allowed_ips: vec!["10.44.1.2/32".to_string()],
                destination_allowed_ips: Vec::new(),
                allow_routing: true,
                state: nostr_vpn_core::paid_routes::PaidRouteAccessState::FreeProbe,
                amount_due_msat: 0,
                paid_msat: 0,
                unpaid_msat: 0,
                expires_at_unix: u64::MAX,
                updated_at_unix: 42,
            }],
        );

        let destination =
            control_frame_destination_peer(&mesh, &FipsPeerIdentityMap::default(), &buyer_pubkey)
                .expect("paid route buyer endpoint identity");

        assert_eq!(destination.npub(), buyer_npub);
    }

    #[test]
    fn fips_control_recipient_is_prioritized_ahead_of_ambient_peers() {
        let ambient_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let recipient_npub = Keys::generate().public_key().to_bech32().expect("npub");
        let peers = vec![
            FipsEndpointPeerTransportConfig {
                npub: ambient_npub.clone(),
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: true,
                discovery_fallback_transit: true,
            },
            FipsEndpointPeerTransportConfig {
                npub: recipient_npub.clone(),
                addresses: Vec::new(),
                connect_on_start: true,
                auto_reconnect: false,
                discovery_fallback_transit: true,
            },
        ];

        let prioritized = prioritize_fips_control_peer(peers, &recipient_npub);

        assert_eq!(prioritized[0].npub, recipient_npub);
        assert!(prioritized[0].auto_reconnect);
        assert_eq!(prioritized[1].npub, ambient_npub);
    }
