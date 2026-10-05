
    #[cfg(feature = "paid-exit")]
    #[test]
    fn paid_route_admissions_seed_configured_endpoint_peers() {
        use nostr_vpn_core::fips_mesh::FipsPaidRouteAdmission;

        let buyer_keys = Keys::generate();
        let buyer_pubkey = buyer_keys.public_key().to_hex();
        let buyer_npub = buyer_keys.public_key().to_bech32().expect("buyer npub");
        let endpoint_peers = super::fips_endpoint_peers_with_paid_route_admissions(
            Vec::new(),
            &[FipsPaidRouteAdmission {
                participant_pubkey: buyer_pubkey,
                session_id: "seller-session-1".to_string(),
                allowed_ips: vec!["10.44.1.2/32".to_string()],
                destination_allowed_ips: vec!["0.0.0.0/0".to_string()],
                allow_routing: true,
                state: nostr_vpn_core::paid_routes::PaidRouteAccessState::Paid,
                amount_due_msat: 1_000,
                paid_msat: 1_000,
                unpaid_msat: 0,
                expires_at_unix: 200,
                updated_at_unix: 100,
            }],
        );

        assert_eq!(endpoint_peers.len(), 1);
        assert_eq!(endpoint_peers[0].npub, buyer_npub);
        assert!(endpoint_peers[0].addresses.is_empty());
        assert!(endpoint_peers[0].auto_reconnect);
        assert!(!endpoint_peers[0].discovery_fallback_transit);
    }

    #[cfg(feature = "paid-exit")]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn paid_route_admissions_install_buyer_return_routes() {
        use nostr_vpn_core::config::PaidExitSellerEgress;
        use nostr_vpn_core::fips_mesh::FipsPaidRouteAdmission;

        let seller_keys = Keys::generate();
        let seller_pubkey = seller_keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = seller_keys.secret_key().to_bech32().expect("seller nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "paid-exit-seller".to_string();
        let mut config = FipsPrivateTunnelConfig::from_app(
            &app,
            "paid-exit-seller",
            "nvpn-paid",
            Some(&seller_pubkey),
            None,
            &[],
        )
        .expect("seller tunnel config");
        config.paid_route_admissions = vec![FipsPaidRouteAdmission {
            participant_pubkey: Keys::generate().public_key().to_hex(),
            session_id: "seller-session-1".to_string(),
            allowed_ips: vec!["10.44.133.173/32".to_string()],
            destination_allowed_ips: vec!["0.0.0.0/0".to_string()],
            allow_routing: true,
            state: nostr_vpn_core::paid_routes::PaidRouteAccessState::FreeProbe,
            amount_due_msat: 0,
            paid_msat: 0,
            unpaid_msat: 0,
            expires_at_unix: 200,
            updated_at_unix: 100,
        }];

        assert!(
            config
                .interface_route_targets(Vec::new())
                .contains(&"10.44.133.173/32".to_string())
        );

        assert!(super::paid_route_admissions_for_egress(&config, true)[0].allow_routing);
        config.local_exit_seller_egress = Some(PaidExitSellerEgress::WireGuard);
        assert!(!super::paid_route_admissions_for_egress(&config, false)[0].allow_routing);

        let upstream = Keys::generate().public_key().to_hex();
        config.local_exit_seller_egress = Some(PaidExitSellerEgress::PrivatePeer {
            pubkey: upstream.clone(),
        });
        config.peers.push(
            FipsMeshPeerConfig::from_participant_pubkey(
                &upstream,
                vec!["0.0.0.0/0".to_string()],
            )
            .expect("private upstream"),
        );
        let connected = HashSet::from([upstream.as_str()]);
        assert!(!super::local_exit_seller_egress_ready(
            &config, &connected, false, None
        ));
        assert!(super::local_exit_seller_egress_ready(
            &config,
            &connected,
            false,
            Some(config.listen_port)
        ));
        config.paid_route_admissions[0].participant_pubkey = upstream;
        assert!(!super::paid_route_admissions_for_egress(&config, true)[0].allow_routing);
    }

    async fn bind_listener_test_runtime(port: u16) -> FipsPrivateMeshRuntime {
        let keys = Keys::generate();
        let endpoint_peers = Vec::new();
        let transport = FipsEndpointTransportConfig {
            listen_port: port,
            bind_interface: None,
            advertised_endpoint: format!("8.8.8.8:{port}"),
            advertise_public_endpoint: true,
            nostr_discovery_enabled: false,
            advertise_on_nostr: false,
            webrtc_enabled: false,
            stun_servers: Vec::new(),
            websocket: Default::default(),
            share_local_candidates: false,
        };
        let config = super::fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            Some(&transport),
            super::private_mesh_mtu_from_app(None),
            NostrDiscoveryPolicy::ConfiguredOnly,
            0,
        );
        FipsPrivateMeshRuntime::bind_with_config_scoped(
            keys.secret_key().to_bech32().expect("nsec"),
            None,
            Vec::new(),
            config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("FIPS bind")
    }

    #[tokio::test]
    async fn production_fips_bind_confirms_its_udp_listener() {
        let port = available_udp_port();
        let runtime = bind_listener_test_runtime(port).await;

        assert_eq!(
            runtime
                .confirmed_udp_listen_port(port, None)
                .await
                .expect("listener snapshot"),
            Some(port)
        );
        runtime.endpoint().shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn production_fips_bind_does_not_claim_an_occupied_udp_port() {
        let reservation = UdpSocket::bind("0.0.0.0:0").expect("reserve UDP port");
        let port = reservation.local_addr().expect("reserved address").port();
        let runtime = bind_listener_test_runtime(port).await;

        assert_eq!(
            runtime
                .confirmed_udp_listen_port(port, Some(false))
                .await
                .expect("listener snapshot"),
            None
        );
        runtime.endpoint().shutdown().await.expect("shutdown");
    }

    #[test]
    fn seller_outbound_interface_follows_the_derived_egress() {
        use nostr_vpn_core::config::PaidExitSellerEgress;

        let private = PaidExitSellerEgress::PrivatePeer {
            pubkey: "private-upstream".to_string(),
        };
        assert_eq!(
            super::local_exit_outbound_interface(
                Some(&PaidExitSellerEgress::Direct),
                "nvpn0",
                Some("wg0"),
                Some("en0")
            )
            .as_deref(),
            Some("en0")
        );
        assert_eq!(
            super::local_exit_outbound_interface(
                Some(&PaidExitSellerEgress::WireGuard),
                "nvpn0",
                Some("wg0"),
                Some("en0")
            )
            .as_deref(),
            Some("wg0")
        );
        assert_eq!(
            super::local_exit_outbound_interface(
                Some(&private),
                "nvpn0",
                Some("wg0"),
                Some("en0")
            )
            .as_deref(),
            Some("nvpn0")
        );
    }

    /// Pin the open-discovery / closed-data-plane invariant.
    ///
    /// FIPS handshake is `Open` so any nvpn node we see on relays may
    /// connect to us (this is what enables transit through friend-of-a-friend
    /// peers). The data plane MUST stay closed: a packet whose FIPS source
    /// npub doesn't own its inner-source IP per the local roster is dropped
    /// before it reaches the tun. This test wires both halves together so a
    /// future "fix" that opens ambient discovery OR loosens the roster gate
    /// will fail loudly.
    ///
    /// The cross-platform integration variants (T1: live handshake, T4:
    /// transit through non-roster peer) live in the FIPS docker continuity
    /// suite — they need a real endpoint pair and can't run as unit tests.
    #[test]
    fn open_discovery_does_not_loosen_tun_roster_gate() {
        let roster_peer = Keys::generate();
        let stranger = Keys::generate();
        let roster_pubkey = roster_peer.public_key().to_hex();
        let roster_npub = roster_peer.public_key().to_bech32().expect("roster npub");
        let stranger_npub = stranger.public_key().to_bech32().expect("stranger npub");
        let roster_node_addr = *PeerIdentity::from_npub(&roster_npub)
            .expect("roster endpoint identity")
            .node_addr()
            .as_bytes();
        let stranger_node_addr = *PeerIdentity::from_npub(&stranger_npub)
            .expect("stranger endpoint identity")
            .node_addr()
            .as_bytes();

        let mesh_peer = FipsMeshPeerConfig::from_participant_pubkey(
            &roster_pubkey,
            vec!["10.44.1.2/32".to_string()],
        )
        .expect("roster peer config");
        let endpoint_peers =
            fips_endpoint_peers_from_mesh(std::slice::from_ref(&mesh_peer), Vec::new(), Vec::new());
        let config = fips_endpoint_config_with_open_discovery_limit(
            &endpoint_peers,
            None,
            super::resolve_private_mesh_mtu(None, None, None),
            NostrDiscoveryPolicy::Open,
            FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        );

        assert_eq!(
            config.node.discovery.nostr.policy,
            fips_endpoint::NostrDiscoveryPolicy::Open,
            "open FIPS discovery must not loosen private roster traffic admission",
        );

        let mesh = FipsMeshRuntime::new(vec![mesh_peer.clone()]);

        // The roster peer's own packet is admitted.
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 44, 1, 2]);
        packet[16..20].copy_from_slice(&[10, 44, 1, 1]);
        assert!(
            mesh.receive_endpoint_data_owned_with_source_node_addr(
                &roster_node_addr,
                packet.clone()
            )
            .is_some(),
            "roster peer's owned source IP must be admitted",
        );

        // A stranger that successfully completed the open FIPS handshake
        // still cannot inject anything onto our tun, regardless of inner
        // source IP.
        assert!(
            mesh.endpoint_source_admitter(&stranger_node_addr).is_none(),
            "non-roster peer must not inject packets onto the tun",
        );

        let mut spoofed = packet.clone();
        spoofed[12..16].copy_from_slice(&[203, 0, 113, 9]);
        assert!(
            mesh.receive_endpoint_data_owned_with_source_node_addr(&stranger_node_addr, spoofed)
                .is_none(),
            "non-roster peer must not inject packets onto the tun (spoofed source)",
        );
    }
