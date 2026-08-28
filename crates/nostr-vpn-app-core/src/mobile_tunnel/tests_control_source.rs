    #[test]
    fn mobile_control_source_accepts_unknown_sender_for_liveness_and_first_contact_records() {
        let roster_peer =
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc".to_string();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(&roster_peer, Vec::new())
            .expect("roster peer");
        let peer_npub = peer.endpoint_npub.clone();
        let mesh = FipsMeshRuntime::with_local_routes(vec![peer], Vec::new());
        let unknown_keys = Keys::generate();
        let unknown_npub = unknown_keys.public_key().to_bech32().expect("unknown npub");
        let unknown_hex = unknown_keys.public_key().to_hex();
        let peer_identity = PeerIdentity::from_npub(&peer_npub).expect("peer identity");
        let unknown_identity = PeerIdentity::from_npub(&unknown_npub).expect("unknown identity");
        let ping = FipsControlFrame::Ping {
            network_id: "mesh-home".to_string(),
            sent_at: 1,
        };
        let join_request = FipsControlFrame::JoinRequest {
            requested_at: 2,
            request: MeshJoinRequest {
                network_id: "mesh-home".to_string(),
                join_secret: String::new(),
                requester_node_name: "iPhone".to_string(),
            },
        };
        let admin = Keys::generate();
        let signed_roster = SignedRoster::sign(
            "mesh-home",
            NetworkRoster {
                network_name: "Home".to_string(),
                devices: vec![Keys::generate().public_key().to_hex()],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: 2,
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

        assert_eq!(
            control_frame_source_pubkey(&mesh, peer_identity, &ping),
            Some(roster_peer)
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, unknown_identity, &ping),
            Some(unknown_hex.clone())
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, unknown_identity, &join_request),
            Some(unknown_hex.clone())
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, unknown_identity, &join_roster),
            Some(unknown_hex)
        );
    }
