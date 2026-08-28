    #[test]
    fn mobile_peer_identity_map_resolves_endpoint_identities_and_skips_invalid_npubs() {
        let participant = Keys::generate().public_key().to_hex();
        let endpoint_keys = Keys::generate();
        let endpoint_hex = endpoint_keys.public_key().to_hex();
        let endpoint_npub = endpoint_keys.public_key().to_bech32().expect("npub");
        let invalid_participant = "invalid-participant".to_string();

        let identities = mobile_peer_identity_map(
            &[
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
            ],
            &HashMap::new(),
        );

        let endpoint_node_addr = *PeerIdentity::from_npub(&endpoint_npub)
            .expect("endpoint identity")
            .node_addr()
            .as_bytes();
        let participant_key = mobile_participant_pubkey_bytes(&participant).expect("participant");
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
            mobile_identity_for_send(&identities, Some(&participant_key), &endpoint_node_addr)
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

    #[test]
    fn mobile_peer_identity_map_resolves_configured_transit() {
        let transit = Keys::generate().public_key().to_hex();
        let expected = FipsMeshPeerConfig::from_participant_pubkey(&transit, Vec::new())
            .expect("transit peer");
        let bootstrap_peers = HashMap::from([(
            transit.clone(),
            vec![FipsPeerAddressHint {
                priority: 0,
                addr: "udp://127.0.0.1:1".to_string(),
                seen_at_ms: None,
            }],
        )]);

        let identities = mobile_peer_identity_map(&[], &bootstrap_peers);

        assert_eq!(
            identities
                .identity_for_participant(&transit)
                .expect("configured transit identity")
                .npub(),
            expected.endpoint_npub
        );
    }
