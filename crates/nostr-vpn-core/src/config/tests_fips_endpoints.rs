    #[test]
    fn fips_peer_endpoints_normalize_and_exclude_self() {
        let (_, own_public_key) = generate_nostr_identity();
        let (_, peer_public_key) = generate_nostr_identity();
        let peer_public_key_hex =
            normalize_nostr_pubkey(&peer_public_key).expect("valid peer public key");
        let mut config = AppConfig::default();
        config.nostr.secret_key = "not-a-secret-key".to_string();
        config.nostr.public_key = own_public_key.clone();
        config.fips_peer_endpoints.insert(
            peer_public_key_hex,
            vec![
                " 10.203.0.12:51820 ".to_string(),
                "10.203.0.12:51820".to_string(),
                "198.51.100.10:51820".to_string(),
                format!("{peer_public_key}:51820"),
                "fips".to_string(),
            ],
        );
        config
            .fips_peer_endpoints
            .insert(own_public_key, vec!["10.203.0.10:51820".to_string()]);

        config.ensure_defaults();

        assert_eq!(
            config.fips_static_peer_endpoints(),
            vec![(
                peer_public_key,
                vec!["10.203.0.12:51820".to_string(), "fips:51820".to_string()]
            )]
        );
        assert!(config.has_fips_static_peer_endpoints());
    }

    #[test]
    fn set_fips_peer_endpoint_hints_replaces_and_removes_peer_hints() {
        let (_, peer_public_key) = generate_nostr_identity();
        let peer_public_key_hex =
            normalize_nostr_pubkey(&peer_public_key).expect("valid peer public key");
        let mut config = AppConfig::default();

        config
            .set_fips_peer_endpoint_hints(
                &peer_public_key,
                &[
                    " peer.example.com ".to_string(),
                    "192.168.1.23".to_string(),
                    "peer.example.com:51820".to_string(),
                    "[fd00::23]".to_string(),
                ],
            )
            .expect("set hints");

        assert_eq!(
            config.fips_peer_endpoint_hints(&peer_public_key_hex),
            vec![
                "192.168.1.23:51820".to_string(),
                "[fd00::23]:51820".to_string(),
                "peer.example.com:51820".to_string()
            ]
        );

        let error = config
            .set_fips_peer_endpoint_hints(&peer_public_key, &["198.51.100.10:51820".to_string()])
            .expect_err("documentation endpoint is rejected")
            .to_string();
        assert!(error.contains("host:port"), "{error}");
        assert_eq!(
            config.fips_peer_endpoint_hints(&peer_public_key),
            vec![
                "192.168.1.23:51820".to_string(),
                "[fd00::23]:51820".to_string(),
                "peer.example.com:51820".to_string()
            ]
        );

        config
            .set_fips_peer_endpoint_hints(&peer_public_key, &[])
            .expect("clear hints");
        assert!(config.fips_peer_endpoint_hints(&peer_public_key).is_empty());
    }
