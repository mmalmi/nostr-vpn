    #[test]
    fn pending_manual_join_preserves_independent_wireguard_exit_and_dns() {
        let joiner_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let joiner_pubkey = joiner_keys.public_key().to_hex();
        let admin_pubkey = admin_keys.public_key().to_hex();
        let network_id = "desktop-manual-pending-wireguard";

        let mut joining = AppConfig::generated_without_networks();
        joining.nostr.secret_key = joiner_keys.secret_key().to_secret_hex();
        joining.nostr.public_key = joiner_pubkey.clone();
        joining
            .add_manual_join_network(&admin_pubkey, network_id)
            .expect("configure manual join");
        joining.set_internet_source(InternetSource::WireGuard);
        joining.wireguard_exit.address = "10.64.70.195/32".to_string();
        joining.wireguard_exit.private_key =
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
        joining.wireguard_exit.peer_public_key =
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
        joining.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();
        joining.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];
        joining.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::ThroughExit;
        joining.exit_dns.through_exit_servers = vec!["9.9.9.9".to_string()];

        let config = FipsPrivateTunnelConfig::from_app(
            &joining,
            network_id,
            "utun-manual-pending-wireguard",
            Some(&joiner_pubkey),
            None,
            &[],
        )
        .expect("pending manual tunnel with WireGuard exit");

        assert!(config.network_id.is_empty());
        assert!(config.route_targets.is_empty());
        assert!(config.magic_dns_records.is_empty());
        assert!(config.advertise_on_nostr);
        assert_eq!(config.wireguard_exit, joining.wireguard_exit);
        assert!(config.secure_dns_required());
        assert_eq!(
            config.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::FailClosed
        );
        assert_eq!(
            config.exit_dns_resolver_config(true).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec!["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]
            }
        );
    }
