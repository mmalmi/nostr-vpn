    #[test]
    fn pending_manual_join_tunnel_is_control_only_until_receipt_backed_acceptance() {
        let joiner_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let joiner_pubkey = joiner_keys.public_key().to_hex();
        let admin_pubkey = admin_keys.public_key().to_hex();
        let network_id = "desktop-manual-pending";

        let mut joining = AppConfig::generated_without_networks();
        joining.nostr.secret_key = joiner_keys.secret_key().to_secret_hex();
        joining.nostr.public_key = joiner_pubkey.clone();
        joining
            .add_manual_join_network(&admin_pubkey, network_id)
            .expect("configure manual join");

        let assert_control_only = |app: &AppConfig| {
            let config = FipsPrivateTunnelConfig::from_app(
                app,
                network_id,
                "utun-manual-pending",
                Some(&joiner_pubkey),
                None,
                &[],
            )
            .expect("pending manual tunnel config");
            assert!(
                config.network_id.is_empty(),
                "an unaccepted join must not enter the requested discovery scope"
            );
            assert!(config.route_targets.is_empty());
            assert!(
                config
                    .peers
                    .iter()
                    .all(|peer| peer.allowed_ips.is_empty()),
                "the configured admin may carry control frames but must own no mesh route"
            );
            assert!(!config.secure_dns_required());
            assert!(config.magic_dns_records.is_empty());
            assert!(!config.advertise_on_nostr);
            assert!(!config.wireguard_exit.enabled);
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                assert!(config.fips_host.is_none());
                assert!(config.local_exit_forwarding_routes.is_empty());
            }
            assert!(config.local_advertised_routes.is_empty());
        };

        assert_control_only(&joining);

        let roster_without_joiner = SignedRoster::sign(
            network_id,
            NetworkRoster {
                network_name: "Manual desktop".to_string(),
                devices: Vec::new(),
                admins: vec![admin_pubkey.clone()],
                aliases: HashMap::new(),
                signed_at: unix_timestamp(),
            },
            &admin_keys,
        )
        .expect("sign unrelated current roster");
        assert!(
            joining
                .apply_verified_admin_signed_shared_roster(&roster_without_joiner)
                .expect("apply configured admin roster")
        );
        assert_control_only(&joining);

        let mut admin = AppConfig::generated();
        admin.nostr.secret_key = admin_keys.secret_key().to_secret_hex();
        admin.nostr.public_key = admin_pubkey.clone();
        let admin_network_entry_id = admin.networks[0].id.clone();
        admin.networks[0].network_id = network_id.to_string();
        admin.networks[0].name = "Manual desktop".to_string();
        admin.networks[0].admins = vec![admin_pubkey.clone()];
        admin.networks[0].devices = vec![joiner_pubkey.clone()];
        admin.networks[0].shared_roster_updated_at = unix_timestamp().saturating_add(1);
        admin.networks[0].shared_roster_signed_by = admin_pubkey.clone();
        let accepted =
            prepare_manual_join_delivery(&admin, &admin_network_entry_id, &joiner_pubkey)
                .expect("prepare accepted manual roster");
        joining
            .apply_manual_join_roster(&accepted, unix_timestamp().saturating_add(1))
            .expect("apply accepted manual roster")
            .expect("manual roster must match pending join");

        let accepted = FipsPrivateTunnelConfig::from_app(
            &joining,
            network_id,
            "utun-manual-accepted",
            Some(&joiner_pubkey),
            None,
            &[],
        )
        .expect("accepted manual tunnel config");
        assert_eq!(accepted.network_id, network_id);
        assert!(accepted.advertise_on_nostr);
        assert!(!accepted.route_targets.is_empty());
        assert!(
            accepted
                .peers
                .iter()
                .any(|peer| peer.participant_pubkey == admin_pubkey
                    && !peer.allowed_ips.is_empty())
        );
    }

    #[test]
    fn tunnel_config_applies_live_endpoint_hints_only_for_network_signal_peers() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let admin_pubkey = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        let network_id = "fips-live-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.networks[0].admins = vec![admin_pubkey.clone()];
        app.fips_webrtc_enabled = false;
        app.nostr.relays.clear();

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[
                (
                    bob_pubkey.clone(),
                    vec![("203.0.113.22:51820".to_string(), 123_000)],
                ),
                (
                    admin_pubkey.clone(),
                    vec![("203.0.113.33:51820".to_string(), 123_000)],
                ),
            ],
        )
        .expect("fips tunnel config");

        assert!(!config.nostr_relays.is_empty());

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("bob endpoint peer");
        assert_eq!(bob.addresses.len(), 1);
        assert_eq!(bob.addresses[0].addr, "203.0.113.22:51820");
        assert_eq!(bob.addresses[0].seen_at_ms, Some(123_000));

        let admin = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint peer");
        assert_eq!(admin.addresses.len(), 1);
        assert_eq!(admin.addresses[0].addr, "203.0.113.33:51820");
        assert_eq!(admin.addresses[0].seen_at_ms, Some(123_000));
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn tunnel_config_applies_live_endpoint_hints_for_selected_paid_exit() {
        let alice_keys = Keys::generate();
        let seller_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let seller_pubkey = seller_keys.public_key().to_hex();
        let seller_npub = seller_keys.public_key().to_bech32().expect("seller npub");
        let network_id = "fips-paid-exit-live-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone()];
        app.fips_bootstrap_enabled = false;
        app.select_public_paid_exit_node(&seller_npub)
            .expect("select paid exit");

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[(
                seller_pubkey.clone(),
                vec![("203.0.113.44:51821".to_string(), 123_000)],
            )],
        )
        .expect("fips tunnel config");

        let seller = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == seller_npub)
            .expect("seller endpoint peer");
        assert_eq!(seller.addresses.len(), 1);
        assert_eq!(seller.addresses[0].addr, "203.0.113.44:51821");
        assert_eq!(seller.addresses[0].seen_at_ms, Some(123_000));
        assert!(config.route_targets.iter().any(|route| route == "0.0.0.0/0"));
        assert!(config.secure_dns_required());
        assert_eq!(
            config.endpoint_hint_ipv4_hosts(),
            vec!["203.0.113.44".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn tunnel_config_pins_manual_provider_for_control_without_routing_through_it() {
        let alice_keys = Keys::generate();
        let seller_keys = Keys::generate();
        let transit_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let seller_npub = seller_keys.public_key().to_bech32().expect("seller npub");
        let transit_npub = transit_keys.public_key().to_bech32().expect("transit npub");
        let network_id = "fips-manual-provider-control-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone()];
        app.fips_bootstrap_enabled = false;
        app.fips_nostr_discovery_enabled = false;
        app.fips_peer_endpoints.insert(
            transit_npub.clone(),
            vec!["203.0.113.46:51821".to_string()],
        );
        app.set_manual_paid_exit_provider(&seller_npub)
            .expect("pin manual provider");

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");

        let seller = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == seller_npub)
            .expect("manual provider endpoint peer");
        assert!(seller.addresses.is_empty());
        assert!(seller.discovery_fallback_transit);
        let transit = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == transit_npub)
            .expect("configured FIPS transit");
        assert_eq!(transit.addresses[0].addr, "203.0.113.46:51821");
        let routed = config
            .peers
            .iter()
            .find(|peer| peer.participant_pubkey == seller_keys.public_key().to_hex())
            .expect("manual provider control peer");
        assert!(routed.allowed_ips.is_empty());
        assert!(!config.route_targets.iter().any(|route| route == "0.0.0.0/0"));
        assert!(!config.nostr_discovery_enabled);
    }

    #[test]
    fn pending_remote_exit_only_keeps_fail_closed_route_when_leak_protection_is_enabled() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "pending-paid-exit".to_string();
        app.set_internet_source(InternetSource::PaidAutomatic);

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "pending-paid-exit",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("pending paid exit tunnel config");

        assert!(!config.route_targets.iter().any(|route| route == "0.0.0.0/0"));
        assert!(config.secure_dns_required());

        app.exit_node_leak_protection = true;
        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "pending-paid-exit",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("protected pending paid exit tunnel config");
        assert!(config.route_targets.iter().any(|route| route == "0.0.0.0/0"));
        assert!(config.secure_dns_required());
        assert!(
            config
                .peers
                .iter()
                .all(|peer| !peer.allowed_ips.iter().any(|route| route == "0.0.0.0/0"))
        );
    }

    #[test]
    fn pending_paid_manual_exit_without_leak_protection_still_owns_dns() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "pending-paid-manual".to_string();
        app.exit_node_leak_protection = false;
        app.set_internet_source(InternetSource::PaidManual);

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "pending-paid-manual",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("pending paid-manual tunnel config");

        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        assert!(config.secure_dns_required());
    }

    #[test]
    fn every_selected_exit_source_owns_dns() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();

        for source in [
            InternetSource::PrivateVpn,
            InternetSource::PaidAutomatic,
            InternetSource::PaidManual,
            InternetSource::WireGuard,
        ] {
            let mut app = AppConfig::default();
            app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
            app.networks[0].enabled = true;
            app.networks[0].network_id = "all-exit-dns".to_string();
            app.exit_node_leak_protection = false;
            app.set_internet_source(source);

            let config = FipsPrivateTunnelConfig::from_app(
                &app,
                "all-exit-dns",
                "utun-test",
                Some(&own_pubkey),
                None,
                &[],
            )
            .expect("exit tunnel config");

            assert!(
                config.secure_dns_required(),
                "{source:?} must keep roster DNS active"
            );
        }
    }

    #[test]
    fn automatic_exit_dns_uses_profile_only_after_wireguard_is_active() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "wg-dns".to_string();
        app.set_internet_source(InternetSource::WireGuard);
        app.wireguard_exit.address = "10.64.70.195/32".to_string();
        app.wireguard_exit.private_key =
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
        app.wireguard_exit.peer_public_key =
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
        app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();
        app.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];
        app.wireguard_exit.dns = vec!["94.140.14.14".to_string()];

        let active = FipsPrivateTunnelConfig::from_app(
            &app,
            "wg-dns",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("active WireGuard tunnel config");
        assert!(active.secure_dns_required());
        assert!(matches!(
            active.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::Doh { .. }
        ));
        assert_eq!(
            active.exit_dns_resolver_config(true).unwrap(),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec!["94.140.14.14".parse::<std::net::IpAddr>().unwrap()]
            }
        );

        app.set_internet_source(InternetSource::Direct);
        let direct = FipsPrivateTunnelConfig::from_app(
            &app,
            "wg-dns",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("direct tunnel config");
        assert!(!direct.secure_dns_required());
        assert!(matches!(
            direct.exit_dns_resolver_config(false).unwrap(),
            ExitDnsResolverConfig::Doh { .. }
        ));
    }

    #[test]
    fn paused_background_tunnel_keeps_control_paths_without_client_network_ownership() {
        let own = Keys::generate();
        let peer = Keys::generate();
        let own_pubkey = own.public_key().to_hex();
        let peer_pubkey = peer.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = own.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "paused-control-only".to_string();
        app.networks[0].devices = vec![own_pubkey.clone(), peer_pubkey];
        app.set_internet_source(InternetSource::WireGuard);
        app.wireguard_exit.enabled = true;
        app.wireguard_exit.address = "10.64.70.195/32".to_string();
        app.wireguard_exit.private_key =
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
        app.wireguard_exit.peer_public_key =
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
        app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();
        app.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];
        app.exit_node_leak_protection = true;

        let mut config = FipsPrivateTunnelConfig::from_app(
            &app,
            "paused-control-only",
            "utun-paused",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("active tunnel config");
        let control_peers = config.endpoint_peers.clone();
        assert!(config.wireguard_exit.enabled);
        assert!(config.secure_dns_required());
        assert!(
            config
                .peers
                .iter()
                .any(|peer| !peer.allowed_ips.is_empty())
        );

        config.disable_client_dataplane();

        assert!(!config.client_dataplane_enabled);
        assert!(config.route_targets.is_empty());
        assert!(config.peers.iter().all(|peer| peer.allowed_ips.is_empty()));
        assert!(!config.wireguard_exit.enabled);
        assert!(!config.exit_node_leak_protection);
        assert!(!config.secure_dns_required());
        assert_eq!(config.endpoint_peers, control_peers);
    }

    #[test]
    fn dns_through_wireguard_fails_closed_until_wireguard_is_active() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "wg-strict-dns".to_string();
        app.set_internet_source(InternetSource::WireGuard);
        app.wireguard_exit.address = "10.64.70.195/32".to_string();
        app.wireguard_exit.private_key =
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
        app.wireguard_exit.peer_public_key =
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
        app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();
        app.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];
        app.exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::ThroughExit;
        app.exit_dns.through_exit_servers = vec!["9.9.9.9".to_string()];

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "wg-strict-dns",
            "utun-test",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("strict WireGuard DNS config");

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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fips_host_uses_the_ordinary_tunnel_interface_and_secure_dns() {
        let keys = Keys::generate();
        let own_pubkey = keys.public_key().to_hex();
        let mut app = AppConfig::default();
        app.nostr.secret_key = keys.secret_key().to_bech32().expect("nsec");
        app.networks[0].enabled = true;
        app.networks[0].network_id = "integrated-fips-host".to_string();
        app.fips_host_tunnel_enabled = true;

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            "integrated-fips-host",
            "nvpn0",
            Some(&own_pubkey),
            None,
            &[],
        )
        .expect("integrated FIPS host config");

        if let Some(fips_host) = config.fips_host.as_ref() {
            assert!(config.secure_dns_required());
            assert!(
                config
                    .interface_addresses()
                    .contains(&format!("{}/128", fips_host.fips_address))
            );
            assert!(
                config
                    .interface_route_targets(config.route_targets.clone())
                    .contains(&"fd00::/8".to_string())
            );
            assert!(!config.route_targets.contains(&"fd00::/8".to_string()));
            assert_eq!(config.interface_mtu(), 1280);
        }
    }

    #[test]
    fn endpoint_bypass_hosts_skip_overlay_tunnel_route_targets() {
        assert!(super::route_targets_include_ipv4_host(
            &["10.44.1.2/32".to_string()],
            "10.44.1.2".parse().unwrap(),
        ));
        assert!(!super::route_targets_include_ipv4_host(
            &["0.0.0.0/0".to_string(), "10.44.1.2/32".to_string()],
            "203.0.113.44".parse().unwrap(),
        ));
    }

    #[test]
    fn link_event_path_hint_refresh_does_not_require_endpoint_restart() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let network_id = "fips-link-refresh-restart-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];

        let current = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[(
                bob_pubkey.clone(),
                vec![("203.0.113.22:51820".to_string(), 123_000)],
            )],
        )
        .expect("current fips tunnel config");
        let refreshed = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("refreshed fips tunnel config");

        let current_bob = current
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("current bob endpoint peer");
        assert_eq!(current_bob.addresses.len(), 1);
        let refreshed_bob = refreshed
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("refreshed bob endpoint peer");
        assert!(
            refreshed_bob.addresses.is_empty(),
            "link-event refreshes must not carry stale live direct hints forward",
        );
        assert!(
            !fips_tunnel_requires_endpoint_restart(&current, &refreshed),
            "path-hint-only refreshes should be applied in place, not by restarting FIPS",
        );

        let mut changed_port = refreshed.clone();
        changed_port.listen_port = changed_port.listen_port.saturating_add(1);
        assert!(
            fips_tunnel_requires_endpoint_restart(&refreshed, &changed_port),
            "transport bind changes still require a real endpoint restart",
        );

        let mut changed_local_address = refreshed.clone();
        changed_local_address.local_address = "10.44.201.17/32".to_string();
        assert!(
            fips_tunnel_requires_endpoint_restart(&refreshed, &changed_local_address),
            "a new roster-derived tunnel address must replace the endpoint and TUN",
        );

        let mut changed_underlay = refreshed.clone();
        changed_underlay.underlay_interface = Some("en0".to_string());
        assert!(
            !fips_tunnel_requires_endpoint_restart(&refreshed, &changed_underlay),
            "a new physical underlay must rebind the configured carrier without replacing FIPS",
        );

        let mut changed_private_hint = refreshed.clone();
        changed_private_hint.advertised_endpoint = "192.168.77.8:51820".to_string();
        assert!(
            !fips_tunnel_requires_endpoint_restart(&refreshed, &changed_private_hint),
            "private local-address hint drift does not change the public FIPS advert",
        );

        let mut changed_public_hint = refreshed.clone();
        changed_public_hint.advertise_public_endpoint = true;
        changed_public_hint.advertised_endpoint = "198.51.100.8:51820".to_string();
        assert!(
            fips_tunnel_requires_endpoint_restart(&refreshed, &changed_public_hint),
            "an effective public FIPS advert change still requires endpoint replacement",
        );
    }

    #[test]
    fn webrtc_toggle_requires_endpoint_restart() {
        let app = AppConfig::generated();
        let network_id = app.effective_network_id();
        let current = FipsPrivateTunnelConfig::from_app(
            &app,
            &network_id,
            "utun-webrtc-toggle",
            app.own_nostr_pubkey_hex().ok().as_deref(),
            None,
            &[],
        )
        .expect("fips tunnel config");
        let mut changed = current.clone();
        changed.webrtc_enabled = !changed.webrtc_enabled;

        assert!(fips_tunnel_requires_endpoint_restart(&current, &changed));
    }

    #[test]
    fn link_event_refresh_restarts_when_underlay_mtu_changes() {
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

        next.mesh_mtu.underlay_udp = next.mesh_mtu.underlay_udp.saturating_sub(1);

        assert!(
            fips_tunnel_requires_endpoint_restart(&current, &next),
            "route refresh must restart FIPS when the transport underlay MTU changes"
        );
    }

    #[test]
    fn tunnel_config_keeps_static_endpoint_hint_for_control_only_admin() {
        let alice_keys = Keys::generate();
        let admin_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let admin_pubkey = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        let network_id = "fips-admin-static-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = Vec::new();
        app.networks[0].admins = vec![admin_pubkey.clone()];
        app.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin_pubkey.clone(),
            requested_at: 1,
        });
        app.fips_peer_endpoints
            .insert(admin_npub.clone(), vec!["203.0.113.10:51820".to_string()]);

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            None,
            &[],
        )
        .expect("fips tunnel config");

        assert!(
            config.peers.iter().all(|peer| peer.allowed_ips.is_empty()),
            "join-request admin peers must not get private-network routes before roster acceptance",
        );
        let admin = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint peer");
        assert_eq!(admin.addresses.len(), 1);
        assert_eq!(admin.addresses[0].addr, "203.0.113.10:51820");
        assert_eq!(admin.addresses[0].seen_at_ms, None);
    }

    #[test]
    fn tunnel_config_seeds_recent_transit_without_granting_routes() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-recent-transit-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = true;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&charlie_pubkey, "203.0.113.55:51820", 123));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert!(
            config
                .peers
                .iter()
                .all(|peer| peer.participant_pubkey != charlie_pubkey),
            "non-roster transit peers must not get private-network routes",
        );
        let charlie = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("authenticated non-roster peer should seed FIPS transit");
        assert_eq!(charlie.addresses.len(), 1);
        assert_eq!(charlie.addresses[0].addr, "203.0.113.55:51820");
        assert_eq!(charlie.addresses[0].seen_at_ms, Some(123_000));
        assert!(!charlie.auto_reconnect);
        assert!(charlie.discovery_fallback_transit);
    }

    #[test]
    fn tunnel_config_drops_non_roster_transit_when_discovery_not_open() {
        if std::env::var("NVPN_FIPS_NOSTR_DISCOVERY_POLICY").is_ok() {
            return;
        }

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let charlie_pubkey = charlie_keys.public_key().to_hex();
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-configured-only-transit-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.connect_to_non_roster_fips_peers = false;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_bootstrap_peers.clear();
        app.fips_bootstrap_peers.insert(
            charlie_npub.clone(),
            vec!["203.0.113.55:51820".to_string()],
        );

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&bob_pubkey, "1.1.1.1:51820", 123));
        assert!(recent.note_success(&charlie_pubkey, "203.0.113.66:51820", 456));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[],
        )
        .expect("fips tunnel config");

        assert_eq!(config.nostr_discovery_policy, NostrDiscoveryPolicy::ConfiguredOnly);
        assert_eq!(config.open_discovery_max_pending, 0);
        assert!(
            config.endpoint_peers.iter().any(|peer| peer.npub == bob_npub),
            "roster recent hints should still be retained"
        );
        assert!(
            config.endpoint_peers.iter().all(|peer| peer.npub != charlie_npub),
            "configured-only discovery must not seed non-roster transit peers"
        );
    }

    #[test]
    fn tunnel_config_uses_only_static_endpoint_hints_when_discovery_disabled() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let alice_nsec = alice_keys.secret_key().to_bech32().expect("alice nsec");
        let alice_pubkey = alice_keys.public_key().to_hex();
        let bob_pubkey = bob_keys.public_key().to_hex();
        let bob_npub = bob_keys.public_key().to_bech32().expect("bob npub");
        let charlie_npub = charlie_keys.public_key().to_bech32().expect("charlie npub");
        let network_id = "fips-static-only-hints-test";

        let mut app = AppConfig::default();
        app.nostr.secret_key = alice_nsec;
        app.fips_nostr_discovery_enabled = false;
        app.networks[0].enabled = true;
        app.networks[0].network_id = network_id.to_string();
        app.networks[0].devices = vec![alice_pubkey.clone(), bob_pubkey.clone()];
        app.fips_peer_endpoints
            .insert(bob_npub.clone(), vec!["192.168.64.5:52528".to_string()]);
        app.fips_peer_endpoints.insert(
            charlie_npub.clone(),
            vec!["192.168.64.6:52528".to_string()],
        );

        let mut recent = recent_peer_cache(&alice_keys, network_id);
        assert!(recent.note_success(&bob_pubkey, "198.51.100.7:52528", 123));

        let config = FipsPrivateTunnelConfig::from_app(
            &app,
            network_id,
            "utun-test",
            Some(&alice_pubkey),
            Some(&recent),
            &[(
                bob_pubkey.clone(),
                vec![("198.51.100.8:52528".to_string(), 456_000)],
            )],
        )
        .expect("fips tunnel config");

        let bob = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == bob_npub)
            .expect("bob endpoint peer");
        assert_eq!(bob.addresses.len(), 1);
        assert_eq!(bob.addresses[0].addr, "192.168.64.5:52528");
        assert_eq!(bob.addresses[0].seen_at_ms, None);
        assert!(
            !bob.discovery_fallback_transit,
            "static-only peers must not become lookup transit"
        );

        let charlie = config
            .endpoint_peers
            .iter()
            .find(|peer| peer.npub == charlie_npub)
            .expect("operator-configured non-roster transit peer");
        assert!(charlie.auto_reconnect);
        assert!(
            charlie.discovery_fallback_transit,
            "an explicit non-roster static peer is the fallback transit path when ambient discovery is disabled"
        );
        assert!(
            config
                .peers
                .iter()
                .all(|peer| peer.endpoint_npub != charlie_npub),
            "fallback transit must not become a private-network route target"
        );
    }

    include!("recent_peer_budget.rs");
