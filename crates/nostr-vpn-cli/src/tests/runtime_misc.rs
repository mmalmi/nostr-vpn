use crate::*;
use fips_core::discovery::nostr::{OverlayEndpointAdvert, OverlayTransportKind};
use nostr_sdk::prelude::{Keys, ToBech32};
use std::collections::HashSet;
use std::net::Ipv4Addr;

fn endpoint_hints_app(endpoint: &str, lan_discovery_enabled: bool) -> AppConfig {
    let mut app = AppConfig::generated();
    app.node.endpoint = endpoint.to_string();
    app.node.listen_port = 51820;
    app.node.tunnel_ip = "10.44.1.1/32".to_string();
    app.lan_discovery_enabled = lan_discovery_enabled;
    app
}

#[test]
fn daemon_vpn_requires_remote_participants_to_be_active() {
    assert!(!daemon_vpn_active(true, 0));
    assert!(daemon_vpn_active(true, 1));
    assert!(!daemon_vpn_active(false, 1));
}

#[test]
fn split_magic_dns_yields_port_53_to_secure_dns_for_every_exit_source() {
    let mut app = AppConfig::generated();
    assert!(!secure_exit_dns_required(&app));
    assert!(split_magic_dns_should_start(&app, false));
    assert!(!split_magic_dns_should_start(&app, true));
    for source in [
        InternetSource::PrivateVpn,
        InternetSource::PaidAutomatic,
        InternetSource::PaidManual,
        InternetSource::WireGuard,
    ] {
        app.set_internet_source(source);
        assert!(secure_exit_dns_required(&app), "source={source:?}");
        assert!(
            !split_magic_dns_should_start(&app, false),
            "a failed exit sync must not start competing split DNS; source={source:?}"
        );
    }
}

#[test]
fn split_magic_dns_never_uses_an_unusable_windows_random_port() {
    #[cfg(target_os = "windows")]
    assert_eq!(split_magic_dns_bind_fallback_port(), None);
    #[cfg(not(target_os = "windows"))]
    assert_eq!(split_magic_dns_bind_fallback_port(), Some(0));
}

#[test]
fn daemon_vpn_idle_status_distinguishes_waiting_from_paused() {
    assert_eq!(
        daemon_vpn_idle_status(true, 0, false),
        crate::WAITING_FOR_PARTICIPANTS_STATUS
    );
    assert_eq!(
        daemon_vpn_idle_status(false, 0, true),
        "Listening for join requests"
    );
    assert_eq!(daemon_vpn_idle_status(false, 0, false), "Paused");
    assert_eq!(daemon_vpn_idle_status(true, 2, false), "Paused");
}

#[test]
fn fips_private_runtime_active_tolerates_no_active_network() {
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    assert!(app.active_network_opt().is_none());
    assert!(!fips_private_runtime_active(&app, true, 0));

    let network_id = app.networks[0].id.clone();
    app.set_network_enabled(&network_id, true)
        .expect("enable network");
    app.set_network_join_requests_enabled(&network_id, true)
        .expect("enable join requests");
    assert!(fips_private_runtime_active(&app, false, 0));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn enabled_fips_host_tunnel_activates_runtime_while_vpn_is_paused() {
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = true;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    assert_eq!(expected_peer_count(&app), 0);
    assert!(fips_private_runtime_active(&app, false, 0));
}

#[test]
fn pending_nostr_join_request_activates_fips_without_network_peers() {
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    assert!(app.active_network_opt().is_none());
    assert_eq!(expected_peer_count(&app), 0);
    assert!(app.pending_nostr_join_request.is_none());
    assert!(!fips_private_runtime_active(&app, false, 0));

    app.ensure_pending_nostr_join_request(1_778_998_000)
        .expect("pending device-approval request");

    assert!(app.pending_nostr_join_request.is_some());
    assert!(fips_private_runtime_active(&app, false, 0));
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_seller_keeps_private_fips_runtime_active_without_roster() {
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    app.paid_exit.enabled = true;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    assert!(app.active_network_opt().is_none());
    assert_eq!(expected_peer_count(&app), 0);
    assert!(paid_exit_fips_runtime_active(&app));
    assert!(fips_private_runtime_active(&app, false, 0));
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_automatic_keeps_fips_runtime_active_before_selecting_seller() {
    use nostr_vpn_core::config::InternetSource;

    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    app.set_internet_source(InternetSource::PaidAutomatic);
    assert!(app.public_paid_exit_node_pubkey_hex().is_none());
    assert!(paid_exit_fips_runtime_active(&app));
    assert!(fips_private_runtime_active(&app, false, 0));

    app.set_internet_source(InternetSource::Direct);
    assert!(!app.connect_to_non_roster_fips_peers);
    assert!(!paid_exit_fips_runtime_active(&app));

    assert!(app.enable_paid_exit_market_discovery());
    assert_eq!(app.internet_source, InternetSource::Direct);
    assert!(paid_exit_fips_runtime_active(&app));
    app.connect_to_non_roster_fips_peers = false;
    assert!(!paid_exit_fips_runtime_active(&app));
}

#[cfg(feature = "paid-exit")]
#[test]
fn manual_provider_starts_fips_without_switching_source_or_enabling_discovery() {
    let provider = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("provider npub");
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    app.fips_nostr_discovery_enabled = false;
    app.fips_advertise_public_endpoint = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }

    app.set_manual_paid_exit_provider(&provider)
        .expect("manual provider");
    app.set_internet_source(InternetSource::PaidManual);
    app.set_internet_source(InternetSource::Direct);

    assert_eq!(app.internet_source, InternetSource::Direct);
    assert!(app.connect_to_non_roster_fips_peers);
    assert!(!app.fips_nostr_discovery_enabled);
    assert!(!app.fips_advertise_public_endpoint);
    assert!(paid_exit_fips_runtime_active(&app));
    assert!(fips_private_runtime_active(&app, false, 0));
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_run_settings_prepare_seller_transport_without_ambient_discovery() {
    use nostr_vpn_core::config::NostrPubsubMode;

    let mut app = AppConfig::generated();
    app.connect_to_non_roster_fips_peers = false;
    app.fips_nostr_discovery_enabled = false;
    app.fips_advertise_public_endpoint = false;
    app.nostr.pubsub.mode = NostrPubsubMode::Off;

    apply_paid_exit_run_settings(
        &mut app,
        &PaidExitRunArgs {
            config: None,
            offer_id: None,
            publish: false,
            no_reload_daemon: true,
            upstream: None,
            price_msat_per_gb: None,
            accepted_mints: None,
            accepted_mint: Vec::new(),
            country_code: None,
            asn: None,
            max_channel_capacity_sat: None,
            channel_expiry_secs: None,
            free_probe_units: None,
            grace_units: None,
            json: false,
        },
    )
    .expect("paid exit run settings");

    assert!(app.paid_exit.enabled);
    assert!(!app.connect_to_non_roster_fips_peers);
    assert!(!app.fips_nostr_discovery_enabled);
    assert!(!app.fips_advertise_public_endpoint);
    assert_eq!(app.nostr.pubsub.mode, NostrPubsubMode::Relay);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_offer_tracks_current_source_without_resaving_seller_settings() {
    let peer = Keys::generate().public_key().to_hex();
    let mut app = AppConfig::generated();
    let offer_upstream = |app: &AppConfig| {
        paid_exit_offer_config(app)
            .expect("advertisable offer")
            .access
            .upstream
    };
    app.set_active_network_id("paid-exit-source-switch")
        .expect("activate network");
    app.networks[0].devices.push(peer.clone());
    app.wireguard_exit.address = "10.200.0.2/32".to_string();
    app.wireguard_exit.private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
    app.wireguard_exit.peer_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
    app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();

    app.paid_exit.access.upstream = PaidExitUpstream::WireGuardExit;
    assert_eq!(offer_upstream(&app), PaidExitUpstream::HostDefault);

    app.paid_exit.access.upstream = PaidExitUpstream::HostDefault;
    app.set_internet_source(InternetSource::WireGuard);
    assert_eq!(offer_upstream(&app), PaidExitUpstream::WireGuardExit);

    app.paid_exit.access.upstream = PaidExitUpstream::WireGuardExit;
    app.set_internet_source(InternetSource::Direct);
    assert_eq!(offer_upstream(&app), PaidExitUpstream::HostDefault);

    app.select_private_exit_node(&peer)
        .expect("select private exit");
    assert_eq!(offer_upstream(&app), PaidExitUpstream::HostDefault);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_upstream_cli_setting_selects_the_same_runtime_source() {
    let mut app = AppConfig::generated();

    set_paid_exit_upstream(&mut app, "wg").expect("select WireGuard");
    assert_eq!(app.internet_source, InternetSource::WireGuard);
    assert!(app.wireguard_exit.enabled);
    assert_eq!(
        app.paid_exit.access.upstream,
        PaidExitUpstream::WireGuardExit
    );

    set_paid_exit_upstream(&mut app, "host-default").expect("select direct internet");
    assert_eq!(app.internet_source, InternetSource::Direct);
    assert!(!app.wireguard_exit.enabled);
    assert_eq!(app.paid_exit.access.upstream, PaidExitUpstream::HostDefault);
}

#[cfg(feature = "paid-exit")]
#[test]
fn selected_public_paid_exit_counts_as_private_fips_peer_without_active_network() {
    let seller = Keys::generate();
    let seller_pubkey = seller.public_key().to_hex();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }
    app.select_public_paid_exit_node(&seller_npub)
        .expect("select public paid exit");

    assert!(app.active_network_opt().is_none());
    assert_eq!(expected_peer_count(&app), 1);
    assert!(paid_exit_fips_runtime_active(&app));
    assert!(fips_private_runtime_active(
        &app,
        true,
        expected_peer_count(&app)
    ));

    let own_pubkey = app.own_nostr_pubkey_hex().expect("own pubkey");
    let config = crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app(
        &app,
        &app.effective_network_id(),
        "utun-test",
        Some(&own_pubkey),
        None,
        &[],
    )
    .expect("fips paid exit tunnel config");

    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].participant_pubkey, seller_pubkey);
    assert!(
        config
            .route_targets
            .iter()
            .any(|route| route == "0.0.0.0/0")
    );

    app.set_internet_source(InternetSource::Direct);
    assert!(!app.connect_to_non_roster_fips_peers);
    assert!(!paid_exit_fips_runtime_active(&app));
}
#[test]
fn fips_roster_publish_attempts_disconnected_recipients() {
    let recipients = vec!["alice".to_string(), "bob".to_string()];

    let (ready, pending) = split_ready_fips_roster_recipients(recipients.clone(), &HashSet::new());

    assert_eq!(ready, recipients);
    assert!(pending.is_empty());
}
#[test]
fn generic_roster_waits_for_join_receipt_without_delaying_existing_peers() {
    let recipients = vec!["existing".to_string(), "joining".to_string()];
    let awaiting = HashSet::from(["joining".to_string()]);
    let (ready, pending) = split_ready_fips_roster_recipients(recipients, &awaiting);
    assert_eq!(ready, ["existing"]);
    assert_eq!(pending, awaiting);
    let (ready, pending) =
        split_ready_fips_roster_recipients(pending.into_iter().collect(), &HashSet::new());
    assert_eq!(ready, ["joining"]);
    assert!(pending.is_empty());
}
#[test]
fn local_fips_endpoint_hints_share_public_configured_endpoint_with_roster() {
    let app = endpoint_hints_app("89.27.103.157:1111", true);

    let hints = local_fips_endpoint_hints(&app, vec![Ipv4Addr::new(192, 168, 50, 10)], &[]);
    let addrs = hints.into_iter().map(|hint| hint.addr).collect::<Vec<_>>();

    assert_eq!(
        addrs,
        vec![
            "192.168.50.10:51820".to_string(),
            "89.27.103.157:51820".to_string(),
        ]
    );
}
#[test]
fn local_fips_endpoint_hints_share_fips_advertised_udp_endpoint_with_roster() {
    let app = endpoint_hints_app("127.0.0.1:1111", false);
    let advertised = vec![
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "8.8.8.8:51820".to_string(),
        },
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        },
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.4.4:443".to_string(),
        },
    ];

    let hints = local_fips_endpoint_hints(&app, Vec::new(), &advertised);
    let addrs = hints.into_iter().map(|hint| hint.addr).collect::<Vec<_>>();

    assert_eq!(addrs, vec!["8.8.8.8:51820"]);
}
#[test]
fn local_fips_endpoint_hints_do_not_share_lan_when_disabled() {
    let app = endpoint_hints_app("127.0.0.1:1111", false);

    let hints = local_fips_endpoint_hints(&app, vec![Ipv4Addr::new(192, 168, 50, 10)], &[]);

    assert!(hints.is_empty());
}
#[test]
fn local_fips_endpoint_hints_keep_configured_lan_when_lan_discovery_disabled() {
    let app = endpoint_hints_app("192.168.50.22:1111", false);

    let hints = local_fips_endpoint_hints(&app, vec![Ipv4Addr::new(192, 168, 50, 10)], &[]);

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].addr, "192.168.50.22:51820");
}
#[test]
fn local_fips_endpoint_hints_do_not_share_cgnat_candidates() {
    let app = endpoint_hints_app("127.0.0.1:1111", true);

    let hints = local_fips_endpoint_hints(&app, vec![Ipv4Addr::new(100, 120, 94, 10)], &[]);

    assert!(hints.is_empty());
}
#[test]
fn local_fips_endpoint_hints_do_not_share_loopback_when_lan_enabled() {
    let app = endpoint_hints_app("127.0.0.1:1111", true);

    let hints = local_fips_endpoint_hints(&app, Vec::new(), &[]);

    assert!(hints.is_empty());
}
#[test]
fn local_fips_endpoint_hints_do_not_share_tunnel_endpoint() {
    let app = endpoint_hints_app("10.44.1.1:1111", true);

    let hints = local_fips_endpoint_hints(&app, Vec::new(), &[]);

    assert!(hints.is_empty());
}
#[test]
fn local_fips_endpoint_hints_keep_dns_endpoint_and_listen_port() {
    let app = endpoint_hints_app("peer.example.com:1111", false);

    let hints = local_fips_endpoint_hints(&app, Vec::new(), &[]);

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].addr, "peer.example.com:51820");
}
#[test]
fn runtime_signal_ipv4_candidates_keep_local_non_tunnel_addresses() {
    let candidates =
        runtime_signal_ipv4_candidates(Some(Ipv4Addr::new(192, 168, 50, 10)), "10.44.1.1/32");

    assert!(candidates.contains(&Ipv4Addr::new(192, 168, 50, 10)));
    assert!(!candidates.contains(&Ipv4Addr::new(10, 44, 1, 1)));
    assert!(!candidates.contains(&Ipv4Addr::new(100, 120, 94, 10)));
}
#[test]
fn runtime_signal_ipv4_candidates_drop_detected_cgnat_address() {
    let candidates =
        runtime_signal_ipv4_candidates(Some(Ipv4Addr::new(100, 120, 94, 10)), "10.44.1.1/32");

    assert!(!candidates.contains(&Ipv4Addr::new(100, 120, 94, 10)));
}
#[test]
fn endpoint_hint_recipients_are_active_participants_only() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let admin = Keys::generate();
    let own_pubkey = own.public_key().to_hex();
    let peer_pubkey = peer.public_key().to_hex();
    let admin_pubkey = admin.public_key().to_hex();
    let mut app = AppConfig::generated();
    let network_id = app.networks[0].id.clone();
    app.set_network_enabled(&network_id, true)
        .expect("activate first network");
    app.nostr.secret_key = own.secret_key().to_bech32().expect("own nsec");
    app.nostr.public_key = own_pubkey.clone();
    app.networks[0].devices = vec![own_pubkey.clone(), peer_pubkey.clone()];
    app.networks[0].admins = vec![admin_pubkey.clone()];

    let recipients = desired_fips_endpoint_hint_recipients(&app);

    assert_eq!(recipients, HashSet::from([peer_pubkey]));
    assert!(!recipients.contains(&own_pubkey));
    assert!(!recipients.contains(&admin_pubkey));
}
#[test]
fn endpoint_hint_capability_refreshes_only_matching_roster_peer() {
    use nostr_vpn_core::fips_control::{PeerCapabilities, PeerEndpointHint};

    let roster_peer = "11".repeat(32);
    let other_peer = "22".repeat(32);
    let recipients = HashSet::from([roster_peer.clone()]);
    let capabilities = PeerCapabilities {
        endpoint_hints: vec![PeerEndpointHint::udp("192.168.50.10:51820")],
        ..PeerCapabilities::default()
    };

    assert_eq!(
        endpoint_hint_refresh_participant(
            Some("network-a"),
            &recipients,
            &roster_peer,
            "network-a",
            &capabilities,
        ),
        Some(roster_peer.clone())
    );
    assert_eq!(
        endpoint_hint_refresh_participant(
            Some("network-a"),
            &recipients,
            &roster_peer,
            "network-b",
            &capabilities,
        ),
        None
    );
    assert_eq!(
        endpoint_hint_refresh_participant(
            Some("network-a"),
            &recipients,
            &other_peer,
            "network-a",
            &capabilities,
        ),
        None
    );
    assert_eq!(
        endpoint_hint_refresh_participant(
            Some("network-a"),
            &recipients,
            &roster_peer,
            "network-a",
            &PeerCapabilities::default(),
        ),
        None
    );
}

#[cfg(feature = "paid-exit")]
#[test]
fn fips_tunnel_config_carries_paid_route_payment_streaming_inputs() {
    let own = Keys::generate();
    let own_pubkey = own.public_key().to_hex();
    let mut app = AppConfig::generated();
    let network_id = app.networks[0].network_id.clone();
    app.node.tunnel_ip = "10.44.1.1/32".to_string();
    app.nostr.secret_key = own.secret_key().to_bech32().expect("own nsec");
    app.nostr.public_key = own_pubkey.clone();
    app.nostr.relays = vec![
        " wss://relay.example ".to_string(),
        "wss://disabled.example".to_string(),
    ];
    app.nostr.disabled_relays = vec!["wss://disabled.example".to_string()];
    app.paid_exit.enabled = true;
    app.paid_exit.pricing.price_msat_per_gb = 123;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-fips-paid-route-streaming-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");

    let config = fips_tunnel_config_from_app(crate::FipsTunnelConfigInput {
        app: &app,
        config_path: &config_path,
        network_id: &network_id,
        iface: "utun-test".to_string(),
        underlay_interface: None,
        underlay_interface_mtu: None,
        own_pubkey: Some(&own_pubkey),
        recent_peers: None,
        live_peer_endpoints: &[],
        ethernet_underlay: None,
    })
    .expect("build fips config");

    assert_eq!(
        config.paid_route_store_path,
        paid_route_store_file_path(&config_path)
    );
    assert_eq!(
        config.paid_route_wallet_data_dir,
        paid_exit_wallet_data_dir(&config_path)
    );
    assert_eq!(
        config.paid_route_payment_relays,
        vec!["wss://relay.example".to_string()]
    );
    assert_eq!(config.paid_exit.pricing.price_msat_per_gb, 123);
    assert_eq!(config.identity_nsec, app.nostr.secret_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_nonzero_pid_rejects_zero_and_invalid_values() {
    assert_eq!(parse_nonzero_pid("4242"), Some(4242));
    assert_eq!(parse_nonzero_pid("0"), None);
    assert_eq!(parse_nonzero_pid("not-a-number"), None);
}

#[test]
fn wall_time_jump_detection_flags_sleep_resume_after_threshold() {
    assert!(!wall_time_jump_detected(
        0,
        1_000,
        0,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS
    ));
    assert!(!wall_time_jump_detected(
        1_000,
        1_000 + MAJOR_LINK_CHANGE_TIME_JUMP_SECS - 1,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS - 1,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
    ));
    assert!(wall_time_jump_detected(
        1_000,
        1_000 + MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
        0,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
    ));
}

#[test]
fn wall_time_jump_detection_does_not_treat_runtime_stalls_as_sleep() {
    assert!(!wall_time_jump_detected(
        1_000,
        1_000 + MAJOR_LINK_CHANGE_TIME_JUMP_SECS + 5,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS + 5,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
    ));
    assert!(wall_time_jump_detected(
        1_000,
        900,
        5,
        MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
    ));
}

#[test]
fn fips_link_events_preserve_sessions_across_network_handoffs() {
    assert_eq!(
        fips_link_event_refresh(false, true, false, false, false),
        FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
    );
}

#[test]
fn fips_link_events_restart_endpoint_after_sleep() {
    assert_eq!(
        fips_link_event_refresh(false, false, false, false, true),
        FipsLinkEventRefresh::RestartEndpoint
    );
}
#[test]
fn fips_link_events_refresh_paths_for_endpoint_only_changes() {
    assert_eq!(
        fips_link_event_refresh(false, false, false, true, false),
        FipsLinkEventRefresh::UpdatePeersAndRefreshPaths
    );
    assert_eq!(
        fips_link_event_refresh(false, false, false, false, false),
        FipsLinkEventRefresh::None
    );
}
#[test]
fn fips_link_events_ignore_route_notifications_without_state_change() {
    assert_eq!(
        fips_link_event_refresh(true, false, false, false, false),
        FipsLinkEventRefresh::None
    );
}
#[path = "runtime_misc/stale_participant_recovery.rs"]
mod stale_participant_recovery;

#[test]
fn fips_endpoint_failures_requiring_runtime_replacement_are_classified() {
    for endpoint_error in [
        fips_endpoint::FipsEndpointError::Timeout {
            operation: "peer path refresh",
        },
        fips_endpoint::FipsEndpointError::Closed,
    ] {
        let error = anyhow::Error::new(endpoint_error)
            .context("fips: refresh_peer_paths rejected by endpoint");
        assert!(fips_endpoint_control_requires_runtime_replacement(&error));
    }
}

#[test]
fn fips_endpoint_node_errors_do_not_replace_runtime() {
    for node_error in [
        fips_core::NodeError::NotStarted,
        fips_core::NodeError::LocalRouteUnavailable(
            "bound UDP address disappeared after network change".to_string(),
        ),
    ] {
        let error = anyhow::Error::new(fips_endpoint::FipsEndpointError::Node(node_error))
            .context("fips: refresh_peer_paths rejected by endpoint");
        assert!(!fips_endpoint_control_requires_runtime_replacement(&error));
    }
}

fn pending_fips_peer(pubkey: &str) -> MeshPeerStatus {
    MeshPeerStatus {
        pubkey: pubkey.to_string(),
        connected: false,
        endpoint_npub: format!("npub1{pubkey}"),
        transport_addr: None,
        transport_type: None,
        srtt_ms: None,
        srtt_age_ms: None,
        link_packets_sent: 0,
        link_packets_recv: 0,
        link_bytes_sent: 0,
        link_bytes_recv: 0,
        rekey_in_progress: false,
        rekey_draining: false,
        current_k_bit: None,
        last_outbound_route: None,
        direct_probe_pending: true,
        direct_probe_after_ms: Some(1_234),
        direct_probe_retry_count: 4,
        direct_probe_auto_reconnect: true,
        direct_probe_expires_at_ms: Some(5_678),
        nostr_traversal_consecutive_failures: 1,
        nostr_traversal_in_cooldown: false,
        nostr_traversal_cooldown_until_ms: None,
        nostr_traversal_last_observed_skew_ms: None,
        last_seen_at: None,
        last_control_seen_at: None,
        last_data_seen_at: None,
        tx_bytes: 1024,
        rx_bytes: 0,
        error: Some("fips link pending".to_string()),
    }
}
fn connected_relay() -> DaemonRelayState {
    DaemonRelayState {
        url: "wss://relay.example".to_string(),
        status: "connected".to_string(),
    }
}
fn roster_pubkeys(values: &[&str]) -> HashSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
#[test]
fn fips_pending_roster_recovery_waits_for_grace_and_cooldown() {
    let peers = vec![pending_fips_peer("a"), pending_fips_peer("b")];
    let relays = vec![connected_relay()];
    let roster = roster_pubkeys(&["a", "b"]);
    let mut state = FipsPendingRosterRestartState::default();
    let start = 10_000;

    assert!(!fips_pending_roster_restart_due(
        &peers, &relays, &roster, 2, &mut state, start
    ));
    assert!(!fips_pending_roster_restart_due(
        &peers,
        &relays,
        &roster,
        2,
        &mut state,
        start + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS - 1
    ));
    assert!(fips_pending_roster_restart_due(
        &peers,
        &relays,
        &roster,
        2,
        &mut state,
        start + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS
    ));
    assert!(!fips_pending_roster_restart_due(
        &peers,
        &relays,
        &roster,
        2,
        &mut state,
        start + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS + 1
    ));
}
#[test]
fn fips_pending_roster_recovery_requires_connected_relay_and_all_pending() {
    let mut state = FipsPendingRosterRestartState::default();
    let disconnected_relay = DaemonRelayState {
        url: "wss://relay.example".to_string(),
        status: "disconnected".to_string(),
    };
    let peers = vec![pending_fips_peer("a"), pending_fips_peer("b")];
    let roster = roster_pubkeys(&["a", "b"]);

    assert!(!fips_pending_roster_restart_due(
        &peers,
        &[disconnected_relay],
        &roster,
        2,
        &mut state,
        10_000 + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS
    ));

    let mut partly_connected = peers.clone();
    partly_connected[0].connected = true;
    partly_connected[0].error = None;
    assert!(!fips_pending_roster_restart_due(
        &partly_connected,
        &[connected_relay()],
        &roster,
        2,
        &mut state,
        20_000
    ));

    let one_peer_missing_from_snapshot = vec![pending_fips_peer("a")];
    assert!(!fips_pending_roster_restart_due(
        &one_peer_missing_from_snapshot,
        &[connected_relay()],
        &roster,
        2,
        &mut state,
        30_000 + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS
    ));
}
#[test]
fn fips_pending_roster_recovery_ignores_connected_non_roster_transit() {
    let mut peers = vec![pending_fips_peer("a"), pending_fips_peer("b")];
    let mut transit = pending_fips_peer("transit");
    transit.connected = true;
    transit.error = None;
    transit.last_seen_at = Some(10_000);
    peers.push(transit);

    let relays = vec![connected_relay()];
    let roster = roster_pubkeys(&["a", "b"]);
    let mut state = FipsPendingRosterRestartState::default();
    let start = 40_000;

    assert!(!fips_pending_roster_restart_due(
        &peers, &relays, &roster, 2, &mut state, start
    ));
    assert!(fips_pending_roster_restart_due(
        &peers,
        &relays,
        &roster,
        2,
        &mut state,
        start + FIPS_PENDING_ROSTER_RESTART_GRACE_SECS
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn runtime_exit_node_routes_do_not_advertise_ipv6_default() {
    let mut app = AppConfig::generated();
    app.node.advertise_exit_node = true;

    assert_eq!(runtime_exit_node_default_routes(), vec!["0.0.0.0/0"]);
    assert_eq!(runtime_effective_advertised_routes(&app), vec!["0.0.0.0/0"]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_host_forwarding_does_not_advertise_free_exit_route() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;

    assert!(runtime_effective_advertised_routes(&app).is_empty());
    assert_eq!(
        runtime_local_exit_forwarding_routes(&app),
        vec!["0.0.0.0/0"]
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_forwarding_ignores_removed_legacy_ip_support_knobs() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.paid_exit.ip_support.ipv4 = false;
    app.paid_exit.ip_support.ipv6 = true;

    assert_eq!(
        runtime_local_exit_forwarding_routes(&app),
        vec!["0.0.0.0/0"]
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_forwarding_rejects_paid_on_paid_resale() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.set_internet_source(InternetSource::PaidAutomatic);

    assert!(runtime_local_exit_forwarding_routes(&app).is_empty());
}

#[test]
fn legacy_macos_exit_cleanup_leaves_global_ipv4_forwarding_alone() {
    let mut app = AppConfig::generated();
    app.node.advertise_exit_node = true;

    let plan = legacy_macos_exit_cleanup_plan(&runtime_effective_advertised_routes(&app));

    assert!(plan.cleanup_pf_nat);
    assert!(!plan.restore_ipv4_forwarding);
}

#[cfg(target_os = "macos")]
#[test]
fn legacy_macos_cleanup_journal_does_not_claim_ownerless_endpoint_routes() {
    let state: MacosNetworkCleanupState = serde_json::from_str(
        r#"{
            "iface": "utun42",
            "endpoint_bypass_routes": ["203.0.113.7/32"],
            "original_default_route": {
                "gateway": "192.0.2.1",
                "interface": "en0"
            }
        }"#,
    )
    .expect("deserialize pre-ownership cleanup journal");

    let actionable = crate::daemon_runtime::macos_cleanup_managed_routes(&state);

    assert!(
        actionable
            .iter()
            .all(|route| route.target != "203.0.113.7/32"),
        "an ownerless legacy endpoint route is non-actionable migration data"
    );
    assert_eq!(
        actionable,
        vec![
            MacosManagedRoute {
                target: "0.0.0.0/1".to_string(),
                gateway: None,
                interface: Some("utun42".to_string()),
            },
            MacosManagedRoute {
                target: "128.0.0.0/1".to_string(),
                gateway: None,
                interface: Some("utun42".to_string()),
            },
        ],
        "exact legacy tunnel ownership remains actionable"
    );
}

#[test]
fn macos_exit_node_pf_rules_are_scoped_to_tunnel_source_and_outbound_iface() {
    let rules = crate::macos_network::macos_exit_node_pf_rules("utun42", "en0", "10.44.0.0/16");

    assert_eq!(
        rules,
        concat!(
            "nat on en0 inet from 10.44.0.0/16 to any -> (en0)\n",
            "pass in quick on utun42 inet from 10.44.0.0/16 to any keep state\n",
            "pass out quick on en0 inet from 10.44.0.0/16 to any keep state\n",
        )
    );
    assert!(!rules.contains("net.inet.ip.forwarding"));
    assert!(!rules.contains("pass in quick on en0"));
}

#[test]
fn macos_ipv4_forwarding_state_parser_accepts_only_kernel_boolean_values() {
    assert!(!crate::parse_macos_ipv4_forwarding_state("0\n").expect("disabled state"));
    assert!(crate::parse_macos_ipv4_forwarding_state("1\n").expect("enabled state"));
    assert!(crate::parse_macos_ipv4_forwarding_state("2\n").is_err());
    assert!(crate::parse_macos_ipv4_forwarding_state("").is_err());
}

#[test]
fn macos_pf_state_parser_accepts_pfctl_status_details() {
    assert!(
        crate::parse_macos_pf_enabled("Status: Enabled for 2 days 01:02:03\n")
            .expect("enabled state")
    );
    assert!(!crate::parse_macos_pf_enabled("Status: Disabled\n").expect("disabled state"));
    assert!(crate::parse_macos_pf_enabled("Status: Unknown\n").is_err());
    assert!(crate::parse_macos_pf_enabled("").is_err());
}

#[test]
fn macos_exit_node_cleanup_flushes_only_nvpn_anchor() {
    let args = crate::macos_network::macos_pf_anchor_flush_args();
    assert_eq!(args, vec!["-a", "com.apple/nostrvpn-exit", "-F", "all"]);
    assert_eq!(args[1].matches('/').count(), 1);
}
