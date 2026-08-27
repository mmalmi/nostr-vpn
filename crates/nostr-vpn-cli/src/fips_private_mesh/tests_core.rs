    use super::{
        FIPS_DISCOVERY_BACKOFF_BASE_SECS, FIPS_DISCOVERY_BACKOFF_MAX_SECS,
        FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY, FIPS_ENDPOINT_FAST_LINK_DEAD_TIMEOUT_SECS,
        FIPS_ENDPOINT_HEARTBEAT_INTERVAL_SECS,
        FIPS_ENDPOINT_LINK_DEAD_TIMEOUT_SECS, FIPS_ENDPOINT_PENDING_PACKETS_PER_DEST,
        FIPS_ENDPOINT_REKEY_AFTER_SECS, FIPS_ENDPOINT_SESSION_IDLE_TIMEOUT_SECS,
        FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS, FIPS_LAN_DISCOVERY_SCOPE_PREFIX,
        FIPS_MESH_EVENT_DRAIN_LIMIT,
        FIPS_NOSTR_EXTENDED_COOLDOWN_SECS, FIPS_NOSTR_FAILURE_STREAK_THRESHOLD,
        FIPS_NOSTR_EXIT_OPEN_DISCOVERY_MAX_PENDING, FIPS_NOSTR_OPEN_DISCOVERY_MAX_PENDING,
        FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS,
        FIPS_PUBLIC_WEBSOCKET_IDLE_TIMEOUT_SECS,
        FIPS_PUBLIC_WEBSOCKET_MAX_CONNECTIONS,
        FIPS_PUBLIC_WEBSOCKET_MAX_INBOUND_CONNECTIONS,
        FIPS_RECONNECT_BACKOFF_BASE_SECS, FIPS_RECONNECT_BACKOFF_MAX_SECS,
        FIPS_RECENT_NON_ROSTER_TRANSIT_MAX_SEEDS,
        FIPS_STATIC_NON_ROSTER_TRANSIT_MAX_SEEDS,
        FIPS_UDP_IPV4_TRANSPORT, FIPS_UDP_IPV6_TRANSPORT,
        FIPS_WEBSOCKET_LISTENER_OPEN_DISCOVERY_MAX_PENDING,
        FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY, FipsEndpointPeerTransportConfig,
        FipsEndpointTransportConfig, FipsPeerActivity,
        FipsPeerActivitySnapshot, FipsPeerAddressHint, FipsPeerIdentityMap, FipsPeerRxKind,
        FipsPrivateMeshEvent,
        FipsPrivateMeshRuntime, FipsPrivateTunnelConfig, Ipv4Subnet,
        control_frame_destination_peer, control_frame_source_pubkey, decode_endpoint_control_frame,
        drain_event_batch,
        endpoint_peers_with_changed_addresses,
        endpoint_identity_for_send,
        filter_stamped_tunnel_endpoints, filter_static_tunnel_endpoints_with_policy,
        filter_static_tunnel_endpoints_with_policy_and_route_check,
        fips_endpoint_config_with_open_discovery_limit, fips_endpoint_peers_from_mesh,
        fips_exit_route_ready_for_connected, fips_lan_discovery_scope, fips_peer_address_from_hint,
        fips_tunnel_requires_endpoint_restart, linux_cap_eff_has_net_admin,
        linux_private_ipv4_route_subnets_from_ip_route,
        linux_route_get_has_direct_private_endpoint_route, linux_tun_setup_error,
        macos_endpoint_bypass_underlay_refresh_required,
        macos_private_ipv4_route_subnets_from_netstat,
        macos_route_get_has_direct_private_endpoint_route, mesh_status_from_endpoint_peer,
        other_endpoint_peer_statuses, parse_fips_nostr_discovery_policy,
        parse_linux_tun_tx_queue_len, participant_pubkey_bytes, peer_activity_map, peer_identity_map,
        prioritize_fips_control_peer,
        static_endpoint_allowed_on_current_underlay_with_route_check, strip_cidr, unix_timestamp,
    };
    #[cfg(feature = "paid-exit")]
    use super::FIPS_NOSTR_PAID_EXIT_OPEN_DISCOVERY_MAX_PENDING;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{
        BorrowedTunFd, TunPipelinePacket, raw_write_packet_to_tun,
        tun_pipeline_packet_targets_fips_host,
    };
    use super::{
        linux_endpoint_bypass_hosts_unchanged, linux_interface_state_matches_json,
        linux_ipv4_underlay_capture_requested, linux_ipv4_underlay_restore_due,
        linux_missing_ipv4_underlay_route_allowed, linux_reuse_cached_underlay_route,
        linux_strict_exit_requested,
        linux_withhold_default_route_for_missing_peer_endpoint,
    };
    #[cfg(target_os = "linux")]
    use super::LINUX_VIRTIO_NET_HDR_LEN;
    use fips_endpoint::{
        Config, ConnectPolicy, FipsEndpointData, FipsEndpointDirectPacketRun, FipsEndpointMessage,
        FipsEndpointPeer, NodeAddr, NostrDiscoveryPolicy, PeerConfig as FipsPeerConfig,
        PeerIdentity, RoutingMode, TransportInstances, UdpConfig,
    };
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::{
        AppConfig, ExitDnsResolverConfig, InternetSource, PendingOutboundJoinRequest,
        derive_mesh_tunnel_ip,
    };
    use nostr_vpn_core::fips_control::{
        FipsControlFrame, JoinRosterControl, NetworkRoster, PeerEndpointHint, SignedRoster,
        encode_fips_control_frame,
    };
    use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
    use nostr_vpn_core::join_requests::{MeshJoinRequest, prepare_manual_join_delivery};
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    use std::time::Duration;

    const FIPS_NOSTR_DISCOVERY_APP: &str = "fips-overlay-v1";

    fn recent_peer_cache(local_keys: &Keys, network_id: &str) -> nostr_vpn_core::recent_peers::RecentPeerEndpoints {
        let local_npub = local_keys.public_key().to_bech32().expect("local npub");
        nostr_vpn_core::recent_peers::RecentPeerEndpoints::new(
            local_npub,
            nostr_vpn_core::recent_peers::recent_peers_scope(network_id),
        )
        .expect("recent peers cache")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn only_fips_ipv6_destinations_use_the_integrated_host_pipeline() {
        let fips = TunPipelinePacket::from_destination(
            vec![0x60; 40],
            Some("fd12:3456::1".parse().unwrap()),
        );
        let other_ula = TunPipelinePacket::from_destination(
            vec![0x60; 40],
            Some("fc12:3456::1".parse().unwrap()),
        );
        let mesh = TunPipelinePacket::from_destination(
            vec![0x45; 20],
            Some("10.44.0.2".parse().unwrap()),
        );

        assert!(tun_pipeline_packet_targets_fips_host(&fips));
        assert!(!tun_pipeline_packet_targets_fips_host(&other_ula));
        assert!(!tun_pipeline_packet_targets_fips_host(&mesh));
    }

    #[test]
    fn unchanged_linux_endpoint_bypass_hosts_skip_route_reconciliation() {
        let current = vec![
            "198.51.100.7/32".to_string(),
            "203.0.113.8/32".to_string(),
        ];
        let same_hosts = vec![
            "203.0.113.8".parse().unwrap(),
            "198.51.100.7".parse().unwrap(),
            "203.0.113.8".parse().unwrap(),
        ];
        let changed_hosts = vec![
            "198.51.100.7".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        ];

        assert!(linux_endpoint_bypass_hosts_unchanged(&current, &same_hosts));
        assert!(!linux_endpoint_bypass_hosts_unchanged(
            &current,
            &changed_hosts,
        ));
    }

    #[test]
    fn ethernet_fips_underlay_does_not_need_an_ip_endpoint_bypass() {
        let routes = vec!["0.0.0.0/0".to_string()];
        let no_hosts = Vec::<Ipv4Addr>::new();

        assert!(linux_withhold_default_route_for_missing_peer_endpoint(
            &routes,
            &no_hosts,
            false,
        ));
        assert!(!linux_withhold_default_route_for_missing_peer_endpoint(
            &routes,
            &no_hosts,
            true,
        ));
        assert!(!linux_withhold_default_route_for_missing_peer_endpoint(
            &routes,
            &["198.51.100.7".parse().unwrap()],
            false,
        ));
    }

    #[test]
    fn ethernet_fips_underlay_allows_an_absent_ip_default_route() {
        assert!(linux_missing_ipv4_underlay_route_allowed(true, false));
        assert!(!linux_missing_ipv4_underlay_route_allowed(false, false));
        assert!(!linux_missing_ipv4_underlay_route_allowed(true, true));
    }

    #[test]
    fn ethernet_fips_underlay_reuses_its_cached_default_after_exit_activation() {
        let cached = "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10";
        let mut cleanup_route = None;

        assert!(linux_reuse_cached_underlay_route(
            &mut cleanup_route,
            Some(cached),
            "eth0",
        ));
        assert_eq!(cleanup_route.as_deref(), Some(cached));
        assert!(!linux_reuse_cached_underlay_route(
            &mut cleanup_route,
            Some(cached),
            "eth1",
        ));
        assert!(!linux_reuse_cached_underlay_route(
            &mut cleanup_route,
            None,
            "eth0",
        ));
    }

    #[test]
    fn unchanged_macos_endpoint_bypasses_reuse_cached_underlay() {
        let routes = vec!["198.51.100.7".to_string(), "203.0.113.8".to_string()];
        let underlay = crate::MacosRouteSpec {
            gateway: Some("192.0.2.1".to_string()),
            interface: "en0".to_string(),
        };

        assert!(!macos_endpoint_bypass_underlay_refresh_required(
            &routes,
            Some(&underlay),
            &routes,
            true,
        ));
        assert!(macos_endpoint_bypass_underlay_refresh_required(
            &routes, None, &routes, true,
        ));
        assert!(macos_endpoint_bypass_underlay_refresh_required(
            &routes,
            Some(&underlay),
            &["198.51.100.9".to_string()],
            true,
        ));
        assert!(macos_endpoint_bypass_underlay_refresh_required(
            &routes,
            Some(&underlay),
            &routes,
            false,
        ));
    }

    #[test]
    fn adding_authenticated_endpoint_address_forces_an_immediate_path_refresh() {
        let npub = Keys::generate().public_key().to_bech32().unwrap();
        let previous = vec![FipsEndpointPeerTransportConfig {
            npub: npub.clone(),
            addresses: Vec::new(),
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: false,
        }];
        let updated = vec![FipsEndpointPeerTransportConfig {
            npub,
            addresses: vec![FipsPeerAddressHint {
                addr: "185.18.221.232:2122".to_string(),
                seen_at_ms: None,
                priority: FIPS_CONFIGURED_PEER_ENDPOINT_PRIORITY,
            }],
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: false,
        }];

        assert_eq!(
            endpoint_peers_with_changed_addresses(&previous, &updated),
            updated
        );
        assert!(endpoint_peers_with_changed_addresses(&updated, &updated).is_empty());
    }

    #[test]
    fn non_strict_exit_route_only_activates_for_the_connected_selected_peer() {
        let selected = Keys::generate().public_key().to_hex();
        let unrelated = Keys::generate().public_key().to_hex();
        let peers = vec![FipsMeshPeerConfig::from_participant_pubkey(
            &selected,
            vec!["0.0.0.0/0".to_string()],
        )
        .expect("selected exit peer")];
        let routes = vec!["0.0.0.0/0".to_string()];

        assert!(!fips_exit_route_ready_for_connected(
            &routes,
            &peers,
            false,
            false,
            false,
            &HashSet::new(),
        ));
        assert!(!fips_exit_route_ready_for_connected(
            &routes,
            &peers,
            false,
            false,
            false,
            &HashSet::from([unrelated.as_str()]),
        ));
        assert!(!fips_exit_route_ready_for_connected(
            &routes,
            &peers,
            false,
            false,
            true,
            &HashSet::from([selected.as_str()]),
        ));
        assert!(fips_exit_route_ready_for_connected(
            &routes,
            &peers,
            false,
            false,
            false,
            &HashSet::from([selected.as_str()]),
        ));
        assert!(fips_exit_route_ready_for_connected(
            &routes,
            &peers,
            true,
            false,
            true,
            &HashSet::new(),
        ));
    }

    #[test]
    fn unchanged_linux_control_interface_state_skips_network_mutation() {
        let state = r#"[
            {
                "ifname": "nvpn-fips",
                "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
                "mtu": 1150,
                "txqlen": 4096,
                "addr_info": [
                    {"family": "inet", "local": "10.44.1.7", "prefixlen": 32},
                    {"family": "inet6", "local": "fd00::7", "prefixlen": 128},
                    {"family": "inet6", "local": "fe80::7", "prefixlen": 64}
                ]
            }
        ]"#;
        let addresses = vec!["10.44.1.7/32".to_string(), "fd00::7/128".to_string()];

        assert!(linux_interface_state_matches_json(
            state,
            &addresses,
            1150,
            Some(4096),
        ));
    }

    #[test]
    fn linux_leak_protection_is_strict_only_when_an_exit_is_requested() {
        assert!(!linux_strict_exit_requested(&[], true));
        assert!(!linux_strict_exit_requested(
            &["10.0.0.0/8".to_string()],
            true,
        ));
        assert!(linux_strict_exit_requested(
            &["0.0.0.0/0".to_string()],
            true,
        ));
        assert!(linux_strict_exit_requested(
            &["::/0".to_string()],
            true,
        ));
        assert!(!linux_strict_exit_requested(
            &["0.0.0.0/0".to_string()],
            false,
        ));
    }

    #[test]
    fn linux_wireguard_only_exit_keeps_underlay_capture_active() {
        assert!(linux_ipv4_underlay_capture_requested(&[], true));
        assert!(!linux_ipv4_underlay_restore_due(true, false, true, false));
        assert!(linux_ipv4_underlay_capture_requested(
            &["0.0.0.0/0".to_string()],
            false,
        ));
        assert!(linux_ipv4_underlay_restore_due(true, false, false, false));
        assert!(!linux_ipv4_underlay_capture_requested(&[], false));
    }

    #[test]
    fn changed_linux_control_interface_state_requires_restoration() {
        let base = r#"[
            {
                "ifname": "nvpn-fips",
                "flags": ["POINTOPOINT", "NOARP", "UP"],
                "mtu": 1150,
                "txqlen": 4096,
                "addr_info": [
                    {"family": "inet", "local": "10.44.1.7", "prefixlen": 32}
                ]
            }
        ]"#;
        let addresses = vec!["10.44.1.7/32".to_string()];

        assert!(!linux_interface_state_matches_json(
            base,
            &["10.44.1.8/32".to_string()],
            1150,
            Some(4096),
        ));
        assert!(!linux_interface_state_matches_json(
            base,
            &addresses,
            1280,
            Some(4096),
        ));
        assert!(!linux_interface_state_matches_json(
            base,
            &addresses,
            1150,
            Some(1024),
        ));
        assert!(!linux_interface_state_matches_json(
            &base.replace("\"UP\"", "\"DOWN\""),
            &addresses,
            1150,
            Some(4096),
        ));
        assert!(!linux_interface_state_matches_json(
            "not-json",
            &addresses,
            1150,
            Some(4096),
        ));
        assert!(!linux_interface_state_matches_json(
            base,
            &["10.44.1.7/99".to_string()],
            1150,
            Some(4096),
        ));
        assert!(!linux_interface_state_matches_json(
            &base.replace(
                r#"{"family": "inet", "local": "10.44.1.7", "prefixlen": 32}"#,
                r#"{"family": "inet", "local": "10.44.0.1", "prefixlen": 32},
                    {"family": "inet", "local": "10.44.1.7", "prefixlen": 32}"#,
            ),
            &addresses,
            1150,
            Some(4096),
        ));
    }

    fn send_tunnel_packet_batch_owned_with_capacity(
        runtime: &FipsPrivateMeshRuntime,
        packets: Vec<Vec<u8>>,
        turn_capacity: usize,
    ) -> anyhow::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let input_packets = packets.len();
        let mesh = runtime.mesh.load();
        let peer_identities = runtime.peer_identities.load();
        let mut runs = Vec::new();
        let mut routed_packets = 0usize;

        {
            let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshRoute);
            for packet in packets {
                let Some(outgoing) = mesh.route_outbound_packet_owned_with_peer(packet) else {
                    continue;
                };
                routed_packets += 1;
                let participant_key = outgoing.participant_pubkey_bytes.copied();
                #[cfg(feature = "paid-exit")]
                runtime.note_paid_route_outbound_packet(
                    Some(outgoing.participant_pubkey),
                    outgoing.participant_pubkey_bytes,
                    &outgoing.bytes,
                )?;
                FipsPrivateMeshRuntime::push_endpoint_send_run(
                    &mut runs,
                    &peer_identities,
                    outgoing.participant_pubkey,
                    participant_key,
                    outgoing.endpoint_node_addr,
                    outgoing.bytes,
                );
            }
        }
        drop(peer_identities);
        drop(mesh);

        crate::pipeline_profile::record_mesh_send_batch(
            input_packets,
            routed_packets,
            runs.len(),
            turn_capacity,
        );

        let _t =
            crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshEndpointSend);
        runtime.blocking_send_endpoint_send_runs(runs)
    }

    async fn recv_mesh_event_batch_into(
        runtime: &FipsPrivateMeshRuntime,
        messages: &mut Vec<FipsEndpointMessage>,
        events: &mut Vec<FipsPrivateMeshEvent>,
        limit: usize,
    ) -> anyhow::Result<Option<usize>> {
        let limit = limit.clamp(1, FIPS_MESH_EVENT_DRAIN_LIMIT);
        events.clear();
        loop {
            if drain_direct_endpoint_mesh_events_into(runtime, events).await? > 0 {
                return Ok(Some(events.len()));
            }

            let Some(_) = (match tokio::time::timeout(
                Duration::from_millis(10),
                runtime.endpoint.recv_batch_into(messages, limit),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => continue,
            }) else {
                return Ok(None);
            };

            let now = Some(unix_timestamp());
            events.reserve(messages.len());
            for message in messages.drain(..) {
                if let Some(event) = endpoint_message_to_mesh_event(runtime, message, now).await? {
                    events.push(event);
                }
            }
            if !events.is_empty() {
                return Ok(Some(events.len()));
            }
        }
    }

    async fn endpoint_message_to_mesh_event(
        runtime: &FipsPrivateMeshRuntime,
        message: FipsEndpointMessage,
        now: Option<u64>,
    ) -> anyhow::Result<Option<FipsPrivateMeshEvent>> {
        let outcome = runtime.endpoint_message_to_mesh_event_outcome(message, now)?;
        if let Some(reply) = outcome.reply
            && let Err(error) = runtime
                .endpoint
                .send_batch_to_peer(reply.peer, vec![reply.data])
                .await
        {
            eprintln!("fips: failed to reply to peer ping: {error}");
        }
        Ok(outcome.event)
    }

    async fn drain_direct_endpoint_mesh_events_into(
        runtime: &FipsPrivateMeshRuntime,
        events: &mut Vec<FipsPrivateMeshEvent>,
    ) -> anyhow::Result<usize> {
        let initial_len = events.len();
        let runs = match runtime
            .direct_endpoint_rx
            .try_recv(FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS)
        {
            Ok(runs) => runs,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(0),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(0),
        };
        direct_endpoint_packet_runs_to_mesh_events(
            runtime,
            runs,
            Some(unix_timestamp()),
            events,
        )
        .await?;

        Ok(events.len().saturating_sub(initial_len))
    }

    async fn direct_endpoint_packet_runs_to_mesh_events(
        runtime: &FipsPrivateMeshRuntime,
        runs: Vec<FipsEndpointDirectPacketRun>,
        now: Option<u64>,
        events: &mut Vec<FipsPrivateMeshEvent>,
    ) -> anyhow::Result<()> {
        for run in runs {
            let source_peer = *run.source_peer();
            let enqueued_at_ms = run.enqueued_at_ms();
            for packet in run.packet_slices() {
                let message = FipsEndpointMessage {
                    source_peer,
                    data: FipsEndpointData::new(packet.to_vec()),
                    enqueued_at_ms,
                };
                if let Some(event) = endpoint_message_to_mesh_event(runtime, message, now).await? {
                    events.push(event);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn macos_udp_send_buffer_derives_release_defaults() {
        assert_eq!(super::macos_default_udp_send_buf_size(), 256 * 1024);
        #[cfg(target_os = "macos")]
        {
            assert_eq!(super::DEFAULT_FIPS_UDP_SEND_BUF_SIZE, Some(256 * 1024));
        }
    }

    #[test]
    fn linux_tun_tx_queue_len_env_keeps_bounded_default() {
        assert_eq!(parse_linux_tun_tx_queue_len(None, 4096), Some(4096));
        assert_eq!(parse_linux_tun_tx_queue_len(Some(""), 4096), Some(4096));
        assert_eq!(parse_linux_tun_tx_queue_len(Some("500"), 4096), Some(500));
        assert_eq!(parse_linux_tun_tx_queue_len(Some("1"), 4096), Some(64));
        assert_eq!(
            parse_linux_tun_tx_queue_len(Some("999999"), 4096),
            Some(65_536)
        );
        assert_eq!(parse_linux_tun_tx_queue_len(Some("0"), 4096), None);
        assert_eq!(parse_linux_tun_tx_queue_len(Some("off"), 4096), None);
        assert_eq!(parse_linux_tun_tx_queue_len(Some("no"), 4096), None);
    }

    #[test]
    fn parses_fips_nostr_discovery_policy_override() {
        for (raw, expected) in [
            ("configured-only", NostrDiscoveryPolicy::ConfiguredOnly),
            ("configured_only", NostrDiscoveryPolicy::ConfiguredOnly),
            ("open", NostrDiscoveryPolicy::Open),
            ("disabled", NostrDiscoveryPolicy::Disabled),
        ] {
            assert_eq!(parse_fips_nostr_discovery_policy(raw), Some(expected));
        }
        assert_eq!(parse_fips_nostr_discovery_policy("wat"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn raw_tun_write_keeps_fd_open_and_writes_platform_frame() {
        let mut pipe_fds = [0; 2];
        let pipe_result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe should open");
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        let packet = [0x45, 0, 0, 20, 1, 2, 3, 4];
        let tun_fd = BorrowedTunFd::new(write_fd);
        raw_write_packet_to_tun(&tun_fd, &packet, 2).expect("write packet frame");
        raw_write_packet_to_tun(&tun_fd, &packet, 2).expect("fd should remain writable");

        let expected_frame: Vec<u8> = {
            #[cfg(target_os = "macos")]
            {
                let mut frame = vec![0, 0, 0, 2];
                frame.extend_from_slice(&packet);
                frame
            }
            #[cfg(target_os = "linux")]
            {
                let mut frame = vec![0; LINUX_VIRTIO_NET_HDR_LEN];
                frame.extend_from_slice(&packet);
                frame
            }
        };
        let mut expected = expected_frame.clone();
        expected.extend_from_slice(&expected_frame);

        let mut read_buf = vec![0_u8; expected.len()];
        let read = unsafe {
            libc::read(
                read_fd,
                read_buf.as_mut_ptr().cast::<libc::c_void>(),
                read_buf.len(),
            )
        };

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        assert_eq!(read as usize, expected.len());
        assert_eq!(read_buf, expected);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn blocking_tun_write_keeps_fd_open_and_writes_platform_frame() {
        let mut pipe_fds = [0; 2];
        let pipe_result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(pipe_result, 0, "pipe should open");
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        let stop = std::sync::atomic::AtomicBool::new(false);
        let packet = [0x45, 0, 0, 20, 1, 2, 3, 4];
        let tun_fd = BorrowedTunFd::new(write_fd);
        super::write_packet_to_tun_blocking(tun_fd, &packet, &stop);
        super::write_packet_to_tun_blocking(tun_fd, &packet, &stop);

        let expected_frame: Vec<u8> = {
            #[cfg(target_os = "macos")]
            {
                let mut frame = vec![0, 0, 0, 2];
                frame.extend_from_slice(&packet);
                frame
            }
            #[cfg(target_os = "linux")]
            {
                let mut frame = vec![0; LINUX_VIRTIO_NET_HDR_LEN];
                frame.extend_from_slice(&packet);
                frame
            }
        };
        let mut expected = expected_frame.clone();
        expected.extend_from_slice(&expected_frame);

        let mut read_buf = vec![0_u8; expected.len()];
        let read = unsafe {
            libc::read(
                read_fd,
                read_buf.as_mut_ptr().cast::<libc::c_void>(),
                read_buf.len(),
            )
        };

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        assert_eq!(read as usize, expected.len());
        assert_eq!(read_buf, expected);
    }
    include!("tests_core/runtime.rs");
    include!("tests_core/send_identity.rs");
