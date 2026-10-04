    use super::*;
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::serialize::binary::{BinEncodable as _, BinEncoder};
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::{NetworkConfig, PendingOutboundJoinRequest};

    fn mobile_app_with_admin(admin_hex: String) -> Arc<RwLock<AppConfig>> {
        let mut app = AppConfig::generated();
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Original".to_string(),
            enabled: true,
            network_id: "mesh".to_string(),
            join_secret: "join-secret".to_string(),
            devices: Vec::new(),
            removed_devices: Vec::new(),
            admins: vec![admin_hex],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        Arc::new(RwLock::new(app))
    }

    fn dns_query(name: &str, query_type: u16) -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            bytes.push(u8::try_from(label.len()).expect("label length fits"));
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&query_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }

    fn fixture_authenticated_dns_response(query: &[u8]) -> Vec<u8> {
        let request = Message::from_vec(query).expect("fixture query");
        let mut response = Message::new(
            request.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.recursion_available = true;
        for query in request.queries {
            response.add_query(query);
        }
        let mut packet = Vec::new();
        response
            .emit(&mut BinEncoder::new(&mut packet))
            .expect("fixture response");
        packet
    }

    struct FixtureSecureDns;

    #[async_trait::async_trait]
    impl SecureDnsLookup for FixtureSecureDns {
        async fn resolve(
            &self,
            query: &[u8],
        ) -> std::result::Result<Vec<u8>, nostr_vpn_core::secure_dns::SecureDnsError> {
            Ok(fixture_authenticated_dns_response(query))
        }
    }

    struct ForwardDependentSecureDns {
        packet_forwarded: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl SecureDnsLookup for ForwardDependentSecureDns {
        async fn resolve(
            &self,
            query: &[u8],
        ) -> std::result::Result<Vec<u8>, nostr_vpn_core::secure_dns::SecureDnsError> {
            self.packet_forwarded.notified().await;
            Ok(fixture_authenticated_dns_response(query))
        }
    }

    fn ipv4_udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let query = MobileDnsQuery {
            source: destination,
            destination: source,
            source_port: destination_port,
            destination_port: source_port,
            payload,
        };
        build_mobile_dns_response_packet(&query, payload).expect("test packet length fits")
    }

    fn test_ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        ipv4_udp_packet(source, destination, 53123, 443, b"mobile-vpn-basic")
    }

    fn test_ipv4_reply(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        ipv4_udp_packet(source, destination, 443, 53123, payload)
    }

    fn test_ipv4_replies(destination: Ipv4Addr) -> (Vec<u8>, Vec<u8>) {
        (
            test_ipv4_reply(Ipv4Addr::new(8, 8, 8, 8), destination, b"reply-one"),
            test_ipv4_reply(Ipv4Addr::new(1, 1, 1, 1), destination, b"reply-two"),
        )
    }

    #[test]
    fn mobile_inbound_roster_requires_signed_event() {
        let admin_hex = Keys::generate().public_key().to_hex();
        let app = mobile_app_with_admin(admin_hex);
        let dirty = AtomicBool::new(false);

        let error = apply_mobile_roster(&app, &dirty, None, None)
            .expect_err("unsigned mobile roster frame must be rejected");

        assert!(
            error.to_string().contains("missing signed roster event"),
            "unexpected error: {error:#}"
        );
        assert!(!dirty.load(Ordering::Relaxed));
    }

    #[test]
    fn mobile_inbound_roster_ignores_non_admin_event_author() {
        let known_admin = Keys::generate();
        let outsider = Keys::generate();
        let member_hex = Keys::generate().public_key().to_hex();
        let known_admin_hex = known_admin.public_key().to_hex();
        let outsider_hex = outsider.public_key().to_hex();
        let app = mobile_app_with_admin(known_admin_hex.clone());
        let dirty = AtomicBool::new(false);
        let signed = SignedRoster::sign(
            "mesh",
            NetworkRoster {
                network_name: "Home".to_string(),
                devices: vec![member_hex],
                admins: vec![known_admin_hex, outsider_hex],
                aliases: HashMap::new(),
                signed_at: 1_726_000_000,
            },
            &outsider,
        )
        .expect("sign roster");

        let updated = apply_mobile_roster(&app, &dirty, None, Some(&signed))
            .expect("valid event from non-admin author should be ignored");

        assert!(updated.is_none());
        assert!(!dirty.load(Ordering::Relaxed));
        assert_eq!(
            app.read()
                .expect("app config")
                .networks
                .first()
                .expect("network")
                .shared_roster_updated_at,
            0
        );
    }

    #[test]
    fn mobile_inbound_roster_applies_event_network_name() {
        let admin = Keys::generate();
        let admin_hex = admin.public_key().to_hex();
        let app = mobile_app_with_admin(admin_hex.clone());
        let dirty = AtomicBool::new(false);
        let signed = SignedRoster::sign(
            "mesh",
            NetworkRoster {
                network_name: "Home Mesh".to_string(),
                devices: Vec::new(),
                admins: vec![admin_hex],
                aliases: std::collections::HashMap::new(),
                signed_at: 1_726_000_000,
            },
            &admin,
        )
        .expect("sign roster");

        let updated = apply_mobile_roster(&app, &dirty, None, Some(&signed))
            .expect("valid admin roster applies");

        assert!(updated.is_some());
        assert!(dirty.load(Ordering::Relaxed));
        let name = app
            .read()
            .expect("app config")
            .networks
            .first()
            .expect("network")
            .name
            .clone();
        assert_eq!(name, "Home Mesh");
    }

    #[test]
    fn mobile_first_join_applies_one_generic_roster_with_the_qr_secret() {
        let now = unix_timestamp();
        let admin = Keys::generate();
        let mut joiner = AppConfig::generated_without_networks();
        joiner
            .ensure_pending_nostr_join_request(now)
            .expect("pending join request");
        let own = joiner.own_nostr_pubkey_hex().expect("joiner pubkey");
        let request_secret = joiner
            .pending_nostr_join_request
            .as_ref()
            .expect("pending request")
            .request
            .request_secret
            .clone();
        let signed = SignedRoster::sign(
            "mobile-mesh",
            NetworkRoster {
                network_name: "Mobile Mesh".to_string(),
                devices: vec![own],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: now,
            },
            &admin,
        )
        .expect("sign ordinary roster");
        let join_roster =
            JoinRosterControl::new(signed, &request_secret).expect("join control record");
        let app = Arc::new(RwLock::new(joiner));
        let dirty = AtomicBool::new(false);

        let updated = apply_mobile_join_roster(&app, &dirty, None, &join_roster)
            .expect("apply first join roster");

        assert!(updated.is_some());
        assert!(dirty.load(Ordering::Relaxed));
        let app = app.read().expect("app config");
        assert!(app.pending_nostr_join_request.is_some());
        assert_eq!(app.active_network().network_id, "mobile-mesh");
    }

    #[test]
    fn mobile_config_stays_split_tunnel_without_exit() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.route_targets.len(), 2);
        assert_eq!(config.peers[0].allowed_ips.len(), 1);
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        );
        let peer_route = config
            .route_targets
            .iter()
            .find(|route| route.as_str() != MESH_TUNNEL_IPV4_CIDR)
            .expect("peer route");
        assert!(peer_route.starts_with("10."));
        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        assert_eq!(
            config.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
        assert_eq!(
            config.magic_dns_server,
            nostr_vpn_core::MESH_MAGIC_DNS_SERVER
        );
        assert_eq!(config.dns_match_domains, vec!["nvpn"]);
    }

    #[test]
    fn mobile_direct_network_without_peers_keeps_private_mesh_route() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "direct-no-peers".to_string(),
            name: "Direct no peers".to_string(),
            enabled: true,
            network_id: "direct-no-peers".to_string(),
            join_secret: "join-secret".to_string(),
            devices: Vec::new(),
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.set_internet_source(nostr_vpn_core::config::InternetSource::Direct);

        let config = MobileTunnelConfig::from_app(&app).expect("direct mobile config");

        assert_eq!(config.peers, [] as [nostr_vpn_core::fips_mesh::FipsMeshPeerConfig; 0]);
        assert_eq!(config.route_targets, vec![MESH_TUNNEL_IPV4_CIDR]);
        assert!(config.wireguard_exit.is_none());
    }

    #[test]
    fn mobile_config_selected_exit_node_adds_default_route() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.exit_node = peer.to_string();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        );
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        assert!(
            config.peers[0]
                .allowed_ips
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        assert_eq!(config.mtu, nostr_vpn_core::MESH_TUNNEL_MTU);
        assert_eq!(
            config.dns_servers,
            vec![nostr_vpn_core::MESH_MAGIC_DNS_SERVER]
        );
        assert_eq!(
            config.magic_dns_server,
            nostr_vpn_core::MESH_MAGIC_DNS_SERVER
        );
        assert_eq!(config.dns_match_domains, vec![""]);
    }

    #[test]
    fn mobile_fips_exit_node_routes_default_traffic_to_selected_member() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_stack_size(4 * 1024 * 1024)
            .build()
            .expect("mobile FIPS test runtime");
        runtime.block_on(Box::pin(run_mobile_fips_exit_node_route_test()));
    }

    async fn run_mobile_fips_exit_node_route_test() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let client_keys = Keys::generate();
        let exit_keys = Keys::generate();
        let client_nsec = client_keys.secret_key().to_bech32().expect("client nsec");
        let exit_nsec = exit_keys.secret_key().to_bech32().expect("exit nsec");
        let client_pubkey = client_keys.public_key().to_hex();
        let exit_pubkey = exit_keys.public_key().to_hex();
        let network_id = format!("mobile-fips-exit-{nonce}");
        let scope = format!("nostr-vpn:{network_id}");
        let exit_port = available_udp_port();

        let exit_mobile = fips_exit_mobile_config(exit_nsec, &exit_pubkey, &network_id, exit_port);
        let exit_endpoint = bind_local_mobile_endpoint(&scope, &exit_mobile).await;
        let client_app =
            fips_exit_client_app(&client_nsec, &client_pubkey, &exit_pubkey, &network_id);

        let mut client_mobile =
            MobileTunnelConfig::from_app(&client_app).expect("client mobile config");
        client_mobile.listen_port = available_udp_port();
        // fips-core rejects loopback-only static peers unless Nostr discovery is
        // available as fallback. The packet assertion below still exercises the
        // deterministic static hint path.
        client_mobile.nostr_discovery_enabled = true;
        client_mobile.peer_hints.insert(
            exit_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: format!("127.0.0.1:{exit_port}"),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }],
        );

        let client_tunnel_ip = assert_mobile_fips_exit_config(&client_mobile, &exit_pubkey);
        let packet = test_ipv4_packet(client_tunnel_ip, Ipv4Addr::new(8, 8, 8, 8));
        let packet_two = test_ipv4_packet(client_tunnel_ip, Ipv4Addr::new(1, 1, 1, 1));
        let mut started = Box::pin(MobileTunnel::start_async(client_mobile, client_app))
            .await
            .expect("start client mobile tunnel");
        let mut messages = send_mobile_packets_until_received(
            &started,
            &exit_endpoint,
            &[packet.clone(), packet_two.clone()],
        )
        .await;
        let message = messages.remove(0);
        let message_two = messages.remove(0);

        let exit_runtime = FipsMeshRuntime::with_local_routes(
            vec![
                FipsMeshPeerConfig::from_participant_pubkey(
                    &client_pubkey,
                    vec![format!("{client_tunnel_ip}/32")],
                )
                .expect("client peer config"),
            ],
            vec!["0.0.0.0/0".to_string()],
        );
        assert!(
            exit_runtime
                .receive_endpoint_data_owned_with_source_node_addr(
                    message.source_peer.node_addr().as_bytes(),
                    message.data.clone(),
                )
                .is_some(),
            "a FIPS exit node with a local default route should admit the first forwarded packet"
        );
        assert!(
            exit_runtime
                .receive_endpoint_data_owned_with_source_node_addr(
                    message_two.source_peer.node_addr().as_bytes(),
                    message_two.data.clone(),
                )
                .is_some(),
            "a FIPS exit node with a local default route should admit the second forwarded packet"
        );
        let (reply, reply_two) = test_ipv4_replies(client_tunnel_ip);
        exit_endpoint
            .send_batch_to_peer(message.source_peer, vec![reply.clone()])
            .await
            .expect("send reply to mobile tunnel");
        exit_endpoint
            .send_batch_to_peer(message.source_peer, vec![reply_two.clone()])
            .await
            .expect("send second reply to mobile tunnel");
        let mut expected_reply = reply;
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut expected_reply);
        let mut expected_reply_two = reply_two;
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut expected_reply_two);
        let expected_replies = vec![expected_reply, expected_reply_two];
        receive_mobile_inbound_packets_until(&mut started, &expected_replies).await;

        shutdown_started_mobile_tunnel(started).await;
        exit_endpoint
            .shutdown()
            .await
            .expect("shutdown exit endpoint");
    }

    #[test]
    fn mobile_magic_dns_answers_peer_name_from_tun_packet() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.set_peer_alias(peer, "fixture-peer")
            .expect("peer alias");
        let app = Arc::new(RwLock::new(app));
        let source = Ipv4Addr::new(10, 44, 206, 222);
        let dns_server =
            parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).expect("magic dns server");
        let query = ipv4_udp_packet(
            source,
            dns_server,
            53000,
            53,
            &dns_query("fixture-peer.nvpn", 1),
        );
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let response = runtime
            .block_on(mobile_magic_dns_response_packet(
                &query, &app, None, dns_server,
            ))
            .expect("dns response packet");

        assert_eq!(&response[12..16], &dns_server.octets());
        assert_eq!(&response[16..20], &source.octets());
        assert_eq!(u16::from_be_bytes([response[20], response[21]]), 53);
        assert_eq!(u16::from_be_bytes([response[22], response[23]]), 53000);
        let expected_ip = derive_mesh_tunnel_ip("test", peer)
            .and_then(|value| strip_cidr(&value).parse::<Ipv4Addr>().ok())
            .expect("peer tunnel ip");
        let expected_octets = expected_ip.octets();
        assert!(
            response.windows(4).any(|window| window == expected_octets),
            "response did not include {expected_ip}: {response:?}"
        );
    }

    #[test]
    fn mobile_dns_without_secure_resolver_returns_server_failure_for_unknown_query() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let app = Arc::new(RwLock::new(app));
        let source = Ipv4Addr::new(10, 44, 206, 222);
        let dns_server =
            parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).expect("magic dns server");
        let query = ipv4_udp_packet(
            source,
            dns_server,
            53000,
            53,
            &dns_query("example.com", 1),
        );
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let response = runtime
            .block_on(mobile_magic_dns_response_packet(
                &query, &app, None, dns_server,
            ))
            .expect("dns response packet");

        assert_eq!(response[31] & 0x0f, 2, "DNS rcode should be SERVFAIL");
    }

    #[test]
    fn mobile_public_dns_uses_authenticated_resolver_response() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let app = Arc::new(RwLock::new(app));
        let source = Ipv4Addr::new(10, 44, 206, 222);
        let dns_server =
            parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).expect("local dns server");
        let query = ipv4_udp_packet(
            source,
            dns_server,
            53000,
            53,
            &dns_query("example.com", 1),
        );
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let resolver = FixtureSecureDns;
        let response = runtime
            .block_on(mobile_magic_dns_response_packet(
                &query,
                &app,
                Some(&resolver),
                dns_server,
            ))
            .expect("DNS response packet");

        let dns = hickory_proto::op::Message::from_vec(&response[28..]).expect("DNS response");
        assert_eq!(dns.id, 0x1234);
        assert_eq!(
            dns.metadata.message_type,
            hickory_proto::op::MessageType::Response
        );
        assert_eq!(dns.queries[0].name.to_ascii(), "example.com.");
    }

    #[test]
    fn mobile_secure_dns_can_wait_for_packet_forwarded_by_same_dispatcher() {
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("mobile DNS dispatch test runtime");
        runtime.block_on(async {
            let keys = Keys::generate();
            let mobile = MobileTunnelConfig {
                identity_nsec: keys.secret_key().to_bech32().expect("mobile nsec"),
                network_id: "secure-dns-dispatch".to_string(),
                local_address: "10.44.206.222/32".to_string(),
                listen_port: available_udp_port(),
                ..empty_config()
            };
            let endpoint =
                bind_local_mobile_endpoint("nostr-vpn:secure-dns-dispatch", &mobile).await;
            let mesh =
                new_mobile_mesh(FipsMeshRuntime::with_local_routes(Vec::new(), Vec::new()));
            let peer_identities = Arc::new(RwLock::new(MobilePeerIdentityMap::default()));
            let app = Arc::new(RwLock::new(AppConfig::generated()));
            let dns_server =
                parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).expect("local DNS server");
            let dns_packet = ipv4_udp_packet(
                Ipv4Addr::new(10, 44, 206, 222),
                dns_server,
                53000,
                53,
                &dns_query("example.com", 1),
            );
            let doh_packet = test_ipv4_packet(
                Ipv4Addr::new(10, 44, 206, 222),
                Ipv4Addr::new(1, 1, 1, 1),
            );
            let (wg_tx, mut wg_rx) = tokio_mpsc::channel(1);
            let (inbound_tx, mut inbound_rx) = tokio_mpsc::channel(1);
            let packet_forwarded = Arc::new(tokio::sync::Notify::new());
            let mut secure_dns = Some(MobileSecureDnsDispatch::new(ForwardDependentSecureDns {
                packet_forwarded: Arc::clone(&packet_forwarded),
            }));
            let expected_doh_packet = doh_packet.clone();
            let forwarded_task = tokio::spawn(async move {
                let batch = tokio::time::timeout(Duration::from_secs(1), wg_rx.recv())
                    .await
                    .expect("dispatcher stalled before forwarding resolver traffic")
                    .expect("WG packet channel closed");
                assert_eq!(batch, vec![expected_doh_packet]);
                packet_forwarded.notify_one();
            });

            assert!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    dispatch_mobile_outbound_packets(
                        &endpoint,
                        &mesh,
                        &peer_identities,
                        Some(&wg_tx),
                        None,
                        None,
                        &inbound_tx,
                        &app,
                        &mut secure_dns,
                        Some(dns_server),
                        None,
                        vec![dns_packet, doh_packet],
                    ),
                )
                .await
                .expect("mobile dispatcher deadlocked on secure DNS")
            );
            forwarded_task.await.expect("forwarded packet task");
            let responses = tokio::time::timeout(Duration::from_secs(1), inbound_rx.recv())
                .await
                .expect("secure DNS response timed out")
                .expect("inbound response channel closed");
            assert_eq!(responses.len(), 1);
            let dns =
                hickory_proto::op::Message::from_vec(&responses[0][28..]).expect("DNS response");
            assert_eq!(dns.id, 0x1234);

            endpoint.shutdown().await.expect("shutdown mobile endpoint");
        });
    }

    #[test]
    fn dropping_mobile_secure_dns_dispatch_aborts_in_flight_resolution() {
        struct ResolutionGuard(Arc<AtomicBool>);

        impl Drop for ResolutionGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        struct PendingSecureDns {
            started: tokio_mpsc::UnboundedSender<()>,
            dropped: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl SecureDnsLookup for PendingSecureDns {
            async fn resolve(
                &self,
                _query: &[u8],
            ) -> std::result::Result<Vec<u8>, nostr_vpn_core::secure_dns::SecureDnsError> {
                let _guard = ResolutionGuard(Arc::clone(&self.dropped));
                let _ = self.started.send(());
                std::future::pending().await
            }
        }

        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("mobile DNS lifecycle test runtime");
        runtime.block_on(async {
            let (started_tx, mut started_rx) = tokio_mpsc::unbounded_channel();
            let dropped = Arc::new(AtomicBool::new(false));
            let mut secure_dns = MobileSecureDnsDispatch::new(PendingSecureDns {
                started: started_tx,
                dropped: Arc::clone(&dropped),
            });
            let app = Arc::new(RwLock::new(AppConfig::generated()));
            let dns_server =
                parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).expect("local DNS server");
            let packet = ipv4_udp_packet(
                Ipv4Addr::new(10, 44, 206, 222),
                dns_server,
                53000,
                53,
                &dns_query("example.com", 1),
            );
            let (inbound_tx, _inbound_rx) = tokio_mpsc::channel(1);
            assert!(secure_dns.try_spawn_response(packet, app, dns_server, inbound_tx));
            tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
                .await
                .expect("resolver task did not start")
                .expect("resolver start channel closed");

            drop(secure_dns);

            tokio::time::timeout(Duration::from_secs(1), async {
                while !dropped.load(Ordering::Relaxed) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("dropping secure DNS dispatch did not abort resolver task");
        });
    }

    #[test]
    fn mobile_wireguard_dns_translation_stays_inside_active_wg_path() {
        let mesh = Ipv4Addr::new(10, 44, 206, 222);
        let local_dns = parse_ipv4(nostr_vpn_core::MESH_MAGIC_DNS_SERVER).unwrap();
        let profile_dns = [
            Ipv4Addr::new(94, 140, 14, 14),
            Ipv4Addr::new(9, 9, 9, 9),
        ];
        let dns_nat = MobileExitDnsNat::new(local_dns, profile_dns.to_vec()).unwrap();
        let mut first = ipv4_udp_packet(
            mesh,
            local_dns,
            53000,
            53,
            &dns_query("example.com", 1),
        );
        let mut second = ipv4_udp_packet(
            mesh,
            local_dns,
            53001,
            53,
            &dns_query("example.net", 1),
        );

        assert_eq!(
            dns_nat.rewrite_query(&mut first),
            Some(profile_dns[0])
        );
        assert_eq!(&first[16..20], &profile_dns[0].octets());
        assert_eq!(
            dns_nat.rewrite_query(&mut second),
            Some(profile_dns[1])
        );
        assert_eq!(&second[16..20], &profile_dns[1].octets());

        let mut response = ipv4_udp_packet(profile_dns[1], mesh, 53, 53001, b"dns response");
        assert!(dns_nat.rewrite_response(&mut response));
        assert_eq!(&response[12..16], &local_dns.octets());

        let mut unrelated = ipv4_udp_packet(profile_dns[1], mesh, 443, 53001, b"not dns");
        assert!(!dns_nat.rewrite_response(&mut unrelated));
        assert_eq!(&unrelated[12..16], &profile_dns[1].octets());

        let mut direct_dns = ipv4_udp_packet(profile_dns[0], mesh, 53, 54000, b"direct DNS");
        assert!(!dns_nat.rewrite_response(&mut direct_dns));
        assert_eq!(&direct_dns[12..16], &profile_dns[0].octets());
    }

    #[test]
    fn mobile_config_includes_static_peer_hints_from_app() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.fips_peer_endpoints
            .insert(peer.to_string(), vec!["192.168.50.10:51820".to_string()]);
        app.ensure_defaults();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let hints = config
            .peer_hints
            .get(peer)
            .expect("static peer hint should be serialized into mobile config");

        assert_eq!(
            hints,
            &vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }]
        );
    }

    #[test]
    fn mobile_config_keeps_join_request_admin_as_control_peer_without_route() {
        let admin_keys = Keys::generate();
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let admin = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: Vec::new(),
            removed_devices: Vec::new(),
            admins: vec![admin.clone()],
            listen_for_join_requests: false,
            join_request_admin: admin.clone(),
            local_identity_confirmation_pending: false,
            outbound_join_request: Some(PendingOutboundJoinRequest {
                recipient: admin.clone(),
                requested_at: 1,
            }),
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.fips_peer_endpoints
            .insert(admin.clone(), vec!["192.168.50.10:51820".to_string()]);
        app.ensure_defaults();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].participant_pubkey, admin);
        assert_eq!(config.peers[0].allowed_ips, [] as [std::string::String; 0]);
        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route.starts_with("10.") && route.ends_with("/32"))
        );
        let hints = config
            .peer_hints
            .get(&admin)
            .expect("admin static hint should stay available for FIPS control");
        assert_eq!(
            hints,
            &vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
                priority: FIPS_STATIC_PEER_ENDPOINT_PRIORITY,
            }]
        );
        let endpoint_config =
            fips_peer_configs_from_mesh(
                &config.peers,
                &config.peer_hints,
                &config.bootstrap_peers,
                false,
            );
        let endpoint_peer = endpoint_config
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint config");
        assert_eq!(endpoint_peer.addresses.len(), 1);
        assert_eq!(endpoint_peer.addresses[0].addr, "192.168.50.10:51820");
        assert_eq!(
            endpoint_peer.addresses[0].priority,
            FIPS_STATIC_PEER_ENDPOINT_PRIORITY
        );
    }

    include!("tests_core/manual_join.rs");
