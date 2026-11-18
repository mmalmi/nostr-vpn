mod tests {
    #[cfg(feature = "peer-credit")]
    include!("peer_credit_tests.rs");
    use super::{
        FipsEndpointAdmissionCache, FipsMeshPeerConfig, FipsMeshRuntime, FipsPaidRouteAdmission,
        endpoint_node_addr_from_pubkey_bytes,
    };
    use crate::paid_routes::PaidRouteAccessState;
    use nostr_sdk::prelude::{Keys, ToBech32};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone)]
    struct TestPeer {
        participant_pubkey: String,
        endpoint_npub: String,
        endpoint_pubkey: [u8; 32],
        endpoint_node_addr: [u8; 16],
    }

    impl TestPeer {
        fn generate() -> Self {
            let keys = Keys::generate();
            let endpoint_pubkey_bytes = *keys.public_key().as_bytes();
            Self {
                participant_pubkey: keys.public_key().to_hex(),
                endpoint_npub: keys.public_key().to_bech32().expect("npub"),
                endpoint_pubkey: endpoint_pubkey_bytes,
                endpoint_node_addr: endpoint_node_addr_from_pubkey_bytes(endpoint_pubkey_bytes),
            }
        }
        fn config(&self, allowed_ips: &[&str]) -> FipsMeshPeerConfig {
            FipsMeshPeerConfig {
                participant_pubkey: self.participant_pubkey.clone(),
                endpoint_npub: self.endpoint_npub.clone(),
                allowed_ips: allowed_ips.iter().map(|ip| (*ip).to_string()).collect(),
            }
        }
    }

    fn runtime() -> FipsMeshRuntime {
        let general = TestPeer::generate();
        let specific = TestPeer::generate();
        FipsMeshRuntime::new(vec![
            general.config(&["10.44.0.0/16"]),
            specific.config(&["10.44.22.44/32"]),
        ])
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let total_len = 20 + payload.len();
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(&payload);
        packet
    }

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..].copy_from_slice(&payload);
        packet
    }

    fn ipv4_udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = ipv4_packet(source, destination);
        packet.resize(28, 0);
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    fn ipv6_udp_packet(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = ipv6_packet(source, destination);
        packet.resize(48, 0);
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    fn ipv4_icmp_error(source: Ipv4Addr, destination: Ipv4Addr, original: &[u8]) -> Vec<u8> {
        let quoted_len = original.len().min(28);
        let mut packet = ipv4_packet(source, destination);
        packet.resize(28 + quoted_len, 0);
        packet[2..4].copy_from_slice(&((28 + quoted_len) as u16).to_be_bytes());
        packet[9] = 1;
        packet[20] = 3;
        packet[21] = 4;
        packet[28..].copy_from_slice(&original[..quoted_len]);
        packet
    }

    fn ipv4_icmp_echo(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        kind: u8,
        identifier: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut packet = ipv4_packet(source, destination);
        packet.resize(28, 0);
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 1;
        packet[20..28].fill(0);
        packet[20] = kind;
        packet[24..26].copy_from_slice(&identifier.to_be_bytes());
        packet[26..28].copy_from_slice(&sequence.to_be_bytes());
        packet
    }

    fn ipv6_icmp_error(source: Ipv6Addr, destination: Ipv6Addr, original: &[u8]) -> Vec<u8> {
        let quoted_len = original.len().min(48);
        let payload_len = 8 + quoted_len;
        let mut packet = ipv6_packet(source, destination);
        packet.resize(40 + payload_len, 0);
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = 58;
        packet[40] = 2;
        packet[44..48].copy_from_slice(&1280_u32.to_be_bytes());
        packet[48..].copy_from_slice(&original[..quoted_len]);
        packet
    }

    fn ipv4_tcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = ipv4_packet(source, destination);
        packet.resize(40, 0);
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = flags;
        packet
    }

    fn paid_route_admission(
        peer: &TestPeer,
        allowed_ips: Vec<&str>,
        allow_routing: bool,
    ) -> FipsPaidRouteAdmission {
        paid_route_admission_with_destinations(peer, allowed_ips, Vec::new(), allow_routing)
    }

    fn paid_route_admission_with_destinations(
        peer: &TestPeer,
        allowed_ips: Vec<&str>,
        destination_allowed_ips: Vec<&str>,
        allow_routing: bool,
    ) -> FipsPaidRouteAdmission {
        FipsPaidRouteAdmission {
            participant_pubkey: peer.participant_pubkey.clone(),
            session_id: "session-1".to_string(),
            allowed_ips: allowed_ips.into_iter().map(ToString::to_string).collect(),
            destination_allowed_ips: destination_allowed_ips
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            allow_routing,
            state: if allow_routing {
                PaidRouteAccessState::Paid
            } else {
                PaidRouteAccessState::Suspended
            },
            amount_due_msat: 0,
            paid_msat: 0,
            unpaid_msat: 0,
            expires_at_unix: 999_999,
            updated_at_unix: 10,
        }
    }

    #[test]
    fn peer_config_from_participant_pubkey_derives_endpoint_npub() {
        let peer = TestPeer::generate();

        let config = FipsMeshPeerConfig::from_participant_pubkey(
            &peer.participant_pubkey,
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer config");

        assert_eq!(config.participant_pubkey, peer.participant_pubkey);
        assert_eq!(config.endpoint_npub, peer.endpoint_npub);
        assert_eq!(config.allowed_ips, vec!["10.44.22.44/32"]);
    }

    #[test]
    fn runtime_caches_canonical_endpoint_npub_for_status_and_routes() {
        let peer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 22, 44));
        let runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            endpoint_npub: format!(" {} ", hex::encode(peer.endpoint_pubkey)),
            ..peer.config(&["10.44.22.44/32"])
        }]);

        let routed = runtime
            .route_outbound_packet_peer(&packet)
            .expect("packet should route");
        assert_eq!(
            runtime.peer_statuses()[0].endpoint_npub,
            peer.endpoint_npub
        );
        assert_eq!(routed.endpoint_node_addr, &peer.endpoint_node_addr);
    }

    #[test]
    fn runtime_indexes_participants_by_pubkey_bytes_and_outputs_hex_edges() {
        let peer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 22, 44));
        let inbound_packet =
            ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: format!(" {} ", peer.endpoint_npub),
            ..peer.config(&["10.44.22.44/32"])
        }]);

        assert_eq!(
            runtime.peer_pubkeys(),
            vec![peer.participant_pubkey.clone()]
        );
        assert_eq!(runtime.peer_statuses()[0].pubkey, peer.participant_pubkey);
        assert_eq!(
            runtime.peer_endpoint_node_addr(&peer.endpoint_npub),
            Some(peer.endpoint_node_addr)
        );
        assert_eq!(
            runtime.peer_endpoint_node_addr_for_participant_pubkey_bytes(&peer.endpoint_pubkey),
            Some(peer.endpoint_node_addr)
        );
        assert_eq!(
            runtime
                .route_outbound_packet_owned_with_peer(packet.clone())
                .expect("packet should route")
                .participant_pubkey,
            peer.participant_pubkey
        );
        assert_eq!(
            runtime
                .route_outbound_packet_peer(&packet)
                .expect("packet should route")
                .participant_pubkey_bytes,
            Some(&peer.endpoint_pubkey)
        );
        assert_eq!(
            runtime
                .receive_endpoint_data_owned_with_source_node_addr(
                    &peer.endpoint_node_addr,
                    inbound_packet
                )
                .expect("packet should be admitted")
                .source_pubkey_bytes,
            Some(&peer.endpoint_pubkey)
        );
    }

    #[test]
    fn runtime_identity_indexes_preserve_first_match_lookup_behavior() {
        let first = TestPeer::generate();
        let second = TestPeer::generate();
        let duplicate_participant = TestPeer::generate();
        let runtime = FipsMeshRuntime::new(vec![
            first.config(&[]),
            FipsMeshPeerConfig {
                endpoint_npub: duplicate_participant.endpoint_npub.clone(),
                ..first.config(&[])
            },
            FipsMeshPeerConfig {
                endpoint_npub: first.endpoint_npub.clone(),
                ..second.config(&[])
            },
        ]);

        assert_eq!(
            runtime.peer_endpoint_node_addr(&first.participant_pubkey),
            Some(first.endpoint_node_addr)
        );
        assert_eq!(
            runtime.participant_for_endpoint_node_addr(&first.endpoint_node_addr),
            Some(first.participant_pubkey)
        );
    }

    #[test]
    fn paid_route_admission_indexes_endpoint_identity_and_allows_paid_raw_route() {
        let buyer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(8, 8, 8, 8));
        let reply = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 44, 22, 44));
        let runtime = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            Vec::new(),
            vec!["0.0.0.0/0".to_string()],
            vec![paid_route_admission(
                &buyer,
                vec!["10.44.22.44/32"],
                true,
            )],
        );

        assert_eq!(runtime.peer_pubkeys(), vec![buyer.participant_pubkey.clone()]);
        assert_eq!(
            runtime.participant_for_endpoint_node_addr(&buyer.endpoint_node_addr),
            Some(buyer.participant_pubkey.clone())
        );
        assert_eq!(
            runtime.peer_endpoint_node_addr_for_participant_pubkey_bytes(&buyer.endpoint_pubkey),
            Some(buyer.endpoint_node_addr)
        );

        let admitter = runtime
            .endpoint_source_admitter(&buyer.endpoint_node_addr)
            .expect("paid buyer source should be admitted to the seller exit route");
        assert_eq!(admitter.source_pubkey(), buyer.participant_pubkey);
        assert!(admitter.receive_owned(packet.clone()).is_some());

        let routed = runtime
            .route_outbound_packet_owned_with_peer(reply.clone())
            .expect("seller reply should route to the paid buyer tunnel address");
        assert_eq!(routed.participant_pubkey, buyer.participant_pubkey);
    }

    #[test]
    fn paid_route_destination_routes_allow_exit_without_free_local_default() {
        let buyer = TestPeer::generate();
        let seller_ip = Ipv4Addr::new(10, 44, 10, 1);
        let buyer_ip = Ipv4Addr::new(10, 44, 22, 44);
        let internet_ip = Ipv4Addr::new(8, 8, 8, 8);
        let packet = ipv4_packet(buyer_ip, internet_ip);
        let spoofed = ipv4_packet(Ipv4Addr::new(203, 0, 113, 9), internet_ip);
        let runtime = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            Vec::new(),
            vec![format!("{seller_ip}/32")],
            vec![paid_route_admission_with_destinations(
                &buyer,
                vec!["10.44.22.44/32"],
                vec!["0.0.0.0/0"],
                true,
            )],
        );

        let admitter = runtime
            .endpoint_source_admitter(&buyer.endpoint_node_addr)
            .expect("paid buyer should have a FIPS source identity");
        assert!(
            admitter.receive_owned(packet.clone()).is_some(),
            "paid destination routes should admit exit traffic without advertising a free default route",
        );
        assert!(
            admitter.receive_owned(spoofed.clone()).is_none(),
            "paid destination routes must not loosen the buyer source-IP gate",
        );
    }

    #[test]
    fn paid_buyer_route_outweighs_private_upstream_default() {
        let upstream = TestPeer::generate();
        let buyer = TestPeer::generate();
        let seller_ip = Ipv4Addr::new(10, 44, 94, 74);
        let buyer_ip = Ipv4Addr::new(10, 44, 195, 6);
        let internet_ip = Ipv4Addr::new(203, 0, 113, 100);
        let runtime = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            vec![upstream.config(&["0.0.0.0/0"])],
            vec!["0.0.0.0/0".to_string()],
            vec![paid_route_admission_with_destinations(
                &buyer,
                vec!["10.44.195.6/32"],
                vec!["0.0.0.0/0"],
                true,
            )],
        );
        let request = ipv4_packet(buyer_ip, internet_ip);

        let buyer_admitter = runtime
            .endpoint_source_admitter(&buyer.endpoint_node_addr)
            .expect("paid buyer identity");
        assert!(buyer_admitter.receive_owned(request.clone()).is_some());
        let upstream_route = runtime
            .route_outbound_packet_owned_with_peer(request)
            .expect("Internet traffic should use the private upstream");
        assert_eq!(upstream_route.participant_pubkey, upstream.participant_pubkey);

        let reply = ipv4_packet(internet_ip, buyer_ip);
        let buyer_route = runtime
            .route_outbound_packet_owned_with_peer(reply)
            .expect("reply should return to the paid buyer");
        assert_eq!(buyer_route.participant_pubkey, buyer.participant_pubkey);

        let upstream_admitter = runtime
            .endpoint_source_admitter(&upstream.endpoint_node_addr)
            .expect("private upstream identity");
        assert!(
            upstream_admitter
                .receive_owned(ipv4_packet(buyer_ip, seller_ip))
                .is_none(),
            "the private upstream cannot claim the paid buyer's more-specific source"
        );
    }

    #[test]
    fn paid_route_admission_without_routing_keeps_identity_but_blocks_raw_packets() {
        let buyer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(8, 8, 8, 8));
        let reply = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 44, 22, 44));
        let runtime = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            Vec::new(),
            vec!["0.0.0.0/0".to_string()],
            vec![paid_route_admission(
                &buyer,
                vec!["10.44.22.44/32"],
                false,
            )],
        );

        let admitter = runtime
            .endpoint_source_admitter(&buyer.endpoint_node_addr)
            .expect("unpaid buyer still has a FIPS source identity");
        assert_eq!(admitter.source_pubkey(), buyer.participant_pubkey);
        assert!(admitter.receive_owned(packet.clone()).is_none());
        assert!(
            runtime.route_outbound_packet_owned_with_peer(reply.clone()).is_none(),
            "allow_routing=false must not install a raw route to the paid buyer"
        );
    }

    #[test]
    fn peer_config_detects_default_route_advertisement() {
        let peer = TestPeer::generate();
        let config = peer.config(&["10.44.22.44/32", " 0.0.0.0/0 ", "::/0"]);

        assert!(config.advertises_default_route());
    }

    #[test]
    fn peer_config_ignores_non_default_routes() {
        let peer = TestPeer::generate();
        let config = peer.config(&["10.44.0.0/16", "fd00::/8"]);

        assert!(!config.advertises_default_route());
    }

    #[test]
    fn outbound_packet_uses_longest_prefix_route() {
        let general = TestPeer::generate();
        let specific = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 22, 44));
        let runtime = FipsMeshRuntime::new(vec![
            general.config(&["10.44.0.0/16"]),
            specific.config(&["10.44.22.44/32"]),
        ]);

        assert_eq!(runtime.exact_route_peer_index.len(), 1);
        let outgoing = runtime
            .route_outbound_packet_owned_with_peer(packet.clone())
            .expect("owned packet should route");

        assert_eq!(outgoing.participant_pubkey, specific.participant_pubkey);
        assert_eq!(outgoing.endpoint_node_addr, &specific.endpoint_node_addr);
        assert_eq!(outgoing.bytes, packet);

        let outgoing = runtime
            .route_outbound_packet_peer(&packet)
            .expect("metadata-only packet should route");

        assert_eq!(outgoing.participant_pubkey, specific.participant_pubkey);
        assert_eq!(outgoing.endpoint_node_addr, &specific.endpoint_node_addr);

        let cached_destination = IpAddr::V4(Ipv4Addr::new(10, 44, 22, 44));
        let outgoing = runtime
            .route_outbound_packet_owned_with_peer_to_destination(
                packet.clone(),
                cached_destination,
            )
            .expect("cached destination should route through current table");

        assert_eq!(outgoing.participant_pubkey, specific.participant_pubkey);
        assert_eq!(outgoing.endpoint_node_addr, &specific.endpoint_node_addr);
        assert_eq!(outgoing.bytes, packet);

        assert!(
            runtime
                .route_outbound_packet_owned_with_peer_to_destination(
                    packet.clone(),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
                )
                .is_none(),
            "cached destination must still consult the current route table"
        );
    }

    #[test]
    fn fallback_prefix_index_skips_exact_routes_and_preserves_longest_prefix() {
        let exact = TestPeer::generate();
        let subnet = TestPeer::generate();
        let exit = TestPeer::generate();
        let runtime = FipsMeshRuntime::new(vec![
            exact.config(&["10.44.22.44/32"]),
            subnet.config(&["10.44.0.0/16"]),
            exit.config(&["0.0.0.0/0", "fd00::/8", "fd00:44::/48"]),
        ]);

        assert_eq!(runtime.exact_route_peer_index.len(), 1);
        assert_eq!(
            runtime
                .prefix_v4_route_peer_index
                .iter()
                .map(|route| route.route.prefix_len)
                .collect::<Vec<_>>(),
            vec![16, 0]
        );
        assert_eq!(
            runtime
                .prefix_v6_route_peer_index
                .iter()
                .map(|route| route.route.prefix_len)
                .collect::<Vec<_>>(),
            vec![48, 8]
        );

        let exact_packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 22, 44));
        let exact_outgoing = runtime
            .route_outbound_packet_owned_with_peer(exact_packet.clone())
            .expect("exact route should use exact index");
        assert_eq!(exact_outgoing.participant_pubkey, exact.participant_pubkey);

        let subnet_packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 5, 9));
        let subnet_outgoing = runtime
            .route_outbound_packet_owned_with_peer(subnet_packet.clone())
            .expect("subnet route should win over default route");
        assert_eq!(
            subnet_outgoing.participant_pubkey,
            subnet.participant_pubkey
        );

        let exit_packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(8, 8, 8, 8));
        let exit_outgoing = runtime
            .route_outbound_packet_owned_with_peer(exit_packet.clone())
            .expect("default route should handle non-peer destination");
        assert_eq!(exit_outgoing.participant_pubkey, exit.participant_pubkey);
    }

    #[test]
    fn duplicate_exact_routes_for_same_peer_are_not_ambiguous() {
        let peer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(10, 44, 22, 44));
        let runtime = FipsMeshRuntime::new(vec![peer.config(&[
            "10.44.22.44/32",
            "10.44.22.44/32",
        ])]);

        let outgoing = runtime
            .route_outbound_packet_owned_with_peer(packet.clone())
            .expect("duplicate same-peer route should still route");

        assert_eq!(outgoing.participant_pubkey, peer.participant_pubkey);
        assert_eq!(outgoing.endpoint_node_addr, &peer.endpoint_node_addr);
    }

    #[test]
    fn outbound_packet_without_route_is_dropped() {
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 10, 1), Ipv4Addr::new(192, 0, 2, 10));

        assert!(runtime().route_outbound_packet_peer(&packet).is_none());
    }

    #[test]
    fn inbound_endpoint_data_accepts_roster_source_with_owned_packet_source() {
        let peer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![peer.config(&["10.44.22.44/32"])]);

        let admitter = runtime
            .endpoint_source_admitter(&peer.endpoint_node_addr)
            .expect("source endpoint should be configured");
        assert_eq!(admitter.source_pubkey(), peer.participant_pubkey);
        assert_eq!(admitter.source_pubkey_bytes(), Some(&peer.endpoint_pubkey));
        assert!(admitter.receive_owned(packet.clone()).is_some());

        let received = runtime
            .receive_endpoint_data_owned_with_source_node_addr(
                &peer.endpoint_node_addr,
                packet.clone(),
            )
            .expect("borrowed-source node addr and packet source should be admitted");

        assert_eq!(received.source_pubkey, peer.participant_pubkey);
        assert_eq!(received.bytes, packet);
    }

    #[test]
    fn inbound_endpoint_source_run_admits_with_single_source_identity() {
        let peer = TestPeer::generate();
        let admitted = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let rejected = ipv4_packet(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![peer.config(&["10.44.22.44/32"])]);

        let mut admission_cache = FipsEndpointAdmissionCache::default();
        let mut accepted = Vec::new();
        let mut endpoint_bytes = 0usize;
        let admitter = runtime
            .endpoint_source_admitter(&peer.endpoint_node_addr)
            .expect("source endpoint should be configured");
        for packet in [admitted.clone(), rejected] {
            if admitter.admit_packet_cached(&packet, &mut admission_cache) {
                endpoint_bytes = endpoint_bytes.saturating_add(packet.len());
                accepted.push(packet);
            }
        }

        assert_eq!(admitter.source_pubkey(), peer.participant_pubkey);
        assert_eq!(admitter.source_pubkey_bytes(), Some(&peer.endpoint_pubkey));
        assert_eq!(endpoint_bytes, admitted.len());
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted, vec![admitted]);
    }

    #[test]
    fn inbound_endpoint_data_drops_unknown_source_node_addr() {
        assert!(runtime().endpoint_source_admitter(&[7_u8; 16]).is_none());
    }

    #[test]
    fn inbound_endpoint_data_drops_known_source_with_unowned_packet_source() {
        let peer = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: peer.participant_pubkey,
            endpoint_npub: peer.endpoint_npub.clone(),
            allowed_ips: vec!["10.44.22.44/32".to_string()],
        }]);

        let admitter = runtime
            .endpoint_source_admitter(&peer.endpoint_node_addr)
            .expect("source endpoint should be configured");
        assert!(admitter.receive_owned(packet.clone()).is_none());
    }

    #[test]
    fn inbound_endpoint_data_rejects_broad_route_spoofing_specific_peer_source() {
        let general = TestPeer::generate();
        let specific = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![
            FipsMeshPeerConfig {
                participant_pubkey: general.participant_pubkey,
                endpoint_npub: general.endpoint_npub.clone(),
                allowed_ips: vec!["10.44.0.0/16".to_string()],
            },
            FipsMeshPeerConfig {
                participant_pubkey: specific.participant_pubkey,
                endpoint_npub: specific.endpoint_npub,
                allowed_ips: vec!["10.44.22.44/32".to_string()],
            },
        ]);

        let admitter = runtime
            .endpoint_source_admitter(&general.endpoint_node_addr)
            .expect("general endpoint should be configured");
        assert!(admitter.receive_owned(packet.clone()).is_none());
    }

    #[test]
    fn equal_prefix_route_ambiguity_is_dropped() {
        let first = TestPeer::generate();
        let second = TestPeer::generate();
        let packet = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let runtime = FipsMeshRuntime::new(vec![
            FipsMeshPeerConfig {
                participant_pubkey: first.participant_pubkey,
                endpoint_npub: first.endpoint_npub.clone(),
                allowed_ips: vec!["10.44.22.44/32".to_string()],
            },
            FipsMeshPeerConfig {
                participant_pubkey: second.participant_pubkey,
                endpoint_npub: second.endpoint_npub,
                allowed_ips: vec!["10.44.22.44/32".to_string()],
            },
        ]);

        assert!(runtime.route_outbound_packet_peer(&packet).is_none());
    }

    #[test]
    fn equal_prefix_ipv6_exact_route_ambiguity_is_dropped() {
        let first = TestPeer::generate();
        let second = TestPeer::generate();
        let source = "fd00:44::1".parse().expect("source");
        let destination = "fd00:44::10".parse().expect("destination");
        let packet = ipv6_packet(source, destination);
        let runtime = FipsMeshRuntime::new(vec![
            FipsMeshPeerConfig {
                participant_pubkey: first.participant_pubkey,
                endpoint_npub: first.endpoint_npub.clone(),
                allowed_ips: vec!["fd00:44::10/128".to_string()],
            },
            FipsMeshPeerConfig {
                participant_pubkey: second.participant_pubkey,
                endpoint_npub: second.endpoint_npub,
                allowed_ips: vec!["fd00:44::10/128".to_string()],
            },
        ]);

        assert!(runtime.route_outbound_packet_peer(&packet).is_none());
    }

    #[test]
    fn local_routes_limit_inbound_packet_destinations() {
        let peer = TestPeer::generate();
        let runtime = FipsMeshRuntime::with_local_routes(
            vec![FipsMeshPeerConfig {
                participant_pubkey: peer.participant_pubkey,
                endpoint_npub: peer.endpoint_npub.clone(),
                allowed_ips: vec!["10.44.22.44/32".to_string()],
            }],
            vec!["10.44.10.1/32".to_string()],
        );
        let admitted = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 1));
        let rejected = ipv4_packet(Ipv4Addr::new(10, 44, 22, 44), Ipv4Addr::new(10, 44, 10, 2));

        let admitter = runtime
            .endpoint_source_admitter(&peer.endpoint_node_addr)
            .expect("source endpoint should be configured");
        assert!(admitter.receive_owned(admitted.clone()).is_some());
        assert!(admitter.receive_owned(rejected.clone()).is_none());
    }

    #[test]
    fn local_default_route_allows_exit_node_destinations() {
        let peer = TestPeer::generate();
        let runtime = FipsMeshRuntime::with_local_routes(
            vec![FipsMeshPeerConfig {
                participant_pubkey: peer.participant_pubkey,
                endpoint_npub: peer.endpoint_npub.clone(),
                allowed_ips: vec!["10.44.22.44/32".to_string()],
            }],
            vec!["0.0.0.0/0".to_string()],
        );
        let packet = ipv4_packet(
            Ipv4Addr::new(10, 44, 22, 44),
            Ipv4Addr::new(203, 0, 113, 10),
        );

        let admitter = runtime
            .endpoint_source_admitter(&peer.endpoint_node_addr)
            .expect("source endpoint should be configured");
        assert!(admitter.receive_owned(packet.clone()).is_some());
    }

    #[test]
    fn two_device_private_mesh_routes_and_admits_bidirectional_packets() {
        let alice = TestPeer::generate();
        let bob = TestPeer::generate();
        let alice_ip = Ipv4Addr::new(10, 44, 1, 10);
        let bob_ip = Ipv4Addr::new(10, 44, 1, 20);
        let alice_runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: bob.participant_pubkey.clone(),
            endpoint_npub: bob.endpoint_npub.clone(),
            allowed_ips: vec![format!("{bob_ip}/32")],
        }]);
        let bob_runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: alice.participant_pubkey.clone(),
            endpoint_npub: alice.endpoint_npub.clone(),
            allowed_ips: vec![format!("{alice_ip}/32")],
        }]);

        let alice_to_bob = ipv4_packet(alice_ip, bob_ip);
        let outgoing = alice_runtime
            .route_outbound_packet_owned_with_peer(alice_to_bob.clone())
            .expect("Alice should route packet to Bob");
        assert_eq!(outgoing.participant_pubkey, bob.participant_pubkey);
        let received = bob_runtime
            .receive_endpoint_data_owned_with_source_node_addr(
                &alice.endpoint_node_addr,
                outgoing.bytes,
            )
            .expect("Bob should admit Alice's owned source IP");
        assert_eq!(received.source_pubkey, alice.participant_pubkey);
        assert_eq!(received.bytes, alice_to_bob);

        let bob_to_alice = ipv4_packet(bob_ip, alice_ip);
        let outgoing = bob_runtime
            .route_outbound_packet_owned_with_peer(bob_to_alice.clone())
            .expect("Bob should route packet to Alice");
        assert_eq!(outgoing.participant_pubkey, alice.participant_pubkey);
        let received = alice_runtime
            .receive_endpoint_data_owned_with_source_node_addr(
                &bob.endpoint_node_addr,
                outgoing.bytes,
            )
            .expect("Alice should admit Bob's owned source IP");
        assert_eq!(received.source_pubkey, bob.participant_pubkey);
        assert_eq!(received.bytes, bob_to_alice);
    }

    #[test]
    fn ipv6_routes_are_supported_for_raw_packets() {
        let peer = TestPeer::generate();
        let runtime = FipsMeshRuntime::new(vec![FipsMeshPeerConfig {
            participant_pubkey: peer.participant_pubkey.clone(),
            endpoint_npub: peer.endpoint_npub.clone(),
            allowed_ips: vec!["fd00:44::/64".to_string()],
        }]);
        let packet = ipv6_packet(
            "fd00:44::20".parse().expect("source"),
            "fd00:44::10".parse().expect("destination"),
        );

        let outgoing = runtime
            .route_outbound_packet_owned_with_peer(packet.clone())
            .expect("IPv6 packet should route");
        let received = runtime
            .receive_endpoint_data_owned_with_source_node_addr(&peer.endpoint_node_addr, packet)
            .expect("IPv6 source should be admitted");

        assert_eq!(outgoing.endpoint_node_addr, &peer.endpoint_node_addr);
        assert_eq!(received.source_pubkey, peer.participant_pubkey);
    }

    #[test]
    fn default_exit_admits_only_udp_replies_to_local_flows() {
        let exit = TestPeer::generate();
        let local = Ipv4Addr::new(10, 44, 10, 1);
        let remote = Ipv4Addr::new(8, 8, 8, 8);
        let runtime = FipsMeshRuntime::with_local_routes(
            vec![FipsMeshPeerConfig {
                participant_pubkey: exit.participant_pubkey.clone(),
                endpoint_npub: exit.endpoint_npub.clone(),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
            }],
            vec![format!("{local}/32")],
        );
        let reply = ipv4_udp_packet(remote, local, 53, 40_000);
        let admitter = runtime
            .endpoint_source_admitter(&exit.endpoint_node_addr)
            .expect("exit source");

        assert!(admitter.receive_owned(reply.clone()).is_none());
        let outbound = ipv4_udp_packet(local, remote, 40_000, 53);
        let routed = runtime
            .route_outbound_destination_peer(IpAddr::V4(remote))
            .expect("cached exit route");
        assert!(routed.via_default_route);
        runtime.note_cached_exit_outbound(*routed.endpoint_node_addr, &outbound);
        assert!(admitter.receive_owned(reply).is_some());
    }

    #[test]
    fn default_exit_flow_state_survives_route_table_refresh() {
        let exit = TestPeer::generate();
        let local = Ipv4Addr::new(10, 44, 10, 1);
        let remote = Ipv4Addr::new(8, 8, 8, 8);
        let config = FipsMeshPeerConfig {
            participant_pubkey: exit.participant_pubkey,
            endpoint_npub: exit.endpoint_npub.clone(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
        };
        let first =
            FipsMeshRuntime::with_local_routes(vec![config.clone()], vec![format!("{local}/32")]);
        assert!(
            first
                .route_outbound_packet_peer(&ipv4_udp_packet(local, remote, 40_000, 443))
                .is_some()
        );

        let mut refreshed =
            FipsMeshRuntime::with_local_routes(vec![config], vec![format!("{local}/32")]);
        refreshed.inherit_exit_flows(&first);
        let reply = ipv4_udp_packet(remote, local, 443, 40_000);

        assert!(
            refreshed
                .receive_endpoint_data_owned_with_source_node_addr(&exit.endpoint_node_addr, reply,)
                .is_some()
        );
    }

    #[test]
    fn default_exit_drops_malformed_and_non_global_sources_even_after_outbound() {
        let exit = TestPeer::generate();
        let local = Ipv4Addr::new(10, 44, 10, 1);
        let private = Ipv4Addr::new(10, 0, 0, 9);
        let runtime = FipsMeshRuntime::with_local_routes(
            vec![FipsMeshPeerConfig {
                participant_pubkey: exit.participant_pubkey,
                endpoint_npub: exit.endpoint_npub.clone(),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
            }],
            vec![format!("{local}/32")],
        );
        let admitter = runtime
            .endpoint_source_admitter(&exit.endpoint_node_addr)
            .expect("exit source");

        assert!(
            runtime
                .route_outbound_packet_peer(&ipv4_udp_packet(local, private, 40_000, 53))
                .is_some()
        );
        assert!(
            admitter
                .receive_owned(ipv4_udp_packet(private, local, 53, 40_000))
                .is_none()
        );
        assert!(
            admitter
                .receive_owned(ipv4_packet(Ipv4Addr::new(8, 8, 4, 4), local))
                .is_none()
        );
    }

    #[test]
    fn default_exit_admits_tcp_replies_but_not_remote_connection_attempts() {
        let exit = TestPeer::generate();
        let local = Ipv4Addr::new(10, 44, 10, 1);
        let remote = Ipv4Addr::new(8, 8, 8, 8);
        let runtime = FipsMeshRuntime::with_local_routes(
            vec![FipsMeshPeerConfig {
                participant_pubkey: exit.participant_pubkey,
                endpoint_npub: exit.endpoint_npub.clone(),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
            }],
            vec![format!("{local}/32")],
        );
        let admitter = runtime
            .endpoint_source_admitter(&exit.endpoint_node_addr)
            .expect("exit source");

        assert!(
            runtime
                .route_outbound_packet_peer(&ipv4_tcp_packet(local, remote, 40_000, 443, 0x02))
                .is_some()
        );
        assert!(
            admitter
                .receive_owned(ipv4_tcp_packet(remote, local, 443, 40_000, 0x12))
                .is_some()
        );
        assert!(
            admitter
                .receive_owned(ipv4_tcp_packet(remote, local, 443, 40_000, 0x02))
                .is_none()
        );
    }

    include!("exit_filter_extended_tests.rs");
}
