    #[test]
    fn explicit_pending_identity_marker_fails_closed_despite_malformed_join_fields() {
        let admin = Keys::generate().public_key().to_hex();
        let replacement = Keys::generate().public_key().to_hex();
        let mut app = AppConfig::generated_without_networks();
        app.add_manual_join_network(&admin, "manual-mesh")
            .expect("configure manual join");
        {
            let network = app.active_network_mut();
            assert!(network.local_identity_confirmation_pending);
            network.join_request_admin.clear();
            network.outbound_join_request = Some(PendingOutboundJoinRequest {
                recipient: replacement,
                requested_at: unix_timestamp(),
            });
        }

        let config =
            MobileTunnelConfig::from_app(&app).expect("malformed pending manual bootstrap config");

        assert_eq!(config.network_id, "");
        assert_eq!(config.peers, [] as [nostr_vpn_core::fips_mesh::FipsMeshPeerConfig; 0]);
        assert_eq!(config.route_targets, [] as [std::string::String; 0]);
        assert_eq!(config.dns_servers, [] as [std::string::String; 0]);
        assert_eq!(config.magic_dns_server, "");
        assert_eq!(config.dns_match_domains, [] as [std::string::String; 0]);
    }
