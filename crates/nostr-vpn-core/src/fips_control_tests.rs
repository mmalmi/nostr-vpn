#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frame_roundtrips_with_magic_prefix() {
        let frame = FipsControlFrame::Ping {
            network_id: "mesh".to_string(),
            sent_at: 42,
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode");
        assert!(encoded.starts_with(FIPS_CONTROL_MAGIC));

        let decoded = decode_fips_control_frame(&encoded)
            .expect("decode")
            .expect("control frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn raw_packet_is_not_control() {
        let packet = [0x45, 0, 0, 20];

        assert!(
            decode_fips_control_frame(&packet)
                .expect("decode")
                .is_none()
        );
    }

    #[test]
    fn capabilities_frame_roundtrips() {
        let frame = FipsControlFrame::Capabilities {
            network_id: "mesh".to_string(),
            capabilities: PeerCapabilities {
                advertised_routes: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                endpoint_hints: vec![PeerEndpointHint::udp("192.168.50.22:51820")],
                dataplane_features: vec!["future_feature".to_string()],
                signed_at: 99,
            },
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode");
        let decoded = decode_fips_control_frame(&encoded)
            .expect("decode")
            .expect("control frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn old_capabilities_decode_with_empty_endpoint_hints() {
        let caps: PeerCapabilities =
            serde_json::from_str(r#"{"advertised_routes":["0.0.0.0/0"],"signed_at":99}"#)
                .expect("decode old capabilities");

        assert_eq!(caps.advertised_routes, vec!["0.0.0.0/0".to_string()]);
        assert!(caps.endpoint_hints.is_empty());
        assert!(caps.dataplane_features.is_empty());
        assert_eq!(caps.signed_at, 99);
    }

    #[test]
    fn peer_capabilities_match_dataplane_features_case_insensitively() {
        let caps = PeerCapabilities {
            dataplane_features: vec!["FUTURE_FEATURE".to_string()],
            ..PeerCapabilities::default()
        };

        assert!(caps.supports_dataplane_feature("future_feature"));
        assert!(!caps.supports_dataplane_feature("unknown_feature"));
    }

    #[test]
    fn local_dataplane_features_are_empty_without_protocol_extensions() {
        assert!(local_fips_dataplane_features().is_empty());
    }

    #[test]
    fn signed_roster_verifies_independent_of_alias_map_order() {
        let admin = Keys::generate();
        let alice = Keys::generate().public_key().to_hex();
        let bob = Keys::generate().public_key().to_hex();
        let mut aliases = HashMap::new();
        aliases.insert(bob.clone(), "bob".to_string());
        aliases.insert(alice.clone(), "alice".to_string());
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![bob.clone(), alice.clone()],
            admins: vec![admin.public_key().to_hex()],
            aliases,
            signed_at: 123,
        };

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");

        signed.verify().expect("verify signed roster");
        assert_eq!(
            signed.signer_pubkey_hex().unwrap(),
            admin.public_key().to_hex()
        );
        assert_eq!(signed.network_id().unwrap(), "mesh");
        assert_eq!(signed.roster().unwrap().network_name, "Home");
        assert_eq!(signed.content_hash().len(), 64);
        assert_eq!(signed.artifact_hash().len(), 64);
    }

    #[test]
    fn signed_roster_puts_roster_fields_in_tags() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let mut aliases = HashMap::new();
        aliases.insert(member.clone(), "phone".to_string());
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member.clone()],
            admins: vec![admin.public_key().to_hex()],
            aliases,
            signed_at: 123,
        };

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let tags = signed
            .event
            .tags
            .iter()
            .map(Tag::as_slice)
            .collect::<Vec<_>>();

        assert!(signed.event.content.is_empty());
        assert!(tags.contains(&vec!["d".to_string(), "mesh".to_string()].as_slice()));
        assert!(tags.contains(&vec!["member".to_string(), member].as_slice()));
        assert!(
            tags.iter()
                .any(|tag| tag.first().is_some_and(|tag| tag == "alias"))
        );
    }

    #[test]
    fn join_binding_lives_in_control_data_without_changing_the_roster_event() {
        let admin = Keys::generate();
        let device = Keys::generate().public_key().to_hex();
        let roster = SignedRoster::sign(
            "mesh",
            NetworkRoster {
                network_name: "Home".to_string(),
                devices: vec![device.clone()],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: 123,
            },
            &admin,
        )
        .expect("sign ordinary roster");
        let join = JoinRosterControl::new(roster.clone(), "qr-request-secret")
            .expect("bind roster to join request");

        join.verify_for_request("qr-request-secret")
            .expect("verify join control data");
        assert_eq!(join.signed_roster, roster);
        assert!(!format!("{join:?}").contains("qr-request-secret"));
        assert!(
            join.verify_for_request("wrong-secret")
                .is_err()
        );

        let frame = join_roster_control_frame(join.clone());
        let encoded = encode_fips_control_frame(&frame).expect("encode join control record");
        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode join control record"),
            Some(frame)
        );
    }

    #[test]
    fn join_roster_ack_roundtrips_as_application_control_data() {
        let frame = join_roster_ack_control_frame("ab".repeat(32));
        let encoded = encode_fips_control_frame(&frame).expect("encode join roster receipt");

        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode join roster receipt"),
            Some(frame)
        );
    }

    #[test]
    fn signed_roster_rejects_tampered_content() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member],
            admins: vec![admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: 123,
        };
        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let mut event = signed.event.clone();
        event.tags.push(roster_tag(&["name", "Office"]).unwrap());
        let signed = SignedRoster { event };

        assert!(signed.verify().is_err());
    }

    #[test]
    fn endpoint_hints_default_to_udp_transport() {
        let hint: PeerEndpointHint =
            serde_json::from_str(r#"{"addr":"192.168.50.22:51820"}"#).expect("decode hint");

        assert_eq!(hint.transport, "udp");
        assert_eq!(hint.addr, "192.168.50.22:51820");
    }

    #[test]
    fn peer_endpoint_hint_addr_accepts_lan_and_dns_udp_hints() {
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22:51820")),
            Some("192.168.50.22:51820".to_string())
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("peer.example.com:51820")),
            Some("peer.example.com:51820".to_string())
        );
    }

    #[test]
    fn peer_endpoint_hint_addr_rejects_unusable_hints() {
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint {
                transport: "tcp".to_string(),
                addr: "192.168.50.22:51820".to_string(),
            }),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("192.168.50.22")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("127.0.0.1:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("100.120.94.10:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("198.51.100.10:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("0.0.0.0:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("localhost:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp("not an endpoint:51820")),
            None
        );
        assert_eq!(
            peer_endpoint_hint_addr(&PeerEndpointHint::udp(format!(
                "{}:51820",
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            ))),
            None
        );
    }

    #[test]
    fn large_stateful_control_frame_roundtrips_as_one_record() {
        let roster = NetworkRoster {
            network_name: "Network 1".to_string(),
            devices: (0..12).map(|value| format!("{value:064x}")).collect(),
            admins: vec!["f".repeat(64)],
            aliases: (0..12)
                .map(|value| (format!("{value:064x}"), format!("node-{value}")))
                .collect(),
            signed_at: 123,
        };
        let frame = FipsControlFrame::Roster {
            network_id: "mesh".to_string(),
            roster,
            signed_roster: None,
        };

        let encoded = encode_fips_control_frame(&frame).expect("encode one state-control record");
        assert!(encoded.len() > 1_100);
        assert_eq!(
            decode_fips_control_frame(&encoded).expect("decode state-control record"),
            Some(frame)
        );
    }

    #[test]
    fn unknown_kind_is_dropped_silently() {
        let mut bytes = Vec::from(FIPS_CONTROL_MAGIC);
        bytes.extend_from_slice(br#"{"v":1,"frame":{"kind":"future_kind","x":1}}"#);

        assert!(decode_fips_control_frame(&bytes).expect("decode").is_none());
    }

    #[test]
    fn future_version_is_dropped_silently() {
        let mut bytes = Vec::from(FIPS_CONTROL_MAGIC);
        bytes
            .extend_from_slice(br#"{"v":99,"frame":{"kind":"ping","network_id":"x","sent_at":1}}"#);

        assert!(decode_fips_control_frame(&bytes).expect("decode").is_none());
    }

    // Compatibility fixtures for admin-assigned tunnel addresses (#159).

    fn signed_roster_event(tags: &[Vec<String>], keys: &Keys) -> Event {
        let tags = tags
            .iter()
            .map(|parts| roster_tag(&parts.iter().map(String::as_str).collect::<Vec<_>>()))
            .collect::<Result<Vec<_>>>()
            .expect("roster tags");
        EventBuilder::new(Kind::Custom(SIGNED_ROSTER_KIND), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(123))
            .sign_with_keys(keys)
            .expect("sign roster event")
    }

    fn roster_tags(version_tags: &[&[&str]], member: &str, extra: &[&[&str]]) -> Vec<Vec<String>> {
        let owned = |parts: &[&str]| parts.iter().map(|part| part.to_string()).collect::<Vec<_>>();
        let mut tags = vec![owned(&["d", "mesh"]), owned(&["app", SIGNED_ROSTER_APP])];
        tags.extend(version_tags.iter().map(|parts| owned(parts)));
        tags.push(owned(&["member", member]));
        tags.extend(extra.iter().map(|parts| owned(parts)));
        tags
    }

    #[test]
    fn unassigned_roster_keeps_the_v1_tag_layout() {
        let admin = Keys::generate();
        let admin_hex = admin.public_key().to_hex();
        let mut members = [
            Keys::generate().public_key().to_hex(),
            Keys::generate().public_key().to_hex(),
        ];
        members.sort();
        let mut aliases = HashMap::new();
        aliases.insert(members[1].clone(), "phone".to_string());
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![members[1].clone(), members[0].clone()],
            admins: vec![admin_hex.clone()],
            aliases,
            signed_at: 123,
        };

        let signed = SignedRoster::sign("mesh", roster, &admin).expect("sign roster");
        let tags = signed
            .event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect::<Vec<_>>();
        let expected = [
            vec!["d", "mesh"],
            vec!["app", SIGNED_ROSTER_APP],
            vec!["v", "1"],
            vec!["name", "Home"],
            vec!["member", &members[0]],
            vec!["member", &members[1]],
            vec!["admin", &admin_hex],
            vec!["alias", &members[1], "phone"],
        ]
        .map(|parts| parts.iter().map(|part| part.to_string()).collect::<Vec<_>>());

        assert_eq!(tags, expected);
    }

    #[test]
    fn current_parser_rejects_a_roster_with_assigned_addresses() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let event = signed_roster_event(
            &roster_tags(
                &[&["v", "2"]],
                &member,
                &[&["address", &member, "100.64.0.13/32"]],
            ),
            &admin,
        );

        let error = SignedRoster::from_event(event).expect_err("v2 roster");
        assert!(error.to_string().contains("unsupported version"), "{error}");
    }

    #[test]
    fn v1_parser_ignores_an_address_tag_so_assignments_need_a_new_version() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let event = signed_roster_event(
            &roster_tags(
                &[&["v", "1"]],
                &member,
                &[&["address", &member, "100.64.0.13/32"]],
            ),
            &admin,
        );

        let roster = SignedRoster::from_event(event)
            .expect("unknown tags are skipped")
            .roster()
            .expect("roster");
        assert_eq!(roster.devices, vec![member]);
    }

    #[test]
    fn roster_requires_exactly_one_well_formed_version_tag() {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let cases: [(&[&[&str]], &str); 6] = [
            (&[], "missing version tag"),
            (&[&["v"]], "unsupported version"),
            (&[&["v", " 1"]], "unsupported version"),
            (&[&["v", "1", "2"]], "unsupported version"),
            (&[&["v", "1"], &["v", "2"]], "more than one version tag"),
            (&[&["v", "1"], &["v", "1"]], "more than one version tag"),
        ];

        for (version_tags, expected) in cases {
            let event = signed_roster_event(&roster_tags(version_tags, &member, &[]), &admin);
            let error = SignedRoster::from_event(event).expect_err("malformed version");
            assert!(
                error.to_string().contains(expected),
                "{version_tags:?}: {error}"
            );
        }
    }

    fn address_tags(tags: &[&[&str]]) -> Vec<Tag> {
        tags.iter()
            .map(|parts| roster_tag(parts).expect("tag"))
            .collect()
    }

    #[test]
    fn address_tags_give_each_member_one_effective_address() {
        let alice = Keys::generate().public_key().to_hex();
        let bob = Keys::generate().public_key().to_hex();
        let members = vec![alice.clone(), bob.clone()];
        let tags = address_tags(&[
            &["member", &alice],
            &["member", &bob],
            &["address", &alice, "100.64.0.13/32"],
        ]);

        let assignments = roster_address_assignments(&tags).expect("assignments");
        let effective =
            crate::config::effective_mesh_tunnel_ipv4s("mesh", &members, &assignments)
                .expect("effective addresses");

        assert_eq!(effective[&alice], Ipv4Addr::new(100, 64, 0, 13));
        assert_eq!(
            Some(format!("{}/32", effective[&bob])),
            crate::config::derive_mesh_tunnel_ip("mesh", &bob)
        );

        let outsider = Keys::generate().public_key().to_hex();
        let tags = address_tags(&[&["address", &outsider, "100.64.0.14/32"]]);
        let assignments = roster_address_assignments(&tags).expect("assignments");
        let error = crate::config::effective_mesh_tunnel_ipv4s("mesh", &members, &assignments)
            .expect_err("non-member");
        assert!(error.to_string().contains("non-member"), "{error}");
    }

    #[test]
    fn malformed_address_tags_are_rejected() {
        let member = Keys::generate().public_key().to_hex();
        let cases: [(&[&[&str]], &str); 6] = [
            (&[&["address", &member]], "needs a member and an address"),
            (&[&["address", &member, "100.64.0.13"]], "not an IPv4 /32"),
            (&[&["address", &member, "100.64.0.0/24"]], "not an IPv4 /32"),
            (&[&["address", &member, "fd7a::1/128"]], "not an IPv4 /32"),
            (&[&["address", "not-a-key", "100.64.0.13/32"]], "pubkey"),
            (
                &[
                    &["address", &member, "100.64.0.13/32"],
                    &["address", &member, "100.64.0.14/32"],
                ],
                "more than one address",
            ),
        ];

        for (tags, expected) in cases {
            let error =
                roster_address_assignments(&address_tags(tags)).expect_err("malformed address");
            assert!(error.to_string().contains(expected), "{tags:?}: {error}");
        }
    }
}
