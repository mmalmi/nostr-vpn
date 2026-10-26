use std::net::IpAddr;

use nostr_sdk::prelude::Keys;
use nostr_vpn_core::fips_mesh::{
    FipsEndpointAdmissionCache, FipsMeshPeerConfig, FipsMeshRuntime, FipsPaidRouteAdmission,
};
use nostr_vpn_core::paid_routes::PaidRouteAccessState;

fn buyer() -> FipsPaidRouteAdmission {
    FipsPaidRouteAdmission {
        participant_pubkey: Keys::generate().public_key().to_hex(),
        session_id: "paid-internet-session".into(),
        allowed_ips: vec!["10.44.22.44/32".into(), "fd00::44/128".into()],
        destination_allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
        allow_routing: true,
        state: PaidRouteAccessState::Paid,
        amount_due_msat: 0,
        paid_msat: 1_000,
        unpaid_msat: 0,
        expires_at_unix: u64::MAX,
        updated_at_unix: 1,
    }
}

fn packet(destination: &str) -> Vec<u8> {
    match destination.parse::<IpAddr>().unwrap() {
        IpAddr::V4(destination) => {
            let mut bytes = vec![0; 28];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[10, 44, 22, 44]);
            bytes[16..20].copy_from_slice(&destination.octets());
            bytes[20..28].copy_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
            bytes
        }
        IpAddr::V6(destination) => {
            let mut bytes = vec![0; 48];
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&8u16.to_be_bytes());
            bytes[6] = 17;
            bytes[7] = 64;
            let source = "fd00::44".parse::<std::net::Ipv6Addr>().unwrap();
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
            bytes[40..48].copy_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
            bytes
        }
    }
}

#[test]
fn paid_buyer_cannot_send_to_seller_private_destinations() {
    // Exercise both explicit paid routes and the legacy local-default path.
    for explicit_destinations in [true, false] {
        let mut admission = buyer();
        if !explicit_destinations {
            admission.destination_allowed_ips.clear();
        }
        let buyer_key = admission.participant_pubkey.clone();
        let seller = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            vec![],
            vec!["10.44.1.1/32".into(), "0.0.0.0/0".into(), "::/0".into()],
            vec![admission],
        );
        let source = seller.peer_endpoint_node_addr(&buyer_key).unwrap();
        let admitter = seller.endpoint_source_admitter(&source).unwrap();
        let mut cache = FipsEndpointAdmissionCache::default();
        for destination in [
            "0.0.0.0",
            "0.1.2.3",
            "10.44.1.1",
            "10.44.22.45",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            "::192.168.1.1",
            "64:ff9b::192.168.1.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::c0a8:101",
            "2002:c0a8:0101::1",
        ] {
            let bytes = packet(destination);
            assert!(
                admitter.receive_owned(bytes.clone()).is_none(),
                "seller admitted paid traffic to {destination} (explicit={explicit_destinations})"
            );
            for _ in 0..2 {
                assert!(!admitter.admit_packet_cached(&bytes, &mut cache));
            }
        }
        for destination in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let bytes = packet(destination);
            assert!(admitter.receive_owned(bytes.clone()).is_some());
            assert!(admitter.admit_packet_cached(&bytes, &mut cache));
        }
    }
}

#[test]
fn paid_destination_scope_source_identity_and_revocation_still_apply() {
    let mut admission = buyer();
    admission.destination_allowed_ips = vec!["8.8.8.0/24".into()];
    let buyer_key = admission.participant_pubkey.clone();
    let mut seller = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
        vec![],
        vec![],
        vec![admission.clone()],
    );
    let source = seller.peer_endpoint_node_addr(&buyer_key).unwrap();
    assert!(
        seller
            .receive_endpoint_data_owned_with_source_node_addr(&source, packet("8.8.8.8"))
            .is_some()
    );
    for destination in ["1.1.1.1", "2606:4700:4700::1111", "10.0.0.1"] {
        assert!(
            seller
                .receive_endpoint_data_owned_with_source_node_addr(&source, packet(destination))
                .is_none()
        );
    }
    let mut spoofed = packet("8.8.8.8");
    spoofed[12..16].copy_from_slice(&[10, 44, 22, 45]);
    assert!(
        seller
            .receive_endpoint_data_owned_with_source_node_addr(&source, spoofed)
            .is_none()
    );
    assert!(
        seller
            .receive_endpoint_data_owned_with_source_node_addr(&[0; 16], packet("8.8.8.8"))
            .is_none()
    );
    admission.allow_routing = false;
    admission.state = PaidRouteAccessState::Suspended;
    seller.replace_paid_route_admissions(vec![admission]);
    assert!(
        seller
            .receive_endpoint_data_owned_with_source_node_addr(&source, packet("8.8.8.8"))
            .is_none()
    );
}

#[test]
fn paid_buyer_cannot_use_publicly_numbered_local_or_mesh_routes() {
    let admission = buyer();
    let buyer_key = admission.participant_pubkey.clone();
    let member = FipsMeshPeerConfig::from_participant_pubkey(
        Keys::generate().public_key().to_hex(),
        vec!["203.0.113.0/24".into(), "2001:db8:2::/64".into()],
    )
    .unwrap();
    let upstream = FipsMeshPeerConfig::from_participant_pubkey(
        Keys::generate().public_key().to_hex(),
        vec!["0.0.0.0/0".into(), "::/0".into()],
    )
    .unwrap();
    let seller = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
        vec![member, upstream],
        vec!["198.51.100.0/24".into(), "2001:db8:1::/64".into()],
        vec![admission],
    );
    let source = seller.peer_endpoint_node_addr(&buyer_key).unwrap();
    for destination in [
        "198.51.100.5",
        "203.0.113.5",
        "2001:db8:1::5",
        "2001:db8:2::5",
    ] {
        assert!(
            seller
                .receive_endpoint_data_owned_with_source_node_addr(&source, packet(destination))
                .is_none(),
            "paid buyer reached private route {destination}"
        );
    }
    for destination in ["8.8.8.8", "2606:4700:4700::1111"] {
        let bytes = packet(destination);
        assert!(
            seller
                .receive_endpoint_data_owned_with_source_node_addr(&source, bytes.clone())
                .is_some()
        );
        assert!(
            seller.route_outbound_packet_peer(&bytes).is_some(),
            "private upstream must still carry paid Internet traffic"
        );
    }
}

#[test]
fn private_roster_members_keep_their_private_network_access() {
    let member = FipsMeshPeerConfig::from_participant_pubkey(
        Keys::generate().public_key().to_hex(),
        vec!["10.44.22.44/32".into(), "fd00::44/128".into()],
    )
    .unwrap();
    let member_key = member.participant_pubkey.clone();
    let seller = FipsMeshRuntime::with_local_routes(
        vec![member],
        vec![
            "10.44.1.1/32".into(),
            "192.168.0.0/16".into(),
            "fd00::/64".into(),
        ],
    );
    let source = seller.peer_endpoint_node_addr(&member_key).unwrap();
    for destination in ["10.44.1.1", "192.168.1.1", "fd00::1"] {
        assert!(
            seller
                .receive_endpoint_data_owned_with_source_node_addr(&source, packet(destination))
                .is_some()
        );
    }
}
