use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use nostr_sdk::prelude::Keys;
use nostr_vpn_core::config::{AppConfig, derive_mesh_tunnel_ip};
use nostr_vpn_core::magic_dns::{MagicDnsServer, build_magic_dns_records};

#[test]
fn build_magic_dns_records_emits_alias_and_suffix_variants() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    if let Some(network) = config.networks.first_mut() {
        network.participants = vec![peer_hex.clone()];
    }
    config.ensure_defaults();
    config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set alias");

    let records = build_magic_dns_records(&config);
    let expected_ip = derive_mesh_tunnel_ip(&config.effective_network_id(), &peer_hex)
        .expect("derived peer ip")
        .split('/')
        .next()
        .expect("split cidr")
        .parse::<Ipv4Addr>()
        .expect("ipv4");

    assert_eq!(records.get("home-server"), Some(&expected_ip));
    assert_eq!(records.get("home-server.nvpn"), Some(&expected_ip));
}

#[test]
fn magic_dns_server_answers_a_and_nxdomain() {
    let expected_ip = Ipv4Addr::new(10, 44, 0, 11);
    let mut records = HashMap::new();
    records.insert("home-server.nvpn".to_string(), expected_ip);
    records.insert("home-server".to_string(), expected_ip);

    let mut server = MagicDnsServer::start(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        records,
    )
    .expect("start dns server");
    let server_addr = server.local_addr();

    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");

    let response = send_dns_query(&socket, server_addr, "home-server.nvpn.", RecordType::A);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    let answer = response.answers().first().expect("expected answer");
    match answer.data() {
        RData::A(A(ip)) => assert_eq!(*ip, expected_ip),
        other => panic!("unexpected answer data: {other:?}"),
    }

    let nxdomain = send_dns_query(&socket, server_addr, "unknown.nvpn.", RecordType::A);
    assert_eq!(nxdomain.response_code(), ResponseCode::NXDomain);
    assert!(nxdomain.answers().is_empty());

    server.stop();
}

fn send_dns_query(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    name: &str,
    record_type: RecordType,
) -> Message {
    let mut request = Message::new();
    request.set_id(42);
    request.set_message_type(MessageType::Query);
    request.set_recursion_desired(true);
    request.add_query(Query::query(
        Name::from_ascii(name).expect("dns name"),
        record_type,
    ));

    let mut packet = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut packet);
    request.emit(&mut encoder).expect("encode dns query");

    socket
        .send_to(&packet, server_addr)
        .expect("send dns query packet");
    let mut reply = [0_u8; 512];
    let (len, _) = socket.recv_from(&mut reply).expect("recv dns reply");
    Message::from_vec(&reply[..len]).expect("decode dns reply")
}
