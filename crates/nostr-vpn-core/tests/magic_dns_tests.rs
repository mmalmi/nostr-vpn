use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use nostr_sdk::prelude::Keys;
use nostr_vpn_core::config::{AppConfig, derive_mesh_tunnel_ip};
use nostr_vpn_core::magic_dns::{MagicDnsServer, build_magic_dns_records};

#[test]
fn build_magic_dns_records_stays_empty_until_manual_join_is_accepted() {
    let joiner = Keys::generate();
    let admin = Keys::generate();
    let mut config = AppConfig::generated_without_networks();
    config.nostr.secret_key = joiner.secret_key().to_secret_hex();
    config.nostr.public_key = joiner.public_key().to_hex();
    config
        .add_manual_join_network(&admin.public_key().to_hex(), "pending-magic-dns")
        .expect("configure manual join");

    assert!(
        build_magic_dns_records(&config).is_empty(),
        "unaccepted identities must not publish unusable mesh DNS records"
    );
}

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
        network.enabled = true;
        network.devices = vec![peer_hex.clone()];
        network.admins = vec![own_hex.clone()];
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
fn build_magic_dns_records_includes_self_name_and_suffixes_peer_collision() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.node_name = "Home Server".to_string();
    if let Some(network) = config.networks.first_mut() {
        network.enabled = true;
        network.devices = vec![peer_hex.clone()];
        network.admins = vec![own_hex.clone()];
    }
    config.ensure_defaults();
    config
        .set_peer_alias(&own_hex, "home-server")
        .expect("set own alias");
    config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set colliding alias");

    let records = build_magic_dns_records(&config);
    let expected_own_ip = derive_mesh_tunnel_ip(&config.effective_network_id(), &own_hex)
        .expect("derived own ip")
        .split('/')
        .next()
        .expect("split cidr")
        .parse::<Ipv4Addr>()
        .expect("ipv4");
    let expected_peer_ip = derive_mesh_tunnel_ip(&config.effective_network_id(), &peer_hex)
        .expect("derived peer ip")
        .split('/')
        .next()
        .expect("split cidr")
        .parse::<Ipv4Addr>()
        .expect("ipv4");

    assert_eq!(records.get("home-server"), Some(&expected_own_ip));
    assert_eq!(records.get("home-server.nvpn"), Some(&expected_own_ip));
    assert_eq!(records.get("home-server-2"), Some(&expected_peer_ip));
    assert_eq!(records.get("home-server-2.nvpn"), Some(&expected_peer_ip));
}

#[test]
fn magic_dns_server_resolves_fips_without_host_access_or_aliases() {
    let identity = fips_core::Identity::generate();
    let mut server = MagicDnsServer::start("127.0.0.1:0".parse().unwrap(), HashMap::new())
        .expect("start DNS without host access or a mesh endpoint");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("DNS client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let name = format!("{}.FiPs.", identity.npub());

    let response = send_dns_query(&socket, server.local_addr(), &name, RecordType::AAAA);
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(response.answers.iter().any(|answer| {
        matches!(&answer.data, RData::AAAA(address) if address.0 == identity.address().to_ipv6())
    }));
    // An empty A response must not poison the IPv6 name lookup with NXDOMAIN.
    let response = send_dns_query(&socket, server.local_addr(), &name, RecordType::A);
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
    let invalid = send_dns_query(
        &socket,
        server.local_addr(),
        "invalid.fips.",
        RecordType::AAAA,
    );
    assert_eq!(invalid.response_code, ResponseCode::NXDomain);
    server.stop();
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
    assert_eq!(response.response_code, ResponseCode::NoError);
    let answer = response.answers.first().expect("expected answer");
    match &answer.data {
        RData::A(A(ip)) => assert_eq!(*ip, expected_ip),
        other => panic!("unexpected answer data: {other:?}"),
    }

    let nxdomain = send_dns_query(&socket, server_addr, "unknown.nvpn.", RecordType::A);
    assert_eq!(nxdomain.response_code, ResponseCode::NXDomain);
    assert!(nxdomain.answers.is_empty());

    server.stop();
}

#[test]
fn magic_dns_server_update_records_reflects_newly_added_alias() {
    // Regression: peers added via `nvpn add-participant` or imported via
    // roster update after the daemon started used to keep returning NXDOMAIN until
    // the daemon was restarted, because the records map was baked at boot
    // and `update_records` was never called outside tests. The session
    // runtime now wires `update_records` into every reload point — guard
    // that behaviour at the server level so a future regression surfaces
    // before it ships.
    let initial_ip = Ipv4Addr::new(10, 44, 0, 11);
    let mut initial = HashMap::new();
    initial.insert("home-server.nvpn".to_string(), initial_ip);

    let mut server = MagicDnsServer::start(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        initial,
    )
    .expect("start dns server");
    let server_addr = server.local_addr();

    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");

    let pre = send_dns_query(&socket, server_addr, "pi.nvpn.", RecordType::A);
    assert_eq!(pre.response_code, ResponseCode::NXDomain);

    let new_ip = Ipv4Addr::new(10, 44, 1, 42);
    let mut updated = HashMap::new();
    updated.insert("home-server.nvpn".to_string(), initial_ip);
    updated.insert("pi.nvpn".to_string(), new_ip);
    server.update_records(updated);

    let post = send_dns_query(&socket, server_addr, "pi.nvpn.", RecordType::A);
    assert_eq!(post.response_code, ResponseCode::NoError);
    let answer = post.answers.first().expect("expected answer after refresh");
    match &answer.data {
        RData::A(A(ip)) => assert_eq!(*ip, new_ip),
        other => panic!("unexpected answer data: {other:?}"),
    }

    // The original record must still resolve — refresh swaps the whole map.
    let still = send_dns_query(&socket, server_addr, "home-server.nvpn.", RecordType::A);
    assert_eq!(still.response_code, ResponseCode::NoError);

    server.stop();
}

fn send_dns_query(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    name: &str,
    record_type: RecordType,
) -> Message {
    let mut request = Message::new(42, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
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
