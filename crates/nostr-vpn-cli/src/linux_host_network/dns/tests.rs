use super::*;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::rr::{
    Record,
    rdata::{A, AAAA, CNAME},
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

struct Server {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Server {
    async fn start() -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let observed = seen.clone();
        let udp_task = tokio::spawn(async move {
            loop {
                let mut bytes = [0; 4096];
                let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..length]).unwrap();
                observed
                    .lock()
                    .unwrap()
                    .push(request.queries[0].name().to_ascii());
                let response = answer(request, true);
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        let tcp_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; usize::from(length)];
                stream.read_exact(&mut bytes).await.unwrap();
                let response = answer(Message::from_vec(&bytes).unwrap(), false);
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        Self {
            address,
            seen,
            tasks: vec![udp_task, tcp_task],
        }
    }

    fn link(&self, domains: &[(&str, bool)], default_route: bool) -> DnsLink {
        let mut server = NameServerConfig::udp_and_tcp(self.address.ip());
        for connection in &mut server.connections {
            connection.port = self.address.port();
        }
        DnsLink {
            servers: vec![server],
            interface: None,
            domains: domains
                .iter()
                .map(|(name, routing)| (Name::from_ascii(name).unwrap(), *routing))
                .collect(),
            default_route,
            options: ResolverOpts::default(),
            opportunistic: false,
            insecure_domains: Vec::new(),
        }
    }
}

fn answer(request: Message, truncated: bool) -> Vec<u8> {
    let query = request.queries[0].clone();
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.truncation = truncated;
    response.add_query(query.clone());
    if !truncated {
        let alias = Name::from_ascii("alias.internal.").unwrap();
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            30,
            RData::CNAME(CNAME(alias.clone())),
        ));
        let data = if query.query_type() == RecordType::A {
            RData::A(A("10.4.0.7".parse().unwrap()))
        } else {
            RData::AAAA(AAAA("2001:db8::7".parse().unwrap()))
        };
        response.add_answer(Record::from_rdata(alias, 30, data));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.invalid.").unwrap(),
            30,
            RData::A(A("203.0.113.6".parse().unwrap())),
        ));
    }
    let mut bytes = Vec::new();
    response.emit(&mut BinEncoder::new(&mut bytes)).unwrap();
    bytes
}

fn protector(denied: bool) -> (DnsSocketProtector, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let marked = count.clone();
    (
        Arc::new(move |socket| {
            assert!(
                socket.peer_addr().is_err(),
                "DNS socket connected before protection"
            );
            marked.fetch_add(1, Ordering::SeqCst);
            if denied {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture policy",
                ))
            } else {
                Ok(())
            }
        }),
        count,
    )
}

#[tokio::test]
async fn split_dns_keeps_private_queries_on_the_selected_link_and_protects_tcp_retry() {
    let private = Server::start().await;
    let public = Server::start().await;
    let snapshot = Snapshot {
        links: vec![
            private.link(&[("internal.", false)], false),
            public.link(&[], true),
        ],
        fallback: Vec::new(),
        ndots: None,
        ipv6: true,
    };
    let (policy, count) = protector(false);
    let addresses = snapshot
        .resolve("mint.internal", 8443, policy.clone())
        .await
        .unwrap();
    assert_eq!(
        addresses,
        vec![
            "10.4.0.7:8443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::7]:8443".parse::<SocketAddr>().unwrap()
        ]
    );
    assert_eq!(
        snapshot
            .resolve("mint.internal", 8443, policy)
            .await
            .unwrap(),
        addresses,
        "repeated lookups retain the selected link and protected socket policy"
    );
    assert!(
        count.load(Ordering::SeqCst) >= 6,
        "both UDP queries and their TCP retry are protected"
    );
    assert_eq!(
        *private.seen.lock().unwrap(),
        ["mint.internal."; 4],
        "TLS setup reuse must not cache DNS answers"
    );
    assert!(
        public.seen.lock().unwrap().is_empty(),
        "private name leaked to default DNS"
    );
}

#[tokio::test]
async fn denied_dns_socket_policy_sends_no_queries() {
    let server = Server::start().await;
    let snapshot = Snapshot {
        links: vec![server.link(&[], true)],
        fallback: Vec::new(),
        ndots: Some(1),
        ipv6: true,
    };
    let (policy, count) = protector(true);
    assert!(snapshot.resolve("mint.example.", 80, policy).await.is_err());
    assert!(count.load(Ordering::SeqCst) >= 2);
    assert!(server.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_search_and_absolute_names_keep_their_distinct_resolution_paths() {
    let server = Server::start().await;
    let snapshot = Snapshot {
        links: vec![server.link(&[("office.example.", false)], true)],
        fallback: Vec::new(),
        ndots: None,
        ipv6: false,
    };
    snapshot
        .resolve("mint", 443, protector(false).0)
        .await
        .unwrap();
    snapshot
        .resolve("mint.", 443, protector(false).0)
        .await
        .unwrap();
    assert_eq!(
        *server.seen.lock().unwrap(),
        ["mint.office.example.", "mint."]
    );
}

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("nvpn-native-dns-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn local_hosts_and_loopback_names_work_without_a_dns_service() {
    let files = Files::new();
    let hosts = files.0.join("hosts");
    std::fs::write(
        &hosts,
        "192.0.2.8 relay.private relay\n2001:db8::8 relay.private # note\n",
    )
    .unwrap();
    let resolver = Arc::new(UnderlayDns {
        source: Source::Direct {
            path: files.0.join("missing-resolv.conf"),
            previous: RwLock::new(Vec::new()),
        },
        hosts,
    });
    assert_eq!(
        resolver.resolve("RELAY.private.", 51820).await.unwrap(),
        vec![
            "192.0.2.8:51820".parse::<SocketAddr>().unwrap(),
            "[2001:db8::8]:51820".parse::<SocketAddr>().unwrap()
        ]
    );
    assert!(
        resolver
            .resolve("localhost", 80)
            .await
            .unwrap()
            .iter()
            .all(|address| address.ip().is_loopback())
    );
}

#[test]
fn direct_dns_refreshes_external_changes_without_reading_the_owned_listener() {
    let files = Files::new();
    let path = files.0.join("resolv.conf");
    std::fs::write(
        &path,
        b"nameserver 192.0.2.53\nsearch office.example\noptions ndots:2 no-aaaa\n",
    )
    .unwrap();
    let resolver = UnderlayDns {
        source: native_source(path.clone()).unwrap(),
        hosts: files.0.join("hosts"),
    };
    std::fs::write(
        &path,
        b"# Managed by nvpn secure DNS\nnameserver 127.0.0.1\n",
    )
    .unwrap();
    let before = resolver.snapshot().unwrap();
    assert_eq!(
        before.links[0].servers[0].ip,
        "192.0.2.53".parse::<IpAddr>().unwrap()
    );
    assert!(!before.ipv6);
    assert_eq!(
        before
            .candidates("mint.site")
            .unwrap()
            .iter()
            .map(Name::to_ascii)
            .collect::<Vec<_>>(),
        ["mint.site.office.example.", "mint.site."]
    );
    std::fs::write(&path, b"nameserver 192.0.2.54\nsearch new.example\n").unwrap();
    let after = resolver.snapshot().unwrap();
    assert_eq!(
        after.links[0].servers[0].ip,
        "192.0.2.54".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        after.candidates("mint").unwrap()[0].to_ascii(),
        "mint.new.example."
    );
    assert!(config::direct(b"nameserver 127.0.0.53\n").is_err());
}

#[tokio::test]
async fn required_dns_tls_protects_its_socket_and_does_not_fall_back_after_a_bad_certificate() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::{TlsAcceptor, rustls};
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["resolver.example".to_owned()]).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let plaintext = UdpSocket::bind(address).await.unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = tcp.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(socket).await else {
                continue;
            };
            let Ok(length) = stream.read_u16().await else {
                continue;
            };
            let mut query = vec![0; usize::from(length)];
            stream.read_exact(&mut query).await.unwrap();
            let response = answer(Message::from_vec(&query).unwrap(), false);
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        }
    });
    let mut server = NameServerConfig::tls(address.ip(), Arc::from("resolver.example"));
    server.connections[0].port = address.port();
    let mut options = ResolverOpts::default();
    options.ip_strategy = LookupIpStrategy::Ipv4Only;
    options.timeout = std::time::Duration::from_secs(1);
    options.attempts = 1;
    let (policy, count) = protector(false);
    let builder = || {
        Resolver::builder_with_config(
            ResolverConfig::from_name_servers(vec![server.clone()]),
            runtime::ProtectedRuntime::new(policy.clone(), None),
        )
        .with_options(options.clone())
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let trusted = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = builder().with_tls_config(trusted).build().unwrap();
    let answer = resolver.lookup_ip("mint.example.").await.unwrap();
    assert!(
        answer
            .iter()
            .any(|ip| ip == "10.4.0.7".parse::<IpAddr>().unwrap())
    );
    let verified = count.load(Ordering::SeqCst);
    assert!(verified > 0);
    drop(resolver);
    let untrusted = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(
        builder()
            .with_tls_config(untrusted)
            .build()
            .unwrap()
            .lookup_ip("mint.example.")
            .await
            .is_err()
    );
    assert!(
        count.load(Ordering::SeqCst) > verified,
        "TLS rejection still used a protected socket"
    );
    let plain = Server::start().await;
    lookup_link(
        plain.link(&[], true),
        Name::from_ascii("mint.example.").unwrap(),
        443,
        false,
        policy.clone(),
    )
    .await
    .unwrap();
    let link = DnsLink {
        servers: vec![server],
        interface: None,
        domains: Vec::new(),
        default_route: true,
        options,
        opportunistic: false,
        insecure_domains: Vec::new(),
    };
    assert!(
        lookup_link(
            link,
            Name::from_ascii("mint.example.").unwrap(),
            443,
            false,
            policy
        )
        .await
        .is_err(),
        "the production TLS path must reject an untrusted certificate after plain DNS setup"
    );
    let mut bytes = [0; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(30),
            plaintext.recv_from(&mut bytes)
        )
        .await
        .is_err(),
        "required TLS silently fell back to plaintext DNS"
    );
    task.abort();
}

#[tokio::test]
async fn required_dnssec_does_not_accept_an_unverifiable_answer() {
    let server = Server::start().await;
    let mut link = server.link(&[], true);
    link.options.validate = true;
    link.options.edns0 = true;
    link.options.attempts = 1;
    link.options.timeout = std::time::Duration::from_secs(1);
    let snapshot = Snapshot {
        links: vec![link],
        fallback: Vec::new(),
        ndots: Some(1),
        ipv6: false,
    };
    let (policy, count) = protector(false);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        snapshot.resolve("mint.example.", 443, policy),
    )
    .await
    .unwrap();
    assert!(result.is_err(), "native DNSSEC requirement was bypassed");
    assert!(count.load(Ordering::SeqCst) > 0);
    assert!(!server.seen.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[path = "tests/resolved.rs"]
mod resolved;

#[test]
fn native_resolver_selection_follows_resolv_conf_without_an_init_system_assumption() {
    let files = Files::new();
    let path = files.0.join("resolv.conf");
    for server in ["127.0.0.53", "127.0.0.54"] {
        std::fs::write(&path, format!("nameserver {server}\n")).unwrap();
        assert!(matches!(
            native_source(path.clone()).unwrap(),
            Source::Resolved
        ));
    }
    std::fs::write(&path, "nameserver 192.0.2.53\n").unwrap();
    assert!(matches!(
        native_source(path.clone()).unwrap(),
        Source::Direct { .. }
    ));
    #[cfg(unix)]
    {
        let link = files.0.join("resolver-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            native_source(link).unwrap(),
            Source::Direct { .. }
        ));
    }
}
