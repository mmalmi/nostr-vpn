#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{JoinHandle, sleep};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use nostr_vpn_core::config::{AppConfig, ExitDnsMode, ExitDohProvider, InternetSource};
use socket2::{Domain, Protocol, Socket, Type};

const NATIVE: &[u8] =
    b"# Fixture native resolver\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n";
const MANAGED: &[u8] =
    b"# Managed by nvpn secure DNS\nnameserver 127.0.0.55\noptions timeout:7 attempts:1\n";
const LEGACY: &[u8] =
    b"# Managed by nvpn secure DNS\nnameserver 127.0.0.1\noptions timeout:7 attempts:1\n";
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 42);
const IFACE: &str = "nvpndnsproof";
const WAIT: Duration = Duration::from_secs(35);
type ResolverSnapshot = (Vec<u8>, u64, i64, i64, i64, i64);

// Pass this executable and a production nvpn binary to
// scripts/test-linux-egress-lifecycle, with this exact test name as argument 3.
// The runner forces the direct/OpenRC resolver path, not systemd-resolved.
#[test]
#[ignore = "requires scripts/test-linux-egress-lifecycle and a Linux production daemon"]
fn linux_dns_coexistence_preserves_resolver_ownership() {
    assert_eq!(std::env::var("NVPN_EGRESS_ISOLATED").as_deref(), Ok("1"));
    assert!(Path::new("/var/lib/nvpn-egress-fixture").exists());
    let links = fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(links, vec![std::ffi::OsString::from("lo")]);
    assert!(Path::new("/run/openrc").exists());
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let root = std::env::temp_dir().join("nvpn-dns-coexistence");
    fs::create_dir(&root).unwrap();

    {
        let _native = NativeDns::start(None);
        let app = mesh_config();
        let mut fixture = Fixture::start(&root, "coexistence", &app);
        fixture.ready();
        assert_eq!(fs::read("/etc/resolv.conf").unwrap(), MANAGED);
        let name = app.self_magic_dns_name().unwrap();
        let expected = nostr_vpn_core::magic_dns::build_magic_dns_records(&app)[&name];
        let fips_name = format!(
            "{}.fips",
            nostr_vpn_core::config::npub_for_pubkey_hex(&app.own_nostr_pubkey_hex().unwrap())
        );
        for tcp in [false, true] {
            assert_native_dns(tcp);
            assert_a(
                &lookup("127.0.0.55:53", &name, RecordType::A, tcp),
                expected,
            );
            let response = lookup("127.0.0.55:53", &fips_name, RecordType::AAAA, tcp);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(
                response
                    .answers
                    .iter()
                    .any(|answer| matches!(&answer.data, RData::AAAA(_)))
            );
        }
        fixture.stop();
        assert_eq!(fs::read("/etc/resolv.conf").unwrap(), NATIVE);
        assert_native_dns(false);
    }

    // Split MagicDNS is UDP-only. Verify its actual listener address both
    // with the preferred port available and with a forced random-port bind.
    for fallback in [false, true] {
        let _native = NativeDns::start(None);
        let preferred: SocketAddr = "127.0.0.55:1053".parse().unwrap();
        let _occupied = fallback.then(|| {
            (
                UdpSocket::bind(preferred).unwrap(),
                TcpListener::bind(preferred).unwrap(),
            )
        });
        let mut app = mesh_config();
        app.fips_host_tunnel_enabled = false;
        let label = if fallback {
            "split-random"
        } else {
            "split-preferred"
        };
        let mut fixture = Fixture::start(&root, label, &app);
        let before = fixture.resolver_before.clone();
        let address = fixture.split_ready();
        assert_eq!(address.ip(), preferred.ip());
        if fallback {
            assert_ne!(address.port(), preferred.port());
            assert_ne!(address.port(), 0);
            assert!(fixture.log().contains("preferred port 1053 unavailable"));
        } else {
            assert_eq!(address, preferred);
        }
        let name = app.self_magic_dns_name().unwrap();
        let expected = nostr_vpn_core::magic_dns::build_magic_dns_records(&app)[&name];
        assert_a(
            &lookup(&address.to_string(), &name, RecordType::A, false),
            expected,
        );
        assert_eq!(resolver_snapshot(), before);
        assert!(fixture.journal()["secure_dns"].is_null());
        assert_native_dns(false);
        assert_native_dns(true);
        fixture.stop();
        assert_eq!(resolver_snapshot(), before);
        drop(UdpSocket::bind(address).expect("split DNS listener was released"));
    }

    // Test both bind orderings: a TCP-only conflict must release the UDP
    // socket it already acquired, and neither failure may write resolv.conf.
    for transport in ["UDP", "TCP"] {
        let _native = NativeDns::start(Some(transport));
        let mut fixture = Fixture::start(&root, &format!("optional-{transport}"), &mesh_config());
        let before = fixture.resolver_before.clone();
        fixture.ready();
        assert_eq!(resolver_snapshot(), before);
        assert!(fixture.journal()["secure_dns"].is_null());
        assert!(
            fixture.log().contains("native DNS"),
            "missing optional conflict diagnostic"
        );
        assert_native_dns(false);
        assert_native_dns(true);
        if transport == "TCP" {
            drop(UdpSocket::bind("127.0.0.55:53").expect("partial UDP listener was released"));
        }
        fixture.stop();
        assert_eq!(resolver_snapshot(), before);

        for policy in [
            "private-exit",
            "encrypted-dns",
            "wireguard",
            "leak-protection",
        ] {
            let mut app = mesh_config();
            match policy {
                "private-exit" => app.set_internet_source(InternetSource::PrivateVpn),
                "encrypted-dns" => {
                    app.set_internet_source(InternetSource::PrivateVpn);
                    app.exit_dns.mode = ExitDnsMode::Encrypted;
                    app.exit_dns.doh_provider = ExitDohProvider::Custom;
                    app.exit_dns.custom_doh_url = "https://dns.fixture.test/dns-query".into();
                    app.exit_dns.custom_doh_bootstrap_ips = vec!["192.0.2.53".into()];
                }
                "wireguard" => {
                    app.wireguard_exit.address = "10.77.0.2/32".into();
                    // Deterministic fixture keys; no peer is contacted because
                    // secure DNS must reject the conflict before WG setup.
                    use base64::Engine as _;
                    app.wireguard_exit.private_key =
                        base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
                    app.wireguard_exit.peer_public_key =
                        base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
                    app.wireguard_exit.endpoint = "192.0.2.2:51820".into();
                    app.set_internet_source(InternetSource::WireGuard);
                    assert!(app.wireguard_exit.enabled && app.wireguard_exit.configured());
                }
                "leak-protection" => app.exit_node_leak_protection = true,
                _ => unreachable!(),
            }
            let mut fixture = Fixture::start(&root, &format!("{policy}-{transport}"), &app);
            let before = fixture.resolver_before.clone();
            fixture.expect_bind_failure(transport);
            assert_eq!(resolver_snapshot(), before, "{policy} changed native DNS");
            assert!(fixture.journal()["secure_dns"].is_null());
            assert!(!Path::new("/sys/class/net").join(IFACE).exists());
            if transport == "TCP" {
                drop(UdpSocket::bind("127.0.0.55:53").expect("failed startup leaked UDP listener"));
            }
            assert_native_dns(false);
            fixture.release_exit_intent();
            assert_eq!(resolver_snapshot(), before, "cleanup changed native DNS");
        }
    }

    // Capture real cleanup journals from the production daemon. Only resolver
    // contents are replaced: old installations and a concurrent DHCP writer.
    let _native = NativeDns::start(None);
    for (label, current, expected) in [
        ("restore-current", MANAGED, NATIVE),
        ("restore-legacy", LEGACY, NATIVE),
        (
            "preserve-dhcp",
            b"# DHCP update\nnameserver 192.0.2.53\n".as_slice(),
            b"# DHCP update\nnameserver 192.0.2.53\n".as_slice(),
        ),
        ("preserve-foreign-prefix", &NATIVE[..12], &NATIVE[..12]),
    ] {
        let mut fixture = Fixture::start(&root, label, &mesh_config());
        fixture.ready();
        assert!(fixture.journal()["secure_dns"]["DirectResolvConf"].is_object());
        fixture.crash();
        fs::write("/etc/resolv.conf", current).unwrap();
        fixture.control("repair-network");
        assert_eq!(fs::read("/etc/resolv.conf").unwrap(), expected, "{label}");
        let repaired = resolver_snapshot();
        fixture.control("repair-network");
        assert_eq!(resolver_snapshot(), repaired, "repair must be idempotent");
        assert!(fixture.journal()["secure_dns"].is_null());
        drop(UdpSocket::bind("127.0.0.55:53").expect("repair left UDP listener"));
        drop(tcp_listener("127.0.0.55"));
    }
}

fn mesh_config() -> AppConfig {
    let mut app = AppConfig::generated();
    let own = app.own_nostr_pubkey_hex().unwrap();
    app.networks[0].enabled = true;
    app.networks[0].network_id = "dns-coexistence-fixture".into();
    app.networks[0].devices = vec![own.clone()];
    app.networks[0].admins = vec![own];
    app.networks[0].listen_for_join_requests = false;
    app.fips_host_tunnel_enabled = true;
    app.autoconnect = true;
    app.set_internet_source(InternetSource::Direct);
    app.exit_node_leak_protection = false;
    app.lan_discovery_enabled = false;
    app.fips_nostr_discovery_enabled = false;
    app.fips_webrtc_enabled = false;
    app.fips_bootstrap_enabled = false;
    app.fips_bootstrap_peers.clear();
    app.fips_websocket_seed_urls.clear();
    app.nostr.relays.clear();
    app.nat.enabled = false;
    app.nat.stun_servers.clear();
    app.node.listen_port = 51829;
    app.ensure_self_magic_dns_alias().unwrap();
    app
}

struct Fixture {
    dir: PathBuf,
    bin: String,
    daemon: Option<Child>,
    resolver_before: ResolverSnapshot,
}

impl Fixture {
    fn start(root: &Path, label: &str, app: &AppConfig) -> Self {
        let dir = root.join(label);
        fs::create_dir(&dir).unwrap();
        fs::write("/etc/resolv.conf", NATIVE).unwrap();
        let resolver_before = resolver_snapshot();
        fs::write(dir.join("config.toml"), app.plaintext_toml().unwrap()).unwrap();
        let bin = std::env::var("NVPN_TEST_BIN").expect("runner must supply production nvpn");
        let log = fs::File::create(dir.join("daemon.log")).unwrap();
        let daemon = Command::new(&bin)
            .args(["daemon", "--iface", IFACE, "--config"])
            .arg(dir.join("config.toml"))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Self {
            dir,
            bin,
            daemon: Some(daemon),
            resolver_before,
        }
    }

    fn state(&self) -> serde_json::Value {
        read_json(&self.dir.join("daemon.state.json"))
    }

    fn journal(&self) -> serde_json::Value {
        read_json(&self.dir.join(".nvpn-network-cleanup/daemon.cleanup.json"))
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("daemon.log")).unwrap_or_default()
    }

    fn ready(&mut self) {
        let deadline = Instant::now() + WAIT;
        while self.state()["vpn_enabled"] != true
            || !Path::new("/sys/class/net").join(IFACE).exists()
            || !self.dir.join("daemon.control.ready").exists()
        {
            assert!(
                self.daemon.as_mut().unwrap().try_wait().unwrap().is_none(),
                "startup failed: {}",
                self.log()
            );
            assert!(
                Instant::now() < deadline,
                "startup timeout: {}",
                self.state()
            );
            sleep(Duration::from_millis(50));
        }
        assert!(self.control("reload").contains("daemon reloaded"));
        assert!(self.daemon.as_mut().unwrap().try_wait().unwrap().is_none());
        assert!(Path::new("/sys/class/net").join(IFACE).exists());
        eprintln!(
            "{}: daemon ready",
            self.dir.file_name().unwrap().to_string_lossy()
        );
    }

    fn expect_bind_failure(&mut self, transport: &str) {
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.daemon.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "startup did not reject DNS conflict"
            );
            sleep(Duration::from_millis(50));
        };
        self.daemon.take();
        assert!(!status.success());
        let diagnostic = format!("failed to bind secure DNS {transport} on 127.0.0.55:53");
        assert!(
            self.log().contains(&diagnostic),
            "unexpected failure: {}",
            self.log()
        );
        let state = self.state();
        assert_eq!(state["vpn_active"], false);
        assert!(
            state["vpn_status"]
                .as_str()
                .unwrap_or_default()
                .contains(&diagnostic)
        );
        eprintln!(
            "{}: rejected {transport} conflict",
            self.dir.file_name().unwrap().to_string_lossy()
        );
    }

    fn split_ready(&mut self) -> SocketAddr {
        let deadline = Instant::now() + WAIT;
        loop {
            assert!(
                self.daemon.as_mut().unwrap().try_wait().unwrap().is_none(),
                "split DNS startup failed: {}",
                self.log()
            );
            let address = self.log().lines().rev().find_map(|line| {
                line.strip_prefix("magicdns: active for local names and .fips via ")
                    .and_then(|address| address.parse::<SocketAddr>().ok())
            });
            if self.dir.join("daemon.control.ready").exists()
                && let Some(address) = address
            {
                assert!(self.control("reload").contains("daemon reloaded"));
                assert!(self.daemon.as_mut().unwrap().try_wait().unwrap().is_none());
                eprintln!(
                    "{}: split DNS ready on {address}",
                    self.dir.file_name().unwrap().to_string_lossy()
                );
                return address;
            }
            assert!(
                Instant::now() < deadline,
                "split DNS startup timeout: {}",
                self.log()
            );
            sleep(Duration::from_millis(50));
        }
    }

    fn control(&self, action: &str) -> String {
        let out = fs::File::create(self.dir.join(format!("{action}.log"))).unwrap();
        let mut child = Command::new(&self.bin)
            .args([action, "--config"])
            .arg(self.dir.join("config.toml"))
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{action} timed out");
            }
            sleep(Duration::from_millis(50));
        };
        let log = fs::read_to_string(self.dir.join(format!("{action}.log"))).unwrap();
        assert!(status.success(), "{action}: {log}");
        log
    }

    fn stop(&mut self) {
        self.control("stop");
        let deadline = Instant::now() + WAIT;
        while self.daemon.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "stop timed out");
            sleep(Duration::from_millis(50));
        }
        self.daemon.take();
    }

    fn release_exit_intent(&mut self) {
        // A failed daemon deliberately retains exit intent. Start the same
        // owner paused with an explicit Direct choice to release its policy
        // through the production path before another fixture takes ownership.
        assert!(self.daemon.is_none());
        fs::rename(
            self.dir.join("daemon.log"),
            self.dir.join("rejected-startup.log"),
        )
        .unwrap();
        let config = self.dir.join("config.toml");
        let mut app = AppConfig::load(&config).unwrap();
        app.set_internet_source(InternetSource::Direct);
        app.autoconnect = false;
        app.fips_host_tunnel_enabled = false;
        app.fips_websocket_bind_addr.clear();
        app.paid_exit.enabled = false;
        app.exit_node_leak_protection = false;
        fs::write(&config, app.plaintext_toml().unwrap()).unwrap();
        let log = fs::File::create(self.dir.join("daemon.log")).unwrap();
        self.daemon = Some(
            Command::new(&self.bin)
                .args(["daemon", "--paused", "--iface", IFACE, "--config"])
                .arg(config)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + WAIT;
        while self.state()["vpn_status"] != "Paused"
            || !self.dir.join("daemon.control.ready").exists()
        {
            assert!(
                self.daemon.as_mut().unwrap().try_wait().unwrap().is_none(),
                "cleanup startup failed: {}",
                self.log()
            );
            assert!(
                Instant::now() < deadline,
                "paused cleanup timed out: {}",
                self.state()
            );
            sleep(Duration::from_millis(50));
        }
        assert!(self.control("reload").contains("daemon reloaded"));
        self.stop();
        assert!(
            !Command::new("nft")
                .args(["list", "table", "inet", "nvpn_egress"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "fixture left an egress guard"
        );
        if let Ok(entries) = fs::read_dir("/var/lib/nvpn/egress") {
            for entry in entries {
                let path = entry.unwrap().path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                {
                    let intent: serde_json::Value =
                        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    assert!(
                        intent["protection"].is_null(),
                        "fixture left active exit intent"
                    );
                }
            }
        }
    }

    fn crash(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            daemon.wait().unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.crash();
        if std::thread::panicking() {
            eprintln!("{}", self.log());
            for path in [
                "daemon.state.json",
                ".nvpn-network-cleanup/daemon.cleanup.json",
            ] {
                eprintln!("{path}: {:?}", fs::read_to_string(self.dir.join(path)));
            }
        }
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::Value::Null,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}

// Ignore atime, which reads may change; detect writes even if bytes are restored.
fn resolver_snapshot() -> ResolverSnapshot {
    let data = fs::read("/etc/resolv.conf").unwrap();
    let m = fs::metadata("/etc/resolv.conf").unwrap();
    (
        data,
        m.ino(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn encode(message: &Message) -> Vec<u8> {
    let mut bytes = Vec::new();
    message.emit(&mut BinEncoder::new(&mut bytes)).unwrap();
    bytes
}

fn lookup(address: &str, name: &str, kind: RecordType, tcp: bool) -> Message {
    let mut query = Message::new(42, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let request = encode(&query);
    let response = if tcp {
        let mut socket =
            TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(2)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .write_all(&(request.len() as u16).to_be_bytes())
            .unwrap();
        socket.write_all(&request).unwrap();
        let mut size = [0; 2];
        socket.read_exact(&mut size).unwrap();
        let mut packet = vec![0; u16::from_be_bytes(size) as usize];
        socket.read_exact(&mut packet).unwrap();
        packet
    } else {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send(&request).unwrap();
        let mut packet = vec![0; 4096];
        let size = socket.recv(&mut packet).unwrap();
        packet.truncate(size);
        packet
    };
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.id, 42);
    response
}

fn assert_a(response: &Message, expected: Ipv4Addr) {
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        response
            .answers
            .iter()
            .any(|answer| matches!(&answer.data, RData::A(address) if address.0 == expected))
    );
}

fn assert_native_dns(tcp: bool) {
    assert_a(
        &lookup("127.0.0.1:53", "native.fixture.test", RecordType::A, tcp),
        ANSWER,
    );
}

fn tcp_listener(ip: &str) -> TcpListener {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    let address: std::net::SocketAddr = format!("{ip}:53").parse().unwrap();
    socket.bind(&address.into()).unwrap();
    socket.listen(16).unwrap();
    socket.into()
}

struct NativeDns {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl NativeDns {
    fn start(wildcard: Option<&str>) -> Self {
        let udp = UdpSocket::bind(if wildcard == Some("UDP") {
            "0.0.0.0:53"
        } else {
            "127.0.0.1:53"
        })
        .unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let tcp = tcp_listener(if wildcard == Some("TCP") {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        });
        tcp.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let udp_stop = Arc::clone(&stop);
        let udp_worker = std::thread::spawn(move || {
            let mut packet = [0; 4096];
            while !udp_stop.load(Ordering::Relaxed) {
                if let Ok((size, peer)) = udp.recv_from(&mut packet)
                    && let Some(response) = native_response(&packet[..size])
                {
                    let _ = udp.send_to(&response, peer);
                }
            }
        });
        let tcp_stop = Arc::clone(&stop);
        let tcp_worker = std::thread::spawn(move || {
            while !tcp_stop.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = tcp.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                    let mut size = [0; 2];
                    if stream.read_exact(&mut size).is_ok() {
                        let mut packet = vec![0; u16::from_be_bytes(size) as usize];
                        if stream.read_exact(&mut packet).is_ok()
                            && let Some(response) = native_response(&packet)
                        {
                            let _ = stream.write_all(&(response.len() as u16).to_be_bytes());
                            let _ = stream.write_all(&response);
                        }
                    }
                } else {
                    sleep(Duration::from_millis(20));
                }
            }
        });
        Self {
            stop,
            workers: vec![udp_worker, tcp_worker],
        }
    }
}

impl Drop for NativeDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn native_response(packet: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(packet).ok()?;
    let mut response = Message::new(request.id, MessageType::Response, request.metadata.op_code);
    response.metadata.recursion_available = true;
    for query in request.queries {
        response.add_query(query.clone());
        if query.name.to_ascii() == "native.fixture.test." && query.query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(
                query.name,
                1,
                RData::A(rdata::A(ANSWER)),
            ));
        } else {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
    }
    Some(encode(&response))
}
