use super::*;
use dbus::{
    blocking::Connection,
    channel::{Channel, MatchingReceiver},
    message::MatchRule,
};
use dbus_crossroads::{Crossroads, IfaceBuilder};
use hickory_resolver::config::ProtocolConfig;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::atomic::AtomicBool,
};

type DnsServers = Vec<(i32, i32, Vec<u8>, u16, String)>;
type Domains = Vec<(i32, String, bool)>;
type Shared = Arc<Mutex<(DnsServers, Domains)>>;

struct Bus {
    child: Child,
    address: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Bus {
    fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("private dbus-daemon fixture");
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().to_owned(),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        }
    }

    fn connection(&self) -> Connection {
        let mut channel = Channel::open_private(&self.address).unwrap();
        channel.register().unwrap();
        channel.into()
    }

    fn serve(&mut self, values: Shared, link_index: i32, tls: &'static str) {
        let connection = self.connection();
        connection
            .request_name("org.freedesktop.resolve1", false, true, true)
            .unwrap();
        let mut crossroads = Crossroads::new();
        let manager = crossroads.register(
            "org.freedesktop.resolve1.Manager",
            move |builder: &mut IfaceBuilder<Shared>| {
                builder
                    .property::<DnsServers, _>("DNSEx")
                    .get(|_, values| Ok(values.lock().unwrap().0.clone()));
                builder
                    .property::<DnsServers, _>("FallbackDNSEx")
                    .get(|_, _| Ok(Vec::new()));
                builder
                    .property::<Domains, _>("Domains")
                    .get(|_, values| Ok(values.lock().unwrap().1.clone()));
                builder
                    .property::<String, _>("DNSOverTLS")
                    .get(|_, _| Ok("no".into()));
                builder
                    .property::<String, _>("DNSSEC")
                    .get(|_, _| Ok("no".into()));
                builder
                    .property::<Vec<String>, _>("DNSSECNegativeTrustAnchors")
                    .get(|_, _| Ok(Vec::new()));
                builder.method(
                    "GetLink",
                    ("index",),
                    ("path",),
                    move |_, _, (index,): (i32,)| {
                        assert_eq!(
                            index, link_index,
                            "owned VPN DNS must not become an underlay link"
                        );
                        Ok((dbus::Path::from("/org/freedesktop/resolve1/link/fixture"),))
                    },
                );
            },
        );
        let link = crossroads.register(
            "org.freedesktop.resolve1.Link",
            move |builder: &mut IfaceBuilder<()>| {
                builder
                    .property::<bool, _>("DefaultRoute")
                    .get(|_, _| Ok(false));
                builder
                    .property::<String, _>("DNSOverTLS")
                    .get(move |_, _| Ok(tls.into()));
                builder
                    .property::<String, _>("DNSSEC")
                    .get(|_, _| Ok("yes".into()));
                builder
                    .property::<Vec<String>, _>("DNSSECNegativeTrustAnchors")
                    .get(|_, _| Ok(vec!["unsigned.office.example".into()]));
            },
        );
        crossroads.insert("/org/freedesktop/resolve1", &[manager], values);
        crossroads.insert("/org/freedesktop/resolve1/link/fixture", &[link], ());
        connection.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |message, connection| {
                crossroads.handle_message(message, connection).unwrap();
                true
            }),
        );
        let stop = self.stop.clone();
        self.worker = Some(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                connection
                    .process(std::time::Duration::from_millis(20))
                    .unwrap();
            }
        }));
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "requires dbus-daemon; run in the native Linux DNS fixture"]
fn systemd_properties_preserve_split_dns_security_and_refresh_without_the_vpn_stub() {
    let link_index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) } as i32;
    assert!(link_index > 0);
    let values: Shared = Arc::new(Mutex::new((
        vec![
            (0, libc::AF_INET, vec![203, 0, 113, 53], 0, String::new()),
            (0, libc::AF_INET, vec![127, 0, 0, 1], 0, String::new()),
            (
                0,
                libc::AF_INET6,
                std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
                0,
                String::new(),
            ),
            (
                link_index,
                libc::AF_INET,
                vec![192, 0, 2, 53],
                8853,
                "resolver.office.example".into(),
            ),
            (9999, libc::AF_INET, vec![127, 0, 0, 55], 53, String::new()),
            (
                9999,
                libc::AF_INET,
                vec![127, 0, 0, 55],
                1053,
                String::new(),
            ),
            (
                9999,
                libc::AF_INET,
                vec![127, 0, 0, 55],
                32553,
                String::new(),
            ),
        ],
        vec![
            (link_index, "office.example".into(), false),
            (9999, ".".into(), true),
        ],
    )));
    let mut bus = Bus::start();
    bus.serve(values.clone(), link_index, "yes");
    let connection = bus.connection();
    let snapshot = config::resolved_connection(&connection).unwrap();
    let selected = snapshot.selected_links(&Name::from_ascii("mint.office.example.").unwrap());
    assert_eq!(selected.len(), 1);
    let private = selected[0];
    assert_eq!(private.interface.as_deref(), Some("lo"));
    assert!(private.options.validate);
    assert!(!private.default_route);
    assert_eq!(
        private.insecure_domains,
        [Name::from_ascii("unsigned.office.example.").unwrap()]
    );
    assert_eq!(private.servers[0].connections.len(), 1);
    assert_eq!(private.servers[0].connections[0].port, 8853);
    assert!(
        matches!(&private.servers[0].connections[0].protocol, ProtocolConfig::Tls { server_name } if server_name.as_ref() == "resolver.office.example")
    );
    let public = snapshot.selected_links(&Name::from_ascii("relay.example.").unwrap());
    assert_eq!(public.len(), 1);
    assert_eq!(
        public[0].servers[0].ip,
        "203.0.113.53".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        public[0]
            .servers
            .iter()
            .map(|server| server.ip)
            .collect::<Vec<_>>(),
        ["203.0.113.53", "127.0.0.1", "::1"].map(|ip| ip.parse::<IpAddr>().unwrap())
    );
    let mut opportunistic = Bus::start();
    opportunistic.serve(values.clone(), link_index, "opportunistic");
    let snapshot = config::resolved_connection(&opportunistic.connection()).unwrap();
    let private = snapshot.selected_links(&Name::from_ascii("mint.office.example.").unwrap())[0];
    assert!(private.opportunistic);
    assert!(private.servers[0].connections.iter().any(|connection| {
        matches!(&connection.protocol, ProtocolConfig::Tls { server_name } if server_name.as_ref() == "resolver.office.example")
    }));
    values.lock().unwrap().0[3].2 = vec![192, 0, 2, 54];
    let refreshed = config::resolved_connection(&connection).unwrap();
    assert_eq!(
        refreshed.selected_links(&Name::from_ascii("mint.office.example.").unwrap())[0].servers[0]
            .ip,
        "192.0.2.54".parse::<IpAddr>().unwrap()
    );
}
