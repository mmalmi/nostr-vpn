use super::*;

pub(super) fn direct(bytes: &[u8]) -> io::Result<Snapshot> {
    if managed_resolv_conf(bytes) {
        return Err(invalid("native DNS configuration is owned by nVPN"));
    }
    let (config, errors) = resolv_conf::Config::parse_with_errors(bytes);
    let mut options = ResolverOpts::default();
    options.ndots = config.ndots as usize;
    options.timeout = std::time::Duration::from_secs(u64::from(config.timeout));
    options.attempts = config.attempts as usize;
    options.edns0 = config.edns0;
    let domains = config
        .get_last_search_or_domain()
        .filter(|domain| *domain != "--")
        .map(|domain| absolute_name(domain).map(|name| (name, false)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut grouped = std::collections::BTreeMap::<Option<String>, Vec<NameServerConfig>>::new();
    for scoped in &config.nameservers {
        let ip = IpAddr::from(scoped);
        if recursive_server(ip) {
            return Err(invalid("native DNS points to a local VPN/systemd listener"));
        }
        let interface = match scoped {
            resolv_conf::ScopedIp::V6(_, scope) => scope.clone(),
            _ => None,
        };
        #[cfg(target_os = "linux")]
        let interface = interface
            .map(|name| match name.parse::<u32>() {
                Ok(index) => interface_name(index),
                Err(_) => Ok(name),
            })
            .transpose()?;
        let server = if config.use_vc {
            NameServerConfig::tcp(ip)
        } else {
            NameServerConfig::udp_and_tcp(ip)
        };
        grouped.entry(interface).or_default().push(server);
    }
    // An offline host can install overlay DNS with no native upstream.
    // An empty link set keeps underlay DNS lookups local and unsuccessful.
    if grouped.is_empty() && !errors.is_empty() {
        return Err(invalid("invalid native DNS configuration"));
    }
    let links = grouped
        .into_iter()
        .map(|(interface, mut servers)| {
            if config.rotate {
                use rand::seq::SliceRandom;
                servers.shuffle(&mut rand::rng());
            }
            DnsLink {
                servers,
                interface,
                domains: domains.clone(),
                default_route: true,
                options: options.clone(),
                opportunistic: false,
                insecure_domains: Vec::new(),
            }
        })
        .collect();
    Ok(Snapshot {
        links,
        fallback: Vec::new(),
        ndots: Some(options.ndots),
        ipv6: !config.no_aaaa,
    })
}

fn recursive_server(ip: IpAddr) -> bool {
    ip == IpAddr::V4(crate::secure_dns_runtime::LINUX_DNS_IP)
        || ip == IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53))
        || ip == IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 54))
}

fn absolute_name(domain: &str) -> io::Result<Name> {
    let mut name = Name::from_utf8(domain).map_err(io::Error::other)?;
    name.set_fqdn(true);
    Ok(name)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn resolved() -> io::Result<Snapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "systemd DNS is Linux-only",
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn resolved() -> io::Result<Snapshot> {
    let connection = dbus::blocking::Connection::new_system().map_err(io::Error::other)?;
    resolved_connection(&connection)
}

#[cfg(target_os = "linux")]
pub(super) fn resolved_connection(connection: &dbus::blocking::Connection) -> io::Result<Snapshot> {
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    use std::collections::BTreeMap;
    const SERVICE: &str = "org.freedesktop.resolve1";
    const MANAGER: &str = "org.freedesktop.resolve1.Manager";
    const LINK: &str = "org.freedesktop.resolve1.Link";

    let manager = connection.with_proxy(
        SERVICE,
        "/org/freedesktop/resolve1",
        std::time::Duration::from_secs(1),
    );
    let servers = read_servers(&manager, "DNSEx", "DNS")?;
    let fallback = read_servers(&manager, "FallbackDNSEx", "FallbackDNS")?;
    let domains: Vec<(i32, String, bool)> =
        manager.get(MANAGER, "Domains").map_err(io::Error::other)?;
    let tls: String = manager
        .get(MANAGER, "DNSOverTLS")
        .map_err(io::Error::other)?;
    let dnssec: String = manager.get(MANAGER, "DNSSEC").map_err(io::Error::other)?;
    let global_anchors: Vec<String> = manager
        .get(MANAGER, "DNSSECNegativeTrustAnchors")
        .map_err(io::Error::other)?;
    let mut grouped = BTreeMap::<i32, Vec<Server>>::new();
    for server in servers {
        if server.address()?.is_some() {
            grouped.entry(server.index).or_default().push(server);
        }
    }
    let mut links = Vec::new();
    for (index, servers) in grouped {
        let domains = domains
            .iter()
            .filter(|(i, _, _)| *i == index)
            .map(|(_, name, routing)| absolute_name(name).map(|name| (name, *routing)))
            .collect::<io::Result<Vec<_>>>()?;
        let (interface, default_route, tls, dnssec, mut negative_anchors) = if index > 0 {
            let (path,): (dbus::Path<'static>,) = manager
                .method_call(MANAGER, "GetLink", (index,))
                .map_err(io::Error::other)?;
            let link = connection.with_proxy(SERVICE, path, std::time::Duration::from_secs(1));
            let default_route: bool = link.get(LINK, "DefaultRoute").map_err(io::Error::other)?;
            let link_tls: String = link.get(LINK, "DNSOverTLS").map_err(io::Error::other)?;
            let link_dnssec: String = link.get(LINK, "DNSSEC").map_err(io::Error::other)?;
            let anchors: Vec<String> = link
                .get(LINK, "DNSSECNegativeTrustAnchors")
                .map_err(io::Error::other)?;
            (
                Some(interface_name(index as u32)?),
                default_route,
                if link_tls.is_empty() {
                    tls.clone()
                } else {
                    link_tls
                },
                if link_dnssec.is_empty() {
                    dnssec.clone()
                } else {
                    link_dnssec
                },
                anchors,
            )
        } else {
            (None, true, tls.clone(), dnssec.clone(), Vec::new())
        };
        negative_anchors.extend(global_anchors.iter().cloned());
        links.push(DnsLink {
            servers: servers
                .iter()
                .map(|server| server.config(&tls))
                .collect::<io::Result<_>>()?,
            interface,
            domains,
            default_route,
            options: resolver_options(&dnssec)?,
            opportunistic: tls == "opportunistic",
            insecure_domains: negative_anchors
                .iter()
                .map(|name| absolute_name(name))
                .collect::<io::Result<_>>()?,
        });
    }
    let mut servers = Vec::new();
    for server in fallback {
        if server.address()?.is_some() {
            servers.push(server.config(&tls)?);
        }
    }
    Ok(Snapshot {
        links,
        fallback: if servers.is_empty() {
            Vec::new()
        } else {
            vec![DnsLink {
                servers,
                interface: None,
                domains: Vec::new(),
                default_route: true,
                options: resolver_options(&dnssec)?,
                opportunistic: tls == "opportunistic",
                insecure_domains: global_anchors
                    .iter()
                    .map(|name| absolute_name(name))
                    .collect::<io::Result<_>>()?,
            }]
        },
        ndots: None,
        ipv6: true,
    })
}

#[cfg(target_os = "linux")]
fn resolver_options(dnssec: &str) -> io::Result<ResolverOpts> {
    let mut options = ResolverOpts::default();
    options.validate = match dnssec {
        "no" | "" => false,
        "yes" | "allow-downgrade" => true,
        _ => return Err(invalid("unknown native DNSSEC policy")),
    };
    options.edns0 = true;
    Ok(options)
}

#[cfg(target_os = "linux")]
struct Server {
    index: i32,
    family: i32,
    bytes: Vec<u8>,
    port: u16,
    name: String,
}

#[cfg(target_os = "linux")]
impl Server {
    fn config(&self, tls: &str) -> io::Result<NameServerConfig> {
        let address = self
            .address()?
            .ok_or_else(|| invalid("recursive native DNS server"))?;
        let mut config = match tls {
            "no" | "" => NameServerConfig::udp_and_tcp(address.ip()),
            "yes" => NameServerConfig::tls(
                address.ip(),
                Arc::from(if self.name.is_empty() {
                    address.ip().to_string()
                } else {
                    self.name.clone()
                }),
            ),
            "opportunistic" => {
                let mut config = NameServerConfig::opportunistic_encryption(address.ip());
                if !self.name.is_empty() {
                    for connection in &mut config.connections {
                        if let hickory_resolver::config::ProtocolConfig::Tls { server_name } =
                            &mut connection.protocol
                        {
                            *server_name = Arc::from(self.name.as_str());
                        }
                    }
                }
                config
            }
            _ => return Err(invalid("unknown native DNS encryption policy")),
        };
        if self.port != 0 {
            for connection in &mut config.connections {
                connection.port = self.port;
            }
        }
        Ok(config)
    }

    fn address(&self) -> io::Result<Option<SocketAddr>> {
        let ip = match (self.family, self.bytes.as_slice()) {
            (libc::AF_INET, [a, b, c, d]) => IpAddr::V4(std::net::Ipv4Addr::new(*a, *b, *c, *d)),
            (libc::AF_INET6, bytes) if bytes.len() == 16 => IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).unwrap(),
            )),
            _ => return Err(invalid("invalid systemd DNS address")),
        };
        if recursive_server(ip) {
            return Ok(None);
        }
        let mut address = SocketAddr::new(ip, if self.port == 0 { 53 } else { self.port });
        if let SocketAddr::V6(address) = &mut address
            && address.ip().is_unicast_link_local()
        {
            address.set_scope_id(
                self.index
                    .try_into()
                    .map_err(|_| invalid("invalid DNS interface index"))?,
            );
        }
        Ok(Some(address))
    }
}

#[cfg(target_os = "linux")]
fn read_servers(
    manager: &dbus::blocking::Proxy<'_, &dbus::blocking::Connection>,
    extended: &str,
    legacy: &str,
) -> io::Result<Vec<Server>> {
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    type ExtendedServer = (i32, i32, Vec<u8>, u16, String);
    let result: Result<Vec<ExtendedServer>, dbus::Error> =
        manager.get("org.freedesktop.resolve1.Manager", extended);
    match result {
        Ok(servers) => Ok(servers
            .into_iter()
            .map(|(index, family, bytes, port, name)| Server {
                index,
                family,
                bytes,
                port,
                name,
            })
            .collect()),
        Err(error) if error.name() == Some("org.freedesktop.DBus.Error.UnknownProperty") => {
            let servers: Vec<(i32, i32, Vec<u8>)> = manager
                .get("org.freedesktop.resolve1.Manager", legacy)
                .map_err(io::Error::other)?;
            Ok(servers
                .into_iter()
                .map(|(index, family, bytes)| Server {
                    index,
                    family,
                    bytes,
                    port: 0,
                    name: String::new(),
                })
                .collect())
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

#[cfg(target_os = "linux")]
fn interface_name(index: u32) -> io::Result<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // The fixed buffer has the size required by if_indextoname.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(io::Error::other)
}
