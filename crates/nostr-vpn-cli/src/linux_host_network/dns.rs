//! Carrier resolution uses native DNS configuration, but owns its sockets.
//! Calling the system resolver after VPN DNS takeover would recurse through
//! application DNS and deadlock payment/bootstrap recovery.

use super::*;
use hickory_proto::rr::{Name, RData};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use hickory_resolver::{
    Resolver, TlsConfig,
    config::{
        LookupIpStrategy, NameServerConfig, OpportunisticEncryption, OpportunisticEncryptionConfig,
        ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts,
    },
};

type DnsSocketProtector = Arc<dyn Fn(&socket2::SockRef<'_>) -> io::Result<()> + Send + Sync>;

mod config;
mod runtime;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
struct DnsLink {
    servers: Vec<NameServerConfig>,
    interface: Option<String>,
    domains: Vec<(Name, bool)>,
    default_route: bool,
    options: ResolverOpts,
    opportunistic: bool,
    insecure_domains: Vec<Name>,
}

#[derive(Clone, Debug)]
struct Snapshot {
    links: Vec<DnsLink>,
    fallback: Vec<DnsLink>,
    // resolved searches only single-label names; resolv.conf uses ndots.
    ndots: Option<usize>,
    ipv6: bool,
}

pub(super) struct UnderlayDns {
    source: Source,
    hosts: PathBuf,
}

enum Source {
    Resolved,
    Direct {
        path: PathBuf,
        previous: RwLock<Vec<u8>>,
    },
}

impl UnderlayDns {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            source: native_source(PathBuf::from("/etc/resolv.conf"))?,
            hosts: PathBuf::from("/etc/hosts"),
        })
    }

    pub(super) fn capture_direct_config(&self, bytes: &[u8]) -> io::Result<()> {
        if let Source::Direct { previous, .. } = &self.source
            && !managed_resolv_conf(bytes)
        {
            // Validate before replacing the last native configuration.
            config::direct(bytes)?;
            *previous
                .write()
                .map_err(|_| io::Error::other("native DNS configuration lock poisoned"))? =
                bytes.to_vec();
        }
        Ok(())
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        match &self.source {
            Source::Resolved => config::resolved(),
            Source::Direct { path, previous } => {
                let current = std::fs::read(path)?;
                if !managed_resolv_conf(&current) {
                    self.capture_direct_config(&current)?;
                }
                config::direct(
                    &previous
                        .read()
                        .map_err(|_| io::Error::other("native DNS configuration lock poisoned"))?,
                )
            }
        }
    }

    pub(super) async fn resolve(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> io::Result<Vec<SocketAddr>> {
        let local_name = host.trim_end_matches('.');
        if local_name.eq_ignore_ascii_case("localhost")
            || local_name.to_ascii_lowercase().ends_with(".localhost")
        {
            return Ok(vec![
                SocketAddr::from(([127, 0, 0, 1], port)),
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
            ]);
        }
        let this = self.clone();
        let name = local_name.to_owned();
        let (local, snapshot) = tokio::task::spawn_blocking(move || {
            let local = hosts_lookup(&this.hosts, &name, port)?;
            if !local.is_empty() {
                return Ok((local, None));
            }
            Ok::<_, io::Error>((local, Some(this.snapshot()?)))
        })
        .await
        .map_err(io::Error::other)??;
        if !local.is_empty() {
            return Ok(local);
        }
        snapshot
            .expect("snapshot exists when hosts lookup is empty")
            .resolve(host, port, Arc::new(protect_socket))
            .await
    }
}

fn native_source(path: PathBuf) -> io::Result<Source> {
    let previous = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    let resolved_target = std::fs::canonicalize(&path).is_ok_and(|target| {
        matches!(
            target.to_str(),
            Some("/run/systemd/resolve/resolv.conf" | "/run/systemd/resolve/stub-resolv.conf")
        )
    });
    let (configuration, _) = resolv_conf::Config::parse_with_errors(&previous);
    let resolved_stub = configuration.nameservers.iter().any(|server| {
        matches!(IpAddr::from(server), IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 53] || ip.octets() == [127, 0, 0, 54])
    });
    // Select the actual configured resolver, not the distribution/init system.
    // A resolved-owned file still requires its metadata; failed resolve1 reads
    // must not downgrade its split DNS, TLS or DNSSEC policy to plain DNS.
    Ok(if resolved_target || resolved_stub {
        Source::Resolved
    } else {
        Source::Direct {
            path,
            previous: RwLock::new(previous),
        }
    })
}

fn managed_resolv_conf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"# Managed by nvpn secure DNS\n")
}

fn hosts_lookup(path: &Path, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut addresses = Vec::new();
    for line in contents.lines() {
        let mut words = line.split('#').next().unwrap_or("").split_whitespace();
        let Some(ip) = words.next().and_then(|word| word.parse::<IpAddr>().ok()) else {
            continue;
        };
        if words.any(|alias| alias.eq_ignore_ascii_case(host)) {
            let address = SocketAddr::new(ip, port);
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    Ok(addresses)
}

impl Snapshot {
    fn candidates(&self, host: &str) -> io::Result<Vec<Name>> {
        let name = Name::from_utf8(host).map_err(io::Error::other)?;
        if name.is_fqdn() {
            return Ok(vec![name]);
        }
        let dots = host.bytes().filter(|byte| *byte == b'.').count();
        let search = self.ndots.is_some() || dots == 0;
        let absolute_first = self.ndots.map_or(dots > 0, |ndots| dots >= ndots);
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let mut names = Vec::new();
        if absolute_first {
            names.push(absolute.clone());
        }
        if search {
            for domain in self
                .links
                .iter()
                .flat_map(|link| &link.domains)
                .filter(|(_, routing)| !routing)
                .map(|(name, _)| name)
            {
                let candidate = name
                    .clone()
                    .append_domain(domain)
                    .map_err(io::Error::other)?;
                if !names.contains(&candidate) {
                    names.push(candidate);
                }
            }
        }
        // resolved does not send unqualified single-label names to public DNS.
        if !absolute_first && self.ndots.is_some() {
            names.push(absolute);
        }
        Ok(names)
    }

    fn selected_links(&self, name: &Name) -> Vec<&DnsLink> {
        let rank = |link: &DnsLink| {
            link.domains
                .iter()
                .filter(|(domain, _)| domain.zone_of(name))
                .map(|(domain, _)| domain.num_labels())
                .max()
        };
        let longest = self.links.iter().filter_map(rank).max();
        let selected: Vec<_> = self
            .links
            .iter()
            .filter(|link| match longest {
                Some(longest) => rank(link) == Some(longest),
                None => link.default_route,
            })
            .collect();
        if selected.is_empty() && longest.is_none() {
            self.fallback.iter().collect()
        } else {
            selected
        }
    }

    async fn resolve(
        &self,
        host: &str,
        port: u16,
        protect: DnsSocketProtector,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no usable native DNS result");
        for name in self.candidates(host)? {
            let selected = self.selected_links(&name);
            // .local is multicast unless explicitly routed to a native DNS link.
            if name.to_ascii().ends_with(".local.")
                && !selected.iter().any(|link| {
                    link.domains
                        .iter()
                        .any(|(domain, _)| domain.num_labels() > 0 && domain.zone_of(&name))
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "carrier multicast DNS is not configured",
                ));
            }
            let mut jobs = tokio::task::JoinSet::new();
            for link in selected {
                let name = name.clone();
                let protect = protect.clone();
                let link = link.clone();
                let ipv6 = self.ipv6;
                jobs.spawn(async move { lookup_link(link, name, port, ipv6, protect).await });
            }
            while let Some(result) = jobs.join_next().await {
                match result.map_err(io::Error::other)? {
                    Ok(addresses) if !addresses.is_empty() => return Ok(addresses),
                    Ok(_) => {}
                    Err(error) => last_error = error,
                }
            }
        }
        Err(last_error)
    }
}

async fn lookup_link(
    link: DnsLink,
    name: Name,
    port: u16,
    ipv6: bool,
    protect: DnsSocketProtector,
) -> io::Result<Vec<SocketAddr>> {
    let plaintext_only = !link.opportunistic
        && link
            .servers
            .iter()
            .flat_map(|server| &server.connections)
            .all(|connection| {
                matches!(
                    connection.protocol,
                    ProtocolConfig::Udp | ProtocolConfig::Tcp
                )
            });
    let mut options = link.options;
    options.ip_strategy = if ipv6 {
        LookupIpStrategy::Ipv4AndIpv6
    } else {
        LookupIpStrategy::Ipv4Only
    };
    options.use_hosts_file = ResolveHosts::Never;
    options.cache_size = 0;
    options.preserve_intermediates = true;
    if link
        .insecure_domains
        .iter()
        .any(|domain| domain.zone_of(&name))
    {
        options.validate = false;
    }
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(link.servers),
        runtime::ProtectedRuntime::new(protect, link.interface),
    )
    .with_options(options);
    if plaintext_only {
        // Hickory eagerly loads native TLS roots even for plaintext DNS. Reuse
        // that unused config; encrypted lookups still load fresh native roots.
        static TLS: OnceLock<TlsConfig> = OnceLock::new();
        if TLS.get().is_none() {
            let config = TlsConfig::new().map_err(io::Error::other)?;
            // Concurrent first lookups can initialize independently. Failed
            // initialization is never cached, so later lookups can recover.
            let _ = TLS.set(config);
        }
        builder = builder.with_tls_config(TLS.get().expect("TLS initialized").config.clone());
    }
    if link.opportunistic {
        builder = builder.with_opportunistic_encryption(OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        });
    }
    let addresses = builder
        .build()
        .map_err(io::Error::other)?
        .lookup_ip(name.clone())
        .await
        .map_err(io::Error::other)?;
    // LookupIp exposes every address record in the reply. Retain only the
    // requested owner and its CNAME chain, including across follow-up queries.
    let answers = addresses.as_lookup().answers();
    let mut names = vec![name];
    for _ in 0..8 {
        let next: Vec<_> = answers
            .iter()
            .filter(|record| names.contains(&record.name))
            .filter_map(|record| match &record.data {
                RData::CNAME(target) => Some(target.0.clone()),
                _ => None,
            })
            .filter(|name| !names.contains(name))
            .collect();
        if next.is_empty() {
            break;
        }
        names.extend(next);
    }
    let mut results = Vec::new();
    for record in answers.iter().filter(|record| names.contains(&record.name)) {
        if let Some(ip) = record.data.ip_addr() {
            let address = SocketAddr::new(ip, port);
            if !results.contains(&address) {
                results.push(address);
            }
        }
    }
    Ok(results)
}
