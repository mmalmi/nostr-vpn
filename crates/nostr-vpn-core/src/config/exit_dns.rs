pub const CLOUDFLARE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
pub const CLOUDFLARE_DOH_BOOTSTRAP_IPS: &[&str] = &["1.1.1.1", "1.0.0.1"];
pub const QUAD9_DOH_URL: &str = "https://dns.quad9.net/dns-query";
pub const QUAD9_DOH_BOOTSTRAP_IPS: &[&str] = &["9.9.9.9", "149.112.112.112"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExitDnsMode {
    #[default]
    Automatic,
    Encrypted,
    ThroughExit,
}

impl ExitDnsMode {
    pub fn is_automatic(&self) -> bool {
        *self == Self::Automatic
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Encrypted => "encrypted",
            Self::ThroughExit => "through_exit",
        }
    }
}

impl std::str::FromStr for ExitDnsMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "automatic" | "auto" => Ok(Self::Automatic),
            "encrypted" | "encrypted_dns" | "doh" => Ok(Self::Encrypted),
            "through_exit" | "exit" | "dns_through_exit" => Ok(Self::ThroughExit),
            _ => Err("expected one of: automatic, encrypted, through_exit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExitDohProvider {
    #[default]
    Cloudflare,
    Quad9,
    Custom,
}

impl ExitDohProvider {
    pub fn is_cloudflare(&self) -> bool {
        *self == Self::Cloudflare
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Quad9 => "quad9",
            Self::Custom => "custom",
        }
    }
}

impl std::str::FromStr for ExitDohProvider {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cloudflare" => Ok(Self::Cloudflare),
            "quad9" => Ok(Self::Quad9),
            "custom" => Ok(Self::Custom),
            _ => Err("expected one of: cloudflare, quad9, custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitDnsConfig {
    #[serde(default, skip_serializing_if = "ExitDnsMode::is_automatic")]
    pub mode: ExitDnsMode,
    #[serde(default, skip_serializing_if = "ExitDohProvider::is_cloudflare")]
    pub doh_provider: ExitDohProvider,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub custom_doh_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_doh_bootstrap_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub through_exit_servers: Vec<String>,
}

impl Default for ExitDnsConfig {
    fn default() -> Self {
        Self {
            mode: ExitDnsMode::Automatic,
            doh_provider: ExitDohProvider::Cloudflare,
            custom_doh_url: String::new(),
            custom_doh_bootstrap_ips: Vec::new(),
            through_exit_servers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitDnsResolverConfig {
    Doh {
        url: String,
        bootstrap_ips: Vec<IpAddr>,
    },
    ThroughExit {
        servers: Vec<IpAddr>,
    },
    FailClosed,
}

impl ExitDnsResolverConfig {
    pub fn through_exit_servers(&self) -> &[IpAddr] {
        match self {
            Self::Doh { .. } => &[],
            Self::ThroughExit { servers } => servers,
            Self::FailClosed => &[],
        }
    }
}

impl ExitDnsConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn normalize(&mut self) {
        self.custom_doh_url = self.custom_doh_url.trim().to_string();
        normalize_string_values(&mut self.custom_doh_bootstrap_ips);
        normalize_string_values(&mut self.through_exit_servers);
    }

    pub fn resolver_config(
        &self,
        wireguard_exit: Option<&WireGuardExitConfig>,
    ) -> Result<ExitDnsResolverConfig> {
        match self.mode {
            ExitDnsMode::Automatic => {
                if let Some(wireguard) = wireguard_exit
                    && !wireguard.dns.is_empty()
                {
                    return Ok(ExitDnsResolverConfig::ThroughExit {
                        servers: parse_exit_dns_ips(&wireguard.dns, "WireGuard profile DNS")?,
                    });
                }
                preset_doh_resolver_config(ExitDohProvider::Cloudflare)
            }
            ExitDnsMode::Encrypted => match self.doh_provider {
                ExitDohProvider::Cloudflare | ExitDohProvider::Quad9 => {
                    preset_doh_resolver_config(self.doh_provider)
                }
                ExitDohProvider::Custom => {
                    if self.custom_doh_url.is_empty() {
                        return Err(anyhow!("custom encrypted DNS requires an HTTPS URL"));
                    }
                    // Validate in the settings path itself so untrusted local
                    // clients cannot persist a poisoned resolver even when the
                    // secure-dns client code is not compiled in.
                    validate_doh_url_shape(&self.custom_doh_url)
                        .map_err(|error| anyhow!(error))?;
                    let bootstrap_ips = parse_exit_dns_ips(
                        &self.custom_doh_bootstrap_ips,
                        "custom encrypted DNS bootstrap IPs",
                    )?;
                    validate_doh_bootstrap_ips(&bootstrap_ips)
                        .map_err(|error| anyhow!(error))?;
                    Ok(ExitDnsResolverConfig::Doh {
                        url: self.custom_doh_url.clone(),
                        bootstrap_ips,
                    })
                }
            },
            ExitDnsMode::ThroughExit => Ok(ExitDnsResolverConfig::ThroughExit {
                servers: parse_exit_dns_ips(
                    &self.through_exit_servers,
                    "DNS-through-exit servers",
                )?,
            }),
        }
    }
}

fn preset_doh_resolver_config(provider: ExitDohProvider) -> Result<ExitDnsResolverConfig> {
    let (url, bootstrap) = match provider {
        ExitDohProvider::Cloudflare => (CLOUDFLARE_DOH_URL, CLOUDFLARE_DOH_BOOTSTRAP_IPS),
        ExitDohProvider::Quad9 => (QUAD9_DOH_URL, QUAD9_DOH_BOOTSTRAP_IPS),
        ExitDohProvider::Custom => {
            return Err(anyhow!("custom encrypted DNS requires explicit settings"));
        }
    };
    Ok(ExitDnsResolverConfig::Doh {
        url: url.to_string(),
        bootstrap_ips: bootstrap
            .iter()
            .map(|ip| ip.parse::<IpAddr>().expect("built-in DNS IP is valid"))
            .collect(),
    })
}

fn parse_exit_dns_ips(values: &[String], label: &str) -> Result<Vec<IpAddr>> {
    if values.is_empty() {
        return Err(anyhow!("{label} require at least one IP address"));
    }
    let mut ips = values
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .with_context(|| format!("invalid {label} address '{value}'"))
        })
        .collect::<Result<Vec<_>>>()?;
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

fn normalize_string_values(values: &mut Vec<String>) {
    *values = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
}

/// Custom DoH endpoints must be canonical HTTPS URLs that name a real DNS
/// hostname. Settings for the machine-wide resolver arrive from untrusted
/// local clients, so IP literals, credentials, fragments, and malformed
/// hostnames are rejected here rather than only when the resolver is built.
pub fn validate_doh_url_shape(endpoint: &str) -> Result<(), String> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| "DoH URL must use https".to_string())?;
    if rest.contains('#') {
        return Err("DoH URL must not contain a fragment".to_string());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err("DoH URL has no host".to_string());
    }
    if authority.contains('@') {
        return Err("DoH URL must not contain credentials".to_string());
    }
    if authority.starts_with('[') {
        return Err("DoH URL must name a DNS hostname, not an IP address".to_string());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| "DoH URL has no usable HTTPS port".to_string())?;
            if port == 0 {
                return Err("DoH URL has no usable HTTPS port".to_string());
            }
            host
        }
        None => authority,
    };
    if host.parse::<IpAddr>().is_ok() {
        return Err("DoH URL must name a DNS hostname, not an IP address".to_string());
    }
    validate_doh_hostname(host)
}

fn validate_doh_hostname(host: &str) -> Result<(), String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err("DoH URL hostname length is invalid".to_string());
    }
    let labels: Vec<&str> = host.split('.').collect();
    // Single-label names cannot receive a publicly trusted TLS certificate
    // and would resolve only through search-domain suffixes.
    if labels.len() < 2 {
        return Err("DoH URL must use a fully qualified DNS hostname".to_string());
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err("DoH URL hostname label length is invalid".to_string());
        }
        let ascii_label = label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !ascii_label || label.starts_with('-') || label.ends_with('-') {
            return Err(format!("DoH URL hostname label '{label}' is invalid"));
        }
    }
    Ok(())
}

/// Bootstrap IPs are contacted before DNS itself works, so they must be
/// globally routable: loopback, link-local, private, and unspecified targets
/// would let a settings writer pivot the encrypted DNS client at the local
/// host or an internal network.
pub fn validate_doh_bootstrap_ips(bootstrap_ips: &[IpAddr]) -> Result<(), String> {
    if bootstrap_ips.is_empty() {
        return Err("DoH requires at least one bootstrap IP".to_string());
    }
    for ip in bootstrap_ips {
        if is_non_global_ip(*ip) {
            return Err(format!("DoH bootstrap IP {ip} must be a public address"));
        }
    }
    Ok(())
}

fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_private()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => is_non_global_ip(IpAddr::V4(ip)),
            None => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local
                    || (ip.segments()[0] & 0xfe00) == 0xfc00 // unique local
            }
        },
    }
}
