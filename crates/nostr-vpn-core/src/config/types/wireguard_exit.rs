#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardExitConfig {
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    #[serde(
        default = "default_wireguard_exit_interface",
        skip_serializing_if = "wireguard_exit_interface_is_default"
    )]
    pub interface: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address_v6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_preshared_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(
        default = "default_wireguard_exit_allowed_ips",
        skip_serializing_if = "wireguard_exit_allowed_ips_is_default"
    )]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(
        default = "default_wireguard_exit_mtu",
        skip_serializing_if = "wireguard_exit_mtu_is_default"
    )]
    pub mtu: u16,
    #[serde(
        default = "default_wireguard_exit_persistent_keepalive_secs",
        skip_serializing_if = "wireguard_exit_persistent_keepalive_secs_is_default"
    )]
    pub persistent_keepalive_secs: u16,
}

impl Default for WireGuardExitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_wireguard_exit_interface(),
            address: String::new(),
            address_v6: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            peer_preshared_key: String::new(),
            endpoint: String::new(),
            allowed_ips: default_wireguard_exit_allowed_ips(),
            dns: Vec::new(),
            mtu: default_wireguard_exit_mtu(),
            persistent_keepalive_secs: default_wireguard_exit_persistent_keepalive_secs(),
        }
    }
}

impl WireGuardExitConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn configured(&self) -> bool {
        !self.address.trim().is_empty()
            && !self.private_key.trim().is_empty()
            && !self.peer_public_key.trim().is_empty()
            && !self.endpoint.trim().is_empty()
    }

    pub fn dns_server_ips(&self) -> Vec<IpAddr> {
        let mut servers = self
            .dns
            .iter()
            .filter_map(|server| server.trim().parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        servers.sort_unstable();
        servers.dedup();
        servers
    }
}

pub fn parse_wireguard_exit_config(raw: &str) -> Result<WireGuardExitConfig> {
    let mut config = WireGuardExitConfig {
        allowed_ips: Vec::new(),
        ..WireGuardExitConfig::default()
    };
    let mut section = WireGuardConfigSection::None;
    let mut saw_interface = false;
    let mut saw_peer = false;
    let mut addresses = Vec::new();

    for (line_index, raw_line) in raw.lines().enumerate() {
        let line_no = line_index + 1;
        let line = strip_wireguard_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section_name) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            let section_name = section_name.trim().to_ascii_lowercase();
            section = match section_name.as_str() {
                "interface" => {
                    saw_interface = true;
                    WireGuardConfigSection::Interface
                }
                "peer" => {
                    if saw_peer {
                        return Err(anyhow!(
                            "WireGuard upstream import supports exactly one peer; extra [Peer] at line {line_no}"
                        ));
                    }
                    saw_peer = true;
                    WireGuardConfigSection::Peer
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard section [{section_name}] at line {line_no}"
                    ));
                }
            };
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("expected key = value at line {line_no}"))?;
        let key = normalize_wireguard_config_key(key);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if wireguard_config_key_is_shell_hook(&key) {
            return Err(anyhow!(
                "WireGuard hook directive at line {line_no} is not supported"
            ));
        }

        match section {
            WireGuardConfigSection::None => {
                return Err(anyhow!(
                    "WireGuard setting before any section at line {line_no}"
                ));
            }
            WireGuardConfigSection::Interface => match key.as_str() {
                "privatekey" => config.private_key = value.to_string(),
                "address" => addresses = parse_wireguard_address_list(value, line_no)?,
                "dns" => config.dns = parse_wireguard_value_list(value),
                "mtu" => config.mtu = parse_wireguard_u16(value, "MTU", line_no)?,
                "listenport" | "fwmark" | "table" | "saveconfig" => {
                    return Err(anyhow!(
                        "WireGuard interface setting '{key}' at line {line_no} is not supported by the upstream importer"
                    ));
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard interface setting '{key}' at line {line_no}"
                    ));
                }
            },
            WireGuardConfigSection::Peer => match key.as_str() {
                "publickey" => config.peer_public_key = value.to_string(),
                "presharedkey" => config.peer_preshared_key = value.to_string(),
                "endpoint" => config.endpoint = value.to_string(),
                "allowedips" => {
                    config.allowed_ips = parse_wireguard_allowed_ips(value, line_no)?;
                }
                "persistentkeepalive" => {
                    config.persistent_keepalive_secs =
                        parse_wireguard_u16(value, "PersistentKeepalive", line_no)?;
                }
                _ => {
                    return Err(anyhow!(
                        "unsupported WireGuard peer setting '{key}' at line {line_no}"
                    ));
                }
            },
        }
    }

    if !saw_interface {
        return Err(anyhow!(
            "WireGuard config is missing an [Interface] section"
        ));
    }
    if !saw_peer {
        return Err(anyhow!("WireGuard config is missing a [Peer] section"));
    }
    if !addresses.is_empty() {
        config.address = select_wireguard_exit_address(&addresses);
        config.address_v6 = select_wireguard_exit_address_v6(&addresses);
    }
    if config.allowed_ips.is_empty() {
        return Err(anyhow!("WireGuard peer is missing AllowedIPs"));
    }
    if !config.allowed_ips.iter().any(|route| route == "0.0.0.0/0") {
        return Err(anyhow!(
            "WireGuard upstream AllowedIPs must include 0.0.0.0/0"
        ));
    }

    normalize_wireguard_exit_config(&mut config);
    if config.address.trim().is_empty() {
        return Err(anyhow!("WireGuard interface is missing Address"));
    }
    if config.private_key.trim().is_empty() {
        return Err(anyhow!("WireGuard interface is missing PrivateKey"));
    }
    if config.peer_public_key.trim().is_empty() {
        return Err(anyhow!("WireGuard peer is missing PublicKey"));
    }
    if config.endpoint.trim().is_empty() {
        return Err(anyhow!("WireGuard peer is missing Endpoint"));
    }
    validate_wireguard_key(&config.private_key, "PrivateKey")?;
    validate_wireguard_key(&config.peer_public_key, "PublicKey")?;
    if !config.peer_preshared_key.trim().is_empty() {
        validate_wireguard_key(&config.peer_preshared_key, "PresharedKey")?;
    }
    Ok(config)
}

pub fn wireguard_exit_config_text(config: &WireGuardExitConfig) -> String {
    if !config.configured() {
        return String::new();
    }

    let mut address = config.address.clone();
    if !config.address_v6.trim().is_empty() {
        address.push_str(", ");
        address.push_str(config.address_v6.trim());
    }
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {}", config.private_key),
        format!("Address = {address}"),
    ];
    if !config.dns.is_empty() {
        lines.push(format!("DNS = {}", config.dns.join(", ")));
    }
    if config.mtu > 0 {
        lines.push(format!("MTU = {}", config.mtu));
    }

    lines.push(String::new());
    lines.push("[Peer]".to_string());
    lines.push(format!("PublicKey = {}", config.peer_public_key));
    if !config.peer_preshared_key.trim().is_empty() {
        lines.push(format!("PresharedKey = {}", config.peer_preshared_key));
    }
    lines.push(format!("Endpoint = {}", config.endpoint));
    lines.push(format!("AllowedIPs = {}", config.allowed_ips.join(", ")));
    if config.persistent_keepalive_secs > 0 {
        lines.push(format!(
            "PersistentKeepalive = {}",
            config.persistent_keepalive_secs
        ));
    }

    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireGuardConfigSection {
    None,
    Interface,
    Peer,
}

fn strip_wireguard_config_comment(line: &str) -> &str {
    line.split(['#', ';']).next().unwrap_or(line)
}

fn normalize_wireguard_config_key(key: &str) -> String {
    key.trim()
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn wireguard_config_key_is_shell_hook(key: &str) -> bool {
    matches!(
        key,
        "preup" | "postup" | "predown" | "postdown" | "preupcmd" | "postupcmd"
    )
}

fn parse_wireguard_value_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_wireguard_address_list(value: &str, line_no: usize) -> Result<Vec<String>> {
    parse_wireguard_value_list(value)
        .into_iter()
        .map(|address| normalize_wireguard_address(&address, line_no))
        .collect()
}

fn normalize_wireguard_address(value: &str, line_no: usize) -> Result<String> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid WireGuard Address '{value}' at line {line_no}"))?;
    let ip: std::net::IpAddr = ip
        .trim()
        .parse()
        .with_context(|| format!("invalid WireGuard Address IP '{value}' at line {line_no}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .with_context(|| format!("invalid WireGuard Address prefix '{value}' at line {line_no}"))?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(anyhow!(
            "invalid WireGuard Address prefix '{value}' at line {line_no}"
        ));
    }
    Ok(format!("{ip}/{prefix}"))
}

fn select_wireguard_exit_address(addresses: &[String]) -> String {
    wireguard_address_in_family(addresses, |ip| ip.is_ipv4())
        .or_else(|| addresses.first().cloned())
        .unwrap_or_default()
}

fn select_wireguard_exit_address_v6(addresses: &[String]) -> String {
    wireguard_address_in_family(addresses, |ip| ip.is_ipv6()).unwrap_or_default()
}

fn wireguard_address_in_family(
    addresses: &[String],
    family: fn(std::net::IpAddr) -> bool,
) -> Option<String> {
    addresses
        .iter()
        .find(|address| {
            address
                .split_once('/')
                .and_then(|(ip, _)| ip.parse::<std::net::IpAddr>().ok())
                .is_some_and(family)
        })
        .cloned()
}

fn parse_wireguard_allowed_ips(value: &str, line_no: usize) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for route in parse_wireguard_value_list(value) {
        let normalized = normalize_advertised_route(&route).ok_or_else(|| {
            anyhow!("invalid WireGuard AllowedIPs route '{route}' at line {line_no}")
        })?;
        routes.push(normalized);
    }
    routes.sort();
    routes.dedup();
    Ok(routes)
}

fn parse_wireguard_u16(value: &str, field: &str, line_no: usize) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .with_context(|| format!("invalid WireGuard {field} '{value}' at line {line_no}"))
}

fn validate_wireguard_key(value: &str, field: &str) -> Result<()> {
    let raw = STANDARD
        .decode(value.trim())
        .with_context(|| format!("WireGuard {field} is not valid base64"))?;
    if raw.len() != 32 {
        return Err(anyhow!("WireGuard {field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

fn default_wireguard_exit_interface() -> String {
    "nvpn-wg-exit".to_string()
}

fn default_wireguard_exit_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string()]
}

fn default_wireguard_exit_mtu() -> u16 {
    1420
}

fn default_wireguard_exit_persistent_keepalive_secs() -> u16 {
    25
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn wireguard_exit_interface_is_default(value: &str) -> bool {
    value == default_wireguard_exit_interface()
}

fn wireguard_exit_allowed_ips_is_default(value: &[String]) -> bool {
    value == default_wireguard_exit_allowed_ips().as_slice()
}

fn wireguard_exit_mtu_is_default(value: &u16) -> bool {
    *value == default_wireguard_exit_mtu()
}

fn wireguard_exit_persistent_keepalive_secs_is_default(value: &u16) -> bool {
    *value == default_wireguard_exit_persistent_keepalive_secs()
}

fn default_exit_node_leak_protection() -> bool {
    false
}

fn normalize_wireguard_exit_config(config: &mut WireGuardExitConfig) {
    config.interface = config.interface.trim().to_string();
    if config.interface.is_empty() {
        config.interface = default_wireguard_exit_interface();
    }
    config.address = config.address.trim().to_string();
    config.address_v6 = config.address_v6.trim().to_string();
    config.private_key = config.private_key.trim().to_string();
    config.peer_public_key = config.peer_public_key.trim().to_string();
    config.peer_preshared_key = config.peer_preshared_key.trim().to_string();
    config.endpoint = config.endpoint.trim().to_string();
    config.allowed_ips = config
        .allowed_ips
        .iter()
        .filter_map(|route| normalize_advertised_route(route))
        .collect();
    config.allowed_ips.sort();
    config.allowed_ips.dedup();
    if config.allowed_ips.is_empty() {
        config.allowed_ips = default_wireguard_exit_allowed_ips();
    }
    config.dns = config
        .dns
        .iter()
        .map(|server| server.trim().to_string())
        .filter(|server| !server.is_empty())
        .collect();
    config.dns.sort();
    config.dns.dedup();
    if config.mtu == 0 {
        config.mtu = default_wireguard_exit_mtu();
    }
}
