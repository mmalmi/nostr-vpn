//! Linux application egress policy. Physical routes remain owned by the
//! network manager; only explicitly protected carrier sockets may use them.

use std::io::{self, Write};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::linux_host_network::CARRIER_MARK;

const TABLE: u32 = 20054;
const NFT_TABLE: &str = "nvpn_egress";
const ROUTE_PROTOCOL: u32 = 99;
const FORWARDED_MARK: u32 = CARRIER_MARK + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelPolicy {
    firewall: Option<Value>,
    routing: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForwardedExit {
    pub(crate) interface: String,
    pub(crate) source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GuardRoute {
    pub(crate) target: String,
    pub(crate) interface: String,
    pub(crate) gateway: Option<String>,
    /// A kernel-connected host subnet mirrored into the guard table so local
    /// destinations keep their native interface. Admission is by destination
    /// prefix, never by interface, so the native default route stays blocked.
    #[serde(default)]
    pub(crate) native: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinuxExitGuard {
    /// Opaque configuration ownership tag, never a path or account identifier.
    pub(crate) owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) vpn_sources: Vec<std::net::Ipv4Addr>,
    pub(crate) forwarded: Option<ForwardedExit>,
    pub(crate) interfaces: Vec<String>,
    pub(crate) routes: Vec<GuardRoute>,
}

impl LinuxExitGuard {
    /// The caller must durably save desired protection before this operation.
    /// Errors retain every already-installed protection; they never restore
    /// native application access as a rollback.
    pub(crate) fn apply(&self, previous: Option<&KernelPolicy>) -> io::Result<()> {
        self.validate()?;
        let owned = self.check_table_owner()?;
        // A firewall reload may remove our table while leaving the exact
        // routing state last observed by this process. Only that verified
        // state authorizes recovery without the firewall ownership tag.
        let known_routing = owned
            || match previous {
                Some(previous) if previous.firewall.is_some() => {
                    self.kernel_policy()?.routing == previous.routing
                }
                _ => false,
            };
        self.check_routes(known_routing)?;
        self.check_rules(known_routing)?;
        let old_sources = vpn_source_rules(known_routing)?;
        let old_forwarded = forwarded_source_rule_state(known_routing)?;
        // Block selected forwarding until both lookup and terminal rejection
        // rules exist. A first apply or interrupted repair must not briefly
        // send a buyer's packets through the host's physical default.
        self.apply_firewall(owned, false)?;
        for family in ["-4", "-6"] {
            ip(&[
                family,
                "route",
                "replace",
                if self.fail_closed {
                    "unreachable"
                } else {
                    "throw"
                },
                "default",
                "metric",
                "32760",
                "table",
                &TABLE.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ])?;
            for rule in rules(family) {
                if !rule.present()? {
                    rule.run("add")?;
                }
            }
        }
        // Initial application lookups use source 0; subsequent lookups and
        // reply validation use a tunnel source. Other source-validation flows
        // can use the native table without changing the application's route.
        // Explicit physical-source binds remain blocked by the firewall.
        for source in &self.vpn_sources {
            if !old_sources.contains(source) {
                vpn_source_rule("add", source)?;
            }
        }
        for source in old_sources {
            if !self.vpn_sources.contains(&source) {
                vpn_source_rule("del", &source)?;
            }
        }
        if old_forwarded != self.forwarded {
            if let Some(forwarded) = &self.forwarded {
                forwarded_source_rule("add", forwarded)?;
            }
            if let Some(forwarded) = &old_forwarded {
                forwarded_source_rule("del", forwarded)?;
            }
        }
        for route in &self.routes {
            route.run("replace")?;
        }
        for old in self.check_routes(true)? {
            // A replacement with the same prefix already superseded the old
            // interface/gateway. Deleting that old route would fail, or remove
            // the replacement on kernels that match only its prefix.
            if !self.routes.iter().any(|route| route.target == old.target) {
                old.run("del")?;
            }
        }
        if self.forwarded.is_some() {
            self.apply_firewall(true, true)?;
        }
        Ok(())
    }

    /// Call only for an explicit Direct/pause intent. Daemon restarts and
    /// temporary tunnel loss leave this guard installed.
    pub(crate) fn release(&self, previous: Option<&KernelPolicy>) -> io::Result<()> {
        self.validate()?;
        let owned = self.check_table_owner()?;
        if !owned {
            let known = match previous {
                Some(previous) if previous.firewall.is_some() => {
                    self.kernel_policy()?.routing == previous.routing
                }
                _ => false,
            };
            if !known {
                // A missing ownership tag is not evidence that cleanup is
                // complete. Report ambiguous leftovers without deleting them.
                self.check_routes(false)?;
                self.check_rules(false)?;
                vpn_source_rules(false)?;
                forwarded_source_rule_state(false)?;
                return Ok(());
            }
        }
        self.check_routes(true)?;
        self.check_rules(true)?;
        if let Some(forwarded) = forwarded_source_rule_state(true)? {
            forwarded_source_rule("del", &forwarded)?;
        }
        for source in vpn_source_rules(true)? {
            vpn_source_rule("del", &source)?;
        }
        for family in ["-4", "-6"] {
            for rule in rules(family) {
                if rule.present()? {
                    rule.run("del")?;
                }
            }
            ip(&[
                family,
                "route",
                "flush",
                "table",
                &TABLE.to_string(),
                "proto",
                &ROUTE_PROTOCOL.to_string(),
            ])?;
        }
        // Keep filtering until both policy tables have finished cleanup.
        if owned {
            nft(&format!("delete table inet {NFT_TABLE}\n"))
        } else {
            Ok(())
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.owner.is_empty()
            || self.owner.len() > 64
            || !self
                .owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid("invalid Linux guard ownership tag"));
        }
        for interface in &self.interfaces {
            validate_interface(interface)?;
        }
        if let Some(forwarded) = &self.forwarded {
            validate_interface(&forwarded.interface)?;
            if !validate_network_prefix(&forwarded.source)?.is_ipv4() {
                return Err(invalid("IPv6 seller forwarding is not supported"));
            }
        }
        let mut targets = std::collections::HashSet::new();
        for route in &self.routes {
            validate_interface(&route.interface)?;
            // Native routes bind host-connected subnets to their own physical
            // interfaces; only destination-scoped firewall admission is built
            // for them, so they never join the tunnel interface accept list.
            if !route.native && !self.interfaces.contains(&route.interface) {
                return Err(invalid("guard route uses an unadmitted interface"));
            }
            let address = validate_network_prefix(&route.target)?;
            if !targets.insert(route.target.as_str()) {
                return Err(invalid("duplicate guard route prefix"));
            }
            if let Some(gateway) = &route.gateway {
                let gateway: std::net::IpAddr = gateway
                    .parse()
                    .map_err(|_| invalid("invalid guard gateway"))?;
                if gateway.is_ipv4() != address.is_ipv4() {
                    return Err(invalid("guard gateway family mismatch"));
                }
            }
        }
        Ok(())
    }

    fn check_table_owner(&self) -> io::Result<bool> {
        Ok(self.firewall_state()?.is_some())
    }

    fn firewall_state(&self) -> io::Result<Option<Value>> {
        let tables = json_command("nft", &["-j", "list", "tables"])?;
        let exists = tables["nftables"].as_array().is_some_and(|tables| {
            tables.iter().any(|entry| {
                entry["table"]["family"] == "inet" && entry["table"]["name"] == NFT_TABLE
            })
        });
        if !exists {
            return Ok(None);
        }
        // Stateless output omits traffic counters; packets must not trigger
        // periodic policy rewrites or disrupt forwarding.
        let mut table = json_command("nft", &["-s", "-j", "list", "table", "inet", NFT_TABLE])?;
        let expected = format!("owner_{}", self.owner);
        if !table["nftables"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["chain"]["name"] == expected)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux egress firewall belongs to another configuration",
            ));
        }
        if let Some(entries) = table["nftables"].as_array_mut() {
            entries.retain(|entry| entry.get("metainfo").is_none());
        }
        Ok(Some(table))
    }

    pub(crate) fn kernel_policy(&self) -> io::Result<KernelPolicy> {
        let firewall = self.firewall_state()?;
        let mut routing = Vec::new();
        for family in ["-4", "-6"] {
            let reserved = rules(family)
                .iter()
                .map(|rule| rule.priority as u64)
                .chain([102, 104])
                .collect::<Vec<_>>();
            let all = json_command("ip", &["-j", "-N", family, "rule", "show"])?;
            routing.push(Value::Array(
                all.as_array()
                    .ok_or_else(|| invalid("invalid Linux rule response"))?
                    .iter()
                    .filter(|rule| {
                        rule["priority"]
                            .as_u64()
                            .is_some_and(|priority| reserved.contains(&priority))
                    })
                    .cloned()
                    .collect(),
            ));
            let all = json_command("ip", &["-j", "-N", family, "route", "show", "table", "all"])?;
            routing.push(Value::Array(
                all.as_array()
                    .ok_or_else(|| invalid("invalid Linux route response"))?
                    .iter()
                    .filter(|route| {
                        route["table"].as_u64() == Some(TABLE as u64)
                            || route["table"].as_str() == Some(&TABLE.to_string())
                    })
                    .cloned()
                    .collect(),
            ));
        }
        Ok(KernelPolicy { firewall, routing })
    }

    fn check_routes(&self, owned: bool) -> io::Result<Vec<GuardRoute>> {
        let mut routes = Vec::new();
        for family in ["-4", "-6"] {
            let all = json_command("ip", &["-j", "-N", family, "route", "show", "table", "all"])?;
            for route in all
                .as_array()
                .ok_or_else(|| invalid("invalid Linux route response"))?
            {
                if route["table"].as_u64() != Some(TABLE as u64)
                    && route["table"].as_str() != Some(&TABLE.to_string())
                {
                    continue;
                }
                if !owned
                    || (route["protocol"].as_u64() != Some(ROUTE_PROTOCOL as u64)
                        && route["protocol"].as_str() != Some(&ROUTE_PROTOCOL.to_string()))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "Linux egress route table contains foreign routes",
                    ));
                }
                if (route["type"] == "7" || route["type"] == "9")
                    && route["dst"] == "default"
                    && route["metric"] == 32760
                {
                    continue;
                }
                if route["metric"] != 100 {
                    return Err(invalid("Linux egress route ownership changed"));
                }
                let target = match route["dst"].as_str() {
                    Some("default") => if family == "-4" { "0.0.0.0/0" } else { "::/0" }.to_owned(),
                    Some(target) => {
                        if target.contains('/') {
                            target.to_owned()
                        } else {
                            format!("{target}/{}", if family == "-4" { 32 } else { 128 })
                        }
                    }
                    None => return Err(invalid("Linux egress route has no target")),
                };
                routes.push(GuardRoute {
                    target,
                    interface: route["dev"]
                        .as_str()
                        .ok_or_else(|| invalid("Linux egress route has no interface"))?
                        .to_owned(),
                    gateway: route["gateway"].as_str().map(str::to_owned),
                    native: false,
                });
            }
        }
        Ok(routes)
    }

    fn check_rules(&self, owned: bool) -> io::Result<()> {
        for family in ["-4", "-6"] {
            for rule in rules(family) {
                if rule.present()? && !owned {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "Linux egress rule is not owned by this configuration",
                    ));
                }
            }
        }
        Ok(())
    }

    fn apply_firewall(&self, owned: bool, forwarding_ready: bool) -> io::Result<()> {
        let mut script = if owned {
            format!("delete table inet {NFT_TABLE}\n")
        } else {
            String::new()
        };
        script.push_str(&format!(
            "table inet {NFT_TABLE} {{\n chain owner_{} {{ }}\n",
            self.owner
        ));
        if let Some(forwarded) = &self.forwarded {
            let action = if forwarding_ready {
                format!("meta mark set {FORWARDED_MARK}")
            } else {
                "drop".to_owned()
            };
            script.push_str(&format!(" chain forwarded {{\n type filter hook prerouting priority mangle; policy accept;\n iifname \"{}\" ip saddr {} {action}\n }}\n", forwarded.interface, forwarded.source));
        }
        if !self.fail_closed {
            // Keep VPN policy routing while honoring explicit native fallback.
            script.push_str("}\n");
            return nft(&script);
        }
        script.push_str(&fail_closed_output_chain(&self.interfaces, &self.routes));
        nft(&script)
    }
}

// The output chain admits tunnel interfaces by name, but native host subnets
// only by destination prefix: fall-through lookups that resolve the physical
// default route into a native interface must still be rejected.
fn fail_closed_output_chain(interfaces: &[String], routes: &[GuardRoute]) -> String {
    let mut chain = format!(
        " chain output {{\n type filter hook output priority 0; policy drop;\n oifname \"lo\" accept\n meta mark {CARRIER_MARK} accept\n"
    );
    for interface in interfaces {
        chain.push_str(&format!(" oifname \"{interface}\" accept\n"));
    }
    for route in routes.iter().filter(|route| route.native) {
        let family = if route.target.contains(':') {
            "ip6"
        } else {
            "ip"
        };
        chain.push_str(&format!(
            " oifname \"{}\" {family} daddr {} accept\n",
            route.interface, route.target
        ));
    }
    chain.push_str(" ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept\n meta skuid 0 udp sport 68 udp dport 67 accept\n meta skuid 0 udp sport 546 udp dport 547 accept\n counter reject with icmpx type admin-prohibited\n }\n}\n");
    chain
}

// This reserved rule priority is owned only while our nft ownership tag is
// present. Protocol 99 distinguishes it from unrelated address-based policy.
fn vpn_source_rule(action: &str, source: &std::net::Ipv4Addr) -> io::Result<()> {
    ip(&[
        "-4",
        "rule",
        action,
        "pref",
        "102",
        "from",
        &format!("{source}/32"),
        "iif",
        "lo",
        "lookup",
        "20054",
        "protocol",
        "99",
    ])
}

// The reverse lookup for a forwarded reply uses the buyer's address and the
// return interface. Scope this to the selected mesh ingress so unrelated
// forwarding keeps its native policy, including with strict rp_filter.
fn forwarded_source_rule(action: &str, forwarded: &ForwardedExit) -> io::Result<()> {
    ip(&[
        "-4",
        "rule",
        action,
        "pref",
        "104",
        "from",
        &forwarded.source,
        "iif",
        &forwarded.interface,
        "lookup",
        "20054",
        "protocol",
        "99",
    ])
}

fn forwarded_source_rule_state(owned: bool) -> io::Result<Option<ForwardedExit>> {
    let all = json_command("ip", &["-j", "-N", "-4", "rule", "show"])?;
    let mut result = None;
    for rule in all
        .as_array()
        .ok_or_else(|| invalid("invalid Linux rule response"))?
    {
        if rule["priority"] != 104 {
            continue;
        }
        let source = rule["src"].as_str().and_then(|source| {
            if source == "all" && rule["srclen"].is_null() {
                return Some("0.0.0.0/0".into());
            }
            let length = if rule["srclen"].is_null() {
                32
            } else {
                rule["srclen"].as_u64()?
            };
            (length <= 32).then(|| format!("{source}/{length}"))
        });
        let interface = rule["iif"].as_str();
        let exact = owned
            && result.is_none()
            && rule["table"] == "20054"
            && (rule["protocol"] == "99" || rule["protocol"] == 99)
            && source
                .as_deref()
                .is_some_and(|source| validate_network_prefix(source).is_ok_and(|ip| ip.is_ipv4()))
            && interface.is_some_and(|interface| validate_interface(interface).is_ok())
            && rule.as_object().is_some_and(|object| {
                object.keys().all(|key| {
                    ["priority", "src", "srclen", "iif", "table", "protocol"]
                        .contains(&key.as_str())
                })
            });
        if !exact {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux forwarded-source rule priority contains a foreign rule",
            ));
        }
        result = Some(ForwardedExit {
            source: source.unwrap(),
            interface: interface.unwrap().into(),
        });
    }
    Ok(result)
}

fn vpn_source_rules(owned: bool) -> io::Result<Vec<std::net::Ipv4Addr>> {
    let all = json_command("ip", &["-j", "-N", "-4", "rule", "show"])?;
    let mut sources = Vec::new();
    for rule in all
        .as_array()
        .ok_or_else(|| invalid("invalid Linux rule response"))?
    {
        if rule["priority"] != 102 {
            continue;
        }
        let source = rule["src"].as_str().and_then(|src| {
            src.strip_suffix("/32")
                .unwrap_or(src)
                .parse::<std::net::Ipv4Addr>()
                .ok()
        });
        let exact = owned
            && source.is_some()
            && rule["iif"] == "lo"
            && rule["table"] == "20054"
            && (rule["protocol"] == "99" || rule["protocol"] == 99)
            && rule.as_object().is_some_and(|object| {
                object.keys().all(|key| {
                    ["priority", "src", "iif", "table", "protocol"].contains(&key.as_str())
                })
            });
        if !exact || sources.contains(&source.unwrap()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux VPN-source rule priority contains a foreign rule",
            ));
        }
        sources.push(source.unwrap());
    }
    Ok(sources)
}

impl GuardRoute {
    fn run(&self, action: &str) -> io::Result<()> {
        let family = if self.target.contains(':') {
            "-6"
        } else {
            "-4"
        };
        let mut args = vec![
            family,
            "route",
            action,
            &self.target,
            "dev",
            &self.interface,
            "table",
            "20054",
            "metric",
            "100",
            "proto",
            "99",
        ];
        if let Some(gateway) = &self.gateway {
            args.extend(["via", gateway]);
        }
        ip(&args)
    }
}

struct Rule {
    family: &'static str,
    priority: u32,
    args: Vec<String>,
    fields: Vec<(&'static str, Value)>,
}

fn rules(family: &'static str) -> Vec<Rule> {
    let (source_port, destination_port) = if family == "-4" { (68, 67) } else { (546, 547) };
    let mut rules = vec![
        Rule {
            family,
            priority: 98,
            args: vec![
                "uidrange".into(),
                "0-0".into(),
                "ipproto".into(),
                "udp".into(),
                "sport".into(),
                source_port.to_string(),
                "dport".into(),
                destination_port.to_string(),
                "lookup".into(),
                "main".into(),
            ],
            fields: vec![
                ("uid_start", Value::from(0)),
                ("uid_end", Value::from(0)),
                ("ipproto", Value::from("ipproto-17")),
                ("sport", Value::from(source_port)),
                ("dport", Value::from(destination_port)),
                ("table", Value::from("254")),
            ],
        },
        Rule {
            family,
            priority: 100,
            args: vec![
                "fwmark".into(),
                CARRIER_MARK.to_string(),
                "lookup".into(),
                "main".into(),
            ],
            fields: vec![
                ("fwmark", Value::from(format!("0x{CARRIER_MARK:x}"))),
                ("table", Value::from("254")),
            ],
        },
        Rule {
            family,
            priority: 110,
            args: vec!["lookup".into(), TABLE.to_string()],
            fields: vec![("table", Value::from(TABLE.to_string()))],
        },
    ];
    if family == "-4" {
        rules.extend([
            Rule {
                family,
                priority: 101,
                args: vec![
                    "from".into(),
                    "0.0.0.0/32".into(),
                    "lookup".into(),
                    TABLE.to_string(),
                ],
                fields: vec![
                    ("src", Value::from("0.0.0.0")),
                    ("table", Value::from(TABLE.to_string())),
                ],
            },
            Rule {
                family,
                priority: 103,
                args: vec!["lookup".into(), "main".into()],
                fields: vec![("table", Value::from("254"))],
            },
        ]);
    }
    // RPDB rules also process forwarded packets. Restrict this host policy to
    // locally originated traffic so seller forwarding keeps its own routes.
    for rule in &mut rules {
        rule.args.extend(["iif".into(), "lo".into()]);
        rule.fields.push(("iif", Value::from("lo")));
    }
    // Only selected mesh ingress receives this mark. Paid forwarding must
    // never fall through to native egress, even if local apps allow fallback.
    rules.extend([
        Rule {
            family,
            priority: 105,
            args: vec![
                "fwmark".into(),
                FORWARDED_MARK.to_string(),
                "lookup".into(),
                TABLE.to_string(),
            ],
            fields: vec![
                ("fwmark", Value::from(format!("0x{FORWARDED_MARK:x}"))),
                ("table", Value::from(TABLE.to_string())),
            ],
        },
        Rule {
            family,
            priority: 106,
            args: vec![
                "fwmark".into(),
                FORWARDED_MARK.to_string(),
                "unreachable".into(),
            ],
            fields: vec![
                ("fwmark", Value::from(format!("0x{FORWARDED_MARK:x}"))),
                ("action", Value::from("7")),
            ],
        },
    ]);
    rules
}

impl Rule {
    fn present(&self) -> io::Result<bool> {
        let rules = json_command("ip", &["-j", "-N", self.family, "rule", "show"])?;
        let mut found = false;
        for rule in rules
            .as_array()
            .ok_or_else(|| invalid("invalid Linux rule response"))?
        {
            if rule["priority"].as_u64() != Some(self.priority as u64) {
                continue;
            }
            if found
                || self.fields.iter().any(|(key, value)| &rule[*key] != value)
                || (rule["src"] != "all" && !self.fields.iter().any(|(name, _)| *name == "src"))
                || rule.as_object().is_none_or(|object| {
                    object.iter().any(|(key, value)| {
                        // Recent iproute2 reports the exact port mask that
                        // older versions omit. Accept only full-width masks
                        // for a selector this rule actually owns.
                        let exact_port_mask = ((key == "sport_mask"
                            && self.fields.iter().any(|(name, _)| *name == "sport"))
                            || (key == "dport_mask"
                                && self.fields.iter().any(|(name, _)| *name == "dport")))
                            && (value.as_str() == Some("0xffff") || value.as_u64() == Some(65535));
                        key != "priority"
                            && key != "src"
                            && !self.fields.iter().any(|(name, _)| name == key)
                            && !exact_port_mask
                    })
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Linux egress rule priority contains a foreign rule",
                ));
            }
            found = true;
        }
        Ok(found)
    }

    fn run(&self, action: &str) -> io::Result<()> {
        let priority = self.priority.to_string();
        let mut args = vec![self.family, "rule", action, "pref", &priority];
        args.extend(self.args.iter().map(String::as_str));
        ip(&args)
    }
}

/// Mirror the host's kernel-connected subnets into the guard route list. An
/// exit default would otherwise capture local-subnet lookups, blackholing
/// the host's own LAN and container bridges, including replies from local
/// services to mesh buyers. Defaults and manager-owned policy routes stay
/// out: physical egress remains the network manager's to define.
pub(crate) fn host_connected_routes(exclude_interfaces: &[&str]) -> io::Result<Vec<GuardRoute>> {
    let mut routes = Vec::new();
    for family in ["-4", "-6"] {
        let table = json_command(
            "ip",
            &["-j", "-N", family, "route", "show", "table", "main"],
        )?;
        routes.extend(connected_routes_from_table(&table, exclude_interfaces));
    }
    Ok(routes)
}

fn connected_routes_from_table(table: &Value, exclude_interfaces: &[&str]) -> Vec<GuardRoute> {
    let Some(entries) = table.as_array() else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    for route in entries {
        if route["type"].as_str().is_some_and(|kind| kind != "unicast") {
            continue;
        }
        // Only kernel-maintained connected routes pin a local subnet. The
        // comparison tolerates numeric and named protocol rendering.
        let protocol = route["protocol"]
            .as_u64()
            .map(|protocol| protocol.to_string())
            .or_else(|| route["protocol"].as_str().map(str::to_owned));
        if protocol.as_deref() != Some("kernel") && protocol.as_deref() != Some("2") {
            continue;
        }
        // A default route has no destination; multipath entries carry no
        // single device. Both stay owned by the network manager.
        let (Some(target), Some(interface)) = (route["dst"].as_str(), route["dev"].as_str()) else {
            continue;
        };
        if validate_interface(interface).is_err()
            || exclude_interfaces.contains(&interface)
            || routes
                .iter()
                .any(|existing: &GuardRoute| existing.target == target)
        {
            continue;
        }
        routes.push(GuardRoute {
            target: target.to_owned(),
            interface: interface.to_owned(),
            gateway: None,
            native: true,
        });
    }
    routes
}

fn validate_interface(interface: &str) -> io::Result<()> {
    if interface.is_empty()
        || interface.len() > 15
        || interface == "lo"
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(invalid("invalid Linux exit interface"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn json_command(program: &str, args: &[&str]) -> io::Result<Value> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(io::Error::other)
}

fn ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ip: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn nft(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("nft stdin unavailable"))?
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn validate_network_prefix(target: &str) -> io::Result<std::net::IpAddr> {
    let Some((address, prefix)) = target.split_once('/') else {
        return Err(invalid("guard route must be an IP prefix"));
    };
    let address: std::net::IpAddr = address
        .parse()
        .map_err(|_| invalid("invalid guard route address"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| invalid("invalid guard route prefix"))?;
    if prefix > if address.is_ipv4() { 32 } else { 128 } {
        return Err(invalid("invalid guard route prefix"));
    }
    let host_bits = match address {
        std::net::IpAddr::V4(ip) => u128::from(u32::from(ip)) & ((1u128 << (32 - prefix)) - 1),
        std::net::IpAddr::V6(ip) => {
            u128::from(ip) & u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
        }
    };
    if host_bits != 0 || target != format!("{address}/{prefix}") {
        return Err(invalid("guard route must use a canonical network prefix"));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn connected_route_filter_keeps_only_kernel_unicast_subnets() {
        let table = json!([
            {"dst": "10.44.182.0/24", "dev": "eth0", "protocol": 2, "scope": 253, "type": "unicast"},
            {"dst": "192.168.1.0/24", "dev": "br-abc123", "protocol": "kernel", "type": "unicast"},
            {"dst": "fe80::/64", "dev": "eth0", "protocol": "kernel", "type": "unicast"},
            {"dst": "fd00:b0::/64", "dev": "br-abc123", "protocol": 2, "type": "unicast"},
            // Defaults and manager-owned policy routes stay native-table only.
            {"dev": "eth0", "protocol": "dhcp", "type": "unicast"},
            {"dst": "203.0.113.0/24", "dev": "eth0", "protocol": "dhcp", "type": "unicast"},
            {"dst": "198.51.100.0/24", "dev": "eth0", "protocol": 9, "type": "unicast"},
            {"dst": "172.17.0.0/16", "dev": "docker0", "protocol": 2, "type": "broadcast"},
            // Mesh and exit interfaces are excluded.
            {"dst": "10.44.55.0/24", "dev": "nvpn0", "protocol": 2, "type": "unicast"},
            // Loopback never passes interface validation; multipath entries
            // carry no single device.
            {"dst": "127.0.0.0/8", "dev": "lo", "protocol": 2, "type": "unicast"},
            {"dst": "10.9.0.0/16", "protocol": 2, "type": "unicast", "nexthops": []}
        ]);
        let routes = connected_routes_from_table(&table, &["nvpn0", "wgexit"]);
        let targets: Vec<&str> = routes.iter().map(|route| route.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "10.44.182.0/24",
                "192.168.1.0/24",
                "fe80::/64",
                "fd00:b0::/64"
            ]
        );
        assert!(
            routes
                .iter()
                .all(|route| route.native && route.gateway.is_none())
        );
    }

    #[test]
    fn fail_closed_chain_admits_native_subnets_only_by_destination() {
        let interfaces = vec!["nvpn0".to_owned(), "wgexit".to_owned()];
        let routes = vec![
            GuardRoute {
                target: "10.44.0.0/16".into(),
                interface: "nvpn0".into(),
                gateway: None,
                native: false,
            },
            GuardRoute {
                target: "10.44.182.0/24".into(),
                interface: "eth0".into(),
                gateway: None,
                native: true,
            },
            GuardRoute {
                target: "fe80::/64".into(),
                interface: "eth0".into(),
                gateway: None,
                native: true,
            },
            GuardRoute {
                target: "172.17.0.0/16".into(),
                interface: "docker0".into(),
                gateway: None,
                native: true,
            },
        ];
        let chain = fail_closed_output_chain(&interfaces, &routes);
        assert!(chain.contains("oifname \"nvpn0\" accept"), "{chain}");
        assert!(chain.contains("oifname \"wgexit\" accept"), "{chain}");
        // Native interfaces must never join the by-name accept list: the
        // physical default route resolves into them for fall-through flows.
        assert!(!chain.contains("oifname \"eth0\" accept"), "{chain}");
        assert!(!chain.contains("oifname \"docker0\" accept"), "{chain}");
        assert!(
            chain.contains("oifname \"eth0\" ip daddr 10.44.182.0/24 accept"),
            "{chain}"
        );
        assert!(
            chain.contains("oifname \"eth0\" ip6 daddr fe80::/64 accept"),
            "{chain}"
        );
        assert!(
            chain.contains("oifname \"docker0\" ip daddr 172.17.0.0/16 accept"),
            "{chain}"
        );
        assert!(
            chain.contains("counter reject with icmpx type admin-prohibited"),
            "{chain}"
        );
    }
}
