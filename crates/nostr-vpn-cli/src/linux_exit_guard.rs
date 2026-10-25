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
// Local ranges that must keep resolving through the main table while the
// customer tunnel owns the exit table's default route. Mirrors the
// local-network accepts rendered into the egress firewall's output chain.
const LOCAL_DESTINATION_TARGETS: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "fe80::/10",
    "fc00::/7",
];

fn local_destination_targets(family: &str) -> impl Iterator<Item = &'static str> {
    let want_ipv6 = family == "-6";
    LOCAL_DESTINATION_TARGETS
        .iter()
        .copied()
        .filter(move |target| target.contains(':') == want_ipv6)
}

// One unused priority per local range, all below the vpn-source (102),
// forwarded-source (104), and forwarded-kill-switch (105/106) rules so a
// local destination can never be captured into the exit table.
fn local_destination_rule_priority(family: &str, index: usize) -> u32 {
    if family == "-4" {
        90 + index as u32
    } else {
        96 + index as u32
    }
}

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
        // Retired mechanism: in-table throws for local ranges, superseded by
        // the local-destination rule priorities. Remove leftovers from earlier
        // releases before ownership validation, which rejects routes it cannot
        // attribute to an interface.
        for family in ["-4", "-6"] {
            for target in local_destination_targets(family) {
                let _ = ip(&[
                    family,
                    "route",
                    "del",
                    "throw",
                    target,
                    "table",
                    &TABLE.to_string(),
                ]);
            }
        }
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
            if !self.interfaces.contains(&route.interface) {
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
        let owned_tag = table["nftables"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["chain"]["name"] == expected)
        });
        // Only this daemon creates the table, so a tagless table whose every
        // chain matches our fingerprints belonged to an instance whose durable
        // intent was lost, such as a recreated host-network container. Adopt
        // it: the owned apply/release paths already delete and rebuild it.
        if !owned_tag && !foreign_table_is_adoptable(&table) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Linux egress firewall belongs to another configuration; remove it with: nft delete table inet nvpn_egress",
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
        script.push_str(&render_output_chain(&self.interfaces));
        script.push_str("}\n");
        nft(&script)
    }
}

// The kill switch guards internet egress only. Host-originated traffic to
// link-local and private destinations — docker bridges and published app
// ports on a shared host, LAN peers, mDNS, DHCP broadcast — must survive a
// fail-closed table, or the daemon jails the machine it runs on. Unmarked
// internet-bound output still rejects below.
fn render_output_chain(interfaces: &[String]) -> String {
    let mut chain = format!(
        " chain output {{\n type filter hook output priority 0; policy drop;\n oifname \"lo\" accept\n meta mark {CARRIER_MARK} accept\n"
    );
    for interface in interfaces {
        chain.push_str(&format!(" oifname \"{interface}\" accept\n"));
    }
    chain.push_str(" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } accept\n");
    chain.push_str(" ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept\n");
    chain.push_str(" ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept\n meta skuid 0 udp sport 68 udp dport 67 accept\n meta skuid 0 udp sport 546 udp dport 547 accept\n counter reject with icmpx type admin-prohibited\n }\n");
    chain
}

// A table whose every chain matches our fingerprints can only have been
// created by an instance of this daemon whose durable intent was lost. Its
// structure alone authorizes adoption by the owned path; any other chain
// keeps the table refused until it is removed explicitly. Entries without a
// chain, such as metainfo, impose nothing.
fn foreign_table_is_adoptable(table_json: &Value) -> bool {
    table_json["nftables"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .filter_map(|entry| entry["chain"]["name"].as_str())
            .all(|name| name.starts_with("owner_") || name == "forwarded" || name == "output")
    })
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
    // Local-destination traffic must resolve in main before the exit table's
    // default route or the forwarded kill switch can capture it. Docker
    // published ports DNAT in prerouting after the forwarded mark, so these
    // rules also carry mesh clients to services hosted on this machine.
    for (index, target) in local_destination_targets(family).enumerate() {
        rules.push(Rule {
            family,
            priority: local_destination_rule_priority(family, index),
            args: vec!["to".into(), target.to_string(), "lookup".into(), "main".into()],
            fields: vec![
                ("to", Value::from(target)),
                ("table", Value::from("254")),
            ],
        });
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

    fn table(chains: &[&str]) -> Value {
        serde_json::json!({
            "nftables": chains
                .iter()
                .map(|name| {
                    serde_json::json!({
                        "chain": {"family": "inet", "table": NFT_TABLE, "name": name}
                    })
                })
                .collect::<Vec<_>>()
        })
    }

    #[test]
    fn orphaned_tables_with_only_our_chain_fingerprints_are_adoptable() {
        let mut owned = table(&["owner_deadbeef01", "forwarded", "output"]);
        owned["nftables"].as_array_mut().unwrap().insert(
            0,
            serde_json::json!({"metainfo": {"version": "1.1.0", "release_name": "libnftables"}}),
        );
        assert!(foreign_table_is_adoptable(&owned));
        // A tagless instance may already have torn its chains down.
        assert!(foreign_table_is_adoptable(&table(&[])));
    }

    #[test]
    fn a_foreign_chain_name_refuses_table_adoption() {
        assert!(!foreign_table_is_adoptable(&table(&[
            "owner_deadbeef01",
            "docker-user-chain"
        ])));
        assert!(!foreign_table_is_adoptable(&Value::Null));
        assert!(!foreign_table_is_adoptable(
            &serde_json::json!({"nftables": {}})
        ));
    }

    #[test]
    fn output_chain_jails_only_internet_egress() {
        let chain = render_output_chain(&["end0".to_owned()]);
        assert!(
            chain.contains(" type filter hook output priority 0; policy drop;\n"),
            "the kill switch must stay fail closed"
        );
        assert!(chain.contains(" oifname \"end0\" accept\n"));
        let local = chain
            .find(" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } accept\n")
            .expect("local-network accept");
        assert!(
            chain.contains(" ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept\n"),
            "local v6 destinations must stay reachable"
        );
        let reject = chain
            .find("counter reject with icmpx type admin-prohibited")
            .expect("catch-all reject");
        assert!(
            local < reject,
            "local-network traffic must be accepted before the catch-all reject"
        );
    }
}
