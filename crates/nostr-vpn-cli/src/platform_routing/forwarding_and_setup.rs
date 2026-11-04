#[cfg(target_os = "linux")]
fn linux_ip_forward_path(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "/proc/sys/net/ipv4/ip_forward",
        LinuxExitNodeIpFamily::V6 => "/proc/sys/net/ipv6/conf/all/forwarding",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn linux_exit_node_source_cidr(tunnel_ip: &str) -> Option<String> {
    let octets = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok()?.octets();
    if octets[0] == 10 && octets[1] == 44 {
        return Some("10.44.0.0/16".to_string());
    }

    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxExitNodeIpFamily {
    V4,
    V6,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LinuxExitNodeDefaultRouteFamilies {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_exit_node_default_route_families(
    routes: &[String],
) -> LinuxExitNodeDefaultRouteFamilies {
    LinuxExitNodeDefaultRouteFamilies {
        ipv4: routes.iter().any(|route| route == "0.0.0.0/0"),
        ipv6: routes.iter().any(|route| route == "::/0"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_exit_node_firewall_binary(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "iptables",
        LinuxExitNodeIpFamily::V6 => "ip6tables",
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_forward_in_rule(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        tunnel_iface.to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-in",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-in",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_forward_out_rule(
    tunnel_iface: &str,
    outbound_iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        outbound_iface.to_string(),
        "-o".to_string(),
        tunnel_iface.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "RELATED,ESTABLISHED".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-out",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-out",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_legacy_forward_in_rule(
    iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-in",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-in",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_legacy_forward_out_rule(
    iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-o".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "RELATED,ESTABLISHED".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-out",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-out",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

// The exit NAT matches the interface a connection entered on. iptables cannot
// match it at POSTROUTING, and the source range alone also matches a local
// network numbered inside the mesh range.
#[cfg(target_os = "linux")]
fn linux_nft_name(name: &str) -> Result<&str> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(anyhow!("unsupported interface name for nftables: {name:?}"));
    }
    Ok(name)
}

#[cfg(target_os = "linux")]
fn linux_exit_node_nat_table(tunnel_iface: &str) -> Result<String> {
    Ok(format!("nvpn_exit_nat_{}", linux_nft_name(tunnel_iface)?))
}

#[cfg(target_os = "linux")]
fn linux_exit_node_ipv4_nat_script(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Result<String> {
    let table = linux_exit_node_nat_table(tunnel_iface)?;
    let outbound_iface = linux_nft_name(outbound_iface)?;
    let (address, prefix) = tunnel_source_cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid exit source range: {tunnel_source_cidr}"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid exit source range: {tunnel_source_cidr}"))?;
    let prefix = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| anyhow!("invalid exit source range: {tunnel_source_cidr}"))?;
    // Declaring the table first makes the delete succeed on first install, so
    // the replacement is one atomic transaction.
    Ok(format!(
        "table ip {table}\n\
         delete table ip {table}\n\
         table ip {table} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority 100; policy accept;\n\
         \t\tiifname \"{tunnel_iface}\" oifname \"{outbound_iface}\" ip saddr {address}/{prefix} counter masquerade\n\
         \t}}\n\
         }}\n"
    ))
}

#[cfg(target_os = "linux")]
fn linux_nft(script: &str) -> Result<()> {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = ProcessCommand::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Linux exit NAT requires nftables: failed to run nft")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("nft stdin unavailable"))?
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "nft: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Masquerades IPv4 traffic that entered on the mesh interface and leaves on
/// the uplink. Replaces the iptables rule earlier versions installed.
#[cfg(target_os = "linux")]
pub(crate) fn linux_exit_node_apply_ipv4_nat(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Result<()> {
    linux_nft(&linux_exit_node_ipv4_nat_script(
        tunnel_iface,
        outbound_iface,
        tunnel_source_cidr,
    )?)?;
    linux_iptables_delete_rule(
        LinuxExitNodeIpFamily::V4,
        Some("nat"),
        &linux_exit_node_ipv4_legacy_masquerade_rule(outbound_iface, tunnel_source_cidr),
    )
}

/// Removes nvpn's exit NAT table and the iptables rule earlier versions used.
#[cfg(target_os = "linux")]
pub(crate) fn linux_exit_node_remove_ipv4_nat(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Result<()> {
    let mut failures = Vec::new();
    // Install refuses an interface name nftables cannot express, so no table
    // exists for one; the iptables rule below is still removed.
    if let Ok(table) = linux_exit_node_nat_table(tunnel_iface)
        && let Err(error) = linux_nft(&format!("table ip {table}\ndelete table ip {table}\n"))
    {
        // Without nft the table cannot be removed or listed. A table left
        // behind only matches the mesh interface, so it cannot touch a local
        // network's traffic.
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            eprintln!("fips: skipping unavailable nftables exit NAT cleanup: {error:#}");
        } else {
            failures.push(format!("remove exit NAT table: {error:#}"));
        }
    }
    if let Err(error) = linux_iptables_delete_rule(
        LinuxExitNodeIpFamily::V4,
        Some("nat"),
        &linux_exit_node_ipv4_legacy_masquerade_rule(outbound_iface, tunnel_source_cidr),
    ) {
        failures.push(format!("remove legacy masquerade rule: {error:#}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}

// Earlier versions masqueraded the whole source range with iptables, which
// also covered a local network inside it. Upgrade and cleanup remove it.
#[cfg(target_os = "linux")]
fn linux_exit_node_ipv4_legacy_masquerade_rule(
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Vec<String> {
    vec![
        "POSTROUTING".to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-exit-masq".to_string(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_ipv4_mss_clamp_rule(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
    mss: u16,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        tunnel_iface.to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-exit-mss".to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--set-mss".to_string(),
        mss.to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_wireguard_exit_inbound_drop_rule(
    wireguard_iface: &str,
    tunnel_iface: &str,
    tunnel_source_cidr: &str,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        wireguard_iface.to_string(),
        "-o".to_string(),
        tunnel_iface.to_string(),
        "-d".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "NEW,INVALID".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-wg-upstream-inbound-drop".to_string(),
        "-j".to_string(),
        "DROP".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
fn linux_iptables_rule_check_proves_absent(
    exit_code: Option<i32>,
    stderr: &str,
    rule: &[String],
) -> bool {
    let tagged_with_comment = rule
        .windows(2)
        .any(|args| args[0] == "-m" && args[1] == "comment");
    let stderr = stderr.to_ascii_lowercase();
    exit_code == Some(2)
        && tagged_with_comment
        && stderr.contains("couldn't load match")
        && stderr.contains("comment")
        && (stderr.contains("no such file or directory") || stderr.contains("not found"))
}

#[cfg(target_os = "linux")]
fn linux_iptables_rule_exists(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<bool> {
    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-C");
    for arg in rule {
        command.arg(arg);
    }

    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if linux_iptables_rule_check_proves_absent(output.status.code(), &stderr, rule) {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "command failed: {display}\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_iptables_ensure_rule_at_front(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let Some((chain, args)) = rule.split_first() else {
        return Err(anyhow!("iptables rule is missing a chain"));
    };

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-I").arg(chain).arg("1");
    for arg in args {
        command.arg(arg);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_iptables_delete_rule(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if !linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-D");
    for arg in rule {
        command.arg(arg);
    }
    run_checked(&mut command)
}

#[cfg(any(target_os = "linux", test))]
#[derive(serde::Deserialize)]
struct LinuxInterfaceAddressSnapshot {
    #[serde(default)]
    addr_info: Vec<LinuxAddressSnapshot>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(serde::Deserialize)]
struct LinuxAddressSnapshot {
    local: String,
    prefixlen: u8,
}

#[cfg(any(target_os = "linux", test))]
fn normalized_linux_interface_address(address: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix_len) = address.split_once('/').unwrap_or((address, ""));
    let ip = ip.parse::<IpAddr>().ok()?;
    let prefix_len = if prefix_len.is_empty() {
        if ip.is_ipv4() { 32 } else { 128 }
    } else {
        prefix_len.parse::<u8>().ok()?
    };
    ((ip.is_ipv4() && prefix_len <= 32) || (ip.is_ipv6() && prefix_len <= 128))
        .then_some((ip, prefix_len))
}

#[cfg(any(target_os = "linux", test))]
fn stale_linux_interface_addresses_json(raw: &str, desired: &[String]) -> Result<Vec<String>> {
    let interfaces = serde_json::from_str::<Vec<LinuxInterfaceAddressSnapshot>>(raw)
        .context("parse Linux tunnel interface addresses")?;
    let [interface] = interfaces.as_slice() else {
        return Err(anyhow!("expected exactly one Linux tunnel interface"));
    };
    let desired = desired
        .iter()
        .filter_map(|address| normalized_linux_interface_address(address))
        .collect::<Vec<_>>();
    Ok(interface
        .addr_info
        .iter()
        .filter_map(|address| {
            let normalized = normalized_linux_interface_address(&format!(
                "{}/{}", address.local, address.prefixlen
            ))?;
            let link_local = match normalized.0 {
                IpAddr::V4(ip) => ip.is_link_local(),
                IpAddr::V6(ip) => ip.is_unicast_link_local(),
            };
            (!link_local && !desired.contains(&normalized))
                .then(|| format!("{}/{}", normalized.0, normalized.1))
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn remove_stale_linux_interface_addresses(iface: &str, desired: &[String]) -> Result<()> {
    let output = ProcessCommand::new("ip")
        .args(["-j", "address", "show", "dev", iface])
        .output()
        .context("inspect Linux tunnel interface addresses")?;
    if !output.status.success() {
        return Err(anyhow!(
            "inspect Linux tunnel interface addresses failed with {}",
            output.status
        ));
    }
    let raw = std::str::from_utf8(&output.stdout)
        .context("Linux tunnel interface addresses were not UTF-8")?;
    for address in stale_linux_interface_addresses_json(raw, desired)? {
        run_checked(
            ProcessCommand::new("ip")
                .args(["address", "delete", &address, "dev", iface]),
        )?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn apply_local_interface_network_with_mtu_and_addresses(
    iface: &str,
    addresses: &[String],
    route_targets: &[String],
    mtu: u16,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mtu = mtu.to_string();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mtu = mtu.as_str();
    #[cfg(target_os = "linux")]
    {
        let ipv4_route_source = addresses
            .iter()
            .find_map(|address| linux_ipv4_route_source(address));
        let local_has_ipv4 = addresses
            .iter()
            .any(|address| linux_tunnel_address_is_ipv4(address));
        let local_has_ipv6 = addresses
            .iter()
            .any(|address| linux_tunnel_address_is_ipv6(address));
        for address in addresses {
            run_checked(
                ProcessCommand::new("ip")
                    .arg("address")
                    .arg("replace")
                    .arg(address)
                    .arg("dev")
                    .arg(iface),
            )?;
        }
        remove_stale_linux_interface_addresses(iface, addresses)?;
        run_checked(
            ProcessCommand::new("ip")
                .arg("link")
                .arg("set")
                .arg("mtu")
                .arg(mtu)
                .arg("up")
                .arg("dev")
                .arg(iface),
        )?;
        for target in route_targets {
            if linux_route_target_is_ipv4(target) && !local_has_ipv4 {
                continue;
            }
            if linux_route_target_is_ipv6(target) && !local_has_ipv6 {
                continue;
            }
            let mut command = ProcessCommand::new("ip");
            command.args(linux_route_replace_args(
                target,
                iface,
                ipv4_route_source.as_deref(),
            ));
            run_checked(&mut command)?;
            if target == "fd00::/8" {
                let _ = ProcessCommand::new("ip")
                    .arg("-6")
                    .arg("rule")
                    .arg("add")
                    .arg("to")
                    .arg(target)
                    .arg("table")
                    .arg("main")
                    .arg("priority")
                    .arg("5265")
                    .status();
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let primary_address = addresses
            .iter()
            .find(|address| linux_tunnel_address_is_ipv4(address))
            .or_else(|| addresses.first())
            .ok_or_else(|| anyhow!("no tunnel interface address configured"))?;
        let ip = strip_cidr(primary_address).to_string();
        run_checked(
            ProcessCommand::new("ifconfig")
                .arg(iface)
                .arg("inet")
                .arg(&ip)
                .arg(&ip)
                .arg("netmask")
                .arg(macos_tunnel_ipv4_netmask())
                .arg("mtu")
                .arg(mtu)
                .arg("up"),
        )?;
        for address in addresses {
            if !linux_tunnel_address_is_ipv6(address) {
                continue;
            }
            let (ip, prefix) = split_cidr(address, "128");
            run_checked(
                ProcessCommand::new("ifconfig")
                    .arg(iface)
                    .arg("inet6")
                    .arg(ip)
                    .arg("prefixlen")
                    .arg(prefix)
                    .arg("alias"),
            )?;
        }
        eprintln!(
            "tunnel: applying macOS interface {} with routes [{}]",
            iface,
            route_targets.join(", ")
        );
        for target in route_targets {
            apply_macos_route(iface, target)?;
        }
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, addresses, route_targets, mtu);

    #[allow(unreachable_code)]
    Err(anyhow!(
        "interface setup is not implemented for this platform"
    ))
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_tunnel_ipv4_netmask() -> &'static str {
    "255.255.255.255"
}

#[cfg(all(test, target_os = "linux"))]
mod linux_exit_nat_tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const RECEIVED: &str = "/tmp/exit-nat-received";
    const HOST_SNAT: &[&str] = &[
        "POSTROUTING", "-o", "uplink0", "-s", "10.44.0.0/24", "-j", "SNAT", "--to-source",
        "192.0.2.99",
    ];
    const HOST_LAN_MARK: &[&str] = &[
        "PREROUTING", "-i", "lan0", "-j", "CONNMARK", "--set-xmark", "0x1000000/0x1000000",
    ];

    fn run(program: &str, args: &[&str]) -> String {
        let output = Command::new(program).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn iptables_has(table: &str, rule: &[&str]) -> bool {
        Command::new("iptables")
            .args(["-t", table, "-C"])
            .args(rule)
            .output()
            .unwrap()
            .status
            .success()
    }

    /// Sends one datagram from a new socket and returns the source address the
    /// internet side saw.
    fn source_seen_from(namespace: &str, payload: &str) -> String {
        run(
            "ip",
            &[
                "netns",
                "exec",
                namespace,
                "python3",
                "-c",
                "import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.sendto(sys.argv[1].encode(),('192.0.2.2',39002))",
                payload,
            ],
        );
        let suffix = format!(" {payload}");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let received = std::fs::read_to_string(RECEIVED).unwrap_or_default();
            if let Some(source) = received.lines().find_map(|line| line.strip_suffix(&suffix)) {
                return source.to_owned();
            }
            assert!(Instant::now() < deadline, "{payload} never reached the internet");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    #[ignore = "run with scripts/test-linux-egress-lifecycle in an isolated root namespace"]
    fn exit_nat_masquerades_only_traffic_from_the_mesh_interface() {
        assert_eq!(std::env::var("NVPN_EGRESS_ISOLATED").as_deref(), Ok("1"));
        assert_eq!(std::fs::read_dir("/sys/class/net").unwrap().count(), 1);
        // This namespace is the exit. Its LAN is numbered inside the mesh range.
        run("ip", &["link", "set", "lo", "up"]);
        for (namespace, interface, local, remote, gateway) in [
            ("internet", "uplink0", "192.0.2.1/24", "192.0.2.2/24", None),
            ("lan", "lan0", "10.44.0.1/24", "10.44.0.5/24", Some("10.44.0.1")),
            ("mesh", "nvpnmesh0", "10.44.200.1/16", "10.44.12.34/16", Some("10.44.200.1")),
        ] {
            run("ip", &["netns", "add", namespace]);
            run("ip", &["link", "add", interface, "type", "veth", "peer", "name", "remote"]);
            run("ip", &["link", "set", "remote", "netns", namespace]);
            run("ip", &["addr", "add", local, "dev", interface]);
            run("ip", &["link", "set", interface, "up"]);
            let inside = |args: &[&str]| {
                run("ip", &[&["netns", "exec", namespace, "ip"][..], args].concat());
            };
            inside(&["link", "set", "lo", "up"]);
            inside(&["addr", "add", remote, "dev", "remote"]);
            inside(&["link", "set", "remote", "up"]);
            if let Some(gateway) = gateway {
                inside(&["route", "add", "default", "via", gateway]);
            }
        }
        // The host's own SNAT address for its LAN, next to the uplink's primary.
        run("ip", &["addr", "add", "192.0.2.99/24", "dev", "uplink0"]);
        run("ip", &["route", "add", "default", "via", "192.0.2.2"]);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        let mut receiver = Command::new("ip")
            .args(["netns", "exec", "internet", "python3", "-u", "-c",
                "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('192.0.2.2',39002))\nprint('ready',flush=True)\nwhile True:\n data,(source,_)=s.recvfrom(64)\n with open('/tmp/exit-nat-received','a') as f: f.write(source+' '+data.decode()+'\\n')"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(receiver.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");

        // Upgrade: an earlier version masqueraded the whole range with iptables.
        let legacy = linux_exit_node_ipv4_legacy_masquerade_rule("uplink0", "10.44.0.0/16");
        let legacy = legacy.iter().map(String::as_str).collect::<Vec<_>>();
        run("iptables", &[&["-t", "nat", "-A"][..], &legacy].concat());
        linux_exit_node_apply_ipv4_nat("nvpnmesh0", "uplink0", "10.44.0.0/16").unwrap();
        assert!(!iptables_has("nat", &legacy), "upgrade kept the iptables masquerade");

        // The host adds its own NAT and marks after nvpn, as a firewall reload
        // would. LAN connections carry the connection-mark bit an earlier
        // revision of this fix relied on; the counting rule proves they do.
        run("iptables", &[&["-t", "nat", "-A"][..], HOST_SNAT].concat());
        run("iptables", &[&["-t", "mangle", "-A"][..], HOST_LAN_MARK].concat());
        run(
            "iptables",
            &["-t", "mangle", "-A", "POSTROUTING", "-o", "uplink0", "-m", "connmark", "--mark",
                "0x1000000/0x1000000"],
        );
        assert_eq!(source_seen_from("mesh", "mesh-1"), "192.0.2.1");
        assert_eq!(source_seen_from("lan", "lan-1"), "192.0.2.99");
        let marked = run("iptables", &["-t", "mangle", "-L", "POSTROUTING", "-v", "-x", "-n"]);
        let marked = marked
            .lines()
            .find(|line| line.contains("connmark"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|packets| packets.parse::<u64>().ok());
        assert!(marked.is_some_and(|packets| packets > 0), "LAN traffic was not marked");

        // Removing nvpn's NAT leaves the host's NAT and marks working.
        linux_exit_node_remove_ipv4_nat("nvpnmesh0", "uplink0", "10.44.0.0/16").unwrap();
        assert!(!run("nft", &["list", "tables"]).contains("nvpn_exit_nat_"));
        assert!(iptables_has("nat", HOST_SNAT));
        assert!(iptables_has("mangle", HOST_LAN_MARK));
        assert_eq!(source_seen_from("lan", "lan-2"), "192.0.2.99");

        // A name nftables cannot express is refused, and cleanup still removes
        // the iptables rule an earlier version installed for it.
        run("iptables", &[&["-t", "nat", "-A"][..], &legacy].concat());
        assert!(linux_exit_node_apply_ipv4_nat("bad\"name", "uplink0", "10.44.0.0/16").is_err());
        linux_exit_node_remove_ipv4_nat("bad\"name", "uplink0", "10.44.0.0/16").unwrap();
        assert!(!iptables_has("nat", &legacy));

        // Without nftables the exit fails instead of masquerading the LAN.
        let nft = run("sh", &["-c", "command -v nft"]).trim().to_owned();
        run("mount", &["--bind", "/dev/null", &nft]);
        let error = linux_exit_node_apply_ipv4_nat("nvpnmesh0", "uplink0", "10.44.0.0/16");
        run("umount", &[&nft]);
        let error = format!("{:#}", error.unwrap_err());
        assert!(error.contains("requires nftables"), "{error}");
        assert!(!iptables_has("nat", &legacy));
        assert!(!run("nft", &["list", "tables"]).contains("nvpn_exit_nat_"));

        receiver.kill().unwrap();
        receiver.wait().unwrap();
    }
}
