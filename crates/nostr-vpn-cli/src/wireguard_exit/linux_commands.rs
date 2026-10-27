use std::io::Write;
use std::process::{Command as ProcessCommand, Output as ProcessOutput, Stdio};

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::WireGuardExitConfig;

use super::{WIREGUARD_EXIT_RULE_PRIORITY, WIREGUARD_EXIT_TABLE};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct LinuxAddressRestore {
    pub(super) configured: String,
    pub(super) previous: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct LinuxLinkState {
    pub(super) mtu: u64,
    pub(super) up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct LinuxRouteRestore {
    pub(super) target: String,
    pub(super) previous_routes: Vec<String>,
}

#[derive(Debug)]
pub(super) struct LinuxCommandOutput {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) trait LinuxCommandRunner {
    fn output(&mut self, program: &str, args: &[String]) -> Result<LinuxCommandOutput>;

    fn output_with_stdin(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<LinuxCommandOutput>;

    fn ipv4_default_route_is_usable(&mut self, route: &crate::LinuxDefaultRouteSpec) -> bool;
}

pub(super) struct SystemLinuxCommandRunner;

impl LinuxCommandRunner for SystemLinuxCommandRunner {
    fn output(&mut self, program: &str, args: &[String]) -> Result<LinuxCommandOutput> {
        let display = command_display(program, args);
        let output = ProcessCommand::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {display}"))?;
        Ok(linux_command_output(output))
    }

    fn output_with_stdin(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<LinuxCommandOutput> {
        let display = command_display(program, args);
        let mut child = ProcessCommand::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to execute {display}"))?;
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open stdin for {display}"))?;
        let write_result = child_stdin.write_all(stdin);
        drop(child_stdin);
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {display}"))?;
        let output = linux_command_output(output);
        if output.success {
            write_result.with_context(|| format!("failed to write stdin for {display}"))?;
        }
        Ok(output)
    }

    fn ipv4_default_route_is_usable(&mut self, route: &crate::LinuxDefaultRouteSpec) -> bool {
        #[cfg(target_os = "linux")]
        {
            crate::linux_ipv4_default_route_is_usable(route)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = route;
            false
        }
    }
}

fn linux_command_output(output: ProcessOutput) -> LinuxCommandOutput {
    LinuxCommandOutput {
        success: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn command_display(program: &str, args: &[String]) -> String {
    format!("{program} {args:?}")
}

pub(super) fn command_output_checked(
    runner: &mut impl LinuxCommandRunner,
    program: &str,
    args: &[String],
) -> Result<String> {
    let output = runner.output(program, args)?;
    if output.success {
        return Ok(output.stdout);
    }
    Err(command_failed(program, args, &output))
}

fn command_output_checked_with_stdin(
    runner: &mut impl LinuxCommandRunner,
    program: &str,
    args: &[String],
    stdin: &[u8],
) -> Result<String> {
    let output = runner.output_with_stdin(program, args, stdin)?;
    if output.success {
        return Ok(output.stdout);
    }
    Err(command_failed(program, args, &output))
}

pub(super) fn run_checked(
    runner: &mut impl LinuxCommandRunner,
    program: &str,
    args: &[String],
) -> Result<()> {
    command_output_checked(runner, program, args).map(drop)
}

fn run_checked_allow_absent(
    runner: &mut impl LinuxCommandRunner,
    program: &str,
    args: &[String],
) -> Result<()> {
    let output = runner.output(program, args)?;
    if output.success || linux_absent_resource_error(&output) {
        Ok(())
    } else {
        Err(command_failed(program, args, &output))
    }
}

fn linux_absent_resource_error(output: &LinuxCommandOutput) -> bool {
    matches!(output.code, Some(1 | 2))
        && [
            "No such process",
            "No such file or directory",
            "Cannot find device",
            "Cannot assign requested address",
            "does not exist",
        ]
        .iter()
        .any(|message| output.stderr.contains(message))
}

fn command_failed(program: &str, args: &[String], output: &LinuxCommandOutput) -> anyhow::Error {
    anyhow!(
        "command failed: {}\nstdout: {}\nstderr: {}",
        command_display(program, args),
        output.stdout.trim(),
        output.stderr.trim()
    )
}

pub(super) fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

pub(super) fn current_linux_default_route(
    runner: &mut impl LinuxCommandRunner,
) -> Result<Option<String>> {
    let output =
        command_output_checked(runner, "ip", &strings(&["-4", "route", "show", "default"]))?;
    Ok(lowest_metric_default_route(&output).map(|(line, _)| line))
}

pub(super) fn lowest_metric_default_route(output: &str) -> Option<(String, String)> {
    crate::linux_default_route_specs_from_output(output)
        .map(|route| (route.metric, route.line, route.dev))
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, line, dev)| (line, dev))
}

pub(super) fn linux_wireguard_link_exists(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
) -> Result<bool> {
    let args = strings(&["link", "show", "dev", iface]);
    let output = runner.output("ip", &args)?;
    if output.success {
        return Ok(true);
    }
    if !linux_link_missing_error(&output) {
        return Err(command_failed("ip", &args, &output));
    }
    Ok(false)
}

pub(super) fn create_linux_wireguard_link(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&["link", "add", "dev", iface, "type", "wireguard"]),
    )
    .with_context(|| {
        format!("WireGuard interface {iface} creation was not acknowledged; ownership is uncertain")
    })
}

fn linux_link_missing_error(output: &LinuxCommandOutput) -> bool {
    output.code == Some(1)
        && (output.stderr.contains("does not exist")
            || output.stderr.contains("Cannot find device"))
}

pub(super) fn linux_ipv4_route_snapshot(
    runner: &mut impl LinuxCommandRunner,
    args: &[&str],
) -> Result<Vec<String>> {
    let mut command_args = strings(&["-4", "route", "show"]);
    command_args.extend(args.iter().map(|arg| (*arg).to_string()));
    let output = command_output_checked(runner, "ip", &command_args)?;
    Ok(route_lines(&output))
}

pub(super) fn linux_ipv4_table_snapshot(
    runner: &mut impl LinuxCommandRunner,
    table: u32,
) -> Result<Vec<String>> {
    let args = strings(&["-4", "route", "show", "table", &table.to_string()]);
    let output = runner.output("ip", &args)?;
    if output.success {
        return Ok(route_lines(&output.stdout));
    }
    if linux_missing_fib_table_error(&output) {
        return Ok(Vec::new());
    }
    Err(command_failed("ip", &args, &output))
}

pub(super) fn linux_missing_fib_table_error(output: &LinuxCommandOutput) -> bool {
    output.code == Some(2) && output.stderr.contains("FIB table does not exist")
}

fn route_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn linux_interface_address_for_config(output: &str, configured: &str) -> Option<String> {
    let configured_ip = configured.trim().split('/').next()?;
    output.lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens.windows(2).find_map(|window| {
            if !matches!(window[0], "inet" | "inet6") {
                return None;
            }
            (window[1].split('/').next() == Some(configured_ip)).then(|| window[1].to_string())
        })
    })
}

pub(super) fn linux_link_state_from_json(output: &str) -> Result<LinuxLinkState> {
    let value: serde_json::Value =
        serde_json::from_str(output).context("failed to parse Linux link state")?;
    let link = value
        .as_array()
        .and_then(|links| links.first())
        .ok_or_else(|| anyhow!("Linux link state is empty"))?;
    let mtu = link
        .get("mtu")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow!("Linux link state has no MTU"))?;
    let up = link
        .get("flags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")));
    Ok(LinuxLinkState { mtu, up })
}

pub(super) fn replace_linux_address(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    address: &str,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&["address", "replace", address, "dev", iface]),
    )
}

pub(super) fn linux_wireguard_kernel_config(
    config: &WireGuardExitConfig,
    endpoint: std::net::SocketAddrV4,
) -> String {
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {}", config.private_key.trim()),
        format!("FwMark = {}", crate::linux_host_network::CARRIER_MARK),
        String::new(),
        "[Peer]".to_string(),
        format!("PublicKey = {}", config.peer_public_key.trim()),
    ];
    if !config.peer_preshared_key.trim().is_empty() {
        lines.push(format!(
            "PresharedKey = {}",
            config.peer_preshared_key.trim()
        ));
    }
    lines.extend([
        format!("AllowedIPs = {}", config.allowed_ips.join(", ")),
        format!("Endpoint = {endpoint}"),
    ]);
    if config.persistent_keepalive_secs > 0 {
        lines.push(format!(
            "PersistentKeepalive = {}",
            config.persistent_keepalive_secs
        ));
    }
    lines.join("\n")
}

pub(super) fn set_linux_wireguard_config(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    kernel_config: &str,
) -> Result<()> {
    // Ubuntu confines `wg` to a small set of readable paths. An inherited
    // pipe works under that policy and avoids persisting key material.
    command_output_checked_with_stdin(
        runner,
        "wg",
        &strings(&["setconf", iface, "/dev/stdin"]),
        kernel_config.as_bytes(),
    )
    .map(drop)
}

pub(super) fn set_linux_wireguard_link(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    mtu: u16,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&["link", "set", "mtu", &mtu.to_string(), "up", "dev", iface]),
    )
}

pub(super) fn apply_linux_endpoint_bypass_route(
    runner: &mut impl LinuxCommandRunner,
    route: &crate::LinuxEndpointBypassRoute,
) -> Result<()> {
    let mut args = strings(&["-4", "route", "replace", &route.target]);
    if let Some(gateway) = route.gateway.as_deref() {
        args.extend(strings(&["via", gateway]));
    }
    args.extend(strings(&["dev", &route.dev]));
    if let Some(src) = route.src.as_deref() {
        args.extend(strings(&["src", src]));
    }
    run_checked(runner, "ip", &args)
}

pub(super) fn replace_linux_policy_default_route(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&[
            "-4",
            "route",
            "replace",
            "default",
            "dev",
            iface,
            "table",
            &WIREGUARD_EXIT_TABLE.to_string(),
        ]),
    )
}

pub(super) fn replace_linux_policy_mesh_route(
    runner: &mut impl LinuxCommandRunner,
    mesh_cidr: &str,
    mesh_iface: &str,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&[
            "-4",
            "route",
            "replace",
            mesh_cidr,
            "dev",
            mesh_iface,
            "table",
            &WIREGUARD_EXIT_TABLE.to_string(),
        ]),
    )
}

pub(super) fn add_linux_wireguard_exit_policy_rule(
    runner: &mut impl LinuxCommandRunner,
    source_cidr: &str,
) -> Result<()> {
    run_checked(
        runner,
        "ip",
        &strings(&[
            "-4",
            "rule",
            "add",
            "priority",
            &WIREGUARD_EXIT_RULE_PRIORITY.to_string(),
            "from",
            source_cidr,
            "table",
            &WIREGUARD_EXIT_TABLE.to_string(),
        ]),
    )
}

pub(super) fn restore_linux_wireguard_config(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    config: &str,
) -> Result<()> {
    set_linux_wireguard_config(runner, iface, config)
        .with_context(|| format!("failed to restore pre-WireGuard configuration on {iface}"))
}

pub(super) fn restore_linux_address(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    address: &LinuxAddressRestore,
) -> Result<()> {
    let delete = run_checked_allow_absent(
        runner,
        "ip",
        &strings(&["address", "del", &address.configured, "dev", iface]),
    );
    let replace = if let Some(previous) = address.previous.as_deref() {
        run_checked(
            runner,
            "ip",
            &strings(&["address", "replace", previous, "dev", iface]),
        )
    } else {
        Ok(())
    };
    match (delete, replace) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(delete), Ok(())) => Err(delete)
            .with_context(|| format!("failed to remove managed WireGuard address on {iface}")),
        (Ok(()), Err(replace)) => Err(replace)
            .with_context(|| format!("failed to restore pre-WireGuard address on {iface}")),
        (Err(delete), Err(replace)) => Err(anyhow!(
            "failed to restore address on {iface}: delete failed ({delete:#}); replace failed ({replace:#})"
        )),
    }
}

pub(super) fn restore_linux_link(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    link: &LinuxLinkState,
) -> Result<()> {
    let mtu = run_checked(
        runner,
        "ip",
        &strings(&["link", "set", "dev", iface, "mtu", &link.mtu.to_string()]),
    );
    let state = run_checked(
        runner,
        "ip",
        &strings(&[
            "link",
            "set",
            if link.up { "up" } else { "down" },
            "dev",
            iface,
        ]),
    );
    match (mtu, state) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(mtu), Ok(())) => {
            Err(mtu).with_context(|| format!("failed to restore pre-WireGuard MTU on {iface}"))
        }
        (Ok(()), Err(state)) => Err(state)
            .with_context(|| format!("failed to restore pre-WireGuard link state on {iface}")),
        (Err(mtu), Err(state)) => Err(anyhow!(
            "failed to restore link on {iface}: MTU failed ({mtu:#}); state failed ({state:#})"
        )),
    }
}

pub(super) fn restore_linux_route_target(
    runner: &mut impl LinuxCommandRunner,
    route: &LinuxRouteRestore,
    table: Option<u32>,
) -> Result<()> {
    let mut delete_args = strings(&["-4", "route", "del", &route.target]);
    if let Some(table) = table {
        delete_args.extend(strings(&["table", &table.to_string()]));
    }
    run_checked_allow_absent(runner, "ip", &delete_args)
        .with_context(|| format!("failed to remove managed route '{}'", route.target))?;
    restore_linux_route_snapshot(runner, &route.previous_routes, table)
}

pub(super) fn restore_linux_route_snapshot(
    runner: &mut impl LinuxCommandRunner,
    routes: &[String],
    table: Option<u32>,
) -> Result<()> {
    let mut failures = Vec::new();
    for route in routes {
        let mut args = strings(&["-4", "route", "replace"]);
        let replay_args = match crate::linux_route_replay_args(route) {
            Ok(args) => args,
            Err(error) => {
                failures.push(format!("'{route}': {error:#}"));
                continue;
            }
        };
        args.extend(replay_args.into_iter().map(ToOwned::to_owned));
        if let Some(table) = table {
            args.extend(strings(&["table", &table.to_string()]));
        }
        if let Err(error) = run_checked(runner, "ip", &args) {
            failures.push(format!("'{route}': {error:#}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to restore pre-WireGuard routes: {}",
            failures.join("; ")
        ))
    }
}

pub(super) fn restore_linux_table_snapshot(
    runner: &mut impl LinuxCommandRunner,
    table: u32,
    routes: &[String],
) -> Result<()> {
    run_checked_allow_absent(
        runner,
        "ip",
        &strings(&["-4", "route", "flush", "table", &table.to_string()]),
    )
    .with_context(|| format!("failed to flush WireGuard policy table {table}"))?;
    restore_linux_route_snapshot(runner, routes, Some(table))
        .with_context(|| format!("failed to restore WireGuard policy table {table}"))
}

pub(super) fn restore_linux_main_default_snapshot(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    routes: &[String],
) -> Result<()> {
    run_checked_allow_absent(
        runner,
        "ip",
        &strings(&["-4", "route", "del", "default", "dev", iface]),
    )
    .context("failed to remove managed WireGuard default route")?;
    let usable_routes = routes
        .iter()
        .filter(|route| {
            crate::linux_default_route_spec_from_line(route).is_some_and(|route| {
                route.dev == iface || runner.ipv4_default_route_is_usable(&route)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    restore_linux_route_snapshot(runner, &usable_routes, None)
        .context("failed to restore pre-WireGuard default routes")
}

pub(super) fn restore_linux_main_default_snapshot_exact(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    routes: &[String],
) -> Result<()> {
    run_checked_allow_absent(
        runner,
        "ip",
        &strings(&["-4", "route", "del", "default", "dev", iface]),
    )
    .context("failed to remove partially-installed WireGuard default route")?;
    restore_linux_route_snapshot(runner, routes, None)
        .context("failed to restore pre-WireGuard default routes without deleting a new underlay")
}

pub(super) fn delete_linux_wireguard_exit_policy_rule(
    runner: &mut impl LinuxCommandRunner,
    source_cidr: &str,
    table: u32,
    priority: u32,
) -> Result<()> {
    run_checked_allow_absent(
        runner,
        "ip",
        &strings(&[
            "-4",
            "rule",
            "del",
            "priority",
            &priority.to_string(),
            "from",
            source_cidr,
            "table",
            &table.to_string(),
        ]),
    )
}

pub(super) fn delete_linux_wireguard_exit_link(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
) -> Result<()> {
    run_checked_allow_absent(runner, "ip", &strings(&["link", "del", "dev", iface]))
}

pub(super) fn flush_linux_route_cache(runner: &mut impl LinuxCommandRunner) -> Result<()> {
    run_checked(runner, "ip", &strings(&["-4", "route", "flush", "cache"]))
}

pub(super) fn linux_wireguard_exit_policy_rule_exists(
    output: &str,
    source_cidr: &str,
    table: u32,
    priority: u32,
) -> bool {
    let priority_prefix = format!("{priority}:");
    let table_lookup = format!("lookup {table}");
    output.lines().any(|line| {
        let line = line.trim();
        line.starts_with(&priority_prefix)
            && line.contains("from ")
            && line.contains(source_cidr)
            && line.contains(&table_lookup)
    })
}
