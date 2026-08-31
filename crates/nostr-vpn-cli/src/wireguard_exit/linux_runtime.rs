#[path = "linux_commands.rs"]
mod commands;

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::WireGuardExitConfig;

use commands::*;

const WIREGUARD_EXIT_TABLE: u32 = 51_888;
const WIREGUARD_EXIT_RULE_PRIORITY: u32 = 10_888;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LinuxInterfaceRestore {
    addresses: Vec<LinuxAddressRestore>,
    wireguard_config: String,
    link: LinuxLinkState,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxWireGuardExitRuntime {
    pub(crate) interface: String,
    pub(crate) managed_address: String,
    pub(crate) source_cidr: String,
    pub(crate) table: u32,
    pub(crate) priority: u32,
    pub(crate) created_interface: bool,
    pub(crate) previous_default_route: Option<String>,
    #[serde(default)]
    handshake_completed: bool,
    endpoint_routes: Vec<LinuxRouteRestore>,
    previous_main_default_routes: Vec<String>,
    previous_table_routes: Vec<String>,
    policy_rule_owned: bool,
    interface_restore: LinuxInterfaceRestore,
}

impl LinuxWireGuardExitRuntime {
    pub(crate) fn has_completed_handshake(&self) -> bool {
        self.handshake_completed
    }

    pub(crate) fn refresh_completed_handshake(&mut self) -> Result<bool> {
        match linux_wireguard_exit_has_completed_handshake_with(
            &mut SystemLinuxCommandRunner,
            &self.interface,
        ) {
            Ok(completed) => {
                self.handshake_completed = completed;
                Ok(completed)
            }
            Err(error) => {
                self.handshake_completed = false;
                Err(error)
            }
        }
    }

    pub(crate) fn refresh_underlay_default_route(&mut self, route: String) {
        self.previous_default_route = Some(upsert_runtime_underlay_route(
            &mut self.previous_main_default_routes,
            &route,
        ));
    }

    pub(crate) fn underlay_default_route_hints(&self) -> &[String] {
        self.underlay_default_route_hints_with(&mut SystemLinuxCommandRunner)
    }

    fn underlay_default_route_hints_with(&self, runner: &mut impl LinuxCommandRunner) -> &[String] {
        if let Some(route) = self.previous_default_route.as_ref()
            && crate::linux_default_route_spec_from_line(route)
                .is_some_and(|route| runner.ipv4_default_route_is_usable(&route))
        {
            return self.previous_default_route.as_slice();
        }
        &self.previous_main_default_routes
    }

    pub(crate) fn underlay_default_route_for_interface(
        &self,
        interface: &str,
    ) -> Option<crate::LinuxDefaultRouteSpec> {
        crate::linux_default_route_from_lines_for_interface(
            &self.previous_main_default_routes,
            interface,
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApplySnapshot {
    address: LinuxAddressRestore,
    wireguard_config: String,
    link: LinuxLinkState,
    endpoint_routes: Vec<LinuxRouteRestore>,
    main_default_routes: Vec<String>,
    table_routes: Vec<String>,
    policy_rule_existed: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct ApplyProgress {
    address_started: bool,
    endpoint_targets_started: Vec<String>,
    wireguard_started: bool,
    link_started: bool,
    table_started: bool,
    policy_rule_added: bool,
    main_default_started: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum LinuxWireGuardExitCleanupObligation {
    ApplyRollback(Box<LinuxWireGuardExitRollbackObligation>),
    CreatedInterface { interface: String },
    RouteCacheFlush,
}

impl LinuxWireGuardExitCleanupObligation {
    pub(crate) fn interface(&self) -> Option<&str> {
        match self {
            Self::ApplyRollback(rollback) => Some(&rollback.interface),
            Self::CreatedInterface { interface } => Some(interface),
            Self::RouteCacheFlush => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxWireGuardExitRollbackObligation {
    interface: String,
    source_cidr: String,
    snapshot: ApplySnapshot,
    progress: ApplyProgress,
    created_interface: bool,
}

#[derive(Debug)]
pub(crate) struct LinuxWireGuardExitApplyFailure {
    error: anyhow::Error,
    cleanup_obligation: Option<LinuxWireGuardExitCleanupObligation>,
}

struct LinuxWireGuardExitApplyContext<'a> {
    source_cidr: &'a str,
    mesh_iface: &'a str,
    previous_runtime: Option<&'a LinuxWireGuardExitRuntime>,
    previous_default_route_hint: Option<&'a str>,
}

impl LinuxWireGuardExitApplyFailure {
    pub(crate) fn into_parts(self) -> (anyhow::Error, Option<LinuxWireGuardExitCleanupObligation>) {
        (self.error, self.cleanup_obligation)
    }
}

impl std::fmt::Display for LinuxWireGuardExitApplyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for LinuxWireGuardExitApplyFailure {}

pub(crate) fn apply_linux_wireguard_exit_upstream(
    config: &WireGuardExitConfig,
    source_cidr: &str,
    mesh_iface: &str,
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    previous_default_route_hint: Option<&str>,
    persist_cleanup_intent: impl FnMut(&LinuxWireGuardExitCleanupObligation) -> Result<()>,
) -> std::result::Result<LinuxWireGuardExitRuntime, LinuxWireGuardExitApplyFailure> {
    apply_linux_wireguard_exit_upstream_with_journal(
        &mut SystemLinuxCommandRunner,
        config,
        LinuxWireGuardExitApplyContext {
            source_cidr,
            mesh_iface,
            previous_runtime,
            previous_default_route_hint,
        },
        super::resolve_linux_wireguard_exit_endpoint,
        persist_cleanup_intent,
    )
}

#[cfg(test)]
fn apply_linux_wireguard_exit_upstream_with(
    runner: &mut impl LinuxCommandRunner,
    config: &WireGuardExitConfig,
    source_cidr: &str,
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    previous_default_route_hint: Option<&str>,
) -> std::result::Result<LinuxWireGuardExitRuntime, LinuxWireGuardExitApplyFailure> {
    apply_linux_wireguard_exit_upstream_with_journal(
        runner,
        config,
        LinuxWireGuardExitApplyContext {
            source_cidr,
            mesh_iface: "nvpn0",
            previous_runtime,
            previous_default_route_hint,
        },
        super::resolve_linux_wireguard_exit_endpoint,
        |_| Ok(()),
    )
}

fn apply_linux_wireguard_exit_upstream_with_journal(
    runner: &mut impl LinuxCommandRunner,
    config: &WireGuardExitConfig,
    context: LinuxWireGuardExitApplyContext<'_>,
    mut resolve_endpoint: impl FnMut(&str) -> Result<std::net::SocketAddrV4>,
    mut persist_cleanup_intent: impl FnMut(&LinuxWireGuardExitCleanupObligation) -> Result<()>,
) -> std::result::Result<LinuxWireGuardExitRuntime, LinuxWireGuardExitApplyFailure> {
    let LinuxWireGuardExitApplyContext {
        source_cidr,
        mesh_iface,
        previous_runtime,
        previous_default_route_hint,
    } = context;
    let iface = super::validate_linux_wireguard_exit_config(config).map_err(apply_failure)?;
    if previous_runtime
        .is_some_and(|runtime| runtime.interface != iface || runtime.source_cidr != source_cidr)
    {
        return Err(apply_failure(anyhow!(
            "WireGuard exit runtime identity changed without cleanup"
        )));
    }
    let resolved_endpoint = resolve_endpoint(&config.endpoint).map_err(apply_failure)?;

    let current_default_route = current_linux_default_route(runner).map_err(apply_failure)?;
    let mut previous_default_route = super::select_linux_wireguard_underlay_default_route(
        previous_default_route_hint,
        previous_runtime.and_then(|runtime| runtime.previous_default_route.as_deref()),
        current_default_route.as_deref(),
        &iface,
    );
    let initial_endpoint_specs = vec![
        linux_wireguard_exit_endpoint_spec(
            runner,
            resolved_endpoint,
            &iface,
            previous_default_route.as_deref(),
        )
        .map_err(apply_failure)?,
    ];
    let kernel_config = linux_wireguard_kernel_config(config, resolved_endpoint);

    let created_interface = !linux_wireguard_link_exists(runner, &iface).map_err(apply_failure)?;
    if created_interface {
        let obligation = LinuxWireGuardExitCleanupObligation::CreatedInterface {
            interface: iface.clone(),
        };
        if let Err(error) = persist_cleanup_intent(&obligation) {
            let mut obligation = obligation;
            return match cleanup_linux_wireguard_exit_obligation_with(runner, &mut obligation) {
                Ok(()) => Err(apply_failure(error.context(
                    "persist WireGuard interface creation intent before mutation",
                ))),
                Err(cleanup) => Err(LinuxWireGuardExitApplyFailure {
                    error: anyhow!(
                        "failed to persist WireGuard interface creation intent \
                         ({error:#}); immediate cleanup also failed ({cleanup:#})"
                    ),
                    cleanup_obligation: Some(obligation),
                }),
            };
        }
        if let Err(error) = create_linux_wireguard_link(runner, &iface) {
            // A failed command does not prove that RTM_NEWLINK did or did not
            // happen. Replace the pre-mutation deletion intent before
            // returning so a concurrently-created same-name interface is
            // never claimed as ours after an observed failure.
            let neutral_obligation = LinuxWireGuardExitCleanupObligation::RouteCacheFlush;
            if let Err(persist) = persist_cleanup_intent(&neutral_obligation) {
                return Err(LinuxWireGuardExitApplyFailure {
                    error: anyhow!(
                        "{error:#}; failed to retire uncertain WireGuard interface creation \
                         intent: {persist:#}"
                    ),
                    cleanup_obligation: Some(neutral_obligation),
                });
            }
            return Err(apply_failure(error));
        }
    }
    let mut snapshot = match capture_apply_snapshot(
        runner,
        config,
        &iface,
        source_cidr,
        &initial_endpoint_specs,
        previous_runtime,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if created_interface {
                let mut obligation =
                    LinuxWireGuardExitCleanupObligation::CreatedInterface { interface: iface };
                if let Err(cleanup) =
                    cleanup_linux_wireguard_exit_obligation_with(runner, &mut obligation)
                {
                    return Err(LinuxWireGuardExitApplyFailure {
                        error: anyhow!(
                            "{error:#}; newly-created interface cleanup is pending: {cleanup:#}"
                        ),
                        cleanup_obligation: Some(obligation),
                    });
                }
            }
            return Err(apply_failure(error));
        }
    };

    let fresh_default_route = previous_default_route
        .as_deref()
        .and_then(crate::linux_default_route_spec_from_line)
        .map(|route| route.dev)
        .and_then(|interface| {
            crate::linux_default_route_from_lines_for_interface(
                &snapshot.main_default_routes,
                &interface,
            )
        })
        .filter(|route| route.dev != iface);
    if let Some(current) = fresh_default_route.as_ref() {
        previous_default_route = Some(current.line.clone());
    }
    let mut endpoint_specs = initial_endpoint_specs;
    if let Some(default) = fresh_default_route {
        for route in &mut endpoint_specs {
            route.gateway = default.gateway.clone();
            route.dev = default.dev.clone();
            route.src = default.source.clone();
        }
    }

    let conservative_progress =
        conservative_apply_progress(&endpoint_specs, previous_runtime, &snapshot);
    let mut write_ahead_obligation = LinuxWireGuardExitCleanupObligation::ApplyRollback(Box::new(
        LinuxWireGuardExitRollbackObligation {
            interface: iface.clone(),
            source_cidr: source_cidr.to_string(),
            snapshot: snapshot.clone(),
            progress: conservative_progress,
            created_interface,
        },
    ));
    if let Err(error) = persist_cleanup_intent(&write_ahead_obligation) {
        return match cleanup_linux_wireguard_exit_obligation_with(
            runner,
            &mut write_ahead_obligation,
        ) {
            Ok(()) => Err(apply_failure(
                error.context("persist WireGuard apply rollback before network mutation"),
            )),
            Err(cleanup) => Err(LinuxWireGuardExitApplyFailure {
                error: anyhow!(
                    "failed to persist WireGuard apply rollback before network mutation \
                     ({error:#}); immediate cleanup also failed ({cleanup:#})"
                ),
                cleanup_obligation: Some(write_ahead_obligation),
            }),
        };
    }

    let mut progress = ApplyProgress::default();
    if let Err(error) = apply_snapshot_mutations(
        runner,
        config,
        &iface,
        source_cidr,
        mesh_iface,
        &kernel_config,
        &endpoint_specs,
        previous_runtime,
        &mut snapshot,
        &mut progress,
        created_interface,
        &mut persist_cleanup_intent,
    ) {
        let mut obligation = LinuxWireGuardExitCleanupObligation::ApplyRollback(Box::new(
            LinuxWireGuardExitRollbackObligation {
                interface: iface,
                source_cidr: source_cidr.to_string(),
                snapshot,
                progress,
                created_interface,
            },
        ));
        return match cleanup_linux_wireguard_exit_obligation_with(runner, &mut obligation) {
            Ok(()) => Err(apply_failure(error)),
            Err(cleanup) => Err(LinuxWireGuardExitApplyFailure {
                error: anyhow!("{error:#}; WireGuard apply cleanup is pending: {cleanup:#}"),
                cleanup_obligation: Some(obligation),
            }),
        };
    }

    Ok(build_runtime(
        LinuxWireGuardExitRollbackObligation {
            interface: iface,
            source_cidr: source_cidr.to_string(),
            snapshot,
            progress,
            created_interface,
        },
        previous_default_route,
        previous_runtime,
        &endpoint_specs,
    ))
}

fn conservative_apply_progress(
    endpoint_specs: &[crate::LinuxEndpointBypassRoute],
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    snapshot: &ApplySnapshot,
) -> ApplyProgress {
    let mut endpoint_targets_started = endpoint_specs
        .iter()
        .map(|route| route.target.clone())
        .collect::<Vec<_>>();
    if let Some(runtime) = previous_runtime {
        endpoint_targets_started.extend(
            runtime
                .endpoint_routes
                .iter()
                .filter(|route| {
                    !endpoint_specs
                        .iter()
                        .any(|desired| desired.target == route.target)
                })
                .map(|route| route.target.clone()),
        );
    }
    endpoint_targets_started.sort();
    endpoint_targets_started.dedup();
    ApplyProgress {
        address_started: true,
        endpoint_targets_started,
        wireguard_started: true,
        link_started: true,
        table_started: true,
        policy_rule_added: !snapshot.policy_rule_existed,
        main_default_started: true,
    }
}

fn apply_failure(error: anyhow::Error) -> LinuxWireGuardExitApplyFailure {
    LinuxWireGuardExitApplyFailure {
        error,
        cleanup_obligation: None,
    }
}

fn build_runtime(
    applied: LinuxWireGuardExitRollbackObligation,
    mut previous_default_route: Option<String>,
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    endpoint_specs: &[crate::LinuxEndpointBypassRoute],
) -> LinuxWireGuardExitRuntime {
    let LinuxWireGuardExitRollbackObligation {
        interface: iface,
        source_cidr,
        snapshot,
        progress,
        created_interface,
    } = applied;
    let endpoint_routes = endpoint_specs
        .iter()
        .filter_map(|spec| {
            previous_runtime
                .and_then(|runtime| {
                    runtime
                        .endpoint_routes
                        .iter()
                        .find(|route| route.target == spec.target)
                })
                .or_else(|| {
                    snapshot
                        .endpoint_routes
                        .iter()
                        .find(|route| route.target == spec.target)
                })
                .cloned()
        })
        .collect();
    let interface_restore = merge_interface_restore(
        previous_runtime,
        &snapshot.address,
        &snapshot.wireguard_config,
        &snapshot.link,
    );
    let mut previous_main_default_routes = previous_runtime.map_or_else(
        || snapshot.main_default_routes.clone(),
        |runtime| runtime.previous_main_default_routes.clone(),
    );
    if previous_runtime.is_some() {
        for route in &snapshot.main_default_routes {
            let is_managed_default = crate::linux_default_route_spec_from_line(route)
                .is_some_and(|route| route.dev == iface);
            if !is_managed_default {
                upsert_runtime_underlay_route(&mut previous_main_default_routes, route);
            }
        }
    }
    if let Some(route) = previous_default_route.as_ref() {
        previous_default_route = Some(upsert_runtime_underlay_route(
            &mut previous_main_default_routes,
            route,
        ));
    }

    LinuxWireGuardExitRuntime {
        interface: iface,
        managed_address: snapshot.address.configured.clone(),
        source_cidr,
        table: WIREGUARD_EXIT_TABLE,
        priority: WIREGUARD_EXIT_RULE_PRIORITY,
        created_interface: created_interface
            || previous_runtime.is_some_and(|runtime| runtime.created_interface),
        previous_default_route,
        handshake_completed: false,
        endpoint_routes,
        previous_main_default_routes,
        previous_table_routes: previous_runtime.map_or_else(
            || snapshot.table_routes.clone(),
            |runtime| runtime.previous_table_routes.clone(),
        ),
        policy_rule_owned: progress.policy_rule_added
            || previous_runtime.is_some_and(|runtime| runtime.policy_rule_owned),
        interface_restore,
    }
}

fn linux_wireguard_exit_has_completed_handshake_with(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
) -> Result<bool> {
    let output = command_output_checked(
        runner,
        "wg",
        &strings(&["show", iface, "latest-handshakes"]),
    )?;
    parse_linux_wireguard_latest_handshakes(&output)
}

fn parse_linux_wireguard_latest_handshakes(output: &str) -> Result<bool> {
    let mut rows = output.lines().map(str::trim).filter(|row| !row.is_empty());
    let Some(row) = rows.next() else {
        return Ok(false);
    };
    if rows.next().is_some() {
        return Err(anyhow!(
            "WireGuard exit interface returned more than one peer handshake"
        ));
    }
    let mut fields = row.split_whitespace();
    let _peer = fields
        .next()
        .ok_or_else(|| anyhow!("WireGuard exit handshake row is missing a peer"))?;
    let timestamp = fields
        .next()
        .ok_or_else(|| anyhow!("WireGuard exit handshake row is missing a timestamp"))?;
    if fields.next().is_some() {
        return Err(anyhow!("WireGuard exit handshake row has extra fields"));
    }
    Ok(timestamp
        .parse::<u64>()
        .context("parse WireGuard exit handshake timestamp")?
        > 0)
}

fn upsert_runtime_underlay_route(routes: &mut Vec<String>, route: &str) -> String {
    if let Some(candidate) = routes.iter().find(|candidate| candidate.as_str() == route) {
        return candidate.clone();
    }
    let Some(incoming) = crate::linux_default_route_spec_from_line(route) else {
        routes.push(route.to_string());
        return route.to_string();
    };
    if let Some(existing) = routes
        .iter()
        .filter_map(|candidate| crate::linux_default_route_spec_from_line(candidate))
        .filter(|candidate| {
            candidate.dev == incoming.dev
                && candidate.gateway == incoming.gateway
                && candidate.source == incoming.source
                && candidate.on_link == incoming.on_link
                && candidate.metric <= incoming.metric
        })
        .min_by_key(|candidate| candidate.metric)
    {
        return existing.line;
    }
    routes.retain(|candidate| {
        crate::linux_default_route_spec_from_line(candidate)
            .is_none_or(|candidate| candidate.dev != incoming.dev)
    });
    routes.push(route.to_string());
    route.to_string()
}

fn merge_interface_restore(
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    address: &LinuxAddressRestore,
    wireguard_config: &str,
    link: &LinuxLinkState,
) -> LinuxInterfaceRestore {
    let Some(runtime) = previous_runtime else {
        return LinuxInterfaceRestore {
            addresses: vec![address.clone()],
            wireguard_config: wireguard_config.to_string(),
            link: link.clone(),
        };
    };
    let mut restore = runtime.interface_restore.clone();
    if !restore
        .addresses
        .iter()
        .any(|candidate| candidate.configured == address.configured)
    {
        restore.addresses.push(address.clone());
    }
    restore
}

fn capture_apply_snapshot(
    runner: &mut impl LinuxCommandRunner,
    config: &WireGuardExitConfig,
    iface: &str,
    source_cidr: &str,
    endpoint_specs: &[crate::LinuxEndpointBypassRoute],
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
) -> Result<ApplySnapshot> {
    let configured = config.address.trim();
    let address_output = command_output_checked(
        runner,
        "ip",
        &strings(&["-o", "address", "show", "dev", iface]),
    )?;
    let address = LinuxAddressRestore {
        configured: configured.to_string(),
        previous: linux_interface_address_for_config(&address_output, configured),
    };
    let wireguard_config = command_output_checked(runner, "wg", &strings(&["showconf", iface]))?;
    let link_output = command_output_checked(
        runner,
        "ip",
        &strings(&["-j", "link", "show", "dev", iface]),
    )?;
    let link = linux_link_state_from_json(&link_output)?;

    let mut targets = endpoint_specs
        .iter()
        .map(|route| route.target.clone())
        .collect::<Vec<_>>();
    if let Some(runtime) = previous_runtime {
        targets.extend(
            runtime
                .endpoint_routes
                .iter()
                .map(|route| route.target.clone()),
        );
    }
    targets.sort();
    targets.dedup();
    let endpoint_routes = targets
        .into_iter()
        .map(|target| {
            linux_ipv4_route_snapshot(runner, &[target.as_str()]).map(|previous_routes| {
                LinuxRouteRestore {
                    target,
                    previous_routes,
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let table_routes = linux_ipv4_table_snapshot(runner, WIREGUARD_EXIT_TABLE)?;
    let main_default_routes = linux_ipv4_route_snapshot(runner, &["default"])?;
    let rules = command_output_checked(runner, "ip", &strings(&["-4", "rule", "show"]))?;
    let policy_rule_existed = linux_wireguard_exit_policy_rule_exists(
        &rules,
        source_cidr,
        WIREGUARD_EXIT_TABLE,
        WIREGUARD_EXIT_RULE_PRIORITY,
    );

    Ok(ApplySnapshot {
        address,
        wireguard_config,
        link,
        endpoint_routes,
        main_default_routes,
        table_routes,
        policy_rule_existed,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_snapshot_mutations(
    runner: &mut impl LinuxCommandRunner,
    config: &WireGuardExitConfig,
    iface: &str,
    source_cidr: &str,
    mesh_iface: &str,
    kernel_config: &str,
    endpoint_specs: &[crate::LinuxEndpointBypassRoute],
    previous_runtime: Option<&LinuxWireGuardExitRuntime>,
    snapshot: &mut ApplySnapshot,
    progress: &mut ApplyProgress,
    created_interface: bool,
    persist_cleanup_intent: &mut impl FnMut(&LinuxWireGuardExitCleanupObligation) -> Result<()>,
) -> Result<()> {
    progress.address_started = true;
    replace_linux_address(runner, iface, config.address.trim())?;

    for route in endpoint_specs {
        progress.endpoint_targets_started.push(route.target.clone());
        apply_linux_endpoint_bypass_route(runner, route)?;
    }
    if let Some(runtime) = previous_runtime {
        for stale in runtime.endpoint_routes.iter().filter(|route| {
            !endpoint_specs
                .iter()
                .any(|desired| desired.target == route.target)
        }) {
            progress.endpoint_targets_started.push(stale.target.clone());
            restore_linux_route_target(runner, stale, None)?;
        }
    }

    progress.wireguard_started = true;
    set_linux_wireguard_config(runner, iface, kernel_config)?;

    progress.link_started = true;
    set_linux_wireguard_link(runner, iface, config.mtu)?;

    progress.table_started = true;
    replace_linux_policy_mesh_route(runner, source_cidr, mesh_iface)?;
    replace_linux_policy_default_route(runner, iface)?;

    if !snapshot.policy_rule_existed {
        progress.policy_rule_added = true;
        add_linux_wireguard_exit_policy_rule(runner, source_cidr)?;
    }

    progress.main_default_started = true;
    let captured_default_routes = snapshot.main_default_routes.clone();
    apply_linux_wireguard_exit_default_route(
        runner,
        iface,
        config.address.trim(),
        &captured_default_routes,
        |discovered| {
            for route in discovered {
                if !snapshot.main_default_routes.contains(route) {
                    snapshot.main_default_routes.push(route.clone());
                }
            }
            persist_cleanup_intent(&LinuxWireGuardExitCleanupObligation::ApplyRollback(
                Box::new(LinuxWireGuardExitRollbackObligation {
                    interface: iface.to_string(),
                    source_cidr: source_cidr.to_string(),
                    snapshot: snapshot.clone(),
                    progress: progress.clone(),
                    created_interface,
                }),
            ))
        },
    )?;
    flush_linux_route_cache(runner)
}

fn rollback_apply(
    runner: &mut impl LinuxCommandRunner,
    iface: &str,
    source_cidr: &str,
    snapshot: &ApplySnapshot,
    progress: &ApplyProgress,
) -> Result<()> {
    let mut failures = Vec::new();
    if progress.wireguard_started {
        record_cleanup_failure(
            &mut failures,
            "WireGuard configuration",
            restore_linux_wireguard_config(runner, iface, &snapshot.wireguard_config),
        );
    }
    if progress.address_started {
        record_cleanup_failure(
            &mut failures,
            "interface address",
            restore_linux_address(runner, iface, &snapshot.address),
        );
    }
    if progress.link_started {
        record_cleanup_failure(
            &mut failures,
            "link state",
            restore_linux_link(runner, iface, &snapshot.link),
        );
    }
    for target in progress.endpoint_targets_started.iter().rev() {
        if let Some(route) = snapshot
            .endpoint_routes
            .iter()
            .find(|route| &route.target == target)
        {
            record_cleanup_failure(
                &mut failures,
                &format!("endpoint route {}", route.target),
                restore_linux_route_target(runner, route, None),
            );
        }
    }
    if progress.policy_rule_added {
        record_cleanup_failure(
            &mut failures,
            "policy rule",
            delete_linux_wireguard_exit_policy_rule(
                runner,
                source_cidr,
                WIREGUARD_EXIT_TABLE,
                WIREGUARD_EXIT_RULE_PRIORITY,
            ),
        );
    }
    if progress.table_started {
        record_cleanup_failure(
            &mut failures,
            "policy table",
            restore_linux_table_snapshot(runner, WIREGUARD_EXIT_TABLE, &snapshot.table_routes),
        );
    }
    if progress.main_default_started {
        record_cleanup_failure(
            &mut failures,
            "main default routes",
            restore_linux_main_default_snapshot_exact(runner, iface, &snapshot.main_default_routes),
        );
    }
    finish_cleanup("WireGuard apply rollback", failures)
}

pub(crate) fn cleanup_linux_wireguard_exit_obligation(
    obligation: &mut LinuxWireGuardExitCleanupObligation,
) -> Result<()> {
    cleanup_linux_wireguard_exit_obligation_with(&mut SystemLinuxCommandRunner, obligation)
}

fn cleanup_linux_wireguard_exit_obligation_with(
    runner: &mut impl LinuxCommandRunner,
    obligation: &mut LinuxWireGuardExitCleanupObligation,
) -> Result<()> {
    loop {
        match obligation {
            LinuxWireGuardExitCleanupObligation::ApplyRollback(rollback) => {
                rollback_apply(
                    runner,
                    &rollback.interface,
                    &rollback.source_cidr,
                    &rollback.snapshot,
                    &rollback.progress,
                )
                .context("retry retained WireGuard apply rollback")?;
                *obligation = if rollback.created_interface {
                    LinuxWireGuardExitCleanupObligation::CreatedInterface {
                        interface: rollback.interface.clone(),
                    }
                } else {
                    LinuxWireGuardExitCleanupObligation::RouteCacheFlush
                };
            }
            LinuxWireGuardExitCleanupObligation::CreatedInterface { interface } => {
                delete_linux_wireguard_exit_link(runner, interface)
                    .context("retry retained newly-created WireGuard interface removal")?;
                *obligation = LinuxWireGuardExitCleanupObligation::RouteCacheFlush;
            }
            LinuxWireGuardExitCleanupObligation::RouteCacheFlush => {
                return flush_linux_route_cache(runner)
                    .context("retry retained WireGuard route-cache flush");
            }
        }
    }
}

pub(crate) fn cleanup_linux_wireguard_exit_upstream(
    runtime: &LinuxWireGuardExitRuntime,
) -> Result<()> {
    cleanup_linux_wireguard_exit_upstream_with(&mut SystemLinuxCommandRunner, runtime)
}

fn cleanup_linux_wireguard_exit_upstream_with(
    runner: &mut impl LinuxCommandRunner,
    runtime: &LinuxWireGuardExitRuntime,
) -> Result<()> {
    let mut failures = Vec::new();
    if !runtime.created_interface {
        record_cleanup_failure(
            &mut failures,
            "WireGuard configuration",
            restore_linux_wireguard_config(
                runner,
                &runtime.interface,
                &runtime.interface_restore.wireguard_config,
            ),
        );
        for address in runtime.interface_restore.addresses.iter().rev() {
            record_cleanup_failure(
                &mut failures,
                "interface address",
                restore_linux_address(runner, &runtime.interface, address),
            );
        }
        record_cleanup_failure(
            &mut failures,
            "link state",
            restore_linux_link(runner, &runtime.interface, &runtime.interface_restore.link),
        );
    }
    for route in runtime.endpoint_routes.iter().rev() {
        record_cleanup_failure(
            &mut failures,
            &format!("endpoint route {}", route.target),
            restore_linux_route_target(runner, route, None),
        );
    }
    if runtime.policy_rule_owned {
        record_cleanup_failure(
            &mut failures,
            "policy rule",
            delete_linux_wireguard_exit_policy_rule(
                runner,
                &runtime.source_cidr,
                runtime.table,
                runtime.priority,
            ),
        );
    }
    record_cleanup_failure(
        &mut failures,
        "policy table",
        restore_linux_table_snapshot(runner, runtime.table, &runtime.previous_table_routes),
    );
    record_cleanup_failure(
        &mut failures,
        "main default routes",
        restore_linux_main_default_snapshot(
            runner,
            &runtime.interface,
            &runtime.previous_main_default_routes,
        ),
    );
    if runtime.created_interface {
        record_cleanup_failure(
            &mut failures,
            "created interface",
            delete_linux_wireguard_exit_link(runner, &runtime.interface),
        );
    }
    record_cleanup_failure(
        &mut failures,
        "route-cache flush",
        flush_linux_route_cache(runner),
    );
    finish_cleanup("WireGuard exit cleanup", failures)
}

fn record_cleanup_failure(failures: &mut Vec<String>, resource: &str, result: Result<()>) {
    if let Err(error) = result {
        failures.push(format!("{resource}: {error:#}"));
    }
}

fn finish_cleanup(operation: &str, failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{operation} incomplete: {}", failures.join("; ")))
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
