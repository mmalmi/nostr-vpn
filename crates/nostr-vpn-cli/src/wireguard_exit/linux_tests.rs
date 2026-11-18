use std::cell::Cell;
#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::sync::Mutex;

use super::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeNetworkState {
    link_exists: bool,
    address: Option<String>,
    wireguard_config: String,
    mtu: u64,
    up: bool,
    endpoint_routes: BTreeMap<String, Vec<String>>,
    table_routes: Vec<String>,
    main_routes: Vec<String>,
    policy_rule_present: bool,
    unscoped_policy_rule_present: bool,
}

struct FakeRunner {
    state: FakeNetworkState,
    commands: Vec<(String, Vec<String>)>,
    stdin_commands: Vec<(String, Vec<String>, Vec<u8>)>,
    table_missing_when_empty: bool,
    table_error: Option<String>,
    fail_route_cache_once: bool,
    fail_showconf: bool,
    fail_link_delete: bool,
    fail_restore_endpoint: bool,
    fail_after_mutation: Option<usize>,
    mutation_count: usize,
    link_add_journal_ready: Option<Rc<Cell<bool>>>,
    usable_default_interfaces: HashSet<String>,
    fail_route_replace_once: Option<String>,
}

impl FakeRunner {
    fn existing() -> Self {
        let mut endpoint_routes = BTreeMap::new();
        endpoint_routes.insert(
            "198.51.100.20/32".to_string(),
            vec!["198.51.100.20/32 via 10.77.0.1 dev nvwg0 src 10.77.0.2 metric 7".to_string()],
        );
        Self {
            state: FakeNetworkState {
                link_exists: true,
                address: Some("10.77.0.2/24".to_string()),
                wireguard_config: "[Interface]\nListenPort = 41194\n".to_string(),
                mtu: 1380,
                up: true,
                endpoint_routes,
                table_routes: vec![
                    "default via 10.77.0.1 dev nvwg0 metric 9".to_string(),
                    "203.0.113.0/24 dev eth9 metric 31".to_string(),
                ],
                main_routes: vec![
                    "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10".to_string(),
                    "default via 203.0.113.1 dev eth1 src 203.0.113.10 metric 20".to_string(),
                ],
                policy_rule_present: true,
                unscoped_policy_rule_present: false,
            },
            commands: Vec::new(),
            stdin_commands: Vec::new(),
            table_missing_when_empty: false,
            table_error: None,
            fail_route_cache_once: false,
            fail_showconf: false,
            fail_link_delete: false,
            fail_restore_endpoint: false,
            fail_after_mutation: None,
            mutation_count: 0,
            link_add_journal_ready: None,
            usable_default_interfaces: ["eth0", "eth1", "eth2", "wlan0"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            fail_route_replace_once: None,
        }
    }

    fn success(stdout: impl Into<String>) -> LinuxCommandOutput {
        LinuxCommandOutput {
            success: true,
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn failure(code: i32, stderr: impl Into<String>) -> LinuxCommandOutput {
        LinuxCommandOutput {
            success: false,
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    fn mutation_result(&mut self) -> LinuxCommandOutput {
        self.mutation_count += 1;
        if self.fail_after_mutation == Some(self.mutation_count) {
            self.fail_after_mutation = None;
            Self::failure(
                5,
                format!("synthetic failure after mutation {}", self.mutation_count),
            )
        } else {
            Self::success("")
        }
    }

    fn route_replace(&mut self, args: &[String]) -> Result<LinuxCommandOutput> {
        let mut route = args[3..].to_vec();
        let table = route
            .windows(2)
            .position(|window| window[0] == "table")
            .map(|index| {
                let table = route[index + 1].clone();
                route.truncate(index);
                table
            });
        let line = route.join(" ");
        if self
            .fail_route_replace_once
            .as_ref()
            .is_some_and(|needle| line.contains(needle))
        {
            self.fail_route_replace_once = None;
            return Ok(Self::failure(5, "synthetic route replacement failure"));
        }
        if line.contains("via 10.77.0.1 dev nvwg0")
            && self.state.address.as_deref() != Some("10.77.0.2/24")
        {
            return Ok(Self::failure(2, "Error: Nexthop has invalid gateway."));
        }
        if self.fail_restore_endpoint && line.contains("via 10.77.0.1 dev nvwg0") {
            return Ok(Self::failure(5, "synthetic endpoint restore failure"));
        }
        if table.as_deref() == Some("51888") {
            replace_route(&mut self.state.table_routes, line);
        } else if route.first().is_some_and(|target| target == "default") {
            replace_route(&mut self.state.main_routes, line);
        } else if let Some(target) = route.first() {
            self.state
                .endpoint_routes
                .insert(target.clone(), vec![line]);
        }
        Ok(self.mutation_result())
    }
}

impl LinuxCommandRunner for FakeRunner {
    fn output(&mut self, program: &str, args: &[String]) -> Result<LinuxCommandOutput> {
        self.commands.push((program.to_string(), args.to_vec()));
        let joined = args.join(" ");

        if program == "ip" && args.iter().any(|arg| arg == "linkdown") {
            return Ok(Self::failure(
                2,
                r#"Error: either "to" is duplicate, or "linkdown" is garbage."#,
            ));
        }

        if program == "wg" && args.first().is_some_and(|arg| arg == "showconf") {
            if self.fail_showconf {
                return Ok(Self::failure(1, "Unable to access interface"));
            }
            return Ok(Self::success(self.state.wireguard_config.clone()));
        }
        if program == "wg" && args.first().is_some_and(|arg| arg == "set") {
            self.state.wireguard_config = "[Interface]\nPrivateKey = managed\n".to_string();
            return Ok(self.mutation_result());
        }

        match joined.as_str() {
            "-4 route show default" => {
                return Ok(Self::success(self.state.main_routes.join("\n") + "\n"));
            }
            "link show dev nvwg0" => {
                return Ok(if self.state.link_exists {
                    Self::success("")
                } else {
                    Self::failure(1, "Device \"nvwg0\" does not exist.")
                });
            }
            "link add dev nvwg0 type wireguard" => {
                if self
                    .link_add_journal_ready
                    .as_ref()
                    .is_some_and(|ready| !ready.get())
                {
                    return Ok(Self::failure(
                        5,
                        "link add reached before durable cleanup intent",
                    ));
                }
                self.state.link_exists = true;
                return Ok(self.mutation_result());
            }
            "link del dev nvwg0" => {
                if self.fail_link_delete {
                    return Ok(Self::failure(5, "synthetic link deletion failure"));
                }
                self.state.link_exists = false;
                return Ok(self.mutation_result());
            }
            "-o address show dev nvwg0" => {
                let output = self
                    .state
                    .address
                    .as_ref()
                    .map_or_else(String::new, |address| {
                        format!("7: nvwg0    inet {address} scope global nvwg0\n")
                    });
                return Ok(Self::success(output));
            }
            "-j link show dev nvwg0" => {
                let flags = if self.state.up { r#"["UP"]"# } else { "[]" };
                return Ok(Self::success(format!(
                    r#"[{{"ifname":"nvwg0","flags":{flags},"mtu":{}}}]"#,
                    self.state.mtu
                )));
            }
            "-4 route get 198.51.100.20" => {
                return Ok(Self::success(
                    "198.51.100.20 via 192.0.2.1 dev eth0 src 192.0.2.10\n",
                ));
            }
            "-4 route show 198.51.100.20/32" => {
                return Ok(Self::success(
                    self.state
                        .endpoint_routes
                        .get("198.51.100.20/32")
                        .cloned()
                        .unwrap_or_default()
                        .join("\n")
                        + "\n",
                ));
            }
            "-4 route show table 51888" => {
                if let Some(error) = self.table_error.as_ref() {
                    return Ok(Self::failure(2, error.clone()));
                }
                if self.table_missing_when_empty && self.state.table_routes.is_empty() {
                    return Ok(Self::failure(
                        2,
                        "Error: ipv4: FIB table does not exist.\nDump terminated",
                    ));
                }
                return Ok(Self::success(self.state.table_routes.join("\n") + "\n"));
            }
            "-4 rule show" => {
                let unscoped = self
                    .state
                    .unscoped_policy_rule_present
                    .then_some("10888:\tfrom 10.44.0.0/16 lookup 51888\n");
                let managed = self
                    .state
                    .policy_rule_present
                    .then_some("10888:\tfrom 10.44.0.0/16 iif nvpn0 lookup 51888\n");
                return Ok(Self::success(format!(
                    "0:\tfrom all lookup local\n{}{}32766:\tfrom all lookup main\n",
                    unscoped.unwrap_or(""),
                    managed.unwrap_or("")
                )));
            }
            "address replace 10.77.0.2/32 dev nvwg0" => {
                self.state.address = Some("10.77.0.2/32".to_string());
                return Ok(self.mutation_result());
            }
            "address del 10.77.0.2/32 dev nvwg0" => {
                self.state.address = None;
                return Ok(self.mutation_result());
            }
            "address replace 10.77.0.2/24 dev nvwg0" => {
                self.state.address = Some("10.77.0.2/24".to_string());
                return Ok(self.mutation_result());
            }
            "link set mtu 1420 up dev nvwg0" => {
                self.state.mtu = 1420;
                self.state.up = true;
                return Ok(self.mutation_result());
            }
            "link set dev nvwg0 mtu 1380" => {
                self.state.mtu = 1380;
                return Ok(self.mutation_result());
            }
            "link set dev nvwg0 mtu 1420" => {
                self.state.mtu = 1420;
                return Ok(self.mutation_result());
            }
            "link set up dev nvwg0" => {
                self.state.up = true;
                return Ok(self.mutation_result());
            }
            "-4 route del default" => {
                self.state.main_routes.clear();
                return Ok(self.mutation_result());
            }
            "-4 route del default dev nvwg0" => {
                self.state
                    .main_routes
                    .retain(|route| !route.contains("dev nvwg0"));
                return Ok(self.mutation_result());
            }
            route if route.starts_with("-4 route del default ") => {
                let route = args[3..].join(" ");
                let existed = self
                    .state
                    .main_routes
                    .iter()
                    .any(|candidate| kernel_route_identity(candidate) == route);
                self.state
                    .main_routes
                    .retain(|candidate| kernel_route_identity(candidate) != route);
                return Ok(if existed {
                    self.mutation_result()
                } else {
                    Self::failure(2, "RTNETLINK answers: No such process")
                });
            }
            "-4 route flush default" => {
                self.state.main_routes.clear();
                return Ok(self.mutation_result());
            }
            "-4 route flush table 51888" => {
                self.state.table_routes.clear();
                return Ok(self.mutation_result());
            }
            "-4 rule add priority 10888 from 10.44.0.0/16 iif nvpn0 table 51888" => {
                self.state.policy_rule_present = true;
                return Ok(self.mutation_result());
            }
            "-4 rule del priority 10888 from 10.44.0.0/16 iif nvpn0 table 51888" => {
                self.state.policy_rule_present = false;
                return Ok(self.mutation_result());
            }
            // Without `iif` the kernel deletes the first rule matching the rest,
            // which is the older unscoped rule when both exist.
            "-4 rule del priority 10888 from 10.44.0.0/16 table 51888" => {
                if self.state.unscoped_policy_rule_present {
                    self.state.unscoped_policy_rule_present = false;
                } else {
                    self.state.policy_rule_present = false;
                }
                return Ok(self.mutation_result());
            }
            "-4 route flush cache" => {
                if self.fail_route_cache_once {
                    self.fail_route_cache_once = false;
                    return Ok(Self::failure(5, "synthetic route-cache failure"));
                }
                return Ok(Self::success(""));
            }
            _ => {}
        }

        if args.starts_with(&strings(&["-4", "route", "replace"])) {
            return self.route_replace(args);
        }
        if args.starts_with(&strings(&["-4", "route", "del"])) {
            let target = args[3].clone();
            self.state.endpoint_routes.remove(&target);
            return Ok(self.mutation_result());
        }
        Ok(Self::failure(
            127,
            format!("unhandled fake command: {program} {joined}"),
        ))
    }

    fn output_with_stdin(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<LinuxCommandOutput> {
        self.commands.push((program.to_string(), args.to_vec()));
        self.stdin_commands
            .push((program.to_string(), args.to_vec(), stdin.to_vec()));
        if program == "wg" && args == strings(&["setconf", "nvwg0", "/dev/stdin"]) {
            self.state.wireguard_config = std::str::from_utf8(stdin)?.to_string();
            return Ok(self.mutation_result());
        }
        Ok(Self::failure(
            127,
            format!("unhandled fake stdin command: {program} {}", args.join(" ")),
        ))
    }

    fn ipv4_default_route_is_usable(&mut self, route: &crate::LinuxDefaultRouteSpec) -> bool {
        self.usable_default_interfaces.contains(&route.dev)
    }
}

fn replace_route(routes: &mut Vec<String>, route: String) {
    let identity = route_identity(&route);
    routes.retain(|candidate| route_identity(candidate) != identity);
    routes.push(route);
}

fn route_identity(route: &str) -> (Option<&str>, Option<&str>) {
    let tokens = route.split_whitespace().collect::<Vec<_>>();
    let metric = tokens
        .windows(2)
        .find(|window| window[0] == "metric")
        .map(|window| window[1]);
    (tokens.first().copied(), metric)
}

fn kernel_route_identity(route: &str) -> String {
    route
        .split_whitespace()
        .filter(|token| *token != "linkdown")
        .collect::<Vec<_>>()
        .join(" ")
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn config() -> WireGuardExitConfig {
    WireGuardExitConfig {
        enabled: true,
        interface: "nvwg0".to_string(),
        address: "10.77.0.2/32".to_string(),
        private_key: "private-key".to_string(),
        peer_public_key: "peer-key".to_string(),
        endpoint: "198.51.100.20:51820".to_string(),
        allowed_ips: vec!["0.0.0.0/0".to_string()],
        mtu: 1420,
        ..WireGuardExitConfig::default()
    }
}

#[test]
fn wireguard_policy_table_keeps_private_mesh_on_the_fips_tunnel() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("WireGuard exit apply");

    assert!(
        runner
            .state
            .table_routes
            .iter()
            .any(|route| route == "10.44.0.0/16 dev nvpn0"),
        "mesh-sourced replies to another private peer must take the FIPS tunnel, \
         not the policy table's WireGuard default"
    );
    assert!(
        runner
            .state
            .table_routes
            .iter()
            .any(|route| route == "default dev nvwg0"),
        "ordinary mesh-sourced exit traffic must still take WireGuard"
    );

    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime)
        .expect("WireGuard exit cleanup");
    assert_eq!(
        runner.state, initial,
        "cleanup must restore the exact preexisting policy table"
    );
}

fn command_index(runner: &FakeRunner, needle: &[&str]) -> usize {
    runner
        .commands
        .iter()
        .position(|(_, args)| args == &strings(needle))
        .unwrap_or_else(|| panic!("missing command: {needle:?}"))
}

#[test]
fn endpoint_resolution_is_pinned_once_for_kernel_and_bypass_ownership() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let mut desired = config();
    desired.endpoint = "vpn.example.test:51820".to_string();
    let resolver_calls = Cell::new(0);

    let runtime = apply_linux_wireguard_exit_upstream_with_journal(
        &mut runner,
        &desired,
        LinuxWireGuardExitApplyContext {
            source_cidr: "10.44.0.0/16",
            mesh_iface: "nvpn0",
            previous_runtime: None,
            previous_default_route_hint: Some(
                "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10",
            ),
        },
        |_| {
            let call = resolver_calls.get();
            resolver_calls.set(call + 1);
            Ok(if call == 0 {
                "198.51.100.20:51820".parse().expect("first DNS answer")
            } else {
                "203.0.113.20:51820"
                    .parse()
                    .expect("alternating DNS answer")
            })
        },
        |_| Ok(()),
    )
    .expect("pinned endpoint apply");

    assert_eq!(
        resolver_calls.get(),
        1,
        "endpoint DNS must run exactly once"
    );
    assert!(
        runner
            .state
            .wireguard_config
            .contains("Endpoint = 198.51.100.20:51820")
    );
    assert!(!runner.state.wireguard_config.contains("vpn.example.test"));
    assert!(
        runner
            .state
            .endpoint_routes
            .contains_key("198.51.100.20/32")
    );
    assert!(!runner.state.endpoint_routes.contains_key("203.0.113.20/32"));

    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime).expect("exact cleanup");
    assert_eq!(runner.state, initial);
}

#[test]
fn endpoint_resolution_failure_precedes_every_kernel_mutation() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let mut desired = config();
    desired.endpoint = "unresolvable.example.test:51820".to_string();

    let error = apply_linux_wireguard_exit_upstream_with_journal(
        &mut runner,
        &desired,
        LinuxWireGuardExitApplyContext {
            source_cidr: "10.44.0.0/16",
            mesh_iface: "nvpn0",
            previous_runtime: None,
            previous_default_route_hint: Some(
                "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10",
            ),
        },
        |_| Err(anyhow!("synthetic endpoint resolution failure")),
        |_| Ok(()),
    )
    .expect_err("resolver failure");

    assert!(format!("{error:#}").contains("synthetic endpoint resolution failure"));
    assert!(runner.commands.is_empty());
    assert!(runner.stdin_commands.is_empty());
    assert_eq!(runner.mutation_count, 0);
    assert_eq!(runner.state, initial);
}

#[test]
#[cfg(target_os = "linux")]
fn serialized_reapply_crash_repairs_rollback_before_prior_runtime_cleanup() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner
        .state
        .table_routes
        .retain(|route| !route.starts_with("default "));
    let initial = runner.state.clone();
    let previous_runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("initial WireGuard apply");
    let mut durable = crate::LinuxNetworkCleanupState {
        iface: "nvpn0".to_string(),
        exit_node_runtime: crate::LinuxExitNodeRuntime {
            wireguard_exit: Some(previous_runtime.clone()),
            ..crate::LinuxExitNodeRuntime::default()
        },
        ..crate::LinuxNetworkCleanupState::default()
    };
    let mut replacement = config();
    replacement.peer_public_key = "replacement-peer-key".to_string();
    let mut serialized = None;

    let failure = apply_linux_wireguard_exit_upstream_with_journal(
        &mut runner,
        &replacement,
        LinuxWireGuardExitApplyContext {
            source_cidr: "10.44.0.0/16",
            mesh_iface: "nvpn0",
            previous_runtime: Some(&previous_runtime),
            previous_default_route_hint: Some(
                "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10",
            ),
        },
        super::super::resolve_linux_wireguard_exit_endpoint,
        |obligation| {
            crate::fips_private_mesh::retain_linux_wireguard_apply_cleanup(
                &mut durable.exit_node_runtime,
                Some(&previous_runtime),
                obligation,
            );
            serialized = Some(serde_json::to_vec(&durable)?);
            Err(anyhow!("synthetic process crash after durable write-ahead"))
        },
    )
    .expect_err("simulated crash boundary");
    assert!(format!("{failure:#}").contains("synthetic process crash"));

    let mut repaired: crate::LinuxNetworkCleanupState = serde_json::from_slice(
        serialized
            .as_deref()
            .expect("write-ahead state was serialized"),
    )
    .expect("deserialize process-boundary cleanup state");
    assert_eq!(
        repaired
            .exit_node_runtime
            .pending_wireguard_exit_cleanup
            .len(),
        1
    );
    assert!(
        repaired.exit_node_runtime.wireguard_exit.is_some(),
        "the prior active runtime must be durable beside the apply rollback"
    );

    let runtime_cleanup_calls = Cell::new(0);
    crate::fips_private_mesh::cleanup_linux_wireguard_state_with(
        &mut repaired.exit_node_runtime,
        |_| Err(anyhow!("synthetic first rollback failure")),
        |_| {
            runtime_cleanup_calls.set(runtime_cleanup_calls.get() + 1);
            Ok(())
        },
    )
    .expect_err("failed transaction rollback remains pending");
    assert_eq!(runtime_cleanup_calls.get(), 0);
    assert!(repaired.exit_node_runtime.wireguard_exit.is_some());
    assert_eq!(
        repaired
            .exit_node_runtime
            .pending_wireguard_exit_cleanup
            .len(),
        1
    );

    let runner = RefCell::new(runner);
    crate::fips_private_mesh::cleanup_linux_wireguard_state_with(
        &mut repaired.exit_node_runtime,
        |obligation| {
            cleanup_linux_wireguard_exit_obligation_with(&mut *runner.borrow_mut(), obligation)
        },
        |runtime| cleanup_linux_wireguard_exit_upstream_with(&mut *runner.borrow_mut(), runtime),
    )
    .expect("retry rolls back the transaction before cleaning the prior runtime");
    let runner = runner.into_inner();

    assert!(
        repaired
            .exit_node_runtime
            .pending_wireguard_exit_cleanup
            .is_empty()
    );
    assert!(repaired.exit_node_runtime.wireguard_exit.is_none());
    assert_eq!(runner.state, initial);
    assert!(
        !runner
            .state
            .main_routes
            .iter()
            .any(|route| route == "default dev nvwg0 src 10.77.0.2"),
        "crash repair must not leave the restored old WireGuard default active"
    );
}

#[test]
fn failed_apply_restores_exact_state_and_address_before_via_routes() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    runner.fail_route_cache_once = true;

    let error = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect_err("final apply failure must roll back");

    assert!(error.to_string().contains("synthetic route-cache failure"));
    assert_eq!(runner.state, initial);
    assert!(
        command_index(
            &runner,
            &["address", "replace", "10.77.0.2/24", "dev", "nvwg0"]
        ) < command_index(
            &runner,
            &[
                "-4",
                "route",
                "replace",
                "default",
                "via",
                "10.77.0.1",
                "dev",
                "nvwg0",
                "metric",
                "9",
                "table",
                "51888",
            ]
        ),
        "old prefix must be restored before its dependent via route"
    );
}

#[test]
fn failure_after_each_apply_mutation_restores_exact_existing_state() {
    let _guard = lock_tests();
    let mut successful = FakeRunner::existing();
    let initial = successful.state.clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut successful,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("successful transaction");
    let apply_mutations = successful.mutation_count;
    assert_eq!(successful.state.address.as_deref(), Some("10.77.0.2/32"));
    assert!(successful.state.wireguard_config.contains("FwMark = 20054"));
    assert!(
        successful
            .state
            .table_routes
            .iter()
            .any(|route| route == "default dev nvwg0")
    );
    assert_eq!(successful.state.main_routes, initial.main_routes);
    assert_eq!(successful.state.endpoint_routes, initial.endpoint_routes);
    assert!(apply_mutations > 0);
    cleanup_linux_wireguard_exit_upstream_with(&mut successful, &runtime).expect("cleanup");
    assert_eq!(successful.state, initial);

    for fail_after in 1..=apply_mutations {
        let mut runner = FakeRunner::existing();
        let initial = runner.state.clone();
        runner.fail_after_mutation = Some(fail_after);
        let error = apply_linux_wireguard_exit_upstream_with(
            &mut runner,
            &config(),
            "10.44.0.0/16",
            None,
            Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
        )
        .expect_err("injected post-mutation failure");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("synthetic failure after mutation"),
            "unexpected failure {fail_after}: {error:#}"
        );
        assert_eq!(
            runner.state, initial,
            "state drift after mutation {fail_after}"
        );
    }
}

#[test]
fn post_apply_cleanup_restores_existing_interface_and_unowned_state() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("apply");

    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime)
        .expect("inbound-guard failure cleanup");
    assert_eq!(runner.state, initial);
    assert!(
        !runner
            .commands
            .iter()
            .any(|(_, args)| args.starts_with(&strings(&["-4", "rule", "del"]))),
        "a preexisting exact policy rule is not owned"
    );
}

#[test]
fn alternate_underlay_refresh_preserves_physical_routes_and_carrier_mark() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let primary = initial.main_routes[0].clone();
    let secondary = initial.main_routes[1].clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial primary apply");
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&secondary),
    )
    .expect("alternate underlay refresh");
    assert_eq!(runner.state.main_routes, initial.main_routes);
    assert_eq!(runner.state.endpoint_routes, initial.endpoint_routes);
    assert!(runner.state.wireguard_config.contains("FwMark = 20054"));
    assert!(!runtime.main_defaults_owned);
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime).expect("cleanup");
    assert_eq!(runner.state, initial);
}

#[test]
fn linkdown_route_annotations_are_never_replayed_to_iproute2() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.main_routes[0].push_str(" linkdown");
    let annotated_primary = runner.state.main_routes[0].clone();
    let expected_defaults = runner.state.main_routes.clone();

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&annotated_primary),
    )
    .expect("strict exit accepts an operational linkdown route annotation");
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime)
        .expect("cleanup accepts a persisted linkdown route annotation");

    assert_eq!(runner.state.main_routes, expected_defaults);
    assert!(
        runner
            .commands
            .iter()
            .all(|(_, args)| args.iter().all(|arg| arg != "linkdown")),
        "display-only route state must never be passed back to iproute2"
    );
}

#[test]
fn legacy_journal_still_restores_pre_policy_main_defaults() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect("fixture apply");
    let mut legacy = serde_json::to_value(&runtime).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("main_defaults_owned");
    let legacy: LinuxWireGuardExitRuntime = serde_json::from_value(legacy).unwrap();
    assert!(legacy.main_defaults_owned);
    runner.state.main_routes = vec!["default dev nvwg0 src 10.77.0.2".into()];
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &legacy).expect("legacy cleanup");
    assert_eq!(runner.state, initial);
}

#[test]
fn policy_rule_matches_only_packets_from_the_mesh_interface() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.policy_rule_present = false;
    // A rule matching the mesh source range from any interface also captures
    // local networks in that range, so it must not count as ours.
    runner.state.unscoped_policy_rule_present = true;
    let initial = runner.state.clone();

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect("WireGuard exit apply");
    command_index(
        &runner,
        &[
            "-4",
            "rule",
            "add",
            "priority",
            "10888",
            "from",
            "10.44.0.0/16",
            "iif",
            "nvpn0",
            "table",
            "51888",
        ],
    );

    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime)
        .expect("WireGuard exit cleanup");
    assert_eq!(
        runner.state, initial,
        "only the owned scoped rule is removed"
    );
}

#[test]
fn legacy_journal_removes_the_unscoped_policy_rule() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.policy_rule_present = false;
    let initial = runner.state.clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect("fixture apply");
    let mut legacy = serde_json::to_value(&runtime).unwrap();
    legacy.as_object_mut().unwrap().remove("policy_rule_iif");
    let legacy: LinuxWireGuardExitRuntime = serde_json::from_value(legacy).unwrap();
    // The version that wrote this journal installed the unscoped rule.
    runner.state.policy_rule_present = false;
    runner.state.unscoped_policy_rule_present = true;
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &legacy).expect("legacy cleanup");
    assert_eq!(runner.state, initial);
}

include!("linux_tests/reconciliation.rs");
include!("linux_tests/readiness.rs");
