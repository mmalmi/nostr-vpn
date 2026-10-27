use super::*;

pub(super) fn daemon_termination_wait()
-> Result<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        Ok(Box::pin(async move {
            let _ = signal.recv().await;
        }))
    }
    #[cfg(not(unix))]
    Ok(Box::pin(std::future::pending()))
}

pub(super) struct DaemonVpnShutdown<'a> {
    pub(super) port_mapping_runtime: &'a mut PortMappingRuntime,
    pub(super) fips_tunnel_runtime: Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    pub(super) tunnel_runtime: &'a mut CliTunnelRuntime,
    pub(super) config_path: &'a Path,
    pub(super) state_file: &'a Path,
    pub(super) pid_file: &'a Path,
    pub(super) expected_peers: usize,
    pub(super) network_snapshot: &'a crate::diagnostics::NetworkSnapshot,
    pub(super) network_changed_at: Option<u64>,
    pub(super) captive_portal: Option<bool>,
    pub(super) failure: Option<anyhow::Error>,
}

trait DaemonShutdownOwnershipActions {
    fn write_terminal_state(&mut self) -> Result<()>;
    fn clear_control_ready(&mut self);
    fn remove_pid_record(&mut self);
}

struct SystemDaemonShutdownOwnership<'a> {
    config_path: &'a Path,
    state_file: &'a Path,
    pid_file: &'a Path,
    final_state: &'a DaemonRuntimeState,
}

impl DaemonShutdownOwnershipActions for SystemDaemonShutdownOwnership<'_> {
    fn write_terminal_state(&mut self) -> Result<()> {
        write_daemon_state(self.state_file, self.final_state)
            .context("failed to write terminal daemon state")
    }

    fn clear_control_ready(&mut self) {
        clear_daemon_control_ready(self.config_path);
    }

    fn remove_pid_record(&mut self) {
        remove_current_daemon_pid_record(self.pid_file);
    }
}

fn finalize_daemon_shutdown_ownership(
    actions: &mut impl DaemonShutdownOwnershipActions,
    mut failures: Vec<String>,
) -> Result<()> {
    if let Err(error) = actions.write_terminal_state() {
        failures.push(format!(
            "failed to persist terminal daemon state: {error:#}"
        ));
    }
    actions.clear_control_ready();
    actions.remove_pid_record();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("{}", failures.join("; ")))
    }
}

pub(super) async fn shutdown_daemon_vpn(shutdown: DaemonVpnShutdown<'_>) -> Result<()> {
    let mut failures = Vec::new();
    let mut preserve_fips_cleanup_ownership = false;
    shutdown.port_mapping_runtime.stop().await;
    if let Some(runtime) = shutdown.fips_tunnel_runtime {
        if let Err(error) = stop_fips_private_tunnel_runtime(shutdown.config_path, runtime).await {
            eprintln!("daemon: failed to stop FIPS private mesh: {error}");
            failures.push(error.to_string());
            preserve_fips_cleanup_ownership = true;
        }
    } else if let Err(persist_error) =
        persist_fips_daemon_network_cleanup_state(shutdown.config_path, None)
    {
        failures.push(format!(
            "failed to persist pending FIPS cleanup ownership: {persist_error:#}"
        ));
    }
    shutdown.tunnel_runtime.stop();
    if !preserve_fips_cleanup_ownership
        && let Err(error) =
            persist_daemon_network_cleanup_state(shutdown.config_path, shutdown.tunnel_runtime)
    {
        eprintln!("daemon: failed to clear network cleanup state: {error}");
        failures.push(format!("failed to clear network cleanup state: {error:#}"));
    }
    let network = shutdown
        .network_snapshot
        .summary(shutdown.network_changed_at, shutdown.captive_portal);
    let final_state = if failures.is_empty() {
        disconnected_daemon_runtime_state(shutdown.expected_peers, &network)
    } else {
        cleanup_failed_daemon_runtime_state(shutdown.expected_peers, &network, &failures)
    };
    if let Some(error) = shutdown.failure {
        failures.push(format!(
            "daemon stopped after fatal runtime failure: {error:#}"
        ));
    }
    finalize_daemon_shutdown_ownership(
        &mut SystemDaemonShutdownOwnership {
            config_path: shutdown.config_path,
            state_file: shutdown.state_file,
            pid_file: shutdown.pid_file,
            final_state: &final_state,
        },
        failures,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeShutdownOwnership {
        events: Vec<&'static str>,
        fail_state_write: bool,
    }

    impl DaemonShutdownOwnershipActions for FakeShutdownOwnership {
        fn write_terminal_state(&mut self) -> Result<()> {
            self.events.push("write-terminal");
            if self.fail_state_write {
                Err(anyhow!("synthetic state write failure"))
            } else {
                Ok(())
            }
        }

        fn clear_control_ready(&mut self) {
            self.events.push("clear-control");
        }

        fn remove_pid_record(&mut self) {
            self.events.push("remove-pid");
        }
    }

    #[test]
    fn failed_network_cleanup_writes_terminal_state_then_clears_liveness_markers() {
        let mut actions = FakeShutdownOwnership::default();
        let error = finalize_daemon_shutdown_ownership(
            &mut actions,
            vec!["synthetic network cleanup failure".to_string()],
        )
        .expect_err("cleanup failure must remain visible");

        assert!(format!("{error:#}").contains("synthetic network cleanup failure"));
        assert_eq!(
            actions.events,
            vec!["write-terminal", "clear-control", "remove-pid"],
            "the cleanup obligation remains durable, but an exited process must not retain \
             stale liveness markers"
        );
    }

    #[test]
    fn disconnected_state_must_persist_before_ownership_markers_are_removed() {
        let mut actions = FakeShutdownOwnership {
            fail_state_write: true,
            ..FakeShutdownOwnership::default()
        };
        finalize_daemon_shutdown_ownership(&mut actions, Vec::new())
            .expect_err("state persistence failure");
        assert_eq!(
            actions.events,
            vec!["write-terminal", "clear-control", "remove-pid"]
        );

        let mut actions = FakeShutdownOwnership::default();
        finalize_daemon_shutdown_ownership(&mut actions, Vec::new()).expect("clean shutdown");
        assert_eq!(
            actions.events,
            vec!["write-terminal", "clear-control", "remove-pid"]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fatal_runtime_shutdown_clears_liveness_and_returns_error() {
        // Isolate the process-wide pending-cleanup registry from other tests.
        if std::env::var_os("NVPN_FATAL_SHUTDOWN_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "session_runtime::daemon_vpn_shutdown::tests::fatal_runtime_shutdown_clears_liveness_and_returns_error",
                    "--nocapture",
                ])
                .env("NVPN_FATAL_SHUTDOWN_TEST_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "nvpn-fatal-shutdown-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let config_path = dir.join("config.toml");
        let pid_file = dir.join("daemon.pid");
        let state_file = dir.join("daemon.state.json");
        write_daemon_pid_record(
            &pid_file,
            &DaemonPidRecord {
                pid: std::process::id(),
                config_path: config_path.to_string_lossy().into_owned(),
                started_at: unix_timestamp(),
            },
        )
        .unwrap();
        write_daemon_control_ready(&config_path, std::process::id()).unwrap();

        let mut port_mapping = PortMappingRuntime::default();
        let mut tunnel = CliTunnelRuntime::new("unused-fatal-shutdown-test");
        let error = shutdown_daemon_vpn(DaemonVpnShutdown {
            port_mapping_runtime: &mut port_mapping,
            fips_tunnel_runtime: None,
            tunnel_runtime: &mut tunnel,
            config_path: &config_path,
            state_file: &state_file,
            pid_file: &pid_file,
            expected_peers: 1,
            network_snapshot: &crate::diagnostics::NetworkSnapshot::default(),
            network_changed_at: None,
            captive_portal: None,
            failure: Some(anyhow!("endpoint shutdown timed out")),
        })
        .await
        .expect_err("successful cleanup must retain the fatal process result");

        assert!(format!("{error:#}").contains("endpoint shutdown timed out"));
        let state = read_daemon_state(&state_file).unwrap().unwrap();
        assert!(!state.vpn_active);
        assert!(!pid_file.exists());
        assert!(!daemon_control_ready_file_path(&config_path).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fatal_runtime_and_shutdown_errors_are_both_reported() {
        let mut actions = FakeShutdownOwnership {
            fail_state_write: true,
            ..Default::default()
        };
        let error = finalize_daemon_shutdown_ownership(
            &mut actions,
            vec!["endpoint shutdown timed out".into()],
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("endpoint shutdown timed out"));
        assert!(error.contains("synthetic state write failure"));
        assert_eq!(
            actions.events,
            vec!["write-terminal", "clear-control", "remove-pid"]
        );
    }
}
