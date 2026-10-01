#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn read_daemon_network_cleanup_state(
    path: &Path,
) -> Result<Option<DaemonNetworkCleanupState>> {
    if !path.exists() {
        return Ok(None);
    }

    if let Some(parent) = path.parent() {
        set_daemon_cleanup_directory_permissions(parent)?;
    }
    set_daemon_cleanup_file_permissions(path)?;
    let raw = fs::read(path)
        .with_context(|| format!("failed to read daemon cleanup file {}", path.display()))?;
    match serde_json::from_slice::<DaemonNetworkCleanupState>(&raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(parse_error) => {
            let trimmed = trim_runtime_json_padding(&raw);
            if trimmed.len() != raw.len()
                && !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_slice::<DaemonNetworkCleanupState>(trimmed)
            {
                if let Err(error) = write_private_runtime_file_atomically(path, trimmed) {
                    eprintln!(
                        "daemon: parsed padded cleanup file {} but failed to rewrite clean copy: {}",
                        path.display(),
                        error
                    );
                } else {
                    set_daemon_cleanup_file_permissions(path)?;
                }
                return Ok(Some(parsed));
            }

            Err(parse_error).with_context(|| {
                format!(
                    "refusing to discard unreadable network cleanup ownership in {}",
                    path.display()
                )
            })
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn write_daemon_network_cleanup_state(
    path: &Path,
    state: &DaemonNetworkCleanupState,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        set_daemon_cleanup_directory_permissions(parent)?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    #[cfg(target_os = "macos")]
    return fs::write_atomic(path, raw.as_bytes(), 0o600, None, true)
        .with_context(|| format!("failed to persist daemon cleanup file {}", path.display()));
    #[cfg(not(target_os = "macos"))]
    {
        write_private_runtime_file_atomically(path, raw.as_bytes())
            .with_context(|| format!("failed to write daemon cleanup file {}", path.display()))?;
        set_daemon_cleanup_file_permissions(path)?;
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .with_context(|| format!("failed to sync daemon cleanup file {}", path.display()))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!(
                        "failed to sync daemon cleanup directory {}",
                        parent.display()
                    )
                })?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn remove_runtime_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

pub(crate) fn persist_daemon_network_cleanup_state(
    config_path: &Path,
    tunnel_runtime: &CliTunnelRuntime,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        if let Some(state) = tunnel_runtime.macos_network_cleanup_state() {
            write_daemon_network_cleanup_state(&path, &state)?;
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (config_path, tunnel_runtime);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_network_cleanup_journal_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "windows")]
pub(crate) fn persist_windows_route_cleanup_intent(
    config_path: &Path,
    routes: &crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot,
    retain: bool,
) -> Result<()> {
    let _journal_lock = windows_network_cleanup_journal_lock();
    let path = daemon_network_cleanup_file_path(config_path)?;
    let mut state = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();
    if retain {
        state.routes.merge(routes.clone());
    } else {
        state.routes.remove(routes);
    }
    if state.is_empty() {
        remove_runtime_file_if_exists(&path)
    } else {
        write_daemon_network_cleanup_state(&path, &state)
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn persist_windows_route_cleanup_result(
    config_path: &Path,
    attempted: &crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot,
    remaining: &crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot,
) -> Result<()> {
    if attempted.is_empty() && remaining.is_empty() {
        return Ok(());
    }
    let _journal_lock = windows_network_cleanup_journal_lock();
    let path = daemon_network_cleanup_file_path(config_path)?;
    let mut state = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();
    state.routes.remove(attempted);
    state.routes.merge(remaining.clone());
    if state.is_empty() {
        remove_runtime_file_if_exists(&path)
    } else {
        write_daemon_network_cleanup_state(&path, &state)
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn persist_windows_native_wireguard_cleanup_intent(
    config_path: &Path,
    cleanup: &crate::wg_upstream_runtime::WindowsNativeWireGuardCleanupState,
) -> Result<()> {
    let _journal_lock = windows_network_cleanup_journal_lock();
    let path = daemon_network_cleanup_file_path(config_path)?;
    let mut state = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();
    state
        .native_wireguard
        .retain(|existing| !existing.same_owner(cleanup));
    if !cleanup.is_empty() {
        state.native_wireguard.push(cleanup.clone());
    }
    if state.is_empty() {
        remove_runtime_file_if_exists(&path)
    } else {
        write_daemon_network_cleanup_state(&path, &state)
    }
}

pub(crate) fn persist_fips_daemon_network_cleanup_state(
    config_path: &Path,
    runtime: Option<&crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let state = runtime
            .and_then(
                crate::fips_private_mesh::FipsPrivateTunnelRuntime::macos_network_cleanup_state,
            )
            .or_else(crate::fips_private_mesh::pending_macos_network_cleanup_state);
        if let Some(state) = state {
            write_daemon_network_cleanup_state(&path, &state)?;
        } else {
            remove_runtime_file_if_exists(&path)?;
        }
    }

    #[cfg(target_os = "linux")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let state = runtime
            .and_then(LinuxNetworkCleanupState::from_runtime)
            .or_else(crate::fips_private_mesh::pending_linux_network_cleanup_state);
        if let Some(state) = state {
            write_daemon_network_cleanup_state(&path, &state)?;
        } else {
            remove_runtime_file_if_exists(&path)?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _journal_lock = windows_network_cleanup_journal_lock();
        let path = daemon_network_cleanup_file_path(config_path)?;
        let durable = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();
        let mut state = WindowsNetworkCleanupState::from_runtime_and_pending(runtime);
        state.routes.merge(durable.routes);
        for cleanup in durable.native_wireguard {
            if let Some(existing) = state
                .native_wireguard
                .iter_mut()
                .find(|existing| existing.same_owner(&cleanup))
            {
                existing.merge_ownership(&cleanup);
            } else {
                state.native_wireguard.push(cleanup);
            }
        }
        // Secure DNS teardown records failures in the pending registry. A
        // successful teardown deliberately disappears from the current
        // runtime/pending snapshot, so do not resurrect its durable entry.
        if state.is_empty() {
            remove_runtime_file_if_exists(&path)?;
        } else {
            write_daemon_network_cleanup_state(&path, &state)?;
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (config_path, runtime);
    }

    Ok(())
}

fn persist_fips_failed_mutation_network_cleanup_state(
    config_path: &Path,
    runtime: Option<&crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let _journal_lock = windows_network_cleanup_journal_lock();
        let path = daemon_network_cleanup_file_path(config_path)?;
        let mut durable = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();
        let current = WindowsNetworkCleanupState::from_runtime_and_pending(runtime);
        durable.routes.merge(current.routes);
        for cleanup in current.native_wireguard {
            if let Some(existing) = durable
                .native_wireguard
                .iter_mut()
                .find(|existing| existing.same_owner(&cleanup))
            {
                existing.merge_ownership(&cleanup);
            } else {
                durable.native_wireguard.push(cleanup);
            }
        }
        durable
            .secure_dns_interface_indexes
            .extend(current.secure_dns_interface_indexes);
        durable.secure_dns_interface_indexes.sort_unstable();
        durable.secure_dns_interface_indexes.dedup();
        if durable.is_empty() {
            remove_runtime_file_if_exists(&path)
        } else {
            write_daemon_network_cleanup_state(&path, &durable)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        persist_fips_daemon_network_cleanup_state(config_path, runtime)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn persist_fips_secure_dns_cleanup_intent(
    config_path: &Path,
    intent: &crate::secure_dns_runtime::SystemDnsCleanupIntent,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    let _journal_lock = windows_network_cleanup_journal_lock();
    let path = daemon_network_cleanup_file_path(config_path)?;
    let mut state = read_daemon_network_cleanup_state(&path)?.unwrap_or_default();

    #[cfg(target_os = "linux")]
    {
        let crate::secure_dns_runtime::SystemDnsCleanupIntent::Linux(cleanup) = intent;
        state.secure_dns = Some(cleanup.clone());
    }

    #[cfg(target_os = "macos")]
    {
        let crate::secure_dns_runtime::SystemDnsCleanupIntent::MacosResolverFiles = intent;
        state.secure_dns_resolver_files = true;
    }

    #[cfg(target_os = "windows")]
    {
        let crate::secure_dns_runtime::SystemDnsCleanupIntent::WindowsInterface(interface_index) =
            intent;
        state.secure_dns_interface_indexes.push(*interface_index);
        state.secure_dns_interface_indexes.sort_unstable();
        state.secure_dns_interface_indexes.dedup();
    }

    write_daemon_network_cleanup_state(&path, &state)
}

pub(crate) fn persist_fips_private_tunnel_start_result<T>(
    config_path: &Path,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(start_error) => {
            match persist_fips_failed_mutation_network_cleanup_state(config_path, None) {
                Ok(()) => Err(start_error),
                Err(persist_error) => Err(anyhow!(
                    "{start_error:#}; failed to persist partial FIPS startup cleanup ownership: \
                 {persist_error:#}"
                )),
            }
        }
    }
}

pub(crate) async fn start_fips_private_tunnel_runtime(
    config_path: &Path,
    config: crate::fips_private_mesh::FipsPrivateTunnelConfig,
) -> Result<crate::fips_private_mesh::FipsPrivateTunnelRuntime> {
    let result =
        crate::fips_private_mesh::FipsPrivateTunnelRuntime::start(config, config_path).await;
    let runtime = persist_fips_private_tunnel_start_result(config_path, result)?;
    persist_started_runtime_or_rollback(
        runtime,
        |runtime| persist_fips_daemon_network_cleanup_state(config_path, Some(runtime)),
        |runtime| rollback_started_fips_runtime(config_path, runtime),
    )
    .await
}

pub(crate) async fn apply_fips_private_tunnel_runtime_config(
    config_path: &Path,
    runtime: &mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    config: crate::fips_private_mesh::FipsPrivateTunnelConfig,
) -> Result<()> {
    let apply_error = runtime.apply_config(config, config_path).await.err();
    let persist_error = if apply_error.is_some() {
        persist_fips_failed_mutation_network_cleanup_state(config_path, Some(runtime)).err()
    } else {
        persist_fips_daemon_network_cleanup_state(config_path, Some(runtime)).err()
    };
    match (apply_error, persist_error) {
        (None, None) => Ok(()),
        (Some(apply), None) => Err(apply),
        (None, Some(persist)) => {
            Err(persist.context("persist FIPS network cleanup ownership after config apply"))
        }
        (Some(apply), Some(persist)) => Err(anyhow!(
            "FIPS config apply failed ({apply:#}); failed to persist resulting network cleanup \
             ownership ({persist:#})"
        )),
    }
}

async fn rollback_started_fips_runtime(
    config_path: &Path,
    runtime: crate::fips_private_mesh::FipsPrivateTunnelRuntime,
) -> Result<()> {
    let stop_error = runtime.stop().await.err();
    let persist_error = if stop_error.is_some() {
        persist_fips_failed_mutation_network_cleanup_state(config_path, None).err()
    } else {
        persist_fips_daemon_network_cleanup_state(config_path, None).err()
    };
    match (stop_error, persist_error) {
        (None, None) => Ok(()),
        (Some(stop), None) => Err(stop),
        (None, Some(persist)) => Err(persist),
        (Some(stop), Some(persist)) => Err(anyhow!(
            "failed to stop FIPS private mesh: {stop:#}; failed to persist remaining cleanup \
             ownership: {persist:#}"
        )),
    }
}

async fn persist_started_runtime_or_rollback<T, Persist, Rollback, RollbackFuture>(
    runtime: T,
    persist: Persist,
    rollback: Rollback,
) -> Result<T>
where
    Persist: FnOnce(&T) -> Result<()>,
    Rollback: FnOnce(T) -> RollbackFuture,
    RollbackFuture: std::future::Future<Output = Result<()>>,
{
    let Err(persist_error) = persist(&runtime) else {
        return Ok(runtime);
    };
    match rollback(runtime).await {
        Ok(()) => Err(anyhow!(
            "failed to persist FIPS network cleanup ownership after startup: \
             {persist_error:#}; started runtime was rolled back"
        )),
        Err(rollback_error) => Err(anyhow!(
            "failed to persist FIPS network cleanup ownership after startup: \
             {persist_error:#}; failed to roll back the started FIPS runtime: \
             {rollback_error:#}"
        )),
    }
}

pub(crate) async fn stop_fips_private_tunnel_runtime(
    config_path: &Path,
    runtime: crate::fips_private_mesh::FipsPrivateTunnelRuntime,
) -> Result<()> {
    let before_error = persist_fips_daemon_network_cleanup_state(config_path, Some(&runtime)).err();
    let stop_error = runtime.stop().await.err();
    let stop_failed = stop_error.is_some();
    let remaining_error = if stop_error.is_none() {
        persist_fips_daemon_network_cleanup_state(config_path, None).err()
    } else {
        None
    };
    if stop_error.is_none() && remaining_error.is_none() {
        return Ok(());
    }

    let mut failures = Vec::new();
    if let Some(error) = stop_error {
        failures.push(format!("failed to stop FIPS private mesh: {error:#}"));
    }
    if (stop_failed || remaining_error.is_some())
        && let Some(error) = before_error
    {
        failures.push(format!(
            "failed to persist cleanup ownership before teardown: {error:#}"
        ));
    }
    if let Some(error) = remaining_error {
        failures.push(format!(
            "failed to persist remaining cleanup ownership after teardown: {error:#}"
        ));
    }
    Err(anyhow!(failures.join("; ")))
}

#[cfg(test)]
mod started_runtime_journal_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn successful_start_journal_returns_the_owned_runtime() {
        let rollback_called = Arc::new(AtomicBool::new(false));
        let rollback_observer = Arc::clone(&rollback_called);
        let runtime = persist_started_runtime_or_rollback(
            42_u8,
            |_| Ok(()),
            move |_| async move {
                rollback_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("successful journal keeps runtime owned");
        assert_eq!(runtime, 42);
        assert!(!rollback_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn failed_start_journal_rolls_back_before_returning_the_error() {
        let rollback_called = Arc::new(AtomicBool::new(false));
        let rollback_observer = Arc::clone(&rollback_called);
        let error = persist_started_runtime_or_rollback(
            42_u8,
            |_| Err(anyhow!("journal unavailable")),
            move |_| async move {
                rollback_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect_err("failed journal must fail startup");
        assert!(rollback_called.load(Ordering::SeqCst));
        assert!(
            error
                .to_string()
                .contains("started runtime was rolled back")
        );
    }

    #[tokio::test]
    async fn failed_start_journal_reports_a_failed_rollback() {
        let error = persist_started_runtime_or_rollback(
            42_u8,
            |_| Err(anyhow!("journal unavailable")),
            |_| async { Err(anyhow!("route cleanup failed")) },
        )
        .await
        .expect_err("failed journal and rollback must fail startup");
        let message = error.to_string();
        assert!(message.contains("journal unavailable"));
        assert!(message.contains("route cleanup failed"));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_network_cleanup_journal_tests {
    use super::*;

    fn native_cleanup(
        owner_token: &str,
        service_owned: bool,
        config_owned: bool,
    ) -> crate::wg_upstream_runtime::WindowsNativeWireGuardCleanupState {
        serde_json::from_value(serde_json::json!({
            "name": "nvpn-wg-exit",
            "config_path": r"C:\ProgramData\nostr-vpn\wireguard\owner\nvpn-wg-exit.conf",
            "wireguard_exe": r"C:\Program Files\WireGuard\wireguard.exe",
            "owner_token": owner_token,
            "service_owned": service_owned,
            "config_owned": config_owned,
        }))
        .expect("native cleanup fixture")
    }

    #[test]
    fn empty_route_cleanup_result_leaves_ownership_journal_untouched() {
        let dir = std::env::temp_dir().join(format!(
            "nvpn-empty-route-cleanup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let config_path = dir.join("config.toml");
        let cleanup_path = daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let empty = crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot::default();
        persist_windows_route_cleanup_result(&config_path, &empty, &empty)
            .expect("empty cleanup without a journal");
        assert!(!dir.exists());
        let owned = native_cleanup("nvpn-empty-route-cleanup", true, true);
        persist_windows_native_wireguard_cleanup_intent(&config_path, &owned)
            .expect("persist native ownership");
        let bytes = fs::read(&cleanup_path).expect("journal bytes");
        let modified = UNIX_EPOCH + std::time::Duration::from_secs(1);
        fs::OpenOptions::new()
            .write(true)
            .open(&cleanup_path)
            .expect("open journal")
            .set_times(fs::FileTimes::new().set_modified(modified))
            .expect("set old journal timestamp");

        persist_windows_route_cleanup_result(&config_path, &empty, &empty)
            .expect("empty cleanup result");
        assert_eq!(fs::read(&cleanup_path).expect("retained journal"), bytes);
        assert_eq!(
            fs::metadata(&cleanup_path)
                .expect("metadata")
                .modified()
                .expect("modified"),
            modified
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn route_cleanup_results_preserve_unrelated_native_ownership() {
        let dir = std::env::temp_dir().join(format!(
            "nvpn-route-cleanup-result-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let config_path = dir.join("config.toml");
        let cleanup_path = daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let owned = native_cleanup("nvpn-route-cleanup-result", true, true);
        persist_windows_native_wireguard_cleanup_intent(&config_path, &owned)
            .expect("persist native ownership");
        let routes: crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot =
            serde_json::from_value(serde_json::json!({
                "owned_routes": [{
                    "prefix": "198.51.100.20/32", "interface_index": 4,
                    "next_hop": "192.0.2.1", "metric": 1,
                    "interface_identity": "test-interface"
                }]
            }))
            .expect("route cleanup fixture");
        let empty = crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot::default();
        for (attempted, remaining) in [(&empty, &routes), (&routes, &empty)] {
            persist_windows_route_cleanup_result(&config_path, attempted, remaining)
                .expect("persist changed route cleanup");
            let retained = read_daemon_network_cleanup_state(&cleanup_path)
                .expect("read journal")
                .expect("native ownership retained");
            assert_eq!(&retained.routes, remaining);
            assert_eq!(retained.native_wireguard.len(), 1);
            assert_eq!(
                serde_json::to_value(&retained.native_wireguard[0]).expect("retained ownership"),
                serde_json::to_value(&owned).expect("original ownership")
            );
        }
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn periodic_persist_retains_inflight_native_intent_but_not_completed_dns() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nvpn-windows-cleanup-journal-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        let config_path = dir.join("config.toml");
        let cleanup_path = daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let owner_token = "nvpn-test-periodic-persist";
        let owned = native_cleanup(owner_token, true, true);
        let routes: crate::wg_upstream_runtime::WindowsRouteCleanupSnapshot =
            serde_json::from_value(serde_json::json!({
                "owned_routes": [{
                    "prefix": "198.51.100.20/32",
                    "interface_index": 4,
                    "next_hop": "192.0.2.1",
                    "metric": 1,
                    "interface_identity": "test-interface"
                }]
            }))
            .expect("route cleanup fixture");

        persist_windows_native_wireguard_cleanup_intent(&config_path, &owned)
            .expect("persist native intent");
        persist_windows_route_cleanup_intent(&config_path, &routes, true)
            .expect("persist route intent");
        persist_fips_secure_dns_cleanup_intent(
            &config_path,
            &crate::secure_dns_runtime::SystemDnsCleanupIntent::WindowsInterface(47),
        )
        .expect("persist secure DNS intent");

        // Native startup has not yet installed the handle in
        // runtime.wg_upstream. Periodic state persistence must retain its
        // write-ahead ownership while retiring successfully-cleaned DNS.
        persist_fips_daemon_network_cleanup_state(&config_path, None).expect("periodic persist");
        let retained = read_daemon_network_cleanup_state(&cleanup_path)
            .expect("read retained state")
            .expect("native ownership remains");
        assert_eq!(retained.native_wireguard.len(), 1);
        assert_eq!(
            serde_json::to_value(&retained.native_wireguard[0])
                .expect("serialize retained native state")["owner_token"],
            owner_token
        );
        assert!(
            !retained.routes.is_empty(),
            "periodic persistence must retain write-ahead route ownership"
        );
        assert!(retained.secure_dns_interface_indexes.is_empty());

        let completed = native_cleanup(owner_token, false, false);
        persist_windows_native_wireguard_cleanup_intent(&config_path, &completed)
            .expect("remove exact completed native intent");
        persist_windows_route_cleanup_intent(&config_path, &routes, false)
            .expect("remove exact completed route intent");
        persist_fips_daemon_network_cleanup_state(&config_path, None)
            .expect("periodic persist after cleanup");
        assert!(
            !cleanup_path.exists(),
            "successful exact native cleanup must not be resurrected"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
