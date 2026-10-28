#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn read_daemon_network_cleanup_state(
    path: &Path,
) -> Result<Option<DaemonNetworkCleanupState>> {
    #[cfg(target_os = "linux")]
    let raw = {
        use std::io::Read as _;

        let Some(directory) = open_linux_daemon_cleanup_directory(path, false)? else {
            return Ok(None);
        };
        let Some(mut file) = open_linux_daemon_cleanup_file(&directory, path)? else {
            return Ok(None);
        };
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .with_context(|| format!("failed to read daemon cleanup file {}", path.display()))?;
        raw
    };
    #[cfg(not(target_os = "linux"))]
    let raw = {
        if !path.exists() {
            return Ok(None);
        }
        if let Some(parent) = path.parent() {
            set_daemon_cleanup_directory_permissions(parent)?;
        }
        set_daemon_cleanup_file_permissions(path)?;
        fs::read(path)
            .with_context(|| format!("failed to read daemon cleanup file {}", path.display()))?
    };
    match serde_json::from_slice::<DaemonNetworkCleanupState>(&raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(parse_error) => {
            let trimmed = trim_runtime_json_padding(&raw);
            if trimmed.len() != raw.len()
                && !trimmed.is_empty()
                && let Ok(parsed) = serde_json::from_slice::<DaemonNetworkCleanupState>(trimmed)
            {
                // Linux reads through a validated handle in a user-controlled
                // parent. Do not reopen that pathname just to remove padding.
                #[cfg(not(target_os = "linux"))]
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

#[cfg(target_os = "linux")]
fn open_linux_daemon_cleanup_directory(path: &Path, create: bool) -> Result<Option<fs::File>> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    let parent = path.parent().context("daemon cleanup file has no parent")?;
    if create {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let directory = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to open daemon cleanup directory {}",
                    parent.display()
                )
            });
        }
    };
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "refusing untrusted daemon cleanup directory {}: expected daemon ownership without group/other write access",
            parent.display()
        ));
    }
    if create {
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(Some(directory))
}

#[cfg(target_os = "linux")]
fn open_linux_daemon_cleanup_file(directory: &fs::File, path: &Path) -> Result<Option<fs::File>> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};

    let name = std::ffi::CString::new(
        path.file_name()
            .context("daemon cleanup file has no name")?
            .as_bytes(),
    )?;
    // Bind the leaf lookup to the directory we checked. The config owner can
    // rename its parent while root is reading, but cannot replace this handle.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error)
            .with_context(|| format!("failed to open daemon cleanup file {}", path.display()));
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = validate_daemon_runtime_file(&file, path)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(anyhow!(
            "refusing untrusted daemon cleanup file {}: expected private daemon-owned file",
            path.display()
        ));
    }
    Ok(Some(file))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn write_daemon_network_cleanup_state(
    path: &Path,
    state: &DaemonNetworkCleanupState,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let _directory = {
        let directory = open_linux_daemon_cleanup_directory(path, true)?
            .context("daemon cleanup directory disappeared")?;
        // Reject an already untrusted journal before publishing new state.
        open_linux_daemon_cleanup_file(&directory, path)?;
        directory
    };
    #[cfg(not(target_os = "linux"))]
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
        write_private_runtime_file_durably(path, raw.as_bytes())
            .with_context(|| format!("failed to write daemon cleanup file {}", path.display()))?;
        // The atomic writer creates and protects its own inode. A Linux
        // pathname chmod here could bless a substituted writable journal.
        #[cfg(not(target_os = "linux"))]
        set_daemon_cleanup_file_permissions(path)?;
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
        // The split MagicDNS runtime journals outside the FIPS runtime
        // snapshot, so its intent must survive this rebuild.
        let magic_dns_active = read_daemon_network_cleanup_state(&path)?
            .is_some_and(|durable| durable.magic_dns_resolver_files);
        let state = runtime
            .and_then(
                crate::fips_private_mesh::FipsPrivateTunnelRuntime::macos_network_cleanup_state,
            )
            .or_else(crate::fips_private_mesh::pending_macos_network_cleanup_state);
        match state {
            Some(mut state) => {
                state.magic_dns_resolver_files |= magic_dns_active;
                write_daemon_network_cleanup_state(&path, &state)?;
            }
            None if magic_dns_active => write_daemon_network_cleanup_state(
                &path,
                &MacosNetworkCleanupState {
                    magic_dns_resolver_files: true,
                    ..Default::default()
                },
            )?,
            None => remove_runtime_file_if_exists(&path)?,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let magic_dns_active = read_daemon_network_cleanup_state(&path)?
            .is_some_and(|durable| durable.magic_dns_split_dns);
        let state = runtime
            .and_then(LinuxNetworkCleanupState::from_runtime)
            .or_else(crate::fips_private_mesh::pending_linux_network_cleanup_state);
        match state {
            Some(mut state) => {
                state.magic_dns_split_dns |= magic_dns_active;
                write_daemon_network_cleanup_state(&path, &state)?;
            }
            None if magic_dns_active => write_daemon_network_cleanup_state(
                &path,
                &LinuxNetworkCleanupState {
                    magic_dns_split_dns: true,
                    ..Default::default()
                },
            )?,
            None => remove_runtime_file_if_exists(&path)?,
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
        state.magic_dns_nrpt_rules |= durable.magic_dns_nrpt_rules;
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

/// Write or clear the split MagicDNS crash-repair intent in the daemon
/// cleanup journal. `retain` is set before the system resolver install and
/// cleared after a successful uninstall or startup repair.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn persist_fips_magic_dns_cleanup_intent(config_path: &Path, retain: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    let _journal_lock = windows_network_cleanup_journal_lock();
    let path = daemon_network_cleanup_file_path(config_path)?;
    let existing = read_daemon_network_cleanup_state(&path)?;
    if !retain && existing.is_none() {
        return Ok(());
    }
    let mut state = existing.unwrap_or_default();

    #[cfg(target_os = "linux")]
    {
        state.magic_dns_split_dns = retain;
    }

    #[cfg(target_os = "macos")]
    {
        state.magic_dns_resolver_files = retain;
    }

    #[cfg(target_os = "windows")]
    {
        state.magic_dns_nrpt_rules = retain;
    }

    if state.is_empty() {
        remove_runtime_file_if_exists(&path)
    } else {
        write_daemon_network_cleanup_state(&path, &state)
    }
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
    invalidate_daemon_probe_route(config_path)?;
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
    if runtime.probe_route_changes(&config) {
        invalidate_daemon_probe_route(config_path)?;
    }
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
    let probe_error = invalidate_daemon_probe_route(config_path).err();
    let before_error = persist_fips_daemon_network_cleanup_state(config_path, Some(&runtime)).err().or(probe_error);
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod magic_dns_cleanup_journal_tests {
    use super::*;

    fn magic_dns_intent_flag(state: &DaemonNetworkCleanupState) -> bool {
        #[cfg(target_os = "linux")]
        {
            state.magic_dns_split_dns
        }
        #[cfg(target_os = "macos")]
        {
            state.magic_dns_resolver_files
        }
        #[cfg(target_os = "windows")]
        {
            state.magic_dns_nrpt_rules
        }
    }

    #[test]
    fn magic_dns_cleanup_intent_survives_until_cleared() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nvpn-magicdns-journal-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        let config_path = dir.join("config.toml");
        let cleanup_path = daemon_network_cleanup_file_path(&config_path).expect("cleanup path");

        persist_fips_magic_dns_cleanup_intent(&config_path, true).expect("persist intent");
        let state = read_daemon_network_cleanup_state(&cleanup_path)
            .expect("read journaled state")
            .expect("intent must be journaled");
        assert!(magic_dns_intent_flag(&state));

        persist_fips_magic_dns_cleanup_intent(&config_path, false).expect("clear intent");
        assert!(
            !cleanup_path.exists(),
            "cleared intent must not leave an empty journal"
        );

        let _ = fs::remove_dir_all(&dir);
    }
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
        persist_fips_daemon_network_cleanup_state(&config_path, None)
            .expect("periodic persist");
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

#[cfg(all(test, target_os = "linux"))]
mod linux_cleanup_journal_files {
    use super::*;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    fn fixture() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nvpn-cleanup-trust-{}", rand::random::<u128>()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn private_cleanup_journal_round_trip_preserves_padded_snapshot() {
        let dir = fixture();
        let path = dir.join("cleanup/daemon.cleanup.json");
        assert!(read_daemon_network_cleanup_state(&path).unwrap().is_none());
        let state = DaemonNetworkCleanupState::default();
        write_daemon_network_cleanup_state(&path, &state).unwrap();
        let mut padded = fs::read(&path).unwrap();
        padded.extend_from_slice(b"\n\0\0");
        fs::write(&path, &padded).unwrap();
        let restored = read_daemon_network_cleanup_state(&path).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(state).unwrap()
        );
        assert_eq!(fs::read(&path).unwrap(), padded);
        fs::remove_file(&path).unwrap();
        assert!(read_daemon_network_cleanup_state(&path).unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsafe_cleanup_journal_permissions_are_not_repaired_or_discarded() {
        let dir = fixture();
        let path = dir.join("cleanup/daemon.cleanup.json");
        let state = DaemonNetworkCleanupState::default();
        write_daemon_network_cleanup_state(&path, &state).unwrap();
        let original = fs::read(&path).unwrap();
        for mode in [0o640, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_daemon_network_cleanup_state(&path).is_err());
            assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, mode);
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let parent = path.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_daemon_network_cleanup_state(&path).is_err());
        assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
        assert_eq!(fs::metadata(parent).unwrap().mode() & 0o777, 0o777);
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cleanup_journal_links_and_fifo_are_rejected_without_mutation() {
        let dir = fixture();
        let path = dir.join("cleanup/daemon.cleanup.json");
        let state = DaemonNetworkCleanupState::default();
        write_daemon_network_cleanup_state(&path, &state).unwrap();
        let target = dir.join("target");
        fs::rename(&path, &target).unwrap();
        let original = fs::read(&target).unwrap();
        for hard_link in [false, true] {
            if hard_link {
                fs::hard_link(&target, &path).unwrap();
            } else {
                symlink(&target, &path).unwrap();
            }
            assert!(read_daemon_network_cleanup_state(&path).is_err());
            assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
            assert_eq!(fs::read(&target).unwrap(), original);
            assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
            fs::remove_file(&path).unwrap();
        }
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_daemon_network_cleanup_state(&path).is_err());
        assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
        assert!(!fs::metadata(&path).unwrap().is_file());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cleanup_read_remains_bound_to_validated_directory_and_file() {
        let dir = fixture();
        let path = dir.join("cleanup/daemon.cleanup.json");
        write_daemon_network_cleanup_state(&path, &DaemonNetworkCleanupState::default()).unwrap();
        let original = fs::read(&path).unwrap();
        let directory = open_linux_daemon_cleanup_directory(&path, false)
            .unwrap()
            .unwrap();
        let retained = dir.join("retained");
        fs::rename(path.parent().unwrap(), &retained).unwrap();
        let replacement = dir.join("replacement");
        fs::create_dir(&replacement).unwrap();
        fs::write(
            replacement.join("daemon.cleanup.json"),
            b"untrusted replacement",
        )
        .unwrap();
        symlink(&replacement, path.parent().unwrap()).unwrap();
        assert!(read_daemon_network_cleanup_state(&path).is_err());
        let mut file = open_linux_daemon_cleanup_file(&directory, &path)
            .unwrap()
            .unwrap();
        let retained_file = retained.join("daemon.cleanup.json");
        fs::rename(&retained_file, retained.join("opened.json")).unwrap();
        fs::write(&retained_file, b"another replacement").unwrap();
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, original);
        assert_eq!(
            fs::read(replacement.join("daemon.cleanup.json")).unwrap(),
            b"untrusted replacement"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires root; isolated filesystem fixtures only"]
    fn root_cleanup_journal_rejects_unprivileged_ownership() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this ownership regression as root"
        );
        let dir = fixture();
        let path = dir.join("cleanup/daemon.cleanup.json");
        let state = DaemonNetworkCleanupState::default();
        write_daemon_network_cleanup_state(&path, &state).unwrap();
        let original = fs::read(&path).unwrap();
        std::os::unix::fs::chown(&path, Some(1), None).unwrap();
        assert!(read_daemon_network_cleanup_state(&path).is_err());
        assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
        assert_eq!(fs::metadata(&path).unwrap().uid(), 1);
        assert_eq!(fs::read(&path).unwrap(), original);
        std::os::unix::fs::chown(&path, Some(0), None).unwrap();
        std::os::unix::fs::chown(path.parent().unwrap(), Some(1), None).unwrap();
        assert!(read_daemon_network_cleanup_state(&path).is_err());
        assert!(write_daemon_network_cleanup_state(&path, &state).is_err());
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().uid(), 1);
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }
}
