pub(crate) fn run_service_command(args: ServiceArgs) -> Result<()> {
    match args.command {
        ServiceCommand::Install(args) => service_install(args),
        ServiceCommand::Enable(args) => service_enable(args),
        ServiceCommand::Disable(args) => service_disable(args),
        ServiceCommand::Uninstall(args) => service_uninstall(args),
        ServiceCommand::Status(args) => service_status(args),
    }
}

fn service_install(args: ServiceInstallArgs) -> Result<()> {
    #[cfg(target_os = "macos")]
    crate::macos_privileged_files::require_root()?;
    #[cfg(target_os = "windows")]
    let config_path = windows_service_install_config_path(args.config)?;

    #[cfg(not(target_os = "windows"))]
    let config_path = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "windows")]
    {
        let legacy_config = legacy_config_path_from_dirs_config_dir(dirs::config_dir().as_deref());
        if config_path != legacy_config && legacy_config.exists() {
            stop_daemon(StopArgs {
                config: Some(legacy_config),
                timeout_secs: 5,
                force: true,
            })?;
        }
    }

    ensure_service_config_exists(&config_path)?;

    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let executable = fs::canonicalize(&executable)
        .with_context(|| format!("failed to canonicalize {}", executable.display()))?;
    let config_path = fs::canonicalize(&config_path)
        .with_context(|| format!("failed to canonicalize {}", config_path.display()))?;
    #[cfg(not(target_os = "macos"))]
    let log_path = daemon_log_file_path(&config_path)?;
    #[cfg(not(target_os = "macos"))]
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    #[cfg(target_os = "macos")]
    {
        macos_service::macos_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.mesh_refresh_interval_secs.max(1),
            args.force,
        )
    }

    #[cfg(target_os = "linux")]
    {
        linux_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.mesh_refresh_interval_secs.max(1),
            &log_path,
            args.force,
        )
    }

    #[cfg(target_os = "windows")]
    {
        windows_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.mesh_refresh_interval_secs.max(1),
            args.force,
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (
            executable,
            config_path,
            log_path,
            args.iface,
            args.mesh_refresh_interval_secs,
            args.force,
        );
        Err(anyhow!(
            "system service install is not implemented on this platform"
        ))
    }
}

pub(crate) fn ensure_service_config_exists(config_path: &Path) -> Result<()> {
    if config_path
        .try_exists()
        .with_context(|| format!("failed to inspect config {}", config_path.display()))?
    {
        let mut config = AppConfig::load(config_path)?;
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        config.save(config_path)?;
        return Ok(());
    }

    let mut config = AppConfig::generated();
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    config.save(config_path)
}

fn service_uninstall(args: ServiceUninstallArgs) -> Result<()> {
    let _config_path = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_service::macos_uninstall_service(&_config_path)
    }

    #[cfg(target_os = "linux")]
    {
        linux_uninstall_service(&_config_path)
    }

    #[cfg(target_os = "windows")]
    {
        windows_uninstall_service()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "system service uninstall is not implemented on this platform"
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn install_service_executable_copy(source: &Path, destination: &Path) -> Result<()> {
    if let Ok(existing) = fs::canonicalize(destination)
        && existing == source
    {
        return Ok(());
    }

    let parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "service executable path has no parent: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let temp = destination.with_extension(format!("tmp-{}", std::process::id()));
    let copy_result = (|| -> Result<()> {
        let mut staged = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .with_context(|| format!("failed to create {}", temp.display()))?;
        std::io::copy(
            &mut fs::File::open(source)
                .with_context(|| format!("failed to open {}", source.display()))?,
            &mut staged,
        )
        .with_context(|| {
            format!(
                "failed to copy service executable from {} to {}",
                source.display(),
                temp.display()
            )
        })?;
        #[cfg(unix)]
        staged
            .set_permissions(fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", temp.display()))?;
        // Sync the staged bytes before rename so power loss right after
        // install cannot leave a truncated service binary.
        staged
            .sync_all()
            .with_context(|| format!("failed to sync {}", temp.display()))?;
        drop(staged);
        fs::rename(&temp, destination).with_context(|| {
            format!(
                "failed to move {} into {}",
                temp.display(),
                destination.display()
            )
        })?;
        // Sync the directory entry so the rename itself survives power loss.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(parent)
                .with_context(|| format!("failed to open {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("failed to sync {}", parent.display()))?;
        }
        Ok(())
    })();

    if copy_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    copy_result
}

fn service_enable(args: ServiceControlArgs) -> Result<()> {
    let _config_path = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_service::macos_enable_service(&_config_path)
    }

    #[cfg(target_os = "windows")]
    {
        windows_enable_service()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow!(
            "system service enable is not implemented on this platform"
        ))
    }
}

fn service_disable(args: ServiceControlArgs) -> Result<()> {
    let _config_path = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_service::macos_disable_service(&_config_path)
    }

    #[cfg(target_os = "windows")]
    {
        windows_disable_service()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow!(
            "system service disable is not implemented on this platform"
        ))
    }
}

fn service_status(args: ServiceStatusArgs) -> Result<()> {
    let _config_path = args.config.unwrap_or_else(default_config_path);
    let status =
        query_service_status_with_binary_version(&_config_path, !args.skip_binary_version)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if !status.supported {
        println!("service: unsupported on this platform");
        return Ok(());
    }

    println!("service_label: {}", status.label);
    println!("service_plist: {}", status.plist_path);
    println!("service_installed: {}", status.installed);
    println!("service_disabled: {}", status.disabled);
    println!("service_loaded: {}", status.loaded);
    println!("service_running: {}", status.running);
    if let Some(pid) = status.pid {
        println!("service_pid: {pid}");
    }
    if !status.binary_path.trim().is_empty() {
        println!("service_binary: {}", status.binary_path);
    }
    if !status.binary_version.trim().is_empty() {
        println!("service_binary_version: {}", status.binary_version);
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn query_service_status(_config_path: &Path) -> Result<ServiceStatusView> {
    query_service_status_with_binary_version(_config_path, true)
}

pub(crate) fn query_service_status_with_binary_version(
    _config_path: &Path,
    include_binary_version: bool,
) -> Result<ServiceStatusView> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = macos_service::macos_service_plist_path(_config_path);
        let label = macos_service::macos_service_label(_config_path);
        let installed = plist_path.exists();
        if !installed {
            return Ok(ServiceStatusView {
                supported: true,
                installed: false,
                disabled: false,
                loaded: false,
                running: false,
                pid: None,
                label,
                plist_path: plist_path.display().to_string(),
                binary_path: String::new(),
                binary_version: String::new(),
            });
        }

        let disabled = macos_service::macos_service_disabled(_config_path).unwrap_or(false);
        let (loaded, running, pid) = if disabled {
            (false, false, None)
        } else {
            match macos_service::macos_service_print(_config_path) {
                Ok(output) => (
                    true,
                    macos_service::macos_service_print_is_running(&output),
                    macos_service::macos_service_print_pid(&output),
                ),
                Err(_) => (false, false, None),
            }
        };
        let service_binary = macos_service::macos_service_executable_path(&plist_path);
        let binary_version = if include_binary_version {
            service_binary
                .as_ref()
                // Status may itself be run as root. Never execute an unsafe
                // legacy helper merely to discover its version.
                .filter(|path| crate::macos_privileged_files::validate_artifact(path).is_ok())
                .and_then(|path| query_binary_version(path))
                .unwrap_or_default()
        } else {
            String::new()
        };

        Ok(ServiceStatusView {
            supported: true,
            installed: true,
            disabled,
            loaded,
            running,
            pid,
            label,
            plist_path: plist_path.display().to_string(),
            binary_path: service_binary
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            binary_version,
        })
    }

    #[cfg(target_os = "linux")]
    {
        linux_query_service_status(_config_path, include_binary_version)
    }

    #[cfg(target_os = "windows")]
    {
        windows_query_service_status(include_binary_version)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(ServiceStatusView {
            supported: false,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: "nvpn".to_string(),
            plist_path: String::new(),
            binary_path: String::new(),
            binary_version: String::new(),
        })
    }
}

fn query_binary_version(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let mut child = ProcessCommand::new(path)
        .args(["version", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= BINARY_VERSION_QUERY_TIMEOUT => {
                let _ = child.kill();
                let _ = child.try_wait();
                return None;
            }
            Ok(None) => thread::sleep(BINARY_VERSION_QUERY_POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }

    let mut stdout = Vec::new();
    child.stdout.take()?.read_to_end(&mut stdout).ok()?;

    let stdout = String::from_utf8_lossy(&stdout);
    let info = serde_json::from_str::<VersionInfoView>(stdout.trim()).ok()?;
    let version = info.version.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod install_service_executable_copy_tests {
    use super::*;

    #[test]
    fn install_service_executable_copy_lands_synced_executable_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "nvpn-install-service-copy-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create staging directory");
        let source = dir.join("nvpn-daemon-source");
        let destination = dir.join("nvpn-daemon-installed");
        fs::write(&source, b"service executable bytes").expect("write source bytes");

        install_service_executable_copy(&source, &destination)
            .expect("service executable installation succeeds");
        assert_eq!(
            fs::read(&destination).expect("read installed file"),
            b"service executable bytes"
        );
        assert!(
            fs::metadata(&destination)
                .expect("installed file metadata")
                .permissions()
                .mode()
                & 0o111
                != 0,
            "installed service executable stays runnable"
        );

        fs::remove_dir_all(&dir).expect("clean up staging directory");
    }
}
