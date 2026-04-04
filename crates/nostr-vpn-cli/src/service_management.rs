use super::*;

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

    let mut config = load_or_default_config(&config_path)?;
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    config.save(&config_path)?;

    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let executable = fs::canonicalize(&executable)
        .with_context(|| format!("failed to canonicalize {}", executable.display()))?;
    let config_path = fs::canonicalize(&config_path)
        .with_context(|| format!("failed to canonicalize {}", config_path.display()))?;
    let log_path = daemon_log_file_path(&config_path);
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
            args.announce_interval_secs.max(1),
            &log_path,
            args.force,
        )
    }

    #[cfg(target_os = "linux")]
    {
        linux_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.announce_interval_secs.max(1),
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
            args.announce_interval_secs.max(1),
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
            args.announce_interval_secs,
            args.force,
        );
        Err(anyhow!(
            "system service install is not implemented on this platform"
        ))
    }
}

fn service_uninstall(args: ServiceUninstallArgs) -> Result<()> {
    let _config_path = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_service::macos_uninstall_service(&_config_path)
    }

    #[cfg(target_os = "linux")]
    {
        linux_uninstall_service()
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
    let status = query_service_status(&_config_path)?;

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

pub(crate) fn query_service_status(_config_path: &Path) -> Result<ServiceStatusView> {
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
        let binary_version = service_binary
            .as_ref()
            .and_then(|path| query_binary_version(path))
            .unwrap_or_default();

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
        linux_query_service_status()
    }

    #[cfg(target_os = "windows")]
    {
        windows_query_service_status()
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
    let output = ProcessCommand::new(path)
        .args(["version", "--json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let info = serde_json::from_str::<VersionInfoView>(stdout.trim()).ok()?;
    let version = info.version.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

#[cfg(target_os = "linux")]
fn linux_service_unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{LINUX_SERVICE_UNIT_NAME}"))
}

#[cfg(target_os = "linux")]
fn linux_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
    force: bool,
) -> Result<()> {
    if !linux_systemctl_available() {
        return Err(anyhow!("systemd (systemctl) is not available on this host"));
    }

    let unit_path = linux_service_unit_path();
    if unit_path.exists() && !force {
        println!(
            "service already installed at {} (pass --force to reinstall)",
            unit_path.display()
        );
        return Ok(());
    }

    let _ = run_systemctl_allow_missing(
        &["disable", "--now", LINUX_SERVICE_UNIT_NAME],
        "disable/stop existing service",
        true,
    );
    stop_existing_daemons_before_service_install(config_path)?;
    let unit = linux_service_unit_content(
        executable,
        config_path,
        iface,
        announce_interval_secs,
        log_path,
    );
    let temp = unit_path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, unit).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to chmod {}", temp.display()))?;
    fs::rename(&temp, &unit_path).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp.display(),
            unit_path.display()
        )
    })?;

    run_systemctl_checked(&["daemon-reload"], "reload systemd")?;
    run_systemctl_checked(
        &["enable", "--now", LINUX_SERVICE_UNIT_NAME],
        "enable/start service",
    )?;
    println!("installed system service: {}", unit_path.display());
    println!("label: {LINUX_SERVICE_UNIT_NAME}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_uninstall_service() -> Result<()> {
    if !linux_systemctl_available() {
        return Err(anyhow!("systemd (systemctl) is not available on this host"));
    }

    run_systemctl_allow_missing(
        &["disable", "--now", LINUX_SERVICE_UNIT_NAME],
        "disable/stop service",
        true,
    )?;

    let unit_path = linux_service_unit_path();
    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .with_context(|| format!("failed to remove {}", unit_path.display()))?;
        println!("removed system service unit: {}", unit_path.display());
    } else {
        println!("system service unit not found: {}", unit_path.display());
    }

    run_systemctl_checked(&["daemon-reload"], "reload systemd")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_query_service_status() -> Result<ServiceStatusView> {
    let unit_path = linux_service_unit_path();
    let installed = unit_path.exists();
    let service_binary = linux_service_executable_path(&unit_path);
    let binary_version = service_binary
        .as_ref()
        .and_then(|path| query_binary_version(path))
        .unwrap_or_default();
    if !linux_systemctl_available() {
        return Ok(ServiceStatusView {
            supported: false,
            installed,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: LINUX_SERVICE_UNIT_NAME.to_string(),
            plist_path: unit_path.display().to_string(),
            binary_path: service_binary
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            binary_version,
        });
    }

    let output = run_systemctl_raw(
        &[
            "show",
            LINUX_SERVICE_UNIT_NAME,
            "--property=LoadState,ActiveState,SubState,MainPID",
            "--no-pager",
        ],
        "query service",
    )?;

    if !output.status.success() {
        return Ok(ServiceStatusView {
            supported: true,
            installed,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: LINUX_SERVICE_UNIT_NAME.to_string(),
            plist_path: unit_path.display().to_string(),
            binary_path: service_binary
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            binary_version,
        });
    }

    let show = String::from_utf8_lossy(&output.stdout);
    let (loaded, running, pid) = linux_service_status_from_show_output(&show);

    Ok(ServiceStatusView {
        supported: true,
        installed,
        disabled: false,
        loaded,
        running,
        pid,
        label: LINUX_SERVICE_UNIT_NAME.to_string(),
        plist_path: unit_path.display().to_string(),
        binary_path: service_binary
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        binary_version,
    })
}

#[cfg(target_os = "linux")]
fn linux_service_executable_path(unit_path: &Path) -> Option<PathBuf> {
    let unit = fs::read_to_string(unit_path).ok()?;
    linux_service_executable_path_from_unit_contents(&unit).map(PathBuf::from)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_executable_path_from_unit_contents(unit: &str) -> Option<String> {
    for line in unit.lines() {
        let Some(command) = line.trim().strip_prefix("ExecStart=") else {
            continue;
        };
        if let Some(quoted) = command.strip_prefix('"') {
            let executable = quoted.split_once('"')?.0;
            if !executable.trim().is_empty() {
                return Some(executable.to_string());
            }
        }
        let executable = command.split_whitespace().next()?.trim();
        if !executable.is_empty() {
            return Some(executable.to_string());
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_unit_content(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
) -> String {
    let exec = systemd_quote(&executable.display().to_string());
    let config = systemd_quote(&config_path.display().to_string());
    let iface = systemd_quote(iface);
    let log = systemd_quote(&log_path.display().to_string());
    format!(
        "[Unit]\nDescription=Nostr VPN daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec} daemon --service --config {config} --iface {iface} --announce-interval-secs {announce_interval_secs}\nRestart=always\nRestartSec=3\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
fn linux_systemctl_available() -> bool {
    ProcessCommand::new("systemctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_systemctl_checked(args: &[&str], context: &str) -> Result<()> {
    let output = run_systemctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "systemctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn run_systemctl_allow_missing(args: &[&str], context: &str, ignore_missing: bool) -> Result<()> {
    let output = run_systemctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && systemctl_missing_service_message(&details) {
        return Ok(());
    }

    Err(anyhow!(
        "systemctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn run_systemctl_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to systemctl {context}"))
}

#[cfg(target_os = "linux")]
fn systemctl_missing_service_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("could not be found")
        || lowered.contains("not loaded")
        || lowered.contains("no such file")
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_status_from_show_output(show: &str) -> (bool, bool, Option<u32>) {
    let mut load_state = None;
    let mut active_state = None;
    let mut sub_state = None;
    let mut pid = None;

    for line in show.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            load_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            active_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("SubState=") {
            sub_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            pid = parse_nonzero_pid(value);
        }
    }

    let loaded = load_state.as_deref() == Some("loaded");
    let running =
        active_state.as_deref() == Some("active") && sub_state.as_deref() == Some("running");
    (loaded, running, pid)
}

#[cfg(target_os = "windows")]
fn windows_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    force: bool,
) -> Result<()> {
    stop_daemon(StopArgs {
        config: Some(config_path.to_path_buf()),
        timeout_secs: 5,
        force: true,
    })?;

    if force {
        windows_stop_service(true)?;
        windows_delete_service(true)?;
    } else if windows_service_query()?.is_some() {
        return Err(anyhow!(
            "system service already installed (pass --force to reinstall)"
        ));
    }

    let bin_path = windows_service_bin_path(
        executable,
        config_path,
        iface,
        announce_interval_secs.max(1),
    );
    run_sc_checked(
        &[
            "create",
            WINDOWS_SERVICE_NAME,
            "type=",
            "own",
            "start=",
            "auto",
            "binPath=",
            &bin_path,
            "DisplayName=",
            WINDOWS_SERVICE_DISPLAY_NAME,
        ],
        "create service",
    )?;
    run_sc_checked(
        &[
            "description",
            WINDOWS_SERVICE_NAME,
            WINDOWS_SERVICE_DESCRIPTION,
        ],
        "set service description",
    )?;
    windows_start_service_and_wait(false, Duration::from_secs(10))?;
    println!("installed system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_uninstall_service() -> Result<()> {
    windows_stop_service(true)?;
    windows_delete_service(true)?;
    println!("removed system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_enable_service() -> Result<()> {
    let status = windows_query_service_status()?;
    if !status.installed {
        return Err(anyhow!("system service is not installed"));
    }

    run_sc_checked(
        &["config", WINDOWS_SERVICE_NAME, "start=", "auto"],
        "configure service start type",
    )?;
    windows_start_service_and_wait(true, Duration::from_secs(10))?;
    println!("enabled system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_disable_service() -> Result<()> {
    let status = windows_query_service_status()?;
    if !status.installed {
        return Err(anyhow!("system service is not installed"));
    }

    windows_stop_service(true)?;
    run_sc_checked(
        &["config", WINDOWS_SERVICE_NAME, "start=", "disabled"],
        "configure service start type",
    )?;
    println!("disabled system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_should_apply_config_via_service(status: &ServiceStatusView) -> bool {
    status.installed && !status.disabled
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_query_service_status() -> Result<ServiceStatusView> {
    let query = windows_service_query()?;
    let Some(query) = query else {
        return Ok(ServiceStatusView {
            supported: true,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: WINDOWS_SERVICE_NAME.to_string(),
            plist_path: WINDOWS_SERVICE_NAME.to_string(),
            binary_path: String::new(),
            binary_version: String::new(),
        });
    };

    let config = windows_service_config_query()?
        .ok_or_else(|| anyhow!("service query succeeded but service config lookup failed"))?;
    let query_text = String::from_utf8_lossy(&query.stdout);
    let config_text = String::from_utf8_lossy(&config.stdout);
    let (running, pid) = windows_service_status_from_query_output(&query_text);
    let disabled = windows_service_disabled_from_qc_output(&config_text);
    let service_binary = windows_service_binary_path_from_sc_qc_output(&config_text);
    let binary_version = service_binary
        .as_ref()
        .and_then(|path| query_binary_version(path))
        .unwrap_or_default();
    Ok(ServiceStatusView {
        supported: true,
        installed: true,
        disabled,
        loaded: !disabled,
        running,
        pid,
        label: WINDOWS_SERVICE_NAME.to_string(),
        plist_path: WINDOWS_SERVICE_NAME.to_string(),
        binary_path: service_binary
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        binary_version,
    })
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_binary_path_from_sc_qc_output(output: &str) -> Option<PathBuf> {
    let line = output
        .lines()
        .find(|line| line.trim_start().starts_with("BINARY_PATH_NAME"))?;
    let (_, command) = line.split_once(':')?;
    let command = command.trim();
    if let Some(quoted) = command.strip_prefix('"') {
        let executable = quoted.split_once('"')?.0;
        if executable.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(executable))
        }
    } else {
        let executable = command.split_whitespace().next()?.trim();
        if executable.is_empty() {
            None
        } else {
            Some(PathBuf::from(executable))
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_service_query() -> Result<Option<std::process::Output>> {
    let output = run_sc_raw(&["queryex", WINDOWS_SERVICE_NAME], "query service")?;
    if output.status.success() {
        return Ok(Some(output));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if windows_service_missing_message(&details) {
        return Ok(None);
    }

    Err(anyhow!(
        "sc query failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_config_query() -> Result<Option<std::process::Output>> {
    let output = run_sc_raw(&["qc", WINDOWS_SERVICE_NAME], "query service config")?;
    if output.status.success() {
        return Ok(Some(output));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if windows_service_missing_message(&details) {
        return Ok(None);
    }

    Err(anyhow!(
        "sc qc failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn windows_start_service(ignore_already_running: bool) -> Result<()> {
    let output = run_sc_raw(&["start", WINDOWS_SERVICE_NAME], "start service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_already_running && windows_service_already_running_message(&details) {
        return Ok(());
    }
    Err(anyhow!(
        "sc start failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_start_service_and_wait(
    ignore_already_running: bool,
    timeout: Duration,
) -> Result<()> {
    windows_start_service(ignore_already_running)?;
    windows_wait_for_service_running(timeout)
}

#[cfg(target_os = "windows")]
fn windows_wait_for_service_running(timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if windows_query_service_status()?.running {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(anyhow!(
        "system service did not reach running state within {}s",
        timeout.as_secs()
    ))
}

#[cfg(target_os = "windows")]
fn windows_stop_service(ignore_missing: bool) -> Result<()> {
    let output = run_sc_raw(&["stop", WINDOWS_SERVICE_NAME], "stop service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing
        && (windows_service_missing_message(&details)
            || windows_service_not_active_message(&details))
    {
        return Ok(());
    }
    Err(anyhow!(
        "sc stop failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn windows_delete_service(ignore_missing: bool) -> Result<()> {
    let output = run_sc_raw(&["delete", WINDOWS_SERVICE_NAME], "delete service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && windows_service_missing_message(&details) {
        return Ok(());
    }
    Err(anyhow!(
        "sc delete failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn run_sc_checked(args: &[&str], context: &str) -> Result<std::process::Output> {
    let output = run_sc_raw(args, context)?;
    if output.status.success() {
        return Ok(output);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "sc {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn run_sc_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("sc.exe")
        .args(args)
        .output()
        .with_context(|| format!("failed to sc.exe {context}"))
}

#[cfg(target_os = "windows")]
fn windows_service_missing_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("failed 1060") || lowered.contains("does not exist as an installed service")
}

#[cfg(target_os = "windows")]
fn windows_service_not_active_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("failed 1062") || lowered.contains("service has not been started")
}

#[cfg(target_os = "windows")]
fn windows_service_already_running_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("failed 1056")
        || lowered.contains("instance of the service is already running")
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_status_from_query_output(output: &str) -> (bool, Option<u32>) {
    let mut running = false;
    let mut pid = None;

    for line in output.lines().map(str::trim) {
        if line.contains("STATE") && line.to_ascii_uppercase().contains("RUNNING") {
            running = true;
        } else if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("PID")
        {
            pid = parse_nonzero_pid(value);
        }
    }

    (running, pid)
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_disabled_from_qc_output(output: &str) -> bool {
    output.lines().map(str::trim).any(|line| {
        line.to_ascii_uppercase().contains("START_TYPE")
            && line.to_ascii_uppercase().contains("DISABLED")
    })
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_bin_path(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
) -> String {
    [
        windows_command_line_quote(&executable.display().to_string()),
        "daemon".to_string(),
        "--service".to_string(),
        "--config".to_string(),
        windows_command_line_quote(&config_path.display().to_string()),
        "--iface".to_string(),
        windows_command_line_quote(iface),
        "--announce-interval-secs".to_string(),
        announce_interval_secs.max(1).to_string(),
    ]
    .join(" ")
}

#[cfg(any(target_os = "windows", test))]
fn windows_command_line_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for ch in value.chars() {
        match ch {
            '\\' => backslashes = backslashes.saturating_add(1),
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    }
    quoted.push('"');
    quoted
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) fn parse_nonzero_pid(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok().filter(|pid| *pid > 0)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn systemd_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
