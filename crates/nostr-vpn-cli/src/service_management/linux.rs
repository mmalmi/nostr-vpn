#[cfg(target_os = "linux")]
fn linux_service_unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{LINUX_SERVICE_UNIT_NAME}"))
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_binary_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/nvpn")
}

// `enable --now` and `disable --now` need systemd v220+. Some NAS and embedded
// hosts ship older systemd that rejects `--now`, so run the equivalent steps
// separately.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_enable_steps(unit: &str) -> [[&str; 2]; 2] {
    [["enable", unit], ["start", unit]]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_disable_steps(unit: &str) -> [[&str; 2]; 2] {
    [["stop", unit], ["disable", unit]]
}

#[cfg(target_os = "linux")]
fn linux_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
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

    let service_executable = linux_service_binary_path();
    let unit = linux_service_unit_content(
        &service_executable,
        config_path,
        iface,
        mesh_refresh_interval_secs,
        log_path,
    )?;
    for step in linux_service_disable_steps(LINUX_SERVICE_UNIT_NAME) {
        let _ = run_systemctl_allow_missing(&step, "disable/stop existing service", true);
    }
    stop_existing_daemons_before_service_install(config_path)?;
    install_service_executable_copy(executable, &service_executable)?;
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
    for step in linux_service_enable_steps(LINUX_SERVICE_UNIT_NAME) {
        run_systemctl_checked(&step, "enable/start service")?;
    }
    println!("installed system service: {}", unit_path.display());
    println!("label: {LINUX_SERVICE_UNIT_NAME}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_uninstall_service() -> Result<()> {
    if !linux_systemctl_available() {
        return Err(anyhow!("systemd (systemctl) is not available on this host"));
    }

    for step in linux_service_disable_steps(LINUX_SERVICE_UNIT_NAME) {
        run_systemctl_allow_missing(&step, "disable/stop service", true)?;
    }

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
fn linux_query_service_status(
    config_path: &Path,
    include_binary_version: bool,
) -> Result<ServiceStatusView> {
    let unit_path = linux_service_unit_path();
    let unit = fs::read_to_string(&unit_path).ok();
    let installed = unit
        .as_deref()
        .is_some_and(|unit| linux_service_unit_matches_config(unit, config_path));
    let service_binary = installed
        .then(|| linux_service_executable_path(&unit_path))
        .flatten();
    let binary_version = if include_binary_version {
        service_binary
            .as_ref()
            .and_then(|path| query_binary_version(path))
            .unwrap_or_default()
    } else {
        String::new()
    };
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

    if !installed {
        return Ok(ServiceStatusView {
            supported: true,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: LINUX_SERVICE_UNIT_NAME.to_string(),
            plist_path: unit_path.display().to_string(),
            binary_path: String::new(),
            binary_version: String::new(),
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
pub(crate) fn linux_service_config_path_from_unit_contents(unit: &str) -> Option<String> {
    let command = unit
        .lines()
        .find_map(|line| line.trim().strip_prefix("ExecStart="))?;
    let value = command.split_once(" --config ")?.1.trim_start();
    systemd_first_argument(value)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_unit_matches_config(unit: &str, config_path: &Path) -> bool {
    linux_service_config_path_from_unit_contents(unit)
        .is_some_and(|installed| installed == config_path.display().to_string())
}

#[cfg(any(target_os = "linux", test))]
fn systemd_first_argument(value: &str) -> Option<String> {
    let Some(quoted) = value.strip_prefix('"') else {
        return value.split_whitespace().next().map(ToOwned::to_owned);
    };
    let mut parsed = String::new();
    let mut escaped = false;
    for character in quoted.chars() {
        if escaped {
            parsed.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(parsed.replace("%%", "%").replace("$$", "$"));
        } else {
            parsed.push(character);
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_service_unit_content(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
    log_path: &Path,
) -> Result<String> {
    for (label, value) in [
        ("executable path", executable.to_string_lossy()),
        ("config path", config_path.to_string_lossy()),
        ("interface", std::borrow::Cow::Borrowed(iface)),
        ("log path", log_path.to_string_lossy()),
    ] {
        if value.chars().any(char::is_control) {
            return Err(anyhow!(
                "systemd {label} must not contain control characters"
            ));
        }
    }
    // StandardOutput/StandardError paths do not support quoted C escapes.
    // Reject line continuation and trailing whitespace rather than changing
    // their path identity when systemd reads the unit.
    let log = log_path.to_string_lossy();
    if log.ends_with('\\') || log.trim_end() != log {
        return Err(anyhow!(
            "systemd log path must not end with backslash or whitespace"
        ));
    }
    let exec = systemd_quote(&executable.display().to_string());
    let config = systemd_quote(&config_path.display().to_string().replace('$', "$$"));
    let iface = systemd_quote(&iface.replace('$', "$$"));
    let log = log.replace('%', "%%");
    Ok(format!(
        "[Unit]\nDescription=Nostr VPN daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec} daemon --service --config {config} --iface {iface} --mesh-refresh-interval-secs {mesh_refresh_interval_secs}\nRestart=always\nRestartSec=3\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=multi-user.target\n"
    ))
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
