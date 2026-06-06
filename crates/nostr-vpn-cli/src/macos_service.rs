use super::*;

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_plist_path(config_path: &Path) -> PathBuf {
    PathBuf::from(format!(
        "/Library/LaunchDaemons/{}.plist",
        macos_service_label(config_path)
    ))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_binary_path(config_path: &Path) -> PathBuf {
    PathBuf::from(format!(
        "/Library/PrivilegedHelperTools/{}",
        macos_service_label(config_path)
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_service_executable_path(plist_path: &Path) -> Option<PathBuf> {
    let plist = fs::read_to_string(plist_path).ok()?;
    macos_service_executable_path_from_plist_contents(&plist).map(PathBuf::from)
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_executable_path_from_plist_contents(plist: &str) -> Option<String> {
    let after_program_args = plist.split_once("<key>ProgramArguments</key>")?.1;
    let after_first_string = after_program_args.split_once("<string>")?.1;
    let executable = after_first_string.split_once("</string>")?.0.trim();
    if executable.is_empty() {
        None
    } else {
        Some(xml_unescape(executable))
    }
}

#[cfg(target_os = "macos")]
fn macos_service_target(config_path: &Path) -> String {
    format!("system/{}", macos_service_label(config_path))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_label(config_path: &Path) -> String {
    if macos_service_uses_default_label(config_path) {
        return MACOS_SERVICE_LABEL.to_string();
    }

    format!(
        "{MACOS_SERVICE_LABEL}.{}",
        macos_service_config_suffix(config_path)
    )
}

#[cfg(any(target_os = "macos", test))]
fn macos_service_uses_default_label(config_path: &Path) -> bool {
    canonicalize_lossy(config_path) == canonicalize_lossy(&default_config_path())
}

#[cfg(any(target_os = "macos", test))]
fn canonicalize_lossy(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(any(target_os = "macos", test))]
fn macos_service_config_suffix(config_path: &Path) -> String {
    let canonical = canonicalize_lossy(config_path);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.as_os_str().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
    log_path: &Path,
    force: bool,
) -> Result<()> {
    let plist_path = macos_service_plist_path(config_path);
    let service_label = macos_service_label(config_path);
    if plist_path.exists() && !force {
        println!(
            "service already installed at {} (pass --force to reinstall)",
            plist_path.display()
        );
        return Ok(());
    }

    macos_service_bootout(config_path, true)?;
    stop_existing_daemons_before_service_install(config_path)?;
    let service_executable = macos_service_binary_path(config_path);
    crate::service_management::install_service_executable_copy(executable, &service_executable)?;
    let plist = macos_service_plist_content(
        &service_label,
        &service_executable,
        config_path,
        iface,
        mesh_refresh_interval_secs,
        log_path,
    );

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let temp = plist_path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, plist).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to chmod {}", temp.display()))?;
    fs::rename(&temp, &plist_path).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp.display(),
            plist_path.display()
        )
    })?;

    macos_activate_service(config_path, &plist_path)?;
    println!("installed system service: {}", plist_path.display());
    println!("label: {service_label}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_uninstall_service(config_path: &Path) -> Result<()> {
    macos_service_bootout(config_path, true)?;
    macos_service_disable(config_path, true)?;
    let plist_path = macos_service_plist_path(config_path);
    if plist_path.exists() {
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
        println!("removed system service plist: {}", plist_path.display());
    } else {
        println!("system service plist not found: {}", plist_path.display());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_enable_service(config_path: &Path) -> Result<()> {
    let plist_path = macos_service_plist_path(config_path);
    let service_label = macos_service_label(config_path);
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_activate_service(config_path, &plist_path)?;
    println!("enabled system service: {}", plist_path.display());
    println!("label: {service_label}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_disable_service(config_path: &Path) -> Result<()> {
    let plist_path = macos_service_plist_path(config_path);
    let service_label = macos_service_label(config_path);
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_service_bootout(config_path, true)?;
    macos_service_disable(config_path, false)?;
    println!("disabled system service: {}", plist_path.display());
    println!("label: {service_label}");
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_plist_content(
    service_label: &str,
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
    log_path: &Path,
) -> String {
    let exec = xml_escape(&executable.display().to_string());
    let config = xml_escape(&config_path.display().to_string());
    let iface = xml_escape(iface);
    let interval = mesh_refresh_interval_secs.to_string();
    let log = xml_escape(&log_path.display().to_string());

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{service_label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exec}</string>
    <string>daemon</string>
    <string>--service</string>
    <string>--config</string>
    <string>{config}</string>
    <string>--iface</string>
    <string>{iface}</string>
    <string>--mesh-refresh-interval-secs</string>
    <string>{interval}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn macos_service_bootstrap(_config_path: &Path, plist_path: &Path) -> Result<()> {
    let plist = plist_path
        .to_str()
        .ok_or_else(|| anyhow!("plist path is not valid UTF-8"))?;
    run_launchctl_checked(&["bootstrap", "system", plist], "bootstrap service")
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_activation_commands(
    config_path: &Path,
    plist_path: &Path,
) -> Vec<Vec<String>> {
    let target = format!("system/{}", macos_service_label(config_path));
    let plist = plist_path.display().to_string();
    vec![
        vec!["enable".to_string(), target.clone()],
        vec!["bootout".to_string(), target.clone()],
        vec!["bootstrap".to_string(), "system".to_string(), plist],
        vec!["kickstart".to_string(), "-k".to_string(), target],
    ]
}

#[cfg(target_os = "macos")]
fn macos_activate_service(config_path: &Path, plist_path: &Path) -> Result<()> {
    for args in macos_service_activation_commands(config_path, plist_path) {
        match args.first().map(String::as_str) {
            Some("enable") => macos_service_enable(config_path)?,
            Some("bootout") => macos_service_bootout(config_path, true)?,
            Some("bootstrap") => macos_service_bootstrap(config_path, plist_path)?,
            Some("kickstart") => macos_service_kickstart(config_path)?,
            _ => return Err(anyhow!("unsupported launchctl activation command")),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_service_enable(config_path: &Path) -> Result<()> {
    let target = macos_service_target(config_path);
    run_launchctl_checked(&["enable", target.as_str()], "enable service")
}

#[cfg(target_os = "macos")]
fn macos_service_disable(config_path: &Path, ignore_missing: bool) -> Result<()> {
    let target = macos_service_target(config_path);
    run_launchctl_allow_missing(
        &["disable", target.as_str()],
        "disable service",
        ignore_missing,
    )
}

#[cfg(target_os = "macos")]
fn macos_service_kickstart(config_path: &Path) -> Result<()> {
    let target = macos_service_target(config_path);
    run_launchctl_checked(&["kickstart", "-k", target.as_str()], "kickstart service")
}

#[cfg(target_os = "macos")]
fn macos_service_bootout(config_path: &Path, ignore_missing: bool) -> Result<()> {
    let target = macos_service_target(config_path);
    run_launchctl_allow_missing(
        &["bootout", target.as_str()],
        "bootout service",
        ignore_missing,
    )
}

#[cfg(target_os = "macos")]
pub(super) fn macos_service_print(config_path: &Path) -> Result<String> {
    let target = macos_service_target(config_path);
    let output = run_launchctl_raw(&["print", target.as_str()], "print service")?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_print_is_running(print_output: &str) -> bool {
    // A KeepAlive daemon idling between (re)spawns reports `spawn scheduled` or
    // `waiting`, not `running`; only `not running` means it is actually down.
    print_output
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("state = "))
        .any(|state| matches!(state, "running" | "spawn scheduled" | "waiting"))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_service_print_pid(print_output: &str) -> Option<u32> {
    for line in print_output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("pid = ")
            && let Ok(pid) = value.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }

    None
}

#[cfg(target_os = "macos")]
pub(super) fn macos_service_disabled(config_path: &Path) -> Result<bool> {
    let output = run_launchctl_raw(&["print-disabled", "system"], "print disabled services")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "launchctl print disabled services failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(macos_service_disabled_from_print_disabled_output(
        &stdout,
        &macos_service_label(config_path),
    ))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_disabled_from_print_disabled_output(output: &str, label: &str) -> bool {
    for line in output.lines().map(str::trim) {
        let Some((entry_label, state)) = line.split_once("=>") else {
            continue;
        };
        if entry_label.trim().trim_matches('"') != label {
            continue;
        }

        return state.trim().trim_end_matches(',') == "disabled";
    }

    false
}

#[cfg(target_os = "macos")]
fn run_launchctl_checked(args: &[&str], context: &str) -> Result<()> {
    let output = run_launchctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "launchctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn run_launchctl_allow_missing(args: &[&str], context: &str, ignore_missing: bool) -> Result<()> {
    let output = run_launchctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("stdout: {}\nstderr: {}", stdout.trim(), stderr.trim());
    if ignore_missing && launchctl_missing_service_message(&details) {
        return Ok(());
    }

    Err(anyhow!(
        "launchctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn run_launchctl_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("launchctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to launchctl {context}"))
}

#[cfg(target_os = "macos")]
fn launchctl_missing_service_message(details: &str) -> bool {
    let lower = details.to_ascii_lowercase();
    lower.contains("could not find service")
        || lower.contains("service is disabled")
        || lower.contains("no such process")
        || lower.contains("not found")
}
