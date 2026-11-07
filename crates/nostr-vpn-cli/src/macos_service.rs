use super::*;

#[cfg(target_os = "macos")]
mod registration;
#[cfg(target_os = "macos")]
pub(super) use registration::Registration;

#[cfg(target_os = "macos")]
fn lock_service_changes() -> Result<fs::File> {
    crate::macos_privileged_files::require_root()?;
    let dir = crate::macos_privileged_files::protected_directory(
        Path::new("/Library/LaunchDaemons"),
        false,
    )?;
    dir.lock().context("lock launchd service installation")?;
    Ok(dir)
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_plist_path(label: &str) -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist"))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_binary_path(label: &str) -> PathBuf {
    PathBuf::from(format!("/Library/PrivilegedHelperTools/{label}"))
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_scoped_service_label(config_path: &Path) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonicalize_lossy(config_path)
        .as_os_str()
        .hash(&mut hasher);
    format!("{MACOS_SERVICE_LABEL}.{:016x}", hasher.finish())
}

#[cfg(any(target_os = "macos", test))]
fn canonicalize_lossy(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
    force: bool,
) -> Result<()> {
    let _lock = lock_service_changes()?;
    let registration = Registration::for_config(config_path)?;
    let plist_path = macos_service_plist_path(&registration.label);
    if plist_path.exists() && !force {
        println!(
            "service already installed at {} (pass --force to reinstall)",
            plist_path.display()
        );
        return Ok(());
    }

    let service_label = registration.remove_duplicate()?;
    macos_service_bootout(&service_label, true)?;
    stop_existing_daemons_before_service_install(config_path)?;
    let service_executable = macos_service_binary_path(&service_label);
    crate::macos_privileged_files::install_executable(executable, &service_executable)?;
    let plist = macos_service_plist_content(
        &service_label,
        &service_executable,
        config_path,
        iface,
        mesh_refresh_interval_secs,
    );

    crate::macos_privileged_files::publish(&mut plist.as_bytes(), &plist_path, 0o644)?;

    macos_activate_service(&service_label, &plist_path)?;
    println!("installed system service: {}", plist_path.display());
    println!("label: {service_label}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_uninstall_service(config_path: &Path) -> Result<()> {
    let _lock = lock_service_changes()?;
    let label = Registration::for_config(config_path)?.remove_duplicate()?;
    remove_registration(&label)?;
    println!("uninstalled system service: {label}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_registration(label: &str) -> Result<()> {
    macos_service_bootout(label, true)?;
    macos_service_enable(label)?;
    macos_remove_service_artifacts(
        &macos_service_plist_path(label),
        &macos_service_binary_path(label),
    )
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_remove_service_artifacts(plist_path: &Path, binary_path: &Path) -> Result<()> {
    for path in [binary_path, plist_path] {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error).with_context(|| format!("failed to remove {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_enable_service(config_path: &Path) -> Result<()> {
    let _lock = lock_service_changes()?;
    let service_label = Registration::for_config(config_path)?.remove_duplicate()?;
    let plist_path = macos_service_plist_path(&service_label);
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_activate_service(&service_label, &plist_path)?;
    println!("enabled system service: {}", plist_path.display());
    println!("label: {service_label}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn macos_disable_service(config_path: &Path) -> Result<()> {
    let _lock = lock_service_changes()?;
    let service_label = Registration::for_config(config_path)?.remove_duplicate()?;
    let plist_path = macos_service_plist_path(&service_label);
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_service_bootout(&service_label, true)?;
    macos_service_disable(&service_label)?;
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
) -> String {
    let exec = xml_escape(&executable.display().to_string());
    let config = xml_escape(&config_path.display().to_string());
    let iface = xml_escape(iface);
    let interval = mesh_refresh_interval_secs.to_string();

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
  <string>Interactive</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn macos_service_bootstrap(plist_path: &Path) -> Result<()> {
    let plist = plist_path
        .to_str()
        .ok_or_else(|| anyhow!("plist path is not valid UTF-8"))?;
    run_launchctl_checked(&["bootstrap", "system", plist], "bootstrap service")
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_service_activation_commands(
    label: &str,
    plist_path: &Path,
) -> Vec<Vec<String>> {
    let target = format!("system/{label}");
    let plist = plist_path.display().to_string();
    vec![
        vec!["enable".to_string(), target.clone()],
        vec!["bootout".to_string(), target.clone()],
        vec!["bootstrap".to_string(), "system".to_string(), plist],
        vec!["kickstart".to_string(), "-k".to_string(), target],
    ]
}

#[cfg(target_os = "macos")]
fn macos_activate_service(label: &str, plist_path: &Path) -> Result<()> {
    let binary_path = macos_service_binary_path(label);
    crate::macos_privileged_files::validate_artifact(&binary_path)?;
    if registration::installed_service(label)?.is_none_or(|job| job.executable != binary_path) {
        return Err(anyhow!(
            "service executable is not the protected helper; reinstall the service"
        ));
    }
    for args in macos_service_activation_commands(label, plist_path) {
        match args.first().map(String::as_str) {
            Some("enable") => macos_service_enable(label)?,
            Some("bootout") => macos_service_bootout(label, true)?,
            Some("bootstrap") => macos_service_bootstrap(plist_path)?,
            Some("kickstart") => macos_service_kickstart(label)?,
            _ => return Err(anyhow!("unsupported launchctl activation command")),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_service_enable(label: &str) -> Result<()> {
    let target = format!("system/{label}");
    run_launchctl_checked(&["enable", target.as_str()], "enable service")
}

#[cfg(target_os = "macos")]
fn macos_service_disable(label: &str) -> Result<()> {
    let target = format!("system/{label}");
    run_launchctl_checked(&["disable", target.as_str()], "disable service")
}

#[cfg(target_os = "macos")]
fn macos_service_kickstart(label: &str) -> Result<()> {
    let target = format!("system/{label}");
    run_launchctl_checked(&["kickstart", "-k", target.as_str()], "kickstart service")
}

#[cfg(target_os = "macos")]
fn macos_service_bootout(label: &str, ignore_missing: bool) -> Result<()> {
    let target = format!("system/{label}");
    run_launchctl_allow_missing(
        &["bootout", target.as_str()],
        "bootout service",
        ignore_missing,
    )
}

#[cfg(target_os = "macos")]
pub(super) fn macos_service_print(label: &str) -> Result<String> {
    let target = format!("system/{label}");
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
pub(super) fn macos_service_disabled(label: &str) -> Result<bool> {
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
        &stdout, label,
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
