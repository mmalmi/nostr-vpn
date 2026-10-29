use super::*;

const CONFIG_PATH_ENV: &str = "NVPN_CONFIG_PATH";

/// How `install-cli` places the executable at the destination.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CliInstallMode {
    /// Copy the executable, so the destination is independent of any app.
    Copy,
    /// Symlink the executable so the destination tracks app updates. The
    /// macOS app updater replaces the bundle in place at the same path, so a
    /// link to the bundled binary never goes stale between releases.
    Link,
}

pub(crate) fn install_cli(args: InstallCliArgs) -> Result<()> {
    let explicit_path = args.path.is_some();
    let destination = args.path.unwrap_or_else(default_cli_install_path);
    let mode = if !explicit_path && cfg!(target_os = "macos") {
        CliInstallMode::Link
    } else {
        CliInstallMode::Copy
    };
    install_cli_to_path(&destination, args.force, mode).map_err(|error| {
        if error
            .downcast_ref::<std::io::Error>()
            .is_none_or(|error| error.kind() != std::io::ErrorKind::PermissionDenied)
        {
            return error;
        }

        #[cfg(not(target_os = "windows"))]
        let (user_path, shell) = (r#""$HOME/.local/bin/nvpn""#, "");
        #[cfg(target_os = "windows")]
        let (user_path, shell) = (r#""$env:USERPROFILE\.local\bin\nvpn.exe""#, " (PowerShell)");
        let force = if args.force { " --force" } else { "" };
        error.context(format!(
            "permission denied installing nvpn CLI to {}. \
             Use the Install CLI action in the Nostr VPN app, or retry the same command with \
             administrator privileges, or install into a directory you own{shell}:\n  \
             nvpn install-cli{force} --path {user_path}\n\
             Add that directory to PATH if needed",
            destination.display()
        ))
    })
}

pub(crate) fn uninstall_cli(args: UninstallCliArgs) -> Result<()> {
    let destination = args.path.unwrap_or_else(default_cli_install_path);
    uninstall_cli_path(&destination)
}

pub(crate) fn print_version(args: VersionArgs) -> Result<()> {
    let info = VersionInfoView {
        version: PRODUCT_VERSION.to_string(),
        fips_core_version: fips_core_build_version(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else if args.verbose {
        println!("{}", info.version);
        println!("fips_core_version: {}", info.fips_core_version);
    } else {
        println!("{}", info.version);
    }

    Ok(())
}

pub(crate) fn default_tunnel_iface() -> String {
    if cfg!(target_os = "windows") {
        "nvpn".to_string()
    } else if cfg!(target_os = "macos") {
        "utun".to_string()
    } else {
        "utun100".to_string()
    }
}

pub(crate) fn install_cli_to_path(
    destination: &Path,
    force: bool,
    mode: CliInstallMode,
) -> Result<()> {
    let source = std::env::current_exe().context("failed to resolve current executable")?;
    let source = fs::canonicalize(&source)
        .with_context(|| format!("failed to canonicalize {}", source.display()))?;

    if destination.as_os_str().is_empty() {
        return Err(anyhow!("install path must not be empty"));
    }
    if destination.is_dir() {
        return Err(anyhow!(
            "install path points to a directory: {}",
            destination.display()
        ));
    }

    if let Ok(existing) = fs::canonicalize(destination)
        && existing == source
    {
        println!("nvpn already installed at {}", destination.display());
        return Ok(());
    }

    if destination.exists() && !force {
        return Err(anyhow!(
            "{} already exists (pass --force to overwrite)",
            destination.display()
        ));
    }

    if destination.exists() && force {
        let metadata = fs::symlink_metadata(destination)
            .with_context(|| format!("failed to inspect {}", destination.display()))?;
        if metadata.file_type().is_dir() {
            return Err(anyhow!(
                "refusing to overwrite directory {}",
                destination.display()
            ));
        }
        fs::remove_file(destination)
            .with_context(|| format!("failed to remove {}", destination.display()))?;
    }

    let parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "install path must include parent directory: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let install_nonce = unix_timestamp();
    let temp_path = parent.join(format!(
        ".nvpn-install-{}-{install_nonce}",
        std::process::id()
    ));
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }

    if mode == CliInstallMode::Link {
        #[cfg(unix)]
        std::os::unix::fs::symlink(&source, &temp_path).with_context(|| {
            format!(
                "failed to link {} to {}",
                temp_path.display(),
                source.display()
            )
        })?;
        #[cfg(not(unix))]
        return Err(anyhow!("link installation is unsupported on this platform"));
    } else {
        fs::copy(&source, &temp_path).with_context(|| {
            format!(
                "failed to copy {} to {}",
                source.display(),
                temp_path.display()
            )
        })?;

        #[cfg(unix)]
        {
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755)).with_context(
                || {
                    format!(
                        "failed to set executable permissions on {}",
                        temp_path.display()
                    )
                },
            )?;
        }
    }

    fs::rename(&temp_path, destination).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp_path.display(),
            destination.display()
        )
    })?;

    println!("installed nvpn CLI at {}", destination.display());
    Ok(())
}

fn uninstall_cli_path(destination: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("nvpn CLI not installed at {}", destination.display());
            return Ok(());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", destination.display()));
        }
    };
    if metadata.file_type().is_dir() {
        return Err(anyhow!(
            "refusing to remove directory {}",
            destination.display()
        ));
    }

    fs::remove_file(destination)
        .with_context(|| format!("failed to remove {}", destination.display()))?;
    println!("removed nvpn CLI from {}", destination.display());
    Ok(())
}

pub(crate) fn init_config(path: &Path, force: bool, devices: Vec<String>) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "config already exists at {} (pass --force to overwrite)",
            path.display()
        ));
    }

    let mut config = AppConfig::generated();
    apply_devices_override(&mut config, devices)?;
    maybe_autoconfigure_node(&mut config);
    config.save(path)?;

    println!("wrote {}", path.display());
    println!("network_id={}", config.effective_network_id());
    println!("nostr_pubkey={}", config.nostr.public_key);
    Ok(())
}

pub(crate) fn apply_config_file(source_path: &Path, target_path: &Path) -> Result<()> {
    let mut config = AppConfig::load(source_path)
        .with_context(|| format!("failed to load source config {}", source_path.display()))?;
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    config
        .save(target_path)
        .with_context(|| format!("failed to save config {}", target_path.display()))?;
    Ok(())
}

pub(crate) fn default_cli_install_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = default_windows_cli_install_dir() {
            return dir.join("nvpn.exe");
        }

        PathBuf::from("nvpn.exe")
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/usr/local/bin/nvpn")
    }
}

#[cfg(target_os = "windows")]
fn default_windows_cli_install_dir() -> Option<PathBuf> {
    let home = dirs::home_dir();

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            if home.as_ref().is_some_and(|home| dir.starts_with(home)) {
                return Some(dir);
            }
        }
    }

    home.map(|home| home.join(".cargo").join("bin"))
}

pub(crate) fn default_config_path() -> PathBuf {
    if let Some(path) = configured_config_path(std::env::var_os(CONFIG_PATH_ENV)) {
        return path;
    }

    if let Some(dir) = dirs::config_dir() {
        #[cfg(target_os = "windows")]
        {
            let program_data_dir = windows_program_data_dir();
            let service_config_path = windows_installed_service_config_path().ok().flatten();
            let machine_config_exists =
                windows_machine_config_path_from_program_data_dir(program_data_dir.as_deref())
                    .as_ref()
                    .is_some_and(|path| path.exists());
            let legacy_config = legacy_config_path_from_dirs_config_dir(Some(dir.as_path()));
            let legacy_config_exists = legacy_config.exists();
            return windows_default_config_path_for_state(
                program_data_dir.as_deref(),
                Some(dir.as_path()),
                service_config_path.as_deref(),
                machine_config_exists,
                legacy_config_exists,
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut path = dir;
            path.push("nvpn");
            path.push("config.toml");
            return path;
        }
    }

    PathBuf::from("nvpn.toml")
}

pub(crate) fn configured_config_path(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

#[cfg(target_os = "windows")]
fn windows_program_data_dir() -> Option<PathBuf> {
    std::env::var_os("PROGRAMDATA").map(PathBuf::from)
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_installed_service_config_path() -> Result<Option<PathBuf>> {
    let Some(output) = service_management::windows_service_config_query()? else {
        return Ok(None);
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(windows_service_config_path_from_sc_qc_output(&stdout))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_install_config_path(
    explicit_config: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(config_path) = explicit_config {
        return Ok(config_path);
    }

    let legacy_config = legacy_config_path_from_dirs_config_dir(dirs::config_dir().as_deref());
    let target_config =
        windows_machine_config_path_from_program_data_dir(windows_program_data_dir().as_deref())
            .unwrap_or_else(|| legacy_config.clone());

    if target_config != legacy_config && !target_config.exists() && legacy_config.exists() {
        if let Some(parent) = target_config.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(&legacy_config, &target_config).with_context(|| {
            format!(
                "failed to migrate Windows config {} to {}",
                legacy_config.display(),
                target_config.display()
            )
        })?;
    }

    Ok(target_config)
}

pub(crate) fn load_or_default_config(path: &Path) -> Result<AppConfig> {
    if path
        .try_exists()
        .with_context(|| format!("failed to inspect config {}", path.display()))?
    {
        AppConfig::migrate_persisted_secrets(path).with_context(|| {
            format!(
                "failed to migrate persisted config secrets in {}",
                path.display()
            )
        })?;
        return AppConfig::load(path);
    }

    let config = AppConfig::generated();
    config.save(path)?;
    Ok(config)
}

pub(crate) fn load_config_read_only(path: &Path) -> Result<AppConfig> {
    if path
        .try_exists()
        .with_context(|| format!("failed to inspect config {}", path.display()))?
    {
        AppConfig::load(path)
    } else {
        Ok(AppConfig::generated())
    }
}

pub(crate) fn apply_devices_override(config: &mut AppConfig, devices: Vec<String>) -> Result<()> {
    if devices.is_empty() {
        return Ok(());
    }

    let mut normalized = devices
        .iter()
        .map(|device| normalize_nostr_pubkey(device))
        .collect::<Result<Vec<_>>>()?;

    normalized.sort();
    normalized.dedup();
    let pending_exit_node = normalize_nostr_pubkey(&config.exit_node).ok();
    config.ensure_defaults();
    if config.active_network_opt().is_none() {
        let network_id = config
            .networks
            .first()
            .map(|network| network.id.clone())
            .unwrap_or_else(|| config.add_network(""));
        config.set_network_enabled(&network_id, true)?;
    }
    config.active_network_mut().devices = normalized.clone();
    if let Some(exit_node) = pending_exit_node
        && normalized.iter().any(|device| device == &exit_node)
    {
        config.select_private_exit_node(&exit_node)?;
    }
    let _ = config.note_active_network_roster_local_change();
    config.ensure_defaults();

    Ok(())
}

pub(crate) fn apply_participants_override(
    config: &mut AppConfig,
    participants: Vec<String>,
) -> Result<()> {
    apply_devices_override(config, participants)
}
