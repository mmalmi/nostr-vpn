use std::path::{Path, PathBuf};

pub fn legacy_config_path_from_dirs_config_dir(dirs_config_dir: Option<&Path>) -> PathBuf {
    if let Some(dir) = dirs_config_dir {
        return dir.join("nvpn").join("config.toml");
    }

    PathBuf::from("nvpn.toml")
}

/// Both Linux clients use the same identity. An explicit app data directory
/// still isolates tests and named profiles from the installed service.
#[cfg(target_os = "linux")]
pub fn linux_user_config_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("NVPN_APP_DATA_DIR").filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir).join("config.toml");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg_root = |key, suffix: &str| {
        std::env::var_os(key)
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .or_else(|| home.as_ref().map(|dir| dir.join(suffix)))
    };
    let cli = xdg_root("XDG_CONFIG_HOME", ".config")
        .unwrap_or_default()
        .join("nvpn/config.toml");
    let desktop = xdg_root("XDG_DATA_HOME", ".local/share")
        .unwrap_or_default()
        .join("nostr-vpn/config.toml");
    let unit = std::fs::read_to_string("/etc/systemd/system/nvpn.service").unwrap_or_default();
    linux_user_config_for_paths(cli, desktop, &unit)
}

#[cfg(any(target_os = "linux", test))]
fn linux_user_config_for_paths(cli: PathBuf, desktop: PathBuf, unit: &str) -> PathBuf {
    // Only adopt a service tied to this user's conventional config locations.
    // A system daemon can belong to a different user or an explicit profile.
    if let Some(path) = linux_service_config_path_from_unit_contents(unit) {
        for candidate in [&cli, &desktop] {
            if candidate == Path::new(&path)
                || candidate.canonicalize().ok().as_deref() == Some(Path::new(&path))
            {
                return candidate.clone();
            }
        }
    }
    if desktop.is_file() { desktop } else { cli }
}

pub fn linux_service_config_path_from_unit_contents(unit: &str) -> Option<String> {
    let command = unit
        .lines()
        .find_map(|line| line.trim().strip_prefix("ExecStart="))?;
    let value = command.split_once(" --config ")?.1.trim_start();
    systemd_first_argument(value)
}

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

pub fn windows_machine_config_path_from_program_data_dir(
    program_data_dir: Option<&Path>,
) -> Option<PathBuf> {
    let root = program_data_dir?;
    let root = root.display().to_string();
    let root = root.trim_end_matches(['\\', '/']);
    Some(PathBuf::from(format!(r"{root}\Nostr VPN\config.toml")))
}

pub fn windows_default_config_path_for_state(
    program_data_dir: Option<&Path>,
    legacy_dirs_config_dir: Option<&Path>,
    installed_service_config_path: Option<&Path>,
    machine_config_exists: bool,
    legacy_config_exists: bool,
) -> PathBuf {
    if let Some(path) = installed_service_config_path {
        return path.to_path_buf();
    }

    let legacy = legacy_config_path_from_dirs_config_dir(legacy_dirs_config_dir);
    if machine_config_exists
        && let Some(machine) = windows_machine_config_path_from_program_data_dir(program_data_dir)
    {
        return machine;
    }

    if legacy_config_exists {
        return legacy;
    }

    windows_machine_config_path_from_program_data_dir(program_data_dir).unwrap_or(legacy)
}

pub fn windows_service_config_path_from_sc_qc_output(output: &str) -> Option<PathBuf> {
    let command = windows_service_command_from_sc_qc_output(output)?;

    windows_command_line_value_for_flag(command, "--config").map(PathBuf::from)
}

pub fn windows_service_binary_path_from_sc_qc_output(output: &str) -> Option<PathBuf> {
    let command = windows_service_command_from_sc_qc_output(output)?;
    windows_command_line_program(command).map(PathBuf::from)
}

fn windows_service_command_from_sc_qc_output(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        let (key, value) = trimmed.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("BINARY_PATH_NAME") {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn windows_command_line_value_for_flag(command: &str, flag: &str) -> Option<String> {
    let flag_index = command.find(flag)?;
    let after_flag = command.get(flag_index + flag.len()..)?.trim_start();
    if after_flag.is_empty() {
        return None;
    }

    if let Some(remainder) = after_flag.strip_prefix('"') {
        let end = remainder.find('"')?;
        return Some(remainder[..end].to_string());
    }

    let end = after_flag
        .find(char::is_whitespace)
        .unwrap_or(after_flag.len());
    Some(after_flag[..end].to_string())
}

fn windows_command_line_program(command: &str) -> Option<String> {
    let command = command.trim_start();
    if command.is_empty() {
        return None;
    }

    if let Some(remainder) = command.strip_prefix('"') {
        let end = remainder.find('"')?;
        return Some(remainder[..end].to_string());
    }

    let end = command.find(char::is_whitespace).unwrap_or(command.len());
    Some(command[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        legacy_config_path_from_dirs_config_dir, linux_user_config_for_paths,
        windows_default_config_path_for_state, windows_machine_config_path_from_program_data_dir,
        windows_service_binary_path_from_sc_qc_output,
        windows_service_config_path_from_sc_qc_output,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn linux_clients_share_existing_identity_and_respect_the_installed_service() {
        // Use an existing regular fixture to represent a previously configured desktop.
        let desktop = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let cli = desktop.with_file_name("missing-cli-config.toml");
        assert_eq!(
            linux_user_config_for_paths(cli.clone(), desktop.clone(), ""),
            desktop
        );
        let installed = format!("ExecStart=nvpn daemon --config \"{}\"", cli.display());
        assert_eq!(
            linux_user_config_for_paths(cli.clone(), desktop.clone(), &installed),
            cli
        );
        assert_eq!(
            linux_user_config_for_paths(
                cli.clone(),
                desktop.clone(),
                "ExecStart=nvpn daemon --config /another/profile"
            ),
            desktop
        );
        let absent = desktop.with_file_name("missing-desktop-config.toml");
        assert_eq!(linux_user_config_for_paths(cli.clone(), absent, ""), cli);
    }

    #[test]
    fn legacy_config_path_uses_user_config_root() {
        assert_eq!(
            legacy_config_path_from_dirs_config_dir(Some(Path::new("/home/test/.config"))),
            PathBuf::from("/home/test/.config/nvpn/config.toml")
        );
    }

    #[test]
    fn windows_machine_config_path_uses_program_data_root() {
        assert_eq!(
            windows_machine_config_path_from_program_data_dir(Some(Path::new(r"C:\ProgramData"))),
            Some(PathBuf::from(r"C:\ProgramData\Nostr VPN\config.toml"))
        );
    }

    #[test]
    fn windows_default_config_path_prefers_installed_service_config() {
        let path = windows_default_config_path_for_state(
            Some(Path::new(r"C:\ProgramData")),
            Some(Path::new(r"C:\Users\Example\AppData\Roaming")),
            Some(Path::new(
                r"C:\Users\Example\AppData\Roaming\nvpn\config.toml",
            )),
            false,
            true,
        );

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\Example\AppData\Roaming\nvpn\config.toml")
        );
    }

    #[test]
    fn windows_default_config_path_prefers_machine_path_for_new_installs() {
        let path = windows_default_config_path_for_state(
            Some(Path::new(r"C:\ProgramData")),
            Some(Path::new(r"C:\Users\Example\AppData\Roaming")),
            None,
            false,
            false,
        );

        assert_eq!(path, PathBuf::from(r"C:\ProgramData\Nostr VPN\config.toml"));
    }

    #[test]
    fn windows_default_config_path_falls_back_to_legacy_when_machine_missing() {
        let path = windows_default_config_path_for_state(
            Some(Path::new(r"C:\ProgramData")),
            Some(Path::new(r"C:\Users\Example\AppData\Roaming")),
            None,
            false,
            true,
        );

        assert_eq!(
            path,
            legacy_config_path_from_dirs_config_dir(Some(Path::new(
                r"C:\Users\Example\AppData\Roaming"
            )))
        );
    }

    #[test]
    fn windows_service_config_path_parser_extracts_config_argument() {
        let output = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --service --config \"C:\\ProgramData\\Nostr VPN\\config.toml\" --iface \"nvpn\"\n";

        assert_eq!(
            windows_service_config_path_from_sc_qc_output(output),
            Some(PathBuf::from(r"C:\ProgramData\Nostr VPN\config.toml"))
        );
    }

    #[test]
    fn windows_service_binary_path_parser_extracts_executable() {
        let output = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --service --config \"C:\\ProgramData\\Nostr VPN\\config.toml\" --iface \"nvpn\"\n";

        assert_eq!(
            windows_service_binary_path_from_sc_qc_output(output),
            Some(PathBuf::from(r"C:\Program Files\Nostr VPN\nvpn.exe"))
        );
    }
}
