use std::path::{Path, PathBuf};

pub fn legacy_config_path_from_dirs_config_dir(dirs_config_dir: Option<&Path>) -> PathBuf {
    if let Some(dir) = dirs_config_dir {
        return dir.join("nvpn").join("config.toml");
    }

    PathBuf::from("nvpn.toml")
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
    let command = output.lines().find_map(|line| {
        let trimmed = line.trim();
        let (key, value) = trimmed.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("BINARY_PATH_NAME") {
            Some(value.trim())
        } else {
            None
        }
    })?;

    windows_command_line_value_for_flag(command, "--config").map(PathBuf::from)
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

#[cfg(test)]
mod tests {
    use super::{
        legacy_config_path_from_dirs_config_dir, windows_default_config_path_for_state,
        windows_machine_config_path_from_program_data_dir,
        windows_service_config_path_from_sc_qc_output,
    };
    use std::path::{Path, PathBuf};

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
            Some(Path::new(r"C:\Users\sirius\AppData\Roaming")),
            Some(Path::new(
                r"C:\Users\sirius\AppData\Roaming\nvpn\config.toml",
            )),
            false,
            true,
        );

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\sirius\AppData\Roaming\nvpn\config.toml")
        );
    }

    #[test]
    fn windows_default_config_path_prefers_machine_path_for_new_installs() {
        let path = windows_default_config_path_for_state(
            Some(Path::new(r"C:\ProgramData")),
            Some(Path::new(r"C:\Users\sirius\AppData\Roaming")),
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
            Some(Path::new(r"C:\Users\sirius\AppData\Roaming")),
            None,
            false,
            true,
        );

        assert_eq!(
            path,
            legacy_config_path_from_dirs_config_dir(Some(Path::new(
                r"C:\Users\sirius\AppData\Roaming"
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
}
