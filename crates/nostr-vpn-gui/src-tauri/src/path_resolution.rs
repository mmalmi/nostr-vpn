use std::env;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command as ProcessCommand;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
#[cfg(any(target_os = "android", target_os = "ios"))]
use tauri::Manager;

#[cfg(target_os = "windows")]
use super::legacy_config_path_from_dirs_config_dir;
#[cfg(any(target_os = "windows", test))]
use super::windows_default_config_path_for_state;
#[cfg(any(target_os = "windows", test))]
use super::windows_machine_config_path_from_program_data_dir;
#[cfg(target_os = "windows")]
use super::windows_service_binary_path_from_sc_qc_output;
#[cfg(target_os = "windows")]
use super::windows_service_config_path_from_sc_qc_output;
use super::{AppConfig, NVPN_BIN_ENV};

pub(crate) fn resolve_nvpn_cli_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        let candidate = PathBuf::from(path);
        return validate_nvpn_binary(candidate);
    }

    #[cfg(target_os = "windows")]
    if let Some(candidate) = windows_installed_service_binary_path()
        && candidate.exists()
        && let Ok(validated) = validate_nvpn_binary(candidate)
    {
        return Ok(validated);
    }

    let bundled_candidates = nvpn_bundled_binary_candidates();
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for candidate in bundled_nvpn_candidate_paths(dir, &bundled_candidates) {
            if candidate.exists()
                && let Ok(validated) = validate_nvpn_binary(candidate)
            {
                return Ok(validated);
            }
        }
    }

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(nvpn_binary_name());
            if candidate.exists()
                && let Ok(validated) = validate_nvpn_binary(candidate)
            {
                return Ok(validated);
            }
        }
    }

    Err(anyhow!(
        "nvpn CLI binary not found; set {} or install nvpn",
        NVPN_BIN_ENV
    ))
}

pub(crate) fn validate_nvpn_binary(path: PathBuf) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;

    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(anyhow!("{} is not executable", canonical.display()));
        }
        if mode & 0o002 != 0 {
            return Err(anyhow!(
                "{} is world-writable and rejected for daemon control safety",
                canonical.display()
            ));
        }
    }

    Ok(canonical)
}

pub(crate) fn cli_binary_installed() -> bool {
    resolve_nvpn_cli_path().is_ok()
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_installed_service_binary_path() -> Option<PathBuf> {
    let mut command = ProcessCommand::new("sc.exe");
    let output = super::apply_windows_subprocess_flags(&mut command)
        .args(["qc", "NvpnService"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    windows_service_binary_path_from_sc_qc_output(&stdout)
}

#[cfg(test)]
pub(crate) fn cli_binary_installed_at(path: &std::path::Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

pub(crate) fn nvpn_bundled_binary_candidates() -> Vec<String> {
    vec![nvpn_binary_name().to_string(), nvpn_sidecar_binary_name()]
}

pub(crate) fn bundled_nvpn_candidate_paths(
    exe_dir: &Path,
    candidate_names: &[String],
) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    let search_dirs = {
        let mut search_dirs = vec![exe_dir.to_path_buf(), exe_dir.join("binaries")];
        if let Some(resources_dir) = exe_dir.parent().map(|path| path.join("Resources")) {
            search_dirs.push(resources_dir.clone());
            search_dirs.push(resources_dir.join("binaries"));
        }
        search_dirs
    };

    #[cfg(not(target_os = "macos"))]
    let search_dirs = vec![exe_dir.to_path_buf(), exe_dir.join("binaries")];

    search_dirs
        .into_iter()
        .flat_map(|dir| {
            candidate_names
                .iter()
                .map(move |candidate_name| dir.join(candidate_name))
        })
        .collect()
}

pub(crate) fn nvpn_sidecar_binary_name() -> String {
    let target = current_target_triple();

    #[cfg(target_os = "windows")]
    {
        format!("{}-{target}.exe", nvpn_binary_stem())
    }

    #[cfg(not(target_os = "windows"))]
    {
        format!("{}-{target}", nvpn_binary_stem())
    }
}

pub(crate) fn nvpn_binary_stem() -> &'static str {
    "nvpn"
}

pub(crate) fn current_target_triple() -> String {
    if let Some(target) = option_env!("NVPN_GUI_TARGET")
        && !target.trim().is_empty()
    {
        return target.to_string();
    }

    let arch = env::consts::ARCH;
    match env::consts::OS {
        "macos" => format!("{arch}-apple-darwin"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        os => format!("{arch}-unknown-{os}"),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn nvpn_binary_name() -> &'static str {
    "nvpn.exe"
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn nvpn_binary_name() -> &'static str {
    nvpn_binary_stem()
}

pub(crate) fn extract_json_document(raw: &str) -> Result<&str> {
    let start = raw
        .find('{')
        .ok_or_else(|| anyhow!("command output did not contain JSON start"))?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| anyhow!("command output did not contain JSON end"))?;

    if end < start {
        return Err(anyhow!("invalid JSON range in command output"));
    }

    Ok(&raw[start..=end])
}

pub(crate) fn requires_admin_privileges(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("openscmanager failed 5")
        || lower.contains("did you run with sudo")
        || lower.contains("admin privileges")
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn requires_admin_privileges_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| requires_admin_privileges(&cause.to_string()))
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_nvpn_command_failure(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    format!(
        "nvpn {command} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    )
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_daemon_apply_requires_service_repair(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("restart the daemon with a newer nvpn binary")
        || lowered.contains("older nvpn daemon binary is still running")
}

pub(crate) fn service_state_refresh_due(
    last_refresh_at: Option<Instant>,
    now: Instant,
    interval: Duration,
) -> bool {
    last_refresh_at
        .map(|last_refresh_at| now.duration_since(last_refresh_at) >= interval)
        .unwrap_or(true)
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_elevated_config_import_args<'a>(
    source: &'a str,
    target: &'a str,
) -> [&'a str; 5] {
    ["apply-config", "--source", source, "--config", target]
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_daemon_config_import_args<'a>(
    source: &'a str,
    target: &'a str,
) -> [&'a str; 5] {
    [
        "apply-config-daemon",
        "--source",
        source,
        "--config",
        target,
    ]
}

#[cfg(target_os = "windows")]
pub(crate) fn normalize_windows_elevated_args<const N: usize>(args: [&str; N]) -> Vec<OsString> {
    args.into_iter()
        .map(|arg| OsString::from(strip_windows_verbatim_prefix(arg)))
        .collect()
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn strip_windows_verbatim_prefix(value: &str) -> &str {
    value.strip_prefix(r"\\?\").unwrap_or(value)
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_should_use_daemon_owned_config_apply(
    config_path: &Path,
    windows_program_data_dir: Option<&std::path::Path>,
    daemon_running: bool,
    service_installed: bool,
) -> bool {
    if !(daemon_running || service_installed) {
        return false;
    }

    let Some(machine_config_path) =
        windows_machine_config_path_from_program_data_dir(windows_program_data_dir)
    else {
        return false;
    };

    let current = config_path.display().to_string();
    let machine = machine_config_path.display().to_string();
    strip_windows_verbatim_prefix(&current)
        .eq_ignore_ascii_case(strip_windows_verbatim_prefix(&machine))
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_should_start_installed_service(
    service_installed: bool,
    service_disabled: bool,
) -> bool {
    service_installed && !service_disabled
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_temp_config_import_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!(
        "nvpn-config-import-{}-{nonce}.toml",
        std::process::id()
    ))
}

pub(crate) fn is_already_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("already running")
}

pub(crate) fn is_not_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("not running")
}

pub(crate) fn epoch_secs_to_system_time(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }

    UNIX_EPOCH.checked_add(Duration::from_secs(value))
}

pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub(crate) fn compact_age_text(age_secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;
    const MONTH: u64 = 30 * DAY;
    const YEAR: u64 = 365 * DAY;

    match age_secs {
        0..MINUTE => format!("{age_secs}s ago"),
        MINUTE..HOUR => format!("{}m ago", age_secs / MINUTE),
        HOUR..DAY => format!("{}h ago", age_secs / HOUR),
        DAY..WEEK => format!("{}d ago", age_secs / DAY),
        WEEK..MONTH => format!("{}w ago", age_secs / WEEK),
        MONTH..YEAR => format!("{}mo ago", age_secs / MONTH),
        _ => format!("{}y ago", age_secs / YEAR),
    }
}

pub(crate) fn compact_remaining_text(remaining_secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    match remaining_secs {
        0..MINUTE => format!("{remaining_secs}s left"),
        MINUTE..HOUR => format!("{}m left", remaining_secs / MINUTE),
        HOUR..DAY => format!("{}h left", remaining_secs / HOUR),
        _ => format!("{}d left", remaining_secs / DAY),
    }
}

pub(crate) fn join_request_age_text(requested_at: u64) -> String {
    let age_secs = epoch_secs_to_system_time(requested_at)
        .and_then(|requested_at| requested_at.elapsed().ok())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    compact_age_text(age_secs)
}

pub(crate) fn shorten_middle(value: &str, head: usize, tail: usize) -> String {
    if value.len() <= head + tail + 3 {
        return value.to_string();
    }

    format!(
        "{}...{}",
        value.chars().take(head).collect::<String>(),
        value
            .chars()
            .rev()
            .take(tail)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    )
}

pub(crate) fn expected_peer_count(config: &AppConfig) -> usize {
    let participants = config.participant_pubkeys_hex();
    if participants.is_empty() {
        return 0;
    }

    let mut expected = participants.len();
    if let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && participants
            .iter()
            .any(|participant| participant == &own_pubkey)
    {
        expected = expected.saturating_sub(1);
    }

    expected
}

pub(crate) fn network_device_count(remote_device_count: usize, enabled: bool) -> usize {
    if enabled {
        remote_device_count.saturating_add(1)
    } else {
        0
    }
}

pub(crate) fn network_online_device_count(
    remote_online_count: usize,
    enabled: bool,
    session_active: bool,
) -> usize {
    if enabled {
        remote_online_count.saturating_add(usize::from(session_active))
    } else {
        0
    }
}

pub(crate) fn is_mesh_complete(connected: usize, expected: usize) -> bool {
    expected > 0 && connected >= expected
}

#[cfg(any(not(target_os = "windows"), test))]
pub(crate) fn config_path_from_roots(
    app_config_dir: Option<&Path>,
    dirs_config_dir: Option<&Path>,
) -> PathBuf {
    if let Some(app_config_dir) = app_config_dir {
        return app_config_dir.join("config.toml");
    }

    if let Some(dirs_config_dir) = dirs_config_dir {
        return dirs_config_dir.join("nvpn").join("config.toml");
    }

    PathBuf::from("nvpn.toml")
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn desktop_config_path_from_roots(
    dirs_config_dir: Option<&Path>,
    windows_program_data_dir: Option<&Path>,
    windows_service_config_path: Option<&Path>,
    machine_config_exists: bool,
    legacy_config_exists: bool,
) -> PathBuf {
    windows_default_config_path_for_state(
        windows_program_data_dir,
        dirs_config_dir,
        windows_service_config_path,
        machine_config_exists,
        legacy_config_exists,
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_program_data_dir() -> Option<PathBuf> {
    std::env::var_os("PROGRAMDATA").map(PathBuf::from)
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_installed_service_config_path() -> Option<PathBuf> {
    let mut command = ProcessCommand::new("sc.exe");
    let output = super::apply_windows_subprocess_flags(&mut command)
        .args(["qc", "NvpnService"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    windows_service_config_path_from_sc_qc_output(&stdout)
}

pub(crate) fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let dirs_config_dir = dirs::config_dir();
        let program_data_dir = windows_program_data_dir();
        let service_config_path = windows_installed_service_config_path();
        let machine_config_exists =
            windows_machine_config_path_from_program_data_dir(program_data_dir.as_deref())
                .as_ref()
                .is_some_and(|path| path.exists());
        let legacy_config = legacy_config_path_from_dirs_config_dir(dirs_config_dir.as_deref());
        let legacy_config_exists = legacy_config.exists();
        return desktop_config_path_from_roots(
            dirs_config_dir.as_deref(),
            program_data_dir.as_deref(),
            service_config_path.as_deref(),
            machine_config_exists,
            legacy_config_exists,
        );
    }

    #[cfg(not(target_os = "windows"))]
    {
        let config_dir = dirs::config_dir();
        config_path_from_roots(None, config_dir.as_deref())
    }
}

pub(crate) fn resolve_backend_config_path<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PathBuf> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let app_config_dir = app
            .path()
            .app_config_dir()
            .context("failed to resolve mobile app config directory")?;
        return Ok(config_path_from_roots(Some(app_config_dir.as_path()), None));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = app;
        Ok(default_config_path())
    }
}
