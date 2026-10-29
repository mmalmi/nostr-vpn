pub(crate) fn read_daemon_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(raw) = fs::read_to_string(path) else {
        return String::new();
    };

    let mut lines = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() > max_lines {
        lines.drain(0..(lines.len() - max_lines));
    }
    lines.join("\n")
}

#[cfg(target_os = "linux")]
pub(crate) fn is_process_running(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    linux_proc_stat_counts_as_running(&stat)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn is_process_running(pid: u32) -> bool {
    ProcessCommand::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("pid=")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_process_running(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, config_path: &Path) -> bool {
    is_process_running(pid)
        && fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|cmdline| linux_proc_daemon_matches_config(&cmdline, config_path))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, config_path: &Path) -> bool {
    if !is_process_running(pid) {
        return false;
    }

    let output = ProcessCommand::new("ps")
        .arg("-ww")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("stat=,command=")
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    daemon_pids_from_ps_output(&String::from_utf8_lossy(&output.stdout), config_path).contains(&pid)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn daemon_pid_record_counts_as_running(_pid: u32, _config_path: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| daemon_pid_record_counts_as_running(*pid, config_path))
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let output = ProcessCommand::new("ps")
        .arg("ax")
        .arg("-ww")
        .arg("-o")
        .arg("pid=,stat=,command=")
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    daemon_pids_from_ps_output(&String::from_utf8_lossy(&output.stdout), config_path)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_proc_daemon_matches_config(cmdline: &[u8], config_path: &Path) -> bool {
    let mut args = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty());
    let Some(executable) = args.next() else {
        return false;
    };
    // Keep argv boundaries: flattening a launcher such as `sudo /path/nvpn`
    // makes its command look like the child daemon and prevents startup.
    if !daemon_command_has_nvpn_executable_prefix(&String::from_utf8_lossy(executable))
        || args.next() != Some(b"daemon".as_slice())
    {
        return false;
    }
    while let Some(arg) = args.next() {
        let configured_path = if arg == b"--config" {
            args.next()
        } else {
            arg.strip_prefix(b"--config=")
        };
        if let Some(configured_path) = configured_path {
            return configured_path == config_path.as_os_str().as_encoded_bytes()
                || fs::canonicalize(config_path).is_ok_and(|canonical| {
                    configured_path == canonical.as_os_str().as_encoded_bytes()
                });
        }
    }
    false
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_proc_stat_counts_as_running(stat: &str) -> bool {
    let Some((_, fields)) = stat.rsplit_once(") ") else {
        return false;
    };
    fields
        .chars()
        .next()
        .is_some_and(|state| !matches!(state, 'Z' | 'X'))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn find_daemon_pids_by_config(_config_path: &Path) -> Vec<u32> {
    Vec::new()
}

#[cfg(any(all(unix, not(target_os = "linux")), test))]
pub(crate) fn daemon_pids_from_ps_output(ps_output: &str, config_path: &Path) -> Vec<u32> {
    let mut pids = Vec::new();

    for line in ps_output.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(pid_text) = parts.next() else {
            continue;
        };
        let Some(second) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        let (stat, command) = if unix_ps_field_looks_like_stat(second) {
            let Some((_, command)) = trimmed
                .split_once(second)
                .map(|(prefix, suffix)| (prefix, suffix.trim_start()))
            else {
                continue;
            };
            (second, command)
        } else {
            ("", trimmed[pid_text.len()..].trim_start())
        };

        if !unix_process_stat_counts_as_running(stat) {
            continue;
        }

        if daemon_command_matches_config(command, config_path) {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(any(all(unix, not(target_os = "linux")), test))]
pub(crate) fn unix_process_stat_counts_as_running(stat: &str) -> bool {
    let trimmed = stat.trim();
    if trimmed.is_empty() {
        return true;
    }

    let state = trimmed.chars().next().unwrap_or_default();
    if matches!(state, 'Z' | 'X') {
        return false;
    }

    !trimmed.contains('E')
}

#[cfg(any(all(unix, not(target_os = "linux")), test))]
fn unix_ps_field_looks_like_stat(field: &str) -> bool {
    let trimmed = field.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 8
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphabetic() || matches!(ch, '<' | '>' | '+' | '-' | '|' | ':'))
}

#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsProcess {
    process_id: u32,
    name: String,
    command_line: Option<String>,
}

#[cfg(windows)]
fn windows_nvpn_processes() -> Result<Vec<WindowsProcess>> {
    // Query the same provider as Get-CimInstance, without starting PowerShell.
    wmi::WMIConnection::new()
        .context("connect to Windows process service")?
        .raw_query(
            "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE Name LIKE 'nvpn%.exe'",
        )
        .context("query Windows daemon processes")
}

#[cfg(any(windows, test))]
fn windows_daemon_candidates(
    processes: &[WindowsProcess],
    config_path: &Path,
    current_pid: u32,
    state: Option<&DaemonRuntimeState>,
    now: u64,
) -> Vec<u32> {
    let mut pids = processes
        .iter()
        .filter(|process| process.process_id != current_pid)
        .filter(|process| {
            process
                .command_line
                .as_deref()
                .is_some_and(|command| daemon_command_matches_config(command, config_path))
        })
        .map(|process| process.process_id)
        .collect::<Vec<_>>();

    // Unelevated clients cannot always read the service command line. Retain
    // the existing fresh-state/single-process recovery only for that case;
    // never override a visible command identifying another config or CLI call.
    if pids.is_empty()
        && state.is_some_and(|state| {
            now.saturating_sub(state.updated_at) <= WINDOWS_DAEMON_STATE_FRESHNESS_SECS
        })
    {
        let mut candidates = processes.iter().filter(|process| {
            process.process_id != current_pid && process.name.eq_ignore_ascii_case("nvpn.exe")
        });
        if let Some(process) = candidates.next()
            && candidates.next().is_none()
            && process.command_line.is_none()
        {
            pids.push(process.process_id);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(windows)]
pub(crate) fn daemon_candidate_pids(config_path: &Path, current_pid: u32) -> Result<Vec<u32>> {
    let processes = windows_nvpn_processes()?;
    let state = read_daemon_state(&daemon_state_file_path(config_path)?)?;
    Ok(windows_daemon_candidates(
        &processes,
        config_path,
        current_pid,
        state.as_ref(),
        unix_timestamp(),
    ))
}

#[cfg(not(windows))]
pub(crate) fn daemon_candidate_pids(config_path: &Path, current_pid: u32) -> Result<Vec<u32>> {
    let mut daemon_pids = find_daemon_pids_by_config(config_path);

    let pid_file = daemon_pid_file_path(config_path)?;
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && record.pid != current_pid
        && daemon_pid_record_counts_as_running(record.pid, config_path)
        && !daemon_pids.contains(&record.pid)
    {
        daemon_pids.push(record.pid);
    }

    daemon_pids.retain(|pid| *pid != current_pid);
    daemon_pids.sort_unstable();
    daemon_pids.dedup();
    Ok(daemon_pids)
}

#[cfg(any(not(target_os = "linux"), test))]
pub(crate) fn daemon_command_matches_config(command: &str, config_path: &Path) -> bool {
    let Some((prefix, _)) = command.split_once(" daemon ") else {
        return false;
    };

    daemon_command_has_nvpn_executable_prefix(prefix)
        && !daemon_command_prefix_looks_like_shell_wrapper(prefix)
        && command.contains(" daemon ")
        && command.contains("--config")
        && daemon_command_mentions_config(command, config_path)
}

#[cfg(any(not(target_os = "linux"), test))]
fn daemon_command_mentions_config(command: &str, config_path: &Path) -> bool {
    let config_text = config_path.display().to_string();
    if command.contains(config_text.as_str()) {
        return true;
    }

    fs::canonicalize(config_path).ok().is_some_and(|canonical| {
        let canonical_text = canonical.display().to_string();
        command.contains(canonical_text.as_str())
    })
}

fn daemon_command_has_nvpn_executable_prefix(prefix: &str) -> bool {
    let trimmed = prefix.trim().trim_matches(|ch| ch == '"' || ch == '\'');
    if trimmed.is_empty() {
        return false;
    }

    let normalized = trimmed.replace('\\', "/");
    let executable_name = normalized.rsplit('/').next().unwrap_or_default();
    let executable_name_lower = executable_name.to_ascii_lowercase();
    if executable_name_lower == "nvpn"
        || executable_name_lower == "nvpn.exe"
        || executable_name_lower.starts_with("nvpn-")
    {
        return true;
    }

    #[cfg(any(target_os = "macos", test))]
    {
        // macOS service-managed daemons live at
        // /Library/PrivilegedHelperTools/to.nostrvpn.nvpn(.<config-suffix>)
        // — the basename starts with the service label, not "nvpn".
        // Without this match, the user-mode CLI can't tell the launchd
        // daemon is running, the GUI falls through to `nvpn start
        // --daemon` (which requires root), and VPN toggle silently fails
        // on a freshly-installed service.
        if let Some(name) = normalized.rsplit('/').next()
            && (name == MACOS_SERVICE_LABEL
                || name
                    .strip_prefix(MACOS_SERVICE_LABEL)
                    .is_some_and(|rest| rest.starts_with('.')))
        {
            return true;
        }
    }

    false
}

#[cfg(any(not(target_os = "linux"), test))]
fn daemon_command_prefix_looks_like_shell_wrapper(prefix: &str) -> bool {
    let trimmed = prefix.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("bash ")
        || lower.starts_with("sh ")
        || lower.starts_with("zsh ")
        || lower.starts_with("dash ")
        || lower.starts_with("fish ")
        || lower.starts_with("cmd ")
        || lower.starts_with("powershell ")
        || lower.starts_with("pwsh ")
        || trimmed.contains(" -c ")
        || trimmed.contains(';')
        || trimmed.contains("&&")
        || trimmed.contains("||")
}

#[cfg(test)]
mod windows_process_tests {
    use super::*;
    #[test]
    fn windows_daemon_snapshot_requires_daemon_command_and_same_config() {
        let config = Path::new(r"C:\Users\Example\nvpn\config.toml");
        let state = DaemonRuntimeState {
            updated_at: 100,
            ..Default::default()
        };
        for (command, expected) in [
            (
                r#""C:\Program Files\Nostr VPN\nvpn.exe" daemon --config "C:\Users\Example\nvpn\config.toml""#,
                vec![1736],
            ),
            (
                r#""C:\Program Files\Nostr VPN\nvpn.exe" daemon --config "C:\other\config.toml""#,
                vec![],
            ),
            (
                r#""C:\Program Files\Nostr VPN\nvpn.exe" status --config "C:\Users\Example\nvpn\config.toml""#,
                vec![],
            ),
            (
                r#"powershell -Command nvpn daemon --config "C:\Users\Example\nvpn\config.toml""#,
                vec![],
            ),
        ] {
            let processes = serde_json::from_value::<Vec<WindowsProcess>>(serde_json::json!([
                {"ProcessId": 1736, "Name": "nvpn.exe", "CommandLine": command},
                {"ProcessId": 42, "Name": "nvpn.exe", "CommandLine": command}
            ]))
            .unwrap();
            assert_eq!(
                windows_daemon_candidates(&processes, config, 42, Some(&state), 103),
                expected
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_process_query_observes_current_cli_process() {
        let processes = windows_nvpn_processes().expect("native WMI process query");
        let current = processes
            .iter()
            .find(|process| process.process_id == std::process::id())
            .expect("WMI must include the running nvpn test executable");
        assert!(
            current
                .command_line
                .as_deref()
                .is_some_and(|command| !command.is_empty())
        );
        assert!(
            windows_daemon_candidates(
                std::slice::from_ref(current),
                Path::new("other.toml"),
                0,
                None,
                0
            )
            .is_empty()
        );
    }

    #[test]
    fn windows_service_recovery_requires_fresh_state_and_one_unreadable_process() {
        let config = Path::new("config.toml");
        let state = DaemonRuntimeState {
            updated_at: 100,
            ..Default::default()
        };
        let processes = serde_json::from_value::<Vec<WindowsProcess>>(serde_json::json!([
            {"ProcessId": 42, "Name": "nvpn.exe", "CommandLine": null},
            {"ProcessId": 9564, "Name": "nvpn.exe", "CommandLine": null},
            {"ProcessId": 97597, "Name": "nvpn.exe", "CommandLine": null}
        ]))
        .unwrap();
        assert_eq!(
            windows_daemon_candidates(&processes[..2], config, 42, Some(&state), 103),
            vec![9564]
        );
        assert!(
            windows_daemon_candidates(&processes[..2], config, 42, Some(&state), 106).is_empty()
        );
        assert!(windows_daemon_candidates(&processes, config, 42, Some(&state), 103).is_empty());
        assert!(windows_daemon_candidates(&processes[..2], config, 42, None, 103).is_empty());
    }
}
