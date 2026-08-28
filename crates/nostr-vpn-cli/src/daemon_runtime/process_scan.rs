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
        && linux_proc_command(pid)
            .is_some_and(|command| daemon_command_matches_config(&command, config_path))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, config_path: &Path) -> bool {
    if !is_process_running(pid) {
        return false;
    }

    let output = ProcessCommand::new("ps")
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

#[cfg(windows)]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, config_path: &Path) -> bool {
    let script = format!(
        "Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
    );
    let output = ProcessCommand::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script.as_str(),
        ])
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    windows_daemon_pid_record_matches_cim(
        pid,
        &String::from_utf8_lossy(&output.stdout),
        config_path,
    )
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
        .filter(|pid| is_process_running(*pid))
        .filter(|pid| {
            linux_proc_command(*pid)
                .is_some_and(|command| daemon_command_matches_config(&command, config_path))
        })
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let output = ProcessCommand::new("ps")
        .arg("ax")
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
pub(crate) fn linux_proc_cmdline_to_command(cmdline: &[u8]) -> Option<String> {
    let args = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg))
        .collect::<Vec<_>>();
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(target_os = "linux")]
fn linux_proc_command(pid: u32) -> Option<String> {
    linux_proc_cmdline_to_command(&fs::read(format!("/proc/{pid}/cmdline")).ok()?)
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

#[cfg(windows)]
pub(crate) fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    let output = ProcessCommand::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_Process -Filter \"Name LIKE 'nvpn%.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    daemon_pids_from_windows_cim_json(&String::from_utf8_lossy(&output.stdout), config_path)
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

#[cfg(any(target_os = "windows", test))]
pub(crate) fn tasklist_pids_from_output(tasklist_output: &str) -> Vec<u32> {
    let trimmed = tasklist_output.trim();
    if trimmed.is_empty()
        || trimmed
            .to_ascii_lowercase()
            .contains("no tasks are running which match")
    {
        return Vec::new();
    }

    let mut pids = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if !(line.starts_with('"') && line.ends_with('"')) {
            continue;
        }
        let inner = &line[1..line.len().saturating_sub(1)];
        let mut fields = inner.split("\",\"");
        let _image_name = fields.next();
        let Some(pid_text) = fields.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        pids.push(pid);
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(windows)]
pub(crate) fn windows_nvpn_pids() -> Vec<u32> {
    let output = ProcessCommand::new("tasklist")
        .args(["/FI", "IMAGENAME eq nvpn.exe", "/FO", "CSV", "/NH"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    tasklist_pids_from_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn recent_windows_daemon_pid_candidate(
    state: Option<&DaemonRuntimeState>,
    current_pid: u32,
    nvpn_pids: &[u32],
    now: u64,
) -> Option<u32> {
    let state = state?;
    if now.saturating_sub(state.updated_at) > WINDOWS_DAEMON_STATE_FRESHNESS_SECS {
        return None;
    }

    let mut other_pids = nvpn_pids
        .iter()
        .copied()
        .filter(|pid| *pid != current_pid)
        .collect::<Vec<_>>();
    other_pids.sort_unstable();
    other_pids.dedup();
    if other_pids.len() == 1 {
        Some(other_pids[0])
    } else {
        None
    }
}

pub(crate) fn daemon_candidate_pids(config_path: &Path, current_pid: u32) -> Result<Vec<u32>> {
    let mut daemon_pids = find_daemon_pids_by_config(config_path);

    let pid_file = daemon_pid_file_path(config_path);
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && record.pid != current_pid
        && daemon_pid_record_counts_as_running(record.pid, config_path)
        && !daemon_pids.contains(&record.pid)
    {
        daemon_pids.push(record.pid);
    }

    #[cfg(windows)]
    {
        let state = read_daemon_state(&daemon_state_file_path(config_path))?;
        if let Some(pid) = recent_windows_daemon_pid_candidate(
            state.as_ref(),
            current_pid,
            &windows_nvpn_pids(),
            unix_timestamp(),
        ) && !daemon_pids.contains(&pid)
        {
            daemon_pids.push(pid);
        }
    }

    daemon_pids.retain(|pid| *pid != current_pid);
    daemon_pids.sort_unstable();
    daemon_pids.dedup();
    Ok(daemon_pids)
}

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

#[cfg(any(target_os = "windows", test))]
pub(crate) fn daemon_pids_from_windows_cim_json(cim_json: &str, config_path: &Path) -> Vec<u32> {
    let trimmed = cim_json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };

    let entries = match parsed {
        serde_json::Value::Array(entries) => entries,
        serde_json::Value::Object(entry) => vec![serde_json::Value::Object(entry)],
        _ => return Vec::new(),
    };

    let mut pids = Vec::new();
    for entry in entries {
        let Some(command) = entry.get("CommandLine").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(pid) = entry
            .get("ProcessId")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            continue;
        };

        if daemon_command_matches_config(command, config_path) {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_daemon_pid_record_matches_cim(
    pid: u32,
    cim_json: &str,
    config_path: &Path,
) -> bool {
    daemon_pids_from_windows_cim_json(cim_json, config_path).contains(&pid)
}
