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

#[cfg(target_os = "macos")]
pub(crate) fn is_process_running(pid: u32) -> bool {
    macos_process_image_path(pid).is_some()
}

#[cfg(windows)]
pub(crate) fn is_process_running(pid: u32) -> bool {
    windows_nvpn_pids().contains(&pid)
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

#[cfg(target_os = "macos")]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, _config_path: &Path) -> bool {
    macos_process_image_path(pid).is_some_and(|image| {
        daemon_command_has_nvpn_executable_prefix(&image.to_string_lossy())
    })
}

#[cfg(windows)]
pub(crate) fn daemon_pid_record_counts_as_running(pid: u32, _config_path: &Path) -> bool {
    is_process_running(pid)
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

#[cfg(windows)]
fn windows_process_images() -> Vec<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }

    let entry_size = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = entry_size;
    let mut images = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let image_len = entry
                .szExeFile
                .iter()
                .position(|ch| *ch == 0)
                .unwrap_or(entry.szExeFile.len());
            images.push((
                entry.th32ProcessID,
                String::from_utf16_lossy(&entry.szExeFile[..image_len]),
            ));
            entry.dwSize = entry_size;
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };
    images
}

#[cfg(windows)]
pub(crate) fn windows_nvpn_pids() -> Vec<u32> {
    windows_process_images()
        .into_iter()
        .filter(|(_, image)| image.eq_ignore_ascii_case("nvpn.exe"))
        .map(|(pid, _)| pid)
        .collect()
}

#[cfg(target_os = "macos")]
// libproc is re-exported through libSystem, which every Rust binary on macOS
// already links, so no #[link] attribute is needed.
unsafe extern "C" {
    fn proc_listallpids(buffer: *mut std::ffi::c_void, numpids: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
}

#[cfg(target_os = "macos")]
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

#[cfg(target_os = "macos")]
fn macos_process_image_path(pid: u32) -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    let written =
        unsafe { proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if written <= 0 {
        return None;
    }
    let path = CStr::from_bytes_until_nul(&buffer).ok()?.to_bytes();
    Some(PathBuf::from(OsStr::from_bytes(path)))
}

#[cfg(target_os = "macos")]
fn macos_all_pids() -> Vec<u32> {
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; count as usize];
    let written = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), count) };
    if written <= 0 {
        return Vec::new();
    }
    pids.truncate(written as usize);
    pids.into_iter().map(|pid| pid as u32).collect()
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_nvpn_pids() -> Vec<u32> {
    macos_all_pids()
        .into_iter()
        .filter(|pid| {
            macos_process_image_path(*pid).is_some_and(|image| {
                daemon_command_has_nvpn_executable_prefix(&image.to_string_lossy())
            })
        })
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub(crate) fn recent_state_file_daemon_pid_candidate(
    state: Option<&DaemonRuntimeState>,
    current_pid: u32,
    nvpn_pids: &[u32],
    now: u64,
) -> Option<u32> {
    let state = state?;
    if now.saturating_sub(state.updated_at) > DAEMON_STATE_FRESHNESS_SECS {
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
    #[cfg(target_os = "linux")]
    let mut daemon_pids = find_daemon_pids_by_config(config_path);
    #[cfg(not(target_os = "linux"))]
    let mut daemon_pids = Vec::new();

    let pid_file = daemon_pid_file_path(config_path)?;
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && record.pid != current_pid
        && daemon_pid_record_counts_as_running(record.pid, config_path)
        && !daemon_pids.contains(&record.pid)
    {
        daemon_pids.push(record.pid);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        #[cfg(target_os = "macos")]
        let nvpn_pids = macos_nvpn_pids();
        #[cfg(windows)]
        let nvpn_pids = windows_nvpn_pids();
        let state = read_daemon_state(&daemon_state_file_path(config_path)?)?;
        if let Some(pid) = recent_state_file_daemon_pid_candidate(
            state.as_ref(),
            current_pid,
            &nvpn_pids,
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

#[cfg(any(target_os = "linux", target_os = "macos", test))]
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
