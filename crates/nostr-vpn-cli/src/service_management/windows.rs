#[cfg(target_os = "windows")]
use std::os::windows::process::ExitStatusExt as _;

#[cfg(target_os = "windows")]
use windows_service::service::{
    Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
};
#[cfg(target_os = "windows")]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

#[cfg(target_os = "windows")]
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
#[cfg(target_os = "windows")]
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    // Retained for the stop state machine contract; the typed SCM query
    // reports vendor-specific raw states as query errors instead.
    #[allow(dead_code)]
    Unknown(u32),
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsServiceStopAction {
    Complete,
    Wait,
    RequestStop,
    Unsupported,
}

#[cfg(target_os = "windows")]
fn windows_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
    force: bool,
) -> Result<()> {
    stop_daemon(StopArgs {
        config: Some(config_path.to_path_buf()),
        timeout_secs: 5,
        force: true,
    })?;

    if force {
        windows_stop_service(true)?;
        windows_delete_service(true)?;
        windows_wait_for_service_deleted(Duration::from_secs(10))?;
    } else if windows_service_is_installed()? {
        return Err(anyhow!(
            "system service already installed (pass --force to reinstall)"
        ));
    }

    let command_line = windows_service_bin_path(
        executable,
        config_path,
        iface,
        mesh_refresh_interval_secs.max(1),
    );
    let service_info = windows_service_info_from_command_line(
        &command_line,
        WINDOWS_SERVICE_DISPLAY_NAME,
        ServiceStartType::AutoStart,
    )?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .context("connect to the Windows service manager")?;
    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
        .context("create system service")?;
    service
        .set_description(WINDOWS_SERVICE_DESCRIPTION)
        .context("set service description")?;
    windows_start_service_and_wait(false, Duration::from_secs(10))?;
    println!("installed system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_uninstall_service() -> Result<()> {
    windows_stop_service(true)?;
    windows_delete_service(true)?;
    windows_wait_for_service_deleted(Duration::from_secs(10))?;
    println!("removed system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_enable_service() -> Result<()> {
    if !windows_service_is_installed()? {
        return Err(anyhow!("system service is not installed"));
    }

    windows_change_service_start_type(ServiceStartType::AutoStart)?;
    windows_start_service_and_wait(true, Duration::from_secs(10))?;
    println!("enabled system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_disable_service() -> Result<()> {
    if !windows_service_is_installed()? {
        return Err(anyhow!("system service is not installed"));
    }

    windows_stop_service(true)?;
    windows_change_service_start_type(ServiceStartType::Disabled)?;
    println!("disabled system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_should_apply_config_via_service(status: &ServiceStatusView) -> bool {
    status.installed && !status.disabled
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_query_service_status(
    include_binary_version: bool,
) -> Result<ServiceStatusView> {
    let service = windows_open_named_service(
        WINDOWS_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    )?;
    let Some(service) = service else {
        return Ok(ServiceStatusView {
            supported: true,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: WINDOWS_SERVICE_NAME.to_string(),
            plist_path: WINDOWS_SERVICE_NAME.to_string(),
            binary_path: String::new(),
            binary_version: String::new(),
        });
    };

    let status = service
        .query_status()
        .context("query system service status")?;
    let config = service
        .query_config()
        .context("query system service config")?;
    let disabled = config.start_type == ServiceStartType::Disabled;
    let service_binary =
        windows_service_executable_from_command_line(&config.executable_path.to_string_lossy());
    let binary_version = if include_binary_version {
        service_binary
            .as_ref()
            .and_then(|path| query_binary_version(path))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(ServiceStatusView {
        supported: true,
        installed: true,
        disabled,
        loaded: !disabled,
        running: status.current_state == ServiceState::Running,
        pid: status.process_id.filter(|pid| *pid > 0),
        label: WINDOWS_SERVICE_NAME.to_string(),
        plist_path: WINDOWS_SERVICE_NAME.to_string(),
        binary_path: service_binary
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        binary_version,
    })
}

#[cfg(target_os = "windows")]
fn windows_service_is_installed() -> Result<bool> {
    Ok(windows_open_named_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)?.is_some())
}

#[cfg(target_os = "windows")]
fn windows_open_named_service(
    service_name: &str,
    access: ServiceAccess,
) -> Result<Option<Service>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connect to the Windows service manager")?;
    match manager.open_service(service_name, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(os_error))
            if os_error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("open service {service_name}")),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_start_named_service(
    service_name: &str,
    ignore_already_running: bool,
) -> Result<()> {
    let service = windows_open_named_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START,
    )?
    .ok_or_else(|| anyhow!("service {service_name} is not installed"))?;
    if let Err(error) = service.start(&[] as &[OsString]) {
        if ignore_already_running
            && let windows_service::Error::Winapi(os_error) = &error
            && os_error.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING)
        {
            return Ok(());
        }
        return Err(error).with_context(|| format!("start service {service_name}"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_start_service_and_wait(
    ignore_already_running: bool,
    timeout: Duration,
) -> Result<()> {
    windows_start_named_service(WINDOWS_SERVICE_NAME, ignore_already_running)?;
    windows_wait_for_service_running(timeout)
}

#[cfg(target_os = "windows")]
fn windows_wait_for_service_running(timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if windows_query_service_lifecycle_state()?
            .is_some_and(|state| state == WindowsServiceState::Running)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(anyhow!(
        "system service did not reach running state within {}s",
        timeout.as_secs()
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_config_query() -> Result<Option<std::process::Output>> {
    // Config bootstrap still consumes the legacy `sc qc` text contract to
    // locate the installed service config; source it from the typed SCM API
    // so localized `sc.exe` output and missing services cannot break it.
    let service =
        windows_open_named_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    let Some(service) = service else {
        return Ok(None);
    };
    let config = service
        .query_config()
        .context("query system service config")?;
    Ok(Some(std::process::Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: format!("BINARY_PATH_NAME : {}\n", config.executable_path.display()).into_bytes(),
        stderr: Vec::new(),
    }))
}

#[cfg(target_os = "windows")]
fn windows_stop_service(ignore_missing: bool) -> Result<()> {
    let started = Instant::now();
    let mut service_was_installed = false;
    let mut stop_requested = false;

    loop {
        let service = windows_open_named_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )?;
        let state = match &service {
            Some(service) => Some(windows_service_state_from_status(
                service
                    .query_status()
                    .context("query system service status")?
                    .current_state,
            )),
            None => None,
        };
        if state.is_some() {
            service_was_installed = true;
        }

        match windows_service_stop_action(state) {
            WindowsServiceStopAction::Complete => {
                if state.is_some() || service_was_installed || ignore_missing {
                    return Ok(());
                }
                return Err(anyhow!("system service is not installed"));
            }
            WindowsServiceStopAction::Wait => {}
            WindowsServiceStopAction::RequestStop if stop_requested => {}
            WindowsServiceStopAction::RequestStop => {
                if let Some(service) = &service {
                    match service.stop() {
                        Ok(_) => stop_requested = true,
                        Err(error) => {
                            let observed = windows_query_service_lifecycle_state()?;
                            if !windows_service_stop_failure_is_joinable(observed) {
                                return Err(error).with_context(|| "stop system service");
                            }
                            if windows_service_stop_action(observed)
                                == WindowsServiceStopAction::Complete
                            {
                                return Ok(());
                            }
                            stop_requested = true;
                        }
                    }
                }
            }
            WindowsServiceStopAction::Unsupported => {
                return Err(anyhow!("system service reported unsupported state {state:?}"));
            }
        }

        if started.elapsed() >= WINDOWS_SERVICE_STOP_TIMEOUT {
            return Err(anyhow!(
                "system service did not reach stopped or missing state within {}s (last state: {state:?})",
                WINDOWS_SERVICE_STOP_TIMEOUT.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(target_os = "windows")]
fn windows_query_service_lifecycle_state() -> Result<Option<WindowsServiceState>> {
    let Some(service) =
        windows_open_named_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)?
    else {
        return Ok(None);
    };
    let status = service
        .query_status()
        .context("query system service status")?;
    Ok(Some(windows_service_state_from_status(
        status.current_state,
    )))
}

#[cfg(target_os = "windows")]
fn windows_service_state_from_status(state: ServiceState) -> WindowsServiceState {
    match state {
        ServiceState::Stopped => WindowsServiceState::Stopped,
        ServiceState::StartPending => WindowsServiceState::StartPending,
        ServiceState::StopPending => WindowsServiceState::StopPending,
        ServiceState::Running => WindowsServiceState::Running,
        ServiceState::ContinuePending => WindowsServiceState::ContinuePending,
        ServiceState::PausePending => WindowsServiceState::PausePending,
        ServiceState::Paused => WindowsServiceState::Paused,
    }
}

#[cfg(target_os = "windows")]
fn windows_delete_service(ignore_missing: bool) -> Result<()> {
    let Some(service) = windows_open_named_service(WINDOWS_SERVICE_NAME, ServiceAccess::DELETE)?
    else {
        if ignore_missing {
            return Ok(());
        }
        return Err(anyhow!("system service is not installed"));
    };
    service.delete().context("delete system service")
}

#[cfg(target_os = "windows")]
fn windows_wait_for_service_deleted(timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if windows_open_named_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)?.is_none()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(anyhow!(
        "system service did not finish deletion within {}s",
        timeout.as_secs()
    ))
}

#[cfg(target_os = "windows")]
fn windows_change_service_start_type(start_type: ServiceStartType) -> Result<()> {
    let service = windows_open_named_service(
        WINDOWS_SERVICE_NAME,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG,
    )?
    .ok_or_else(|| anyhow!("system service is not installed"))?;
    let config = service
        .query_config()
        .context("query system service config")?;
    let mut service_info = windows_service_info_from_command_line(
        &config.executable_path.to_string_lossy(),
        &config.display_name.to_string_lossy(),
        start_type,
    )?;
    service_info.service_type = config.service_type;
    service_info.error_control = config.error_control;
    service_info.dependencies = config.dependencies;
    service_info.account_name = config.account_name;
    service
        .change_config(&service_info)
        .context("configure system service start type")
}

#[cfg(target_os = "windows")]
fn windows_service_info_from_command_line(
    command_line: &str,
    display_name: &str,
    start_type: ServiceStartType,
) -> Result<ServiceInfo> {
    let mut arguments = windows_command_line_argv(command_line).into_iter();
    let executable_path = arguments
        .next()
        .filter(|executable| !executable.trim().is_empty())
        .ok_or_else(|| anyhow!("service command line has no executable path"))?;
    Ok(ServiceInfo {
        name: WINDOWS_SERVICE_NAME.into(),
        display_name: display_name.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable_path.into(),
        launch_arguments: arguments.map(Into::into).collect(),
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    })
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_executable_from_command_line(command: &str) -> Option<PathBuf> {
    let executable = windows_command_line_argv(command).into_iter().next()?;
    if executable.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(executable))
    }
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_command_line_argv(command: &str) -> Vec<String> {
    // Inverse of the Windows command line quoting rules used by
    // `windows_command_line_quote` and the SCM ImagePath: backslash pairs are
    // literal, a backslash before a quote escapes it, and unquoted whitespace
    // separates arguments.
    let mut argv = Vec::new();
    let mut argument = String::new();
    let mut argument_started = false;
    let mut in_quotes = false;
    let mut backslashes = 0_usize;
    for ch in command.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                argument.extend(std::iter::repeat('\\').take(backslashes / 2));
                if backslashes % 2 == 1 {
                    argument.push('"');
                } else {
                    in_quotes = !in_quotes;
                    argument_started = true;
                }
                backslashes = 0;
            }
            ' ' | '\t' if !in_quotes => {
                argument.extend(std::iter::repeat('\\').take(backslashes));
                backslashes = 0;
                if argument_started || !argument.is_empty() {
                    argv.push(std::mem::take(&mut argument));
                    argument_started = false;
                }
            }
            _ => {
                argument.extend(std::iter::repeat('\\').take(backslashes));
                backslashes = 0;
                argument.push(ch);
                argument_started = true;
            }
        }
    }
    argument.extend(std::iter::repeat('\\').take(backslashes));
    if argument_started || !argument.is_empty() {
        argv.push(argument);
    }
    argv
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_stop_action(
    state: Option<WindowsServiceState>,
) -> WindowsServiceStopAction {
    match state {
        None | Some(WindowsServiceState::Stopped) => WindowsServiceStopAction::Complete,
        Some(
            WindowsServiceState::StartPending
            | WindowsServiceState::StopPending
            | WindowsServiceState::ContinuePending
            | WindowsServiceState::PausePending,
        ) => WindowsServiceStopAction::Wait,
        Some(WindowsServiceState::Running | WindowsServiceState::Paused) => {
            WindowsServiceStopAction::RequestStop
        }
        Some(WindowsServiceState::Unknown(_)) => WindowsServiceStopAction::Unsupported,
    }
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_stop_failure_is_joinable(
    observed: Option<WindowsServiceState>,
) -> bool {
    matches!(
        observed,
        None | Some(WindowsServiceState::Stopped | WindowsServiceState::StopPending)
    )
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_service_bin_path(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    mesh_refresh_interval_secs: u64,
) -> String {
    [
        windows_command_line_quote(&executable.display().to_string()),
        "daemon".to_string(),
        "--service".to_string(),
        "--config".to_string(),
        windows_command_line_quote(&config_path.display().to_string()),
        "--iface".to_string(),
        windows_command_line_quote(iface),
        "--mesh-refresh-interval-secs".to_string(),
        mesh_refresh_interval_secs.max(1).to_string(),
    ]
    .join(" ")
}
