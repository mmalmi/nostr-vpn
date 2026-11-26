#[cfg(target_os = "windows")]
fn stop_and_delete_windows_native_wireguard_service(service_name: &str) -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("connect to the Windows service manager")?;
    let service = manager
        .open_service(
            service_name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("open owned native WireGuard service {service_name}"))?;
    let mut status = service
        .query_status()
        .with_context(|| format!("query owned native WireGuard service {service_name}"))?;
    if status.current_state != ServiceState::Stopped {
        if status.current_state != ServiceState::StopPending {
            service
                .stop()
                .with_context(|| format!("stop owned native WireGuard service {service_name}"))?;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            status = service.query_status().with_context(|| {
                format!("wait for owned native WireGuard service {service_name} to stop")
            })?;
            if status.current_state == ServiceState::Stopped {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "owned native WireGuard service {service_name} did not stop within 5s"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    service
        .delete()
        .with_context(|| format!("delete stopped native WireGuard service {service_name}"))
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsNativeWireGuardServiceOwnership {
    Owned,
    PathOwned,
    Absent,
    Foreign,
    Undetermined,
}

#[cfg(any(test, target_os = "windows"))]
fn classify_windows_native_service_ownership_output(
    output: &str,
) -> WindowsNativeWireGuardServiceOwnership {
    match output.trim().to_ascii_lowercase().as_str() {
        "owned" => WindowsNativeWireGuardServiceOwnership::Owned,
        "path-owned" => WindowsNativeWireGuardServiceOwnership::PathOwned,
        "absent" => WindowsNativeWireGuardServiceOwnership::Absent,
        "foreign" => WindowsNativeWireGuardServiceOwnership::Foreign,
        _ => WindowsNativeWireGuardServiceOwnership::Undetermined,
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_native_wireguard_service_ownership_script(
    service_name: &str,
    expected_binary_path: &str,
    owner_token: &str,
) -> String {
    let escaped_service_name = service_name.replace('\'', "''");
    let service_filter =
        windows_powershell_literal(&format!("Name='{escaped_service_name}'"));
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $expectedPath = {}; \
         $service = Get-CimInstance Win32_Service \
           -Filter {service_filter}; \
         if ($null -eq $service) {{ 'absent' }} \
         elseif ($service.PathName -cne $expectedPath) {{ 'foreign' }} \
         elseif ($service.Description -ceq {}) {{ 'owned' }} \
         elseif ([string]::IsNullOrEmpty($service.Description)) {{ 'path-owned' }} \
         else {{ 'foreign' }}",
        windows_powershell_literal(expected_binary_path),
        windows_powershell_literal(owner_token),
    )
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_service_is_owned(
    cleanup: &WindowsNativeWireGuardCleanupState,
) -> Result<bool> {
    let service_name = format!("WireGuardTunnel${}", cleanup.name);
    let expected_binary_path =
        windows_native_wireguard_service_binary_path(&cleanup.wireguard_exe, &cleanup.config_path);
    let script = windows_native_wireguard_service_ownership_script(
        &service_name,
        &expected_binary_path,
        &cleanup.owner_token,
    );
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .bounded_output(&format!(
            "audit native WireGuard service ownership {service_name}"
        ))?;
    if !output.status.success() {
        return Err(anyhow!(
            "native WireGuard service ownership audit failed for {service_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let state = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    match classify_windows_native_service_ownership_output(&state) {
        WindowsNativeWireGuardServiceOwnership::Owned => Ok(true),
        WindowsNativeWireGuardServiceOwnership::PathOwned => {
            if windows_native_wireguard_config_unmarked_in_owner_dir(
                &cleanup.config_path,
                &cleanup.owner_token,
            )? || windows_native_wireguard_config_is_owned(
                &cleanup.config_path,
                &cleanup.owner_token,
            )?
            {
                Ok(true)
            } else {
                Err(anyhow!(
                    "native WireGuard service {service_name} has the intended binary path \
                     but its owner-marked config is absent"
                ))
            }
        }
        WindowsNativeWireGuardServiceOwnership::Absent => Ok(false),
        WindowsNativeWireGuardServiceOwnership::Foreign => Err(anyhow!(
            "refusing to remove foreign same-name native WireGuard service {service_name}"
        )),
        WindowsNativeWireGuardServiceOwnership::Undetermined => Err(anyhow!(
            "unexpected ownership state {state:?} for native WireGuard service {service_name}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn cleanup_windows_native_wireguard_config(path: &Path, owner_token: &str) -> Result<()> {
    let legacy_layout = matches!(
        windows_native_wireguard_config_layout(path, owner_token)?,
        WindowsNativeWireGuardConfigLayout::Legacy
    );
    let config_owned = windows_native_wireguard_config_is_owned(path, owner_token)?;
    let marker_owned = windows_native_wireguard_owner_marker_is_owned(path, owner_token)?;
    if config_owned {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("remove owned config {}", path.display()));
            }
        }
    }

    let marker_path = if legacy_layout {
        windows_native_wireguard_legacy_owner_marker_path(path)
    } else {
        windows_native_wireguard_owner_marker_path(path)
    };
    if marker_owned {
        match std::fs::remove_file(&marker_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "remove owned native WireGuard marker {}",
                        marker_path.display()
                    )
                });
            }
        }
    }

    // The per-owner directory is not itself a network or secret-bearing
    // artifact once the exact config and marker are gone. Remove it when it
    // is still empty, but never recurse into or touch unexpected contents.
    if (config_owned || marker_owned)
        && let Some(owner_root) = windows_native_wireguard_owner_root(path, owner_token)?
    {
        let _ = std::fs::remove_dir(owner_root);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_windows_native_wireguard_state(
    cleanup: &mut WindowsNativeWireGuardCleanupState,
) -> Result<()> {
    let mut failures = Vec::new();
    if cleanup.service_owned {
        match windows_native_wireguard_service_is_owned(cleanup) {
            Ok(false) => cleanup.service_owned = false,
            Ok(true) => match stop_and_delete_windows_native_wireguard_service(&format!(
                "WireGuardTunnel${}",
                cleanup.name
            )) {
                Ok(()) => cleanup.service_owned = false,
                Err(error) => failures.push(format!("stop and delete owned tunnel service: {error:#}")),
            },
            Err(error) => failures.push(format!("{error:#}")),
        }
    }
    if cleanup.config_owned && !cleanup.service_owned {
        match windows_native_wireguard_config_unmarked_in_owner_dir(
            &cleanup.config_path,
            &cleanup.owner_token,
        ) {
            // The token-named owner directory already proves ownership, so a missing marker must not brick startup.
            Ok(true) => {
                eprintln!(
                    "wg-upstream: WARNING — owned native WireGuard config {} retained \
                     without its owner marker; deletion obligation stays journaled",
                    cleanup.config_path.display()
                );
            }
            Ok(false) => {
                match cleanup_windows_native_wireguard_config(
                    &cleanup.config_path,
                    &cleanup.owner_token,
                ) {
                    Ok(()) => cleanup.config_owned = false,
                    Err(error) => failures.push(format!("{error:#}")),
                }
            }
            Err(error) => failures.push(format!("{error:#}")),
        }
    } else if cleanup.config_owned {
        failures.push("owned config cleanup deferred until service removal succeeds".to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}

#[cfg(target_os = "windows")]
impl WindowsNativeWireGuardTunnel {
    fn cleanup(&mut self) -> Result<()> {
        let Some(mut cleanup) = self.cleanup_state() else {
            return Ok(());
        };
        let cleanup_result = cleanup_windows_native_wireguard_state(&mut cleanup);
        self.service_owned = cleanup.service_owned;
        self.config_owned = cleanup.config_owned;
        let persist_result = crate::daemon_runtime::persist_windows_native_wireguard_cleanup_intent(
            &self.cleanup_journal_config_path,
            &cleanup,
        );
        match (cleanup_result, persist_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => {
                Err(error.context("persist completed native WireGuard cleanup"))
            }
            (Err(cleanup_error), Err(persist_error)) => Err(anyhow!(
                "{cleanup_error:#}; failed to persist remaining native WireGuard ownership: \
                 {persist_error:#}"
            )),
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsNativeWireGuardTunnel {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            if let Some(cleanup) = self.cleanup_state() {
                retain_pending_windows_native_cleanup(cleanup);
            }
            eprintln!("wg-upstream: WARNING — owned native WireGuard cleanup retained: {error:#}");
        }
    }
}

#[cfg(target_os = "windows")]
fn with_windows_native_cleanup_error(
    error: anyhow::Error,
    operation: &str,
    cleanup: Result<()>,
) -> anyhow::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => anyhow!("{error:#}; {operation}: {cleanup_error:#}"),
    }
}
