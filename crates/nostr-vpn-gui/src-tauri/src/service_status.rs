use super::*;
use std::time::Instant;

impl NvpnBackend {
    pub(crate) fn invalidate_service_status_cache(&mut self) {
        self.last_service_status_refresh_at = None;
    }

    #[cfg(target_os = "android")]
    pub(crate) fn fetch_cli_service_status(&self) -> Result<CliServiceStatusResponse> {
        Ok(CliServiceStatusResponse {
            supported: false,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: "android-vpn".to_string(),
            plist_path: String::new(),
            binary_path: String::new(),
            binary_version: String::new(),
        })
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn fetch_cli_service_status(&self) -> Result<CliServiceStatusResponse> {
        Ok(CliServiceStatusResponse {
            supported: false,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: "ios-packet-tunnel".to_string(),
            plist_path: String::new(),
            binary_path: String::new(),
            binary_version: String::new(),
        })
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
    pub(crate) fn fetch_cli_service_status(&self) -> Result<CliServiceStatusResponse> {
        let output = self.run_nvpn_command([
            "service",
            "status",
            "--json",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "nvpn service status failed\nstdout: {}\nstderr: {}",
                stdout.trim(),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_text = extract_json_document(&stdout)?;
        let parsed = serde_json::from_str::<CliServiceStatusResponse>(json_text)
            .context("failed to parse `nvpn service status --json` output")?;
        Ok(parsed)
    }

    pub(crate) fn sync_service_state(&mut self) {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.service_supported = false;
            self.service_enablement_supported = false;
            self.service_installed = false;
            self.service_disabled = false;
            self.service_running = false;
            self.service_status_detail =
                "Background service unsupported on this platform".to_string();
            self.service_binary_version.clear();
            return;
        }

        let now = Instant::now();
        if !service_state_refresh_due(
            self.last_service_status_refresh_at,
            now,
            SERVICE_STATUS_REFRESH_INTERVAL,
        ) {
            return;
        }

        match self.fetch_cli_service_status() {
            Ok(status) => {
                self.last_service_status_refresh_at = Some(now);
                self.service_supported = status.supported;
                self.service_installed = status.installed;
                self.service_disabled = status.disabled;
                self.service_running = status.running;
                self.service_binary_version = status.binary_version.clone();
                self.service_status_detail = if !status.supported {
                    "Background service unsupported on this platform".to_string()
                } else if !status.installed {
                    "Background service is not installed".to_string()
                } else if status.disabled {
                    "Background service is installed but disabled in launchd".to_string()
                } else if status.running {
                    match status.pid {
                        Some(pid) => format!("Background service running (pid {pid})"),
                        None => "Background service running".to_string(),
                    }
                } else if status.loaded {
                    "Background service installed but not running".to_string()
                } else {
                    "Background service installed but launch status is unavailable".to_string()
                };
                eprintln!(
                    "gui: service status synced supported={} installed={} disabled={} loaded={} running={} pid={:?} label={} path={}",
                    status.supported,
                    status.installed,
                    status.disabled,
                    status.loaded,
                    status.running,
                    status.pid,
                    status.label,
                    status.plist_path
                );
            }
            Err(error) => {
                self.last_service_status_refresh_at = Some(now);
                self.service_supported = cfg!(any(
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                ));
                self.service_installed = false;
                self.service_disabled = false;
                self.service_running = false;
                self.service_binary_version.clear();
                self.service_status_detail = format!("Service status unavailable: {error}");
                eprintln!("gui: failed to sync service status: {error}");
            }
        }
    }

    pub(crate) fn gui_requires_service_install(&self) -> bool {
        gui_requires_service_install(
            self.service_supported,
            self.service_installed,
            self.daemon_running,
        )
    }

    pub(crate) fn gui_requires_service_enable(&self) -> bool {
        gui_requires_service_enable(
            self.service_enablement_supported,
            self.service_installed,
            self.service_disabled,
            self.daemon_running,
        )
    }

    pub(crate) fn gui_requires_service_action(&self) -> bool {
        self.gui_requires_service_install() || self.gui_requires_service_enable()
    }
}
