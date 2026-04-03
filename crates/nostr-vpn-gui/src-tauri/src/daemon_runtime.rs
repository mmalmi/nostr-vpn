use super::*;

impl NvpnBackend {
    pub(crate) fn connect_session(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.session_status = runtime.runtime_status_detail.to_string();
            return Err(anyhow!(self.session_status.clone()));
        }
        let _ = self.persist_config()?;
        self.sync_daemon_state();
        if self.daemon_running {
            self.resume_daemon_process()?;
        } else {
            if self.gui_requires_service_install() {
                self.install_system_service()?;
                self.sync_daemon_state();
            } else if self.gui_requires_service_enable() {
                self.enable_system_service()?;
                self.sync_daemon_state();
            }

            if self.daemon_running {
                self.resume_daemon_process()?;
            } else if self.gui_requires_service_install() {
                self.session_status = gui_service_setup_status_text(false).to_string();
                return Err(anyhow!(self.session_status.clone()));
            } else if self.gui_requires_service_enable() {
                self.session_status = gui_service_enable_status_text(false).to_string();
                return Err(anyhow!(self.session_status.clone()));
            }

            self.start_daemon_process()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    pub(crate) fn disconnect_session(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.session_status = runtime.runtime_status_detail.to_string();
            return Err(anyhow!(self.session_status.clone()));
        }
        if self.daemon_running {
            self.pause_daemon_process()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub(crate) fn start_daemon_process(&mut self) -> Result<()> {
        self.android_session.start(self.config.clone())
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn start_daemon_process(&mut self) -> Result<()> {
        let mut config = self.config.clone();
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        write_ios_probe(format!(
            "ios-start: prepare network_id={} participants={} endpoint={} listen_port={}",
            config.effective_network_id(),
            config.participant_pubkeys_hex().len(),
            config.node.endpoint,
            config.node.listen_port
        ));
        ios_vpn::prepare()?;
        write_ios_probe("ios-start: prepare complete");
        let status = ios_vpn::start(&ios_vpn::StartVpnArgs {
            session_name: config.effective_network_id(),
            config_json: serde_json::to_string(&config)
                .context("failed to serialize iOS VPN config")?,
            local_address: ios_vpn::local_address_for_tunnel(&config.node.tunnel_ip),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            mtu: ios_vpn::IOS_TUN_MTU,
        })?;
        write_ios_probe(format!(
            "ios-start: start complete prepared={} active={} state_present={} error={}",
            status.prepared,
            status.active,
            status.state.is_some(),
            status.error.as_deref().unwrap_or("")
        ));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn start_daemon_process(&mut self) -> Result<()> {
        self.refresh_windows_config_path()?;
        let config_path = self.daemon_config_path_arg()?;
        let iface_override = nvpn_gui_iface_override();

        if let Ok(status) = self.fetch_cli_status()
            && status.daemon.running
        {
            return Ok(());
        }

        let result = if let Some(iface) = iface_override.as_deref() {
            self.run_nvpn_command_with_admin_privileges([
                "start",
                "--daemon",
                "--connect",
                "--iface",
                iface,
                "--config",
                config_path,
            ])
        } else {
            self.run_nvpn_command_with_admin_privileges([
                "start",
                "--daemon",
                "--connect",
                "--config",
                config_path,
            ])
        };

        match result {
            Ok(()) => Ok(()),
            Err(error) if is_already_running_message(&error.to_string()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    #[cfg(all(
        not(target_os = "macos"),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    pub(crate) fn start_daemon_process(&mut self) -> Result<()> {
        self.refresh_windows_config_path()?;

        #[cfg(target_os = "windows")]
        if windows_should_start_installed_service(self.service_installed, self.service_disabled) {
            self.enable_system_service()?;
            return Ok(());
        }

        let config_path = self.daemon_config_path_arg()?;
        let iface_override = nvpn_gui_iface_override();
        let output = if let Some(iface) = iface_override.as_deref() {
            self.run_nvpn_command([
                "start",
                "--daemon",
                "--connect",
                "--iface",
                iface,
                "--config",
                config_path,
            ])?
        } else {
            self.run_nvpn_command(["start", "--daemon", "--connect", "--config", config_path])?
        };

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn start failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        if is_already_running_message(&message) {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        if requires_admin_privileges(&message) {
            let escalated = if let Some(iface) = iface_override.as_deref() {
                self.run_nvpn_command_with_admin_privileges([
                    "start",
                    "--daemon",
                    "--connect",
                    "--iface",
                    iface,
                    "--config",
                    config_path,
                ])
            } else {
                self.run_nvpn_command_with_admin_privileges([
                    "start",
                    "--daemon",
                    "--connect",
                    "--config",
                    config_path,
                ])
            };

            match escalated {
                Ok(()) => {}
                Err(error) if is_already_running_message(&error.to_string()) => {}
                Err(error) => return Err(error),
            }
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    pub(crate) fn reload_daemon_process(&mut self) -> Result<()> {
        self.android_session.reload(self.config.clone())
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn reload_daemon_process(&mut self) -> Result<()> {
        let _ = ios_vpn::stop();
        self.start_daemon_process()
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
    pub(crate) fn reload_daemon_process(&mut self) -> Result<()> {
        self.refresh_windows_config_path()?;
        let args = [
            "reload",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn reload failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    pub(crate) fn pause_daemon_process(&mut self) -> Result<()> {
        self.android_session.stop()
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn pause_daemon_process(&mut self) -> Result<()> {
        let _ = ios_vpn::stop()?;
        Ok(())
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
    pub(crate) fn pause_daemon_process(&mut self) -> Result<()> {
        self.refresh_windows_config_path()?;
        let args = [
            "pause",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn pause failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    pub(crate) fn resume_daemon_process(&mut self) -> Result<()> {
        self.android_session.start(self.config.clone())
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn resume_daemon_process(&mut self) -> Result<()> {
        self.start_daemon_process()
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
    pub(crate) fn resume_daemon_process(&mut self) -> Result<()> {
        self.refresh_windows_config_path()?;
        let args = [
            "resume",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn resume failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn reload_daemon_if_running(&mut self) -> Result<()> {
        if !self.daemon_running {
            return Ok(());
        }

        self.reload_daemon_process()
    }
}
