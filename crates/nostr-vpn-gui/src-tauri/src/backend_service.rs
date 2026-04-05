use super::*;

impl NvpnBackend {
    pub(crate) fn persist_config(&mut self) -> Result<PersistConfigOutcome> {
        if self.config.nostr.relays.is_empty() {
            return Err(anyhow!("at least one relay is required"));
        }

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);

        #[cfg(target_os = "windows")]
        {
            self.refresh_windows_config_path()?;
            if windows_should_use_daemon_owned_config_apply(
                &self.config_path,
                windows_program_data_dir().as_deref(),
                self.daemon_running,
                self.service_installed,
            ) {
                match self.persist_config_via_running_daemon() {
                    Ok(()) => {
                        self.ensure_relay_status_entries();
                        self.ensure_peer_status_entries();
                        return Ok(PersistConfigOutcome::ReloadedRunningDaemon);
                    }
                    Err(error) => {
                        eprintln!(
                            "gui: daemon-backed config apply failed, falling back to direct save: {error}"
                        );
                    }
                }
            }
        }

        if let Err(error) = self.config.save(&self.config_path) {
            #[cfg(target_os = "windows")]
            {
                if requires_admin_privileges_error(&error) {
                    self.persist_config_with_admin_privileges()?;
                } else {
                    return Err(error);
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                return Err(error);
            }
        }
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        Ok(PersistConfigOutcome::SavedLocally)
    }

    pub(crate) fn persist_config_without_daemon_reload(&mut self) -> Result<()> {
        let _ = self.persist_config()?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn persist_config_via_running_daemon(&mut self) -> Result<()> {
        let temp_path = windows_temp_config_import_path();
        self.config.save(&temp_path).with_context(|| {
            format!(
                "failed to stage config for daemon import {}",
                temp_path.display()
            )
        })?;

        let result = (|| {
            let source = temp_path
                .to_str()
                .ok_or_else(|| anyhow!("temp config path is not valid UTF-8"))?;
            let target = self
                .config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?
                .to_string();
            let args = windows_daemon_config_import_args(source, target.as_str());
            let mut output = self.run_nvpn_command(args)?;

            if !output.status.success() {
                let failure = windows_nvpn_command_failure("apply-config-daemon", &output);
                if windows_daemon_apply_requires_service_repair(&failure) {
                    eprintln!(
                        "gui: daemon-backed config apply detected stale Windows service; reinstalling service and retrying"
                    );
                    self.reinstall_windows_system_service()?;
                    self.invalidate_service_status_cache();
                    output = self.run_nvpn_command(args)?;
                }
            }

            if output.status.success() {
                Ok(())
            } else {
                let failure = windows_nvpn_command_failure("apply-config-daemon", &output);
                if requires_admin_privileges(&failure) {
                    self.run_nvpn_command_with_admin_privileges(args)?;
                    Ok(())
                } else {
                    Err(anyhow!("{failure}"))
                }
            }
        })();

        let _ = fs::remove_file(&temp_path);
        result
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn persist_config_with_admin_privileges(&self) -> Result<()> {
        let temp_path = windows_temp_config_import_path();
        self.config.save(&temp_path).with_context(|| {
            format!(
                "failed to stage config for elevated import {}",
                temp_path.display()
            )
        })?;

        let result = (|| {
            let source = temp_path
                .to_str()
                .ok_or_else(|| anyhow!("temp config path is not valid UTF-8"))?;
            let target = self
                .config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
            self.run_nvpn_command_with_admin_privileges(windows_elevated_config_import_args(
                source, target,
            ))
        })();

        let _ = fs::remove_file(&temp_path);
        result
    }

    pub(crate) fn ensure_relay_status_entries(&mut self) {
        let configured: HashSet<String> = self.config.nostr.relays.iter().cloned().collect();
        self.relay_status
            .retain(|relay, _| configured.contains(relay));

        for relay in &self.config.nostr.relays {
            self.relay_status
                .entry(relay.clone())
                .or_insert(RelayStatus {
                    state: "unknown".to_string(),
                    status_text: "not checked".to_string(),
                });
        }
    }

    pub(crate) fn ensure_peer_status_entries(&mut self) {
        let configured: HashSet<String> = self
            .config
            .all_participant_pubkeys_hex()
            .into_iter()
            .collect();
        self.peer_status
            .retain(|participant, _| configured.contains(participant));

        for participant in configured {
            self.peer_status.entry(participant).or_default();
        }
    }

    pub(crate) fn daemon_config_path_arg(&self) -> Result<&str> {
        self.config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))
    }

    pub(crate) fn install_cli_binary(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.cli_install_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        let args = ["install-cli", "--force"];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn install-cli failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn uninstall_cli_binary(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.cli_install_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        let args = ["uninstall-cli"];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn uninstall-cli failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn install_system_service(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        #[cfg(target_os = "windows")]
        let args = [
            "service",
            "install",
            "--force",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];

        #[cfg(not(target_os = "windows"))]
        let args = [
            "service",
            "install",
            "--force",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            self.invalidate_service_status_cache();
            #[cfg(target_os = "windows")]
            self.reload_preferred_windows_config_path()?;
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service install failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            self.invalidate_service_status_cache();
            #[cfg(target_os = "windows")]
            self.reload_preferred_windows_config_path()?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn reinstall_windows_system_service(&self) -> Result<()> {
        let config_path = self
            .config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
        let args = ["service", "install", "--force", "--config", config_path];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let message = windows_nvpn_command_failure("service install", &output);
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn uninstall_system_service(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "uninstall",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            self.invalidate_service_status_cache();
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service uninstall failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn enable_system_service(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "enable",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            self.invalidate_service_status_cache();
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service enable failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    pub(crate) fn disable_system_service(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "disable",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            self.invalidate_service_status_cache();
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service disable failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn reload_preferred_windows_config_path(&mut self) -> Result<()> {
        let preferred_path = default_config_path();
        if preferred_path == self.config_path {
            return Ok(());
        }

        if preferred_path.exists() {
            let mut config = AppConfig::load(&preferred_path)
                .with_context(|| format!("failed to load config {}", preferred_path.display()))?;
            config.ensure_defaults();
            maybe_autoconfigure_node(&mut config);
            self.config = config;
        }
        self.config_path = preferred_path;
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn refresh_windows_config_path(&mut self) -> Result<()> {
        self.reload_preferred_windows_config_path()
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn refresh_windows_config_path(&mut self) -> Result<()> {
        Ok(())
    }

    pub(crate) fn reload_config_from_disk_if_present(&mut self) {
        if !self.config_path.exists() {
            return;
        }

        let mut config = match AppConfig::load(&self.config_path) {
            Ok(config) => config,
            Err(error) => {
                eprintln!(
                    "gui: failed to reload config from {}: {error}",
                    self.config_path.display()
                );
                return;
            }
        };
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        self.config = config;
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
    }

    #[cfg(target_os = "android")]
    pub(crate) fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let (running, state) = self.android_session.status();
        Ok(CliStatusResponse {
            daemon: CliDaemonStatus { running, state },
        })
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let status = ios_vpn::status()?;
        Ok(CliStatusResponse {
            daemon: CliDaemonStatus {
                running: status.active,
                state: status.state,
            },
        })
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
    pub(crate) fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let output = self.run_nvpn_command([
            "status",
            "--json",
            "--discover-secs",
            "0",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "nvpn status failed\nstdout: {}\nstderr: {}",
                stdout.trim(),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_text = extract_json_document(&stdout)?;
        let parsed = serde_json::from_str::<CliStatusResponse>(json_text)
            .context("failed to parse `nvpn status --json` output")?;
        Ok(parsed)
    }

    pub(crate) fn run_nvpn_command<const N: usize>(
        &self,
        args: [&str; N],
    ) -> Result<std::process::Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {} or install nvpn in PATH",
                NVPN_BIN_ENV
            ));
        };

        let mut command = ProcessCommand::new(nvpn_bin);
        apply_windows_subprocess_flags(&mut command)
            .args(args)
            .output()
            .with_context(|| {
                format!(
                    "failed to execute {} {}",
                    nvpn_bin.display(),
                    args.join(" ")
                )
            })
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    pub(crate) fn run_nvpn_command_with_admin_privileges<const N: usize>(
        &self,
        args: [&str; N],
    ) -> Result<()> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {} or install nvpn in PATH",
                NVPN_BIN_ENV
            ));
        };
        let nvpn_bin = nvpn_bin
            .to_str()
            .ok_or_else(|| anyhow!("nvpn binary path is not valid UTF-8"))?;

        #[cfg(target_os = "macos")]
        {
            let mut command = runas::Command::new(nvpn_bin);
            command.gui(true);
            command.args(&args);

            let status = command.status().context(
                "failed to execute elevated nvpn command via native macOS authorization prompt",
            )?;

            if status.success() {
                return Ok(());
            }
            return Err(anyhow!(
                "elevated nvpn command failed via macOS authorization: {status}"
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let output = ProcessCommand::new("pkexec")
                .arg(nvpn_bin)
                .args(args)
                .output();

            let output = match output {
                Ok(output) => output,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(anyhow!(
                        "pkexec not found; install policykit (polkit) to allow GUI privilege prompts"
                    ));
                }
                Err(error) => {
                    return Err(anyhow!(
                        "failed to execute pkexec for elevated nvpn command: {error}"
                    ));
                }
            };

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let details = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            if details
                .to_ascii_lowercase()
                .contains("no authentication agent found")
            {
                return Err(anyhow!(
                    "pkexec could not find a polkit authentication agent; run a desktop polkit agent or start nvpn with sudo"
                ));
            }
            return Err(anyhow!(
                "elevated nvpn command failed via pkexec: {details}"
            ));
        }

        #[cfg(target_os = "windows")]
        {
            let normalized_args = normalize_windows_elevated_args(args);
            let status = runas::Command::new(nvpn_bin)
                .args(&normalized_args)
                .status()
                .context("failed to execute elevated nvpn command via Windows UAC prompt")?;

            if status.success() {
                return Ok(());
            }
            return Err(anyhow!(
                "elevated nvpn command failed via Windows UAC authorization: {status}"
            ));
        }

        #[allow(unreachable_code)]
        Err(anyhow!(
            "privilege escalation helper is not implemented on this platform"
        ))
    }
}
