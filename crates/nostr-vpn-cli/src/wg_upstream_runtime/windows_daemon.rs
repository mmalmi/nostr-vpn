// ---------------------------------------------------------------------------
// Windows daemon entry point. Mirrors the macOS variant: creates a
// dedicated WinTun adapter for the WG upstream, runs the userspace
// state machine, watchdogs the handshake, and only swaps the default
// route after a successful handshake.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const WINDOWS_NATIVE_RECONCILE_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(any(test, target_os = "windows"))]
pub(crate) fn windows_wireguard_ipv6_default(config: &WireGuardExitConfig) -> Result<bool> {
    let routes_ipv6 = config
        .allowed_ips
        .iter()
        .any(|route| nostr_vpn_core::config::route_is_ipv6(route));
    if !routes_ipv6 {
        if config.allowed_ips.iter().any(|route| route == "0.0.0.0/0") {
            // Without ::/0 the IPv6 default stays on the physical adapter
            // and no firewall block covers it.
            return Err(anyhow!(
                "Windows WireGuard exit claiming the IPv4 default (0.0.0.0/0) must also \
                 route ::/0; import a dual-stack provider config so IPv6 traffic cannot \
                 bypass the tunnel"
            ));
        }
        return Ok(false);
    }
    if !config.allowed_ips.iter().any(|route| route == "::/0") {
        return Err(anyhow!(
            "Windows WireGuard exit IPv6 AllowedIPs must include ::/0; partial IPv6 routes are not supported"
        ));
    }
    if nostr_vpn_core::config::route_is_ipv6(&config.address) {
        return Err(anyhow!(
            "Windows WireGuard exits need an IPv4 Address as well as an IPv6 Address"
        ));
    }
    if !nostr_vpn_core::config::route_is_ipv6(&config.address_v6) {
        return Err(anyhow!(
            "WireGuard exit with IPv6 AllowedIPs needs an IPv6 Address; re-import the \
             provider config so its dual-stack Address line is kept"
        ));
    }
    Ok(true)
}

#[cfg(target_os = "windows")]
pub async fn apply_daemon_wg_upstream(
    config: &WireGuardExitConfig,
    handshake_timeout: Duration,
) -> Result<DaemonWgUpstream> {
    let cleanup_journal_config_path = crate::default_config_path();
    apply_daemon_wg_upstream_excluding(config, handshake_timeout, &[], &cleanup_journal_config_path)
        .await
}

#[cfg(target_os = "windows")]
pub(crate) async fn apply_daemon_wg_upstream_for_fips(
    config: &WireGuardExitConfig,
    handshake_timeout: Duration,
    fips_interface_index: u32,
    cleanup_journal_config_path: &Path,
) -> Result<DaemonWgUpstream> {
    apply_daemon_wg_upstream_excluding(
        config,
        handshake_timeout,
        &[fips_interface_index],
        cleanup_journal_config_path,
    )
    .await
}

#[cfg(target_os = "windows")]
async fn apply_daemon_wg_upstream_excluding(
    config: &WireGuardExitConfig,
    handshake_timeout: Duration,
    excluded_tunnel_interfaces: &[u32],
    cleanup_journal_config_path: &Path,
) -> Result<DaemonWgUpstream> {
    match tokio::time::timeout(
        WINDOWS_NATIVE_RECONCILE_TIMEOUT,
        apply_daemon_wg_upstream_native(
            config,
            handshake_timeout,
            excluded_tunnel_interfaces,
            cleanup_journal_config_path,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "native Windows WireGuard reconcile timed out after {}s; owned-resource rollback was triggered",
            WINDOWS_NATIVE_RECONCILE_TIMEOUT.as_secs()
        )),
    }
}

#[cfg(target_os = "windows")]
async fn apply_daemon_wg_upstream_native(
    config: &WireGuardExitConfig,
    handshake_timeout: Duration,
    excluded_tunnel_interfaces: &[u32],
    cleanup_journal_config_path: &Path,
) -> Result<DaemonWgUpstream> {
    let manage_default_v6 = windows_wireguard_ipv6_default(config)?;
    let fingerprint = WireGuardExitFingerprint::from_config(config);
    let tunnel_name = windows_native_wireguard_tunnel_name(config);
    let blocking_config = config.clone();
    let blocking_tunnel_name = tunnel_name.clone();
    let blocking_journal_config_path = cleanup_journal_config_path.to_path_buf();
    // Synchronous bring-up child processes must not stall async workers or defeat the outer timeout.
    let (tools, mut tunnel) = tokio::task::spawn_blocking(
        move || -> Result<(WindowsWireGuardTools, WindowsNativeWireGuardTunnel)> {
            let tools = resolve_windows_wireguard_tools()?;
            let owner_token = windows_native_wireguard_owner_token();
            let config_path =
                windows_native_wireguard_config_path(&blocking_tunnel_name, &owner_token);
            retry_pending_windows_native_cleanup_journaled(&blocking_journal_config_path)
                .context("clean up pending native WireGuard before startup")?;
            let mut config_intent = WindowsNativeWireGuardCleanupState {
                name: blocking_tunnel_name.clone(),
                config_path: config_path.clone(),
                wireguard_exe: tools.wireguard_exe.clone(),
                owner_token: owner_token.clone(),
                service_owned: false,
                config_owned: true,
            };
            crate::daemon_runtime::persist_windows_native_wireguard_cleanup_intent(
                &blocking_journal_config_path,
                &config_intent,
            )
            .context("fsync native WireGuard config cleanup intent before creation")?;
            let owned_config = match write_windows_native_wireguard_config(
                &blocking_tunnel_name,
                &blocking_config,
                &owner_token,
            ) {
                Ok(config) => config,
                Err(error) => {
                    let cleanup = cleanup_windows_native_wireguard_state(&mut config_intent);
                    let persist =
                        crate::daemon_runtime::persist_windows_native_wireguard_cleanup_intent(
                            &blocking_journal_config_path,
                            &config_intent,
                        );
                    return Err(with_windows_native_cleanup_error(
                        with_windows_native_cleanup_error(
                            error,
                            "retry native WireGuard config cleanup after creation failure",
                            cleanup,
                        ),
                        "persist actual native WireGuard config ownership after creation failure",
                        persist,
                    ));
                }
            };

            let mut tunnel = WindowsNativeWireGuardTunnel {
                name: blocking_tunnel_name.clone(),
                config_path: owned_config.transfer(),
                wireguard_exe: tools.wireguard_exe.clone(),
                owner_token,
                service_owned: false,
                config_owned: true,
                cleanup_journal_config_path: blocking_journal_config_path.clone(),
            };

            if let Err(error) = ensure_windows_native_wireguard_service_absent(
                &tools.wireguard_exe,
                &blocking_tunnel_name,
            ) {
                let cleanup = tunnel.cleanup();
                return Err(with_windows_native_cleanup_error(
                    error,
                    "remove owned native WireGuard config after service-name collision",
                    cleanup,
                ));
            }
            // Write-ahead ownership is deliberately conservative: once the service
            // create is attempted, cleanup audits its exact description token and
            // removes it if present. A failed New-Service call can still have created
            // the service before PowerShell reported an error.
            tunnel.service_owned = true;
            if let Err(error) =
                crate::daemon_runtime::persist_windows_native_wireguard_cleanup_intent(
                    &blocking_journal_config_path,
                    &tunnel
                        .cleanup_state()
                        .expect("native WireGuard config/service intent is owned"),
                )
            {
                tunnel.service_owned = false;
                let cleanup = tunnel.cleanup();
                return Err(with_windows_native_cleanup_error(
                    error.context("fsync native WireGuard service cleanup intent before creation"),
                    "remove owned native WireGuard config after journal failure",
                    cleanup,
                ));
            }
            if let Err(error) = create_windows_native_wireguard_service(
                &tools.wireguard_exe,
                &tunnel.config_path,
                &blocking_tunnel_name,
                &tunnel.owner_token,
            )
            .with_context(|| {
                format!(
                    "create owned native WireGuardNT tunnel service from {}",
                    tunnel.config_path.display()
                )
            }) {
                let cleanup = tunnel.cleanup();
                return Err(with_windows_native_cleanup_error(
                    error,
                    "remove owned native WireGuard config",
                    cleanup,
                ));
            }
            if let Err(error) =
                configure_and_start_windows_native_wireguard_service(&blocking_tunnel_name)
            {
                return Err(with_windows_native_cleanup_error(
                    error.context("configure and start owned native WireGuardNT tunnel service"),
                    "remove owned native WireGuard service/config after startup failure",
                    tunnel.cleanup(),
                ));
            }
            Ok((tools, tunnel))
        },
    )
    .await
    .map_err(|error| anyhow!("native Windows WireGuard bring-up task failed: {error}"))??;
    // The WireGuard tunnel service receives the config path as its
    // startup argument, so keep the file around while the native
    // service is alive. `WindowsNativeWireGuardTunnel::cleanup` removes
    // it after uninstalling the service.

    let handshake_deadline = tokio::time::Instant::now() + handshake_timeout;
    if let Err(error) = begin_windows_native_wireguard_handshake(
        &tools.wg_exe,
        &tunnel_name,
        &config.peer_public_key,
        handshake_deadline,
    )
    .await
    {
        return Err(with_windows_native_cleanup_error(
            error.context("stimulate native WireGuardNT handshake"),
            "clean up native WireGuard after handshake stimulus failure",
            tunnel.cleanup(),
        ));
    }
    let handshake_completed = match wait_windows_native_wireguard_handshake(
        &tools.wg_exe,
        &tunnel_name,
        &config.peer_public_key,
        handshake_deadline,
    )
    .await
    {
        Ok(completed) => completed,
        Err(error) => {
            let error = match restore_windows_native_wireguard_keepalive(
                &tools.wg_exe,
                &tunnel_name,
                &config.peer_public_key,
                config.persistent_keepalive_secs,
            ) {
                Ok(()) => error,
                Err(restore_error) => anyhow!(
                    "{error:#}; configured keepalive restore also failed: {restore_error:#}"
                ),
            };
            return Err(with_windows_native_cleanup_error(
                error.context("query native WireGuardNT handshake"),
                "clean up native WireGuard after handshake query failure",
                tunnel.cleanup(),
            ));
        }
    };
    if let Err(error) = restore_windows_native_wireguard_keepalive(
        &tools.wg_exe,
        &tunnel_name,
        &config.peer_public_key,
        config.persistent_keepalive_secs,
    ) {
        return Err(with_windows_native_cleanup_error(
            error.context("restore configured native WireGuardNT keepalive"),
            "clean up native WireGuard after keepalive restore failure",
            tunnel.cleanup(),
        ));
    }
    if !handshake_completed {
        let error = anyhow!(
            "native WireGuardNT handshake to {} did not complete within {}s",
            config.endpoint,
            handshake_timeout.as_secs()
        );
        return Err(with_windows_native_cleanup_error(
            error,
            "clean up native WireGuard after handshake timeout",
            tunnel.cleanup(),
        ));
    }

    let mut upstream = match windows_native_wireguard_peer_endpoint(
        &tools.wg_exe,
        &tunnel_name,
        &config.peer_public_key,
    ) {
        Ok(upstream) => upstream,
        Err(error) => {
            return Err(with_windows_native_cleanup_error(
                error.context("read concrete native WireGuardNT peer endpoint"),
                "clean up native WireGuard after endpoint query failure",
                tunnel.cleanup(),
            ));
        }
    };
    let interface_index = match resolve_windows_interface_index_for_alias_name(&tunnel_name) {
        Ok(index) => index,
        Err(error) => {
            return Err(with_windows_native_cleanup_error(
                error.context("resolve native WireGuardNT interface"),
                "clean up native WireGuard after interface resolution failure",
                tunnel.cleanup(),
            ));
        }
    };
    let mut full_route = match apply_windows_endpoint_bypass_route(
        interface_index,
        upstream,
        excluded_tunnel_interfaces,
        manage_default_v6,
        cleanup_journal_config_path,
    ) {
        Ok(route) => route,
        Err(error) => {
            return Err(with_windows_native_cleanup_error(
                error.context("guard native WireGuard endpoint underlay route"),
                "clean up native WireGuard after route failure",
                tunnel.cleanup(),
            ));
        }
    };
    let verified_upstream = match windows_native_wireguard_peer_endpoint(
        &tools.wg_exe,
        &tunnel_name,
        &config.peer_public_key,
    ) {
        Ok(upstream) => upstream,
        Err(error) => {
            let route_cleanup = full_route.revert();
            let cleanup = tunnel.cleanup();
            return Err(with_windows_native_cleanup_error(
                with_windows_native_cleanup_error(
                    error.context("recheck concrete native WireGuardNT peer endpoint"),
                    "revert native WireGuard routes after endpoint recheck failure",
                    route_cleanup,
                ),
                "clean up native WireGuard after endpoint recheck failure",
                cleanup,
            ));
        }
    };
    if verified_upstream != upstream {
        if let Err(error) = full_route
            .reconcile_endpoint_and_underlay(verified_upstream, excluded_tunnel_interfaces)
        {
            let route_cleanup = full_route.revert();
            let cleanup = tunnel.cleanup();
            return Err(with_windows_native_cleanup_error(
                with_windows_native_cleanup_error(
                    error.context("migrate native WireGuard route to rechecked peer endpoint"),
                    "revert native WireGuard routes after endpoint migration failure",
                    route_cleanup,
                ),
                "clean up native WireGuard after endpoint migration failure",
                cleanup,
            ));
        }
        upstream = verified_upstream;
    }

    Ok(DaemonWgUpstream {
        iface: tunnel_name,
        upstream,
        interface_index,
        full_route: Some(full_route),
        tunnel,
        wg_exe: tools.wg_exe,
        peer_public_key: config.peer_public_key.clone(),
        config_fingerprint: fingerprint,
    })
}

#[cfg(target_os = "windows")]
struct WindowsWireGuardTools {
    wireguard_exe: PathBuf,
    wg_exe: PathBuf,
}

#[cfg(target_os = "windows")]
fn resolve_windows_wireguard_tools() -> Result<WindowsWireGuardTools> {
    let wireguard_exe = resolve_windows_wireguard_tool("wireguard.exe")?;
    let wg_exe = wireguard_exe
        .parent()
        .map(|dir| dir.join("wg.exe"))
        .filter(|path| path.is_file())
        .or_else(|| resolve_windows_wireguard_tool("wg.exe").ok())
        .ok_or_else(|| anyhow!("wg.exe not found next to {}", wireguard_exe.display()))?;
    Ok(WindowsWireGuardTools {
        wireguard_exe,
        wg_exe,
    })
}

#[cfg(target_os = "windows")]
fn resolve_windows_wireguard_tool(name: &str) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join(name));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(program_files).join("WireGuard").join(name));
    }
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        candidates.push(
            PathBuf::from(program_files_x86)
                .join("WireGuard")
                .join(name),
        );
    }
    candidates.push(PathBuf::from(r"C:\Program Files\WireGuard").join(name));

    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let output = ProcessCommand::new("where")
        .arg(name)
        .bounded_output(&format!("search PATH for {name}"))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(path) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    Err(anyhow!("{name} not found"))
}

#[cfg(any(test, target_os = "windows"))]
fn windows_native_wireguard_tunnel_name(config: &WireGuardExitConfig) -> String {
    let raw = if config.interface.trim().is_empty() {
        "nvpn-wg-upstream"
    } else {
        config.interface.trim()
    };
    let mut name = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            name.push(ch);
        } else {
            name.push('-');
        }
    }
    let name = name.trim_matches('-');
    let candidate = if name.is_empty() {
        "nvpn-wg-upstream"
    } else {
        name
    };
    if windows_wireguard_tunnel_name_is_valid(candidate) {
        candidate.to_string()
    } else {
        format!("nvpn-{:016x}", windows_wireguard_name_hash(raw.as_bytes()))
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_wireguard_tunnel_name_is_valid(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 32
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_=+.-".contains(&byte))
    {
        return false;
    }
    let basename = name.rsplit_once('.').map_or(name, |(basename, _)| basename);
    !matches!(
        basename.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(any(test, target_os = "windows"))]
fn windows_wireguard_name_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

#[cfg(target_os = "windows")]
fn ensure_windows_path_is_not_reparse_point(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect native WireGuard path {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(anyhow!(
            "refusing native WireGuard secret path containing reparse point {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn restrict_and_verify_windows_native_wireguard_acl(path: &Path, directory: bool) -> Result<()> {
    let security_type = if directory {
        "DirectorySecurity"
    } else {
        "FileSecurity"
    };
    let inheritance = if directory {
        "[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'"
    } else {
        "[System.Security.AccessControl.InheritanceFlags]::None"
    };
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $path = {}; \
         $allowed = @('S-1-5-18', 'S-1-5-32-544'); \
         $acl = New-Object System.Security.AccessControl.{security_type}; \
         $acl.SetAccessRuleProtection($true, $false); \
         foreach ($sidValue in $allowed) {{ \
           $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue); \
           $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(\
             $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, \
             {inheritance}, [System.Security.AccessControl.PropagationFlags]::None, \
             [System.Security.AccessControl.AccessControlType]::Allow); \
           $acl.AddAccessRule($rule) | Out-Null; \
         }}; \
         Set-Acl -LiteralPath $path -AclObject $acl; \
         $actual = Get-Acl -LiteralPath $path; \
         if (-not $actual.AreAccessRulesProtected) {{ throw 'ACL inheritance is enabled' }}; \
         $seen = @{{}}; \
         foreach ($rule in $actual.Access) {{ \
           $sid = $rule.IdentityReference.Translate(\
             [System.Security.Principal.SecurityIdentifier]).Value; \
           if ($allowed -notcontains $sid -or \
               $rule.AccessControlType -ne \
                 [System.Security.AccessControl.AccessControlType]::Allow -or \
               ($rule.FileSystemRights -band \
                 [System.Security.AccessControl.FileSystemRights]::FullControl) -ne \
                 [System.Security.AccessControl.FileSystemRights]::FullControl) {{ \
             throw \"unexpected ACL entry $sid $($rule.FileSystemRights)\"; \
           }}; \
           $seen[$sid] = $true; \
         }}; \
         foreach ($sid in $allowed) {{ \
           if (-not $seen.ContainsKey($sid)) {{ throw \"missing ACL entry $sid\" }} \
         }}",
        windows_powershell_literal(&path.display().to_string()),
    );
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .bounded_output(&format!(
            "restrict and audit Windows ACL for {}",
            path.display()
        ));
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!(
                "Windows ACL restriction/audit failed with {}: stdout={:?}, stderr={:?}",
                output.status,
                stdout.trim(),
                stderr.trim()
            ))
        }
        Err(error) => Err(error).context("run native WireGuard ACL restriction/audit"),
    }
}

#[cfg(target_os = "windows")]
async fn begin_windows_native_wireguard_handshake(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
    deadline: tokio::time::Instant,
) -> Result<()> {
    loop {
        match windows_native_wireguard_has_handshake(wg_exe, tunnel_name, peer_public_key) {
            Ok(_) => break,
            Err(error) if tokio::time::Instant::now() >= deadline => {
                return Err(error.context(format!(
                    "native WireGuard interface {tunnel_name} never became queryable"
                )));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    for keepalive in [0, 1] {
        set_windows_native_wireguard_peer_keepalive(
            wg_exe,
            tunnel_name,
            peer_public_key,
            keepalive,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn restore_windows_native_wireguard_keepalive(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
    configured_keepalive: u16,
) -> Result<()> {
    set_windows_native_wireguard_peer_keepalive(
        wg_exe,
        tunnel_name,
        peer_public_key,
        configured_keepalive,
    )
}

#[cfg(target_os = "windows")]
fn set_windows_native_wireguard_peer_keepalive(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
    keepalive: u16,
) -> Result<()> {
    let keepalive = keepalive.to_string();
    let output = ProcessCommand::new(wg_exe)
        .args([
            "set",
            tunnel_name,
            "peer",
            peer_public_key,
            "persistent-keepalive",
            &keepalive,
        ])
        .bounded_output(&format!(
            "set native WireGuard keepalive on {tunnel_name}"
        ))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "wg.exe keepalive update failed for {tunnel_name} with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "windows")]
async fn wait_windows_native_wireguard_handshake(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    loop {
        let query_error =
            match windows_native_wireguard_has_handshake(wg_exe, tunnel_name, peer_public_key) {
                Ok(true) => return Ok(true),
                Ok(false) => None,
                Err(error) => Some(error),
            };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            if let Some(error) = query_error {
                return Err(error.context(format!(
                    "native WireGuard interface {tunnel_name} never became queryable"
                )));
            }
            return Ok(false);
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(500))).await;
    }
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_has_handshake(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
) -> Result<bool> {
    let output = ProcessCommand::new(wg_exe)
        .args(["show", tunnel_name, "latest-handshakes"])
        .bounded_output(&format!(
            "query native WireGuard handshakes for {tunnel_name}"
        ))?;
    if !output.status.success() {
        return Err(anyhow!(
            "wg.exe show {tunnel_name} latest-handshakes failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_windows_wireguard_latest_handshakes(
        &String::from_utf8_lossy(&output.stdout),
        peer_public_key,
    )
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_wireguard_latest_handshakes(output: &str, peer_public_key: &str) -> Result<bool> {
    let entries = parse_windows_wireguard_peer_rows(output, "latest-handshakes")?;
    let (peer, timestamp) = entries
        .as_slice()
        .first()
        .copied()
        .ok_or_else(|| anyhow!("native WireGuard returned no peer handshake row"))?;
    if entries.len() != 1 || peer != peer_public_key.trim() {
        return Err(anyhow!(
            "native WireGuard handshake peer mismatch: expected exactly {}, got {:?}",
            peer_public_key.trim(),
            entries.iter().map(|(peer, _)| *peer).collect::<Vec<_>>()
        ));
    }
    Ok(timestamp
        .parse::<u64>()
        .context("parse native WireGuard handshake timestamp")?
        > 0)
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_peer_endpoint(
    wg_exe: &Path,
    tunnel_name: &str,
    peer_public_key: &str,
) -> Result<SocketAddr> {
    let output = ProcessCommand::new(wg_exe)
        .args(["show", tunnel_name, "endpoints"])
        .bounded_output(&format!(
            "query native WireGuard endpoint for {tunnel_name}"
        ))?;
    if !output.status.success() {
        return Err(anyhow!(
            "wg.exe show {tunnel_name} endpoints failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_windows_wireguard_peer_endpoint(&String::from_utf8_lossy(&output.stdout), peer_public_key)
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_wireguard_peer_endpoint(
    output: &str,
    peer_public_key: &str,
) -> Result<SocketAddr> {
    let entries = parse_windows_wireguard_peer_rows(output, "endpoints")?;
    let (peer, endpoint) = entries
        .as_slice()
        .first()
        .copied()
        .ok_or_else(|| anyhow!("native WireGuard returned no peer endpoint row"))?;
    if entries.len() != 1 || peer != peer_public_key.trim() {
        return Err(anyhow!(
            "native WireGuard endpoint peer mismatch: expected exactly {}, got {:?}",
            peer_public_key.trim(),
            entries.iter().map(|(peer, _)| *peer).collect::<Vec<_>>()
        ));
    }
    endpoint
        .parse::<SocketAddr>()
        .with_context(|| format!("parse concrete native WireGuard peer endpoint {endpoint:?}"))
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_wireguard_peer_rows<'a>(
    output: &'a str,
    field: &str,
) -> Result<Vec<(&'a str, &'a str)>> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut columns = line.split_whitespace();
            let peer = columns
                .next()
                .ok_or_else(|| anyhow!("missing peer key in WireGuard {field} row"))?;
            let value = columns
                .next()
                .ok_or_else(|| anyhow!("missing value in WireGuard {field} row for {peer}"))?;
            if columns.next().is_some() {
                return Err(anyhow!(
                    "unexpected columns in WireGuard {field} row for {peer}"
                ));
            }
            Ok((peer, value))
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn ensure_windows_native_wireguard_service_absent(
    wireguard_exe: &Path,
    tunnel_name: &str,
) -> Result<()> {
    let service_name = format!("WireGuardTunnel${tunnel_name}");
    let escaped_service_name = service_name.replace('\'', "''");
    let script = format!(
        "$service = Get-Service -Name '{escaped_service_name}' -ErrorAction SilentlyContinue; \
         if ($null -eq $service) {{ 'absent' }} else {{ 'present' }}"
    );
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .bounded_output(&format!("audit native WireGuard service {service_name}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to audit native WireGuard service {service_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    match String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "absent" => Ok(()),
        "present" => Err(anyhow!(
            "refusing to install native WireGuard with existing unowned service {service_name}"
        )),
        state => Err(anyhow!(
            "unexpected service ownership response {state:?} for {service_name} \
             while preparing {}",
            wireguard_exe.display()
        )),
    }
}

#[cfg(target_os = "windows")]
fn windows_powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_service_binary_path(
    wireguard_exe: &Path,
    config_path: &Path,
) -> String {
    format!(
        "\"{}\" /tunnelservice \"{}\"",
        wireguard_exe.display(),
        config_path.display()
    )
}

#[cfg(target_os = "windows")]
fn create_windows_native_wireguard_service(
    wireguard_exe: &Path,
    config_path: &Path,
    tunnel_name: &str,
    owner_token: &str,
) -> Result<()> {
    let service_name = format!("WireGuardTunnel${tunnel_name}");
    let binary_path = windows_native_wireguard_service_binary_path(wireguard_exe, config_path);
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         New-Service -Name {} -BinaryPathName {} -DisplayName {} -Description {} \
         -StartupType Automatic -DependsOn @('Nsi', 'TcpIp') | Out-Null",
        windows_powershell_literal(&service_name),
        windows_powershell_literal(&binary_path),
        windows_powershell_literal(&format!("WireGuard Tunnel: {tunnel_name}")),
        windows_powershell_literal(owner_token),
    );
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .bounded_output(&format!("create native WireGuard service {service_name}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "atomic service creation refused or failed for {service_name}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "windows")]
fn configure_and_start_windows_native_wireguard_service(tunnel_name: &str) -> Result<()> {
    let service_name = format!("WireGuardTunnel${tunnel_name}");
    let output = ProcessCommand::new("sc.exe")
        .args(["sidtype", &service_name, "unrestricted"])
        .bounded_output(&format!("set unrestricted SID type on {service_name}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "sc.exe sidtype failed for {service_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    // The tunnel service may already be running from a previous start.
    crate::service_management::windows_start_named_service(&service_name, true)
}
