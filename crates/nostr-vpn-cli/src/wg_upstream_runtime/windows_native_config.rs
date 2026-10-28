#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsNativeWireGuardConfigLayout {
    Legacy,
    OwnerDirectory(std::path::PathBuf),
}

#[cfg(any(test, target_os = "windows"))]
fn classify_windows_native_wireguard_config_path(
    path: &std::path::Path,
    config_root: &std::path::Path,
    owner_token: &str,
) -> Result<WindowsNativeWireGuardConfigLayout> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("native WireGuard config path has no parent"))?;
    if parent == config_root {
        return Ok(WindowsNativeWireGuardConfigLayout::Legacy);
    }
    if parent.file_name().and_then(|name| name.to_str()) == Some(owner_token)
        && parent.parent() == Some(config_root)
    {
        return Ok(WindowsNativeWireGuardConfigLayout::OwnerDirectory(
            parent.to_path_buf(),
        ));
    }
    Err(anyhow!(
        "refusing malformed native WireGuard owner path {}",
        path.display()
    ))
}

#[cfg(any(test, target_os = "windows"))]
fn windows_native_wireguard_legacy_owner_marker_path(
    path: &std::path::Path,
) -> std::path::PathBuf {
    let mut marker = path.as_os_str().to_os_string();
    marker.push(":nvpn-owner");
    std::path::PathBuf::from(marker)
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_owner_token() -> String {
    static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nonce = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("nvpn-{now:032x}-{:08x}-{nonce:016x}", std::process::id())
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_owner_marker_path(path: &Path) -> PathBuf {
    let mut marker = path.as_os_str().to_os_string();
    marker.push(".nvpn-owner");
    PathBuf::from(marker)
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_config_root() -> PathBuf {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    program_data.join("nostr-vpn").join("wireguard")
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_config_path(tunnel_name: &str, owner_token: &str) -> PathBuf {
    windows_native_wireguard_config_root()
        .join(owner_token)
        .join(format!("{tunnel_name}.conf"))
}

#[cfg(target_os = "windows")]
fn write_windows_native_wireguard_owner_marker(
    owned: &mut OwnedWindowsNativeWireGuardConfig,
) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let marker_path = windows_native_wireguard_owner_marker_path(&owned.path);
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&marker_path)
        .with_context(|| {
            format!(
                "create native WireGuard owner marker {}",
                marker_path.display()
            )
        })?;
    owned.owner_marker_created = true;
    if marker
        .metadata()
        .with_context(|| {
            format!(
                "inspect native WireGuard owner marker {}",
                marker_path.display()
            )
        })?
        .file_attributes()
        & FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(anyhow!(
            "refusing native WireGuard owner marker through reparse point {}",
            marker_path.display()
        ));
    }
    restrict_and_verify_windows_native_wireguard_acl(&marker_path, false)
        .context("restrict and verify native WireGuard owner marker")?;
    ensure_windows_path_is_not_reparse_point(&marker_path)?;
    std::io::Write::write_all(&mut marker, owned.owner_token.as_bytes())
        .and_then(|()| std::io::Write::flush(&mut marker))
        .and_then(|()| marker.sync_all())
        .with_context(|| {
            format!(
                "write native WireGuard owner marker {}",
                marker_path.display()
            )
        })
}

#[cfg(target_os = "windows")]
fn write_windows_native_wireguard_config(
    tunnel_name: &str,
    config: &WireGuardExitConfig,
    owner_token: &str,
) -> Result<OwnedWindowsNativeWireGuardConfig> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let path = windows_native_wireguard_config_path(tunnel_name, owner_token);
    let owner_root = path
        .parent()
        .expect("native WireGuard config path has a parent")
        .to_path_buf();
    let root = owner_root
        .parent()
        .expect("native WireGuard owner directory has a config root")
        .to_path_buf();
    let app_root = root
        .parent()
        .expect("native WireGuard config root has an app root")
        .to_path_buf();
    let program_data = app_root
        .parent()
        .expect("native WireGuard app root has a ProgramData parent")
        .to_path_buf();
    std::fs::create_dir_all(&root)
        .with_context(|| format!("create native WireGuard config dir {}", root.display()))?;
    for component in [&program_data, &app_root, &root] {
        ensure_windows_path_is_not_reparse_point(component)?;
    }
    restrict_and_verify_windows_native_wireguard_acl(&root, true)
        .context("restrict and verify native WireGuard config directory")?;

    std::fs::create_dir(&owner_root).with_context(|| {
        format!(
            "create exclusively-owned native WireGuard directory {}",
            owner_root.display()
        )
    })?;
    let mut owned = OwnedWindowsNativeWireGuardConfig {
        path: path.clone(),
        owner_token: owner_token.to_string(),
        owner_directory_created: true,
        owner_marker_created: false,
        config_created: false,
        owned: true,
    };
    if let Err(error) = ensure_windows_path_is_not_reparse_point(&owner_root).and_then(|()| {
        restrict_and_verify_windows_native_wireguard_acl(&owner_root, true)
            .context("restrict and verify native WireGuard owner directory")
    }) {
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            error,
            "remove unsafe native WireGuard owner directory",
            cleanup,
        ));
    }
    if let Err(error) = write_windows_native_wireguard_owner_marker(&mut owned) {
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            error,
            "remove incomplete native WireGuard ownership marker",
            cleanup,
        ));
    }

    let config_text = windows_native_wireguard_config_text(config)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .with_context(|| {
            format!(
                "create exclusively-owned native WireGuard config {}",
                path.display()
            )
        })?;
    owned.config_created = true;
    let file_attributes = match file.metadata() {
        Ok(metadata) => metadata.file_attributes(),
        Err(error) => {
            drop(file);
            let cleanup = owned.cleanup();
            return Err(with_windows_native_cleanup_error(
                error.into(),
                "remove unauditable native WireGuard config",
                cleanup,
            ));
        }
    };
    if file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        drop(file);
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            anyhow!(
                "refusing to write native WireGuard secret through reparse point {}",
                path.display()
            ),
            "remove reparse-point native WireGuard config",
            cleanup,
        ));
    }
    if let Err(error) = restrict_and_verify_windows_native_wireguard_acl(&path, false) {
        drop(file);
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            error,
            "remove unrestricted native WireGuard config",
            cleanup,
        ));
    }
    if let Err(error) = ensure_windows_path_is_not_reparse_point(&path) {
        drop(file);
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            error,
            "remove reparse-point native WireGuard config",
            cleanup,
        ));
    }
    if let Err(error) = std::io::Write::write_all(&mut file, config_text.as_bytes())
        .and_then(|()| std::io::Write::flush(&mut file))
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write and sync native WireGuard config {}", path.display()))
    {
        drop(file);
        let cleanup = owned.cleanup();
        return Err(with_windows_native_cleanup_error(
            error,
            "remove partial native WireGuard config",
            cleanup,
        ));
    }
    Ok(owned)
}

#[cfg(any(test, target_os = "windows"))]
fn windows_native_wireguard_config_text(config: &WireGuardExitConfig) -> Result<String> {
    let config_text = nostr_vpn_core::config::wireguard_exit_config_text(config);
    let rest = config_text
        .strip_prefix("[Interface]\n")
        .ok_or_else(|| anyhow!("unexpected native WireGuard config: missing [Interface] header"))?;
    let (interface, peer) = rest
        .split_once("\n[Peer]\n")
        .ok_or_else(|| anyhow!("unexpected native WireGuard config: missing [Peer] section"))?;
    if peer.contains("\n[Peer]\n") {
        return Err(anyhow!(
            "unexpected native WireGuard config: multiple [Peer] sections"
        ));
    }
    let interface = interface
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_none_or(|(key, _)| !key.trim().eq_ignore_ascii_case("dns"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    // The Windows daemon owns route installation and durable cleanup. Without
    // this, WireGuardNT applies AllowedIPs=/0 (including its firewall policy)
    // and provider DNS as soon as the service starts, before the target
    // handshake is verified.
    Ok(format!(
        "[Interface]\nTable = off\n{interface}\n\n[Peer]\n{peer}"
    ))
}

#[cfg(target_os = "windows")]
struct OwnedWindowsNativeWireGuardConfig {
    path: PathBuf,
    owner_token: String,
    owner_directory_created: bool,
    owner_marker_created: bool,
    config_created: bool,
    owned: bool,
}

#[cfg(target_os = "windows")]
impl OwnedWindowsNativeWireGuardConfig {
    fn cleanup(&mut self) -> Result<()> {
        if !self.owned {
            return Ok(());
        }
        if self.config_created {
            match std::fs::remove_file(&self.path) {
                Ok(()) => self.config_created = false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.config_created = false;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("remove owned config {}", self.path.display()));
                }
            }
        }
        if self.owner_marker_created {
            let marker_path = windows_native_wireguard_owner_marker_path(&self.path);
            match std::fs::remove_file(&marker_path) {
                Ok(()) => self.owner_marker_created = false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.owner_marker_created = false;
                }
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
        if self.owner_directory_created {
            let owner_root = self
                .path
                .parent()
                .expect("native WireGuard config path has a parent");
            match std::fs::remove_dir(owner_root) {
                Ok(()) => self.owner_directory_created = false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.owner_directory_created = false;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "remove owned native WireGuard directory {}",
                            owner_root.display()
                        )
                    });
                }
            }
        }
        self.owned =
            self.config_created || self.owner_marker_created || self.owner_directory_created;
        if self.owned {
            Err(anyhow!(
                "native WireGuard config ownership cleanup remained incomplete"
            ))
        } else {
            Ok(())
        }
    }

    fn transfer(mut self) -> PathBuf {
        debug_assert!(self.owner_directory_created);
        debug_assert!(self.owner_marker_created);
        debug_assert!(self.config_created);
        self.owned = false;
        self.path.clone()
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedWindowsNativeWireGuardConfig {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            if self.owned {
                retain_pending_windows_native_cleanup(WindowsNativeWireGuardCleanupState {
                    name: String::new(),
                    config_path: self.path.clone(),
                    wireguard_exe: PathBuf::new(),
                    owner_token: self.owner_token.clone(),
                    service_owned: false,
                    config_owned: true,
                });
            }
            eprintln!(
                "wg-upstream: WARNING — partial native WireGuard config cleanup retained: \
                 {error:#}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn ensure_windows_native_wireguard_config_root_is_safe(config_root: &Path) -> Result<()> {
    let app_root = config_root
        .parent()
        .expect("native WireGuard config root has an app root");
    let program_data = app_root
        .parent()
        .expect("native WireGuard app root has a ProgramData parent");
    for component in [program_data, app_root, config_root] {
        let metadata = match std::fs::symlink_metadata(component) {
            Ok(metadata) => metadata,
            // Cleanup may revisit ownership after its directory was removed.
            // Existing ancestors are still checked before treating it as absent.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect native WireGuard directory {}", component.display())
                });
            }
        };
        ensure_windows_path_is_not_reparse_point(component)?;
        if !metadata.is_dir() {
            return Err(anyhow!(
                "native WireGuard root is not a directory: {}",
                component.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_config_layout(
    path: &Path,
    owner_token: &str,
) -> Result<WindowsNativeWireGuardConfigLayout> {
    let config_root = windows_native_wireguard_config_root();
    let layout =
        classify_windows_native_wireguard_config_path(path, &config_root, owner_token)?;
    ensure_windows_native_wireguard_config_root_is_safe(&config_root)?;
    Ok(layout)
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_owner_root(
    path: &Path,
    owner_token: &str,
) -> Result<Option<PathBuf>> {
    let WindowsNativeWireGuardConfigLayout::OwnerDirectory(owner_root) =
        windows_native_wireguard_config_layout(path, owner_token)?
    else {
        // Prior releases placed the config directly in the restricted root
        // and marked ownership with an NTFS alternate data stream.
        return Ok(None);
    };
    match std::fs::symlink_metadata(&owner_root) {
        Ok(_) => ensure_windows_path_is_not_reparse_point(&owner_root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect native WireGuard owner directory {}",
                    owner_root.display()
                )
            });
        }
    }
    Ok(Some(owner_root))
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_owner_marker_is_owned(path: &Path, owner_token: &str) -> Result<bool> {
    let layout = windows_native_wireguard_config_layout(path, owner_token)?;
    let marker_path = match layout {
        WindowsNativeWireGuardConfigLayout::Legacy => {
            match std::fs::symlink_metadata(path) {
                Ok(_) => ensure_windows_path_is_not_reparse_point(path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect legacy owned config {}", path.display()));
                }
            }
            windows_native_wireguard_legacy_owner_marker_path(path)
        }
        WindowsNativeWireGuardConfigLayout::OwnerDirectory(_) => {
            if windows_native_wireguard_owner_root(path, owner_token)?.is_none() {
                return Ok(false);
            }
            let marker_path = windows_native_wireguard_owner_marker_path(path);
            match std::fs::symlink_metadata(&marker_path) {
                Ok(_) => ensure_windows_path_is_not_reparse_point(&marker_path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect native WireGuard owner marker {}",
                            marker_path.display()
                        )
                    });
                }
            }
            marker_path
        }
    };
    let marker = match std::fs::read_to_string(&marker_path) {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "read native WireGuard owner marker {}",
                    marker_path.display()
                )
            });
        }
    };
    if marker == owner_token {
        Ok(true)
    } else {
        Err(anyhow!(
            "refusing mismatched native WireGuard owner marker {}",
            marker_path.display()
        ))
    }
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_config_is_owned(path: &Path, owner_token: &str) -> Result<bool> {
    if matches!(
        windows_native_wireguard_config_layout(path, owner_token)?,
        WindowsNativeWireGuardConfigLayout::OwnerDirectory(_)
    ) && windows_native_wireguard_owner_root(path, owner_token)?.is_none()
    {
        return Ok(false);
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect owned config {}", path.display()));
        }
    }
    ensure_windows_path_is_not_reparse_point(path)?;
    if windows_native_wireguard_owner_marker_is_owned(path, owner_token)? {
        Ok(true)
    } else {
        Err(anyhow!(
            "refusing to remove unmarked native WireGuard config {}",
            path.display()
        ))
    }
}

#[cfg(target_os = "windows")]
fn windows_native_wireguard_config_unmarked_in_owner_dir(
    path: &Path,
    owner_token: &str,
) -> Result<bool> {
    if !matches!(
        windows_native_wireguard_config_layout(path, owner_token)?,
        WindowsNativeWireGuardConfigLayout::OwnerDirectory(_)
    ) {
        return Ok(false);
    }
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(false);
    }
    Ok(!windows_native_wireguard_owner_marker_is_owned(path, owner_token)?)
}

#[cfg(target_os = "windows")]
fn pending_windows_native_cleanup()
-> &'static std::sync::Mutex<Vec<WindowsNativeWireGuardCleanupState>> {
    static PENDING: std::sync::OnceLock<std::sync::Mutex<Vec<WindowsNativeWireGuardCleanupState>>> =
        std::sync::OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

#[cfg(target_os = "windows")]
fn retain_pending_windows_native_cleanup(cleanup: WindowsNativeWireGuardCleanupState) {
    let mut pending = pending_windows_native_cleanup()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = pending
        .iter_mut()
        .find(|existing| existing.owner_token == cleanup.owner_token)
    {
        existing.service_owned |= cleanup.service_owned;
        existing.config_owned |= cleanup.config_owned;
    } else {
        pending.push(cleanup);
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn pending_windows_native_cleanup_snapshot() -> Vec<WindowsNativeWireGuardCleanupState> {
    pending_windows_native_cleanup()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(target_os = "windows")]
pub(crate) fn retry_pending_windows_native_cleanup_journaled(
    config_path: &Path,
) -> Result<()> {
    let pending = {
        let mut guard = pending_windows_native_cleanup()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    };
    let mut remaining = Vec::new();
    let mut failures = Vec::new();
    for mut cleanup in pending {
        let before = cleanup.clone();
        let cleanup_result = cleanup_windows_native_wireguard_state(&mut cleanup);
        let persist_result =
            crate::daemon_runtime::persist_windows_native_wireguard_cleanup_intent(
                config_path,
                &cleanup,
            );
        if let Err(error) = cleanup_result {
            failures.push(format!("{error:#}"));
            remaining.push(cleanup.clone());
        }
        if let Err(error) = persist_result {
            failures.push(format!(
                "persist pending native WireGuard cleanup result: {error:#}"
            ));
            if cleanup.is_empty() {
                remaining.push(before);
            } else if !remaining
                .iter()
                .any(|existing| existing.same_owner(&cleanup))
            {
                remaining.push(cleanup);
            }
        }
    }
    for cleanup in remaining {
        retain_pending_windows_native_cleanup(cleanup);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "pending native WireGuard cleanup incomplete: {}",
            failures.join("; ")
        ))
    }
}
