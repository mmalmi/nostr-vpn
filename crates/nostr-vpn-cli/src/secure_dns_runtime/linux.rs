#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};

pub(super) const LINUX_DIRECT_RESOLV_CONF: &[u8] = b"# Managed by nvpn secure DNS\n\
nameserver 127.0.0.1\n\
options timeout:7 attempts:1\n";
#[cfg(unix)]
const LINUX_RESOLVED_PREFIX: &str = ".nvpn-resolv-";
#[cfg(unix)]
static LINUX_RESOLVED_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxResolvedResolvConfCleanupState {
    pub(super) previous_target: PathBuf,
    pub(super) stub_target: PathBuf,
    #[serde(default)]
    pub(super) ownership_token: String,
}

#[cfg(unix)]
pub(super) struct LinuxResolvedPaths {
    pub(super) marker: PathBuf,
    pub(super) backup: PathBuf,
    pub(super) candidate: PathBuf,
    pub(super) active: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum LinuxSecureDnsCleanupState {
    Resolved {
        interface: String,
        #[serde(default)]
        interface_index: Option<u32>,
        #[serde(default)]
        resolv_conf: Option<LinuxResolvedResolvConfCleanupState>,
    },
    DirectResolvConf {
        previous: Vec<u8>,
    },
}

#[cfg(target_os = "linux")]
pub(super) fn cleanup_intent(interface: &str) -> Result<LinuxSecureDnsCleanupState> {
    let direct = linux_direct_resolv_conf_allowed(
        Path::new("/.dockerenv").exists(),
        Path::new("/run/openrc").exists() || Path::new("/sbin/openrc").exists(),
    );
    if direct {
        return Ok(LinuxSecureDnsCleanupState::DirectResolvConf {
            previous: read_linux_resolv_conf(Path::new("/etc/resolv.conf"))?,
        });
    }
    Ok(LinuxSecureDnsCleanupState::Resolved {
        interface: interface.to_string(),
        interface_index: read_linux_interface_index(interface)?,
        resolv_conf: linux_resolved_resolv_conf_cleanup_intent(
            Path::new("/etc/resolv.conf"),
            Path::new("/run/systemd/resolve/resolv.conf"),
            Path::new("/run/systemd/resolve/stub-resolv.conf"),
        )?,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn install(state: &LinuxSecureDnsCleanupState) -> Result<()> {
    match state {
        LinuxSecureDnsCleanupState::Resolved {
            interface,
            resolv_conf,
            ..
        } => {
            run_checked(Command::new("resolvectl").args(["dns", interface, "127.0.0.1"]))?;
            run_checked(Command::new("resolvectl").args(["domain", interface, "~."]))?;
            if let Some(cleanup) = resolv_conf {
                install_linux_resolved_resolv_conf(Path::new("/etc/resolv.conf"), cleanup)?;
            }
            Ok(())
        }
        LinuxSecureDnsCleanupState::DirectResolvConf { .. } => {
            write_linux_resolv_conf(LINUX_DIRECT_RESOLV_CONF)
                .context("failed to install direct secure DNS resolver")
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn restore(state: &LinuxSecureDnsCleanupState) -> Result<()> {
    match state {
        LinuxSecureDnsCleanupState::Resolved {
            interface,
            interface_index,
            resolv_conf,
        } => restore_linux_resolved_components(
            || match resolv_conf {
                Some(cleanup) => {
                    restore_linux_resolved_resolv_conf(Path::new("/etc/resolv.conf"), cleanup)
                }
                None => Ok(()),
            },
            || {
                if !linux_resolved_link_is_owned(interface, *interface_index)? {
                    return Ok(());
                }
                run_checked(Command::new("resolvectl").args(["revert", interface]))
            },
        ),
        LinuxSecureDnsCleanupState::DirectResolvConf { previous } => {
            let current = read_linux_resolv_conf(Path::new("/etc/resolv.conf"))?;
            if linux_direct_resolv_conf_needs_restore(&current, previous) {
                write_linux_resolv_conf(previous)
                    .context("failed to restore and sync /etc/resolv.conf")
            } else {
                Ok(())
            }
        }
    }
}

pub(super) fn restore_linux_resolved_components(
    restore_resolv_conf: impl FnOnce() -> Result<()>,
    restore_link: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let resolv_conf = restore_resolv_conf();
    let link = restore_link();
    match (link, resolv_conf) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(link), Ok(())) => Err(link.context("failed to revert Linux per-link DNS")),
        (Ok(()), Err(resolv_conf)) => {
            Err(resolv_conf.context("failed to restore Linux /etc/resolv.conf"))
        }
        (Err(link), Err(resolv_conf)) => Err(anyhow!(
            "failed to revert Linux per-link DNS ({link:#}); \
             failed to restore Linux /etc/resolv.conf ({resolv_conf:#})"
        )),
    }
}

pub(super) fn linux_direct_resolv_conf_needs_restore(current: &[u8], previous: &[u8]) -> bool {
    current != previous
        && (current == LINUX_DIRECT_RESOLV_CONF
            || LINUX_DIRECT_RESOLV_CONF.starts_with(current)
            || previous.starts_with(current))
}

pub(super) fn linux_direct_resolv_conf_allowed(container: bool, openrc: bool) -> bool {
    container || openrc
}

#[cfg(target_os = "linux")]
fn write_linux_resolv_conf(contents: &[u8]) -> Result<()> {
    std::fs::write("/etc/resolv.conf", contents).context("write /etc/resolv.conf")?;
    std::fs::OpenOptions::new()
        .write(true)
        .open("/etc/resolv.conf")
        .and_then(|file| file.sync_all())
        .context("sync /etc/resolv.conf")
}

#[cfg(unix)]
pub(super) fn linux_resolved_resolv_conf_cleanup_intent(
    resolv_conf: &Path,
    uplink: &Path,
    stub: &Path,
) -> Result<Option<LinuxResolvedResolvConfCleanupState>> {
    let previous_target = std::fs::read_link(resolv_conf).with_context(|| {
        format!(
            "systemd-resolved secure DNS requires {} to be a symlink",
            resolv_conf.display()
        )
    })?;
    let parent = resolver_parent(resolv_conf)?;
    ensure_no_reserved_linux_resolver_paths(parent)?;
    if linux_resolver_target_is_reserved(parent, &previous_target) {
        return Err(anyhow!(
            "{} points at a reserved nVPN resolver path; refusing stale ownership",
            resolv_conf.display()
        ));
    }
    let current = canonical_linux_symlink_target(resolv_conf, &previous_target)?;
    let canonical_uplink = std::fs::canonicalize(uplink)
        .with_context(|| format!("resolve systemd-resolved uplink {}", uplink.display()))?;
    let canonical_stub = std::fs::canonicalize(stub)
        .with_context(|| format!("resolve systemd-resolved stub {}", stub.display()))?;
    if current == canonical_stub {
        return Ok(None);
    }
    if current != canonical_uplink {
        return Err(anyhow!(
            "unsupported systemd-resolved {} target {}; refusing secure DNS because libc/NSS \
             could bypass the nVPN stub",
            resolv_conf.display(),
            previous_target.display()
        ));
    }
    let ownership_token = new_linux_resolver_ownership_token();
    Ok(Some(LinuxResolvedResolvConfCleanupState {
        previous_target,
        stub_target: stub.to_path_buf(),
        ownership_token,
    }))
}

#[cfg(unix)]
fn canonical_linux_symlink_target(symlink_path: &Path, target: &Path) -> Result<PathBuf> {
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        resolver_parent(symlink_path)?.join(target)
    };
    std::fs::canonicalize(&target)
        .with_context(|| format!("resolve symlink target {}", target.display()))
}

#[cfg(unix)]
fn resolver_parent(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))
}

#[cfg(unix)]
fn new_linux_resolver_ownership_token() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = u128::from(LINUX_RESOLVED_TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed));
    let pid = u128::from(std::process::id());
    let token = timestamp ^ pid.rotate_left(43) ^ sequence.rotate_left(87);
    format!("{token:032x}")
}

#[cfg(unix)]
pub(super) fn linux_resolved_paths(
    resolv_conf: &Path,
    cleanup: &LinuxResolvedResolvConfCleanupState,
) -> Result<LinuxResolvedPaths> {
    // The daemon's single-instance lock makes these 128-bit token paths an
    // app-private namespace. System resolver writers own /etc/resolv.conf,
    // never these paths; deliberate root mutation is outside the threat model.
    let token = &cleanup.ownership_token;
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid Linux resolver ownership token"));
    }
    let parent = resolver_parent(resolv_conf)?;
    Ok(LinuxResolvedPaths {
        marker: parent.join(format!("{LINUX_RESOLVED_PREFIX}{token}.stub")),
        backup: parent.join(format!("{LINUX_RESOLVED_PREFIX}{token}.backup")),
        candidate: parent.join(format!("{LINUX_RESOLVED_PREFIX}{token}.candidate")),
        active: parent.join(format!("{LINUX_RESOLVED_PREFIX}{token}.active")),
    })
}

#[cfg(unix)]
fn ensure_no_reserved_linux_resolver_paths(parent: &Path) -> Result<()> {
    for entry in std::fs::read_dir(parent)
        .with_context(|| format!("inspect Linux resolver directory {}", parent.display()))?
    {
        let entry = entry.context("inspect Linux resolver ownership entry")?;
        if entry
            .file_name()
            .as_bytes()
            .starts_with(LINUX_RESOLVED_PREFIX.as_bytes())
        {
            return Err(anyhow!(
                "refusing stale Linux resolver ownership path {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn linux_resolver_target_is_reserved(parent: &Path, target: &Path) -> bool {
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        parent.join(target)
    };
    resolved.file_name().is_some_and(|name| {
        name.as_bytes()
            .starts_with(LINUX_RESOLVED_PREFIX.as_bytes())
    })
}

#[cfg(unix)]
fn ensure_linux_resolver_path_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(anyhow!(
            "refusing to replace existing Linux resolver ownership path {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect resolver ownership path {}", path.display())),
    }
}

#[cfg(unix)]
fn sync_linux_resolver_parent(path: &Path) -> Result<()> {
    let parent = resolver_parent(path)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync Linux resolver directory {}", parent.display()))
}

#[cfg(unix)]
fn create_linux_resolver_symlink(path: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, path).with_context(|| {
        format!(
            "create Linux resolver symlink {} -> {}",
            path.display(),
            target.display()
        )
    })?;
    sync_linux_resolver_parent(path)
}

#[cfg(unix)]
fn read_linux_symlink_if_present(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::read_link(path) {
        Ok(target) => Ok(Some(target)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Err(anyhow!(
            "resolver ownership path {} exists but is not a symlink",
            path.display()
        )),
        Err(error) => Err(error).with_context(|| format!("read symlink {}", path.display())),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PathIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn path_identity_if_present(path: &Path) -> Result<Option<PathIdentity>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect symlink {}", path.display()));
        }
    };
    Ok(Some(PathIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum LinuxResolverPathState {
    Missing,
    Symlink(PathBuf),
    Other,
}

#[cfg(unix)]
fn read_linux_resolver_path_state(path: &Path) -> Result<LinuxResolverPathState> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LinuxResolverPathState::Missing);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect resolver path {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        return std::fs::read_link(path)
            .map(LinuxResolverPathState::Symlink)
            .with_context(|| format!("read resolver symlink {}", path.display()));
    }
    Ok(LinuxResolverPathState::Other)
}

#[cfg(unix)]
fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("resolver path contains NUL: {}", path.display()))
}

#[cfg(target_os = "linux")]
fn rename_linux_resolver_path_noreplace(source: &Path, destination: &Path) -> Result<()> {
    let source_c = c_path(source)?;
    let destination_c = c_path(destination)?;
    // SAFETY: both C strings are NUL-terminated and live for the syscall.
    // Invoke the kernel entry point directly because libc does not expose
    // renameat2 on every supported Linux libc (notably musl).
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "atomically quarantine {} as {}",
                source.display(),
                destination.display()
            )
        });
    }
    sync_linux_resolver_parent(source)
}

#[cfg(all(test, target_os = "macos"))]
fn rename_linux_resolver_path_noreplace(source: &Path, destination: &Path) -> Result<()> {
    let source_c = c_path(source)?;
    let destination_c = c_path(destination)?;
    // SAFETY: both C strings are NUL-terminated and live for the syscall.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "atomically quarantine {} as {}",
                source.display(),
                destination.display()
            )
        });
    }
    sync_linux_resolver_parent(source)
}

#[cfg(all(test, unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename_linux_resolver_path_noreplace(_source: &Path, _destination: &Path) -> Result<()> {
    Err(anyhow!(
        "atomic resolver quarantine is unsupported on this test platform"
    ))
}

#[cfg(unix)]
fn remove_unique_linux_resolver_link(
    path: &Path,
    owned_target: Option<&Path>,
    owned_identity: Option<PathIdentity>,
) -> Result<()> {
    let current_identity = path_identity_if_present(path)?;
    match (owned_identity, current_identity) {
        (None, None) => return Ok(()),
        (None, Some(_)) => {
            return Err(anyhow!(
                "unique resolver path {} appeared after ownership sampling; preserving it",
                path.display()
            ));
        }
        (Some(_), None) => return Ok(()),
        (Some(expected), Some(current)) if expected != current => {
            return Err(anyhow!(
                "unique resolver ownership path {} changed; preserving it",
                path.display()
            ));
        }
        (Some(_), Some(_)) => {}
    }
    if let Some(target) = owned_target
        && read_linux_symlink_if_present(path)?.as_deref() != Some(target)
    {
        return Err(anyhow!(
            "unique resolver ownership target {} changed; preserving it",
            path.display()
        ));
    }
    std::fs::remove_file(path)
        .with_context(|| format!("remove unique resolver path {}", path.display()))?;
    sync_linux_resolver_parent(path)
}

#[cfg(unix)]
pub(super) fn install_linux_resolved_resolv_conf(
    resolv_conf: &Path,
    cleanup: &LinuxResolvedResolvConfCleanupState,
) -> Result<()> {
    install_linux_resolved_resolv_conf_with_hook(resolv_conf, cleanup, || Ok(()))
}

#[cfg(unix)]
pub(super) fn install_linux_resolved_resolv_conf_with_hook(
    resolv_conf: &Path,
    cleanup: &LinuxResolvedResolvConfCleanupState,
    after_backup_capture: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let paths = linux_resolved_paths(resolv_conf, cleanup)?;
    for path in [
        &paths.marker,
        &paths.backup,
        &paths.candidate,
        &paths.active,
    ] {
        ensure_linux_resolver_path_absent(path)?;
    }
    let marker_target = PathBuf::from(
        paths
            .marker
            .file_name()
            .ok_or_else(|| anyhow!("resolver marker has no file name"))?,
    );
    create_linux_resolver_symlink(&paths.marker, &cleanup.stub_target)?;
    create_linux_resolver_symlink(&paths.candidate, &marker_target)?;
    rename_linux_resolver_path_noreplace(resolv_conf, &paths.backup)
        .context("capture the prior resolver symlink")?;
    after_backup_capture()?;
    if read_linux_resolver_path_state(&paths.backup)?
        != LinuxResolverPathState::Symlink(cleanup.previous_target.clone())
    {
        if read_linux_resolver_path_state(resolv_conf)? == LinuxResolverPathState::Missing {
            rename_linux_resolver_path_noreplace(&paths.backup, resolv_conf)
                .context("restore concurrently changed resolver symlink")?;
        }
        return Err(anyhow!(
            "Linux resolver changed before nVPN installed secure DNS"
        ));
    }
    rename_linux_resolver_path_noreplace(&paths.candidate, resolv_conf)
        .context("activate the nVPN resolver symlink")?;
    if read_linux_symlink_if_present(resolv_conf)?.as_ref() != Some(&marker_target)
        || read_linux_symlink_if_present(&paths.marker)?.as_ref() != Some(&cleanup.stub_target)
        || read_linux_resolver_path_state(&paths.backup)?
            != LinuxResolverPathState::Symlink(cleanup.previous_target.clone())
        || read_linux_symlink_if_present(&paths.candidate)?.is_some()
    {
        return Err(anyhow!(
            "Linux resolver ownership changed while nVPN installed secure DNS"
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn restore_linux_resolved_resolv_conf(
    resolv_conf: &Path,
    cleanup: &LinuxResolvedResolvConfCleanupState,
) -> Result<()> {
    restore_linux_resolved_resolv_conf_with_hook(resolv_conf, cleanup, || Ok(()))
}

#[cfg(unix)]
pub(super) fn restore_linux_resolved_resolv_conf_with_hook(
    resolv_conf: &Path,
    cleanup: &LinuxResolvedResolvConfCleanupState,
    after_active_capture: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let parent = resolver_parent(resolv_conf)?;
    let paths = linux_resolved_paths(resolv_conf, cleanup)?;
    let marker_target = PathBuf::from(
        paths
            .marker
            .file_name()
            .ok_or_else(|| anyhow!("resolver marker has no file name"))?,
    );
    let mut current = read_linux_resolver_path_state(resolv_conf)?;
    let marker = read_linux_symlink_if_present(&paths.marker)?;
    let backup = read_linux_resolver_path_state(&paths.backup)?;
    let candidate = read_linux_symlink_if_present(&paths.candidate)?;
    let active = read_linux_symlink_if_present(&paths.active)?;

    if marker.is_none()
        && backup == LinuxResolverPathState::Missing
        && candidate.is_none()
        && active.is_none()
    {
        if current == LinuxResolverPathState::Missing {
            return Err(anyhow!(
                "main resolver is missing; retaining cleanup journal"
            ));
        }
        if matches!(
            &current,
            LinuxResolverPathState::Symlink(target)
                if linux_resolver_target_is_reserved(parent, target)
        ) {
            return Err(anyhow!(
                "main resolver still points at a reserved nVPN path"
            ));
        }
        return Ok(());
    }
    if marker.as_ref() != Some(&cleanup.stub_target)
        || candidate
            .as_ref()
            .is_some_and(|target| target != &marker_target)
        || active
            .as_ref()
            .is_some_and(|target| target != &marker_target)
    {
        return Err(anyhow!(
            "Linux resolver ownership artifacts changed; preserving resolver state"
        ));
    }
    let marker_identity = path_identity_if_present(&paths.marker)?;
    let backup_identity = path_identity_if_present(&paths.backup)?;
    let candidate_identity = path_identity_if_present(&paths.candidate)?;
    let mut active_identity = path_identity_if_present(&paths.active)?;

    if current == LinuxResolverPathState::Symlink(marker_target.clone()) {
        if backup == LinuxResolverPathState::Missing || active.is_some() {
            return Err(anyhow!(
                "Linux resolver ownership is incomplete; preserving resolver state"
            ));
        }
        let owned_main = path_identity_if_present(resolv_conf)?
            .ok_or_else(|| anyhow!("main resolver is missing"))?;
        rename_linux_resolver_path_noreplace(resolv_conf, &paths.active)
            .context("capture active nVPN resolver before restoration")?;
        active_identity = Some(owned_main);
        current = LinuxResolverPathState::Missing;
        after_active_capture()?;
        if read_linux_symlink_if_present(&paths.active)?.as_ref() != Some(&marker_target)
            || path_identity_if_present(&paths.active)? != active_identity
        {
            return Err(anyhow!(
                "active resolver ownership changed after capture; preserving state"
            ));
        }
    } else if matches!(
        &current,
        LinuxResolverPathState::Symlink(target)
            if linux_resolver_target_is_reserved(parent, target)
    ) {
        return Err(anyhow!(
            "main resolver points at an unexpected reserved nVPN path"
        ));
    }

    if backup != LinuxResolverPathState::Missing {
        current = read_linux_resolver_path_state(resolv_conf)?;
        if current == LinuxResolverPathState::Missing {
            rename_linux_resolver_path_noreplace(&paths.backup, resolv_conf)
                .context("restore captured resolver without replacing external state")?;
            current = backup;
        } else {
            remove_unique_linux_resolver_link(&paths.backup, None, backup_identity)
                .context("discard older captured resolver after external takeover")?;
        }
    }
    if current == LinuxResolverPathState::Missing
        && (candidate.is_some() || active.is_some() || marker.is_some())
    {
        return Err(anyhow!(
            "prior resolver backup is unavailable; preserving cleanup artifacts"
        ));
    }

    remove_unique_linux_resolver_link(&paths.candidate, Some(&marker_target), candidate_identity)?;
    remove_unique_linux_resolver_link(&paths.active, Some(&marker_target), active_identity)?;
    remove_unique_linux_resolver_link(&paths.marker, Some(&cleanup.stub_target), marker_identity)?;

    if read_linux_resolver_path_state(&paths.backup)? != LinuxResolverPathState::Missing
        || read_linux_symlink_if_present(&paths.candidate)?.is_some()
        || read_linux_symlink_if_present(&paths.active)?.is_some()
        || read_linux_symlink_if_present(&paths.marker)?.is_some()
        || matches!(
            read_linux_resolver_path_state(resolv_conf)?,
            LinuxResolverPathState::Symlink(target)
                if linux_resolver_target_is_reserved(parent, &target)
        )
    {
        return Err(anyhow!(
            "Linux resolver cleanup is incomplete; retaining cleanup journal"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_linux_interface_index(interface: &str) -> Result<Option<u32>> {
    let path = Path::new("/sys/class/net").join(interface).join("ifindex");
    match std::fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(raw.trim().parse().with_context(|| {
            format!("parse Linux interface index from {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("read Linux interface index from {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn linux_resolved_link_is_owned(interface: &str, expected_index: Option<u32>) -> Result<bool> {
    let interface_root = Path::new("/sys/class/net").join(interface);
    if !interface_root.exists() {
        return Ok(false);
    }
    if let Some(expected_index) = expected_index
        && read_linux_interface_index(interface)? != Some(expected_index)
    {
        return Ok(false);
    }
    if !interface_root.join("tun_flags").exists() {
        return Ok(false);
    }
    let output = Command::new("resolvectl")
        .args(["dns", interface])
        .output()
        .context("query Linux per-link DNS ownership")?;
    if !output.status.success() {
        if !interface_root.exists() {
            return Ok(false);
        }
        return Err(anyhow!(
            "failed to query DNS for Linux link {interface}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split_ascii_whitespace()
        .any(|token| token == "127.0.0.1"))
}

#[cfg(target_os = "linux")]
pub(crate) fn repair_linux_secure_dns_cleanup_state(
    state: &mut Option<LinuxSecureDnsCleanupState>,
) -> Result<()> {
    let Some(restore_state) = state.as_ref() else {
        return Ok(());
    };
    restore(restore_state)?;
    state.take();
    flush_caches();
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn read_linux_resolv_conf(path: &Path) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn flush_caches() {
    let _ = Command::new("resolvectl").arg("flush-caches").status();
}

#[cfg(target_os = "linux")]
fn run_checked(command: &mut Command) -> Result<()> {
    let output = command
        .output()
        .context("failed to execute DNS configuration command")?;
    if output.status.success() {
        return Ok(());
    }
    let details = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout)
    } else {
        String::from_utf8_lossy(&output.stderr)
    };
    Err(anyhow!(
        "DNS configuration command failed: {}",
        details.trim()
    ))
}
