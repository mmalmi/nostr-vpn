//! Root-owned launchd artifacts and daemon status. Never clone source metadata.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use nostr_vpn_core::macos_file_io::{clear_inherited_acl, reject_write_acl};

pub(crate) fn helper_destination(path: &Path) -> Option<PathBuf> {
    let helpers = Path::new("/Library/PrivilegedHelperTools");
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    // Replace a leaf symlink in the actual helper directory, never its target.
    if absolute.starts_with(helpers) {
        return Some(absolute);
    }
    let resolved = fs::canonicalize(&absolute)
        .or_else(|_| {
            let parent = fs::canonicalize(absolute.parent().unwrap_or(Path::new("/")))?;
            Ok::<_, io::Error>(parent.join(absolute.file_name().unwrap_or_default()))
        })
        .ok()?;
    if resolved.starts_with(helpers) {
        return Some(resolved);
    }
    // APFS firmlinks (including the Data volume path) are directory aliases
    // that canonicalize() does not necessarily translate to /Library.
    let helper_metadata = fs::metadata(helpers).ok()?;
    let aliases_helpers = resolved.parent()?.ancestors().any(|parent| {
        fs::metadata(parent).is_ok_and(|metadata| {
            metadata.dev() == helper_metadata.dev() && metadata.ino() == helper_metadata.ino()
        })
    });
    aliases_helpers.then_some(resolved)
}

pub(crate) fn validate_artifact(path: &Path) -> Result<()> {
    open_artifact(path).map(|_| ())
}

fn open_artifact(path: &Path) -> Result<File> {
    protected_directory(
        path.parent().context("system artifact has no parent")?,
        false,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!("unsafe system artifact; reinstall the service with administrator privileges");
    }
    reject_write_acl(&file)?;
    Ok(file)
}

/// Status is public to local readers, but only root may publish it. Unlike
/// installation and cleanup records, these frequent snapshots need no fsync.
pub(crate) fn write_runtime_state(path: &Path, contents: &[u8]) -> Result<()> {
    require_root()?;
    protected_directory(path.parent().context("runtime state has no parent")?, true)?;
    nostr_vpn_core::macos_file_io::write_atomic(path, contents, 0o644, Some((0, 0)), false)?;
    Ok(())
}

pub(crate) fn read_runtime_state(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match open_artifact(path) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(Some(contents))
}

pub(crate) fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("installing or updating a system helper requires administrator privileges");
    }
    Ok(())
}

/// Validate from the filesystem root down. Once each ancestor is protected,
/// an unprivileged process cannot exchange the next component between checks.
pub(crate) fn protected_directory(path: &Path, create: bool) -> Result<File> {
    if !path.is_absolute() {
        bail!("system artifact directory must be absolute");
    }
    let mut current = PathBuf::new();
    let mut directory = None;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => bail!("system artifact directory must not contain parent traversal"),
        }
        let open = || {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(&current)
        };
        let file = match open() {
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o755).create(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error).context("create system artifact directory"),
                }
                open()?
            }
            result => result.with_context(|| format!("open protected {}", current.display()))?,
        };
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "system artifact directory is not root-owned and protected: {}",
                current.display()
            );
        }
        reject_write_acl(&file)?;
        directory = Some(file);
    }
    directory.context("missing system artifact directory")
}

pub(crate) fn install_executable(source: &Path, destination: &Path) -> Result<()> {
    require_root()?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .context("open service executable")?;
    if !source.metadata()?.is_file() {
        bail!("service executable must be a regular file");
    }
    // Also recopy when source == destination: old installs may have unsafe
    // ownership, ACLs, or open writable descriptors held by their former owner.
    publish(&mut source, destination, 0o755)
}

pub(crate) fn publish(contents: &mut impl Read, destination: &Path, mode: u32) -> Result<()> {
    require_root()?;
    let parent = destination
        .parent()
        .context("system artifact has no parent")?;
    let directory = protected_directory(parent, true)?;
    let name = destination
        .file_name()
        .context("system artifact has no filename")?;
    let mut temporary = None;
    for _ in 0..128 {
        let candidate = parent.join(format!(
            ".{}.{}",
            name.to_string_lossy(),
            rand::random::<u128>()
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create system artifact staging file"),
        }
    }
    let (temporary, mut file) = temporary.context("allocate system artifact staging file")?;
    let result = (|| -> Result<()> {
        // Copy bytes into our newly created inode; fs::copy on macOS can clone
        // the installing user's ownership and ACLs from the app bundle.
        clear_inherited_acl(&file)?;
        io::copy(contents, &mut file)?;
        std::os::unix::fs::fchown(&file, Some(0), Some(0))?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        reject_write_acl(&file)?;
        file.sync_all()?;
        // Replaces an old inode or symlink without opening/chmod'ing its target.
        fs::rename(&temporary, destination)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("publish protected system artifact")
}

/// A user may edit configuration, but must not forge the daemon's status or
/// record of routes/DNS it owns. Keep those under protected system ancestors.
pub(crate) fn runtime_directory(config_path: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let config_path = nostr_vpn_core::macos_file_io::absolute_path(config_path)?;
    let identity = format!("{:x}", Sha256::digest(config_path.as_os_str().as_bytes()));
    Ok(Path::new("/Library/Application Support/nvpn/runtime").join(identity))
}

pub(crate) fn network_cleanup_path(config_path: &Path) -> Result<PathBuf> {
    require_root()?;
    let config_path = nostr_vpn_core::macos_file_io::absolute_path(config_path)?;
    let path = runtime_directory(&config_path)?.join("daemon.cleanup.json");
    migrate_private_state(&config_path.with_file_name("daemon.cleanup.json"), &path)?;
    Ok(path)
}

pub(crate) fn migrate_private_state(legacy: &Path, destination: &Path) -> Result<()> {
    require_root()?;
    let parent = destination
        .parent()
        .context("private state has no parent")?;
    protected_directory(parent, true)?;
    let marker = destination.with_extension("migrated");
    match fs::symlink_metadata(&marker) {
        Ok(_) => return validate_artifact(&marker),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => validate_artifact(destination)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let source = nostr_vpn_core::macos_file_io::OpenOptions::new()
                .read(true)
                .open(legacy);
            match source {
                Ok(mut file) => {
                    let metadata = file.metadata()?;
                    // Older releases wrote 0644 journals. Read permission is
                    // compatible; non-root write permission is not. The new
                    // copy is always private regardless of the legacy mode.
                    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                        bail!(
                            "untrusted legacy network cleanup record; refusing automatic migration"
                        );
                    }
                    reject_write_acl(&file)?;
                    let mut raw = Vec::new();
                    file.by_ref()
                        .take(4 * 1024 * 1024 + 1)
                        .read_to_end(&mut raw)?;
                    if raw.len() > 4 * 1024 * 1024 {
                        bail!("legacy network cleanup record is too large");
                    }
                    publish(&mut raw.as_slice(), destination, 0o600)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("open legacy network cleanup record"),
            }
        }
        Err(error) => return Err(error.into()),
    }
    // Commit the marker after the new record, before unlinking the old one.
    // It prevents replay after a successful cleanup removes the new record.
    publish(&mut &b"1\n"[..], &marker, 0o600)?;
    match nostr_vpn_core::macos_file_io::remove_file(legacy) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove migrated network cleanup record"),
    }
}
