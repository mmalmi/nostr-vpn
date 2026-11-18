//! Resolve user-owned storage through directory handles. A privileged service
//! must never follow a symlink exchanged between validation and a file operation.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, renameat, unlinkat};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) fn directory(path: &Path) -> Result<File> {
    let path = std::path::absolute(path)?;
    // System-owned aliases occur in Apple and Android app-container paths.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let aliases: &[&str] = &["/var", "/tmp", "/etc"];
    #[cfg(target_os = "android")]
    let aliases: &[&str] = &["/data/user/0"];
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    let aliases: &[&str] = &[];
    let mut path = path;
    for alias in aliases {
        if let Ok(tail) = path.strip_prefix(alias) {
            let metadata = fs::symlink_metadata(alias)?;
            if metadata.file_type().is_symlink() {
                ensure!(metadata.uid() == 0, "Untrusted system directory");
                let target = fs::read_link(alias)?;
                let target = if target.is_absolute() {
                    target
                } else {
                    Path::new(alias)
                        .parent()
                        .context("Invalid system alias")?
                        .join(target)
                };
                path = target.join(tail);
                break;
            }
        }
    }
    open_directory(&path)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open_directory(path: &Path) -> Result<File> {
    ensure!(
        !path.components().any(|part| part == Component::ParentDir),
        "Invalid file storage directory"
    );
    // Darwin checks every component during this one lookup, including ancestors.
    let no_symlinks = OFlags::from_bits_retain(libc::O_NOFOLLOW_ANY as u32);
    Ok(File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | no_symlinks,
        Mode::empty(),
    )?))
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn open_directory(path: &Path) -> Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let access = OFlags::PATH;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let access = OFlags::RDONLY;
    let mut current = File::from(rustix::fs::open(
        "/",
        access | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                current = File::from(openat(
                    &current,
                    name,
                    access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
            _ => anyhow::bail!("Invalid file storage directory"),
        }
    }
    Ok(File::from(openat(
        &current,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn parent(path: &Path) -> Result<(File, &OsStr)> {
    Ok((
        directory(path.parent().context("Missing file parent")?)?,
        path.file_name().context("Missing filename")?,
    ))
}

pub(super) fn set_owner(config: &Path, handle: &File, is_directory: bool) -> Result<()> {
    let owner = directory(config.parent().context("Config directory is missing")?)?.metadata()?;
    let metadata = handle.metadata()?;
    ensure!(
        metadata.is_dir() == is_directory && (is_directory || metadata.is_file()),
        "Unexpected storage type"
    );
    if metadata.uid() != owner.uid() || metadata.gid() != owner.gid() {
        rustix::fs::fchown(
            handle,
            Some(rustix::fs::Uid::from_raw(owner.uid())),
            Some(rustix::fs::Gid::from_raw(owner.gid())),
        )?;
    }
    handle.set_permissions(fs::Permissions::from_mode(if is_directory {
        0o700
    } else {
        0o600
    }))?;
    #[cfg(target_os = "macos")]
    crate::macos_file_io::clear_inherited_acl(handle)?;
    Ok(())
}

pub(super) fn owned_dir(config: &Path, path: &Path) -> Result<()> {
    let (parent, name) = parent(path)?;
    let created = match mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => return Err(error.into()),
    };
    let handle = File::from(openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if created {
        set_owner(config, &handle, true)?;
    } else {
        check_owner(config, &handle.metadata()?)?;
    }
    Ok(())
}

pub(super) fn open_owned(config: &Path, path: &Path) -> Result<File> {
    let (parent, name) = parent(path)?;
    let file = File::from(openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Expected a regular file");
    check_owner(config, &metadata)?;
    Ok(file)
}

/// The iOS app and its share extension publish commands from separate processes.
/// Probe the already-verified directory handle on idle ticks. A nonempty or
/// replaced queue goes through the normal protected path walk before processing.
#[cfg(any(target_os = "ios", all(test, target_os = "macos")))]
pub(super) struct IdleCommandQueue {
    path: PathBuf,
    handle: File,
    device: u64,
    inode: u64,
    owner: u32,
}

#[cfg(any(target_os = "ios", all(test, target_os = "macos")))]
impl IdleCommandQueue {
    pub(super) fn open(config: &Path) -> Result<Self> {
        let path = state_dir(config).join("commands");
        let handle = directory(&path)?;
        let metadata = handle.metadata()?;
        check_owner(config, &metadata)?;
        Ok(Self {
            path,
            handle,
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    pub(super) fn is_empty(&mut self, config: &Path) -> Result<bool> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        if (metadata.dev(), metadata.ino(), metadata.uid()) != (self.device, self.inode, self.owner)
            || metadata.mode() & 0o022 != 0
        {
            *self = Self::open(config)?;
        }
        for entry in rustix::fs::Dir::read_from(&self.handle)? {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(super) fn visit_names(
    config: &Path,
    path: &Path,
    mut visitor: impl FnMut(&OsStr),
) -> Result<()> {
    let handle = directory(path)?;
    check_owner(config, &handle.metadata()?)?;
    // Continue reading this exact directory if its pathname is replaced.
    for entry in rustix::fs::Dir::read_from(&handle)? {
        let entry = entry?;
        visitor(OsStr::from_bytes(entry.file_name().to_bytes()));
    }
    Ok(())
}

fn create_at(config: &Path, parent: &File, name: &OsStr) -> Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    set_owner(config, &file, false)?;
    Ok(file)
}

pub(super) fn create_owned(config: &Path, path: &Path) -> Result<File> {
    let (parent, name) = parent(path)?;
    create_at(config, &parent, name)
}

pub(super) fn write_atomic(config: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, name) = parent(target)?;
    let temporary = format!(".{}.tmp", uuid::Uuid::new_v4().simple());
    let result = (|| -> Result<()> {
        let mut output = create_at(config, &parent, OsStr::new(&temporary))?;
        output.write_all(bytes)?;
        output.sync_all()?;
        renameat(&parent, &temporary, &parent, name)?;
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(&parent, &temporary, AtFlags::empty());
    }
    result
}

pub(super) fn remove(path: &Path, is_directory: bool) -> Result<()> {
    let (parent, name) = parent(path)?;
    unlinkat(
        &parent,
        name,
        if is_directory {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        },
    )?;
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod ios_queue_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn idle_probe_follows_atomic_commands_and_directory_replacement() {
        let root = std::env::temp_dir().join(format!("nvpn-idle-queue-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let config = root.join("config.toml");
        let state = state_dir(&config);
        let queue = state.join("commands");
        owned_dir(&config, &state).unwrap();
        owned_dir(&config, &queue).unwrap();
        let mut probe = IdleCommandQueue::open(&config).unwrap();
        assert!(probe.is_empty(&config).unwrap());

        let command = queue.join("first.json");
        write_atomic(&config, &command, b"{}").unwrap();
        assert!(!probe.is_empty(&config).unwrap());
        fs::remove_file(&command).unwrap();
        assert!(probe.is_empty(&config).unwrap());

        let old = state.join("old-commands");
        fs::rename(&queue, &old).unwrap();
        assert!(probe.is_empty(&config).unwrap());
        owned_dir(&config, &queue).unwrap();
        write_atomic(&config, &command, b"{}").unwrap();
        assert!(!probe.is_empty(&config).unwrap());

        fs::remove_file(&command).unwrap();
        fs::set_permissions(&queue, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(probe.is_empty(&config).is_err());
        fs::remove_dir(&queue).unwrap();
        symlink(&old, &queue).unwrap();
        assert!(probe.is_empty(&config).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
