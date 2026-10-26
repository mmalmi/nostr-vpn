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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let access = OFlags::PATH;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let access = OFlags::from_bits_retain(libc::O_SEARCH as u32);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
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
