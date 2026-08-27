use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub(crate) fn read_private_regular_to_string(path: &Path) -> io::Result<String> {
    let mut file = open_regular_nofollow(path)?;
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        secure_unix_file(&file, preferred_file_or_parent_owner(&file, parent)?)?;
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub(crate) fn write_atomic_private(path: &Path, content: &[u8]) -> io::Result<()> {
    write_atomic_private_inner(path, content, true).map(|_| ())
}

pub(crate) fn create_atomic_private(path: &Path, content: &[u8]) -> io::Result<bool> {
    write_atomic_private_inner(path, content, false)
}

pub(crate) fn open_private_lock_file(path: &Path, owner_source: &Path) -> io::Result<File> {
    #[cfg(not(unix))]
    let _ = owner_source;
    require_nofollow_platform()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    loop {
        match open_regular_nofollow_writable(path) {
            Ok(file) => {
                #[cfg(unix)]
                secure_unix_file(
                    &file,
                    preferred_open_file_owner(&file, owner_source, parent)?,
                )?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_atomic_private(path, b"")?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    open_regular_nofollow_with_access(path, false)
}

fn open_regular_nofollow_writable(path: &Path) -> io::Result<File> {
    open_regular_nofollow_with_access(path, true)
}

fn open_regular_nofollow_with_access(path: &Path, writable: bool) -> io::Result<File> {
    require_nofollow_platform()?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.write(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Validate the opened descriptor before using it without letting a
        // FIFO or device block the process during `open`.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    ensure_regular_nofollow(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn preferred_open_file_owner(
    file: &File,
    owner_source: &Path,
    parent: &Path,
) -> io::Result<Option<(u32, u32)>> {
    use std::os::unix::fs::MetadataExt as _;

    if let Some(owner) = non_root_owner(file)? {
        return Ok(Some(owner));
    }
    match open_regular_nofollow(owner_source) {
        Ok(owner_source) => {
            let metadata = owner_source.metadata()?;
            if metadata.uid() != 0 {
                return Ok(Some((metadata.uid(), metadata.gid())));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent_metadata = fs::metadata(parent)?;
    Ok((parent_metadata.uid() != 0).then_some((parent_metadata.uid(), parent_metadata.gid())))
}

#[cfg(unix)]
fn preferred_file_or_parent_owner(file: &File, parent: &Path) -> io::Result<Option<(u32, u32)>> {
    use std::os::unix::fs::MetadataExt as _;

    if let Some(owner) = non_root_owner(file)? {
        return Ok(Some(owner));
    }
    let metadata = fs::metadata(parent)?;
    Ok((metadata.uid() != 0).then_some((metadata.uid(), metadata.gid())))
}

#[cfg(unix)]
fn non_root_owner(file: &File) -> io::Result<Option<(u32, u32)>> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    Ok((metadata.uid() != 0).then_some((metadata.uid(), metadata.gid())))
}

fn ensure_regular_nofollow(file: &File, path: &Path) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private state {} is not a regular file", path.display()),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("private state {} is a reparse point", path.display()),
            ));
        }
    }
    Ok(())
}

fn write_atomic_private_inner(path: &Path, content: &[u8], replace: bool) -> io::Result<bool> {
    require_nofollow_platform()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    let owner = preferred_non_root_owner(path, parent)?;

    let mut temporary = tempfile::Builder::new()
        .prefix(".cashu-private-")
        .tempfile_in(parent)?;
    temporary.write_all(content)?;
    #[cfg(unix)]
    secure_unix_file(temporary.as_file(), owner)?;
    temporary.as_file().sync_all()?;

    let persisted = if replace {
        temporary.persist(path).map_err(|error| error.error)?;
        true
    } else {
        match temporary.persist_noclobber(path) {
            Ok(_) => true,
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.error),
        }
    };
    #[cfg(unix)]
    if persisted {
        File::open(parent)?.sync_all()?;
    }
    Ok(persisted)
}

#[cfg(any(unix, windows))]
fn require_nofollow_platform() -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn require_nofollow_platform() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private state requires no-follow filesystem support",
    ))
}

#[cfg(unix)]
fn preferred_non_root_owner(path: &Path, parent: &Path) -> io::Result<Option<(u32, u32)>> {
    use std::os::unix::fs::MetadataExt as _;

    let existing = match open_regular_nofollow(path) {
        Ok(file) => {
            let metadata = file.metadata()?;
            (metadata.uid() != 0).then_some((metadata.uid(), metadata.gid()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if existing.is_some() {
        return Ok(existing);
    }
    let metadata = fs::metadata(parent)?;
    Ok((metadata.uid() != 0).then_some((metadata.uid(), metadata.gid())))
}

#[cfg(unix)]
fn secure_unix_file(file: &File, owner: Option<(u32, u32)>) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if let Some((uid, gid)) = owner {
        let metadata = file.metadata()?;
        if (metadata.uid(), metadata.gid()) != (uid, gid) {
            std::os::unix::fs::fchown(file, Some(uid), Some(gid))?;
        }
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_write_replaces_complete_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_atomic_private(&path, b"first").unwrap();
        write_atomic_private(&path, b"second").unwrap();
        assert_eq!(read_private_regular_to_string(&path).unwrap(), "second");
    }

    #[test]
    fn private_read_rejects_directory() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_private_regular_to_string(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_read_and_write_reject_symlink_leaf() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let link = directory.path().join("state.json");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &link).unwrap();

        assert!(read_private_regular_to_string(&link).is_err());
        assert!(write_atomic_private(&link, b"changed").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn private_write_preserves_non_root_owner_and_mode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        fs::write(&path, b"old").unwrap();
        let before = fs::metadata(&path).unwrap();
        write_atomic_private(&path, b"new").unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_lock_is_regular_owner_only_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let owner_source = directory.path().join("state.json");
        let lock = directory.path().join("state.json.lock");
        let file = open_private_lock_file(&lock, &owner_source).unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(file);

        std::fs::remove_file(&lock).unwrap();
        let victim = directory.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &lock).unwrap();
        assert!(open_private_lock_file(&lock, &owner_source).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }
}
