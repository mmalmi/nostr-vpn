//! File I/O for the macOS daemon and its user-owned configuration directory.
//! Walk with directory descriptors, never through user-replaceable symlinks.
//! Validate opened inodes before truncating, chmod'ing, reading or writing.

use anyhow::{Context, Result, bail};
use std::ffi::{CString, OsStr};
pub use std::fs::*;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

fn name(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::Error::other("NUL in file path"))
}

fn opened(fd: i32) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub struct Directory(File);

impl Directory {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        let path = absolute_path(path)?;
        let mut directory = Self(File::open("/")?);
        for component in path.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            let component = name(component)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mut next =
                opened(unsafe { libc::openat(directory.0.as_raw_fd(), component.as_ptr(), flags) });
            if create
                && next
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                let created =
                    unsafe { libc::mkdirat(directory.0.as_raw_fd(), component.as_ptr(), 0o755) }
                        == 0;
                if !created && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
                next = opened(unsafe {
                    libc::openat(directory.0.as_raw_fd(), component.as_ptr(), flags)
                });
                if created && unsafe { libc::geteuid() } == 0 {
                    let parent = directory.0.metadata()?;
                    if parent.uid() != 0 {
                        std::os::unix::fs::fchown(
                            next.as_ref().map_err(|e| io::Error::other(e.to_string()))?,
                            Some(parent.uid()),
                            Some(parent.gid()),
                        )?;
                    }
                }
            }
            directory = Self(next?);
        }
        Ok(directory)
    }

    fn parent(path: &Path) -> io::Result<(Self, CString)> {
        let path = absolute_path(path)?;
        let filename = path
            .file_name()
            .ok_or_else(|| io::Error::other("missing filename"))?;
        Ok((Self::open(path.parent().unwrap(), false)?, name(filename)?))
    }

    fn open_file(&self, filename: &CString, flags: i32, mode: u32) -> io::Result<File> {
        let file = opened(unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                filename.as_ptr(),
                (flags & !libc::O_TRUNC) | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        })?;
        let metadata = file.metadata()?;
        if flags & libc::O_DIRECTORY == 0 && (!metadata.is_file() || metadata.nlink() != 1) {
            return Err(io::Error::other("expected a regular file with one link"));
        }
        if flags & libc::O_TRUNC != 0 {
            file.set_len(0)?;
        }
        Ok(file)
    }

    pub fn set_owner_and_permissions(&self, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        let current = self.0.metadata()?;
        if current.uid() == 0 && uid != 0 {
            std::os::unix::fs::fchown(&self.0, Some(uid), Some(gid))?;
        }
        use std::os::unix::fs::PermissionsExt;
        self.0.set_permissions(Permissions::from_mode(mode))
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.0.sync_all()
    }

    pub fn write_atomic(
        &self,
        filename: &OsStr,
        contents: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
        durable: bool,
    ) -> io::Result<()> {
        if Path::new(filename).components().count() != 1
            || !matches!(
                Path::new(filename).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(io::Error::other("atomic write requires a filename"));
        }
        let filename = name(filename)?;
        let mut temporary = None;
        for attempt in 0..128 {
            let candidate = CString::new(format!(
                ".nvpn-{}-{}-{attempt}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
            .unwrap();
            match self.open_file(
                &candidate,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let (temporary, mut file) =
            temporary.ok_or_else(|| io::Error::other("allocate atomic staging file"))?;
        let result = (|| {
            clear_inherited_acl(&file)?;
            file.write_all(contents)?;
            if let Some((uid, gid)) = owner {
                let current = file.metadata()?;
                if current.uid() != uid || current.gid() != gid {
                    match std::os::unix::fs::fchown(&file, Some(uid), Some(gid)) {
                        Err(error)
                            if error.kind() == io::ErrorKind::PermissionDenied
                                && unsafe { libc::geteuid() } != 0 => {}
                        result => result?,
                    }
                }
            }
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(mode))?;
            if durable {
                file.sync_all()?;
            }
            if unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    temporary.as_ptr(),
                    self.0.as_raw_fd(),
                    filename.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if durable {
                self.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            unsafe { libc::unlinkat(self.0.as_raw_fd(), temporary.as_ptr(), 0) };
        }
        result
    }
}

pub fn write_atomic(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    durable: bool,
) -> io::Result<()> {
    let (parent, _) = Directory::parent(path)?;
    parent.write_atomic(
        path.file_name()
            .ok_or_else(|| io::Error::other("missing filename"))?,
        contents,
        mode,
        owner,
        durable,
    )
}

/// Lexical absolute identity; do not resolve user-controlled symlinks first.
pub fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::other(
            "parent traversal is not allowed in daemon file paths",
        ));
    }
    let root_file = File::open("/")?;
    // /var, /tmp and /etc are OS-owned aliases on macOS. Only translate
    // their known system targets, after checking their protected parent.
    let path = if let Some((alias, target)) = [
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/tmp"), Path::new("/private/tmp")),
        (Path::new("/etc"), Path::new("/private/etc")),
    ]
    .into_iter()
    .find(|(alias, _)| path.starts_with(alias))
    {
        let root = root_file.metadata()?;
        if root.uid() != 0 || root.mode() & 0o022 != 0 {
            return Err(io::Error::other("unprotected filesystem root"));
        }
        reject_write_acl(&root_file).map_err(io::Error::other)?;
        let link = std::fs::read_link(alias)?;
        if Path::new("/").join(link) != target {
            return Err(io::Error::other("unexpected macOS system directory alias"));
        }
        target.join(path.strip_prefix(alias).unwrap())
    } else {
        path
    };
    Ok(path.components().collect())
}

#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: Option<u32>,
    flags: i32,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(&mut self, yes: bool) -> &mut Self {
        self.read = yes;
        self
    }
    pub fn write(&mut self, yes: bool) -> &mut Self {
        self.write = yes;
        self
    }
    pub fn append(&mut self, yes: bool) -> &mut Self {
        self.append = yes;
        self
    }
    pub fn truncate(&mut self, yes: bool) -> &mut Self {
        self.truncate = yes;
        self
    }
    pub fn create(&mut self, yes: bool) -> &mut Self {
        self.create = yes;
        self
    }
    pub fn create_new(&mut self, yes: bool) -> &mut Self {
        self.create_new = yes;
        self
    }
    pub fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        let write = self.write || self.append;
        let access = match (self.read, write) {
            (true, true) => libc::O_RDWR,
            (true, false) => libc::O_RDONLY,
            (false, true) => libc::O_WRONLY,
            _ => return Err(io::Error::other("file access mode is required")),
        };
        if !write && (self.truncate || self.create || self.create_new) {
            return Err(io::Error::other(
                "creation and truncation require write access",
            ));
        }
        let mut flags = access | (self.flags & !libc::O_ACCMODE);
        if self.append {
            flags |= libc::O_APPEND;
        }
        if self.create || self.create_new {
            flags |= libc::O_CREAT;
        }
        if self.create_new {
            flags |= libc::O_EXCL;
        }
        if self.truncate {
            flags |= libc::O_TRUNC;
        }
        let (parent, filename) = Directory::parent(path.as_ref())?;
        parent.open_file(&filename, flags, self.mode.unwrap_or(0o666))
    }
}

impl OpenOptionsExt for OpenOptions {
    fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = Some(mode);
        self
    }
    fn custom_flags(&mut self, flags: i32) -> &mut Self {
        self.flags = flags;
        self
    }
}

pub fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    Directory::open(path.as_ref(), true).map(|_| ())
}
pub fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(path)?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}
pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    String::from_utf8(read(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?
        .write_all(contents.as_ref())
}
pub fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    let (parent, filename) = Directory::parent(path.as_ref())?;
    if unsafe { libc::unlinkat(parent.0.as_raw_fd(), filename.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    let (from_parent, from) = Directory::parent(from.as_ref())?;
    let (to_parent, to) = Directory::parent(to.as_ref())?;
    if unsafe {
        libc::renameat(
            from_parent.0.as_raw_fd(),
            from.as_ptr(),
            to_parent.0.as_raw_fd(),
            to.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
pub fn set_permissions(path: impl AsRef<Path>, permissions: Permissions) -> io::Result<()> {
    let (parent, filename) = Directory::parent(path.as_ref())?;
    let file = opened(unsafe {
        libc::openat(
            parent.0.as_raw_fd(),
            filename.as_ptr(),
            libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() && (!metadata.is_file() || metadata.nlink() != 1) {
        return Err(io::Error::other(
            "expected a directory or regular file with one link",
        ));
    }
    file.set_permissions(permissions)
}

// chmod does not remove inherited ACL grants. Clear them on a newly allocated
// inode before writing secret bytes, so its requested mode is authoritative.
pub fn clear_inherited_acl(file: &File) -> io::Result<()> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_init(count: i32) -> *mut c_void;
        fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: u32) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    let empty = unsafe { acl_init(0) };
    if empty.is_null() {
        return Err(io::Error::last_os_error());
    }
    let status = unsafe { acl_set_fd_np(file.as_raw_fd(), empty, 0x100) };
    let error = io::Error::last_os_error();
    unsafe { acl_free(empty) };
    if status == 0 { Ok(()) } else { Err(error) }
}
// Darwin ACLs can grant writes even when Unix mode bits appear protected.
// Deny and read-only entries are fine; reject every write grant, including
// inherited grants. This deliberately fails closed for unusual system ACLs.
pub fn reject_write_acl(file: &File) -> Result<()> {
    reject_write_acl_impl(file, false)
}

/// Stock macOS ships root-owned system directories (`/Library`,
/// `/Library/Application Support`) that are group-writable by the built-in
/// `admin` group and inherit a matching ACL grant. Admin-group write is
/// sudo-equivalent on macOS, so it grants nothing to unprivileged users;
/// this variant rejects write grants from every other principal.
pub fn reject_untrusted_ancestor_write_acl(file: &File) -> Result<()> {
    reject_write_acl_impl(file, true)
}

fn reject_write_acl_impl(file: &File, allow_builtin_admin_group: bool) -> Result<()> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: u32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, which: i32, entry: *mut *mut c_void) -> i32;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut u32) -> i32;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    const ACL_TYPE_EXTENDED: u32 = 0x100;
    const ACL_EXTENDED_ALLOW: u32 = 1;
    const WRITE_PERMISSIONS: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // On a valid descriptor Darwin's FILESEC_ACL lookup returns ENOENT
        // when the inode has no extended ACL (acl_file.c / filesec.c).
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error).context("read system artifact ACL");
    }
    let result = (|| -> Result<()> {
        let mut which = 0; // ACL_FIRST_ENTRY
        loop {
            let mut entry = std::ptr::null_mut();
            if unsafe { acl_get_entry(acl, which, &mut entry) } != 0 {
                // Darwin uses EINVAL to indicate the end of this valid ACL.
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                return Err(io::Error::last_os_error()).context("read ACL entry");
            }
            which = -1; // ACL_NEXT_ENTRY
            let mut tag = 0;
            let mut permissions = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
            {
                return Err(io::Error::last_os_error()).context("read ACL permissions");
            }
            if tag == ACL_EXTENDED_ALLOW
                && permissions & WRITE_PERMISSIONS != 0
                && !(allow_builtin_admin_group && qualifier_is_builtin_admin_or_wheel(entry))
            {
                bail!("system artifact path has a write-granting ACL");
            }
        }
        Ok(())
    })();
    unsafe { acl_free(acl) };
    result
}

// Apple synthesizes GUIDs for POSIX groups from the fixed prefix
// ABCDEFAB-CDEF-ABCD-EFAB-CDEF followed by the big-endian GID, so the built-in
// `wheel` (0) and `admin` (80) groups are stable without DirectoryService
// calls. The kernel enforces membership by GUID, so a spoofed qualifier grants
// nothing. Fail closed when the qualifier is missing or unreadable.
fn qualifier_is_builtin_admin_or_wheel(entry: *mut std::ffi::c_void) -> bool {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    const GROUP_GUID_PREFIX: [u8; 12] = [
        0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF,
    ];
    let mut qualifier = [0u8; 16];
    // SAFETY: `entry` came from acl_get_entry on a live ACL and outlives this
    // call; acl_get_qualifier returns a 16-byte guid_t (uuid_t) for extended
    // entries and NULL when the entry carries no qualifier.
    let raw = unsafe { acl_get_qualifier(entry) };
    if raw.is_null() {
        return false;
    }
    qualifier.copy_from_slice(unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), 16) });
    unsafe { acl_free(raw) };
    qualifier[..12] == GROUP_GUID_PREFIX
        && matches!(
            u32::from_be_bytes([qualifier[12], qualifier[13], qualifier[14], qualifier[15]]),
            0 | 80
        )
}
