const MAX_SHARED_ROSTER_FUTURE_SECS: u64 = 600;

fn next_shared_roster_updated_at(previous: u64) -> u64 {
    current_unix_timestamp().max(previous.saturating_add(1))
}

/// Atomically writes a private file while retaining an existing non-root owner.
pub fn write_private_file_preserving_user_owner(
    path: &Path,
    raw: &[u8],
) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[cfg(unix)]
    let existing_owner = fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    #[cfg(unix)]
    let parent_owner = {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::metadata(parent)
            .ok()
            .map(|metadata| (metadata.uid(), metadata.gid()))
    };
    #[cfg(unix)]
    let desired_owner = preferred_private_file_owner(existing_owner, parent_owner);
    #[cfg(not(unix))]
    let desired_owner = None;
    write_private_file_with_owner(path, raw, desired_owner)
}

pub(crate) fn write_private_file_with_owner(
    path: &Path,
    raw: &[u8],
    desired_owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(not(unix))]
    let _ = desired_owner;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut temp_path = None;
    let mut temp_file = None;
    for attempt in 0..128u32 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate) {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate unique config temp file",
        )
    })?;
    let mut file = temp_file.expect("temp file set with temp path");
    if let Err(error) = file.write_all(raw) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    #[cfg(unix)]
    {
        let secure = (|| {
            if let Some((uid, gid)) = desired_owner {
                let metadata = file.metadata()?;
                if metadata.uid() != uid || metadata.gid() != gid {
                    match std::os::unix::fs::fchown(&file, Some(uid), Some(gid)) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))
        })();
        if let Err(error) = secure {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    }
    if let Err(error) = file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    drop(file);
    if let Err(error) = replace_private_file(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_private_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(windows)]
fn replace_private_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    const RETRY_DELAYS_MS: [u64; 7] = [10, 20, 40, 80, 160, 320, 640];

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut retry = 0;
    loop {
        // SAFETY: both arguments are valid, NUL-terminated UTF-16 paths for this call.
        let moved = unsafe {
            MoveFileExW(
                temporary.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved != 0 {
            return Ok(());
        }

        let error = std::io::Error::last_os_error();
        let retriable = matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ACCESS_DENIED as i32
                    || code == ERROR_SHARING_VIOLATION as i32
                    || code == ERROR_LOCK_VIOLATION as i32
        );
        if !retriable || retry == RETRY_DELAYS_MS.len() {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(RETRY_DELAYS_MS[retry]));
        retry += 1;
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::time::Duration;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    #[test]
    fn private_file_replace_retries_a_transient_share_lock() {
        let directory = std::env::temp_dir().join(format!(
            "nvpn-config-replace-retry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let destination = directory.join("config.toml");
        let temporary = directory.join("config.toml.tmp");
        std::fs::write(&destination, b"old").expect("write destination");
        std::fs::write(&temporary, b"new").expect("write replacement");

        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&destination)
            .expect("hold destination without delete sharing");
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            drop(held);
        });

        super::replace_private_file(&temporary, &destination)
            .expect("replace after transient share lock clears");
        release.join().expect("release destination lock");
        assert_eq!(
            std::fs::read(&destination).expect("read replaced destination"),
            b"new"
        );
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}

#[cfg(unix)]
pub(crate) fn preferred_private_file_owner(
    existing_owner: Option<(u32, u32)>,
    parent_owner: Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    match (existing_owner, parent_owner) {
        (Some((0, _)), Some((parent_uid, parent_gid))) if parent_uid != 0 => {
            Some((parent_uid, parent_gid))
        }
        (Some(owner), _) => Some(owner),
        (None, Some((parent_uid, parent_gid))) if parent_uid != 0 => Some((parent_uid, parent_gid)),
        (None, _) => None,
    }
}
