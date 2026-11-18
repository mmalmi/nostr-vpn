use std::io;
use std::path::Path;
#[cfg(not(target_vendor = "apple"))]
use std::time::Duration;

pub(super) struct JoinRosterWatch {
    #[cfg(target_vendor = "apple")]
    changes: apple::DirectoryChanges,
}

impl JoinRosterWatch {
    // Apple creates a fallible kernel watcher; keep one constructor contract
    // for callers on platforms whose polling watcher needs no setup.
    #[cfg_attr(not(target_vendor = "apple"), allow(clippy::unnecessary_wraps))]
    pub(super) fn new(config_path: &Path) -> io::Result<Self> {
        #[cfg(not(target_vendor = "apple"))]
        let _ = config_path;
        Ok(Self {
            #[cfg(target_vendor = "apple")]
            changes: apple::DirectoryChanges::new(
                nostr_vpn_core::join_delivery::join_roster_outbox_directory(config_path),
            )?,
        })
    }

    pub(super) async fn changed(&mut self) -> io::Result<()> {
        #[cfg(target_vendor = "apple")]
        self.changes.changed().await?;
        #[cfg(not(target_vendor = "apple"))]
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok(())
    }
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::fs::{DirBuilder, File, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::PathBuf;
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    pub(super) struct DirectoryChanges {
        path: PathBuf,
        directory: Option<File>,
        notifications: AsyncFd<OwnedFd>,
    }

    impl DirectoryChanges {
        pub(super) fn new(path: PathBuf) -> io::Result<Self> {
            // SAFETY: kqueue returns a new descriptor owned by this watcher.
            let descriptor = unsafe { libc::kqueue() };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the successful descriptor has no other owner.
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            // SAFETY: the descriptor remains open throughout this call.
            if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: The owned kqueue descriptor stays open and unchanged
            // for the lifetime of this AsyncFd.
            let notifications =
                unsafe { AsyncFd::register_with_interest(descriptor, Interest::READABLE)? };
            let mut watcher = Self {
                path,
                directory: None,
                notifications,
            };
            watcher.arm()?;
            Ok(watcher)
        }

        fn arm(&mut self) -> io::Result<()> {
            // Closing the old vnode also removes any queued events for it.
            // Reopen after a notification so replacing the directory cannot
            // leave us watching its unlinked predecessor. Register before the
            // caller scans: concurrent atomic publishes stay queued for us.
            self.directory = None;
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.path)?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_EVTONLY | libc::O_CLOEXEC)
                .open(&self.path)?;
            let change = libc::kevent {
                ident: libc::uintptr_t::try_from(directory.as_raw_fd())
                    .expect("an open file has a nonnegative descriptor"),
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE
                    | libc::NOTE_DELETE
                    | libc::NOTE_RENAME
                    | libc::NOTE_REVOKE,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: the queue and directory are live descriptors; change
            // points to one initialized event and no output array is requested.
            if unsafe {
                libc::kevent(
                    self.notifications.get_ref().as_raw_fd(),
                    &raw const change,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            self.directory = Some(directory);
            Ok(())
        }

        pub(super) async fn changed(&mut self) -> io::Result<()> {
            loop {
                let mut ready = self.notifications.readable().await?;
                let result = ready.try_io(|queue| {
                    // SAFETY: zero is a valid initial representation for these
                    // C structs. kevent writes at most the one provided event.
                    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                    let timeout = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    let count = unsafe {
                        libc::kevent(
                            queue.get_ref().as_raw_fd(),
                            std::ptr::null(),
                            0,
                            &raw mut event,
                            1,
                            &raw const timeout,
                        )
                    };
                    match count {
                        -1 => Err(io::Error::last_os_error()),
                        0 => Err(io::ErrorKind::WouldBlock.into()),
                        _ if event.flags & libc::EV_ERROR != 0 => {
                            let error = i32::try_from(event.data).map_err(io::Error::other)?;
                            Err(io::Error::from_raw_os_error(error))
                        }
                        _ => Ok(()),
                    }
                });
                match result {
                    Ok(Ok(())) => break,
                    Ok(Err(error)) if error.kind() != io::ErrorKind::Interrupted => {
                        return Err(error);
                    }
                    _ => {}
                }
            }
            self.arm()
        }
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use nostr_vpn_core::join_delivery::join_roster_outbox_directory;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn join_roster_watch_sleeps_until_atomic_publish_and_survives_replacement() {
        let root = std::env::temp_dir().join(format!(
            "nvpn-join-watch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let config = root.join("config.toml");
        let outbox = join_roster_outbox_directory(&config);
        let mut watch = JoinRosterWatch::new(&config).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), watch.changed())
                .await
                .is_err(),
            "an unchanged outbox must not wake the tunnel"
        );

        // Delivery uses a private temporary file followed by an atomic rename.
        let temporary = root.join("pending.tmp");
        fs::write(&temporary, b"approval").unwrap();
        fs::rename(&temporary, outbox.join("approval.json")).unwrap();
        tokio::time::timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(outbox.join("approval.json")).unwrap(), b"approval");
        assert!(
            tokio::time::timeout(Duration::from_millis(400), watch.changed())
                .await
                .is_err()
        );

        fs::rename(&outbox, root.join("old-outbox")).unwrap();
        fs::create_dir(&outbox).unwrap();
        fs::write(outbox.join("replacement.json"), b"new approval").unwrap();
        tokio::time::timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read(outbox.join("replacement.json")).unwrap(),
            b"new approval"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(400), watch.changed())
                .await
                .is_err()
        );

        fs::write(&temporary, b"after replacement").unwrap();
        fs::rename(&temporary, outbox.join("later.json")).unwrap();
        tokio::time::timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
        drop(watch);
        fs::remove_dir_all(root).unwrap();
    }
}
