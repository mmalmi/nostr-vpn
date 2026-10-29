//! Regression tests for the durable service executable staging sequence.
//!
//! `install_service_executable_copy` is linux-only, but the staging file
//! operations it performs are portable, and the durability bug this fixes
//! surfaced on Windows: `File::sync_all` calls `FlushFileBuffers`, which
//! rejects handles opened without write access. These tests pin the corrected
//! sequence on every platform.

use std::fs;

// Reproduces install_service_executable_copy's staging sequence: the temp
// file is created with a writable handle, the staged bytes are synced through
// that handle, the file is renamed into place, and the parent directory entry
// is fsynced. Durability must ride the writing handle: on Windows,
// FlushFileBuffers rejects read-only handles, so syncing a handle opened for
// reading cannot persist anything.
#[test]
fn service_executable_staging_syncs_a_writable_handle_before_rename() {
    let dir = std::env::temp_dir().join(format!(
        "nvpn-service-staging-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create staging directory");
    let source = dir.join("nvpn-daemon-source");
    let destination = dir.join("nvpn-daemon-installed");
    let temp = destination.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&source, b"service executable bytes").expect("write source bytes");

    // The pre-fix code synced `fs::File::open(&temp)`, a read-only handle.
    // On Windows that handle cannot be flushed, so an installation there
    // would fail at the sync step.
    #[cfg(windows)]
    {
        let read_only = fs::File::open(&source).expect("open read-only handle");
        assert!(
            read_only.sync_all().is_err(),
            "Windows FlushFileBuffers must reject a read-only handle"
        );
    }

    let mut staged = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)
        .expect("create writable staging file");
    std::io::copy(
        &mut fs::File::open(&source).expect("open source"),
        &mut staged,
    )
    .expect("copy staged bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        staged
            .set_permissions(fs::Permissions::from_mode(0o755))
            .expect("chmod staged file");
    }
    staged.sync_all().expect("sync writable staging handle");
    drop(staged);
    fs::rename(&temp, &destination).expect("rename staged file into place");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&dir)
            .expect("open parent directory")
            .sync_all()
            .expect("fsync parent directory");
    }

    assert_eq!(
        fs::read(&destination).expect("read installed file"),
        b"service executable bytes"
    );
    assert!(!temp.exists(), "staging file is gone after the rename");
    fs::remove_dir_all(&dir).expect("clean up staging directory");
}
