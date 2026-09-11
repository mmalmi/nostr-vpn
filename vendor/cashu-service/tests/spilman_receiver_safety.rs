#![cfg(feature = "spilman-configurable-host")]

use std::sync::{Arc, Barrier};

use cashu_service::{load_or_create_cashu_spilman_receiver_key, spilman_receiver_key_path};

#[test]
fn simultaneous_receiver_startup_preserves_one_persisted_identity() {
    let directory = tempfile::tempdir().unwrap();
    let start = Arc::new(Barrier::new(16));
    let keys = std::thread::scope(|scope| {
        let workers = (0..16)
            .map(|_| {
                let start = Arc::clone(&start);
                let directory = directory.path();
                scope.spawn(move || {
                    start.wait();
                    load_or_create_cashu_spilman_receiver_key(directory)
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    let persisted = load_or_create_cashu_spilman_receiver_key(directory.path()).unwrap();
    for key in keys {
        assert_eq!(
            key, persisted,
            "a receiver started with an unsaved identity"
        );
    }
}

#[cfg(unix)]
#[test]
fn receiver_key_reopens_with_private_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let original = load_or_create_cashu_spilman_receiver_key(directory.path()).unwrap();
    let path = spilman_receiver_key_path(directory.path());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let reopened = load_or_create_cashu_spilman_receiver_key(directory.path()).unwrap();

    assert_eq!(reopened, original);
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn receiver_key_rejects_symlinks_without_touching_the_target() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    load_or_create_cashu_spilman_receiver_key(target_directory.path()).unwrap();
    let target = spilman_receiver_key_path(target_directory.path());
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::read(&target).unwrap();
    symlink(&target, spilman_receiver_key_path(directory.path())).unwrap();

    assert!(load_or_create_cashu_spilman_receiver_key(directory.path()).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), before);
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
