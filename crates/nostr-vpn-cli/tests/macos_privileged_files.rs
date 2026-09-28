//! Filesystem regression tests: never touch an installed helper or launchd.
#![cfg(target_os = "macos")]

extern crate self as nostr_vpn_core;
#[path = "../../nostr-vpn-core/src/macos_file_io.rs"]
pub mod macos_file_io;

#[path = "../src/macos_privileged_files.rs"]
mod macos_privileged_files;

use macos_privileged_files::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown, symlink};
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn user() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nvpn-files-fixture-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn root() -> Self {
        require_root().expect("run this fixture as root explicitly");
        // Publicly traversable ancestors let the dropped-privilege check prove
        // protection of the artifact and its immediate parent, not root's home.
        let path = Path::new("/private/var").join(format!(
            "nvpn-helper-fixture-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn assert_protected(path: &Path, mode: u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!((metadata.uid(), metadata.gid()), (0, 0));
    assert_eq!(metadata.mode() & 0o7777, mode);
    assert_eq!(metadata.nlink(), 1);
    validate_artifact(path).unwrap();
}

#[test]
fn non_root_install_is_rejected_without_writes() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let path =
        std::env::temp_dir().join(format!("nvpn-no-install-{:032x}", rand::random::<u128>()));
    assert!(install_executable(Path::new("/usr/bin/true"), &path).is_err());
    assert!(publish(&mut &b"plist"[..], &path, 0o644).is_err());
    assert!(!path.exists());
    assert!(network_cleanup_path(&path).is_err());
    assert!(write_runtime_state(&path, b"forged status").is_err());
    assert!(!path.exists());
}

#[test]
fn runtime_state_rejects_unprotected_storage() {
    let fixture = Fixture::user();
    let path = fixture.path("daemon.state.json");
    fs::write(&path, b"forged state").unwrap();
    assert!(read_runtime_state(&path).is_err());
    assert!(read_runtime_state(&fixture.path("missing.pid")).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"forged state");
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_runtime_state_is_readable_but_cannot_be_forged_by_users() {
    let fixture = Fixture::root();
    let directory = fixture.path("runtime");
    for name in ["daemon.pid", "daemon.state.json"] {
        let path = directory.join(name);
        assert!(read_runtime_state(&path).unwrap().is_none());
        write_runtime_state(&path, b"first").unwrap();
        assert_protected(&path, 0o644);
        let mut previous = File::open(&path).unwrap();
        write_runtime_state(&path, b"second").unwrap();
        let mut old = String::new();
        previous.read_to_string(&mut old).unwrap();
        assert_eq!(old, "first");
        assert_eq!(read_runtime_state(&path).unwrap().unwrap(), b"second");

        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Only async-signal-safe syscalls after fork in this threaded runner.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(65534) != 0
                    || libc::setuid(65534) != 0
                {
                    libc::_exit(2);
                }
                if libc::open(path_c.as_ptr(), libc::O_RDONLY) < 0 {
                    libc::_exit(3);
                }
                if libc::open(path_c.as_ptr(), libc::O_WRONLY) >= 0
                    || libc::unlink(path_c.as_ptr()) == 0
                {
                    libc::_exit(4);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(
            status, 0,
            "users may read, but must not write or unlink status"
        );

        chown(&path, Some(65534), None).unwrap();
        assert!(read_runtime_state(&path).is_err());
        write_runtime_state(&path, b"repaired").unwrap();
        assert_protected(&path, 0o644);
        fs::remove_file(&path).unwrap();
        let victim = fixture.path("victim");
        fs::write(&victim, b"preserved").unwrap();
        symlink(&victim, &path).unwrap();
        assert!(read_runtime_state(&path).is_err());
        write_runtime_state(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"preserved");
        assert_protected(&path, 0o644);
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(read_runtime_state(&directory.join("daemon.pid")).is_err());
    assert!(write_runtime_state(&directory.join("daemon.pid"), b"unsafe").is_err());
}

#[test]
fn runtime_file_access_rejects_links_and_special_files_before_mutation() {
    let fixture = Fixture::user();
    let victim = fixture.path("victim");
    let path = fixture.path("runtime");
    fs::write(&victim, b"preserved").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o640)).unwrap();
    for hard in [false, true] {
        if hard {
            fs::hard_link(&victim, &path).unwrap();
        } else {
            symlink(&victim, &path).unwrap();
        }
        assert!(macos_file_io::read(&path).is_err());
        assert!(macos_file_io::write(&path, b"overwrite").is_err());
        assert!(macos_file_io::set_permissions(&path, fs::Permissions::from_mode(0o777)).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"preserved");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o640);
        // Atomic output replaces the entry without modifying the linked inode.
        macos_file_io::write_atomic(&path, b"replacement", 0o600, None, true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::read(&victim).unwrap(), b"preserved");
        fs::remove_file(&path).unwrap();
    }
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(macos_file_io::read(&path).is_err());
    assert!(macos_file_io::write(&path, b"overwrite").is_err());
}

#[test]
fn runtime_directory_swaps_cannot_redirect_operations() {
    let fixture = Fixture::user();
    let directory = fixture.path("settings");
    let moved = fixture.path("moved");
    let victim = fixture.path("victim");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(&victim).unwrap();
    fs::write(victim.join("state"), b"preserved").unwrap();
    let held = macos_file_io::Directory::open(&directory, false).unwrap();
    fs::rename(&directory, &moved).unwrap();
    symlink(&victim, &directory).unwrap();
    held.write_atomic(std::ffi::OsStr::new("state"), b"new", 0o600, None, true)
        .unwrap();
    assert_eq!(fs::read(moved.join("state")).unwrap(), b"new");
    assert_eq!(fs::read(victim.join("state")).unwrap(), b"preserved");
    let linked = directory.join("state");
    assert!(macos_file_io::read(&linked).is_err());
    assert!(macos_file_io::write(&linked, b"overwrite").is_err());
    assert!(macos_file_io::write_atomic(&linked, b"overwrite", 0o600, None, true).is_err());
    assert!(macos_file_io::remove_file(&linked).is_err());
    assert!(macos_file_io::rename(&linked, fixture.path("stolen")).is_err());
    assert!(macos_file_io::set_permissions(&linked, fs::Permissions::from_mode(0o777)).is_err());
    assert!(macos_file_io::create_dir_all(directory.join("child")).is_err());
    assert_eq!(fs::read(victim.join("state")).unwrap(), b"preserved");
    assert!(!victim.join("child").exists());
    assert!(macos_file_io::absolute_path(&fixture.path("../victim")).is_err());
    assert_eq!(
        macos_file_io::absolute_path(Path::new("/var/run")).unwrap(),
        Path::new("/private/var/run")
    );
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_config_ownership_and_private_journal_migration() {
    runtime_directory_swaps_cannot_redirect_operations();
    runtime_file_access_rejects_links_and_special_files_before_mutation();
    let fixture = Fixture::root();
    let settings = fixture.path("settings");
    fs::create_dir(&settings).unwrap();
    chown(&settings, Some(65534), Some(65534)).unwrap();
    let nested = settings.join("nested");
    macos_file_io::create_dir_all(&nested).unwrap();
    assert_eq!(fs::metadata(&nested).unwrap().uid(), 65534);
    let config = nested.join("config.toml");
    macos_file_io::write_atomic(&config, b"settings", 0o600, Some((65534, 65534)), true).unwrap();
    assert_eq!(fs::metadata(&config).unwrap().uid(), 65534);
    assert_eq!(fs::metadata(&config).unwrap().mode() & 0o777, 0o600);

    let legacy = settings.join("daemon.cleanup.json");
    let destination = fixture.path("protected/daemon.cleanup.json");
    fs::write(&legacy, b"forged").unwrap();
    chown(&legacy, Some(65534), Some(65534)).unwrap();
    assert!(migrate_private_state(&legacy, &destination).is_err());
    assert!(!destination.exists());
    fs::remove_file(&legacy).unwrap();
    fs::write(&legacy, b"root recovery record").unwrap();
    // A legacy file can inherit the user's group; private mode is what matters.
    chown(&legacy, Some(0), Some(65534)).unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    migrate_private_state(&legacy, &destination).unwrap();
    assert_protected(&destination, 0o600);
    assert_eq!(fs::read(&destination).unwrap(), b"root recovery record");
    assert!(!legacy.exists());
    fs::remove_file(&destination).unwrap();
    fs::write(&legacy, b"replayed record").unwrap();
    migrate_private_state(&legacy, &destination).unwrap();
    assert!(
        !destination.exists(),
        "completed migration must never replay user-directory state"
    );

    let empty_source = settings.join("no-previous-journal");
    let empty_destination = fixture.path("fresh/state.json");
    migrate_private_state(&empty_source, &empty_destination).unwrap();
    assert!(!empty_destination.exists());
    fs::write(&empty_source, b"late injection").unwrap();
    migrate_private_state(&empty_source, &empty_destination).unwrap();
    assert!(!empty_destination.exists());

    // Recover a crash after copying the journal but before publishing the
    // migration marker. Never replace the already committed recovery record.
    let interrupted = fixture.path("interrupted/state.json");
    publish(&mut &b"committed recovery record"[..], &interrupted, 0o600).unwrap();
    migrate_private_state(&legacy, &interrupted).unwrap();
    assert_eq!(
        fs::read(&interrupted).unwrap(),
        b"committed recovery record"
    );
    assert_protected(&interrupted.with_extension("migrated"), 0o600);
    assert!(!legacy.exists());

    // Releases before private cleanup journals used 0644. Upgrade those
    // without weakening the ownership/write checks, and make the copy private.
    fs::write(&legacy, b"older readable recovery record").unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o644)).unwrap();
    let older = fixture.path("older/state.json");
    migrate_private_state(&legacy, &older).unwrap();
    assert_protected(&older, 0o600);
    assert_eq!(fs::read(&older).unwrap(), b"older readable recovery record");
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_private_state_rejects_untrusted_legacy_inputs_and_inherited_acls() {
    let fixture = Fixture::root();
    let legacy = fixture.path("legacy");
    let victim = fixture.path("victim");
    let destination = fixture.path("protected/state.json");
    fs::write(&victim, b"preserved").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&victim, &legacy).unwrap();
    assert!(migrate_private_state(&legacy, &destination).is_err());
    fs::remove_file(&legacy).unwrap();
    fs::hard_link(&victim, &legacy).unwrap();
    assert!(migrate_private_state(&legacy, &destination).is_err());
    fs::remove_file(&legacy).unwrap();
    fs::write(&legacy, b"legacy").unwrap();
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(migrate_private_state(&legacy, &destination).is_err());
    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&legacy)
            .status()
            .unwrap()
            .success()
    );
    assert!(migrate_private_state(&legacy, &destination).is_err());
    assert!(!destination.exists());
    assert!(!destination.with_extension("migrated").exists());
    assert_eq!(fs::read(&victim).unwrap(), b"preserved");

    let acl_parent = fixture.path("acl-parent");
    fs::create_dir(&acl_parent).unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write,file_inherit"])
            .arg(&acl_parent)
            .status()
            .unwrap()
            .success()
    );
    let private = acl_parent.join("secret");
    macos_file_io::write_atomic(&private, b"private fixture", 0o600, None, true).unwrap();
    let read_acl_parent = fixture.path("read-acl-parent");
    fs::create_dir(&read_acl_parent).unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,file_inherit"])
            .arg(&read_acl_parent)
            .status()
            .unwrap()
            .success()
    );
    let protected_private = read_acl_parent.join("migrated-secret");
    publish(&mut &b"private fixture"[..], &protected_private, 0o600).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let private = std::ffi::CString::new(private.as_os_str().as_bytes()).unwrap();
    let protected_private =
        std::ffi::CString::new(protected_private.as_os_str().as_bytes()).unwrap();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(65534) != 0
                || libc::setuid(65534) != 0
            {
                libc::_exit(2);
            }
            if libc::open(private.as_ptr(), libc::O_RDONLY) >= 0 {
                libc::_exit(3);
            }
            if libc::open(private.as_ptr(), libc::O_WRONLY) >= 0 {
                libc::_exit(4);
            }
            if libc::open(protected_private.as_ptr(), libc::O_RDONLY) >= 0 {
                libc::_exit(5);
            }
            libc::_exit(0);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(
        status, 0,
        "inherited ACL must not override private output mode"
    );
}

#[test]
fn helper_update_paths_are_identified() {
    let helper = Path::new("/Library/PrivilegedHelperTools/to.nostrvpn.nvpn");
    assert_eq!(helper_destination(helper).as_deref(), Some(helper));
    assert!(
        helper_destination(Path::new(
            "/Library/PrivilegedHelperTools/to.nostrvpn.nvpn.instance"
        ))
        .is_some()
    );
    assert!(helper_destination(Path::new("/usr/local/bin/nvpn-fixture-not-installed")).is_none());
    assert!(helper_destination(Path::new("/Library/PrivilegedHelperTools-other/nvpn")).is_none());
    // Read-only check of the OS's directory alias, with no helper file access.
    let data_helpers = Path::new("/System/Volumes/Data/Library/PrivilegedHelperTools");
    if data_helpers.is_dir() {
        assert!(helper_destination(&data_helpers.join("nvpn-fixture-not-installed")).is_some());
    }
}

#[test]
fn protected_runtime_identity_is_stable_across_system_aliases() {
    let first = runtime_directory(Path::new("/var/nvpn/config.toml")).unwrap();
    assert_eq!(
        first,
        runtime_directory(Path::new("/private/var/nvpn/./config.toml")).unwrap()
    );
    assert!(first.starts_with("/Library/Application Support/nvpn/runtime"));
    assert_ne!(
        first,
        runtime_directory(Path::new("/var/nvpn/other.toml")).unwrap()
    );
    assert!(runtime_directory(Path::new("/var/nvpn/../config.toml")).is_err());
}

#[test]
fn protected_directory_rejects_untrusted_ancestors_and_traversal() {
    assert!(protected_directory(Path::new("relative"), false).is_err());
    assert!(protected_directory(Path::new("/private/var/../var"), false).is_err());
    // Even a root-owned child in a writable ancestor is not a trusted path.
    assert!(protected_directory(Path::new("/private/tmp"), false).is_err());
    assert!(protected_directory(Path::new("/tmp"), false).is_err());
    protected_directory(Path::new("/"), false).unwrap();
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_install_replacement_and_same_path_repair() {
    let fixture = Fixture::root();
    let source = fixture.path("app-nvpn");
    let destination = fixture.path("helpers/nvpn");
    fs::write(&source, b"first inert fixture").unwrap();
    chown(&source, Some(65534), Some(65534)).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o777)).unwrap();

    // Reproduce the old production copy on this filesystem without executing it.
    let legacy = fixture.path("legacy-copy");
    fs::copy(&source, &legacy).unwrap();
    eprintln!(
        "legacy fs::copy retained source owner: {}",
        fs::metadata(&legacy).unwrap().uid() == 65534
    );

    install_executable(&source, &destination).unwrap();
    assert_protected(&destination, 0o755);
    assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());
    let mut old_reader = File::open(&destination).unwrap();
    fs::write(&source, b"updated inert fixture").unwrap();
    install_executable(&source, &destination).unwrap();
    let mut old_bytes = Vec::new();
    old_reader.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, b"first inert fixture");
    assert_eq!(fs::read(&destination).unwrap(), b"updated inert fixture");
    assert_protected(&destination, 0o755);

    chown(&destination, Some(65534), Some(65534)).unwrap();
    let mut former_owner_handle = OpenOptions::new().write(true).open(&destination).unwrap();
    assert!(validate_artifact(&destination).is_err());
    install_executable(&destination, &destination).unwrap();
    assert_protected(&destination, 0o755);
    former_owner_handle.write_all(b"stale descriptor").unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"updated inert fixture");
    let plist = fixture.path("daemons/service.plist");
    publish(&mut &b"plist fixture"[..], &plist, 0o644).unwrap();
    assert_protected(&plist, 0o644);

    use std::os::unix::ffi::OsStrExt;
    let destination_c = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
    let replacement_c = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
    // Only async-signal-safe syscalls in the child of this multithreaded runner.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(65534) != 0
                || libc::setuid(65534) != 0
            {
                libc::_exit(2);
            }
            if libc::open(destination_c.as_ptr(), libc::O_WRONLY) >= 0 {
                libc::_exit(3);
            }
            if libc::rename(replacement_c.as_ptr(), destination_c.as_ptr()) == 0 {
                libc::_exit(4);
            }
            libc::_exit(0);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(
        status, 0,
        "unprivileged write/replace attempt must be denied"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"updated inert fixture");
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_install_does_not_follow_links_or_accept_unsafe_parents() {
    let fixture = Fixture::root();
    let source = fixture.path("source");
    let victim = fixture.path("victim");
    let destination = fixture.path("installed");
    fs::write(&source, b"new fixture").unwrap();
    fs::write(&victim, b"preserved fixture").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    for hard_link in [false, true] {
        if hard_link {
            fs::hard_link(&victim, &destination).unwrap();
        } else {
            symlink(&victim, &destination).unwrap();
        }
        install_executable(&source, &destination).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"preserved fixture");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o600);
        assert_protected(&destination, 0o755);
        fs::remove_file(&destination).unwrap();
    }
    let linked_source = fixture.path("source-link");
    symlink(&source, &linked_source).unwrap();
    assert!(install_executable(&linked_source, &destination).is_err());
    assert!(install_executable(&fixture.0, &destination).is_err());
    let parent = fixture.path("parent");
    fs::create_dir(&parent).unwrap();
    let parent_link = fixture.path("parent-link");
    symlink(&parent, &parent_link).unwrap();
    assert!(install_executable(&source, &parent_link.join("nvpn")).is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(install_executable(&source, &parent.join("nvpn")).is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    chown(&parent, Some(65534), None).unwrap();
    assert!(install_executable(&source, &parent.join("nvpn")).is_err());
    assert!(!parent.join("nvpn").exists());
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_install_rejects_write_acls_and_does_not_copy_source_acl() {
    let fixture = Fixture::root();
    let source = fixture.path("source");
    let destination = fixture.path("installed");
    fs::write(&source, b"inert fixture").unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write,append,writeattr,writeextattr"])
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    install_executable(&source, &destination).unwrap();
    assert_protected(&destination, 0o755);
    let parent = fixture.path("parent");
    fs::create_dir(&parent).unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args([
            "+a",
            "everyone allow add_file,add_subdirectory,delete_child",
        ])
        .arg(&parent)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(install_executable(&source, &parent.join("nvpn")).is_err());
    assert!(!parent.join("nvpn").exists());
}

#[test]
#[ignore = "requires root; only creates isolated filesystem fixtures"]
fn root_failed_publication_preserves_existing_artifact() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture read failure"))
        }
    }
    let fixture = Fixture::root();
    let destination = fixture.path("installed");
    publish(&mut &b"old fixture"[..], &destination, 0o755).unwrap();
    assert!(publish(&mut FailingReader, &destination, 0o755).is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"old fixture");
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}
