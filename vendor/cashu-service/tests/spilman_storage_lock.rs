#![cfg(feature = "spilman")]

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use cashu_service::FileSpilmanClientStorage;
#[cfg(feature = "spilman-wallet")]
use cashu_service::FileSpilmanPaymentSigner;
use cdk_spilman::ClientStorage;

const PROCESS_TEST_ROLE: &str = "CASHU_SPILMAN_STORAGE_PROCESS_TEST_ROLE";
const PROCESS_TEST_DIR: &str = "CASHU_SPILMAN_STORAGE_PROCESS_TEST_DIR";

fn test_funding() -> cdk_spilman::ClientChannelFunding {
    cdk_spilman::ClientChannelFunding {
        params_json: r#"{"capacity":100}"#.to_string(),
        funding_proofs_json: "[]".to_string(),
        channel_secret_hex: "aa".repeat(32),
        keyset_info_json: "{}".to_string(),
        sender_pubkey_hex: format!("02{}", "bb".repeat(32)),
        capacity: 100,
        funding_token_amount: 100,
        mint_url: "https://mint.example".to_string(),
        created_at: 123,
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

#[test]
fn file_spilman_client_storage_process_child() {
    let Ok(role) = std::env::var(PROCESS_TEST_ROLE) else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os(PROCESS_TEST_DIR).unwrap());
    let path = directory.join("client.json");
    #[cfg(feature = "spilman-wallet")]
    if role == "fifo-signer-try-load" {
        match FileSpilmanPaymentSigner::try_load(&directory) {
            Err(_) => {}
            Ok(None) => panic!("Spilman signer store lock unexpectedly reported busy"),
            Ok(Some(_)) => panic!("Spilman signer accepted FIFO state"),
        }
        return;
    }
    if role == "second" {
        std::fs::write(directory.join("second-started"), b"").unwrap();
    }
    let (mut storage, errors) = FileSpilmanClientStorage::load(path).unwrap();
    std::fs::write(directory.join(format!("{role}-loaded")), b"").unwrap();
    if role == "first" {
        assert!(wait_for_path(
            &directory.join("release-first"),
            Duration::from_secs(10)
        ));
    }
    storage.save_funding(&role, test_funding());
    errors.ensure_ok().unwrap();
}

#[test]
fn file_spilman_client_storage_serializes_real_processes_without_lost_updates() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let spawn = |role: &str| {
        Command::new(&executable)
            .args([
                "--exact",
                "file_spilman_client_storage_process_child",
                "--nocapture",
            ])
            .env(PROCESS_TEST_ROLE, role)
            .env(PROCESS_TEST_DIR, directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap()
    };

    let mut first = spawn("first");
    assert!(wait_for_path(
        &directory.path().join("first-loaded"),
        Duration::from_secs(5)
    ));
    let mut second = spawn("second");
    assert!(wait_for_path(
        &directory.path().join("second-started"),
        Duration::from_secs(5)
    ));
    let second_was_serialized = !wait_for_path(
        &directory.path().join("second-loaded"),
        Duration::from_millis(500),
    );
    std::fs::write(directory.path().join("release-first"), b"").unwrap();

    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    assert!(
        second_was_serialized,
        "the second process bypassed the lock"
    );

    let (storage, errors) =
        FileSpilmanClientStorage::load(directory.path().join("client.json")).unwrap();
    errors.ensure_ok().unwrap();
    assert_eq!(
        storage.list_channel_ids(),
        vec!["first".to_string(), "second".to_string()]
    );
}

#[test]
fn file_spilman_client_storage_try_load_reports_busy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.json");
    let (storage, _) = FileSpilmanClientStorage::load(&path).unwrap();
    assert!(FileSpilmanClientStorage::try_load(&path).unwrap().is_none());
    drop(storage);
    assert!(FileSpilmanClientStorage::try_load(&path).unwrap().is_some());
}

#[cfg(all(unix, feature = "spilman-wallet"))]
#[test]
fn file_spilman_payment_signer_try_load_rejects_fifo_promptly() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let directory = tempfile::tempdir().unwrap();
    let path = cashu_service::spilman_client_store_path(directory.path());
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is a valid NUL-terminated platform path and mode is valid.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

    let executable = std::env::current_exe().unwrap();
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "file_spilman_client_storage_process_child",
            "--nocapture",
        ])
        .env(PROCESS_TEST_ROLE, "fifo-signer-try-load")
        .env(PROCESS_TEST_DIR, directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "FIFO rejection child failed");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Spilman client storage blocked while opening a FIFO");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn file_spilman_client_storage_round_trips_channel_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("client.json");
    let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
    storage.save_funding("channel-1", test_funding());
    storage.save_payment_state(
        "channel-1",
        cdk_spilman::ClientPaymentState {
            balance: 7,
            signature: "sig".to_string(),
            payment_count: 1,
            last_payment_at: 456,
        },
    );
    storage.set_closed("channel-1");
    errors.ensure_ok().unwrap();
    drop(storage);

    let (storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
    errors.ensure_ok().unwrap();
    assert_eq!(storage.list_channel_ids(), vec!["channel-1".to_string()]);
    assert_eq!(storage.get_funding("channel-1").unwrap().capacity, 100);
    assert_eq!(storage.get_payment_state("channel-1").unwrap().balance, 7);
    assert_eq!(
        storage.get_state("channel-1"),
        cdk_spilman::ClientChannelState::Closed
    );
}

#[cfg(unix)]
#[test]
fn file_spilman_client_storage_rejects_symlink_reads_and_writes() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("client.json");
    let victim = temp.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    symlink(&victim, &path).unwrap();
    assert!(FileSpilmanClientStorage::load(&path).is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");

    std::fs::remove_file(&path).unwrap();
    let (mut storage, errors) = FileSpilmanClientStorage::load(&path).unwrap();
    storage.save_funding("channel-1", test_funding());
    errors.ensure_ok().unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink(&victim, &path).unwrap();
    storage.set_closed("channel-1");
    assert!(errors.ensure_ok().is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}
