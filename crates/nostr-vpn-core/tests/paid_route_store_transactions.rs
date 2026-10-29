use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nostr_vpn_core::paid_route_store::{load_paid_route_store, update_paid_route_store};

const ROLE_ENV: &str = "NVPN_PAID_ROUTE_TRANSACTION_TEST_ROLE";
const STORE_ENV: &str = "NVPN_PAID_ROUTE_TRANSACTION_TEST_STORE";

#[cfg(unix)]
#[test]
fn paid_route_lock_rejects_links_without_modifying_target() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let directory = std::env::temp_dir().join(format!(
        "nvpn-paid-route-lock-security-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&directory).expect("create lock test directory");
    let store_path = directory.join("paid-routes.json");
    let lock_path = store_path.with_extension("json.lock");
    let target = directory.join("unrelated-file");
    std::fs::write(&target, b"must remain unchanged").expect("write target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640))
        .expect("set target permissions");
    let before = std::fs::metadata(&target).expect("target metadata");

    for hard_link in [true, false] {
        if hard_link {
            std::fs::hard_link(&target, &lock_path).expect("hard link lock target");
        } else {
            symlink(&target, &lock_path).expect("symlink lock target");
        }
        let mut updated = false;
        let result = update_paid_route_store(&store_path, |_| {
            updated = true;
            Ok(())
        });
        let after = std::fs::metadata(&target).expect("target metadata after transaction");
        assert!(result.is_err(), "linked lock must be rejected");
        assert!(!updated, "unsafe lock must not enter transaction");
        assert_eq!(after.permissions().mode(), before.permissions().mode());
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"must remain unchanged"
        );
        std::fs::remove_file(&lock_path).expect("remove test lock");
    }
    assert!(!store_path.exists());
    std::fs::remove_dir_all(directory).expect("remove lock test directory");
}

#[test]
fn concurrent_process_updates_survive() {
    if let Some(role) = std::env::var_os(ROLE_ENV) {
        run_worker(role.to_string_lossy().as_ref());
        return;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "nvpn-paid-route-transaction-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create transaction test directory");
    let store_path = directory.join("paid-routes.json");
    let entered_path = directory.join("first-writer-entered");
    let test_binary = std::env::current_exe().expect("current test binary");

    let mut first = Command::new(&test_binary)
        .args(["--exact", "concurrent_process_updates_survive"])
        .env(ROLE_ENV, "first")
        .env(STORE_ENV, &store_path)
        .spawn()
        .expect("spawn first paid-route writer");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered_path.exists() {
        assert!(
            Instant::now() < deadline,
            "first writer did not enter its transaction"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let second = Command::new(&test_binary)
        .args(["--exact", "concurrent_process_updates_survive"])
        .env(ROLE_ENV, "second")
        .env(STORE_ENV, &store_path)
        .status()
        .expect("run second paid-route writer");
    assert!(second.success(), "second paid-route writer failed");
    assert!(
        first
            .wait()
            .expect("wait for first paid-route writer")
            .success(),
        "first paid-route writer failed"
    );

    let store = load_paid_route_store(&store_path).expect("load concurrent paid-route updates");
    assert_eq!(store.wallet.default_mint, "https://mint.example");
    assert_eq!(store.buyer_session_admissions.get("seller"), Some(&123));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let store_metadata = std::fs::metadata(&store_path).expect("store metadata");
        let lock_metadata =
            std::fs::metadata(store_path.with_extension("json.lock")).expect("lock metadata");
        assert_eq!(
            (lock_metadata.uid(), lock_metadata.gid()),
            (store_metadata.uid(), store_metadata.gid())
        );
        assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);
    }
    std::fs::remove_dir_all(directory).expect("remove transaction test directory");
}

fn run_worker(role: &str) {
    let store_path = std::path::PathBuf::from(
        std::env::var_os(STORE_ENV).expect("paid-route transaction worker store path"),
    );
    match role {
        "first" => update_paid_route_store(&store_path, |store| {
            store.upsert_wallet_mint("https://mint.example", "Example", None, 1);
            store.set_default_mint("https://mint.example");
            std::fs::write(
                store_path
                    .parent()
                    .expect("transaction store parent")
                    .join("first-writer-entered"),
                b"entered",
            )?;
            std::thread::sleep(Duration::from_millis(500));
            Ok(())
        })
        .expect("first transaction"),
        "second" => update_paid_route_store(&store_path, |store| {
            store
                .buyer_session_admissions
                .insert("seller".to_string(), 123);
            Ok(())
        })
        .expect("second transaction"),
        other => panic!("unknown paid-route transaction worker role {other}"),
    }
}
