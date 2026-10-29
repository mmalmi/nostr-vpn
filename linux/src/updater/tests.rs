use super::*;

#[test]
fn verified_updates_download_into_the_users_own_data_directory() {
    if std::env::var_os("NVPN_UPDATE_DOWNLOAD_DIR").is_some() {
        // The override is exercised by the e2e update script.
        return;
    }
    let directory = update_download_dir();
    assert_eq!(
        directory,
        download_dir_under(&crate::default_data_dir()),
        "downloads must follow the user's own data directory"
    );
    assert_eq!(
        directory.file_name().and_then(|name| name.to_str()),
        Some("update-downloads")
    );
    assert!(
        !directory.starts_with(std::env::temp_dir()),
        "verified updates must not default into a shared temporary directory"
    );
}

#[test]
fn download_preparation_never_launches_an_application() {
    if let Some(directory) = std::env::var_os("NVPN_TEST_UPDATE_PREPARATION_CHILD") {
        let directory = PathBuf::from(directory);
        prepare_download(&directory.join("update.deb"), "update.deb").unwrap();
        prepare_download(&directory.join("update.AppImage"), "update.AppImage").unwrap();
        return;
    }

    let directory = std::env::temp_dir().join(format!(
        "nvpn-update-open-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let marker = directory.join("opened");
    let opener = directory.join("xdg-open");
    fs::write(
        &opener,
        "#!/bin/sh\nprintf opened > \"$NVPN_TEST_UPDATE_OPENED\"\n",
    )
    .unwrap();
    fs::set_permissions(&opener, fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["update.deb", "update.AppImage"] {
        let file = directory.join(name);
        fs::write(&file, "fixture").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Re-exec isolates PATH and the fake desktop opener from other tests.
    // Captured pipes also wait for an accidentally spawned opener to exit.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "updater::tests::download_preparation_never_launches_an_application",
            "--nocapture",
        ])
        .env("NVPN_TEST_UPDATE_PREPARATION_CHILD", &directory)
        .env("NVPN_TEST_UPDATE_OPENED", &marker)
        .env_remove("NVPN_UPDATE_SKIP_OPEN")
        .env("PATH", &directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    assert!(
        !marker.exists(),
        "a background download launched a desktop application"
    );
    assert_eq!(
        fs::metadata(directory.join("update.deb"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(directory.join("update.AppImage"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    fs::remove_dir_all(directory).unwrap();
}
