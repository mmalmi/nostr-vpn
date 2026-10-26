use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nostr_vpn_core::config::AppConfig;

#[test]
fn status_commands_do_not_migrate_legacy_config_or_create_sidecars() {
    let dir = TestDir::new();
    let config_path = dir.path().join("legacy.toml");
    let config = AppConfig::generated();
    fs::write(
        &config_path,
        config.plaintext_toml().expect("encode legacy config"),
    )
    .expect("write legacy config");
    assert!(
        AppConfig::config_file_needs_secret_migration(&config_path).expect("inspect legacy config")
    );
    let before = directory_snapshot(dir.path());
    let config_arg = config_path.to_str().expect("utf8 config path");

    for args in [
        vec![
            "status",
            "--config",
            config_arg,
            "--discover-secs",
            "0",
            "--json",
        ],
        vec!["paid-exit", "status", "--config", config_arg, "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nvpn"))
            .args(&args)
            .output()
            .expect("run nvpn status command");

        assert!(
            output.status.success(),
            "nvpn {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(directory_snapshot(dir.path()), before, "nvpn {args:?}");
    }
}

#[test]
fn status_only_reports_fips_connections_from_platform_runtime_state() {
    let dir = TestDir::new();
    let config_path = dir.path().join("config.toml");
    fs::write(
        &config_path,
        AppConfig::generated()
            .plaintext_toml()
            .expect("encode config"),
    )
    .expect("write config");
    let state_path = dir.path().join("daemon.state.json");
    let mut state = serde_json::json!({
        "updated_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "vpn_enabled": false,
        "vpn_active": false,
        "vpn_status": "Paused",
        "expected_peer_count": 0,
        "connected_peer_count": 0,
        "fips_direct_roster_peer_count": 2,
        "fips_other_peer_count": 3,
        "mesh_ready": false,
    });
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let status = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nvpn"));
        command
            .args(["status", "--discover-secs", "0", "--config"])
            .arg(&config_path)
            .env("NVPN_DAEMON_STATUS_MODE", "state-file")
            .env("NVPN_DAEMON_STATE_RUNNING_MAX_AGE_SECS", "60");
        if json {
            command.arg("--json");
        }
        let output = command.output().expect("run status");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("status is UTF-8")
    };
    let output: serde_json::Value = serde_json::from_str(&status(true)).unwrap();
    assert_eq!(output["peer_count"], 0);
    let text = status(false);
    if cfg!(target_os = "macos") {
        // macOS status is root-owned; a fresh user-side snapshot cannot forge it.
        assert_eq!(output["daemon"]["running"], false);
        assert!(output["mesh_ready"].is_null());
        assert!(output["daemon"]["state"].is_null());
        assert_ne!(output["daemon"]["state_file"], state_path.to_str().unwrap());
        assert!(text.contains("daemon: stopped"), "{text}");
        assert!(!text.lines().any(|line| line.starts_with("fips_peers:")));
        assert_eq!(
            fs::read(&state_path).unwrap(),
            serde_json::to_vec(&state).unwrap()
        );
    } else {
        assert_eq!(output["daemon"]["running"], true);
        assert_eq!(output["status_source"], "daemon");
        assert_eq!(output["mesh_ready"], false);
        assert_eq!(
            output["daemon"]["state"]["fips_direct_roster_peer_count"],
            2
        );
        assert_eq!(output["daemon"]["state"]["fips_other_peer_count"], 3);
        assert!(text.contains("vpn_status: Paused"), "{text}");
        assert!(
            text.contains("fips_peers: 5 connected (2 direct roster, 3 other)"),
            "{text}"
        );

        state["mesh_ready"] = true.into();
        fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let output: serde_json::Value = serde_json::from_str(&status(true)).unwrap();
        assert_eq!(output["status_source"], "daemon");
        assert_eq!(output["mesh_ready"], true);
    }

    state["updated_at"] = 0.into();
    fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let text = status(false);
    assert!(text.contains("daemon: stopped"));
    assert!(text.contains("mesh_ready: unknown"), "{text}");
    assert!(
        text.contains("foreground `nvpn connect` sessions"),
        "{text}"
    );
    assert!(!text.contains("mesh_progress:"), "{text}");
    let output: serde_json::Value = serde_json::from_str(&status(true)).unwrap();
    assert_eq!(output["status_source"], "config");
    assert!(output["mesh_ready"].is_null());
    assert!(
        !text.lines().any(|line| line.starts_with("fips_peers:")),
        "stopped daemon must not report stale links"
    );
}

fn directory_snapshot(path: &Path) -> BTreeMap<OsString, Vec<u8>> {
    fs::read_dir(path)
        .expect("read test directory")
        .map(|entry| {
            let entry = entry.expect("read directory entry");
            let name = entry.file_name();
            let contents = fs::read(entry.path()).expect("read directory entry contents");
            (name, contents)
        })
        .collect()
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nvpn-status-readonly-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
