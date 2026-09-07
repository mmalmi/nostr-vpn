#[cfg(unix)]
#[test]
fn signed_roster_persistence_avoids_preexisting_temporary_symlinks() {
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::fips_control::{NetworkRoster, SignedRoster};
    use nostr_vpn_core::signed_rosters::{load_signed_rosters, upsert_signed_roster};

    let directory = std::env::temp_dir().join(format!(
        "nvpn-private-roster-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    fs::create_dir(&directory).expect("create test directory");
    let path = directory.join("signed-rosters.json");
    let target = directory.join("unrelated-file");
    let temporary = directory.join("signed-rosters.json.tmp");
    fs::write(&target, "do-not-overwrite").expect("write symlink target");
    symlink(&target, &temporary).expect("create temporary symlink");
    let admin = Keys::generate();
    let roster = SignedRoster::sign(
        "mesh",
        NetworkRoster {
            network_name: "Private network".to_string(),
            devices: Vec::new(),
            admins: vec![admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: 1,
        },
        &admin,
    )
    .expect("sign roster");

    assert!(upsert_signed_roster(&path, roster.clone()).expect("persist signed roster"));

    assert_eq!(
        fs::read_to_string(&target).expect("read symlink target"),
        "do-not-overwrite"
    );
    assert!(
        fs::symlink_metadata(&temporary)
            .expect("symlink metadata")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("roster metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        load_signed_rosters(&path)
            .expect("load roster")
            .latest_for("mesh"),
        Some(&roster)
    );
    fs::remove_dir_all(&directory).expect("remove test directory");
}
