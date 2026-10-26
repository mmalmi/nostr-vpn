//! Exercise the public file-control boundary without a VPN, keychain, or runtime.
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::file_transfers::{
    FileCommand, FileState, TransferState, completed_file, create_upload, discard_staged, enqueue,
    outbox_dir, read_state, stage_source, state_dir, validate_recipient,
};

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    app: AppConfig,
    recipient: String,
}
impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("nvpn-file-storage-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        private_permissions(&directory, true);
        let config = directory.join("config.toml");
        let mut app = AppConfig::default();
        app.node_name = "File transfer test".into();
        let recipient = Keys::generate().public_key().to_hex();
        let own = app.own_nostr_pubkey_hex().unwrap();
        let network = &mut app.networks[0];
        network.enabled = true;
        network.local_identity_confirmation_pending = false;
        network.devices = vec![own.clone(), recipient.clone()];
        network.admins = vec![own];
        let fixture = Self {
            directory,
            config,
            app,
            recipient,
        };
        fixture.save_config();
        fixture
    }
    fn save_config(&self) {
        // Unlike save/save_plaintext, this serializer does not persist platform secrets.
        fs::write(&self.config, self.app.plaintext_toml().unwrap()).unwrap();
        private_permissions(&self.config, false);
    }
    fn source(&self) -> PathBuf {
        let path = self.directory.join("selected.txt");
        fs::write(&path, b"selected bytes").unwrap();
        path
    }
    fn send(&self, path: &Path) -> FileCommand {
        FileCommand::Send {
            npub: self.recipient.clone(),
            paths: vec![path.to_string_lossy().into_owned()],
        }
    }
    fn state(&self, path: &Path) -> TransferState {
        TransferState {
            id: "received-file".into(),
            peer_npub: self.recipient.clone(),
            peer_name: "Peer".into(),
            is_sender: false,
            files: vec![FileState {
                name: "received.txt".into(),
                size_bytes: 5,
                local_path: Some(path.to_string_lossy().into_owned()),
            }],
            status: "completed".into(),
            transferred_bytes: 5,
            total_bytes: 5,
            error: None,
        }
    }
    fn save_state(&self, state: &TransferState) {
        let directory = state_dir(&self.config);
        fs::create_dir_all(&directory).unwrap();
        private_permissions(&directory, true);
        let path = directory.join("state.json");
        fs::write(&path, serde_json::to_vec(&vec![state]).unwrap()).unwrap();
        private_permissions(&path, false);
    }
    fn received(&self) -> PathBuf {
        let directory = state_dir(&self.config).join("inbox").join("received-file");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("received.txt");
        fs::write(&path, b"hello").unwrap();
        private_permissions(&path, false);
        self.save_state(&self.state(&path));
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn private_permissions(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, directory);
}

#[test]
fn staged_source_is_independent_and_queue_contains_only_owned_references() {
    let fixture = Fixture::new();
    assert!(read_state(&fixture.config).unwrap().is_empty());
    let source = fixture.source();
    let staged = stage_source(&fixture.config, &source).unwrap();
    fs::write(&source, b"changed source").unwrap();
    assert_eq!(fs::read(&staged).unwrap(), b"selected bytes");
    let npub = nostr_sdk::prelude::PublicKey::from_hex(&fixture.recipient)
        .unwrap()
        .to_bech32()
        .unwrap();
    validate_recipient(&fixture.config, &npub).unwrap();
    let id = enqueue(&fixture.config, fixture.send(&staged)).unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(
            state_dir(&fixture.config)
                .join("commands")
                .join(format!("{id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(record["id"], id);
    assert_eq!(
        record["command"]["paths"][0],
        staged.to_string_lossy().as_ref()
    );
    discard_staged(&fixture.config, &staged).unwrap();
    assert!(!staged.exists());
    assert_eq!(fs::read(source).unwrap(), b"changed source");
}

#[test]
fn disabled_unconfirmed_removed_and_unknown_members_cannot_queue_files() {
    let mut fixture = Fixture::new();
    let staged = stage_source(&fixture.config, &fixture.source()).unwrap();
    let original = fixture.app.clone();
    let own = fixture.app.own_nostr_pubkey_hex().unwrap();
    assert!(validate_recipient(&fixture.config, &own).is_err());
    assert!(validate_recipient(&fixture.config, &Keys::generate().public_key().to_hex()).is_err());
    for case in 0..3 {
        fixture.app = original.clone();
        let network = &mut fixture.app.networks[0];
        match case {
            0 => network.enabled = false,
            1 => network.local_identity_confirmation_pending = true,
            _ => network.removed_devices = vec![fixture.recipient.clone()],
        }
        fixture.save_config();
        assert!(
            validate_recipient(&fixture.config, &fixture.recipient).is_err(),
            "membership case {case}"
        );
        assert!(enqueue(&fixture.config, fixture.send(&staged)).is_err());
    }
    assert!(!state_dir(&fixture.config).join("commands").exists());
    assert_eq!(fs::read(staged).unwrap(), b"selected bytes");
}

#[test]
fn queue_rejects_unstaged_paths_invalid_ids_and_excess_pending_operations() {
    let fixture = Fixture::new();
    assert!(enqueue(&fixture.config, fixture.send(&fixture.source())).is_err());
    assert!(
        enqueue(
            &fixture.config,
            FileCommand::Cancel {
                id: "../outside".into()
            }
        )
        .is_err()
    );
    assert!(
        enqueue(
            &fixture.config,
            FileCommand::Send {
                npub: fixture.recipient.clone(),
                paths: vec![]
            }
        )
        .is_err()
    );
    let staged = stage_source(&fixture.config, &fixture.source()).unwrap();
    enqueue(&fixture.config, fixture.send(&staged)).unwrap();
    let queue = state_dir(&fixture.config).join("commands");
    for index in 1..64 {
        fs::write(queue.join(format!("pending-{index}.json")), b"{}").unwrap();
    }
    assert!(
        enqueue(
            &fixture.config,
            FileCommand::Cancel {
                id: "received-file".into()
            }
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(queue).unwrap().count(), 64);
}

#[test]
fn completed_downloads_require_received_state_exact_path_and_unchanged_size() {
    let fixture = Fixture::new();
    let path = fixture.received();
    let (_, mut file) = completed_file(&fixture.config, "received-file", 0).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"hello");
    drop(file);
    assert!(completed_file(&fixture.config, "../received-file", 0).is_err());
    assert!(completed_file(&fixture.config, "received-file", 1).is_err());
    for bad_path in [
        fixture.source(),
        state_dir(&fixture.config).join("inbox/batch/../received-file/received.txt"),
        state_dir(&fixture.config).join("inbox/too/deep/received.txt"),
    ] {
        fixture.save_state(&fixture.state(&bad_path));
        assert!(completed_file(&fixture.config, "received-file", 0).is_err());
    }
    for (sender, status) in [(true, "completed"), (false, "transferring")] {
        let mut state = fixture.state(&path);
        state.is_sender = sender;
        state.status = status.into();
        fixture.save_state(&state);
        assert!(completed_file(&fixture.config, "received-file", 0).is_err());
    }
    fixture.save_state(&fixture.state(&path));
    fs::write(&path, b"changed size").unwrap();
    assert!(completed_file(&fixture.config, "received-file", 0).is_err());
}

#[cfg(unix)]
#[test]
fn exchanged_staging_ancestor_blocks_send_and_cleanup_without_touching_target() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let (staged, mut output) = create_upload(&fixture.config, "selected.txt").unwrap();
    output.write_all(b"upload bytes").unwrap();
    output.sync_all().unwrap();
    drop(output);
    let external = fixture.directory.join("unrelated");
    fs::create_dir(&external).unwrap();
    let target = external.join("selected.txt");
    fs::write(&target, b"keep this file").unwrap();
    let batch = staged.parent().unwrap();
    let retained = outbox_dir(&fixture.config).join("retained-batch");
    fs::rename(batch, &retained).unwrap();
    symlink(&external, batch).unwrap();
    assert!(enqueue(&fixture.config, fixture.send(&staged)).is_err());
    assert!(discard_staged(&fixture.config, &staged).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep this file");
    assert_eq!(
        fs::read(retained.join("selected.txt")).unwrap(),
        b"upload bytes"
    );
}

#[cfg(unix)]
#[test]
fn linked_outbox_blocks_upload_and_source_staging_without_creating_external_files() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let external = fixture.directory.join("unrelated");
    fs::create_dir(&external).unwrap();
    let sentinel = external.join("sentinel");
    fs::write(&sentinel, b"unchanged").unwrap();
    symlink(&external, outbox_dir(&fixture.config)).unwrap();
    assert!(create_upload(&fixture.config, "upload.txt").is_err());
    assert!(stage_source(&fixture.config, &fixture.source()).is_err());
    assert_eq!(fs::read_dir(external).unwrap().count(), 1);
    assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn linked_download_ancestor_and_state_file_are_rejected() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let path = fixture.received();
    let external = fixture.directory.join("unrelated");
    fs::create_dir(&external).unwrap();
    let target = external.join("received.txt");
    fs::write(&target, b"hello").unwrap();
    private_permissions(&target, false);
    let batch = path.parent().unwrap();
    fs::rename(batch, batch.with_file_name("retained-batch")).unwrap();
    symlink(&external, batch).unwrap();
    assert!(completed_file(&fixture.config, "received-file", 0).is_err());
    let state = state_dir(&fixture.config).join("state.json");
    let retained_state = fixture.directory.join("retained-state.json");
    fs::rename(&state, &retained_state).unwrap();
    symlink(&retained_state, &state).unwrap();
    assert!(read_state(&fixture.config).is_err());
    assert_eq!(fs::read(target).unwrap(), b"hello");
}
