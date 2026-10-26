use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use nostr_sdk::Keys;
use nostr_vpn_core::config::{AppConfig, PendingInboundJoinRequest};
use nostr_vpn_core::join_delivery::load_join_rosters;
use serde_json::Value;

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    admin: AppConfig,
    joiner: AppConfig,
    request: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("nvpn-agent-join-{}", uuid::Uuid::new_v4(),));
        std::fs::create_dir(&directory).unwrap();
        let config = directory.join("admin.toml");
        let mut admin = AppConfig::generated_without_networks();
        let network = admin.add_owned_network("Agent test");
        admin.set_network_enabled(&network, true).unwrap();
        let own = admin.own_nostr_pubkey_hex().unwrap();
        admin.add_device_to_network(&network, &own).unwrap();
        admin.save(&config).unwrap();
        let mut joiner = AppConfig::generated_without_networks();
        joiner.node_name = "Joining agent".into();
        joiner.ensure_pending_nostr_join_request(now()).unwrap();
        let request = directory.join("join-request.txt");
        std::fs::write(
            &request,
            joiner
                .pending_nostr_join_request_link("nvpn://join-request/")
                .unwrap(),
        )
        .unwrap();
        Self {
            directory,
            config,
            admin,
            joiner,
            request,
        }
    }

    fn run(&self, command: &str, options: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_nvpn"))
            .args([
                "join-requests",
                "--config",
                self.config.to_str().unwrap(),
                "--json",
                command,
            ])
            .args(options)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        AppConfig::delete_persisted_secrets_for_path(&self.config).unwrap();
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn shared_request_can_be_reviewed_and_approved_by_a_headless_admin() {
    let mut fixture = Fixture::new();
    let before = std::fs::read(&fixture.config).unwrap();
    let request_path = fixture.request.to_str().unwrap();
    let reviewed = fixture.run("inspect", &["--request-file", request_path]);
    let review = json(&reviewed);
    let recipient = fixture.joiner.own_nostr_pubkey_hex().unwrap();
    assert_eq!(review["device_id"], recipient);
    assert_eq!(review["approved"], false);
    assert_eq!(std::fs::read(&fixture.config).unwrap(), before);
    assert!(load_join_rosters(&fixture.config).is_empty());
    let secret = &fixture
        .joiner
        .pending_nostr_join_request
        .as_ref()
        .unwrap()
        .request
        .request_secret;
    assert!(!String::from_utf8_lossy(&reviewed.stdout).contains(secret));

    let approved = json(&fixture.run("approve", &["--request-file", request_path]));
    assert_eq!(approved["approved"], true);
    assert_eq!(approved["delivery"], "queued");
    let saved = AppConfig::load(&fixture.config).unwrap();
    assert!(saved.active_network().devices.contains(&recipient));
    let queued = load_join_rosters(&fixture.config);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].1.recipient_npub, recipient);
    let roster = &queued[0].1.join_roster;
    roster.signed_roster.verify().unwrap();
    assert_eq!(
        roster.signed_roster.signer_pubkey_hex().unwrap(),
        fixture.admin.own_nostr_pubkey_hex().unwrap()
    );
    assert!(
        fixture
            .joiner
            .apply_nostr_join_roster(roster, now())
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture.joiner.effective_network_id(),
        saved.effective_network_id()
    );
}

#[test]
fn a_non_admin_cannot_approve_and_invalid_links_do_not_change_the_roster() {
    let mut fixture = Fixture::new();
    std::fs::write(&fixture.request, "nvpn://join-request/not-a-request").unwrap();
    let before = std::fs::read(&fixture.config).unwrap();
    let denied = fixture.run(
        "approve",
        &["--request-file", fixture.request.to_str().unwrap()],
    );
    assert!(!denied.status.success());
    assert_eq!(std::fs::read(&fixture.config).unwrap(), before);
    assert!(load_join_rosters(&fixture.config).is_empty());

    let other = Keys::generate().public_key().to_hex();
    fixture.admin.active_network_mut().admins = vec![other];
    fixture.admin.save(&fixture.config).unwrap();
    let before = std::fs::read(&fixture.config).unwrap();
    let denied = fixture.run(
        "approve",
        &["--device", &fixture.joiner.own_nostr_pubkey_hex().unwrap()],
    );
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("not administered"));
    assert_eq!(std::fs::read(&fixture.config).unwrap(), before);
    assert!(load_join_rosters(&fixture.config).is_empty());
}

#[test]
fn list_and_approve_select_only_an_existing_pending_device() {
    let mut fixture = Fixture::new();
    let recipient = fixture.joiner.own_nostr_pubkey_hex().unwrap();
    fixture.admin.active_network_mut().inbound_join_requests = vec![PendingInboundJoinRequest {
        requester: recipient.clone(),
        requester_node_name: "Joining agent".into(),
        requested_at: now(),
    }];
    fixture.admin.save(&fixture.config).unwrap();
    let listed = json(&fixture.run("list", &[]));
    assert_eq!(listed["requests"][0]["requester"], recipient);
    let unknown = Keys::generate().public_key().to_hex();
    assert!(
        !fixture
            .run("approve", &["--device", &unknown])
            .status
            .success()
    );
    assert!(load_join_rosters(&fixture.config).is_empty());
    assert_eq!(
        json(&fixture.run("approve", &["--device", &recipient]))["delivery"],
        "queued"
    );
    let saved = AppConfig::load(&fixture.config).unwrap();
    assert!(saved.active_network().inbound_join_requests.is_empty());
    assert!(saved.active_network().devices.contains(&recipient));
    assert_eq!(load_join_rosters(&fixture.config).len(), 1);
}
