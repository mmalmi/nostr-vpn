use std::fs;
use std::path::{Path, PathBuf};

use clap::CommandFactory;
use nostr_vpn_core::relay::{RelayOperatorState, ServiceOperatorState};

use crate::*;

#[test]
fn clap_stats_supports_json_and_state_file() {
    let command = Cli::command();
    let stats = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "stats")
        .expect("stats subcommand exists");

    assert!(
        stats
            .get_arguments()
            .any(|argument| argument.get_long() == Some("json")),
        "missing --json on stats command"
    );
    assert!(
        stats
            .get_arguments()
            .any(|argument| argument.get_long() == Some("state-file")),
        "missing --state-file on stats command"
    );
}

#[test]
fn parse_service_operator_state_accepts_legacy_relay_state() {
    let raw = serde_json::to_vec(&RelayOperatorState {
        updated_at: 42,
        relay_pubkey: "relay-pubkey".to_string(),
        advertised_endpoint: "203.0.113.10:51820".to_string(),
        total_sessions_served: 7,
        total_forwarded_bytes: 9_940_733,
        current_forward_bps: 4_096,
        unique_peer_count: 3,
        known_peer_pubkeys: vec!["peer-a".to_string()],
        active_sessions: Vec::new(),
    })
    .expect("serialize legacy relay state");

    let state = parse_service_operator_state(&raw).expect("parse relay state");
    assert_eq!(state.updated_at, 42);
    assert_eq!(state.operator_pubkey, "relay-pubkey");
    assert!(state.nat_assist.is_none());
    assert_eq!(
        state
            .relay
            .as_ref()
            .map(|relay| relay.total_forwarded_bytes),
        Some(9_940_733)
    );
}

#[test]
fn format_human_bytes_uses_binary_units() {
    assert_eq!(format_human_bytes(999), "999 B");
    assert_eq!(format_human_bytes(1_536), "1.50 KiB");
    assert_eq!(format_human_bytes(9_940_733), "9.48 MiB");
}

#[test]
fn resolve_stats_state_file_prefers_existing_config_adjacent_state() {
    let dir = unique_stats_test_dir("config");
    fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let state_path = relay_operator_state_file_path(&config_path);
    fs::write(&state_path, b"{}").expect("write state file");

    let resolved =
        resolve_stats_state_file_path(None, &config_path).expect("resolve config-adjacent path");
    assert_eq!(resolved, state_path);

    fs::remove_dir_all(&dir).expect("remove test dir");
}

#[test]
fn render_service_operator_stats_humanizes_totals() {
    let state = ServiceOperatorState {
        updated_at: 100,
        operator_pubkey: "relay-pubkey".to_string(),
        relay: Some(RelayOperatorState {
            updated_at: 100,
            relay_pubkey: "relay-pubkey".to_string(),
            advertised_endpoint: "203.0.113.10:51820".to_string(),
            total_sessions_served: 258,
            total_forwarded_bytes: 9_940_733,
            current_forward_bps: 4_096,
            unique_peer_count: 11,
            known_peer_pubkeys: Vec::new(),
            active_sessions: Vec::new(),
        }),
        nat_assist: None,
    };

    let rendered = render_service_operator_stats(Path::new("/tmp/relay.operator.json"), &state);
    assert!(rendered.contains("total_forwarded: 9.48 MiB (9940733 B)"));
    assert!(rendered.contains("current_forward_rate: 4.00 KiB/s"));
    assert!(rendered.contains("unique_peers_served: 11"));
}

fn unique_stats_test_dir(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("nvpn-stats-test-{label}-{nonce}"))
}
