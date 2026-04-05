use crate::*;
use nostr_vpn_core::signaling::SignalPayload;
use std::path::Path;

#[test]
fn daemon_session_requires_remote_participants_to_be_active() {
    assert!(!daemon_session_active(true, 0));
    assert!(daemon_session_active(true, 1));
    assert!(!daemon_session_active(false, 1));
}

#[test]
fn daemon_session_idle_status_distinguishes_waiting_from_paused() {
    assert_eq!(
        daemon_session_idle_status(true, 0, false),
        crate::WAITING_FOR_PARTICIPANTS_STATUS
    );
    assert_eq!(
        daemon_session_idle_status(false, 0, true),
        "Listening for join requests"
    );
    assert_eq!(daemon_session_idle_status(false, 0, false), "Paused");
    assert_eq!(daemon_session_idle_status(true, 2, false), "Paused");
}

#[test]
fn parse_nonzero_pid_rejects_zero_and_invalid_values() {
    assert_eq!(parse_nonzero_pid("4242"), Some(4242));
    assert_eq!(parse_nonzero_pid("0"), None);
    assert_eq!(parse_nonzero_pid("not-a-number"), None);
}

#[test]
fn daemon_reconnect_backoff_is_bounded_exponential() {
    assert_eq!(daemon_reconnect_backoff_delay(1).as_secs(), 1);
    assert_eq!(daemon_reconnect_backoff_delay(2).as_secs(), 2);
    assert_eq!(daemon_reconnect_backoff_delay(3).as_secs(), 4);
    assert_eq!(daemon_reconnect_backoff_delay(4).as_secs(), 8);
    assert_eq!(daemon_reconnect_backoff_delay(5).as_secs(), 16);
    assert_eq!(daemon_reconnect_backoff_delay(6).as_secs(), 30);
    assert_eq!(daemon_reconnect_backoff_delay(99).as_secs(), 30);
}

#[test]
fn reconnect_only_for_connection_class_errors() {
    assert!(publish_error_requires_reconnect(
        "client not connected to relays"
    ));
    assert!(publish_error_requires_reconnect("relay pool shutdown"));
    assert!(publish_error_requires_reconnect(
        "event not published: relay not connected (status changed)"
    ));
    assert!(publish_error_requires_reconnect(
        "event not published: recv message response timeout"
    ));
    assert!(publish_error_requires_reconnect(
        "connection closed by peer"
    ));

    assert!(!publish_error_requires_reconnect(
        "private signaling event rejected by all relays"
    ));
    assert!(!publish_error_requires_reconnect(
        "event not published: Policy violated and pubkey is not in our web of trust."
    ));
}

#[test]
fn peer_signal_timeout_has_reasonable_floor_and_scale() {
    assert_eq!(peer_signal_timeout_secs(1), 20);
    assert_eq!(peer_signal_timeout_secs(5), 20);
    assert_eq!(peer_signal_timeout_secs(10), 30);
}

#[test]
fn peer_path_cache_timeout_keeps_endpoint_memory_longer_than_presence_timeout() {
    assert_eq!(peer_path_cache_timeout_secs(1), 60);
    assert_eq!(peer_path_cache_timeout_secs(5), 60);
    assert_eq!(peer_path_cache_timeout_secs(10), 90);
}

#[test]
fn outbound_announce_book_republishes_after_peer_forget() {
    let mut book = OutboundAnnounceBook::default();
    assert!(book.needs_send("peer-a", "fp1"));
    book.mark_sent("peer-a", "fp1");
    assert!(!book.needs_send("peer-a", "fp1"));
    assert!(book.needs_send("peer-a", "fp2"));

    book.forget("peer-a");
    assert!(book.needs_send("peer-a", "fp1"));
}

#[test]
fn hello_signal_forces_targeted_private_announce_republish() {
    let mut book = OutboundAnnounceBook::default();
    book.mark_sent("peer-a", "fp1");
    crate::maybe_reset_targeted_announce_cache_for_hello(
        &mut book,
        "peer-a",
        &SignalPayload::Hello,
    );
    assert!(book.needs_send("peer-a", "fp1"));

    book.mark_sent("peer-a", "fp1");
    crate::maybe_reset_targeted_announce_cache_for_hello(
        &mut book,
        "peer-a",
        &SignalPayload::Announce(PeerAnnouncement {
            node_id: "node-a".to_string(),
            public_key: "pubkey".to_string(),
            endpoint: "192.0.2.10:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("198.51.100.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 1,
        }),
    );
    assert!(!book.needs_send("peer-a", "fp1"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_underlay_repair_resets_tunnel_runtime() {
    let mut runtime = CliTunnelRuntime::new("utun4");
    runtime.last_fingerprint = Some("fingerprint".to_string());
    runtime.active_listen_port = Some(51820);

    crate::session_runtime::reset_tunnel_runtime_after_macos_underlay_repair(&mut runtime);

    assert!(runtime.last_fingerprint.is_none());
    assert!(runtime.active_listen_port.is_none());
    assert!(!runtime.is_running());
}

#[test]
fn macos_connect_privilege_preflight_requires_admin_when_euid_is_not_root() {
    let _guard = crate::macos_euid_override_lock_for_test()
        .lock()
        .expect("macos euid test lock");
    crate::set_macos_euid_override_for_test(Some(501));

    let error = crate::ensure_macos_connect_privileges(Path::new("/tmp/nvpn.toml"))
        .expect_err("non-root macOS preflight should fail");
    let message = error.to_string();
    assert!(message.contains("admin privileges"));
    assert!(message.contains("did you run with sudo?"));
    assert!(message.contains("sudo nvpn start --connect"));
    assert!(message.contains("sudo nvpn service install"));

    crate::set_macos_euid_override_for_test(None);
}

#[test]
fn macos_connect_privilege_preflight_allows_root() {
    let _guard = crate::macos_euid_override_lock_for_test()
        .lock()
        .expect("macos euid test lock");
    crate::set_macos_euid_override_for_test(Some(0));

    crate::ensure_macos_connect_privileges(Path::new("/tmp/nvpn.toml"))
        .expect("root macOS preflight should pass");

    crate::set_macos_euid_override_for_test(None);
}
