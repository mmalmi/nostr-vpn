use std::collections::HashMap;

use crate::*;

use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::relay::RelayAllocationRejectReason;
use nostr_vpn_core::signaling::SignalPayload;

use super::super::support::sample_peer_announcement;

#[test]
fn explicit_announcement_can_attach_active_relay_endpoint() {
    let announcement = crate::build_explicit_peer_announcement_with_relay(
        "peer-a".to_string(),
        generate_keypair().public_key,
        "203.0.113.20:51820".to_string(),
        "192.168.178.80:51820".to_string(),
        "10.44.0.239/32".to_string(),
        Vec::new(),
        crate::RelayAnnouncementDetails {
            relay_endpoint: Some("198.51.100.30:40001".to_string()),
            relay_pubkey: Some("relay-pubkey".to_string()),
            relay_expires_at: Some(500),
        },
    );

    assert_eq!(
        announcement.relay_endpoint.as_deref(),
        Some("198.51.100.30:40001")
    );
    assert_eq!(announcement.relay_pubkey.as_deref(), Some("relay-pubkey"));
    assert_eq!(announcement.relay_expires_at, Some(500));
}

#[test]
fn relay_endpoint_is_preferred_when_active() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: Some("198.51.100.30:40001".to_string()),
        relay_pubkey: Some("relay-pubkey".to_string()),
        relay_expires_at: Some(500),
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("10.0.0.33:51820"),
        100,
    )
    .expect("planned tunnel peers");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "198.51.100.30:40001");
}

#[test]
fn expired_relay_endpoint_is_ignored_for_planning() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: Some("198.51.100.30:40001".to_string()),
        relay_pubkey: Some("relay-pubkey".to_string()),
        relay_expires_at: Some(50),
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("10.0.0.33:51820"),
        100,
    )
    .expect("planned tunnel peers");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "203.0.113.20:51820");
}

#[test]
fn local_relay_session_overrides_runtime_endpoint() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);
    let relay_sessions = HashMap::from([(
        participant.clone(),
        ActiveRelaySession {
            relay_pubkey: "relay-pubkey".to_string(),
            local_ingress_endpoint: "198.51.100.30:40001".to_string(),
            advertised_ingress_endpoint: "198.51.100.30:40002".to_string(),
            granted_at: 100,
            verified_at: Some(101),
            expires_at: 500,
        },
    )]);
    let effective =
        crate::effective_peer_announcements_for_runtime(&announcements, &relay_sessions, 100);

    assert_eq!(
        effective
            .get(&participant)
            .and_then(|announcement| announcement.relay_endpoint.as_deref()),
        Some("198.51.100.30:40001")
    );

    let selected = planned_tunnel_peers(
        &config,
        None,
        &effective,
        &mut PeerPathBook::default(),
        Some("10.0.0.33:51820"),
        100,
    )
    .expect("planned tunnel peers");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "198.51.100.30:40001");
}

#[test]
fn relay_endpoint_preempts_recent_failed_direct_selection() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let direct_only = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key.clone(),
        endpoint: "10.203.1.11:51820".to_string(),
        local_endpoint: Some("10.203.1.11:51820".to_string()),
        public_endpoint: Some("10.203.1.11:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 100,
    };

    let direct_and_relay = PeerAnnouncement {
        relay_endpoint: Some("10.203.1.2:40001".to_string()),
        relay_pubkey: Some("relay-pubkey".to_string()),
        relay_expires_at: Some(500),
        ..direct_only.clone()
    };

    let mut path_book = PeerPathBook::default();
    let own_local_endpoints = vec!["10.203.1.10:51820".to_string()];
    path_book.refresh_from_announcement(participant.clone(), &direct_only, 100);
    let initially_selected = path_book
        .select_endpoint_for_local_endpoints(
            &participant,
            &direct_only,
            &own_local_endpoints,
            100,
            crate::PEER_PATH_RETRY_AFTER_SECS,
        )
        .expect("initial endpoint");
    assert_eq!(initially_selected, "10.203.1.11:51820");
    path_book.note_selected(participant.clone(), &initially_selected, 100);

    path_book.refresh_from_announcement(participant.clone(), &direct_and_relay, 101);
    let selected_before_retry = path_book
        .select_endpoint_for_local_endpoints(
            &participant,
            &direct_and_relay,
            &own_local_endpoints,
            101,
            crate::PEER_PATH_RETRY_AFTER_SECS,
        )
        .expect("relay endpoint");

    assert_eq!(selected_before_retry, "10.203.1.11:51820");

    let selected_with_relay = path_book
        .select_endpoint_for_local_endpoints(
            &participant,
            &direct_and_relay,
            &own_local_endpoints,
            106,
            crate::PEER_PATH_RETRY_AFTER_SECS,
        )
        .expect("relay endpoint after retry window");

    assert_eq!(selected_with_relay, "10.203.1.2:40001");
}

#[test]
fn relay_candidates_for_participant_skip_self_target_and_limit_count() {
    let participant = "11".repeat(32);
    let own_pubkey = "22".repeat(32);
    let relay_pubkeys = vec![
        participant.clone(),
        own_pubkey.clone(),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
        "66".repeat(32),
    ];

    let selected = crate::relay_candidates_for_participant(
        &relay_pubkeys,
        &participant,
        Some(&own_pubkey),
        &HashMap::new(),
        &HashMap::new(),
        100,
    );

    assert_eq!(
        selected,
        vec![
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "5555555555555555555555555555555555555555555555555555555555555555",
        ]
    );
}

#[test]
fn accept_relay_allocation_grant_queues_standby_after_first_activation() {
    let participant = "11".repeat(32);
    let mut pending_requests = HashMap::from([
        (
            "req-a".to_string(),
            PendingRelayRequest {
                participant: participant.clone(),
                relay_pubkey: "relay-a".to_string(),
                requested_at: 100,
            },
        ),
        (
            "req-b".to_string(),
            PendingRelayRequest {
                participant: participant.clone(),
                relay_pubkey: "relay-b".to_string(),
                requested_at: 100,
            },
        ),
    ]);
    let mut relay_sessions = HashMap::new();
    let mut standby_relay_sessions = HashMap::new();
    let relay_failures = HashMap::new();

    let accepted = crate::accept_relay_allocation_grant(
        RelayAllocationGranted {
            request_id: "req-a".to_string(),
            network_id: "mesh-1".to_string(),
            relay_pubkey: "relay-a".to_string(),
            requester_ingress_endpoint: "198.51.100.10:41001".to_string(),
            target_ingress_endpoint: "198.51.100.10:41002".to_string(),
            expires_at: 500,
        },
        &mut pending_requests,
        &mut relay_sessions,
        &mut standby_relay_sessions,
        &relay_failures,
        200,
    );

    assert_eq!(accepted, RelayGrantAction::Activated(participant.clone()));
    assert_eq!(
        relay_sessions
            .get(&participant)
            .map(|session| session.relay_pubkey.as_str()),
        Some("relay-a")
    );
    assert_eq!(pending_requests.len(), 1);

    pending_requests.insert(
        "req-c".to_string(),
        PendingRelayRequest {
            participant: participant.clone(),
            relay_pubkey: "relay-c".to_string(),
            requested_at: 200,
        },
    );
    let queued = crate::accept_relay_allocation_grant(
        RelayAllocationGranted {
            request_id: "req-b".to_string(),
            network_id: "mesh-1".to_string(),
            relay_pubkey: "relay-b".to_string(),
            requester_ingress_endpoint: "198.51.100.11:42001".to_string(),
            target_ingress_endpoint: "198.51.100.11:42002".to_string(),
            expires_at: 500,
        },
        &mut pending_requests,
        &mut relay_sessions,
        &mut standby_relay_sessions,
        &relay_failures,
        201,
    );

    assert_eq!(queued, RelayGrantAction::QueuedStandby(participant.clone()));
    assert_eq!(
        relay_sessions
            .get(&participant)
            .map(|session| session.relay_pubkey.as_str()),
        Some("relay-a")
    );
    assert_eq!(
        standby_relay_sessions
            .get(&participant)
            .expect("standby relay")
            .iter()
            .map(|session| session.relay_pubkey.as_str())
            .collect::<Vec<_>>(),
        vec!["relay-b"]
    );
}

#[test]
fn reconcile_active_relay_sessions_promotes_verified_standby_after_timeout() {
    let participant = "11".repeat(32);
    let peer_keys = generate_keypair();
    let announcement = sample_peer_announcement(peer_keys.public_key.clone());
    let mut presence = PeerPresenceBook::default();
    assert!(presence.apply_signal(
        participant.clone(),
        SignalPayload::Announce(announcement.clone()),
        100,
    ));

    let mut relay_sessions = HashMap::from([(
        participant.clone(),
        ActiveRelaySession {
            relay_pubkey: "relay-a".to_string(),
            local_ingress_endpoint: "198.51.100.10:41001".to_string(),
            advertised_ingress_endpoint: "198.51.100.10:41002".to_string(),
            granted_at: 200,
            verified_at: None,
            expires_at: 500,
        },
    )]);
    let mut standby_relay_sessions = HashMap::from([(
        participant.clone(),
        vec![ActiveRelaySession {
            relay_pubkey: "relay-b".to_string(),
            local_ingress_endpoint: "198.51.100.20:42001".to_string(),
            advertised_ingress_endpoint: "198.51.100.20:42002".to_string(),
            granted_at: 201,
            verified_at: None,
            expires_at: 500,
        }],
    )]);
    let mut relay_failures = HashMap::new();
    let mut relay_provider_verifications = HashMap::new();
    let mut pending_requests = HashMap::from([(
        "req-z".to_string(),
        PendingRelayRequest {
            participant: participant.clone(),
            relay_pubkey: "relay-z".to_string(),
            requested_at: 205,
        },
    )]);

    let changed = crate::reconcile_active_relay_sessions(
        &presence,
        None,
        &mut relay_sessions,
        &mut standby_relay_sessions,
        &mut relay_failures,
        &mut relay_provider_verifications,
        &mut pending_requests,
        200 + crate::RELAY_SESSION_VERIFY_TIMEOUT_SECS,
    );

    assert_eq!(changed, vec![participant.clone()]);
    assert_eq!(
        relay_sessions
            .get(&participant)
            .map(|session| session.relay_pubkey.as_str()),
        Some("relay-b")
    );
    assert_eq!(
        relay_sessions
            .get(&participant)
            .map(|session| session.granted_at),
        Some(200 + crate::RELAY_SESSION_VERIFY_TIMEOUT_SECS)
    );
    assert!(pending_requests.is_empty());
    assert!(crate::relay_is_in_failure_cooldown(
        &relay_failures,
        &participant,
        "relay-a",
        200 + crate::RELAY_SESSION_VERIFY_TIMEOUT_SECS,
    ));
}

#[test]
fn relay_candidates_for_participant_skip_cooled_down_relays() {
    let participant = "11".repeat(32);
    let relay_pubkeys = vec!["33".repeat(32), "44".repeat(32), "55".repeat(32)];
    let mut relay_failures = HashMap::new();
    relay_failures.insert(
        format!(
            "{}:{}",
            participant, "3333333333333333333333333333333333333333333333333333333333333333"
        ),
        500,
    );

    let selected = crate::relay_candidates_for_participant(
        &relay_pubkeys,
        &participant,
        None,
        &relay_failures,
        &HashMap::new(),
        400,
    );

    assert_eq!(
        selected,
        vec![
            "4444444444444444444444444444444444444444444444444444444444444444",
            "5555555555555555555555555555555555555555555555555555555555555555",
        ]
    );
}

#[test]
fn relay_candidates_prefer_recently_verified_providers() {
    let participant = "11".repeat(32);
    let relay_pubkeys = vec!["33".repeat(32), "44".repeat(32), "55".repeat(32)];
    let relay_provider_verifications = HashMap::from([
        (
            "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            RelayProviderVerification {
                verified_at: Some(250),
                failure_cooldown_until: None,
                last_failure_at: None,
                last_probe_attempt_at: Some(250),
                consecutive_failures: 0,
            },
        ),
        (
            "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            RelayProviderVerification {
                verified_at: Some(200),
                failure_cooldown_until: None,
                last_failure_at: None,
                last_probe_attempt_at: Some(200),
                consecutive_failures: 0,
            },
        ),
    ]);

    let selected = crate::relay_candidates_for_participant(
        &relay_pubkeys,
        &participant,
        None,
        &HashMap::new(),
        &relay_provider_verifications,
        300,
    );

    assert_eq!(
        selected,
        vec![
            "4444444444444444444444444444444444444444444444444444444444444444",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "5555555555555555555555555555555555555555555555555555555555555555",
        ]
    );
}

#[test]
fn relay_rejection_marks_provider_and_participant_failed() {
    let participant = "11".repeat(32);
    let relay_pubkey = "33".repeat(32);
    let now = 200;
    let mut pending_requests = HashMap::from([(
        "req-a".to_string(),
        PendingRelayRequest {
            participant: participant.clone(),
            relay_pubkey: relay_pubkey.clone(),
            requested_at: 100,
        },
    )]);
    let mut relay_failures = HashMap::new();
    let mut relay_provider_verifications = HashMap::new();

    let changed = crate::accept_relay_allocation_rejection(
        RelayAllocationRejected {
            request_id: "req-a".to_string(),
            network_id: "mesh-1".to_string(),
            relay_pubkey: relay_pubkey.clone(),
            reason: RelayAllocationRejectReason::OverCapacity,
            retry_after_secs: Some(90),
        },
        &mut pending_requests,
        &mut relay_failures,
        &mut relay_provider_verifications,
        now,
    );

    assert_eq!(changed.as_deref(), Some(participant.as_str()));
    assert!(pending_requests.is_empty());
    assert!(crate::relay_is_in_failure_cooldown(
        &relay_failures,
        &participant,
        &relay_pubkey,
        now
    ));
    assert!(crate::relay_provider_in_failure_cooldown(
        &relay_provider_verifications,
        &relay_pubkey,
        now
    ));
    assert_eq!(
        relay_provider_verifications
            .get(&relay_pubkey)
            .and_then(|verification| verification.failure_cooldown_until),
        Some(now + 90)
    );
}
