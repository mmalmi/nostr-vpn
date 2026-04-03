use super::*;

pub(crate) fn relay_session_is_active(session: &ActiveRelaySession, now: u64) -> bool {
    session.expires_at > now
        && !session.local_ingress_endpoint.trim().is_empty()
        && !session.advertised_ingress_endpoint.trim().is_empty()
}

pub(crate) fn relay_session_is_verified(session: &ActiveRelaySession) -> bool {
    session.verified_at.is_some()
}

pub(crate) fn relay_session_verification_timed_out(session: &ActiveRelaySession, now: u64) -> bool {
    !relay_session_is_verified(session)
        && now.saturating_sub(session.granted_at) >= RELAY_SESSION_VERIFY_TIMEOUT_SECS
}

pub(crate) fn relay_failure_key(participant: &str, relay_pubkey: &str) -> String {
    format!("{participant}:{relay_pubkey}")
}

pub(crate) fn relay_is_in_failure_cooldown(
    relay_failures: &RelayFailureCooldowns,
    participant: &str,
    relay_pubkey: &str,
    now: u64,
) -> bool {
    relay_failures
        .get(&relay_failure_key(participant, relay_pubkey))
        .is_some_and(|cooldown_until| *cooldown_until > now)
}

pub(crate) fn note_failed_relay(
    relay_failures: &mut RelayFailureCooldowns,
    participant: &str,
    relay_pubkey: &str,
    now: u64,
) {
    relay_failures.insert(
        relay_failure_key(participant, relay_pubkey),
        now + RELAY_FAILED_RETRY_AFTER_SECS,
    );
}

pub(crate) fn prune_relay_failure_cooldowns(
    relay_failures: &mut RelayFailureCooldowns,
    now: u64,
) -> bool {
    let before = relay_failures.len();
    relay_failures.retain(|_, cooldown_until| *cooldown_until > now);
    relay_failures.len() != before
}

pub(crate) fn relay_provider_in_failure_cooldown(
    relay_provider_verifications: &RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
) -> bool {
    relay_provider_verifications
        .get(relay_pubkey)
        .and_then(|verification| verification.failure_cooldown_until)
        .is_some_and(|cooldown_until| cooldown_until > now)
}

pub(crate) fn note_verified_relay_provider(
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
) {
    let verification = relay_provider_verifications
        .entry(relay_pubkey.to_string())
        .or_default();
    verification.verified_at = Some(now);
    verification.failure_cooldown_until = None;
    verification.last_failure_at = None;
    verification.last_probe_attempt_at = Some(now);
    verification.consecutive_failures = 0;
}

pub(crate) fn note_relay_provider_probe_attempt(
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
) {
    relay_provider_verifications
        .entry(relay_pubkey.to_string())
        .or_default()
        .last_probe_attempt_at = Some(now);
}

pub(crate) fn note_failed_relay_provider(
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
    retry_after_secs: Option<u64>,
) {
    let verification = relay_provider_verifications
        .entry(relay_pubkey.to_string())
        .or_default();
    verification.last_failure_at = Some(now);
    verification.last_probe_attempt_at = Some(now);
    verification.consecutive_failures = verification.consecutive_failures.saturating_add(1);
    let base = retry_after_secs
        .unwrap_or(RELAY_FAILED_RETRY_AFTER_SECS)
        .max(1);
    let multiplier_shift = verification.consecutive_failures.saturating_sub(1).min(4);
    let multiplier = 1_u64 << multiplier_shift;
    let cooldown = base
        .saturating_mul(multiplier)
        .min(RELAY_PROVIDER_FAILURE_MAX_COOLDOWN_SECS);
    verification.failure_cooldown_until = Some(now + cooldown);
}

pub(crate) fn relay_provider_probe_due(
    relay_provider_verifications: &RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
) -> bool {
    let Some(verification) = relay_provider_verifications.get(relay_pubkey) else {
        return true;
    };
    if verification.verified_at.is_some() {
        return false;
    }
    if verification
        .failure_cooldown_until
        .is_some_and(|cooldown_until| cooldown_until > now)
    {
        return false;
    }
    verification
        .last_probe_attempt_at
        .is_none_or(|last_probe_at| {
            now.saturating_sub(last_probe_at) >= RELAY_PROVIDER_PROBE_RETRY_AFTER_SECS
        })
}

pub(crate) fn prune_relay_provider_verifications(
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    now: u64,
) -> bool {
    let before = relay_provider_verifications.len();
    relay_provider_verifications.retain(|_, verification| {
        if verification
            .failure_cooldown_until
            .is_some_and(|cooldown_until| cooldown_until <= now)
        {
            verification.failure_cooldown_until = None;
        }
        verification.verified_at.is_some()
            || verification.failure_cooldown_until.is_some()
            || verification.last_failure_at.is_some()
            || verification.last_probe_attempt_at.is_some()
    });
    relay_provider_verifications.len() != before
}

pub(crate) fn relay_provider_sort_key(
    relay_provider_verifications: &RelayProviderVerificationBook,
    relay_pubkey: &str,
    now: u64,
) -> (u8, std::cmp::Reverse<u64>, u64) {
    if let Some(verification) = relay_provider_verifications.get(relay_pubkey) {
        if verification
            .failure_cooldown_until
            .is_some_and(|cooldown_until| cooldown_until > now)
        {
            return (
                2,
                std::cmp::Reverse(0),
                verification.last_failure_at.unwrap_or(0),
            );
        }
        if let Some(verified_at) = verification.verified_at {
            return (
                0,
                std::cmp::Reverse(verified_at),
                verification.last_failure_at.unwrap_or(0),
            );
        }
        return (
            1,
            std::cmp::Reverse(0),
            verification.last_failure_at.unwrap_or(0),
        );
    }
    (1, std::cmp::Reverse(0), 0)
}

pub(crate) fn prune_active_relay_sessions(
    relay_sessions: &mut HashMap<String, ActiveRelaySession>,
    now: u64,
) -> bool {
    let before = relay_sessions.len();
    relay_sessions.retain(|_, session| relay_session_is_active(session, now));
    relay_sessions.len() != before
}

pub(crate) fn prune_pending_relay_requests(
    pending_requests: &mut HashMap<String, PendingRelayRequest>,
    now: u64,
) -> bool {
    let before = pending_requests.len();
    pending_requests
        .retain(|_, request| now.saturating_sub(request.requested_at) < RELAY_REQUEST_TIMEOUT_SECS);
    pending_requests.len() != before
}

pub(crate) fn prune_standby_relay_sessions(
    standby_relay_sessions: &mut HashMap<String, Vec<ActiveRelaySession>>,
    now: u64,
) -> bool {
    let before = standby_relay_sessions.len();
    standby_relay_sessions.retain(|_, sessions| {
        sessions.retain(|session| relay_session_is_active(session, now));
        !sessions.is_empty()
    });
    standby_relay_sessions.len() != before
}

pub(crate) fn active_relay_session_from_grant(
    granted: RelayAllocationGranted,
    granted_at: u64,
) -> ActiveRelaySession {
    ActiveRelaySession {
        relay_pubkey: granted.relay_pubkey,
        local_ingress_endpoint: granted.requester_ingress_endpoint,
        advertised_ingress_endpoint: granted.target_ingress_endpoint,
        granted_at,
        verified_at: None,
        expires_at: granted.expires_at,
    }
}

pub(crate) fn relay_sessions_match(left: &ActiveRelaySession, right: &ActiveRelaySession) -> bool {
    left.relay_pubkey == right.relay_pubkey
        && left.local_ingress_endpoint == right.local_ingress_endpoint
        && left.advertised_ingress_endpoint == right.advertised_ingress_endpoint
}

pub(crate) fn queue_standby_relay_session(
    standby_relay_sessions: &mut HashMap<String, Vec<ActiveRelaySession>>,
    participant: &str,
    session: ActiveRelaySession,
) -> bool {
    let sessions = standby_relay_sessions
        .entry(participant.to_string())
        .or_default();
    if sessions
        .iter()
        .any(|existing| relay_sessions_match(existing, &session))
    {
        return false;
    }
    sessions.push(session);
    true
}

pub(crate) fn pop_next_standby_relay_session(
    standby_relay_sessions: &mut HashMap<String, Vec<ActiveRelaySession>>,
    relay_failures: &RelayFailureCooldowns,
    participant: &str,
    now: u64,
) -> Option<ActiveRelaySession> {
    let sessions = standby_relay_sessions.get_mut(participant)?;
    let next_index = sessions.iter().position(|session| {
        relay_session_is_active(session, now)
            && !relay_is_in_failure_cooldown(
                relay_failures,
                participant,
                &session.relay_pubkey,
                now,
            )
    })?;
    let mut session = sessions.remove(next_index);
    session.granted_at = now;
    session.verified_at = None;
    if sessions.is_empty() {
        standby_relay_sessions.remove(participant);
    }
    Some(session)
}

pub(crate) fn runtime_peer_verifies_relay_session(
    participant: &str,
    presence: &PeerPresenceBook,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    session: &ActiveRelaySession,
    now: u64,
) -> Option<u64> {
    let announcement = presence.announcement_for(participant)?;
    let runtime_peer = peer_runtime_lookup(announcement, runtime_peers)?;
    if runtime_peer.endpoint.as_deref()? != session.local_ingress_endpoint {
        return None;
    }
    let handshake_at = runtime_peer.last_handshake_at(now)?;
    (handshake_at >= session.granted_at).then_some(handshake_at)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_active_relay_sessions(
    presence: &PeerPresenceBook,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    relay_sessions: &mut HashMap<String, ActiveRelaySession>,
    standby_relay_sessions: &mut HashMap<String, Vec<ActiveRelaySession>>,
    relay_failures: &mut RelayFailureCooldowns,
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    pending_requests: &mut HashMap<String, PendingRelayRequest>,
    now: u64,
) -> Vec<String> {
    let participants = relay_sessions.keys().cloned().collect::<Vec<_>>();
    let mut changed = Vec::new();

    for participant in participants {
        let Some(session_snapshot) = relay_sessions.get(&participant).cloned() else {
            continue;
        };

        if !relay_session_is_active(&session_snapshot, now) {
            relay_sessions.remove(&participant);
            if let Some(next_session) = pop_next_standby_relay_session(
                standby_relay_sessions,
                relay_failures,
                &participant,
                now,
            ) {
                relay_sessions.insert(participant.clone(), next_session);
            } else {
                pending_requests.retain(|_, request| request.participant != participant);
            }
            changed.push(participant);
            continue;
        }

        if let Some(verified_at) = runtime_peer_verifies_relay_session(
            &participant,
            presence,
            runtime_peers,
            &session_snapshot,
            now,
        ) {
            note_verified_relay_provider(
                relay_provider_verifications,
                &session_snapshot.relay_pubkey,
                verified_at,
            );
            if let Some(session) = relay_sessions.get_mut(&participant)
                && session.verified_at.is_none()
            {
                session.verified_at = Some(verified_at);
            }
            continue;
        }

        if !relay_session_verification_timed_out(&session_snapshot, now) {
            continue;
        }

        relay_sessions.remove(&participant);
        note_failed_relay(
            relay_failures,
            &participant,
            &session_snapshot.relay_pubkey,
            now,
        );
        note_failed_relay_provider(
            relay_provider_verifications,
            &session_snapshot.relay_pubkey,
            now,
            None,
        );
        pending_requests.retain(|_, request| request.participant != participant);
        if let Some(next_session) = pop_next_standby_relay_session(
            standby_relay_sessions,
            relay_failures,
            &participant,
            now,
        ) {
            relay_sessions.insert(participant.clone(), next_session);
        }
        changed.push(participant);
    }

    changed.sort();
    changed.dedup();
    changed
}
