use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::relay::{
    NatAssistOperatorState, RelayAllocationRejectReason, RelayOperatorSessionState,
    RelayOperatorState, ServiceOperatorState,
};
use tokio::time::Instant;

use crate::DEFAULT_STATE_FILE_NAME;

use super::unix_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayServiceLimits {
    pub(crate) max_active_sessions: usize,
    pub(crate) max_sessions_per_requester: usize,
    pub(crate) max_bytes_per_session: u64,
    pub(crate) max_forward_bps: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct SessionForwardingState {
    forward_window: Option<ForwardWindow>,
    total_forwarded_bytes: u64,
    closed: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForwardWindow {
    last_refill: Instant,
    available_bytes: u64,
}

#[derive(Debug, Default)]
pub(crate) struct RelayRuntimeState {
    pub(crate) relay_pubkey: String,
    pub(crate) advertised_endpoint: String,
    pub(crate) total_sessions_served: u64,
    pub(crate) total_forwarded_bytes: u64,
    pub(crate) current_forward_bps: u64,
    pub(crate) last_rate_sample_at: u64,
    pub(crate) last_rate_sample_bytes: u64,
    pub(crate) known_peer_pubkeys: HashSet<String>,
    pub(crate) active_sessions: HashMap<String, RelayOperatorSessionState>,
}

impl RelayRuntimeState {
    pub(crate) fn prune_expired_sessions(&mut self, now: u64) {
        self.active_sessions
            .retain(|_, session| session.expires_at > now);
    }

    pub(crate) fn allocation_rejection_for_requester(
        &mut self,
        requester_pubkey: &str,
        now: u64,
        limits: &RelayServiceLimits,
    ) -> Option<(RelayAllocationRejectReason, Option<u64>)> {
        self.prune_expired_sessions(now);

        if self.active_sessions.len() >= limits.max_active_sessions {
            return Some((RelayAllocationRejectReason::OverCapacity, Some(30)));
        }

        let requester_sessions = self
            .active_sessions
            .values()
            .filter(|session| session.requester_pubkey == requester_pubkey)
            .count();
        if requester_sessions >= limits.max_sessions_per_requester {
            return Some((
                RelayAllocationRejectReason::TooManySessionsForRequester,
                Some(60),
            ));
        }

        None
    }

    pub(crate) fn note_session_started(&mut self, session: RelayOperatorSessionState) {
        self.prune_expired_sessions(unix_timestamp());
        self.total_sessions_served = self.total_sessions_served.saturating_add(1);
        self.known_peer_pubkeys
            .insert(session.requester_pubkey.clone());
        self.known_peer_pubkeys
            .insert(session.target_pubkey.clone());
        self.active_sessions
            .insert(session.request_id.clone(), session);
    }

    pub(crate) fn note_forwarded_bytes(
        &mut self,
        request_id: &str,
        requester_leg: bool,
        bytes: u64,
    ) {
        self.total_forwarded_bytes = self.total_forwarded_bytes.saturating_add(bytes);
        if let Some(session) = self.active_sessions.get_mut(request_id) {
            if requester_leg {
                session.bytes_from_requester = session.bytes_from_requester.saturating_add(bytes);
            } else {
                session.bytes_from_target = session.bytes_from_target.saturating_add(bytes);
            }
        }
    }

    pub(crate) fn snapshot(&mut self, now: u64) -> RelayOperatorState {
        self.prune_expired_sessions(now);

        let elapsed = now.saturating_sub(self.last_rate_sample_at);
        if elapsed > 0 {
            let bytes_delta = self
                .total_forwarded_bytes
                .saturating_sub(self.last_rate_sample_bytes);
            self.current_forward_bps = bytes_delta.checked_div(elapsed).unwrap_or(0);
            self.last_rate_sample_at = now;
            self.last_rate_sample_bytes = self.total_forwarded_bytes;
        } else if self.last_rate_sample_at == 0 {
            self.last_rate_sample_at = now;
            self.last_rate_sample_bytes = self.total_forwarded_bytes;
        }

        let mut known_peer_pubkeys = self.known_peer_pubkeys.iter().cloned().collect::<Vec<_>>();
        known_peer_pubkeys.sort();

        let mut active_sessions = self.active_sessions.values().cloned().collect::<Vec<_>>();
        active_sessions.sort_by(|left, right| {
            left.started_at
                .cmp(&right.started_at)
                .then_with(|| left.request_id.cmp(&right.request_id))
        });

        RelayOperatorState {
            updated_at: now,
            relay_pubkey: self.relay_pubkey.clone(),
            advertised_endpoint: self.advertised_endpoint.clone(),
            total_sessions_served: self.total_sessions_served,
            total_forwarded_bytes: self.total_forwarded_bytes,
            current_forward_bps: self.current_forward_bps,
            unique_peer_count: known_peer_pubkeys.len(),
            known_peer_pubkeys,
            active_sessions,
        }
    }
}

impl SessionForwardingState {
    pub(crate) fn allow_forward(
        &mut self,
        limits: &RelayServiceLimits,
        now: Instant,
        bytes: usize,
    ) -> Result<(), RelayAllocationRejectReason> {
        if self.closed {
            return Err(RelayAllocationRejectReason::ByteLimitExceeded);
        }

        let bytes = bytes as u64;
        if self.total_forwarded_bytes.saturating_add(bytes) > limits.max_bytes_per_session {
            self.closed = true;
            return Err(RelayAllocationRejectReason::ByteLimitExceeded);
        }

        if let Some(max_forward_bps) = limits.max_forward_bps {
            let burst = max_forward_bps.max(bytes);
            let window = self.forward_window.get_or_insert(ForwardWindow {
                last_refill: now,
                available_bytes: burst,
            });
            let elapsed = now
                .saturating_duration_since(window.last_refill)
                .as_secs_f64();
            if elapsed > 0.0 {
                let refill = (elapsed * max_forward_bps as f64) as u64;
                window.available_bytes = window.available_bytes.saturating_add(refill).min(burst);
                window.last_refill = now;
            }
            if window.available_bytes < bytes {
                return Err(RelayAllocationRejectReason::RateLimited);
            }
            window.available_bytes = window.available_bytes.saturating_sub(bytes);
        }

        self.total_forwarded_bytes = self.total_forwarded_bytes.saturating_add(bytes);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct NatAssistRuntimeState {
    pub(crate) advertised_endpoint: String,
    pub(crate) total_discovery_requests: u64,
    pub(crate) total_punch_requests: u64,
    pub(crate) current_request_bps: u64,
    pub(crate) last_rate_sample_at: u64,
    pub(crate) last_rate_sample_requests: u64,
    pub(crate) known_clients: HashSet<String>,
}

impl NatAssistRuntimeState {
    pub(crate) fn note_discovery_request(&mut self, src: std::net::SocketAddr) {
        self.total_discovery_requests = self.total_discovery_requests.saturating_add(1);
        self.known_clients.insert(src.ip().to_string());
    }

    pub(crate) fn note_punch_request(&mut self, src: std::net::SocketAddr) {
        self.total_punch_requests = self.total_punch_requests.saturating_add(1);
        self.known_clients.insert(src.ip().to_string());
    }

    pub(crate) fn snapshot(&mut self, now: u64) -> NatAssistOperatorState {
        let total_requests = self
            .total_discovery_requests
            .saturating_add(self.total_punch_requests);
        let elapsed = now.saturating_sub(self.last_rate_sample_at);
        if elapsed > 0 {
            let requests_delta = total_requests.saturating_sub(self.last_rate_sample_requests);
            self.current_request_bps = requests_delta.checked_div(elapsed).unwrap_or(0);
            self.last_rate_sample_at = now;
            self.last_rate_sample_requests = total_requests;
        } else if self.last_rate_sample_at == 0 {
            self.last_rate_sample_at = now;
            self.last_rate_sample_requests = total_requests;
        }

        NatAssistOperatorState {
            updated_at: now,
            advertised_endpoint: self.advertised_endpoint.clone(),
            total_discovery_requests: self.total_discovery_requests,
            total_punch_requests: self.total_punch_requests,
            current_request_bps: self.current_request_bps,
            unique_client_count: self.known_clients.len(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ServiceRuntimeState {
    pub(crate) operator_pubkey: String,
    pub(crate) relay: Option<RelayRuntimeState>,
    pub(crate) nat_assist: Option<NatAssistRuntimeState>,
}

impl ServiceRuntimeState {
    pub(crate) fn note_session_started(&mut self, session: RelayOperatorSessionState) {
        if let Some(relay) = self.relay.as_mut() {
            relay.note_session_started(session);
        }
    }

    pub(crate) fn note_forwarded_bytes(
        &mut self,
        request_id: &str,
        requester_leg: bool,
        bytes: u64,
    ) {
        if let Some(relay) = self.relay.as_mut() {
            relay.note_forwarded_bytes(request_id, requester_leg, bytes);
        }
    }

    pub(crate) fn note_discovery_request(&mut self, src: std::net::SocketAddr) {
        if let Some(nat_assist) = self.nat_assist.as_mut() {
            nat_assist.note_discovery_request(src);
        }
    }

    pub(crate) fn note_punch_request(&mut self, src: std::net::SocketAddr) {
        if let Some(nat_assist) = self.nat_assist.as_mut() {
            nat_assist.note_punch_request(src);
        }
    }

    pub(crate) fn snapshot(&mut self, now: u64) -> ServiceOperatorState {
        ServiceOperatorState {
            updated_at: now,
            operator_pubkey: self.operator_pubkey.clone(),
            relay: self.relay.as_mut().map(|relay| relay.snapshot(now)),
            nat_assist: self
                .nat_assist
                .as_mut()
                .map(|nat_assist| nat_assist.snapshot(now)),
        }
    }
}

pub(crate) fn relay_runtime_state_from_snapshot(
    snapshot: RelayOperatorState,
    relay_pubkey: String,
    advertised_endpoint: String,
    now: u64,
) -> RelayRuntimeState {
    RelayRuntimeState {
        relay_pubkey,
        advertised_endpoint,
        total_sessions_served: snapshot.total_sessions_served,
        total_forwarded_bytes: snapshot.total_forwarded_bytes,
        current_forward_bps: 0,
        last_rate_sample_at: now,
        last_rate_sample_bytes: snapshot.total_forwarded_bytes,
        known_peer_pubkeys: snapshot.known_peer_pubkeys.into_iter().collect(),
        active_sessions: HashMap::new(),
    }
}

pub(crate) fn nat_assist_runtime_state_from_snapshot(
    snapshot: NatAssistOperatorState,
    advertised_endpoint: String,
    now: u64,
) -> NatAssistRuntimeState {
    let total_requests = snapshot
        .total_discovery_requests
        .saturating_add(snapshot.total_punch_requests);
    NatAssistRuntimeState {
        advertised_endpoint,
        total_discovery_requests: snapshot.total_discovery_requests,
        total_punch_requests: snapshot.total_punch_requests,
        current_request_bps: 0,
        last_rate_sample_at: now,
        last_rate_sample_requests: total_requests,
        known_clients: HashSet::new(),
    }
}

pub(crate) fn load_runtime_state(
    path: &Path,
    operator_pubkey: String,
    relay_endpoint: Option<String>,
    nat_assist_endpoint: Option<String>,
) -> ServiceRuntimeState {
    let now = unix_timestamp();
    let Ok(raw) = fs::read(path) else {
        return ServiceRuntimeState {
            operator_pubkey: operator_pubkey.clone(),
            relay: relay_endpoint.map(|advertised_endpoint| RelayRuntimeState {
                relay_pubkey: operator_pubkey.clone(),
                advertised_endpoint,
                last_rate_sample_at: now,
                ..RelayRuntimeState::default()
            }),
            nat_assist: nat_assist_endpoint.map(|advertised_endpoint| NatAssistRuntimeState {
                advertised_endpoint,
                last_rate_sample_at: now,
                ..NatAssistRuntimeState::default()
            }),
        };
    };

    match serde_json::from_slice::<ServiceOperatorState>(&raw) {
        Ok(snapshot)
            if snapshot.relay.is_some()
                || snapshot.nat_assist.is_some()
                || !snapshot.operator_pubkey.trim().is_empty() =>
        {
            ServiceRuntimeState {
                operator_pubkey: operator_pubkey.clone(),
                relay: relay_endpoint.map(|advertised_endpoint| {
                    let advertised_endpoint_fallback = advertised_endpoint.clone();
                    snapshot.relay.map_or_else(
                        || RelayRuntimeState {
                            relay_pubkey: operator_pubkey.clone(),
                            advertised_endpoint: advertised_endpoint_fallback,
                            last_rate_sample_at: now,
                            ..RelayRuntimeState::default()
                        },
                        |relay| {
                            relay_runtime_state_from_snapshot(
                                relay,
                                operator_pubkey.clone(),
                                advertised_endpoint,
                                now,
                            )
                        },
                    )
                }),
                nat_assist: nat_assist_endpoint.map(|advertised_endpoint| {
                    let advertised_endpoint_fallback = advertised_endpoint.clone();
                    snapshot.nat_assist.map_or_else(
                        || NatAssistRuntimeState {
                            advertised_endpoint: advertised_endpoint_fallback,
                            last_rate_sample_at: now,
                            ..NatAssistRuntimeState::default()
                        },
                        |nat_assist| {
                            nat_assist_runtime_state_from_snapshot(
                                nat_assist,
                                advertised_endpoint,
                                now,
                            )
                        },
                    )
                }),
            }
        }
        Err(_) | Ok(_) => match serde_json::from_slice::<RelayOperatorState>(&raw) {
            Ok(snapshot) => ServiceRuntimeState {
                operator_pubkey: operator_pubkey.clone(),
                relay: relay_endpoint.map(|advertised_endpoint| {
                    relay_runtime_state_from_snapshot(
                        snapshot,
                        operator_pubkey.clone(),
                        advertised_endpoint,
                        now,
                    )
                }),
                nat_assist: nat_assist_endpoint.map(|advertised_endpoint| NatAssistRuntimeState {
                    advertised_endpoint,
                    last_rate_sample_at: now,
                    ..NatAssistRuntimeState::default()
                }),
            },
            Err(error) => {
                eprintln!(
                    "relay-service: failed to parse existing state file {}: {error}",
                    path.display()
                );
                ServiceRuntimeState {
                    operator_pubkey: operator_pubkey.clone(),
                    relay: relay_endpoint.map(|advertised_endpoint| RelayRuntimeState {
                        relay_pubkey: operator_pubkey.clone(),
                        advertised_endpoint,
                        last_rate_sample_at: now,
                        ..RelayRuntimeState::default()
                    }),
                    nat_assist: nat_assist_endpoint.map(|advertised_endpoint| {
                        NatAssistRuntimeState {
                            advertised_endpoint,
                            last_rate_sample_at: now,
                            ..NatAssistRuntimeState::default()
                        }
                    }),
                }
            }
        },
    }
}

pub(crate) fn default_state_file_path() -> PathBuf {
    dirs::config_dir()
        .map(|dir| dir.join("nvpn").join(DEFAULT_STATE_FILE_NAME))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_FILE_NAME))
}

pub(crate) fn write_state_file(path: &Path, state: &ServiceOperatorState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_vec_pretty(state).context("failed to serialize relay state")?;
    write_runtime_file_atomically(path, &raw)?;
    set_private_state_file_permissions(path)?;
    Ok(())
}

fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime file has no parent: {}", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("relay-state"),
        std::process::id(),
        unix_timestamp()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temp runtime file {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn set_private_state_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set relay state file permissions on {}",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}
