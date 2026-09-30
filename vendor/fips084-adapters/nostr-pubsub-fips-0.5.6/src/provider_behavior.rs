use std::collections::{HashMap, VecDeque};

const SCORE_DECAY_INTERVAL_MS: u64 = 30_000;
const DISCONNECT_SCORE: u32 = 12;
const RECONNECT_COOLDOWN_MS: u64 = 60_000;
const UNIQUE_FILTER_MISMATCH_GRACE: u32 = 3;
const MAX_TRACKED_PROVIDERS: usize = 1_024;

#[derive(Clone, Copy)]
pub(super) enum ProviderViolation {
    MalformedFrame,
    UnansweredInventory,
    OutOfFilterEvent { repeated: bool },
}

#[derive(Default)]
struct ProviderState {
    score: u32,
    unique_filter_mismatches: u32,
    updated_at_ms: u64,
    cooldown_until_ms: u64,
}

#[derive(Default)]
pub(super) struct ProviderBehavior {
    peers: HashMap<String, ProviderState>,
    order: VecDeque<String>,
}

impl ProviderBehavior {
    /// Returns the new cooldown deadline when the objective local threshold is
    /// crossed. Scores decay and a few unique filter mismatches are tolerated
    /// for subscription races.
    pub(super) fn record(
        &mut self,
        peer_npub: &str,
        violation: ProviderViolation,
        now_ms: u64,
    ) -> Option<u64> {
        if !self.peers.contains_key(peer_npub) {
            while self.peers.len() >= MAX_TRACKED_PROVIDERS {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.peers.remove(&oldest);
            }
            self.order.push_back(peer_npub.to_string());
        }
        let state = self.peers.entry(peer_npub.to_string()).or_default();
        decay(state, now_ms);
        let points = match violation {
            ProviderViolation::MalformedFrame => 4,
            ProviderViolation::UnansweredInventory => 2,
            ProviderViolation::OutOfFilterEvent { repeated: true } => 1,
            ProviderViolation::OutOfFilterEvent { repeated: false } => {
                state.unique_filter_mismatches = state.unique_filter_mismatches.saturating_add(1);
                u32::from(state.unique_filter_mismatches > UNIQUE_FILTER_MISMATCH_GRACE)
            }
        };
        state.score = state.score.saturating_add(points);
        if state.score < DISCONNECT_SCORE || now_ms < state.cooldown_until_ms {
            return None;
        }
        state.cooldown_until_ms = now_ms.saturating_add(RECONNECT_COOLDOWN_MS);
        Some(state.cooldown_until_ms)
    }

    pub(super) fn is_in_cooldown(&mut self, peer_npub: &str, now_ms: u64) -> bool {
        let Some(state) = self.peers.get_mut(peer_npub) else {
            return false;
        };
        decay(state, now_ms);
        now_ms < state.cooldown_until_ms
    }
}

fn decay(state: &mut ProviderState, now_ms: u64) {
    if state.updated_at_ms == 0 {
        state.updated_at_ms = now_ms;
        return;
    }
    let elapsed = now_ms.saturating_sub(state.updated_at_ms);
    let steps = elapsed / SCORE_DECAY_INTERVAL_MS;
    if steps == 0 {
        return;
    }
    let steps = u32::try_from(steps).unwrap_or(u32::MAX);
    state.score = state.score.saturating_sub(steps);
    state.unique_filter_mismatches = state.unique_filter_mismatches.saturating_sub(steps);
    state.updated_at_ms = state
        .updated_at_ms
        .saturating_add(u64::from(steps).saturating_mul(SCORE_DECAY_INTERVAL_MS));
}

#[cfg(test)]
mod tests {
    use super::{ProviderBehavior, ProviderViolation, RECONNECT_COOLDOWN_MS};

    #[test]
    fn objective_abuse_disconnects_then_decays() {
        let mut behavior = ProviderBehavior::default();
        assert_eq!(
            behavior.record("peer", ProviderViolation::MalformedFrame, 1_000),
            None
        );
        assert_eq!(
            behavior.record("peer", ProviderViolation::MalformedFrame, 1_001),
            None
        );
        assert_eq!(
            behavior.record("peer", ProviderViolation::MalformedFrame, 1_002),
            Some(1_002 + RECONNECT_COOLDOWN_MS)
        );
        assert!(behavior.is_in_cooldown("peer", 1_003));
        assert!(!behavior.is_in_cooldown("peer", 1_002 + RECONNECT_COOLDOWN_MS));
    }

    #[test]
    fn one_filter_race_is_not_penalized() {
        let mut behavior = ProviderBehavior::default();
        for now_ms in 1..=3 {
            assert_eq!(
                behavior.record(
                    "peer",
                    ProviderViolation::OutOfFilterEvent { repeated: false },
                    now_ms,
                ),
                None
            );
        }
        for now_ms in 4..15 {
            assert_eq!(
                behavior.record(
                    "peer",
                    ProviderViolation::OutOfFilterEvent { repeated: false },
                    now_ms,
                ),
                None
            );
        }
        assert_eq!(
            behavior.record(
                "peer",
                ProviderViolation::OutOfFilterEvent { repeated: true },
                15,
            ),
            Some(15 + RECONNECT_COOLDOWN_MS)
        );
    }
}
