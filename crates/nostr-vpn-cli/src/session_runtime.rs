use super::*;

pub(crate) const DAEMON_STATE_PERSIST_INTERVAL_SECS: u64 = 5;
const DAEMON_PEER_MAX_FUTURE_SKEW_SECS: u64 = 2;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) const DAEMON_NETWORK_REFRESH_INTERVAL_SECS: u64 = 300;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) const DAEMON_NETWORK_REFRESH_INTERVAL_SECS: u64 = 1;
pub(crate) const DAEMON_NETWORK_EVENT_DEBOUNCE_MILLIS: u64 = 250;
pub(crate) const DAEMON_NETWORK_SETTLE_RECHECK_MILLIS: u64 = 200;
pub(crate) const DAEMON_NETWORK_SETTLE_RECHECK_ATTEMPTS: u8 = 60;
pub(crate) const DAEMON_NETWORK_REFRESH_RETRY_MILLIS: u64 = 100;
pub(crate) const DAEMON_NETWORK_REFRESH_RETRY_ATTEMPTS: u8 = 1;
pub(crate) const FIPS_LINK_EVENT_CONFIG_BUILD_TIMEOUT_MILLIS: u64 = 500;

pub(crate) fn daemon_wall_clock_unix_milliseconds() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) fn begin_platform_network_settle_rechecks(remaining: &mut u8) {
    *remaining = DAEMON_NETWORK_SETTLE_RECHECK_ATTEMPTS;
}

pub(crate) fn platform_network_event_receive_enabled(
    event_pending: bool,
    settle_rechecks_remaining: u8,
    event_deadline: &PlatformNetworkSampleDeadline,
) -> bool {
    !event_pending && settle_rechecks_remaining == 0 && !event_deadline.is_active()
}

pub(crate) fn platform_network_background_maintenance_enabled(
    event_deadline: &PlatformNetworkSampleDeadline,
) -> bool {
    !event_deadline.blocks_background_maintenance()
}

pub(crate) fn daemon_state_background_maintenance_enabled(
    event_deadline: &PlatformNetworkSampleDeadline,
    has_pending_control_request: bool,
) -> bool {
    !has_pending_control_request && platform_network_background_maintenance_enabled(event_deadline)
}

pub(crate) fn schedule_platform_network_event_sampling(
    event_deadline: &mut PlatformNetworkSampleDeadline,
    remaining: &mut u8,
) {
    begin_platform_network_settle_rechecks(remaining);
    event_deadline.reset_after(
        Duration::from_millis(DAEMON_NETWORK_EVENT_DEBOUNCE_MILLIS),
        true,
    );
}

pub(crate) fn schedule_platform_network_settle_recheck(
    event_deadline: &mut PlatformNetworkSampleDeadline,
    remaining: &mut u8,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    // Route notifications commonly arrive while an interface is disappearing,
    // before DHCP and the replacement default route are usable. Re-sample for
    // a short, bounded window because there may be no later notification. The
    // first sample already gave route recovery exclusive ownership; unchanged
    // settle probes must not black out status, FIPS heartbeats, or durable
    // roster delivery retries for the entire sampling window.
    event_deadline.reset_after(
        Duration::from_millis(DAEMON_NETWORK_SETTLE_RECHECK_MILLIS),
        false,
    );
    true
}

#[derive(Debug, Clone)]
pub(crate) struct PlatformNetworkRefreshAttempt {
    target_snapshot: crate::diagnostics::NetworkSnapshot,
    refresh: FipsLinkEventRefresh,
    reason: &'static str,
    carrier_rebound: bool,
    completion_retries_remaining: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformNetworkRefreshRetry {
    Scheduled,
    Exhausted,
}

impl PlatformNetworkRefreshAttempt {
    pub(crate) fn new(
        target_snapshot: crate::diagnostics::NetworkSnapshot,
        refresh: FipsLinkEventRefresh,
        reason: &'static str,
    ) -> Self {
        Self {
            target_snapshot,
            refresh,
            reason,
            carrier_rebound: false,
            completion_retries_remaining: DAEMON_NETWORK_REFRESH_RETRY_ATTEMPTS,
        }
    }

    pub(crate) fn is_superseded_by(
        &self,
        latest_snapshot: &crate::diagnostics::NetworkSnapshot,
        resumed_after_sleep: bool,
        network_state_drift: bool,
    ) -> bool {
        resumed_after_sleep
            || self.target_snapshot != *latest_snapshot
            || (network_state_drift
                && !matches!(
                    self.refresh,
                    FipsLinkEventRefresh::RestartEndpoint
                        | FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
                        | FipsLinkEventRefresh::ReconcileNetworkState
                ))
    }

    pub(crate) fn needs_carrier_rebind(&self, runtime_present: bool) -> bool {
        runtime_present
            && !self.carrier_rebound
            && matches!(
                self.refresh,
                FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
            )
    }

    const fn waits_for_usable_underlay(&self) -> bool {
        matches!(self.refresh, FipsLinkEventRefresh::RestartEndpoint)
    }

    pub(crate) fn mark_carrier_rebound(&mut self) {
        self.carrier_rebound = true;
    }

    pub(crate) fn parameters(
        &self,
        runtime_present: bool,
    ) -> (
        FipsLinkEventRefresh,
        &'static str,
        crate::diagnostics::NetworkSnapshot,
        bool,
    ) {
        (
            self.refresh,
            self.reason,
            self.target_snapshot.clone(),
            self.needs_carrier_rebind(runtime_present),
        )
    }

    pub(crate) fn schedule_completion_retry(
        &mut self,
        event_deadline: &mut PlatformNetworkSampleDeadline,
    ) -> PlatformNetworkRefreshRetry {
        if self.completion_retries_remaining == 0 {
            return PlatformNetworkRefreshRetry::Exhausted;
        }
        self.completion_retries_remaining -= 1;
        event_deadline.reset_after(
            Duration::from_millis(DAEMON_NETWORK_REFRESH_RETRY_MILLIS),
            true,
        );
        PlatformNetworkRefreshRetry::Scheduled
    }
}

pub(crate) fn platform_network_refresh_waits_for_underlay(
    attempt: Option<&PlatformNetworkRefreshAttempt>,
    sampled_network: &crate::diagnostics::NetworkSnapshot,
) -> bool {
    attempt.is_some_and(PlatformNetworkRefreshAttempt::waits_for_usable_underlay)
        && (sampled_network.default_interface.is_none()
            || (sampled_network.primary_ipv4.is_none() && sampled_network.primary_ipv6.is_none()))
}

pub(crate) fn stage_platform_network_refresh_retry(
    terminal_error: &mut Option<anyhow::Error>,
    attempt: &mut PlatformNetworkRefreshAttempt,
    event_deadline: &mut PlatformNetworkSampleDeadline,
    error: anyhow::Error,
    exhausted_context: &'static str,
) -> bool {
    match attempt.schedule_completion_retry(event_deadline) {
        PlatformNetworkRefreshRetry::Scheduled => true,
        PlatformNetworkRefreshRetry::Exhausted => {
            *terminal_error = Some(error.context(exhausted_context));
            false
        }
    }
}

pub(crate) fn stage_platform_network_refresh_failure(
    vpn_status: &mut String,
    terminal_error: &mut Option<anyhow::Error>,
    attempt: &mut Option<PlatformNetworkRefreshAttempt>,
    event_deadline: &mut PlatformNetworkSampleDeadline,
    error: anyhow::Error,
    failure_label: &'static str,
    exhausted_context: &'static str,
) -> bool {
    eprintln!("daemon: {failure_label}: {error:#}");
    *vpn_status = format!("{failure_label} ({error})");
    stage_platform_network_refresh_retry(
        terminal_error,
        attempt
            .as_mut()
            .expect("failed network refresh remains staged"),
        event_deadline,
        error,
        exhausted_context,
    )
}

pub(crate) const fn daemon_network_trigger_is_event_driven(
    trigger: DaemonNetworkTrigger,
    runtime_resume_pending: bool,
) -> bool {
    matches!(trigger, DaemonNetworkTrigger::EventDeadline) || runtime_resume_pending
}

macro_rules! current_fips_peer_statuses {
    ($runtime:expr) => {
        $runtime
            .as_ref()
            .map(|runtime| runtime.peer_statuses())
            .unwrap_or_default()
    };
}
macro_rules! current_fips_endpoint_peer_states {
    ($signature:expr) => {
        daemon_endpoint_peer_states_from_signature($signature)
    };
}

include!("session_runtime/network_refresh_helpers.rs");
include!("session_runtime/fips_status_helpers.rs");
include!("session_runtime/connect_vpn.rs");

#[path = "session_runtime/daemon_vpn/heartbeat.rs"]
mod daemon_vpn_heartbeat;
#[path = "session_runtime/daemon_vpn/intervals.rs"]
mod daemon_vpn_intervals;
#[path = "session_runtime/daemon_vpn/join_approval.rs"]
mod daemon_vpn_join_approval;
#[cfg(feature = "paid-exit")]
#[path = "session_runtime/daemon_vpn/paid_exit.rs"]
pub(crate) mod daemon_vpn_paid_exit;
#[path = "session_runtime/daemon_vpn/persistence.rs"]
mod daemon_vpn_persistence;
#[path = "session_runtime/daemon_vpn/shutdown.rs"]
mod daemon_vpn_shutdown;
#[path = "session_runtime/daemon_vpn/startup.rs"]
mod daemon_vpn_startup;
pub(crate) use daemon_vpn_intervals::{
    DaemonNetworkTrigger, PlatformNetworkSampleDeadline, next_daemon_network_trigger,
};
#[cfg(feature = "paid-exit")]
use daemon_vpn_paid_exit::*;
use {
    daemon_vpn_heartbeat::*, daemon_vpn_intervals::daemon_vpn_intervals,
    daemon_vpn_join_approval::*, daemon_vpn_persistence::*, daemon_vpn_shutdown::*,
    daemon_vpn_startup::*,
};

include!("session_runtime/daemon_vpn.rs");
include!("session_runtime/daemon_state.rs");
include!("session_runtime/tests.rs");
