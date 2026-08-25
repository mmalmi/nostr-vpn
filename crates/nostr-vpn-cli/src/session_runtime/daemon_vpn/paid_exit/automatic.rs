use super::*;
use nostr_vpn_core::paid_routes::PaidRouteUsage;

#[path = "automatic/payments.rs"]
mod payments;
#[path = "automatic/runtime.rs"]
mod runtime;
#[path = "automatic/selection.rs"]
mod selection;
#[path = "automatic/state.rs"]
mod state;

pub(crate) use payments::finalize_automatic_paid_exit;
use payments::{
    fund_automatic_paid_exit, queue_recovered_automatic_channel_open, suspend_automatic_paid_exit,
};
pub(crate) use runtime::update_automatic_paid_exit;
pub(crate) use runtime::{paid_exit_route_probe_measurement, record_paid_exit_probe};
pub(crate) use selection::reconcile_automatic_paid_exit_selection;
#[cfg(test)]
use state::PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS;
#[cfg(test)]
use state::PaidExitAutomaticCandidate;
use state::{PAID_EXIT_AUTO_HEALTH_TTL_SECS, PaidExitAutomaticProbe};
pub(crate) use state::{PaidExitAutomaticBuyer, PaidExitUsageFlush};

#[cfg(test)]
#[path = "automatic/tests.rs"]
mod tests;
