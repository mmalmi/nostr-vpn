use serde::{Deserialize, Serialize};

/// Explicit permission to redeem earned claims into this application's receiving
/// wallet. One labeled invoice per interval limits retries across daemon restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoCashout {
    pub min_sat: u64,
    pub max_sat: u64,
    pub max_fee_sat: u64,
    pub interval_secs: u64,
}
impl AutoCashout {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_sat == 0
            || self.max_sat < self.min_sat
            || self.max_sat.checked_add(self.max_fee_sat).is_none()
            || !(60..=2_592_000).contains(&self.interval_secs)
        {
            return Err(
                "choose a positive withdrawal range and an interval between one minute and 30 days"
                    .into(),
            );
        }
        Ok(())
    }
}
