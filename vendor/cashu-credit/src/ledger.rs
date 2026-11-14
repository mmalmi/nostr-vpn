use crate::CreditError;

/// Unbacked, non-redeemable relationship credit issued by one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCreditLedger {
    pub(crate) outstanding_sat: u64,
    pub(crate) offline_outstanding_sat: u64,
}

impl PeerCreditLedger {
    pub fn outstanding_sat(&self) -> u64 {
        self.outstanding_sat
    }

    pub fn offline_outstanding_sat(&self) -> u64 {
        self.offline_outstanding_sat
    }

    pub(crate) fn credit(&mut self, amount: u64, offline: bool) -> Result<(), CreditError> {
        let outstanding = self
            .outstanding_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let offline_outstanding = if offline {
            self.offline_outstanding_sat
                .checked_add(amount)
                .ok_or(CreditError::ArithmeticOverflow)?
        } else {
            self.offline_outstanding_sat
        };
        self.outstanding_sat = outstanding;
        self.offline_outstanding_sat = offline_outstanding;
        Ok(())
    }

    pub(crate) fn debit(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.outstanding_sat {
            return Err(CreditError::InsufficientPeerCredit);
        }
        self.outstanding_sat -= amount;
        self.offline_outstanding_sat = self.offline_outstanding_sat.min(self.outstanding_sat);
        Ok(())
    }
}

/// Deposit-backed value that can circulate or buy issuer service, but cannot cash out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosedLoopLedger {
    pub(crate) total_deposited_sat: u64,
    pub(crate) available_backing_sat: u64,
    pub(crate) claimable_sat: u64,
    pub(crate) consumed_sat: u64,
}

impl ClosedLoopLedger {
    pub fn total_deposited_sat(&self) -> u64 {
        self.total_deposited_sat
    }

    pub fn available_backing_sat(&self) -> u64 {
        self.available_backing_sat
    }

    pub fn claimable_sat(&self) -> u64 {
        self.claimable_sat
    }

    pub fn consumed_sat(&self) -> u64 {
        self.consumed_sat
    }

    pub fn conserved_sat(&self) -> Result<u64, CreditError> {
        let accounted = self
            .available_backing_sat
            .checked_add(self.claimable_sat)
            .and_then(|value| value.checked_add(self.consumed_sat))
            .ok_or(CreditError::ArithmeticOverflow)?;
        if accounted != self.total_deposited_sat {
            return Err(CreditError::ConservationViolation);
        }
        Ok(accounted)
    }

    pub(crate) fn deposit(&mut self, amount: u64) -> Result<(), CreditError> {
        let total = self
            .total_deposited_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let available = self
            .available_backing_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.total_deposited_sat = total;
        self.available_backing_sat = available;
        Ok(())
    }

    pub(crate) fn allocate(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.available_backing_sat {
            return Err(CreditError::InsufficientClosedLoopBacking);
        }
        let claimable = self
            .claimable_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.available_backing_sat -= amount;
        self.claimable_sat = claimable;
        Ok(())
    }

    pub(crate) fn consume(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.claimable_sat {
            return Err(CreditError::InsufficientClosedLoopBacking);
        }
        let consumed = self
            .consumed_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.claimable_sat -= amount;
        self.consumed_sat = consumed;
        Ok(())
    }
}

/// Reserve-backed sats that may leave through an external settlement backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WithdrawableReserveLedger {
    pub(crate) total_deposited_sat: u64,
    pub(crate) available_sat: u64,
    pub(crate) redeemable_sat: u64,
    pub(crate) pending_external_sat: u64,
    pub(crate) settled_external_sat: u64,
}

impl WithdrawableReserveLedger {
    pub fn total_deposited_sat(&self) -> u64 {
        self.total_deposited_sat
    }

    pub fn available_sat(&self) -> u64 {
        self.available_sat
    }

    pub fn redeemable_sat(&self) -> u64 {
        self.redeemable_sat
    }

    pub fn pending_external_sat(&self) -> u64 {
        self.pending_external_sat
    }

    pub fn settled_external_sat(&self) -> u64 {
        self.settled_external_sat
    }

    pub fn conserved_sat(&self) -> Result<u64, CreditError> {
        let accounted = self
            .available_sat
            .checked_add(self.redeemable_sat)
            .and_then(|value| value.checked_add(self.pending_external_sat))
            .and_then(|value| value.checked_add(self.settled_external_sat))
            .ok_or(CreditError::ArithmeticOverflow)?;
        if accounted != self.total_deposited_sat {
            return Err(CreditError::ConservationViolation);
        }
        Ok(accounted)
    }

    pub(crate) fn deposit(&mut self, amount: u64) -> Result<(), CreditError> {
        let total = self
            .total_deposited_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let available = self
            .available_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.total_deposited_sat = total;
        self.available_sat = available;
        Ok(())
    }

    pub(crate) fn allocate(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.available_sat {
            return Err(CreditError::InsufficientAvailableReserve);
        }
        let redeemable = self
            .redeemable_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.available_sat -= amount;
        self.redeemable_sat = redeemable;
        Ok(())
    }

    pub(crate) fn authorize(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.redeemable_sat {
            return Err(CreditError::InsufficientRedeemableReserve);
        }
        let pending = self
            .pending_external_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.redeemable_sat -= amount;
        self.pending_external_sat = pending;
        Ok(())
    }

    pub(crate) fn complete(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.pending_external_sat {
            return Err(CreditError::ConservationViolation);
        }
        let settled = self
            .settled_external_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.pending_external_sat -= amount;
        self.settled_external_sat = settled;
        Ok(())
    }

    pub(crate) fn cancel(&mut self, amount: u64) -> Result<(), CreditError> {
        if amount > self.pending_external_sat {
            return Err(CreditError::ConservationViolation);
        }
        let redeemable = self
            .redeemable_sat
            .checked_add(amount)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.pending_external_sat -= amount;
        self.redeemable_sat = redeemable;
        Ok(())
    }
}
