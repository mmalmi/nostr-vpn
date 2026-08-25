use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic seconds used by the isolated payment network.
pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> u64;
}

/// An explicitly advanced clock. It never reads or sleeps on wall time.
#[derive(Debug)]
pub struct VirtualClock {
    now: AtomicU64,
}

impl VirtualClock {
    pub const fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
        }
    }

    pub fn advance(&self, seconds: u64) -> Result<u64, ClockError> {
        self.now
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                now.checked_add(seconds)
            })
            .map(|previous| previous + seconds)
            .map_err(|_| ClockError::Overflow)
    }

    pub fn set(&self, now: u64) -> Result<u64, ClockError> {
        loop {
            let previous = self.now.load(Ordering::SeqCst);
            if now < previous {
                return Err(ClockError::WentBackwards { previous, now });
            }
            match self
                .now
                .compare_exchange(previous, now, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(now),
                Err(_) => continue,
            }
        }
    }
}

impl MonotonicClock for VirtualClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    Overflow,
    WentBackwards { previous: u64, now: u64 },
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("virtual clock overflow"),
            Self::WentBackwards { previous, now } => write!(
                formatter,
                "virtual clock cannot move backwards from {previous} to {now}"
            ),
        }
    }
}

impl std::error::Error for ClockError {}
