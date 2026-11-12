//! Seconds since the Unix epoch, UTC.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time as whole seconds since the Unix epoch (UTC).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// The current system time. A clock before 1970 reads as 0.
    pub fn now() -> Self {
        Self(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
    }

    /// This time plus `secs`, saturating.
    pub fn plus(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// This time minus `secs`, saturating at 0.
    pub fn minus(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }
}
