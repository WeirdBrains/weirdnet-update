//! Staged rollouts.
//!
//! A plan is a list of stages (share in basis points, start time, minimum dwell). The device
//! compares its own bucket with the current share, so the server never learns who updated.

use crate::target::BUCKETS;
use crate::{Error, Result, Timestamp};
use serde::{Deserialize, Serialize};

/// Most stages in a plan.
pub const MAX_STAGES: usize = 16;

/// One stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage {
    /// Share of devices, in basis points (100 = 1%, 10000 = all).
    pub percent_bp: u16,
    /// When the stage starts.
    pub start_at: Timestamp,
    /// Minimum seconds before the next stage may start (checked when the plan is built).
    #[serde(default)]
    pub min_dwell_secs: u64,
}

/// A staged rollout, e.g. 1% → 10% → 50% → 100%.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPlan {
    /// Stages in order.
    pub stages: Vec<Stage>,
}

impl RolloutPlan {
    /// Everyone at once from `at`.
    pub fn immediate(at: Timestamp) -> Self {
        Self { stages: vec![Stage { percent_bp: BUCKETS, start_at: at, min_dwell_secs: 0 }] }
    }

    /// Stages must grow in share, start in order and respect each stage's dwell.
    pub fn validate(&self) -> Result<()> {
        if self.stages.is_empty() || self.stages.len() > MAX_STAGES {
            return Err(Error::invalid("rollout", format!("needs 1..={MAX_STAGES} stages")));
        }
        for s in &self.stages {
            if s.percent_bp == 0 || s.percent_bp > BUCKETS {
                return Err(Error::invalid("rollout", "stage share must be 1..=10000 basis points"));
            }
        }
        for pair in self.stages.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            if b.percent_bp <= a.percent_bp {
                return Err(Error::invalid("rollout", "each stage must reach more devices than the last"));
            }
            if b.start_at < a.start_at.plus(a.min_dwell_secs) {
                return Err(Error::invalid("rollout", "a stage starts before the previous stage's dwell ends"));
            }
        }
        Ok(())
    }

    /// The share live at `now` (0 before the first stage), limited by an optional cap from a
    /// freshness record (a paused rollout).
    pub fn current_bp(&self, now: Timestamp, cap_bp: Option<u16>) -> u16 {
        let live = self.stages.iter().filter(|s| s.start_at <= now).map(|s| s.percent_bp).max().unwrap_or(0);
        cap_bp.map_or(live, |c| live.min(c))
    }

    /// Whether a device in `bucket` is in the rollout at `now`.
    pub fn includes(&self, bucket: u16, now: Timestamp, cap_bp: Option<u16>) -> bool {
        bucket < self.current_bp(now, cap_bp)
    }
}
