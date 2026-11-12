//! Boot health and automatic local rollback.
//!
//! After an update is staged, the next start runs it on trial. Each start that begins
//! without the previous trial start having reported ready counts as a failed boot; after
//! `max_failed_boots` the client goes back to the previous good state and marks the update
//! bad. The app persists [`BootHealth`] before acting on each step, so a crash can't skip one.

use serde::{Deserialize, Serialize};

/// Where an update is in its trial.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthState {
    /// Nothing pending.
    #[default]
    Idle,
    /// Staged; the next start tries it.
    Staged {
        /// Update id.
        update_id: String,
    },
    /// Running on trial.
    Trial {
        /// Update id.
        update_id: String,
        /// Trial starts so far.
        boots: u8,
    },
    /// Reached ready; now the good state.
    Committed {
        /// Update id.
        update_id: String,
    },
    /// Rolled back after failed boots.
    RolledBack {
        /// Update id.
        update_id: String,
    },
}

/// What to run at this start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootChoice {
    /// Run the current good state (no trial pending).
    Current,
    /// Run the staged candidate.
    Candidate(String),
    /// The candidate failed too often: run the previous good state and mark it bad.
    RollBack(String),
}

/// The boot-health state machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootHealth {
    /// Current state.
    pub state: HealthState,
    /// Failed trial boots before rolling back (default 2).
    pub max_failed_boots: u8,
}

impl Default for BootHealth {
    fn default() -> Self {
        Self { state: HealthState::Idle, max_failed_boots: 2 }
    }
}

impl BootHealth {
    /// Stages a verified, downloaded update for the next start.
    pub fn stage(&mut self, update_id: &str) {
        self.state = HealthState::Staged { update_id: update_id.to_owned() };
    }

    /// Call at the very start of each launch.
    pub fn begin_boot(&mut self) -> BootChoice {
        match std::mem::take(&mut self.state) {
            HealthState::Staged { update_id } => {
                self.state = HealthState::Trial { update_id: update_id.clone(), boots: 1 };
                BootChoice::Candidate(update_id)
            }
            HealthState::Trial { update_id, boots } if boots >= self.max_failed_boots.max(1) => {
                self.state = HealthState::RolledBack { update_id: update_id.clone() };
                BootChoice::RollBack(update_id)
            }
            HealthState::Trial { update_id, boots } => {
                self.state = HealthState::Trial { update_id: update_id.clone(), boots: boots + 1 };
                BootChoice::Candidate(update_id)
            }
            other => {
                self.state = other;
                BootChoice::Current
            }
        }
    }

    /// Call when the first frame is drawn and the app's own ready signal fired. Returns the
    /// committed update id, if a trial just passed.
    pub fn mark_ready(&mut self) -> Option<String> {
        if let HealthState::Trial { update_id, .. } = &self.state {
            let id = update_id.clone();
            self.state = HealthState::Committed { update_id: id.clone() };
            return Some(id);
        }
        None
    }
}
