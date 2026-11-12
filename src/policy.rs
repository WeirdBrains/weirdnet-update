//! Opt-in consent policy. Updates are never forced.
//!
//! Per app the user picks a [`ConsentMode`]: ask for each update (the default), install
//! automatically, notify only, or off. The F-Droid flavor defaults to off. Which update kinds
//! a build may take at all depends on its [`Flavor`]. New capabilities always ask again, even
//! in automatic mode. Declining is remembered and never blocks the app.

use crate::manifest::{UpdateKind, UpdateManifest};
use crate::{Error, Result, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The user's choice for an app.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsentMode {
    /// Ask for each update (default).
    #[default]
    Ask,
    /// Install updates automatically (opt-in). New capabilities still ask.
    Auto,
    /// Show that an update exists; never download it.
    NotifyOnly,
    /// No update checks.
    Off,
}

/// How the app was distributed; decides which update kinds it may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flavor {
    /// Desktop builds outside a store.
    Desktop,
    /// Sideloaded Android or iOS outside a store.
    Sideload,
    /// Google Play: no full updates.
    Play,
    /// Apple App Store and TestFlight: assets, Wasm and store notices only.
    AppStore,
    /// Mac App Store: store notices only.
    MacAppStore,
    /// F-Droid: opt-in assets and Wasm only, off by default.
    FDroid,
}

impl Flavor {
    /// The mode a fresh install starts in.
    pub fn default_mode(self) -> ConsentMode {
        match self {
            Self::FDroid => ConsentMode::Off,
            _ => ConsentMode::Ask,
        }
    }

    /// Whether this flavor may take `kind`. Dart patches also need `dart_patches`, which no
    /// client turns on until the engine support exists.
    pub fn allows(self, kind: &UpdateKind, dart_patches: bool) -> bool {
        match kind {
            UpdateKind::StoreNotice { .. } => true,
            UpdateKind::Assets | UpdateKind::Wasm { .. } => !matches!(self, Self::MacAppStore),
            UpdateKind::Full(_) => matches!(self, Self::Desktop | Self::Sideload),
            UpdateKind::DartPatch(_) => dart_patches && matches!(self, Self::Desktop | Self::Sideload | Self::Play),
        }
    }
}

/// The per-app policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Distribution flavor.
    pub flavor: Flavor,
    /// Dart patches enabled for this build (placeholder; keep `false`).
    #[serde(default)]
    pub dart_patches: bool,
}

/// A recorded user choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Choice {
    /// Install this update, with the capabilities it listed.
    Accepted,
    /// Don't install this update.
    Declined,
    /// Switched the app's mode.
    Mode(ConsentMode),
    /// Agreed to the F-Droid wording ("you're choosing to bypass F-Droid's checks").
    FDroidBypassAcknowledged,
}

/// One timestamped choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// The update the choice is about; `None` for mode changes.
    pub update_id: Option<String>,
    /// The choice.
    pub choice: Choice,
    /// When it was made.
    pub at: Timestamp,
}

/// The app's consent history, stored locally by the app.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentLog {
    /// Records, oldest first.
    pub records: Vec<ConsentRecord>,
}

impl ConsentLog {
    /// Records a per-update choice.
    pub fn decide(&mut self, update_id: &str, accepted: bool, at: Timestamp) {
        let choice = if accepted { Choice::Accepted } else { Choice::Declined };
        self.records.push(ConsentRecord { update_id: Some(update_id.to_owned()), choice, at });
    }

    /// Records a mode change. Leaving `Off` in the F-Droid flavor needs the F-Droid
    /// acknowledgement first.
    pub fn set_mode(&mut self, flavor: Flavor, mode: ConsentMode, at: Timestamp) -> Result<()> {
        if flavor == Flavor::FDroid && mode != ConsentMode::Off && !self.fdroid_acknowledged() {
            return Err(Error::invalid("consent", "F-Droid builds need the bypass acknowledgement before updates are enabled"));
        }
        self.records.push(ConsentRecord { update_id: None, choice: Choice::Mode(mode), at });
        Ok(())
    }

    /// Records the F-Droid acknowledgement.
    pub fn acknowledge_fdroid(&mut self, at: Timestamp) {
        self.records.push(ConsentRecord { update_id: None, choice: Choice::FDroidBypassAcknowledged, at });
    }

    fn fdroid_acknowledged(&self) -> bool {
        self.records.iter().any(|r| r.choice == Choice::FDroidBypassAcknowledged)
    }

    /// The current mode: the last mode change, or the flavor's default.
    pub fn mode(&self, flavor: Flavor) -> ConsentMode {
        self.records
            .iter()
            .rev()
            .find_map(|r| match r.choice {
                Choice::Mode(m) => Some(m),
                _ => None,
            })
            .unwrap_or(flavor.default_mode())
    }

    /// The latest accept or decline for an update.
    pub fn choice_for(&self, update_id: &str) -> Option<bool> {
        self.records.iter().rev().find_map(|r| match (&r.update_id, &r.choice) {
            (Some(id), Choice::Accepted) if id == update_id => Some(true),
            (Some(id), Choice::Declined) if id == update_id => Some(false),
            _ => None,
        })
    }
}

/// Why the client should ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskReason {
    /// The mode is "ask for each update".
    PerUpdate,
    /// Auto mode, but the update requests capabilities not granted before.
    NewCapabilities,
}

/// Why nothing happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Updates are off.
    Off,
    /// The user declined this update.
    Declined,
    /// This build's flavor can't take this kind.
    KindNotAllowed,
}

/// What the client does with a verified, targeted update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Download and install (the user opted in to auto mode, or accepted this update).
    Install,
    /// Show the consent prompt.
    Ask {
        /// Why.
        reason: AskReason,
        /// Capabilities not granted before (always shown).
        new_capabilities: Vec<String>,
        /// Security label present: show the distinct badge.
        security: bool,
    },
    /// Show a notice only (notify-only mode, or a store notice).
    Notify {
        /// Security label present: show it prominently.
        security: bool,
    },
    /// Do nothing.
    Skip(SkipReason),
}

/// Decides what to do with an update. `granted` holds capabilities the user already approved.
pub fn decide(policy: &Policy, log: &ConsentLog, update: &UpdateManifest, granted: &BTreeSet<String>) -> Decision {
    if !policy.flavor.allows(&update.kind, policy.dart_patches) {
        return Decision::Skip(SkipReason::KindNotAllowed);
    }
    let mode = log.mode(policy.flavor);
    let security = update.labels.security.is_some();
    if mode == ConsentMode::Off {
        return Decision::Skip(SkipReason::Off);
    }
    if matches!(update.kind, UpdateKind::StoreNotice { .. }) {
        return Decision::Notify { security };
    }
    match log.choice_for(&update.update_id) {
        Some(false) => return Decision::Skip(SkipReason::Declined),
        Some(true) => return Decision::Install,
        None => {}
    }
    let new_capabilities: Vec<String> = update.capabilities.iter().filter(|c| !granted.contains(*c)).cloned().collect();
    match mode {
        ConsentMode::NotifyOnly => Decision::Notify { security },
        ConsentMode::Ask => Decision::Ask { reason: AskReason::PerUpdate, new_capabilities, security },
        ConsentMode::Auto if new_capabilities.is_empty() => Decision::Install,
        ConsentMode::Auto => Decision::Ask { reason: AskReason::NewCapabilities, new_capabilities, security },
        ConsentMode::Off => Decision::Skip(SkipReason::Off),
    }
}
