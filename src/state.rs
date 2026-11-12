//! Client anti-rollback state, persisted by the app.

use crate::envelope::Signed;
use crate::{Hash32, Result, cbor};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Highest seq and manifest hash seen for one app and channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// Seq.
    pub seq: u64,
    /// Payload hash of that manifest.
    pub manifest_hash: Hash32,
}

/// What the client remembers between runs. Store it in the app's private storage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    /// The trusted root chain, oldest first; re-verified from the pin on load.
    pub roots: Vec<Signed>,
    /// Last manifest seen per `app/channel`.
    pub seen: BTreeMap<String, Seen>,
    /// Installed version per `app/channel/kind`.
    pub installed: BTreeMap<String, Version>,
    /// Updates that failed their boot check here.
    pub bad: BTreeSet<String>,
}

impl ClientState {
    /// CBOR encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        cbor::to_vec(self)
    }

    /// Parses saved state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        cbor::from_slice(bytes)
    }
}

pub(crate) fn channel_key(app: &str, channel: &str) -> String {
    format!("{app}/{channel}")
}

pub(crate) fn installed_key(app: &str, channel: &str, kind: &str) -> String {
    format!("{app}/{channel}/{kind}")
}
