//! Optional timestamp records.
//!
//! When the root lists timestamp keys, every manifest must come with a [`Freshness`] record
//! signed by them: it names the latest seq and manifest hash for an app and channel, lists
//! revoked updates, can cap a rollout (pause), and expires within hours. That blocks freeze
//! attacks and lets a takedown reach installed clients. Apps whose root lists no timestamp
//! keys skip it; then only the manifest's own expiry and seq order apply.

use crate::ids::{check_id, check_unique};
use crate::{Error, Hash32, Result, Timestamp};
use serde::{Deserialize, Serialize};

/// Most revoked ids one record may list.
pub const MAX_REVOKED: usize = 4096;

/// A signed freshness statement for one app and channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    /// App id.
    pub app: String,
    /// Channel.
    pub channel: String,
    /// Seq of the latest manifest.
    pub latest_seq: u64,
    /// [`Signed::payload_hash`](crate::Signed::payload_hash) of that manifest.
    pub manifest_hash: Hash32,
    /// Update ids that must not be installed (takedowns, bad releases).
    #[serde(default)]
    pub revoked: Vec<String>,
    /// A rollout cap in basis points (0..=10000); a paused rollout holds its current share.
    #[serde(default)]
    pub rollout_cap_bp: Option<u16>,
    /// Issue time.
    pub issued: Timestamp,
    /// Expiry.
    pub expires: Timestamp,
}

impl Freshness {
    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        check_id("app", &self.app)?;
        check_id("channel", &self.channel)?;
        if self.expires <= self.issued {
            return Err(Error::invalid("freshness", "expires must be after issued"));
        }
        if self.revoked.len() > MAX_REVOKED {
            return Err(Error::invalid("freshness", format!("more than {MAX_REVOKED} revocations")));
        }
        for id in &self.revoked {
            check_id("revoked update id", id)?;
        }
        check_unique("revoked", &self.revoked)?;
        if self.rollout_cap_bp.is_some_and(|c| c > 10_000) {
            return Err(Error::invalid("freshness", "rollout cap above 10000 basis points"));
        }
        Ok(())
    }
}
