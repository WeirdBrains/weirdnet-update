//! Update announcements: small signed notices that a new manifest exists, carried by relays
//! so devices behind NAT hear about updates.
//!
//! An [`Announcement`] names one manifest (app, channel, seq and its payload hash) and is
//! signed by the same delegated release keys as the manifest, under its own domain
//! (`weirdnet-update/v1/announcement`). It carries no update content and nothing that
//! identifies a device. A device that hears one checks it against its own root
//! ([`crate::Client::verify_announcement`]), then fetches and verifies the full bundle as
//! usual; the announcement never replaces the acceptance rule, and installing still needs
//! the user's consent.
//!
//! Relays and other carriers keep the latest announcement per org, app and channel in a
//! [`Carrier`], which accepts only announcements signed for roots its operator trusts.
//! [`wire`] (feature `wire`) is the stream protocol between devices, publishers and carriers.

mod carrier;
#[cfg(test)]
mod tests;
#[cfg(feature = "wire")]
pub mod wire;

pub use carrier::{Carrier, Offered, Topic};

use crate::envelope::{Domain, Signed};
use crate::ids::check_id;
use crate::keys::SigningKey;
use crate::manifest::UpdateManifest;
use crate::root::{Root, RootPin};
use crate::{Error, Hash32, Result, Timestamp};
use serde::{Deserialize, Serialize};

/// The largest announcement envelope (encoded).
pub const MAX_ANNOUNCEMENT_BYTES: usize = 8 * 1024;
/// The longest an announcement may be valid.
pub const MAX_LIFETIME_SECS: u64 = 30 * 86_400;
/// Most fetch hints.
pub const MAX_SOURCES: usize = 8;

/// A notice that a manifest was published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    /// The org's id.
    pub org: String,
    /// The pin of the org's first root, as compiled into its apps.
    pub pin: RootPin,
    /// App id.
    pub app: String,
    /// Channel.
    pub channel: String,
    /// The manifest's update id.
    pub update_id: String,
    /// The manifest's seq.
    pub seq: u64,
    /// The manifest envelope's payload hash.
    pub manifest_hash: Hash32,
    /// When it was announced.
    pub published: Timestamp,
    /// When carriers drop it (at most [`MAX_LIFETIME_SECS`] after `published`).
    pub expires: Timestamp,
    /// Whether the manifest is labelled a security update (for display only; the manifest
    /// decides).
    #[serde(default)]
    pub security: bool,
    /// Where the bundle can be fetched: `https://` URLs or `weirdnet:` content ids. Hints
    /// only; whatever arrives is verified.
    #[serde(default)]
    pub sources: Vec<String>,
}

impl Announcement {
    /// An announcement for a manifest the publisher just signed.
    pub fn for_manifest(org: &str, pin: RootPin, manifest: &Signed, published: Timestamp, lifetime_secs: u64, sources: Vec<String>) -> Result<Self> {
        if manifest.domain != Domain::Manifest {
            return Err(Error::WrongDomain { expected: Domain::Manifest, found: manifest.domain });
        }
        let m: UpdateManifest = manifest.decode()?;
        let a = Self {
            org: org.into(),
            pin,
            app: m.app.clone(),
            channel: m.channel.clone(),
            update_id: m.update_id.clone(),
            seq: m.seq,
            manifest_hash: manifest.payload_hash(),
            published,
            expires: published.plus(lifetime_secs.min(MAX_LIFETIME_SECS)).min(m.expires),
            security: m.labels.security.is_some(),
            sources,
        };
        a.validate()?;
        Ok(a)
    }

    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        check_id("org", &self.org)?;
        check_id("app", &self.app)?;
        check_id("channel", &self.channel)?;
        check_id("update id", &self.update_id)?;
        if self.expires <= self.published || self.expires.0 - self.published.0 > MAX_LIFETIME_SECS {
            return Err(Error::invalid("announcement", format!("must expire within {MAX_LIFETIME_SECS} s of publishing")));
        }
        if self.sources.len() > MAX_SOURCES {
            return Err(Error::invalid("announcement", format!("more than {MAX_SOURCES} sources")));
        }
        for s in &self.sources {
            let ok = (s.starts_with("https://") || s.starts_with("weirdnet:")) && s.len() <= 512 && !s.chars().any(char::is_control);
            if !ok {
                return Err(Error::invalid("announcement source", "https:// URLs or weirdnet: ids, up to 512 bytes"));
            }
        }
        Ok(())
    }

    /// Signs with release keys (as many as the root's release threshold).
    pub fn sign(&self, keys: &[&SigningKey]) -> Result<Signed> {
        self.validate()?;
        let env = Signed::sign(Domain::Announcement, self, keys)?;
        if env.to_bytes()?.len() > MAX_ANNOUNCEMENT_BYTES {
            return Err(Error::invalid("announcement", format!("larger than {MAX_ANNOUNCEMENT_BYTES} bytes")));
        }
        Ok(env)
    }

    /// Verifies an announcement against a trusted root of the org pinned by `pin`: a
    /// threshold of release keys delegated for its app and channel signed it, and it is
    /// current at `now`.
    ///
    /// The payload is decoded before the signature check only to learn which app and channel
    /// to check keys for; nothing in it is used unless the check passes.
    pub fn verify(env: &Signed, pin: RootPin, root: &Root, now: Timestamp) -> Result<Self> {
        if env.domain != Domain::Announcement {
            return Err(Error::WrongDomain { expected: Domain::Announcement, found: env.domain });
        }
        if env.payload.len() > MAX_ANNOUNCEMENT_BYTES {
            return Err(Error::Decode("announcement too large".into()));
        }
        let claimed: Announcement = env.decode()?;
        let keys = root.release_keys_for(&claimed.app, &claimed.channel, now);
        if keys.is_empty() {
            return Err(Error::NotDelegated(format!("{}/{}", claimed.app, claimed.channel)));
        }
        env.verify_threshold(Domain::Announcement, &keys, root.release_threshold.into())?;
        claimed.validate()?;
        if claimed.pin != pin || claimed.org != root.org {
            return Err(Error::PinMismatch);
        }
        root.check_live(now)?;
        if now < claimed.published.minus(300) || now >= claimed.expires {
            return Err(Error::Expired(Domain::Announcement));
        }
        Ok(claimed)
    }

    /// Whether `manifest` (a verified manifest's envelope) is the one announced.
    pub fn names(&self, manifest: &Signed) -> bool {
        manifest.domain == Domain::Manifest && manifest.payload_hash() == self.manifest_hash
    }
}
