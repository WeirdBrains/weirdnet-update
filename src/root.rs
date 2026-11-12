//! Org roots: the client's root of trust.
//!
//! A [`Root`] lists the org's k-of-n root keys, the release keys it delegates (optionally
//! scoped to apps and channels, with an expiry) and the timestamp keys the org chose to trust:
//! none, the WeirdBrains timestamp key, the org's own, or several. The app pins a
//! [`RootPin`] (a fingerprint of the first root's keys and threshold) at build time.
//!
//! Rotation follows TUF: root version N+1 must be signed by a threshold of version N's keys
//! *and* a threshold of its own keys.

use crate::envelope::{Domain, Signed};
use crate::ids::{check_id, check_unique};
use crate::keys::PublicKey;
use crate::{Error, Hash32, Result, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Most keys in any one role.
pub const MAX_KEYS: usize = 32;
/// Most app or channel names in one delegation scope.
pub const MAX_SCOPE: usize = 256;

/// A release key delegated by the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// The release key.
    pub key: PublicKey,
    /// Apps it may sign for; empty means every app of the org.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Channels it may sign for; empty means every channel.
    #[serde(default)]
    pub channels: Vec<String>,
    /// After this time the delegation no longer counts.
    #[serde(default)]
    pub expires: Option<Timestamp>,
}

impl Delegation {
    /// An unscoped delegation with no expiry.
    pub fn any(key: PublicKey) -> Self {
        Self { key, apps: Vec::new(), channels: Vec::new(), expires: None }
    }

    /// Whether this delegation covers `app`/`channel` at `now`.
    pub fn covers(&self, app: &str, channel: &str, now: Timestamp) -> bool {
        (self.apps.is_empty() || self.apps.iter().any(|a| a == app))
            && (self.channels.is_empty() || self.channels.iter().any(|c| c == channel))
            && self.expires.is_none_or(|e| now < e)
    }
}

/// An org root record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Starts at 1 and goes up by exactly 1 per rotation.
    pub version: u32,
    /// The org's id on the service.
    pub org: String,
    /// Root keys (held offline by the org, never by the service).
    pub keys: Vec<PublicKey>,
    /// Root signatures needed.
    pub threshold: u8,
    /// Delegated release keys.
    pub release: Vec<Delegation>,
    /// Release signatures needed on a manifest.
    pub release_threshold: u8,
    /// Trusted timestamp keys; empty means the app trusts none (freshness falls back to the
    /// manifest's own expiry and seq order).
    #[serde(default)]
    pub timestamp: Vec<PublicKey>,
    /// Timestamp signatures needed; 0 exactly when `timestamp` is empty.
    #[serde(default)]
    pub timestamp_threshold: u8,
    /// Optional expiry of this root version.
    #[serde(default)]
    pub expires: Option<Timestamp>,
}

impl Root {
    /// Structural checks: ids, no duplicate keys, thresholds within range, limits.
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(Error::invalid("root", "version starts at 1"));
        }
        check_id("org", &self.org)?;
        check_role("root keys", &self.keys, self.threshold, false)?;
        let release_keys: Vec<PublicKey> = self.release.iter().map(|d| d.key).collect();
        check_role("release keys", &release_keys, self.release_threshold, false)?;
        check_role("timestamp keys", &self.timestamp, self.timestamp_threshold, true)?;
        for d in &self.release {
            if d.apps.len() > MAX_SCOPE || d.channels.len() > MAX_SCOPE {
                return Err(Error::invalid("delegation", format!("more than {MAX_SCOPE} scope entries")));
            }
            for a in &d.apps {
                check_id("app", a)?;
            }
            for c in &d.channels {
                check_id("channel", c)?;
            }
        }
        Ok(())
    }

    /// The fingerprint of this root's keys and threshold.
    pub fn pin(&self) -> RootPin {
        RootPin::for_keys(&self.keys, self.threshold)
    }

    /// Whether the app trusts any timestamp key.
    pub fn trusts_timestamps(&self) -> bool {
        !self.timestamp.is_empty()
    }

    /// Release keys that may sign for `app`/`channel` at `now`.
    pub fn release_keys_for(&self, app: &str, channel: &str, now: Timestamp) -> Vec<PublicKey> {
        self.release.iter().filter(|d| d.covers(app, channel, now)).map(|d| d.key).collect()
    }

    pub(crate) fn check_live(&self, now: Timestamp) -> Result<()> {
        if self.expires.is_some_and(|e| now >= e) {
            return Err(Error::Expired(Domain::Root));
        }
        Ok(())
    }

    /// Verifies the first root against the pin compiled into the app: its keys must hash to
    /// the pin and a threshold of them must have signed it.
    pub fn verify_initial(pin: &RootPin, env: &Signed, now: Timestamp) -> Result<Self> {
        if env.domain != Domain::Root {
            return Err(Error::WrongDomain { expected: Domain::Root, found: env.domain });
        }
        let root: Root = env.decode()?;
        root.validate()?;
        if root.pin() != *pin {
            return Err(Error::PinMismatch);
        }
        env.verify_threshold(Domain::Root, &root.keys, root.threshold.into())?;
        root.check_live(now)?;
        Ok(root)
    }

    /// Verifies a rotation from `self` to the next version.
    pub fn verify_next(&self, env: &Signed, now: Timestamp) -> Result<Self> {
        // Old keys first: nothing in the payload is trusted until the current root vouches for it.
        env.verify_threshold(Domain::Root, &self.keys, self.threshold.into())?;
        let next: Root = env.decode()?;
        next.validate()?;
        if next.version != self.version.saturating_add(1) || self.version == u32::MAX {
            return Err(Error::RootVersion { current: self.version, found: next.version });
        }
        if next.org != self.org {
            return Err(Error::RootOrg);
        }
        env.verify_threshold(Domain::Root, &next.keys, next.threshold.into())?;
        next.check_live(now)?;
        Ok(next)
    }
}

fn check_role(what: &'static str, keys: &[PublicKey], threshold: u8, may_be_empty: bool) -> Result<()> {
    if keys.len() > MAX_KEYS {
        return Err(Error::invalid(what, format!("more than {MAX_KEYS} keys")));
    }
    check_unique(what, keys)?;
    if keys.is_empty() {
        return if may_be_empty && threshold == 0 {
            Ok(())
        } else if may_be_empty {
            Err(Error::invalid(what, "threshold must be 0 when no keys are listed"))
        } else {
            Err(Error::invalid(what, "at least one key is required"))
        };
    }
    if threshold == 0 || usize::from(threshold) > keys.len() {
        return Err(Error::invalid(what, format!("threshold must be 1..={}", keys.len())));
    }
    Ok(())
}

/// The trust anchor compiled into an app: BLAKE3 (derive-key mode) over the threshold and the
/// sorted root keys. It names a key set, not a document, so it survives re-signing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RootPin(pub Hash32);

impl RootPin {
    /// The pin for a root key set.
    pub fn for_keys(keys: &[PublicKey], threshold: u8) -> Self {
        let mut sorted: Vec<&PublicKey> = keys.iter().collect();
        sorted.sort();
        let mut h = blake3::Hasher::new_derive_key("weirdnet-update v1 root pin");
        h.update(&[threshold]);
        h.update(&(sorted.len() as u32).to_le_bytes());
        for k in sorted {
            h.update(k.as_bytes());
        }
        Self(h.finalize().into())
    }

    /// Parses the hex form (as written in `salty.toml`).
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(Self(Hash32::from_hex(s)?))
    }
}

impl fmt::Display for RootPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl fmt::Debug for RootPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootPin({})", self.0.to_hex())
    }
}
