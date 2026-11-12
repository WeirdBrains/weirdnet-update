//! Errors. None of them carry key material.

use crate::envelope::Domain;

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while building, signing or checking update metadata.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// CBOR encoding failed.
    #[error("encoding failed: {0}")]
    Encode(String),
    /// CBOR decoding failed or the input was malformed.
    #[error("decoding failed: {0}")]
    Decode(String),
    /// A key, signature or hash could not be parsed, or is weak.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// The OS random generator failed.
    #[error("randomness unavailable")]
    Random,
    /// A record is structurally invalid (empty ids, bad thresholds, bad paths, limits).
    #[error("invalid {what}: {reason}")]
    Invalid {
        /// What was being validated.
        what: &'static str,
        /// Why it was refused.
        reason: String,
    },
    /// An envelope was signed for a different purpose.
    #[error("expected a {expected} record, got {found}")]
    WrongDomain {
        /// The domain the caller asked for.
        expected: Domain,
        /// The domain in the envelope.
        found: Domain,
    },
    /// Too few distinct trusted keys signed.
    #[error("{domain}: {found} valid signature(s) from trusted keys, {needed} needed")]
    Threshold {
        /// The record kind.
        domain: Domain,
        /// Valid signatures from distinct trusted keys.
        found: usize,
        /// The threshold.
        needed: usize,
    },
    /// The root's keys do not hash to the fingerprint compiled into the app.
    #[error("root does not match the pinned fingerprint")]
    PinMismatch,
    /// A root update does not follow the trusted root.
    #[error("root version {found} does not follow trusted version {current}")]
    RootVersion {
        /// The trusted root version.
        current: u32,
        /// The offered root version.
        found: u32,
    },
    /// A root update names a different org.
    #[error("root update changes the org")]
    RootOrg,
    /// A record has expired (or is not valid yet).
    #[error("{0} record expired or not yet valid")]
    Expired(Domain),
    /// The record is for a different app or channel than the caller asked for.
    #[error("record is for {found}, expected {expected}")]
    WrongTarget {
        /// `app/channel` the caller expects.
        expected: String,
        /// `app/channel` in the record.
        found: String,
    },
    /// The sequence number is not above the last one seen (replay or rollback).
    #[error("seq {found} is not above the last seen {last}")]
    Replay {
        /// Last seq seen for this app and channel.
        last: u64,
        /// Offered seq.
        found: u64,
    },
    /// Two different manifests claim the same seq.
    #[error("a different manifest was already seen with seq {0}")]
    Equivocation(u64),
    /// The update is listed as revoked by a trusted freshness record.
    #[error("update {0} is revoked")]
    Revoked(String),
    /// The update failed its boot-health check on this device before.
    #[error("update {0} is marked bad on this device")]
    KnownBad(String),
    /// The freshness record names another manifest.
    #[error("freshness record does not match this manifest")]
    FreshnessMismatch,
    /// The root trusts timestamp keys but no valid freshness record came with the manifest.
    #[error("a freshness record is required by the root")]
    FreshnessRequired,
    /// A lower version without a rollback record.
    #[error("downgrade from {installed} to {offered} without a rollback record")]
    Downgrade {
        /// Installed version.
        installed: String,
        /// Offered version.
        offered: String,
    },
    /// The installed base release is not one the update applies to.
    #[error("update does not apply to base release {0}")]
    BaseMismatch(String),
    /// The running client version is outside the update's range.
    #[error("update does not apply to client version {0}")]
    ClientVersion(String),
    /// The release key is not delegated for this app or channel, or its delegation expired.
    #[error("no release key is delegated for {0}")]
    NotDelegated(String),
    /// This client does not accept the update kind.
    #[error("update kind {0} is not supported by this client")]
    UnsupportedKind(&'static str),
    /// A downloaded file failed its size or hash check.
    #[error("file {path}: {reason}")]
    File {
        /// Path from the manifest.
        path: String,
        /// What failed.
        reason: String,
    },
    /// A targeting rule is invalid.
    #[error("targeting rule: {0}")]
    Rule(String),
}

impl Error {
    pub(crate) fn invalid(what: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid { what, reason: reason.into() }
    }
}
