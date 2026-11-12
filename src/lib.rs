//! Weirdnet update metadata and client-side verification.
//!
//! This crate holds the parts of an over-the-air update system that are not tied to an app
//! or a UI toolkit (Salty Gull builds on it):
//!
//! - [`root`]: an org root of k-of-n Ed25519 keys, pinned into the app by its
//!   [`RootPin`], that delegates release keys and names 0 or more timestamp keys.
//!   Org roots are independent keys, not Weirdnet user keys.
//! - [`manifest`]: the signed [`UpdateManifest`] and its
//!   [`UpdateKind`] (assets, Wasm, full signed package, Dart patch placeholder,
//!   store notice).
//! - [`freshness`]: optional short-lived timestamp records that block freeze attacks and carry
//!   revocations.
//! - [`envelope`]: domain-separated signing over the exact CBOR bytes.
//! - [`verify`]: the client acceptance rule and [`ClientState`] anti-rollback.
//! - [`target`] and [`rollout`]: targeting rules and staged rollouts, evaluated on the device.
//! - [`policy`]: the opt-in consent policy. Updates are never forced.
//! - [`health`]: boot counting and automatic local rollback.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bytes;
pub mod envelope;
pub mod error;
pub mod freshness;
pub mod health;
pub mod keys;
pub mod manifest;
pub mod policy;
pub mod root;
pub mod rollout;
pub mod state;
pub mod target;
pub mod time;
pub mod verify;

mod cbor;
mod ids;

pub use bytes::Hash32;
pub use envelope::{Domain, Signed};
pub use error::{Error, Result};
pub use freshness::Freshness;
pub use keys::{PublicKey, Signature, SigningKey};
pub use manifest::{FileEntry, UpdateKind, UpdateManifest};
pub use policy::{ConsentMode, Decision, Flavor, Policy};
pub use root::{Delegation, Root, RootPin};
pub use state::ClientState;
pub use time::Timestamp;
pub use verify::{Client, UpdateBundle, VerifiedUpdate, VerifyOptions};

#[cfg(test)]
mod tests;
