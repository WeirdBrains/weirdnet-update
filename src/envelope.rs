//! Signed envelopes.
//!
//! An envelope carries the exact CBOR bytes of a record and the signatures over them, so a
//! verifier checks signatures on the bytes it received and only then decodes. Each signature
//! covers `weirdnet-update/v1/<domain>` + `0x00` + payload, so a signature made for one record
//! kind never verifies as another.

use crate::keys::{PublicKey, Signature, SigningKey};
use crate::{Error, Hash32, Result, cbor};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;
use std::fmt;

/// Largest encoded envelope accepted from the network.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Most signatures one envelope may carry.
pub const MAX_SIGNATURES: usize = 64;

/// What a signature is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    /// An org [`Root`](crate::Root).
    Root,
    /// An [`UpdateManifest`](crate::UpdateManifest).
    Manifest,
    /// A [`Freshness`](crate::Freshness) record.
    Freshness,
}

impl Domain {
    /// The signing context string.
    pub fn context(self) -> &'static str {
        match self {
            Self::Root => "weirdnet-update/v1/root",
            Self::Manifest => "weirdnet-update/v1/manifest",
            Self::Freshness => "weirdnet-update/v1/freshness",
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Root => "root",
            Self::Manifest => "manifest",
            Self::Freshness => "freshness",
        })
    }
}

/// One signature and the key that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// Signer.
    pub key: PublicKey,
    /// Signature over the domain-separated payload.
    pub sig: Signature,
}

/// A record's CBOR bytes plus signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// What the record is.
    pub domain: Domain,
    /// The record's exact CBOR encoding.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Signatures, in any order.
    pub signatures: Vec<SignatureEntry>,
}

fn message(domain: Domain, payload: &[u8]) -> Vec<u8> {
    let ctx = domain.context().as_bytes();
    let mut msg = Vec::with_capacity(ctx.len() + 1 + payload.len());
    msg.extend_from_slice(ctx);
    msg.push(0);
    msg.extend_from_slice(payload);
    msg
}

impl Signed {
    /// Encodes `value` and signs it with each key (k-of-n signers may also add theirs later
    /// with [`Signed::add_signature`]).
    pub fn sign<T: Serialize>(domain: Domain, value: &T, keys: &[&SigningKey]) -> Result<Self> {
        let mut env = Self { domain, payload: cbor::to_vec(value)?, signatures: Vec::new() };
        for key in keys {
            env.add_signature(key);
        }
        Ok(env)
    }

    /// Adds (or replaces) `key`'s signature.
    pub fn add_signature(&mut self, key: &SigningKey) {
        let public = key.public();
        let sig = key.sign_raw(&message(self.domain, &self.payload));
        self.signatures.retain(|e| e.key != public);
        self.signatures.push(SignatureEntry { key: public, sig });
    }

    /// Checks that at least `threshold` distinct keys from `trusted` made valid signatures.
    /// Signatures from other keys, and repeated signatures from one key, don't count.
    pub fn verify_threshold(&self, domain: Domain, trusted: &[PublicKey], threshold: usize) -> Result<()> {
        if self.domain != domain {
            return Err(Error::WrongDomain { expected: domain, found: self.domain });
        }
        if threshold == 0 {
            return Err(Error::invalid("threshold", "must be at least 1"));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid("envelope", format!("more than {MAX_SIGNATURES} signatures")));
        }
        let msg = message(domain, &self.payload);
        let mut good = BTreeSet::new();
        for entry in &self.signatures {
            if trusted.contains(&entry.key) && !good.contains(&entry.key) && entry.key.verify(&msg, &entry.sig) {
                good.insert(entry.key);
            }
        }
        if good.len() < threshold {
            return Err(Error::Threshold { domain, found: good.len(), needed: threshold });
        }
        Ok(())
    }

    /// Decodes the payload. Call only after [`Signed::verify_threshold`], or on data whose
    /// trust is checked another way (an initial root is checked against its pin).
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        cbor::from_slice(&self.payload)
    }

    /// BLAKE3 of the payload; freshness records name a manifest by it.
    pub fn payload_hash(&self) -> Hash32 {
        Hash32::of(&self.payload)
    }

    /// CBOR encoding of the whole envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        cbor::to_vec(self)
    }

    /// Parses an envelope, refusing anything over [`MAX_ENVELOPE_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Decode(format!("envelope larger than {MAX_ENVELOPE_BYTES} bytes")));
        }
        let env: Self = cbor::from_slice(bytes)?;
        if env.signatures.len() > MAX_SIGNATURES {
            return Err(Error::Decode(format!("more than {MAX_SIGNATURES} signatures")));
        }
        Ok(env)
    }
}
