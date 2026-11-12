//! Ed25519 keys and signatures.
//!
//! Org root, release and timestamp keys are independent Ed25519 keys. They are not
//! Weirdnet user keys; an org that wants to tie them to a Weirdnet identity derives an
//! app-scoped seed itself and passes it to [`SigningKey::from_seed`].

use crate::bytes::decode_hex;
use crate::{Error, Result};
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// A secret Ed25519 signing key. Wiped on drop, never printed.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// A fresh key from the OS random generator.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| Error::Random)?;
        Ok(Self::from_seed(&seed))
    }

    /// A key from a 32-byte seed (for keys held in a keyring or derived elsewhere).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The seed, for the caller to store sealed. Handle as a secret.
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey(<redacted>, public {})", self.public())
    }
}

/// An Ed25519 public key. Parsing refuses invalid and small-order (weak) points.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Parses and checks 32 key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey("not an Ed25519 point".into()))?;
        if key.is_weak() {
            return Err(Error::InvalidKey("weak Ed25519 key".into()));
        }
        Ok(Self(bytes))
    }

    /// Parses 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(decode_hex("public key", s)?)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Strict verification (RFC 8032 with the cofactorless, non-malleable checks).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else { return false };
        key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig.0)).is_ok()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub(crate) [u8; 64]);

impl Signature {
    /// Wraps raw signature bytes (checked only when verified).
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}…)", hex::encode(&self.0[..8]))
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self(decode_hex("signature", &s).map_err(serde::de::Error::custom)?))
    }
}
