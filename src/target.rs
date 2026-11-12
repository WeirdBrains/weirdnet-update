//! On-device targeting rules.
//!
//! A rule is a small boolean expression over device attributes, signed inside the manifest
//! and evaluated on the device, so attributes never leave it. Built-in attribute names are
//! listed in [`BUILTIN_ATTRS`]; app-defined attributes start with `custom.`.
//! A comparison on an attribute the device doesn't have is false (so `Not` of it is true).

use crate::ids::{MAX_ID, check_id};
use crate::{Error, Result, Timestamp};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Deepest nesting allowed.
pub const MAX_DEPTH: usize = 16;
/// Most nodes in one rule.
pub const MAX_NODES: usize = 256;
/// Most values in one `In` list.
pub const MAX_IN: usize = 64;
/// Rollout buckets run from 0 to `BUCKETS - 1` (basis points).
pub const BUCKETS: u16 = 10_000;

/// Attribute names the platform layer fills in.
pub const BUILTIN_ATTRS: &[&str] = &[
    "app_version",
    "base_release",
    "channel",
    "platform",
    "os",
    "os_version",
    "arch",
    "package_type",
    "store",
    "device_class",
    "form_factor",
    "locale",
    "region",
];

/// Prefix for app-defined attributes.
pub const CUSTOM_PREFIX: &str = "custom.";

/// An attribute value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Value {
    /// Text.
    Str(String),
    /// Integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
    /// Semantic version.
    Version(Version),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Int(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<Version> for Value {
    fn from(v: Version) -> Self {
        Self::Version(v)
    }
}

/// Ordering comparisons (integers and versions only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
}

/// A targeting rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rule {
    /// Always true.
    True,
    /// Every sub-rule is true (empty: true).
    All(Vec<Rule>),
    /// Some sub-rule is true (empty: false).
    Any(Vec<Rule>),
    /// Negation.
    Not(Box<Rule>),
    /// Attribute equals value.
    Eq {
        /// Attribute name.
        attr: String,
        /// Value.
        value: Value,
    },
    /// Attribute is one of the values.
    In {
        /// Attribute name.
        attr: String,
        /// Values.
        values: Vec<Value>,
    },
    /// Ordered comparison; both sides must be integers or both versions.
    Cmp {
        /// Attribute name.
        attr: String,
        /// Operator.
        op: CmpOp,
        /// Right-hand side.
        value: Value,
    },
    /// String attribute starts with a prefix (e.g. `locale` starts with `de`).
    StartsWith {
        /// Attribute name.
        attr: String,
        /// Prefix.
        prefix: String,
    },
    /// The user installed a signed cohort token with this name (e.g. beta testers).
    Cohort(String),
    /// Only between two times (UTC).
    Window {
        /// Start, inclusive.
        from: Timestamp,
        /// End, exclusive.
        until: Timestamp,
    },
}

fn check_attr(attr: &str) -> Result<()> {
    let ok =
        BUILTIN_ATTRS.contains(&attr) || (attr.len() > CUSTOM_PREFIX.len() && attr.starts_with(CUSTOM_PREFIX) && check_id("attribute", attr).is_ok());
    if !ok {
        return Err(Error::Rule(format!("unknown attribute {attr:?}; custom attributes start with {CUSTOM_PREFIX:?}")));
    }
    Ok(())
}

fn check_value(v: &Value) -> Result<()> {
    if let Value::Str(s) = v
        && s.len() > MAX_ID * 2
    {
        return Err(Error::Rule("string value too long".into()));
    }
    Ok(())
}

impl Rule {
    /// Checks size limits, attribute names and value types.
    pub fn validate(&self) -> Result<()> {
        let mut nodes = 0;
        self.validate_at(1, &mut nodes)
    }

    fn validate_at(&self, depth: usize, nodes: &mut usize) -> Result<()> {
        *nodes += 1;
        if depth > MAX_DEPTH {
            return Err(Error::Rule(format!("nested deeper than {MAX_DEPTH}")));
        }
        if *nodes > MAX_NODES {
            return Err(Error::Rule(format!("more than {MAX_NODES} nodes")));
        }
        match self {
            Self::True => {}
            Self::All(rules) | Self::Any(rules) => {
                for r in rules {
                    r.validate_at(depth + 1, nodes)?;
                }
            }
            Self::Not(r) => r.validate_at(depth + 1, nodes)?,
            Self::Eq { attr, value } => {
                check_attr(attr)?;
                check_value(value)?;
            }
            Self::In { attr, values } => {
                check_attr(attr)?;
                if values.is_empty() || values.len() > MAX_IN {
                    return Err(Error::Rule(format!("`in` needs 1..={MAX_IN} values")));
                }
                values.iter().try_for_each(check_value)?;
            }
            Self::Cmp { attr, value, .. } => {
                check_attr(attr)?;
                if !matches!(value, Value::Int(_) | Value::Version(_)) {
                    return Err(Error::Rule("ordered comparisons take an integer or a version".into()));
                }
            }
            Self::StartsWith { attr, prefix } => {
                check_attr(attr)?;
                check_value(&Value::Str(prefix.clone()))?;
            }
            Self::Cohort(name) => check_id("cohort", name).map_err(|e| Error::Rule(e.to_string()))?,
            Self::Window { from, until } => {
                if from >= until {
                    return Err(Error::Rule("window must end after it starts".into()));
                }
            }
        }
        Ok(())
    }

    /// Evaluates the rule against a device.
    pub fn evaluate(&self, device: &Device) -> bool {
        match self {
            Self::True => true,
            Self::All(rules) => rules.iter().all(|r| r.evaluate(device)),
            Self::Any(rules) => rules.iter().any(|r| r.evaluate(device)),
            Self::Not(r) => !r.evaluate(device),
            Self::Eq { attr, value } => device.attr(attr).is_some_and(|v| v == value),
            Self::In { attr, values } => device.attr(attr).is_some_and(|v| values.contains(v)),
            Self::Cmp { attr, op, value } => {
                let ord = match (device.attr(attr), value) {
                    (Some(Value::Int(a)), Value::Int(b)) => a.cmp(b),
                    (Some(Value::Version(a)), Value::Version(b)) => a.cmp(b),
                    _ => return false,
                };
                match op {
                    CmpOp::Lt => ord.is_lt(),
                    CmpOp::Le => ord.is_le(),
                    CmpOp::Gt => ord.is_gt(),
                    CmpOp::Ge => ord.is_ge(),
                }
            }
            Self::StartsWith { attr, prefix } => matches!(device.attr(attr), Some(Value::Str(s)) if s.starts_with(prefix.as_str())),
            Self::Cohort(name) => device.cohorts.contains(name),
            Self::Window { from, until } => *from <= device.now && device.now < *until,
        }
    }
}

/// What the device knows about itself. Never sent anywhere.
#[derive(Clone)]
pub struct Device {
    attrs: BTreeMap<String, Value>,
    cohorts: BTreeSet<String>,
    bucket_secret: [u8; 32],
    /// The current time.
    pub now: Timestamp,
}

impl Device {
    /// A device with a local random secret used only for rollout buckets. Create the secret
    /// once per install and keep it on the device.
    pub fn new(bucket_secret: [u8; 32], now: Timestamp) -> Self {
        Self { attrs: BTreeMap::new(), cohorts: BTreeSet::new(), bucket_secret, now }
    }

    /// Sets an attribute (built-in or `custom.*`).
    pub fn set(&mut self, attr: &str, value: impl Into<Value>) -> Result<&mut Self> {
        check_attr(attr)?;
        self.attrs.insert(attr.to_owned(), value.into());
        Ok(self)
    }

    /// Adds a cohort whose signed token the user installed. Token checks are the caller's.
    pub fn join_cohort(&mut self, name: &str) -> &mut Self {
        self.cohorts.insert(name.to_owned());
        self
    }

    /// Reads an attribute.
    pub fn attr(&self, attr: &str) -> Option<&Value> {
        self.attrs.get(attr)
    }

    /// This device's rollout bucket for one update, 0..[`BUCKETS`]. Keyed by the local secret
    /// so no one else can compute it, and per update so a device isn't always first.
    pub fn bucket(&self, update_id: &str) -> u16 {
        let mut h = blake3::Hasher::new_keyed(&self.bucket_secret);
        h.update(b"weirdnet-update/v1/bucket\0");
        h.update(update_id.as_bytes());
        let out = h.finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&out.as_bytes()[..8]);
        (u64::from_le_bytes(first) % u64::from(BUCKETS)) as u16
    }
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("attrs", &self.attrs)
            .field("cohorts", &self.cohorts)
            .field("bucket_secret", &"<redacted>")
            .field("now", &self.now)
            .finish()
    }
}
