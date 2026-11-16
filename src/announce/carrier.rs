use super::Announcement;
use crate::envelope::{Domain, Signed};
use crate::root::{Root, RootPin};
use crate::{Error, Result, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// What to hear about: one org's app on one channel, every channel of an app (`channel`
/// empty), or every app of the org (`app` empty too).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Topic {
    /// The org's root pin.
    pub pin: RootPin,
    /// App id, or empty for all.
    #[serde(default)]
    pub app: String,
    /// Channel, or empty for all.
    #[serde(default)]
    pub channel: String,
}

impl Topic {
    /// Whether `a` falls under this topic.
    pub fn matches(&self, a: &Announcement) -> bool {
        self.pin == a.pin && (self.app.is_empty() || self.app == a.app) && (self.channel.is_empty() || self.channel == a.channel)
    }
}

/// What [`Carrier::offer`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Offered {
    /// Newer than what the carrier held: pass it on.
    New,
    /// Already held.
    Same,
    /// Older than (or conflicting with) what the carrier holds: dropped.
    Stale,
    /// A root rotation, now trusted.
    Root,
}

type Key = (RootPin, String, String);

/// The latest announcements for the orgs a carrier (a relay) trusts.
#[derive(Debug, Default)]
pub struct Carrier {
    roots: HashMap<RootPin, (Root, Vec<Signed>)>,
    latest: HashMap<Key, (Announcement, Signed)>,
    max: usize,
}

impl Carrier {
    /// A carrier holding at most `max` announcements.
    pub fn new(max: usize) -> Self {
        Self { roots: HashMap::new(), latest: HashMap::new(), max: max.max(1) }
    }

    /// Trusts an org: its root chain from the first root (checked against `pin`) to the
    /// newest rotation.
    pub fn trust(&mut self, pin: RootPin, chain: &[Signed], now: Timestamp) -> Result<()> {
        let (first, rest) = chain.split_first().ok_or_else(|| Error::invalid("root chain", "empty"))?;
        let mut root = Root::verify_initial(&pin, first, now)?;
        for env in rest {
            root = root.verify_next(env, now)?;
        }
        self.roots.insert(pin, (root, chain.to_vec()));
        Ok(())
    }

    /// The trusted orgs' pins.
    pub fn pins(&self) -> Vec<RootPin> {
        self.roots.keys().copied().collect()
    }

    /// The current root chain for `pin` (to hand to devices that lag behind).
    pub fn chain(&self, pin: &RootPin) -> Option<&[Signed]> {
        self.roots.get(pin).map(|(_, c)| c.as_slice())
    }

    /// Takes an announcement or a root rotation for a trusted org.
    pub fn offer(&mut self, env: &Signed, now: Timestamp) -> Result<Offered> {
        if env.domain == Domain::Root {
            for (root, chain) in self.roots.values_mut() {
                if chain.iter().any(|c| c == env) {
                    return Ok(Offered::Same);
                }
                if let Ok(next) = root.verify_next(env, now) {
                    *root = next;
                    chain.push(env.clone());
                    return Ok(Offered::Root);
                }
            }
            return Err(Error::invalid("root rotation", "does not follow any trusted root"));
        }
        let claimed: Announcement = if env.domain == Domain::Announcement {
            env.decode()?
        } else {
            return Err(Error::WrongDomain { expected: Domain::Announcement, found: env.domain });
        };
        let (root, _) = self.roots.get(&claimed.pin).ok_or(Error::PinMismatch)?;
        let a = Announcement::verify(env, claimed.pin, root, now)?;
        let key = (a.pin, a.app.clone(), a.channel.clone());
        if let Some((held, held_env)) = self.latest.get(&key) {
            if held_env == env {
                return Ok(Offered::Same);
            }
            if a.seq <= held.seq && held.expires > now {
                return Ok(Offered::Stale);
            }
        }
        self.latest.insert(key, (a, env.clone()));
        if self.latest.len() > self.max {
            self.prune(now);
            while self.latest.len() > self.max {
                let oldest = self.latest.iter().min_by_key(|(_, (a, _))| a.published).map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.latest.remove(&k);
                }
            }
        }
        Ok(Offered::New)
    }

    /// Current announcements under any of `topics`.
    pub fn matching(&self, topics: &[Topic], now: Timestamp) -> Vec<Signed> {
        self.latest.values().filter(|(a, _)| a.expires > now && topics.iter().any(|t| t.matches(a))).map(|(_, e)| e.clone()).collect()
    }

    /// Every current announcement (for carriers following this one).
    pub fn all(&self, now: Timestamp) -> Vec<Signed> {
        self.latest.values().filter(|(a, _)| a.expires > now).map(|(_, e)| e.clone()).collect()
    }

    /// Whether `env` (already offered) falls under `topics`.
    pub fn matches(env: &Signed, topics: &[Topic]) -> bool {
        env.decode::<Announcement>().is_ok_and(|a| topics.iter().any(|t| t.matches(&a)))
    }

    /// Drops expired announcements.
    pub fn prune(&mut self, now: Timestamp) {
        self.latest.retain(|_, (a, _)| a.expires > now);
    }

    /// How many announcements are held.
    pub fn len(&self) -> usize {
        self.latest.len()
    }

    /// Whether none are held.
    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }
}
