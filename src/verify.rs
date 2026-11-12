//! The client acceptance rule.
//!
//! An update is accepted only when all of these hold:
//! 1. the root chains to the pinned fingerprint (rotations signed by old and new thresholds);
//! 2. the manifest carries a threshold of signatures from release keys the root delegates for
//!    this app and channel, and is inside its validity window;
//! 3. when the root trusts timestamp keys, a valid, unexpired, short-lived freshness record
//!    names this exact manifest and doesn't revoke it;
//! 4. its seq is above the last seen for the channel (the same manifest again is fine);
//! 5. its kind, client-version range, base release and version (no silent downgrade) fit
//!    this client.
//!
//! Targeting and rollout ([`VerifiedUpdate::applies`]) and consent ([`crate::policy`]) come after.

use crate::envelope::{Domain, Signed};
use crate::freshness::Freshness;
use crate::manifest::{UpdateKind, UpdateManifest};
use crate::root::{Root, RootPin};
use crate::state::{ClientState, Seen, channel_key, installed_key};
use crate::target::Device;
use crate::{Error, Hash32, Result, Timestamp};
use semver::Version;

/// Per-check settings.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// Current time.
    pub now: Timestamp,
    /// The running app version.
    pub client_version: Version,
    /// The installed base release id, if the app knows it.
    pub base_release: Option<String>,
    /// Accept Dart patches (placeholder; leave `false`).
    pub dart_patches: bool,
    /// The Wasm host ABI this build provides; `None` refuses Wasm updates.
    pub wasm_host_abi: Option<u32>,
    /// Longest freshness lifetime accepted (default 24 hours).
    pub max_freshness_secs: u64,
    /// Allowed clock skew for "not yet valid" checks (default 5 minutes).
    pub clock_skew_secs: u64,
}

impl VerifyOptions {
    /// Defaults for a client at `client_version`.
    pub fn new(now: Timestamp, client_version: Version) -> Self {
        Self {
            now,
            client_version,
            base_release: None,
            dart_patches: false,
            wasm_host_abi: None,
            max_freshness_secs: 24 * 3600,
            clock_skew_secs: 300,
        }
    }
}

/// What arrives from a relay, a peer or HTTPS.
#[derive(Clone, Debug, Default)]
pub struct UpdateBundle {
    /// Root rotations newer than the client may have, oldest first.
    pub roots: Vec<Signed>,
    /// The manifest.
    pub manifest: Option<Signed>,
    /// The freshness record, when the root trusts timestamp keys.
    pub freshness: Option<Signed>,
}

/// A manifest that passed the acceptance rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUpdate {
    /// The manifest.
    pub manifest: UpdateManifest,
    /// Its payload hash.
    pub manifest_hash: Hash32,
    /// The freshness record that vouched for it, if the root trusts timestamp keys.
    pub freshness: Option<Freshness>,
}

/// Whether a verified update is meant for this device right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applicability {
    /// Targeted, and inside the rollout.
    Applies,
    /// The targeting rule doesn't match.
    NotTargeted,
    /// Targeted, but this device's bucket isn't in the rollout yet (or it is paused).
    NotInRolloutYet,
}

impl VerifiedUpdate {
    /// Evaluates targeting and rollout on the device.
    pub fn applies(&self, device: &Device) -> Applicability {
        if let Some(rule) = &self.manifest.targeting
            && !rule.evaluate(device)
        {
            return Applicability::NotTargeted;
        }
        let cap = self.freshness.as_ref().and_then(|f| f.rollout_cap_bp);
        let included = match &self.manifest.rollout {
            Some(plan) => plan.includes(device.bucket(&self.manifest.update_id), device.now, cap),
            None => cap.is_none_or(|c| device.bucket(&self.manifest.update_id) < c),
        };
        if included { Applicability::Applies } else { Applicability::NotInRolloutYet }
    }
}

/// An app's update verifier: the pinned root, the trusted root chain and anti-rollback state.
#[derive(Debug)]
pub struct Client {
    pin: RootPin,
    root: Root,
    state: ClientState,
}

impl Client {
    /// Starts from the first root, checked against the pin compiled into the app.
    pub fn new(pin: RootPin, initial_root: &Signed, now: Timestamp) -> Result<Self> {
        let root = Root::verify_initial(&pin, initial_root, now)?;
        let state = ClientState { roots: vec![initial_root.clone()], ..ClientState::default() };
        Ok(Self { pin, root, state })
    }

    /// Restores saved state, re-verifying the whole root chain from the pin.
    pub fn from_state(pin: RootPin, state: ClientState, now: Timestamp) -> Result<Self> {
        let (first, rest) = state.roots.split_first().ok_or_else(|| Error::invalid("client state", "no root"))?;
        let mut root = Root::verify_initial(&pin, first, now)?;
        for env in rest {
            root = root.verify_next(env, now)?;
        }
        Ok(Self { pin, root, state })
    }

    /// The pin.
    pub fn pin(&self) -> RootPin {
        self.pin
    }

    /// The trusted root.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// State to persist after each change.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// Applies a root rotation. Versions at or below the trusted one are ignored if they are the
    /// same document, and refused otherwise.
    pub fn update_root(&mut self, env: &Signed, now: Timestamp) -> Result<()> {
        if self.state.roots.iter().any(|r| r == env) {
            return Ok(());
        }
        let next = self.root.verify_next(env, now)?;
        self.root = next;
        self.state.roots.push(env.clone());
        Ok(())
    }

    /// Runs the acceptance rule for `app`/`channel` and records the seq on success.
    pub fn verify(&mut self, app: &str, channel: &str, bundle: &UpdateBundle, opts: &VerifyOptions) -> Result<VerifiedUpdate> {
        for env in &bundle.roots {
            self.update_root(env, opts.now)?;
        }
        self.root.check_live(opts.now)?;
        let target = channel_key(app, channel);
        let env = bundle.manifest.as_ref().ok_or_else(|| Error::invalid("bundle", "no manifest"))?;

        let keys = self.root.release_keys_for(app, channel, opts.now);
        if keys.is_empty() {
            return Err(Error::NotDelegated(target));
        }
        env.verify_threshold(Domain::Manifest, &keys, self.root.release_threshold.into())?;
        let manifest: UpdateManifest = env.decode()?;
        manifest.validate()?;
        if manifest.app != app || manifest.channel != channel {
            return Err(Error::WrongTarget { expected: target, found: manifest.target() });
        }
        if opts.now.plus(opts.clock_skew_secs) < manifest.created || opts.now >= manifest.expires {
            return Err(Error::Expired(Domain::Manifest));
        }
        self.check_kind(&manifest, opts)?;
        if self.state.bad.contains(&manifest.update_id) {
            return Err(Error::KnownBad(manifest.update_id));
        }

        let manifest_hash = env.payload_hash();
        if let Some(seen) = self.state.seen.get(&target) {
            if manifest.seq < seen.seq {
                return Err(Error::Replay { last: seen.seq, found: manifest.seq });
            }
            if manifest.seq == seen.seq && manifest_hash != seen.manifest_hash {
                return Err(Error::Equivocation(manifest.seq));
            }
        }

        let freshness = self.check_freshness(app, channel, &manifest, manifest_hash, bundle, opts)?;
        Self::check_applicable(&manifest, opts)?;
        self.check_downgrade(&manifest, opts)?;

        self.state.seen.insert(target, Seen { seq: manifest.seq, manifest_hash });
        Ok(VerifiedUpdate { manifest, manifest_hash, freshness })
    }

    fn check_kind(&self, m: &UpdateManifest, opts: &VerifyOptions) -> Result<()> {
        match &m.kind {
            UpdateKind::DartPatch(_) if !opts.dart_patches => Err(Error::UnsupportedKind("dart-patch")),
            UpdateKind::Wasm { host_abi } if opts.wasm_host_abi != Some(*host_abi) => Err(Error::UnsupportedKind("wasm (host ABI)")),
            _ => Ok(()),
        }
    }

    fn check_freshness(
        &self,
        app: &str,
        channel: &str,
        m: &UpdateManifest,
        manifest_hash: Hash32,
        bundle: &UpdateBundle,
        opts: &VerifyOptions,
    ) -> Result<Option<Freshness>> {
        if !self.root.trusts_timestamps() {
            // The org trusts no timestamp key: manifest expiry and seq order are the only
            // freshness checks, and any record that came along carries no weight.
            return Ok(None);
        }
        let env = bundle.freshness.as_ref().ok_or(Error::FreshnessRequired)?;
        env.verify_threshold(Domain::Freshness, &self.root.timestamp, self.root.timestamp_threshold.into())?;
        let f: Freshness = env.decode()?;
        f.validate()?;
        if f.app != app || f.channel != channel {
            return Err(Error::WrongTarget { expected: channel_key(app, channel), found: channel_key(&f.app, &f.channel) });
        }
        let lifetime = f.expires.0 - f.issued.0;
        if opts.now.plus(opts.clock_skew_secs) < f.issued || opts.now >= f.expires || lifetime > opts.max_freshness_secs {
            return Err(Error::Expired(Domain::Freshness));
        }
        if f.revoked.iter().any(|id| id == &m.update_id) {
            return Err(Error::Revoked(m.update_id.clone()));
        }
        if f.latest_seq != m.seq || f.manifest_hash != manifest_hash {
            return Err(Error::FreshnessMismatch);
        }
        Ok(Some(f))
    }

    fn check_applicable(m: &UpdateManifest, opts: &VerifyOptions) -> Result<()> {
        let v = &opts.client_version;
        if m.min_client.as_ref().is_some_and(|lo| v < lo) || m.max_client.as_ref().is_some_and(|hi| v > hi) {
            return Err(Error::ClientVersion(v.to_string()));
        }
        if !m.base_releases.is_empty() {
            let base = opts.base_release.as_deref().unwrap_or("");
            if !m.base_releases.iter().any(|b| b == base) {
                return Err(Error::BaseMismatch(base.to_owned()));
            }
        }
        Ok(())
    }

    fn check_downgrade(&self, m: &UpdateManifest, opts: &VerifyOptions) -> Result<()> {
        if m.rollback_of.is_some() {
            return Ok(());
        }
        let installed = match &m.kind {
            UpdateKind::Full(_) | UpdateKind::StoreNotice { .. } => Some(&opts.client_version),
            _ => self.state.installed.get(&installed_key(&m.app, &m.channel, m.kind.name())),
        };
        if let Some(cur) = installed
            && m.version < *cur
        {
            return Err(Error::Downgrade { installed: cur.to_string(), offered: m.version.to_string() });
        }
        Ok(())
    }

    /// Records that an update was installed and committed (after its boot check).
    pub fn mark_installed(&mut self, update: &VerifiedUpdate) {
        let m = &update.manifest;
        self.state.installed.insert(installed_key(&m.app, &m.channel, m.kind.name()), m.version.clone());
    }

    /// Records that an update failed its boot check; it is refused from now on.
    pub fn mark_bad(&mut self, update_id: &str) {
        self.state.bad.insert(update_id.to_owned());
    }
}
