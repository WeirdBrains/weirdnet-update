//! Unit and threat-model tests.

use crate::envelope::{MAX_ENVELOPE_BYTES, SignatureEntry};
use crate::health::{BootChoice, BootHealth, HealthState};
use crate::manifest::{Arch, DartPatch, FullPackage, InstallMode, Labels, PackageFormat, Platform, SecurityLabel, Severity};
use crate::policy::{AskReason, ConsentLog, SkipReason, decide};
use crate::rollout::{RolloutPlan, Stage};
use crate::target::{CmpOp, Device, Rule, Value};
use crate::verify::Applicability;
use crate::*;
use semver::Version;
use std::collections::BTreeSet;

const NOW: Timestamp = Timestamp(1_800_000_000);
const DAY: u64 = 86_400;

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

struct Org {
    root_keys: Vec<SigningKey>,
    release: SigningKey,
    ts: SigningKey,
    root: Root,
    root_env: Signed,
}

fn root_doc(version: u32, keys: &[&SigningKey], threshold: u8, release: &[Delegation], ts: &[&SigningKey]) -> Root {
    Root {
        version,
        org: "weirdbrains".into(),
        keys: keys.iter().map(|k| k.public()).collect(),
        threshold,
        release: release.to_vec(),
        release_threshold: 1,
        timestamp: ts.iter().map(|k| k.public()).collect(),
        timestamp_threshold: u8::from(!ts.is_empty()),
        expires: None,
    }
}

/// A 2-of-3 org root with one release key and, optionally, one trusted timestamp key.
fn org(with_ts: bool) -> Org {
    let root_keys = vec![key(1), key(2), key(3)];
    let release = key(10);
    let ts = key(20);
    let rk: Vec<&SigningKey> = root_keys.iter().collect();
    let ts_list: Vec<&SigningKey> = if with_ts { vec![&ts] } else { vec![] };
    let root = root_doc(1, &rk, 2, &[Delegation::any(release.public())], &ts_list);
    let root_env = Signed::sign(Domain::Root, &root, &[&root_keys[0], &root_keys[1]]).unwrap();
    Org { root_keys, release, ts, root, root_env }
}

fn manifest(seq: u64, id: &str) -> UpdateManifest {
    UpdateManifest {
        app: "com.weirdbrains.morph".into(),
        channel: "stable".into(),
        update_id: id.into(),
        seq,
        kind: UpdateKind::Assets,
        version: v("1.0.0"),
        base_releases: vec![],
        files: vec![FileEntry::describe("ui/main.rfw", b"hello")],
        min_client: None,
        max_client: None,
        capabilities: vec![],
        labels: Labels::default(),
        targeting: None,
        rollout: None,
        rollback_of: None,
        notes: "Fixes".into(),
        created: NOW,
        expires: NOW.plus(7 * DAY),
    }
}

fn sign_m(o: &Org, m: &UpdateManifest) -> Signed {
    Signed::sign(Domain::Manifest, m, &[&o.release]).unwrap()
}

fn fresh_for(env: &Signed, m: &UpdateManifest) -> Freshness {
    Freshness {
        app: m.app.clone(),
        channel: m.channel.clone(),
        latest_seq: m.seq,
        manifest_hash: env.payload_hash(),
        revoked: vec![],
        rollout_cap_bp: None,
        issued: NOW,
        expires: NOW.plus(3600),
    }
}

fn sign_f(o: &Org, f: &Freshness) -> Signed {
    Signed::sign(Domain::Freshness, f, &[&o.ts]).unwrap()
}

fn bundle(o: &Org, m: &UpdateManifest) -> UpdateBundle {
    let env = sign_m(o, m);
    let f = fresh_for(&env, m);
    UpdateBundle { roots: vec![], manifest: Some(env), freshness: Some(sign_f(o, &f)) }
}

fn opts() -> VerifyOptions {
    let mut o = VerifyOptions::new(NOW, v("1.0.0"));
    o.wasm_host_abi = Some(1);
    o
}

fn client(o: &Org) -> Client {
    Client::new(o.root.pin(), &o.root_env, NOW).unwrap()
}

fn check(c: &mut Client, b: &UpdateBundle) -> Result<VerifiedUpdate> {
    c.verify("com.weirdbrains.morph", "stable", b, &opts())
}

// ---------- keys and envelopes ----------

#[test]
fn signatures_verify_and_tampering_fails() {
    let o = org(false);
    let m = manifest(1, "u1");
    let mut env = sign_m(&o, &m);
    env.verify_threshold(Domain::Manifest, &[o.release.public()], 1).unwrap();
    env.payload[3] ^= 1;
    assert!(matches!(env.verify_threshold(Domain::Manifest, &[o.release.public()], 1), Err(Error::Threshold { found: 0, .. })));
}

#[test]
fn signature_for_one_domain_never_verifies_as_another() {
    let o = org(true);
    let m = manifest(1, "u1");
    let mut env = Signed::sign(Domain::Manifest, &m, &[&o.ts]).unwrap();
    assert!(matches!(env.verify_threshold(Domain::Freshness, &[o.ts.public()], 1), Err(Error::WrongDomain { .. })));
    env.domain = Domain::Freshness;
    assert!(matches!(env.verify_threshold(Domain::Freshness, &[o.ts.public()], 1), Err(Error::Threshold { found: 0, .. })));
}

#[test]
fn repeated_and_untrusted_signatures_do_not_count() {
    let o = org(false);
    let mut env = o.root_env.clone();
    let first = env.signatures[0].clone();
    env.signatures = vec![first.clone(), first.clone(), first];
    let trusted: Vec<PublicKey> = o.root_keys.iter().map(|k| k.public()).collect();
    assert!(matches!(env.verify_threshold(Domain::Root, &trusted, 2), Err(Error::Threshold { found: 1, needed: 2, .. })));
    env.add_signature(&key(99));
    assert!(matches!(env.verify_threshold(Domain::Root, &trusted, 2), Err(Error::Threshold { found: 1, .. })));
    // A signature claiming a trusted key but made by another key.
    let forged = Signed::sign(Domain::Root, &o.root, &[&key(98)]).unwrap();
    env.signatures.push(SignatureEntry { key: o.root_keys[2].public(), sig: forged.signatures[0].sig });
    assert!(matches!(env.verify_threshold(Domain::Root, &trusted, 2), Err(Error::Threshold { found: 1, .. })));
    assert!(env.verify_threshold(Domain::Root, &trusted, 0).is_err());
}

#[test]
fn add_signature_replaces_the_same_key() {
    let o = org(false);
    let mut env = o.root_env.clone();
    env.add_signature(&o.root_keys[0]);
    assert_eq!(env.signatures.len(), 2);
}

#[test]
fn weak_and_malformed_keys_are_refused() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(PublicKey::from_bytes(identity).is_err());
    assert!(PublicKey::from_hex("zz").is_err());
    assert!(PublicKey::from_hex(&"00".repeat(31)).is_err());
    let k = key(5).public();
    assert_eq!(PublicKey::from_hex(&k.to_hex()).unwrap(), k);
}

#[test]
fn secrets_are_not_printed() {
    let k = key(7);
    let dbg = format!("{k:?}");
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains(&hex::encode(*k.to_seed())));
    let d = Device::new([9; 32], NOW);
    assert!(format!("{d:?}").contains("redacted"));
    assert!(!format!("{d:?}").contains("9, 9"));
}

#[test]
fn generated_keys_differ() {
    assert_ne!(SigningKey::generate().unwrap().public(), SigningKey::generate().unwrap().public());
}

#[test]
fn envelope_bytes_roundtrip_and_limits() {
    let o = org(false);
    let bytes = o.root_env.to_bytes().unwrap();
    assert_eq!(Signed::from_bytes(&bytes).unwrap(), o.root_env);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Signed::from_bytes(&trailing).is_err());
    assert!(Signed::from_bytes(&vec![0u8; MAX_ENVELOPE_BYTES + 1]).is_err());
    assert!(Signed::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}

// ---------- roots ----------

#[test]
fn initial_root_must_match_the_pin_and_threshold() {
    let o = org(false);
    let other = RootPin::for_keys(&[key(4).public()], 1);
    assert_eq!(Client::new(other, &o.root_env, NOW).unwrap_err(), Error::PinMismatch);
    let one = Signed::sign(Domain::Root, &o.root, &[&o.root_keys[0]]).unwrap();
    assert!(matches!(Client::new(o.root.pin(), &one, NOW), Err(Error::Threshold { found: 1, needed: 2, .. })));
    // The pin is order independent.
    let mut keys = o.root.keys.clone();
    keys.reverse();
    assert_eq!(RootPin::for_keys(&keys, 2), o.root.pin());
    assert_ne!(RootPin::for_keys(&keys, 1), o.root.pin());
    assert_eq!(RootPin::from_hex(&o.root.pin().to_string()).unwrap(), o.root.pin());
}

#[test]
fn root_validation() {
    let k1 = key(1);
    let rel = [Delegation::any(key(10).public())];
    assert!(root_doc(1, &[&k1], 1, &rel, &[]).validate().is_ok());
    assert!(root_doc(0, &[&k1], 1, &rel, &[]).validate().is_err());
    assert!(root_doc(1, &[&k1], 2, &rel, &[]).validate().is_err());
    assert!(root_doc(1, &[&k1, &k1], 1, &rel, &[]).validate().is_err());
    assert!(root_doc(1, &[], 1, &rel, &[]).validate().is_err());
    assert!(root_doc(1, &[&k1], 1, &[], &[]).validate().is_err());
    let mut r = root_doc(1, &[&k1], 1, &rel, &[]);
    r.timestamp_threshold = 1;
    assert!(r.validate().is_err());
    r.timestamp_threshold = 0;
    r.org = "bad org!".into();
    assert!(r.validate().is_err());
}

#[test]
fn root_rotation_needs_old_and_new_thresholds() {
    let o = org(false);
    let mut c = client(&o);
    let (n1, n2) = (key(41), key(42));
    let next = root_doc(2, &[&n1, &n2], 2, &[Delegation::any(key(11).public())], &[]);
    let good = Signed::sign(Domain::Root, &next, &[&o.root_keys[0], &o.root_keys[2], &n1, &n2]).unwrap();
    let only_old = Signed::sign(Domain::Root, &next, &[&o.root_keys[0], &o.root_keys[2]]).unwrap();
    let only_new = Signed::sign(Domain::Root, &next, &[&n1, &n2]).unwrap();
    assert!(matches!(c.update_root(&only_old, NOW), Err(Error::Threshold { .. })));
    assert!(matches!(c.update_root(&only_new, NOW), Err(Error::Threshold { .. })));
    c.update_root(&good, NOW).unwrap();
    assert_eq!(c.root().version, 2);
    c.update_root(&good, NOW).unwrap(); // same document again is a no-op
    assert_eq!(c.state().roots.len(), 2);

    // The old release key is no longer delegated.
    let err = check(&mut c, &bundle(&o, &manifest(1, "u1"))).unwrap_err();
    assert!(matches!(err, Error::Threshold { .. }), "{err:?}");
    // State reloads by re-verifying the chain from the pin.
    let restored = Client::from_state(o.root.pin(), c.state().clone(), NOW).unwrap();
    assert_eq!(restored.root().version, 2);
}

#[test]
fn root_rotation_refuses_skips_rollbacks_and_org_changes() {
    let o = org(false);
    let mut c = client(&o);
    let rk: Vec<&SigningKey> = o.root_keys.iter().collect();
    let rel = [Delegation::any(o.release.public())];
    let skip = root_doc(3, &rk, 2, &rel, &[]);
    let env = Signed::sign(Domain::Root, &skip, &[&o.root_keys[0], &o.root_keys[1]]).unwrap();
    assert_eq!(c.update_root(&env, NOW).unwrap_err(), Error::RootVersion { current: 1, found: 3 });
    let mut same = o.root.clone();
    same.release_threshold = 1;
    same.expires = Some(NOW.plus(DAY));
    let env = Signed::sign(Domain::Root, &same, &[&o.root_keys[0], &o.root_keys[1]]).unwrap();
    assert_eq!(c.update_root(&env, NOW).unwrap_err(), Error::RootVersion { current: 1, found: 1 });
    let mut moved = root_doc(2, &rk, 2, &rel, &[]);
    moved.org = "someone-else".into();
    let env = Signed::sign(Domain::Root, &moved, &[&o.root_keys[0], &o.root_keys[1]]).unwrap();
    assert_eq!(c.update_root(&env, NOW).unwrap_err(), Error::RootOrg);
}

#[test]
fn expired_root_is_refused() {
    let o = org(false);
    let mut r = o.root.clone();
    r.expires = Some(NOW);
    let env = Signed::sign(Domain::Root, &r, &[&o.root_keys[0], &o.root_keys[1]]).unwrap();
    assert_eq!(Client::new(r.pin(), &env, NOW).unwrap_err(), Error::Expired(Domain::Root));
}

#[test]
fn tampered_saved_state_is_refused() {
    let o = org(false);
    let c = client(&o);
    let mut state = c.state().clone();
    state.roots[0].payload[5] ^= 1;
    assert!(Client::from_state(o.root.pin(), state, NOW).is_err());
    assert!(Client::from_state(o.root.pin(), ClientState::default(), NOW).is_err());
    let bytes = c.state().to_bytes().unwrap();
    assert_eq!(ClientState::from_bytes(&bytes).unwrap(), *c.state());
}

// ---------- manifests ----------

#[test]
fn accepts_a_valid_update_with_and_without_timestamp_keys() {
    for with_ts in [true, false] {
        let o = org(with_ts);
        let mut c = client(&o);
        let b = bundle(&o, &manifest(1, "u1"));
        let ok = check(&mut c, &b).unwrap();
        assert_eq!(ok.manifest.update_id, "u1");
        assert_eq!(ok.freshness.is_some(), with_ts);
        assert_eq!(c.state().seen["com.weirdbrains.morph/stable"].seq, 1);
    }
}

#[test]
fn manifests_from_undelegated_keys_are_refused() {
    let o = org(false);
    let mut c = client(&o);
    let env = Signed::sign(Domain::Manifest, &manifest(1, "u1"), &[&key(66)]).unwrap();
    let b = UpdateBundle { manifest: Some(env), ..Default::default() };
    assert!(matches!(check(&mut c, &b), Err(Error::Threshold { found: 0, .. })));
    // A root key is not a release key either.
    let env = Signed::sign(Domain::Manifest, &manifest(1, "u1"), &[&o.root_keys[0]]).unwrap();
    let b = UpdateBundle { manifest: Some(env), ..Default::default() };
    assert!(matches!(check(&mut c, &b), Err(Error::Threshold { .. })));
    assert!(check(&mut c, &UpdateBundle::default()).is_err());
}

#[test]
fn delegations_are_scoped_and_expire() {
    let o = org(false);
    let rk: Vec<&SigningKey> = o.root_keys.iter().collect();
    let scoped = Delegation {
        key: o.release.public(),
        apps: vec!["com.weirdbrains.morph".into()],
        channels: vec!["beta".into()],
        expires: Some(NOW.plus(DAY)),
    };
    let root = root_doc(1, &rk, 2, &[scoped], &[]);
    let env = Signed::sign(Domain::Root, &root, &[&o.root_keys[0], &o.root_keys[1]]).unwrap();
    let mut c = Client::new(root.pin(), &env, NOW).unwrap();
    let b = bundle(&o, &manifest(1, "u1"));
    assert!(matches!(check(&mut c, &b), Err(Error::NotDelegated(_))));
    let mut m = manifest(1, "u1");
    m.channel = "beta".into();
    let b = bundle(&o, &m);
    c.verify("com.weirdbrains.morph", "beta", &b, &opts()).unwrap();
    let mut late = opts();
    late.now = NOW.plus(DAY);
    m.seq = 2;
    let b = bundle(&o, &m);
    assert!(matches!(c.verify("com.weirdbrains.morph", "beta", &b, &late), Err(Error::NotDelegated(_))));
    assert!(matches!(c.verify("com.other", "beta", &b, &opts()), Err(Error::NotDelegated(_))));
}

#[test]
fn manifest_for_another_app_or_channel_is_refused() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = manifest(1, "u1");
    m.app = "com.weirdbrains.muninn".into();
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::WrongTarget { .. })));
}

#[test]
fn expired_and_future_manifests_are_refused() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = manifest(1, "u1");
    m.created = NOW.minus(8 * DAY);
    m.expires = NOW;
    assert_eq!(check(&mut c, &bundle(&o, &m)).unwrap_err(), Error::Expired(Domain::Manifest));
    let mut m = manifest(1, "u1");
    m.created = NOW.plus(3600);
    m.expires = NOW.plus(DAY);
    assert_eq!(check(&mut c, &bundle(&o, &m)).unwrap_err(), Error::Expired(Domain::Manifest));
}

#[test]
fn replays_and_equivocation_are_refused() {
    let o = org(true);
    let mut c = client(&o);
    let old = bundle(&o, &manifest(1, "u1"));
    check(&mut c, &old).unwrap();
    check(&mut c, &old).unwrap(); // same manifest again is fine
    check(&mut c, &bundle(&o, &manifest(2, "u2"))).unwrap();
    assert_eq!(check(&mut c, &old).unwrap_err(), Error::Replay { last: 2, found: 1 });
    let mut twin = manifest(2, "u2-other");
    twin.notes = "different".into();
    assert_eq!(check(&mut c, &bundle(&o, &twin)).unwrap_err(), Error::Equivocation(2));
}

#[test]
fn freshness_is_required_when_the_root_trusts_timestamps() {
    let o = org(true);
    let mut c = client(&o);
    let m = manifest(1, "u1");
    let env = sign_m(&o, &m);
    let b = UpdateBundle { manifest: Some(env.clone()), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::FreshnessRequired);
    // Signed by the release key instead of the timestamp key.
    let f = Signed::sign(Domain::Freshness, &fresh_for(&env, &m), &[&o.release]).unwrap();
    let b = UpdateBundle { manifest: Some(env), freshness: Some(f), ..Default::default() };
    assert!(matches!(check(&mut c, &b), Err(Error::Threshold { domain: Domain::Freshness, .. })));
}

#[test]
fn freeze_attacks_and_stale_freshness_are_refused() {
    let o = org(true);
    let mut c = client(&o);
    let m = manifest(1, "u1");
    let env = sign_m(&o, &m);
    let mut f = fresh_for(&env, &m);
    f.issued = NOW.minus(7200);
    f.expires = NOW.minus(3600);
    let b = UpdateBundle { manifest: Some(env.clone()), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::Expired(Domain::Freshness));
    let mut f = fresh_for(&env, &m);
    f.expires = NOW.plus(30 * DAY);
    let b = UpdateBundle { manifest: Some(env.clone()), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::Expired(Domain::Freshness));
    // Freshness says a newer manifest exists: this one is stale.
    let mut f = fresh_for(&env, &m);
    f.latest_seq = 2;
    let b = UpdateBundle { manifest: Some(env.clone()), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::FreshnessMismatch);
    let mut f = fresh_for(&env, &m);
    f.manifest_hash = Hash32::of(b"other");
    let b = UpdateBundle { manifest: Some(env.clone()), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::FreshnessMismatch);
    let mut f = fresh_for(&env, &m);
    f.channel = "beta".into();
    let b = UpdateBundle { manifest: Some(env), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert!(matches!(check(&mut c, &b), Err(Error::WrongTarget { .. })));
}

#[test]
fn revoked_updates_are_refused() {
    let o = org(true);
    let mut c = client(&o);
    let m = manifest(1, "u1");
    let env = sign_m(&o, &m);
    let mut f = fresh_for(&env, &m);
    f.revoked = vec!["u1".into()];
    let b = UpdateBundle { manifest: Some(env), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::Revoked("u1".into()));
    assert!(c.state().seen.is_empty());
}

#[test]
fn without_timestamp_keys_a_bogus_freshness_record_is_ignored() {
    let o = org(false);
    let mut c = client(&o);
    let m = manifest(1, "u1");
    let env = sign_m(&o, &m);
    let mut f = fresh_for(&env, &m);
    f.revoked = vec!["u1".into()];
    let f = Signed::sign(Domain::Freshness, &f, &[&key(77)]).unwrap();
    let b = UpdateBundle { manifest: Some(env), freshness: Some(f), ..Default::default() };
    assert!(check(&mut c, &b).unwrap().freshness.is_none());
}

#[test]
fn dart_patches_are_a_placeholder_refused_by_default() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = manifest(1, "u1");
    m.kind = UpdateKind::DartPatch(DartPatch { engine_hash: "abc123".into(), platform: Platform::Android, arch: Arch::Aarch64 });
    let b = bundle(&o, &m);
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::UnsupportedKind("dart-patch"));
    let mut allow = opts();
    allow.dart_patches = true;
    c.verify("com.weirdbrains.morph", "stable", &b, &allow).unwrap();
}

#[test]
fn wasm_needs_a_matching_host_abi() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = manifest(1, "u1");
    m.kind = UpdateKind::Wasm { host_abi: 2 };
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::UnsupportedKind(_))));
    m.kind = UpdateKind::Wasm { host_abi: 1 };
    check(&mut c, &bundle(&o, &m)).unwrap();
}

#[test]
fn client_version_and_base_release_must_match() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = manifest(1, "u1");
    m.min_client = Some(v("2.0.0"));
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::ClientVersion(_))));
    let mut m = manifest(1, "u1");
    m.max_client = Some(v("0.9.0"));
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::ClientVersion(_))));
    let mut m = manifest(1, "u1");
    m.base_releases = vec!["morph-1.0.0-linux-x86_64".into()];
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::BaseMismatch(_))));
    let mut ok = opts();
    ok.base_release = Some("morph-1.0.0-linux-x86_64".into());
    c.verify("com.weirdbrains.morph", "stable", &bundle(&o, &m), &ok).unwrap();
}

fn full(version: &str) -> UpdateManifest {
    let mut m = manifest(1, "full");
    m.kind = UpdateKind::Full(FullPackage {
        platform: Platform::Linux,
        arch: Arch::X86_64,
        format: PackageFormat::TarGz,
        signing_identity: "minisign:61BA1720747F9146".into(),
    });
    m.version = v(version);
    m
}

#[test]
fn downgrades_need_a_rollback_record() {
    let o = org(false);
    let mut c = client(&o);
    let mut m = full("0.9.0");
    assert!(matches!(check(&mut c, &bundle(&o, &m)), Err(Error::Downgrade { .. })));
    m.rollback_of = Some("u-bad".into());
    check(&mut c, &bundle(&o, &m)).unwrap();
    let mut m = full("1.1.0");
    m.seq = 2;
    check(&mut c, &bundle(&o, &m)).unwrap();

    // Asset bundles compare with the installed bundle version.
    let mut a = manifest(3, "a3");
    a.version = v("2.0.0");
    let ok = check(&mut c, &bundle(&o, &a)).unwrap();
    c.mark_installed(&ok);
    let mut older = manifest(4, "a4");
    older.version = v("1.5.0");
    assert!(matches!(check(&mut c, &bundle(&o, &older)), Err(Error::Downgrade { .. })));
}

#[test]
fn updates_marked_bad_are_refused() {
    let o = org(false);
    let mut c = client(&o);
    c.mark_bad("u1");
    assert_eq!(check(&mut c, &bundle(&o, &manifest(1, "u1"))).unwrap_err(), Error::KnownBad("u1".into()));
}

#[test]
fn files_are_checked_by_size_and_hash() {
    let e = FileEntry::describe("a/b.wasm", b"0123456789");
    e.verify(b"0123456789").unwrap();
    assert!(e.verify(b"0123456788").is_err());
    assert!(e.verify(b"012345678").is_err());
    let mut s = e.verifier();
    s.update(b"01234").unwrap();
    assert!(s.update(b"56789x").is_err());
    let mut s = e.verifier();
    s.update(b"01234").unwrap();
    s.update(b"56789").unwrap();
    s.finish().unwrap();
}

#[test]
fn manifest_validation() {
    for bad in ["../x", "/etc/passwd", "a//b", "a/./b", "C:/x", "a\\b", ""] {
        let mut m = manifest(1, "u1");
        m.files = vec![FileEntry::describe(bad, b"x")];
        assert!(m.validate().is_err(), "{bad:?}");
    }
    let mut m = manifest(1, "u1");
    m.files.push(m.files[0].clone());
    assert!(m.validate().is_err());
    let mut m = manifest(1, "u1");
    m.files.clear();
    assert!(m.validate().is_err());
    let mut m = manifest(1, "u1");
    m.kind = UpdateKind::StoreNotice { url: "https://apps.apple.com/app/id1".into() };
    assert!(m.validate().is_err());
    m.files.clear();
    m.validate().unwrap();
    m.kind = UpdateKind::StoreNotice { url: "http://example.com".into() };
    assert!(m.validate().is_err());
    let mut m = manifest(1, "bad id");
    assert!(m.validate().is_err());
    m.update_id = "ok".into();
    m.capabilities = vec!["net".into(), "net".into()];
    assert!(m.validate().is_err());
    m.capabilities.clear();
    m.min_client = Some(v("2.0.0"));
    m.max_client = Some(v("1.0.0"));
    assert!(m.validate().is_err());
    let mut m = manifest(1, "u1");
    m.expires = m.created;
    assert!(m.validate().is_err());
    assert_eq!(manifest(1, "u1").total_size(), 5);
}

#[test]
fn manifests_survive_json_for_tools() {
    let mut m = full("1.2.0");
    m.labels.security = Some(SecurityLabel { severity: Severity::High, advisory: "CVE fix".into() });
    m.targeting = Some(Rule::Eq { attr: "platform".into(), value: "linux".into() });
    m.rollout = Some(RolloutPlan::immediate(NOW));
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"tar-gz\""));
    assert_eq!(serde_json::from_str::<UpdateManifest>(&json).unwrap(), m);
}

#[test]
fn package_formats_never_escalate_silently() {
    assert_eq!(PackageFormat::TarGz.install_mode(), InstallMode::Swap);
    assert_eq!(PackageFormat::Deb.install_mode(), InstallMode::PrivilegedPackageManager);
    assert_eq!(PackageFormat::Rpm.install_mode(), InstallMode::PrivilegedPackageManager);
    assert_eq!(PackageFormat::PkgTarZst.install_mode(), InstallMode::NotifyOnly);
    assert_eq!(PackageFormat::Nix.install_mode(), InstallMode::NotifyOnly);
    assert_eq!(PackageFormat::Apk.install_mode(), InstallMode::PlatformInstaller);
}

// ---------- targeting and rollout ----------

fn device() -> Device {
    let mut d = Device::new([7; 32], NOW);
    d.set("platform", "android").unwrap();
    d.set("app_version", v("2.3.1")).unwrap();
    d.set("locale", "de-AT").unwrap();
    d.set("custom.tier", 3i64).unwrap();
    d.join_cohort("beta-testers");
    d
}

#[test]
fn rules_evaluate_on_device() {
    let d = device();
    let rule = Rule::All(vec![
        Rule::In { attr: "platform".into(), values: vec!["android".into(), "ios".into()] },
        Rule::Cmp { attr: "app_version".into(), op: CmpOp::Ge, value: Value::Version(v("2.3.0")) },
        Rule::StartsWith { attr: "locale".into(), prefix: "de".into() },
        Rule::Cohort("beta-testers".into()),
        Rule::Cmp { attr: "custom.tier".into(), op: CmpOp::Gt, value: Value::Int(2) },
        Rule::Window { from: NOW.minus(1), until: NOW.plus(1) },
    ]);
    rule.validate().unwrap();
    assert!(rule.evaluate(&d));
    assert!(!Rule::Eq { attr: "platform".into(), value: "ios".into() }.evaluate(&d));
    assert!(!Rule::Eq { attr: "region".into(), value: "AT".into() }.evaluate(&d), "missing attribute is false");
    assert!(Rule::Not(Box::new(Rule::Eq { attr: "region".into(), value: "AT".into() })).evaluate(&d));
    assert!(!Rule::Cmp { attr: "locale".into(), op: CmpOp::Lt, value: Value::Int(1) }.evaluate(&d));
    assert!(!Rule::Any(vec![]).evaluate(&d));
    assert!(Rule::All(vec![]).evaluate(&d));
    assert!(!Rule::Window { from: NOW.plus(1), until: NOW.plus(2) }.evaluate(&d));
    assert!(Rule::True.evaluate(&d));
}

#[test]
fn rules_are_validated() {
    assert!(Rule::Eq { attr: "device_id".into(), value: "x".into() }.validate().is_err());
    assert!(Rule::Eq { attr: "custom.".into(), value: "x".into() }.validate().is_err());
    assert!(Rule::Cmp { attr: "locale".into(), op: CmpOp::Lt, value: "x".into() }.validate().is_err());
    assert!(Rule::In { attr: "locale".into(), values: vec![] }.validate().is_err());
    assert!(Rule::Window { from: NOW, until: NOW }.validate().is_err());
    let mut deep = Rule::True;
    for _ in 0..20 {
        deep = Rule::Not(Box::new(deep));
    }
    assert!(deep.validate().is_err());
    assert!(Rule::All(vec![Rule::True; 300]).validate().is_err());
    assert!(Device::new([0; 32], NOW).set("serial", "x").is_err());
}

#[test]
fn buckets_are_private_stable_and_spread() {
    let d = device();
    assert_eq!(d.bucket("u1"), d.bucket("u1"));
    assert_ne!(Device::new([8; 32], NOW).bucket("u1"), d.bucket("u1"));
    let mut below = 0;
    for i in 0..10_000 {
        let b = Device::new([0; 32], NOW).bucket(&format!("update-{i}"));
        assert!(b < 10_000);
        if b < 5_000 {
            below += 1;
        }
    }
    assert!((4_700..5_300).contains(&below), "{below}");
}

#[test]
fn rollout_plans() {
    let plan = RolloutPlan {
        stages: vec![
            Stage { percent_bp: 100, start_at: NOW, min_dwell_secs: DAY },
            Stage { percent_bp: 1_000, start_at: NOW.plus(DAY), min_dwell_secs: 0 },
            Stage { percent_bp: 10_000, start_at: NOW.plus(2 * DAY), min_dwell_secs: 0 },
        ],
    };
    plan.validate().unwrap();
    assert_eq!(plan.current_bp(NOW.minus(1), None), 0);
    assert_eq!(plan.current_bp(NOW, None), 100);
    assert_eq!(plan.current_bp(NOW.plus(DAY), None), 1_000);
    assert_eq!(plan.current_bp(NOW.plus(3 * DAY), Some(500)), 500);
    assert!(plan.includes(99, NOW, None) && !plan.includes(100, NOW, None));
    let mut bad = plan.clone();
    bad.stages[1].start_at = NOW.plus(10);
    assert!(bad.validate().is_err());
    let mut bad = plan.clone();
    bad.stages[2].percent_bp = 500;
    assert!(bad.validate().is_err());
    let mut bad = plan;
    bad.stages[0].percent_bp = 0;
    assert!(bad.validate().is_err());
    assert!(RolloutPlan { stages: vec![] }.validate().is_err());
}

#[test]
fn applicability_uses_targeting_rollout_and_pause_cap() {
    let o = org(true);
    let mut c = client(&o);
    let d = device();
    let mut m = manifest(1, "u1");
    m.targeting = Some(Rule::Eq { attr: "platform".into(), value: "ios".into() });
    assert_eq!(check(&mut c, &bundle(&o, &m)).unwrap().applies(&d), Applicability::NotTargeted);

    let mut m = manifest(2, "u2");
    let bucket = d.bucket("u2");
    m.rollout = Some(RolloutPlan { stages: vec![Stage { percent_bp: bucket + 1, start_at: NOW, min_dwell_secs: 0 }] });
    let env = sign_m(&o, &m);
    let mut f = fresh_for(&env, &m);
    let b = UpdateBundle { manifest: Some(env.clone()), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap().applies(&d), Applicability::Applies);
    f.rollout_cap_bp = Some(bucket); // paused just below this device
    let b = UpdateBundle { manifest: Some(env), freshness: Some(sign_f(&o, &f)), ..Default::default() };
    assert_eq!(check(&mut c, &b).unwrap().applies(&d), Applicability::NotInRolloutYet);
}

// ---------- consent policy ----------

fn pol(flavor: Flavor) -> Policy {
    Policy { flavor, dart_patches: false }
}

#[test]
fn ask_is_the_default_and_auto_is_opt_in() {
    let m = manifest(1, "u1");
    let none = BTreeSet::new();
    let mut log = ConsentLog::default();
    assert!(matches!(decide(&pol(Flavor::Desktop), &log, &m, &none), Decision::Ask { reason: AskReason::PerUpdate, .. }));
    log.set_mode(Flavor::Desktop, ConsentMode::Auto, NOW).unwrap();
    assert_eq!(decide(&pol(Flavor::Desktop), &log, &m, &none), Decision::Install);
    log.set_mode(Flavor::Desktop, ConsentMode::NotifyOnly, NOW).unwrap();
    assert_eq!(decide(&pol(Flavor::Desktop), &log, &m, &none), Decision::Notify { security: false });
    log.set_mode(Flavor::Desktop, ConsentMode::Off, NOW).unwrap();
    assert_eq!(decide(&pol(Flavor::Desktop), &log, &m, &none), Decision::Skip(SkipReason::Off));
}

#[test]
fn new_capabilities_always_ask() {
    let mut m = manifest(1, "u1");
    m.kind = UpdateKind::Wasm { host_abi: 1 };
    m.capabilities = vec!["net.fetch".into(), "storage".into()];
    let mut log = ConsentLog::default();
    log.set_mode(Flavor::Desktop, ConsentMode::Auto, NOW).unwrap();
    let granted: BTreeSet<String> = ["storage".to_string()].into();
    let d = decide(&pol(Flavor::Desktop), &log, &m, &granted);
    assert_eq!(d, Decision::Ask { reason: AskReason::NewCapabilities, new_capabilities: vec!["net.fetch".into()], security: false });
    let all: BTreeSet<String> = ["storage".to_string(), "net.fetch".to_string()].into();
    assert_eq!(decide(&pol(Flavor::Desktop), &log, &m, &all), Decision::Install);
}

#[test]
fn choices_are_remembered_and_declining_never_blocks() {
    let m = manifest(1, "u1");
    let mut log = ConsentLog::default();
    log.decide("u1", false, NOW);
    assert_eq!(decide(&pol(Flavor::Sideload), &log, &m, &BTreeSet::new()), Decision::Skip(SkipReason::Declined));
    log.decide("u1", true, NOW.plus(1));
    assert_eq!(decide(&pol(Flavor::Sideload), &log, &m, &BTreeSet::new()), Decision::Install);
    log.decide("u1", false, NOW.plus(2));
    assert_eq!(log.choice_for("u1"), Some(false));
    assert_eq!(log.choice_for("u2"), None);
}

#[test]
fn security_labels_are_prominent_but_not_forced() {
    let mut m = manifest(1, "u1");
    m.labels.security = Some(SecurityLabel { severity: Severity::Critical, advisory: "fix".into() });
    let mut log = ConsentLog::default();
    assert!(matches!(decide(&pol(Flavor::Desktop), &log, &m, &BTreeSet::new()), Decision::Ask { security: true, .. }));
    log.set_mode(Flavor::Desktop, ConsentMode::NotifyOnly, NOW).unwrap();
    assert_eq!(decide(&pol(Flavor::Desktop), &log, &m, &BTreeSet::new()), Decision::Notify { security: true });
}

#[test]
fn flavors_gate_update_kinds() {
    let none = BTreeSet::new();
    let log = ConsentLog::default();
    let full = full("2.0.0");
    for f in [Flavor::Play, Flavor::AppStore, Flavor::MacAppStore, Flavor::FDroid] {
        assert_eq!(decide(&pol(f), &log, &full, &none), Decision::Skip(SkipReason::KindNotAllowed), "{f:?}");
    }
    let mut dart = manifest(1, "d");
    dart.kind = UpdateKind::DartPatch(DartPatch { engine_hash: "e".into(), platform: Platform::Android, arch: Arch::Aarch64 });
    assert_eq!(decide(&pol(Flavor::Play), &log, &dart, &none), Decision::Skip(SkipReason::KindNotAllowed));
    let play_dart = Policy { flavor: Flavor::Play, dart_patches: true };
    assert!(matches!(decide(&play_dart, &log, &dart, &none), Decision::Ask { .. }));
    let ios_dart = Policy { flavor: Flavor::AppStore, dart_patches: true };
    assert_eq!(decide(&ios_dart, &log, &dart, &none), Decision::Skip(SkipReason::KindNotAllowed));
    let assets = manifest(1, "a");
    assert_eq!(decide(&pol(Flavor::MacAppStore), &log, &assets, &none), Decision::Skip(SkipReason::KindNotAllowed));
    let mut notice = manifest(1, "n");
    notice.kind = UpdateKind::StoreNotice { url: "https://play.google.com/store/apps/details?id=x".into() };
    notice.files.clear();
    assert_eq!(decide(&pol(Flavor::Play), &log, &notice, &none), Decision::Notify { security: false });
}

#[test]
fn fdroid_is_off_until_the_user_acknowledges_the_bypass() {
    let m = manifest(1, "u1");
    let mut log = ConsentLog::default();
    assert_eq!(decide(&pol(Flavor::FDroid), &log, &m, &BTreeSet::new()), Decision::Skip(SkipReason::Off));
    assert!(log.set_mode(Flavor::FDroid, ConsentMode::Ask, NOW).is_err());
    log.acknowledge_fdroid(NOW);
    log.set_mode(Flavor::FDroid, ConsentMode::Ask, NOW).unwrap();
    assert!(matches!(decide(&pol(Flavor::FDroid), &log, &m, &BTreeSet::new()), Decision::Ask { .. }));
}

// ---------- boot health ----------

#[test]
fn a_healthy_trial_commits() {
    let mut h = BootHealth::default();
    assert_eq!(h.begin_boot(), BootChoice::Current);
    h.stage("u1");
    assert_eq!(h.begin_boot(), BootChoice::Candidate("u1".into()));
    assert_eq!(h.mark_ready(), Some("u1".into()));
    assert_eq!(h.state, HealthState::Committed { update_id: "u1".into() });
    assert_eq!(h.begin_boot(), BootChoice::Current);
    assert_eq!(h.mark_ready(), None);
}

#[test]
fn two_failed_boots_roll_back() {
    let mut h = BootHealth::default();
    h.stage("u1");
    assert_eq!(h.begin_boot(), BootChoice::Candidate("u1".into())); // crashes
    assert_eq!(h.begin_boot(), BootChoice::Candidate("u1".into())); // crashes again
    assert_eq!(h.begin_boot(), BootChoice::RollBack("u1".into()));
    assert_eq!(h.state, HealthState::RolledBack { update_id: "u1".into() });
    assert_eq!(h.begin_boot(), BootChoice::Current);
    let json = serde_json::to_string(&h).unwrap();
    assert_eq!(serde_json::from_str::<BootHealth>(&json).unwrap(), h);
}

#[test]
fn end_to_end_failed_update_is_never_offered_again() {
    let o = org(true);
    let mut c = client(&o);
    let b = bundle(&o, &manifest(1, "u1"));
    let ok = check(&mut c, &b).unwrap();
    for f in &ok.manifest.files {
        f.verify(b"hello").unwrap();
    }
    let mut h = BootHealth::default();
    h.stage(&ok.manifest.update_id);
    h.begin_boot();
    h.begin_boot();
    if let BootChoice::RollBack(id) = h.begin_boot() {
        c.mark_bad(&id);
    }
    assert_eq!(check(&mut c, &b).unwrap_err(), Error::KnownBad("u1".into()));
}
