//! Announcement threat-model tests.

use super::*;
use crate::manifest::{FileEntry, Labels, UpdateKind};
use crate::root::Delegation;
use crate::verify::{Client, UpdateBundle, VerifyOptions};
use semver::Version;

const NOW: Timestamp = Timestamp(1_800_000_000);
const DAY: u64 = 86_400;

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

struct Org {
    roots: Vec<SigningKey>,
    release: SigningKey,
    root: Root,
    env: Signed,
    pin: RootPin,
}

fn org(seed: u8, release: Vec<Delegation>) -> Org {
    let roots = vec![key(seed), key(seed + 1)];
    let root = Root {
        version: 1,
        org: "weirdbrains".into(),
        keys: roots.iter().map(|k| k.public()).collect(),
        threshold: 2,
        release,
        release_threshold: 1,
        timestamp: vec![],
        timestamp_threshold: 0,
        expires: None,
    };
    let env = Signed::sign(Domain::Root, &root, &[&roots[0], &roots[1]]).unwrap();
    let pin = root.pin();
    Org { roots, release: key(seed + 10), root, env, pin }
}

fn weirdbrains() -> Org {
    org(1, vec![Delegation { key: key(11).public(), apps: vec!["org.weirdbrains.morph".into()], channels: vec![], expires: None }])
}

fn manifest(o: &Org, seq: u64) -> Signed {
    let m = UpdateManifest {
        app: "org.weirdbrains.morph".into(),
        channel: "stable".into(),
        update_id: format!("u{seq}"),
        seq,
        kind: UpdateKind::Assets,
        version: Version::new(1, 0, seq),
        base_releases: vec![],
        files: vec![FileEntry::describe("ui/main.rfw", b"hello")],
        min_client: None,
        max_client: None,
        capabilities: vec![],
        labels: Labels::default(),
        targeting: None,
        rollout: None,
        rollback_of: None,
        notes: String::new(),
        created: NOW,
        expires: NOW.plus(7 * DAY),
    };
    Signed::sign(Domain::Manifest, &m, &[&o.release]).unwrap()
}

fn announce(o: &Org, m: &Signed) -> (Announcement, Signed) {
    let a = Announcement::for_manifest("weirdbrains", o.pin, m, NOW, DAY, vec!["https://updates.weirdbrains.com/morph".into()]).unwrap();
    let env = a.sign(&[&o.release]).unwrap();
    (a, env)
}

#[test]
fn a_device_hears_and_then_verifies_the_full_bundle() {
    let o = weirdbrains();
    let m = manifest(&o, 3);
    let (a, env) = announce(&o, &m);
    let mut client = Client::new(o.pin, &o.env, NOW).unwrap();
    let heard = client.verify_announcement(&env, NOW).unwrap().expect("news");
    assert_eq!(heard, a);
    assert!(heard.names(&m));
    assert!(!heard.names(&manifest(&o, 4)));
    let opts = VerifyOptions::new(NOW, Version::new(1, 0, 0));
    client.verify("org.weirdbrains.morph", "stable", &UpdateBundle { manifest: Some(m), ..Default::default() }, &opts).unwrap();
    // Once that seq is seen, the same announcement is no longer news.
    assert_eq!(client.verify_announcement(&env, NOW).unwrap(), None);
}

#[test]
fn forged_misscoped_or_stale_announcements_are_refused() {
    let o = weirdbrains();
    let m = manifest(&o, 1);
    let (a, env) = announce(&o, &m);
    let client = Client::new(o.pin, &o.env, NOW).unwrap();

    // Signed by a key the root doesn't delegate.
    let forged = a.sign(&[&key(99)]).unwrap();
    assert!(matches!(client.verify_announcement(&forged, NOW), Err(Error::Threshold { .. })));
    // A delegated key outside its scope: the release key covers only Morph.
    let mut other = a.clone();
    other.app = "org.weirdbrains.muninn".into();
    assert!(matches!(client.verify_announcement(&other.sign(&[&o.release]).unwrap(), NOW), Err(Error::NotDelegated(_))));
    // Tampered after signing.
    let mut t = env.clone();
    let mut changed = a.clone();
    changed.seq = 9;
    t.payload = crate::cbor::to_vec(&changed).unwrap();
    assert!(client.verify_announcement(&t, NOW).is_err());
    // A manifest signature doesn't pass as an announcement, nor the other way round.
    let as_manifest = Signed { domain: Domain::Manifest, ..env.clone() };
    assert!(matches!(client.verify_announcement(&as_manifest, NOW), Err(Error::WrongDomain { .. })));
    let mut cross = env.clone();
    cross.domain = Domain::Announcement;
    cross.payload = m.payload.clone();
    cross.signatures = m.signatures.clone();
    assert!(client.verify_announcement(&cross, NOW).is_err());
    // Expired, or published far in the future.
    assert!(matches!(client.verify_announcement(&env, NOW.plus(DAY)), Err(Error::Expired(Domain::Announcement))));
    assert!(matches!(client.verify_announcement(&env, NOW.minus(3600)), Err(Error::Expired(Domain::Announcement))));
    // Another org's pin.
    let mut wrong = a.clone();
    wrong.pin = RootPin::for_keys(&[key(50).public()], 1);
    assert!(matches!(client.verify_announcement(&wrong.sign(&[&o.release]).unwrap(), NOW), Err(Error::PinMismatch)));
    // Shape limits.
    let mut long = a.clone();
    long.expires = long.published.plus(MAX_LIFETIME_SECS + 1);
    assert!(long.sign(&[&o.release]).is_err());
    let mut src = a.clone();
    src.sources = vec!["http://plain.example".into()];
    assert!(src.sign(&[&o.release]).is_err());
    assert!(Announcement::for_manifest("weirdbrains", o.pin, &env, NOW, DAY, vec![]).is_err(), "not a manifest");
}

#[test]
fn carriers_keep_the_latest_for_trusted_orgs_only() {
    let o = weirdbrains();
    let mut c = Carrier::new(100);
    let (_, a1) = announce(&o, &manifest(&o, 1));
    assert!(matches!(c.offer(&a1, NOW), Err(Error::PinMismatch)), "untrusted org");
    c.trust(o.pin, std::slice::from_ref(&o.env), NOW).unwrap();
    assert!(c.trust(RootPin::for_keys(&[key(50).public()], 1), std::slice::from_ref(&o.env), NOW).is_err());
    assert_eq!(c.offer(&a1, NOW).unwrap(), Offered::New);
    assert_eq!(c.offer(&a1, NOW).unwrap(), Offered::Same);
    let (_, a2) = announce(&o, &manifest(&o, 2));
    assert_eq!(c.offer(&a2, NOW).unwrap(), Offered::New);
    assert_eq!(c.offer(&a1, NOW).unwrap(), Offered::Stale, "an older seq never replaces a newer one");
    assert_eq!(c.len(), 1);
    let morph = Topic { pin: o.pin, app: "org.weirdbrains.morph".into(), channel: "stable".into() };
    let beta = Topic { channel: "beta".into(), ..morph.clone() };
    let all_apps = Topic { pin: o.pin, app: String::new(), channel: String::new() };
    assert_eq!(c.matching(std::slice::from_ref(&morph), NOW), vec![a2.clone()]);
    assert!(c.matching(&[beta], NOW).is_empty());
    assert_eq!(c.matching(&[all_apps], NOW).len(), 1);
    assert!(Carrier::matches(&a2, &[morph]));
    // A forgery for a trusted org is refused, not stored.
    let (a, _) = announce(&o, &manifest(&o, 5));
    assert!(c.offer(&a.sign(&[&key(99)]).unwrap(), NOW).is_err());
    assert_eq!(c.len(), 1);
    // Expiry.
    c.prune(NOW.plus(2 * DAY));
    assert!(c.is_empty());
    assert!(c.all(NOW).is_empty());
}

#[test]
fn carriers_follow_root_rotations() {
    let o = weirdbrains();
    let mut c = Carrier::new(10);
    c.trust(o.pin, std::slice::from_ref(&o.env), NOW).unwrap();
    // v2 delegates a new release key; announcements signed by it are accepted only after
    // the rotation arrives.
    let new_release = key(40);
    let mut v2 = o.root.clone();
    v2.version = 2;
    v2.release = vec![Delegation::any(new_release.public())];
    let rot = Signed::sign(Domain::Root, &v2, &[&o.roots[0], &o.roots[1]]).unwrap();
    let a = Announcement::for_manifest("weirdbrains", o.pin, &manifest(&o, 7), NOW, DAY, vec![]).unwrap();
    let env = a.sign(&[&new_release]).unwrap();
    assert!(c.offer(&env, NOW).is_err());
    assert_eq!(c.offer(&rot, NOW).unwrap(), Offered::Root);
    assert_eq!(c.offer(&rot, NOW).unwrap(), Offered::Same);
    assert_eq!(c.chain(&o.pin).unwrap().len(), 2);
    assert_eq!(c.offer(&env, NOW).unwrap(), Offered::New);
    // A rotation not signed by the current root is refused.
    let mut bad = v2.clone();
    bad.version = 3;
    let other = [key(60), key(61)];
    bad.keys = other.iter().map(|k| k.public()).collect();
    assert!(c.offer(&Signed::sign(Domain::Root, &bad, &[&other[0], &other[1]]).unwrap(), NOW).is_err());
}

#[test]
fn carriers_stay_bounded() {
    let o = org(1, vec![Delegation::any(key(11).public())]);
    let mut c = Carrier::new(3);
    c.trust(o.pin, std::slice::from_ref(&o.env), NOW).unwrap();
    for i in 0..10u64 {
        let mut a = Announcement::for_manifest("weirdbrains", o.pin, &manifest(&o, 1), NOW.plus(i), DAY, vec![]).unwrap();
        a.channel = format!("c{i}");
        assert_eq!(c.offer(&a.sign(&[&o.release]).unwrap(), NOW.plus(i)).unwrap(), Offered::New);
    }
    assert_eq!(c.len(), 3);
}

#[cfg(feature = "wire")]
#[test]
fn wire_frames_round_trip_and_are_bounded() {
    use super::wire::*;
    use futures_util::FutureExt;
    async {
        let o = weirdbrains();
        let (_, env) = announce(&o, &manifest(&o, 1));
        let mut buf = Vec::new();
        write(&mut buf, &FromCarrier::Envelope(env.clone())).await.unwrap();
        write(&mut buf, &FromCarrier::Keepalive).await.unwrap();
        let mut r = futures_util::io::Cursor::new(buf);
        assert_eq!(read::<_, FromCarrier>(&mut r).await.unwrap(), Some(FromCarrier::Envelope(env)));
        assert_eq!(read::<_, FromCarrier>(&mut r).await.unwrap(), Some(FromCarrier::Keepalive));
        assert_eq!(read::<_, FromCarrier>(&mut r).await.unwrap(), None);
        let mut big = futures_util::io::Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes().to_vec());
        assert!(read::<_, FromCarrier>(&mut big).await.is_err());
    }
    .now_or_never()
    .unwrap();
}
