# weirdnet-update

Signed update metadata and client-side checks for Weirdnet apps. Salty Gull (the WeirdBrains
over-the-air update service for Flutter apps) builds on it; nothing here is Flutter-specific.

- **Org roots** (`root`): k-of-n Ed25519 root keys, release-key delegations scoped to apps and
  channels with expiry, and 0 or more trusted timestamp keys. Org root keys are independent
  keys, not Weirdnet user keys. Apps pin a `RootPin` (a BLAKE3 fingerprint of the first root's
  keys and threshold). Rotation needs the old and the new threshold.
- **Manifests** (`manifest`): app, channel, update id, seq, kind, version, base releases,
  per-file size and BLAKE3, client-version range, requested capabilities, security and
  "recommended" labels, a targeting rule, a staged rollout, an optional rollback target,
  notes and an expiry. Kinds: assets (including Remote Flutter Widgets files), Wasm (with a host
  ABI version), full signed package (platform, arch, format, platform signing identity), a
  reserved Dart patch placeholder that clients refuse by default, and store notices.
- **Freshness** (`freshness`): optional short-lived records from timestamp keys naming the
  latest manifest, revocations and a rollout cap (pause). Required only when the root lists
  timestamp keys.
- **Envelopes** (`envelope`): signatures over the exact CBOR payload with a domain string
  (`weirdnet-update/v1/root|manifest|freshness`), checked before decoding; duplicate and
  untrusted signatures don't count toward a threshold.
- **Client** (`verify`, `state`): the acceptance rule and persisted anti-rollback state
  (trusted root chain, last seq and manifest hash per channel, installed versions, updates
  marked bad).
- **Targeting and rollout** (`target`, `rollout`): boolean rules over device attributes and
  stages in basis points, evaluated on the device. Rollout buckets come from a keyed hash of a
  device-local secret and the update id, so no install id is needed.
- **Consent** (`policy`): ask for each update by default, opt-in automatic installs, notify
  only, or off (the F-Droid default). New capabilities always ask. Flavors gate which kinds a
  build can take (no full updates on Play, App Store, Mac App Store or F-Droid).
- **Boot health** (`health`): trial boots, commit on ready, automatic local rollback after two
  failed boots.

```rust,ignore
let mut client = Client::new(PINNED_ROOT, &initial_root_envelope, Timestamp::now())?;
let update = client.verify("com.weirdbrains.morph", "stable", &bundle, &opts)?;
if update.applies(&device) == Applicability::Applies {
    match policy::decide(&policy, &consent_log, &update.manifest, &granted) { /* … */ }
}
```

Not in this crate: transport (announcements and content transfer live in `weirdnet-net`),
installers and package-manager hand-off (Salty Gull's `salty-client`), and UI.

See [SECURITY.md](SECURITY.md) for the threat model covered by tests. Not audited.

## License

BSD-3-Clause.
