# weirdnet-update security notes

Not audited. This records what the 0.1 design checks and what it leaves to callers.

## Primitives

| Need | Construction | Crate |
| ---- | ---- | ---- |
| Signatures | Ed25519, `verify_strict`, weak keys refused at parse | `ed25519-dalek` 2 |
| File and payload hashes, root pin, rollout bucket | BLAKE3 (derive-key and keyed modes) | `blake3` 1 |
| Encoding | CBOR; signatures cover the exact bytes, trailing bytes refused | `ciborium` 0.2 |
| Randomness | OS generator | `getrandom` 0.2 |

## Threats tested

- Forged or tampered manifests, roots and freshness records; signatures from untrusted keys,
  root keys used as release keys, and repeated signatures from one key (they count once).
- Cross-domain reuse: a signature made for one record kind never verifies as another.
- Pin mismatch; root rotation without the old or the new threshold; skipped, repeated or
  reused root versions; org changes; expired roots; tampered saved state.
- Release keys outside their app/channel scope or past their delegation expiry.
- Replay of an older seq, and equivocation (two manifests with one seq).
- Freeze attacks: expired or over-long freshness records; freshness naming a newer manifest.
- Revocation through freshness; updates marked bad after failed boots.
- Downgrades without a signed rollback record (full packages against the running version,
  bundles against the installed bundle version).
- Unsafe file paths (absolute, `..`, drive letters, backslashes), duplicate paths, size and
  hash mismatches, streamed bodies longer than declared.
- Kind gating: Dart patches refused unless enabled, Wasm only for the matching host ABI, store
  flavors never take full updates.
- Consent: nothing installs without an opt-in (auto mode or a per-update accept); new
  capabilities always ask; declines are remembered; F-Droid stays off until the bypass wording
  is acknowledged.
- Announcements: forged, tampered or out-of-scope ones, other orgs' pins, expired or
  future-dated ones, and manifest signatures replayed as announcements are refused. Carriers
  keep only announcements for orgs they trust, never let an older seq replace a newer one,
  follow root rotations only from their trusted root, and stay bounded.

## Limits

- Apps whose root trusts no timestamp key get weaker freeze protection (bounded by the
  manifest expiry the org chose), and takedowns can't reach installed copies.
- Envelope payloads are decoded before verification only for the initial root (whose keys are
  checked against the pin first), for rotations (after the old threshold verified) and for
  announcements (to learn which app and channel's keys to check; nothing is used before the
  check passes).
- An announcement only says a manifest exists. It never makes an update acceptable: the
  device still fetches the bundle and runs the full acceptance rule, and consent still
  applies. A carrier can withhold announcements, so devices should also poll.
- Cohort tokens, platform signing-identity comparison, minisign checks and installers are the
  caller's (`salty-client`).
- The rollout bucket secret and the consent log are stored by the app; this crate never writes
  files.
- No fuzzing yet.
