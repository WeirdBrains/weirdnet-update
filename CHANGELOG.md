# Changelog

## [Unreleased]

### Added

- `UNSIGNED` (`"unsigned"`): the signing identity of a plain file set with no platform signature, accepted only for `tar-gz` and `zip` packages. `FullPackage::platform_signed` and `FullPackage::signing_identity_matches(running)` (equal identities only, so `unsigned` matches only `unsigned`).

### Changed

- Manifest validation refuses `"unsigned"` as the signing identity of any other package format.

## [0.2.0] - 2026-11-16

### Added

- Signed update announcements, a carrier that keeps the latest per org, app and channel, and on-device checks.
- The `wire` feature: the announcement stream protocol relays carry.

### Changed

- `Domain` has an `Announcement` variant, so exhaustive matches on it need a new arm.

## [0.1.0] - 2026-11-12

### Added

- Org roots with k-of-n keys, scoped release delegations, optional timestamp keys and rotation.
- Signed update manifests for assets, Wasm, full packages, store notices and a reserved Dart patch kind.
- Optional freshness records with revocation and rollout caps.
- Client acceptance rule with anti-rollback state.
- On-device targeting rules and staged rollouts.
- Opt-in consent policy and boot-health rollback.
