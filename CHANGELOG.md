# Changelog — goodnet-security-noise

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_security_vtable_t`.

## [Unreleased]

### `provides_flags` vtable slot

Added `provides_flags` lambda to `make_vtable()` returning
`GN_SEC_PROVIDES_E2E_ENCRYPTION | GN_SEC_PROVIDES_AUTHENTICATION |
GN_SEC_PROVIDES_FORWARD_SECRECY`. The kernel uses this slot to
advertise the security properties of an active session to upper
layers without re-inspecting the provider name.

### IK pattern + isolated test suite

The provider now exposes the Noise IK pattern as a light
wrapper over the existing XX core. IK skips the initial
identity exchange when the responder's static public key is
already known to the initiator, which cuts the handshake to a
single round-trip for first-contact paths where the address is
authenticated out-of-band (e.g. via gn.dns or operator
config). The handshake driver shares the same cipher / hash /
rekey paths as XX so the security surface stays uniform; the
new test suite under `tests/` exercises the IK leg in
isolation.

Track C abort breadcrumbs are emitted on each handshake
failure path so the operator-visible reason for a rejected
connection lands in the kernel's diagnostics channel rather
than disappearing into a generic `ENOSEC`.

## [1.0.0-rc1] — 2026-05-08

Initial release. Noise XX security provider extracted from the
legacy in-tree `security/noise` into its own plugin git.

### Added

- `Noise_XX_25519_ChaChaPoly_BLAKE2b` on libsodium primitives
  with the prologue `"goodnet/v1/noise"` per Noise §6.5.
- Atomic rekey on either cipher reaching `2^60` bytes;
  per-direction counters are independent and a single rekey
  swaps both directions in lock-step.
- Ed25519 mesh-address keys are crossed to X25519 inside this
  plugin via libsodium's birational map. The kernel never sees
  the X25519 form — the trust-class boundary stays clean
  against the mesh-address surface in
  `docs/contracts/security-trust.en.md`.
- `noise` provider registered via `gn_plugin_init` through the
  `GN_PLUGIN_*_NAME` macros so static-link variants pick up the
  correct entry symbol prefix.
- Wire format + handshake specification at `docs/handshake.en.md`.

### Out of scope for v1

- UDP / datagram framing class. The current provider is
  stream-only; datagram callers need a frame-layer replay
  window the v1 provider does not implement.
- PSK-based patterns. XX (mutual auth, no preshared peer pk) is
  the only pattern in the initial release; IK lands later as an
  additive surface.
