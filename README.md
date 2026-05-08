# goodnet-security-noise

Noise XX security provider for GoodNet. Pattern
`Noise_XX_25519_ChaChaPoly_BLAKE2b` on libsodium primitives, with
the prologue `"goodnet/v1/noise"` per Noise §6.5 and atomic rekey
on either cipher reaching `2^60`. The Ed25519 mesh-address keys
cross to X25519 inside this plugin via libsodium's birational map;
the kernel never sees the X25519 form.

**Kind**: security provider · **Artefact**: dynamic plugin (`.so` via
dlopen) · **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input (libsodium on the build path). From
this checkout:

```sh
nix run .#build         # release build of libgoodnet_security_noise.so
nix run .#test          # vanilla ctest (handshake, transport, rekey)
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `noise` provider. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Contract

- Wire format + handshake spec: [`docs/handshake.md`](docs/handshake.md)
- Kernel-side trust-class policy: `docs/contracts/security-trust.en.md`
- Pattern: Noise XX (mutual auth, no preshared peer pk).
  IK as a v1.x sibling provider lands separately under
  `goodnet-security-noise-ik`.
