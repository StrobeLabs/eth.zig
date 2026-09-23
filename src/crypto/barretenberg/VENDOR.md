# Barretenberg dependency (Noir UltraHonk verification)

Unlike c-kzg and blst, Barretenberg is not vendored as source. It is a C++20
code base whose static library is about 50 MB per target, so `src/noir.zig`
consumes the prebuilt release archives as lazy Zig package dependencies
declared in `build.zig.zon`. Nothing is downloaded, linked or tested unless
the build is invoked with `-Dnoir=true`, and then only the archive for the
target being built is fetched (sha256-pinned through Zig's package hash).

## Barretenberg

- Source: https://github.com/AztecProtocol/aztec-packages (directory
  `barretenberg/`); releases are published from the mirror
  https://github.com/AztecProtocol/barretenberg/releases
- Pinned release: **v5.2.0** (2026-08-17)
- License: **Apache-2.0** (`barretenberg/LICENSE` in aztec-packages). The
  archives are consumed unmodified; this repository stays MIT.
- Paired Noir toolchain: nargo **1.0.0-beta.25** (the `noir-repo` submodule at
  tag v5.2.0 is exactly that release). The test vectors under
  `tests/vectors/noir/` were produced with this pairing.

Each archive contains a single file, `libbb-external.a`, and no headers. Only
the C symbols `bbapi` and `bbfree` are used; the wire format they speak
(msgpack `NamedUnion` commands) is implemented in `src/noir/msgpack.zig` and
`src/noir.zig`.

| build.zig.zon name           | Release asset                              | Upstream SHA-256 (release digest)                                  | Zig package hash                                   |
|------------------------------|--------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------|
| `barretenberg_arm64_darwin`  | `barretenberg-static-arm64-darwin.tar.gz`  | `71e4e6c904cede582374d2aaf61530090b2d7f949943648835585a931c25e054` | `N-V-__8AAKAlJwOvxF9WMTWZ6_g3tK6kxoN1XqeG0j1bIxfK` |
| `barretenberg_amd64_darwin`  | `barretenberg-static-amd64-darwin.tar.gz`  | `5923ae204ecee4aa53476447e7d4fd6fb6361f993dd20425ed4df9c533951f95` | `N-V-__8AAEi5uATDH1uT4EsKM7BxD_qgy01S6bvSVntg5M_O` |
| `barretenberg_amd64_linux`   | `barretenberg-static-amd64-linux.tar.gz`   | `3726c437ef017d6a0c0d9b5f0e854197e364bc33bf7e7ccd20aee8cac7c12e6b` | `N-V-__8AABCloQVNS5sP_eXpnSbYWfq2xQBd4DQuiwYOKmDL` |
| `barretenberg_arm64_linux`   | `barretenberg-static-arm64-linux.tar.gz`   | `12e4db24d1f6e6bbbaec360ff8eeab2d4665afd8f40b1302e4ddae6a4065d098` | `N-V-__8AAB5oGQRtvwJEs6U1kH632yGzq9QqF7aGtv8LDL-y` |

The Zig package hash covers the unpacked contents (the `.a` file), so the
build fails on any content change even if the URL still resolves. The upstream
digest column is what GitHub reports for the release asset
(`gh api repos/AztecProtocol/barretenberg/releases/tags/v5.2.0 --jq
'.assets[] | "\(.name) \(.digest)"'`) and lets a reviewer cross-check the
package hash against the artifact Aztec published.

Upstream also ships `arm64-ios`, `arm64-ios-sim`, Android and `amd64-windows`
archives; they are not wired up. Windows is out of scope (the library allocates
responses with `_aligned_malloc` there, so the `bbfree` contract differs).

CI (`.github/workflows/ci.yml`, job "Noir verify") exercises `ubuntu-latest`
(x86_64-linux) and `macos-latest` (aarch64-macos). The `arm64-linux` and
`amd64-darwin` archives are therefore validated out-of-band: run the update
procedure's step 6 on those hosts (or under emulation) at every release bump
and record the result in the pull request.

## Linking

- The archive is linked as an object file input together with libc++ and libc
  (`link_libcpp`, `link_libc` on the module). Exceptions are enabled inside the
  library and stay inside it for every post-decode failure, which the library
  reports as an `ErrorResponse`.
- macOS only: `aligned_alloc_macos.c` provides a strong C11 `aligned_alloc`.
  The archive carries a weak hidden definition of that libc-named symbol and
  Zig's Mach-O linker binds it to libSystem's strict implementation, which
  returns NULL for the non-multiple-of-alignment sizes the library requests.
  See the comment in that file.
- The archives were built by upstream with Zig's own bundled clang, not a
  distribution toolchain: `strings libbb-external.a` on the amd64-linux archive
  shows `clang version 20.1.2 (https://github.com/ziglang/zig-bootstrap
  c6bc9398c72c7a63fe9420a9055dcfd1845bc266)`, and upstream's wrappers pin
  glibc 2.35 for Linux. Zig's bundled libc++ links them cleanly.
- libc++ version delta: the archives were compiled against libc++ 20.1 headers
  while Zig 0.16 links libc++ 21.1 (`_LIBCPP_VERSION 210100`). libc++ is
  ABI-stable across these releases in its default configuration, and only the
  C symbols `bbapi` and `bbfree` cross the boundary (C++ exceptions are caught
  inside the library on every post-decode path), so no C++ type crosses it.
  Re-check this delta on any release or toolchain bump.

## CRS

Verification needs only the BN254 G1 generator and the trusted-setup G2
element `[x]_2`. Both are embedded as constants in `src/noir.zig`, copied from
`barretenberg/cpp/src/barretenberg/srs/factories/bn254_crs_data.hpp`, and the
G2 bytes are checked against the SHA-256 upstream pins in the same header. No
CRS file or download is involved. The BN254 CRS factory is first-writer-wins
per process (`init_bn254_mem_crs_factory` returns early if one is already
installed), so the one-point CRS installed by `noir.init` cannot be enlarged
later; proving support would have to change `init`.

### Why IPA (rollup) proofs are not supported

`ProofSystemSettings.ipa_accumulation` is part of the wire struct, but no
`VerifierTarget` sets it and `verify` cannot honor it. An IPA-accumulating
proof (`bb --verifier_target noir-rollup`) dispatches to `UltraFlavor, RollupIO`,
whose verifier calls `verify_ipa` and constructs a Grumpkin verifier
commitment key of `1 << CONST_ECCVM_LOG_N` = 32768 points. That reaches
`get_grumpkin_crs_factory()`, which throws unless a Grumpkin CRS was installed;
`noir.init` never sends `SrsInitGrumpkinSrs`, so such a request comes back as
`error.ProofRejected` with "You need to initialize the global CRS with a call
to init_grumpkin_crs_factory".

Supporting it would mean shipping or fetching 32768 x 64 = 2 MB of Grumpkin
points, which cannot be an embedded constant like the 192-byte BN254 pair and
would give up the offline property for that mode. One thing makes it easier
than it looks: unlike the BN254 factory, `init_grumpkin_mem_crs_factory` has no
first-writer-wins guard, so a Grumpkin CRS can be installed later in the
process without disturbing the BN254 one already in place.

## Update procedure

1. Pick the new release tag on https://github.com/AztecProtocol/barretenberg/releases
   and note the Noir version it pairs with (`barretenberg/bbup/bb-versions.json`
   or the `noir-repo` submodule commit at that tag).
2. For each of the four targets run
   `zig fetch --save=barretenberg_<target> https://github.com/AztecProtocol/barretenberg/releases/download/<tag>/barretenberg-static-<target>.tar.gz`
   and then re-add `.lazy = true` to each entry in `build.zig.zon` (`zig fetch`
   drops it).
3. Record the new upstream digests and package hashes in the table above and
   bump the release tag in `src/noir.zig` (`BARRETENBERG_VERSION`).
4. Re-validate the wire schema against the new release: the `SrsInitSrs`,
   `CircuitVerify`, `ProofSystemSettings` and response structs in
   `bbapi/bbapi_srs.hpp`, `bbapi/bbapi_ultra_honk.hpp` and
   `bbapi/bbapi_shared.hpp`, or `bb msgpack schema`. The library has no runtime
   schema check and rejects requests with missing fields by terminating the
   process, so every field must be present with the exact snake_case name.
5. Regenerate `tests/vectors/noir/` with the paired nargo/bb (see the README
   there) and refresh the reference request bytes.
6. Run `zig build test -Dnoir=true` on every wired-up host (macOS arm64,
   macOS x86_64, Linux x86_64, Linux aarch64), plus the default `make ci`,
   before committing. CI covers only the first and third, so record the other
   two in the pull request.
