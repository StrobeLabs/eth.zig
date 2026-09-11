# Vendored KZG (EIP-4844 / EIP-7594) dependencies

This directory and `../blst` contain vendored C sources used to provide real,
test-vector-verified KZG support for EIP-4844 blob transactions and EIP-7594
(PeerDAS) cells.

## c-kzg-4844

- Source: https://github.com/ethereum/c-kzg-4844
- Pinned version: **v2.1.8**
- Pinned commit: `e125905e5e01186e6ccb7a0ced4845bf7eddbcfe` (the `v2.1.8` tag)
- Release tarball: `https://github.com/ethereum/c-kzg-4844/archive/refs/tags/v2.1.8.tar.gz`
  sha256 `28c9b2163c6154a0e25c7e6c30844cd75f06c971d612cdda6051b1cc19ec38a4`
- Vendored: `src/ckzg.c` (unity build) plus all headers/sources it `#include`s
  under `common/`, `eip4844/`, `eip7594/`, `setup/`, and the mainnet
  `trusted_setup.txt` (the KZG ceremony output, unchanged since v2.1.1). The
  `src/test/` tree, `src/Makefile`, `src/PROFILE.md` and `src/.clang-format`
  are intentionally not vendored.
- No local patches.

`ckzg.c` is a single translation unit that `#include`s every other `.c` file,
so the build compiles exactly one C file for c-kzg.

Notable upstream changes since the previously vendored v2.1.1: the
`verify_cell_kzg_proof_batch` Fiat-Shamir challenge now hashes the
deduplicated commitment list (c-kzg #607, found in the Fusaka audit
competition); `recover_cells_and_kzg_proofs` rejects unsorted cell indices
(#594, consensus-specs #4519); point-at-infinity handling around the blst
multi-scalar multiplication (#600, #603, #604); prover performance work
(#626, #628, #629).

## blst

- Source: https://github.com/supranational/blst
- Pinned version: **v0.3.17**
- Pinned commit: `54e6e55674722fc2797ebb4bbb71b26d881eb4b8` (the `v0.3.17` tag)
- Release tarball: `https://github.com/supranational/blst/archive/refs/tags/v0.3.17.tar.gz`
  sha256 `c3fef37b566b67419703b2bbb648e15176276af9a880c22aa8f5f2e8cecc2e4d`
- Vendored: `src/*.c`, `src/*.h` (the unity build `src/server.c`, the
  portable C backend `no_asm.h` and the addchain headers), `bindings/blst.h`,
  `bindings/blst_aux.h`, and the pre-generated assembly: `build/assembly.S`
  with the `build/elf/`, `build/mach-o/` and `build/coff/` object-format
  variants it `#include`s for x86_64 and aarch64. The perl generators under
  `src/asm/`, the MSVC `build/win64/` `.asm` files, the CHERI variants and the
  language bindings are not vendored.
- Local patch (one hunk, `src/vect.h`): the `__BLST_NO_ASM__` limb-width
  branch is hoisted above the x86_64/aarch64 branch so that a no-assembly build
  uses 32-bit limbs on every architecture (blst's `no_asm.h` only defines
  `llimb_t` for 32-bit limbs). The hunk is inert unless `__BLST_NO_ASM__` is
  defined.

blst v0.3.16 hardened `s_mult_wbits` (the fixed-base MSM used by the FK20
prover when `precompute > 0`) against an over-read and infinity inputs found
in the zkSecurity 2025 PeerDAS audit; v0.3.17 caps stack use in
`ptype##s_precompute_wbits` and refines the x86_64 carry chains.

### Build mode: portable no-assembly C

blst is built with `-D__BLST_NO_ASM__` so it uses its pure-C field arithmetic
(`src/no_asm.h`) instead of the platform assembly under `build/assembly.S`.
The assembly sources are vendored alongside the C sources (see above) so the
build can be switched per target without another vendoring pass.

`__BLST_PORTABLE__` is also defined to disable the optional SHA/crypto CPU
intrinsics path in `src/sha256.h`.

## Trusted setup

`trusted_setup.txt` (~800 KB) is `@embedFile`d by `src/kzg.zig` and loaded once
via c-kzg's `load_trusted_setup_file`, fed through an in-memory `FILE*`
(`fmemopen`). Consumers need no external setup file.

## Test vectors

`test_vectors/` holds four EIP-4844 vectors from the same release (see
`test_vectors/ATTRIBUTION.md`).
