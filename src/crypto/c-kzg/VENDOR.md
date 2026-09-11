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

`ckzg_shim.c` (next to this file, outside `src/`) is eth.zig-owned, not part
of the release: it exports `sizeof`/`_Alignof(KZGSettings)` so `src/kzg.zig`
can size opaque storage for the settings instead of mirroring the struct
layout. Keep it when re-vendoring.

Notable upstream changes since the previously vendored v2.1.1, verified
against the diff rather than release notes:

- `recover_cells_and_kzg_proofs` now requires cell indices in strictly
  ascending order and rejects anything else with `C_KZG_BADARGS` (#594,
  consensus-specs #4519). v2.1.1 accepted shuffled indices, so this is a
  behaviour change for callers.
- The `verify_cell_kzg_proof_batch` Fiat-Shamir challenge preimage now
  includes `FIELD_ELEMENTS_PER_BLOB` alongside `FIELD_ELEMENTS_PER_CELL`,
  so the challenge differs from the one v2.1.1 computed and matches the
  current reference vectors. Note that #607 ("create cell verification
  challenge with deduplicated commitments") repaired a regression
  introduced *after* v2.1.1: v2.1.1 already passed the deduplicated list,
  so that bug never reached this repository.
- Point-at-infinity handling in `g1_lincomb_fast` was reworked around the
  blst multi-scalar multiplication (#600, #601, #603, #604, #606).
- Prover and helper performance work (#626, #628, #629, #644).

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

### Build mode: blst assembly on x86_64 and aarch64, portable C elsewhere

`build.zig` (`addKzg`) compiles blst the way upstream c-kzg-4844's own
`build.zig` does on x86_64 and aarch64: `src/server.c` plus the pre-generated
`build/assembly.S`, which `#include`s the `.s`/`.S` files for the target's
object format (`elf/` on Linux, `mach-o/` on macOS, `coff/` on Windows). Both
files get `-O2 -ffreestanding -D__BLST_PORTABLE__`; `__BLST_PORTABLE__` makes
the x86_64 assembly carry both the ADX (`mulx`) and the baseline (`mulq`)
variants and pick one at run time via `cpuid`, so a `-Dcpu=baseline` build
still runs on any x86_64 CPU, and it disables the SHA CPU-intrinsics path in
`src/sha256.h`. `assembly.S` is added as a C source file (not via
`addAssemblyFile`) because it must be preprocessed with the same defines.

Every other target (and any x86_64/aarch64 build with `-Dblst-asm=false`)
uses the portable no-assembly C backend: `-D__BLST_NO_ASM__` selects
`src/no_asm.h` with 32-bit limbs (the vect.h patch above). That path is
6-8x slower and exists only as a fallback.

The earlier rationale for shipping the portable build everywhere ("GAS versus
clang assembler conflicts") no longer applies: with Zig 0.16 the `.S` file is
assembled by Zig's bundled clang, exactly as upstream's CI does on Linux,
macOS and Windows.

Measured on an Apple M4 (ReleaseFast, minimum of repeated runs, the two
columns taken back to back from the same commit):

| Operation | `-Dblst-asm=false` | assembly | speedup |
| --- | ---: | ---: | ---: |
| trusted setup load | 7383 ms | 1136 ms | 6.5x |
| `blob_to_kzg_commitment` | 200 ms | 25.9 ms | 7.7x |
| `compute_blob_kzg_proof` | 205 ms | 26.4 ms | 7.8x |
| `verify_blob_kzg_proof` | 7.26 ms | 1.10 ms | 6.6x |
| `compute_cells_and_kzg_proofs` | 1156 ms | 158 ms | 7.3x |
| `verify_cell_kzg_proof_batch` (1 / 128 cells) | 12.2 / 69.5 ms | 1.67 / 10.8 ms | 7.3x / 6.4x |
| `recover_cells_and_kzg_proofs` (64 cells) | 1233 ms | 173 ms | 7.1x |

Reproduce with `zig build bench-kzg [-Dblst-asm=false]`.

Targets exercised for the assembly path: aarch64-macos (native, full test
suite), aarch64-linux-musl and x86_64-linux-musl (`-Dcpu=baseline`,
cross-compiled; the aarch64 binary runs the full suite in a Linux container),
x86_64-macos and x86_64/aarch64-windows-gnu (compile and assemble only).
riscv64-linux-musl and wasm32 exercise the portable fallback.

## Re-vendoring checklist

1. Download the release tarballs, record their sha256 above, and replace
   `c-kzg/src/` (minus `test/`, `Makefile`, `PROFILE.md`, `.clang-format`),
   `blst/src/*.{c,h}`, `blst/bindings/blst{,_aux}.h` and
   `blst/build/{assembly.S,elf,mach-o,coff}`.
2. Re-apply the `vect.h` hunk (it is the only patch) and keep
   `c-kzg/ckzg_shim.c`.
3. Refresh `test_vectors/` and `tests/vectors/kzg/` if upstream regenerated
   or renamed cases, and update the tag in both attribution files.
4. Run `make ci`. `src/kzg.zig` does not mirror any C struct, so a layout
   change needs no Zig edit; a new or renamed C function does.

## Trusted setup

`trusted_setup.txt` (~800 KB) is `@embedFile`d by `src/kzg.zig` and loaded once
via c-kzg's `load_trusted_setup_file`, fed through an in-memory `FILE*`
(`fmemopen`). Consumers need no external setup file. The file is byte-identical
to the one vendored with v2.1.1; upstream has not changed its format.

`fmemopen` is POSIX, so this path does not link on Windows targets. Switching
to `load_trusted_setup` over the parsed point bytes (as upstream's own Zig
bindings do) would remove that limitation and is the natural follow-up.

## Test vectors

`test_vectors/` holds four EIP-4844 vectors from the same release, embedded by
the unit tests (see `test_vectors/ATTRIBUTION.md`). The point-evaluation and
EIP-7594 cell vectors, plus the go-ethereum blob-transaction cross-check, live
under `tests/vectors/kzg/` and run as `zig build vector-test`; that directory's
README lists the selection.
