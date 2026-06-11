# Vendored KZG (EIP-4844) dependencies

This directory and `../blst` contain vendored C sources used to provide real,
test-vector-verified KZG support for EIP-4844 blob transactions.

## c-kzg-4844

- Source: https://github.com/ethereum/c-kzg-4844
- Pinned version: **v2.1.1**
- Pinned commit: `28743bc8a2d89d737e63e8d9ca63fe23fdccdd80`
- Vendored: `src/ckzg.c` (unity build) plus all headers/sources it `#include`s
  under `common/`, `eip4844/`, `eip7594/`, `setup/`, and the mainnet
  `trusted_setup.txt` (the KZG ceremony output). The `src/test/` tree and the
  `Makefile`/`PROFILE.md` are intentionally not vendored.

`ckzg.c` is a single translation unit that `#include`s every other `.c` file,
so the build compiles exactly one C file for c-kzg.

## blst

- Source: https://github.com/supranational/blst
- Pinned version: **v0.3.14**
- Pinned commit: `8c7db7fe8d2ce6e76dc398ebd4d475c0ec564355`
- Vendored: `src/*.c`, `src/*.h` (the unity build `src/server.c` plus the
  portable C backend `no_asm.h` and the addchain headers) and
  `bindings/blst.h`, `bindings/blst_aux.h`.

### Build mode: portable no-assembly C

blst is built with `-D__BLST_NO_ASM__` so it uses its pure-C field arithmetic
(`src/no_asm.h`) instead of the platform assembly under `src/asm/` and
`build/assembly.S`. This keeps the build simple and robust across targets (no
GAS-vs-clang assembler issues, no per-arch `.S` selection) at a modest
performance cost, which is acceptable for sidecar construction. The assembly
sources are therefore not vendored.

`__BLST_PORTABLE__` is also defined to disable the optional SHA/crypto CPU
intrinsics path in `src/sha256.h`.

## Trusted setup

`trusted_setup.txt` (~800 KB) is `@embedFile`d by `src/kzg.zig` and loaded once
via c-kzg's `load_trusted_setup_file`, fed through an in-memory `FILE*`
(`fmemopen`). Consumers need no external setup file.
