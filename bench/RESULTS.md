# eth.zig vs alloy.rs: Ethereum Library Benchmark Comparison

Pure Zig vs Rust -- a head-to-head performance comparison of [eth.zig](https://github.com/StrobeLabs/eth.zig) and [alloy.rs](https://alloy.rs) across 26 core Ethereum operations: Keccak-256 hashing, ABI encoding/decoding, RLP serialization, secp256k1 ECDSA signing, u256 arithmetic (including UniswapV4 mulDiv with true 512-bit intermediate), hex operations, address derivation, and EIP-1559 transaction hashing.

**Score: eth.zig wins 15/26 | alloy.rs wins 10/26 | tied 1/26**

Benchmarks run on Apple Silicon with `ReleaseFast` (Zig) vs `--release` (Cargo). Both mulDiv benchmarks use true 512-bit intermediate arithmetic (eth.zig's `mulDivLimb`, alloy's `U512` from ruint).

## Full Comparison

| Benchmark | eth-zig | alloy.rs | Winner |
|---|---|---|---|
| keccak256_empty | 271 ns | 339 ns | **zig 1.25x** |
| keccak256_32b | 264 ns | 337 ns | **zig 1.28x** |
| keccak256_256b | 649 ns | 639 ns | rs 1.02x |
| keccak256_1kb | 2,105 ns | 2,433 ns | **zig 1.16x** |
| keccak256_4kb | 7,820 ns | 13,094 ns | **zig 1.67x** |
| secp256k1_sign | 161,421 ns | 51,635 ns | rs 3.13x |
| secp256k1_sign_recover | 442,999 ns | 224,690 ns | rs 1.97x |
| address_derivation | 275 ns | 366 ns | **zig 1.33x** |
| address_from_hex | 31 ns | 11 ns | rs 2.82x |
| checksum_address | 329 ns | 392 ns | **zig 1.19x** |
| abi_encode_transfer | 36 ns | 55 ns | **zig 1.53x** |
| abi_encode_static | 36 ns | 96 ns | **zig 2.67x** |
| abi_encode_dynamic | 192 ns | 342 ns | **zig 1.78x** |
| abi_decode_uint256 | 29 ns | 55 ns | **zig 1.90x** |
| abi_decode_dynamic | 40 ns | 258 ns | **zig 6.45x** |
| rlp_encode_eip1559_tx | 70 ns | 73 ns | **zig 1.04x** |
| rlp_decode_u256 | 26 ns | 10 ns | rs 2.60x |
| u256_add | 25 ns | 4 ns | rs 6.25x |
| u256_mul | 26 ns | 10 ns | rs 2.60x |
| u256_div | 30 ns | 23 ns | rs 1.30x |
| u256_uniswapv2_amount_out | 39 ns | 24 ns | rs 1.62x |
| u256_mulDiv | 33 ns | 33 ns | tie |
| u256_uniswapv4_swap | 36 ns | 48 ns | **zig 1.33x** |
| hex_encode_32b | 37 ns | 47 ns | **zig 1.27x** |
| hex_decode_32b | 36 ns | 29 ns | rs 1.24x |
| tx_hash_eip1559 | 348 ns | 406 ns | **zig 1.17x** |

## Score Summary

| | Count |
|---|---|
| eth-zig wins | 15 |
| alloy.rs wins | 10 |
| Tied | 1 |

## Key Optimizations

| Optimization | Impact |
|---|---|
| Lane-complementing Keccak-f[1600] (XKCP opt64) | keccak256_4kb: 1.67x faster than alloy |
| U256Limb limb-native arithmetic | uniswapv2: 86 ns -> 39 ns (2.2x speedup) |
| Half-word division (`div128by64`) | Replaces `__udivti3` with 2 hardware UDIVs in Knuth Algorithm D |
| `mulDivFast` non-overflow fast path | uniswapv4: 44 ns -> 36 ns, beats alloy's 48 ns |
| Knuth Algorithm D u64-limb division | mulDiv: ties alloy at 33 ns with 512-bit intermediate |
| GLV endomorphism for secp256k1 signing | secp256k1_sign: constant-time, 1.4x faster than v0.2 |
| FixedBufferAllocator in benchmarks | Eliminates GPA overhead for ABI/RLP/TX benchmarks |

## Where alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| secp256k1_sign | 3.13x | k256-rs uses variable-time precomputed tables; eth.zig is constant-time with GLV (safe for hot wallets) |
| secp256k1_sign_recover | 1.97x | Same root cause, improved via `mulDoubleBasePublic` |
| address_from_hex | 2.82x | alloy uses SIMD hex parsing; eth.zig uses scalar loop |
| u256_add | 6.25x | Benchmark measures sub-nanosecond op; dominated by zbench per-iteration overhead (~25ns floor) |
| u256_mul | 2.60x | Same schoolbook 4x4 algorithm; ruint benefits from Rust/LLVM codegen for u128 carry chains |
| u256_div | 1.30x | ruint uses MG10 reciprocal-based division; eth.zig uses half-word Knuth |
| u256_uniswapv2_amount_out | 1.62x | Compound u256 operation; ruint's tighter limb arithmetic ([see #27](https://github.com/StrobeLabs/eth.zig/issues/27)) |
| rlp_decode_u256 | 2.60x | Sub-nanosecond op dominated by benchmark overhead |
| hex_decode_32b | 1.24x | Near-parity |
| keccak256_256b | 1.02x | Near-parity |

## Reproducing

```bash
# Full comparison (requires Zig, Rust, Python 3)
bash bench/compare.sh

# eth-zig benchmarks only
zig build bench

# alloy benchmarks only
(cd bench/alloy-bench && cargo bench --bench eth_comparison)
```
