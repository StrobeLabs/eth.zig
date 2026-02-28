# eth.zig vs alloy.rs: Ethereum Library Benchmark Comparison

Pure Zig vs Rust -- a head-to-head performance comparison of [eth.zig](https://github.com/StrobeLabs/eth.zig) and [alloy.rs](https://alloy.rs) across 26 core Ethereum operations: Keccak-256 hashing, ABI encoding/decoding, RLP serialization, secp256k1 ECDSA signing, u256 arithmetic (including UniswapV4 mulDiv with true 512-bit intermediate), hex operations, address derivation, and EIP-1559 transaction hashing.

**Score: eth.zig wins 17/26 | alloy.rs wins 7/26 | tied 2/26**

Benchmarks run on Apple Silicon with `ReleaseFast` (Zig) vs `--release` (Cargo). Both mulDiv benchmarks use true 512-bit intermediate arithmetic (eth.zig's native `mulDiv`, alloy's `U512` from ruint).

## Full Comparison

| Benchmark | eth-zig | alloy.rs | Winner |
|---|---|---|---|
| keccak256_empty | 301 ns | 335 ns | zig 1.11x |
| keccak256_32b | 300 ns | 337 ns | zig 1.12x |
| keccak256_256b | 626 ns | 641 ns | zig 1.02x |
| keccak256_1kb | 2,463 ns | 2,435 ns | rs 1.01x |
| keccak256_4kb | 9,536 ns | 9,278 ns | rs 1.03x |
| secp256k1_sign | 161,919 ns | 51,659 ns | rs 3.13x |
| secp256k1_sign_recover | 443,770 ns | 219,160 ns | rs 2.02x |
| address_derivation | 299 ns | 363 ns | zig 1.21x |
| address_from_hex | 15 ns | 26 ns | zig 1.73x |
| checksum_address | 351 ns | 388 ns | zig 1.11x |
| abi_encode_transfer | 63 ns | 55 ns | rs 1.15x |
| abi_encode_static | 59 ns | 97 ns | zig 1.64x |
| abi_encode_dynamic | 228 ns | 326 ns | zig 1.43x |
| abi_decode_uint256 | 47 ns | 50 ns | zig 1.06x |
| abi_decode_dynamic | 151 ns | 257 ns | zig 1.70x |
| rlp_encode_eip1559_tx | 85 ns | 71 ns | rs 1.20x |
| rlp_decode_u256 | 6 ns | 10 ns | zig 1.67x |
| u256_add | 4 ns | 4 ns | tie |
| u256_mul | 5 ns | 9 ns | zig 1.80x |
| u256_div | 8 ns | 24 ns | zig 3.00x |
| u256_uniswapv2_amount_out | 86 ns | 24 ns | rs 3.58x |
| u256_mulDiv | 24 ns | 33 ns | zig 1.38x |
| u256_uniswapv4_swap | 41 ns | 49 ns | zig 1.20x |
| hex_encode_32b | 21 ns | 21 ns | tie |
| hex_decode_32b | 23 ns | 47 ns | zig 2.04x |
| tx_hash_eip1559 | 399 ns | 404 ns | zig 1.01x |

## Score Summary

| | Count |
|---|---|
| eth-zig wins | 17 |
| alloy.rs wins | 7 |
| Tied | 2 |

## Key Optimizations in v0.3.0

| Optimization | Impact |
|---|---|
| GLV endomorphism for secp256k1 signing | secp256k1_sign: 4.09x loss -> 3.13x loss (1.40x speedup) |
| Lane-complementing Keccak-f[1600] (XKCP opt64) | keccak256_32b: 340 ns -> 300 ns (1.13x speedup) |
| Knuth Algorithm D u64-limb division | mulDiv: 281 ns -> 24 ns, beats alloy's 33 ns |
| secp256k1 `mulDoubleBasePublic` recovery | sign_recover: 837 us -> 444 us (1.9x) |
| Stack-buffer RLP encoding (single pass) | rlp_encode: 89 ns -> 85 ns |
| ABI static-only fast path | abi_encode_static: 71 ns -> 59 ns |
| `fastMul` u128 fast path | u256 compound ops: 2x faster |

## Remaining alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| secp256k1_sign | 3.13x | k256-rs uses variable-time precomputed tables; eth.zig is constant-time with GLV (safe for hot wallets) |
| secp256k1_sign_recover | 2.02x | Same root cause, improved via `mulDoubleBasePublic` |
| u256_uniswapv2_amount_out | 3.58x | alloy's `ruint` uses hand-optimized 4x u64 limb arithmetic; LLVM's u256 compound ops are slow |
| abi_encode_transfer | 1.15x | alloy's `sol!` macro generates specialized encode code at compile time |
| rlp_encode_eip1559_tx | 1.20x | alloy derive macros produce single-purpose encode code |
| keccak256_1kb | 1.01x | Near-parity; alloy uses tiny-keccak (Rust) |
| keccak256_4kb | 1.03x | Near-parity; alloy uses tiny-keccak (Rust) |

## Reproducing

```bash
# Full comparison (requires Zig, Rust, Python 3)
bash bench/compare.sh

# eth-zig benchmarks only
zig build bench

# alloy benchmarks only
(cd bench/alloy-bench && cargo bench --bench eth_comparison)
```
