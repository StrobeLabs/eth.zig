# eth.zig vs alloy.rs: Ethereum Library Benchmark Comparison

Pure Zig vs Rust -- a head-to-head performance comparison of [eth.zig](https://github.com/StrobeLabs/eth.zig) and [alloy.rs](https://alloy.rs) across 26 core Ethereum operations: Keccak-256 hashing, ABI encoding/decoding, RLP serialization, secp256k1 ECDSA signing, u256 arithmetic (including UniswapV4 mulDiv), hex operations, address derivation, and EIP-1559 transaction hashing.

**Score: eth.zig wins 19/26 | alloy.rs wins 5/26 | tied 2/26**

Benchmarks run on Apple Silicon with `ReleaseFast` (Zig) and `--release` (Cargo).

## Full Comparison

| Benchmark | eth-zig | alloy.rs | Winner |
|---|---|---|---|
| keccak256_empty | 119 ns | 173 ns | zig 1.45x |
| keccak256_32b | 128 ns | 175 ns | zig 1.37x |
| keccak256_256b | 258 ns | 334 ns | zig 1.29x |
| keccak256_1kb | 1,028 ns | 1,262 ns | zig 1.23x |
| keccak256_4kb | 4,008 ns | 4,772 ns | zig 1.19x |
| secp256k1_sign | 112,061 ns | 27,372 ns | rs 4.09x |
| secp256k1_sign_recover | 254,525 ns | 119,700 ns | rs 2.13x |
| address_derivation | 135 ns | 190 ns | zig 1.41x |
| address_from_hex | 8 ns | 13 ns | zig 1.62x |
| checksum_address | 159 ns | 201 ns | zig 1.26x |
| abi_encode_transfer | 31 ns | 29 ns | rs 1.07x |
| abi_encode_static | 26 ns | 50 ns | zig 1.92x |
| abi_encode_dynamic | 114 ns | 175 ns | zig 1.54x |
| abi_decode_uint256 | 22 ns | 26 ns | zig 1.18x |
| abi_decode_dynamic | 75 ns | 133 ns | zig 1.77x |
| rlp_encode_eip1559_tx | 41 ns | 38 ns | rs 1.08x |
| rlp_decode_u256 | 3 ns | 6 ns | zig 2.00x |
| u256_add | 2 ns | 2 ns | tie |
| u256_mul | 2 ns | 5 ns | zig 2.50x |
| u256_div | 3 ns | 12 ns | zig 4.00x |
| u256_uniswapv2_amount_out | 40 ns | 13 ns | rs 3.08x |
| u256_mulDiv | 11 ns | 14 ns | zig 1.27x |
| u256_uniswapv4_swap | 21 ns | 24 ns | zig 1.14x |
| hex_encode_32b | 11 ns | 11 ns | tie |
| hex_decode_32b | 12 ns | 24 ns | zig 2.00x |
| tx_hash_eip1559 | 184 ns | 210 ns | zig 1.14x |

## Score Summary

| | Count |
|---|---|
| eth-zig wins | 19 |
| alloy.rs wins | 5 |
| Tied | 2 |

## Key Optimizations in v0.3.0

| Optimization | Impact |
|---|---|
| Knuth Algorithm D u64-limb division | mulDiv: 281 ns -> 11 ns (25x), beats alloy |
| secp256k1 `mulDoubleBasePublic` recovery | sign_recover: 837 us -> 255 us (3.3x) |
| Stack-buffer RLP encoding (single pass) | rlp_encode: 89 ns -> 41 ns (2.2x) |
| ABI static-only fast path | abi_encode_transfer: 71 ns -> 31 ns (2.3x) |
| `fastMul` u128 fast path | u256 compound ops: 2x faster |

## Remaining alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| secp256k1_sign | 4.09x | Zig stdlib constant-time EC scalar multiplication vs k256-rs precomputed tables with variable-time ops |
| secp256k1_sign_recover | 2.13x | Same as above (improved 3.3x via `mulDoubleBasePublic`) |
| u256_uniswapv2_amount_out | 3.08x | alloy's `ruint` uses hand-optimized 4×u64 limb arithmetic; LLVM's u256 compound ops are slow |
| abi_encode_transfer | 1.07x | alloy's `sol!` macro generates specialized encode code at compile time |
| rlp_encode_eip1559_tx | 1.08x | alloy derive macros produce single-purpose encode code |

## Reproducing

```bash
# Full comparison (requires Zig, Rust, Python 3)
bash bench/compare.sh

# eth-zig benchmarks only
zig build bench

# alloy benchmarks only
(cd bench/alloy-bench && cargo bench --bench eth_comparison)
```
