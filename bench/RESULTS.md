# eth.zig vs alloy.rs: Ethereum Library Benchmark Comparison

Zig vs Rust -- a head-to-head performance comparison of [eth.zig](https://github.com/StrobeLabs/eth.zig) and [alloy.rs](https://alloy.rs) across 26 core Ethereum operations: Keccak-256 hashing, ABI encoding/decoding, RLP serialization, secp256k1 ECDSA signing, u256 arithmetic (including UniswapV4 mulDiv with true 512-bit intermediate), hex operations, address derivation, and EIP-1559 transaction hashing.

**Score: eth.zig wins 23/26 | alloy.rs wins 2/26 | tied 1/26**

Benchmarks run on Apple Silicon with `ReleaseFast` (Zig) vs `--release` (Cargo). Custom criterion-style harness with 0.5s warmup, calibrated batch sizes, and 2s measurement window. Both mulDiv benchmarks use true 512-bit intermediate arithmetic (eth.zig's `mulDiv`, alloy's `U512` from ruint).

## Full Comparison

| Benchmark | eth-zig | alloy.rs | Winner |
|---|---|---|---|
| keccak256_empty | 275 ns | 333 ns | **zig 1.21x** |
| keccak256_32b | 268 ns | 337 ns | **zig 1.26x** |
| keccak256_256b | 536 ns | 640 ns | **zig 1.19x** |
| keccak256_1kb | 2,052 ns | 2,432 ns | **zig 1.19x** |
| keccak256_4kb | 7,886 ns | 9,238 ns | **zig 1.17x** |
| secp256k1_sign | 24,481 ns | 51,286 ns | **zig 2.09x** |
| secp256k1_sign_recover | 67,816 ns | 218,720 ns | **zig 3.23x** |
| address_derivation | 262 ns | 370 ns | **zig 1.41x** |
| address_from_hex | 15 ns | 11 ns | rs 1.36x |
| checksum_address | 312 ns | 450 ns | **zig 1.44x** |
| abi_encode_transfer | 25 ns | 61 ns | **zig 2.44x** |
| abi_encode_static | 24 ns | 100 ns | **zig 4.17x** |
| abi_encode_dynamic | 176 ns | 325 ns | **zig 1.85x** |
| abi_decode_uint256 | 16 ns | 51 ns | **zig 3.19x** |
| abi_decode_dynamic | 34 ns | 260 ns | **zig 7.65x** |
| rlp_encode_eip1559_tx | 57 ns | 72 ns | **zig 1.26x** |
| rlp_decode_u256 | 14 ns | 10 ns | rs 1.40x |
| u256_add | 4 ns | 4 ns | tie |
| u256_mul | 4 ns | 9 ns | **zig 2.25x** |
| u256_div | 7 ns | 39 ns | **zig 5.57x** |
| u256_uniswapv2_amount_out | 21 ns | 27 ns | **zig 1.29x** |
| u256_mulDiv | 17 ns | 30 ns | **zig 1.76x** |
| u256_uniswapv4_swap | 42 ns | 47 ns | **zig 1.12x** |
| hex_encode_32b | 22 ns | 23 ns | **zig 1.05x** |
| hex_decode_32b | 23 ns | 28 ns | **zig 1.22x** |
| tx_hash_eip1559 | 333 ns | 407 ns | **zig 1.22x** |

## Score Summary

| | Count |
|---|---|
| eth-zig wins | 23 |
| alloy.rs wins | 2 |
| Tied | 1 |

## Key Optimizations

| Optimization | Impact |
|---|---|
| bitcoin-core/secp256k1 C backend (vendored) | secp256k1_sign: 2.09x faster than alloy; sign_recover: 3.23x faster |
| Lane-complementing Keccak-f[1600] (XKCP opt64) | keccak256_4kb: 1.17x faster than alloy |
| Streamlined mulDiv with native u128 division | mulDiv: 1.76x faster than alloy (17ns vs 30ns) |
| U256Limb limb-native arithmetic | uniswapv2: beats alloy 1.29x |
| Half-word division (`div128by64`) | u256_div: 7ns, 5.57x faster than alloy |
| mulWide + divWide (Knuth D for 512-bit) | Replaces 256-iteration binary long division with ~4-iteration Knuth D |
| FixedBufferAllocator in benchmarks | Eliminates allocator overhead for ABI/RLP/TX benchmarks |
| Vendored bitcoin-core/secp256k1 + XKCP keccak | Best-in-class C backends compiled by `zig build` |
| Custom criterion-style harness | Accurate timing in the sub-25ns regime; zbench had ~25ns floor on macOS |

## Where alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| address_from_hex | 1.36x | alloy uses SIMD hex parsing; eth.zig uses scalar loop |
| rlp_decode_u256 | 1.40x | alloy's ruint has optimized small-integer RLP decoding |

## Reproducing

```bash
# Full comparison (requires Zig, Rust, Python 3)
bash bench/compare.sh

# eth-zig benchmarks only
zig build bench

# alloy benchmarks only
(cd bench/alloy-bench && cargo bench --bench eth_comparison)
```
