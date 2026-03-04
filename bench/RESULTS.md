# eth.zig vs alloy.rs: Ethereum Library Benchmark Comparison

Pure Zig vs Rust -- a head-to-head performance comparison of [eth.zig](https://github.com/StrobeLabs/eth.zig) and [alloy.rs](https://alloy.rs) across 26 core Ethereum operations: Keccak-256 hashing, ABI encoding/decoding, RLP serialization, secp256k1 ECDSA signing, u256 arithmetic (including UniswapV4 mulDiv with true 512-bit intermediate), hex operations, address derivation, and EIP-1559 transaction hashing.

**Score: eth.zig wins 20/26 | alloy.rs wins 4/26 | tied 2/26**

Benchmarks run on Apple Silicon with `ReleaseFast` (Zig) vs `--release` (Cargo). Custom criterion-style harness with 0.5s warmup, calibrated batch sizes, and 2s measurement window. Both mulDiv benchmarks use true 512-bit intermediate arithmetic (eth.zig's `mulDiv`, alloy's `U512` from ruint).

## Full Comparison

| Benchmark | eth-zig | alloy.rs | Winner |
|---|---|---|---|
| keccak256_empty | 131 ns | 175 ns | **zig 1.34x** |
| keccak256_32b | 135 ns | 179 ns | **zig 1.33x** |
| keccak256_256b | 271 ns | 333 ns | **zig 1.23x** |
| keccak256_1kb | 1,069 ns | 1,263 ns | **zig 1.18x** |
| keccak256_4kb | 4,097 ns | 4,826 ns | **zig 1.18x** |
| secp256k1_sign | 83,448 ns | 27,000 ns | rs 3.09x |
| secp256k1_sign_recover | 233,841 ns | 114,170 ns | rs 2.05x |
| address_derivation | 136 ns | 190 ns | **zig 1.40x** |
| address_from_hex | 8 ns | 6 ns | rs 1.33x |
| checksum_address | 161 ns | 201 ns | **zig 1.25x** |
| abi_encode_transfer | 13 ns | 29 ns | **zig 2.23x** |
| abi_encode_static | 13 ns | 51 ns | **zig 3.92x** |
| abi_encode_dynamic | 91 ns | 171 ns | **zig 1.88x** |
| abi_decode_uint256 | 8 ns | 26 ns | **zig 3.25x** |
| abi_decode_dynamic | 17 ns | 135 ns | **zig 7.94x** |
| rlp_encode_eip1559_tx | 34 ns | 37 ns | **zig 1.09x** |
| rlp_decode_u256 | 5 ns | 5 ns | tie |
| u256_add | 2 ns | 2 ns | tie |
| u256_mul | 2 ns | 5 ns | **zig 2.50x** |
| u256_div | 3 ns | 12 ns | **zig 4.00x** |
| u256_uniswapv2_amount_out | 10 ns | 13 ns | **zig 1.30x** |
| u256_mulDiv | 18 ns | 15 ns | rs 1.20x |
| u256_uniswapv4_swap | 22 ns | 24 ns | **zig 1.09x** |
| hex_encode_32b | 11 ns | 12 ns | **zig 1.09x** |
| hex_decode_32b | 12 ns | 14 ns | **zig 1.17x** |
| tx_hash_eip1559 | 170 ns | 216 ns | **zig 1.27x** |

## Score Summary

| | Count |
|---|---|
| eth-zig wins | 20 |
| alloy.rs wins | 4 |
| Tied | 2 |

## Key Optimizations

| Optimization | Impact |
|---|---|
| Lane-complementing Keccak-f[1600] (XKCP opt64) | keccak256_4kb: 1.18x faster than alloy |
| U256Limb limb-native arithmetic | uniswapv2: beats alloy 1.30x (was 3.58x loss) |
| Half-word division (`div128by64`) | u256_div: 3ns, 4.00x faster than alloy |
| FixedBufferAllocator in benchmarks | Eliminates allocator overhead for ABI/RLP/TX benchmarks |
| GLV endomorphism for secp256k1 signing | Constant-time, 1.4x faster than v0.2 |
| Custom criterion-style harness | Accurate timing in the sub-25ns regime; zbench had ~25ns floor on macOS |

## Where alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| secp256k1_sign | 3.09x | k256-rs uses large precomputed base point tables (hundreds of points); eth.zig uses 16-point GLV tables. Both constant-time for signing. |
| secp256k1_sign_recover | 2.05x | k256-rs uses variable-time Shamir's trick for recovery (safe -- no secrets involved); eth.zig uses conservative constant-time path |
| address_from_hex | 1.33x | alloy uses SIMD hex parsing; eth.zig uses scalar loop |
| u256_mulDiv | 1.20x | ruint's reciprocal-based division vs eth.zig's Knuth Algorithm D |

## Reproducing

```bash
# Full comparison (requires Zig, Rust, Python 3)
bash bench/compare.sh

# eth-zig benchmarks only
zig build bench

# alloy benchmarks only
(cd bench/alloy-bench && cargo bench --bench eth_comparison)
```
