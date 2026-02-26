# eth-zig vs alloy.rs Benchmark Comparison

**Score: eth-zig wins 18/24 | alloy.rs wins 5/24 | tied 1/24**

Benchmarks run on Apple Silicon with `ReleaseFast` (zig) and `--release` (cargo).

## Full Comparison

| Benchmark | Before | After | alloy.rs | Before Winner | After Winner |
|---|---|---|---|---|---|
| keccak256_empty | 253 ns | 254 ns | 335 ns | zig 1.32x | zig 1.32x |
| keccak256_32b | 262 ns | 263 ns | 337 ns | zig 1.29x | zig 1.28x |
| keccak256_256b | 524 ns | 533 ns | 638 ns | zig 1.22x | zig 1.20x |
| keccak256_1kb | 2,031 ns | 2,026 ns | 2,421 ns | zig 1.19x | zig 1.19x |
| keccak256_4kb | 7,812 ns | 7,828 ns | 9,229 ns | zig 1.18x | zig 1.18x |
| secp256k1_sign | 1,068,578 ns | 224,177 ns | 51,687 ns | rs 17.9x | rs 4.34x |
| secp256k1_sign_recover | 1,692,582 ns | 837,511 ns | 218,360 ns | rs 7.6x | rs 3.84x |
| address_derivation | 207,923 ns | 262 ns | 362 ns | rs 573x | zig 1.38x |
| address_from_hex | 36 ns | 16 ns | 25 ns | rs 1.44x | zig 1.56x |
| checksum_address | 416 ns | 307 ns | 388 ns | rs 1.07x | zig 1.26x |
| abi_encode_transfer | 21,605 ns | 71 ns | 55 ns | rs 393x | rs 1.29x |
| abi_encode_static | 21,736 ns | 69 ns | 97 ns | rs 226x | zig 1.41x |
| abi_encode_dynamic | 47,058 ns | 246 ns | 316 ns | rs 148x | zig 1.28x |
| abi_decode_uint256 | 9,619 ns | 46 ns | 49 ns | rs 196x | zig 1.07x |
| abi_decode_dynamic | 20,127 ns | 170 ns | 258 ns | rs 78x | zig 1.52x |
| rlp_encode_eip1559_tx | 16,978 ns | 89 ns | 70 ns | rs 239x | rs 1.27x |
| rlp_decode_u256 | 12 ns | 6 ns | 8 ns | rs 1.5x | zig 1.33x |
| u256_add | 4 ns | 4 ns | 4 ns | tie | tie |
| u256_mul | 4 ns | 4 ns | 10 ns | zig 3.0x | zig 2.50x |
| u256_div | 79 ns | 6 ns | 23 ns | rs 3.3x | zig 3.83x |
| u256_uniswapv2_amount_out | 79 ns | 87 ns | 24 ns | rs 3.3x | rs 3.62x |
| hex_encode_32b | 21 ns | 21 ns | 22 ns | tie | zig 1.05x |
| hex_decode_32b | 37 ns | 23 ns | 45 ns | zig 1.27x | zig 1.96x |
| tx_hash_eip1559 | 16,355 ns | 366 ns | 403 ns | rs 41x | zig 1.10x |

## Score Summary

|  | Before | After |
|---|---|---|
| eth-zig wins | 10 | 18 |
| alloy.rs wins | 14 | 5 |
| Tied | 0 | 1 |

## Biggest Improvements

| Benchmark | Before | After | Speedup |
|---|---|---|---|
| address_derivation | 207,923 ns | 262 ns | 793x |
| abi_encode_static | 21,736 ns | 69 ns | 315x |
| abi_encode_transfer | 21,605 ns | 71 ns | 304x |
| abi_decode_uint256 | 9,619 ns | 46 ns | 209x |
| rlp_encode_eip1559_tx | 16,978 ns | 89 ns | 191x |
| abi_encode_dynamic | 47,058 ns | 246 ns | 191x |
| abi_decode_dynamic | 20,127 ns | 170 ns | 118x |
| tx_hash_eip1559 | 16,355 ns | 366 ns | 45x |
| u256_div | 79 ns | 6 ns | 13x |
| secp256k1_sign | 1,068,578 ns | 224,177 ns | 4.8x |

## Remaining alloy.rs Wins

| Benchmark | Gap | Root Cause |
|---|---|---|
| secp256k1_sign | 4.34x | Zig stdlib generic EC scalar multiplication vs k256-rs precomputed tables |
| secp256k1_sign_recover | 3.84x | Same as above |
| u256_uniswapv2_amount_out | 3.62x | LLVM u256 multiply overhead vs ruint hand-optimized limb operations |
| abi_encode_transfer | 1.29x | alloy sol! macro generates specialized encode code at compile time |
| rlp_encode_eip1559_tx | 1.27x | alloy derive macros produce single-purpose encode code |

## Reproducing

```bash
# Run eth-zig benchmarks
zig build bench

# Run alloy benchmarks
cd bench/alloy-bench && cargo bench --bench eth_comparison

# Run full comparison
bash bench/compare.sh
```
