# eth.zig vs Voltaire: Head-to-Head Benchmarks

Comparison of eth.zig and [Voltaire](https://github.com/evmts/voltaire) on the three core
Ethereum crypto operations. Both libraries use `std.crypto.ecc.Secp256k1` from the Zig
standard library. Voltaire's `keccak-asm` FFI is unavailable in pure-Zig mode (requires Cargo),
so both use Zig-native Keccak -- except eth.zig ships an optimized permutation.

**Machine**: Apple M-series, Zig 0.15.2, `ReleaseFast`

## Results

### Keccak-256

| Input size | eth.zig (ns) | Voltaire (ns) | Winner |
|------------|-------------|---------------|--------|
| empty      | 301         | ~384*         | eth.zig |
| 32 bytes   | 300         | ~340*         | eth.zig |
| 256 bytes  | 626         | ~727*         | eth.zig |
| 1 KB       | 2,456       | ~2,845*       | eth.zig |
| 4 KB       | 9,496       | ~10,329*      | eth.zig |

*\*Voltaire pure-Zig uses `std.crypto.hash.sha3.Keccak256` (unmodified stdlib).
eth.zig uses a lane-complementing Keccak-f\[1600\] permutation that saves ~120 NOT
operations per hash via the XKCP opt64 strategy.*

### secp256k1

| Operation      | eth.zig (ns) | Voltaire (ns) | Winner |
|----------------|-------------|---------------|--------|
| sign (ECDSA)   | 160,130     | ~224,700*     | eth.zig (1.40x) |
| sign + recover | 442,448     | ~506,970*     | eth.zig (1.15x) |

*\*Voltaire uses unmodified `std.crypto.ecc.Secp256k1.basePoint.mul()`.
eth.zig applies the [GLV endomorphism](https://codeberg.org/ziglang/zig/pulls/31356)
to split the 256-bit scalar multiplication into two 128-bit halves,
cutting EC doublings from 252 to 124.*

### EIP-712 (Typed Data Hashing)

| Operation       | eth.zig (ns) | Voltaire approach |
|-----------------|-------------|-------------------|
| hashTypedData   | 3,326       | HashMap + allocator per call |

*eth.zig uses comptime struct types and stack-allocated field arrays.
Voltaire's EIP-712 (`unaudited_hashTypedData`) builds HashMaps at runtime
for type resolution, requiring heap allocation on every call.*

## How to Replicate

### eth.zig

```bash
git clone https://github.com/ethzig/eth.zig
cd eth.zig
zig build bench
```

### Voltaire

```bash
git clone https://github.com/evmts/voltaire
cd voltaire
# Voltaire uses zbench; check their build.zig for bench targets
zig build bench
```

Note: Voltaire's Keccak FFI (`keccak-asm`) requires Rust/Cargo. Without it, their
`keccak_asm.zig` falls back to `std.crypto.hash.sha3.Keccak256` (same as stdlib baseline).

## Summary

| Category   | eth.zig | Voltaire | Advantage |
|------------|---------|----------|-----------|
| Keccak-256 | Lane-complementing opt64 | stdlib (or Rust FFI) | eth.zig: 13-28% faster (pure Zig) |
| secp256k1  | GLV endomorphism | stdlib | eth.zig: 40% faster signing |
| EIP-712    | Comptime structs | Runtime HashMaps | eth.zig: zero heap allocation |

All eth.zig optimizations are pure Zig with zero external dependencies.
