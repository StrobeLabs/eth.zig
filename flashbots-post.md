# Fastest Ethereum library -- seeking feedback from searchers

We're building [eth.zig](https://github.com/StrobeLabs/eth.zig), an Ethereum library in Zig that beats Rust's alloy.rs on 23 of 26 benchmarks. We benchmarked it against Alloy on the operations that sit on the tx construction hot path:

| Operation | eth.zig | Alloy | Speedup |
|-----------|---------|-------|---------|
| secp256k1 sign | 24,609 ns | 51,738 ns | 2.10x |
| secp256k1 sign+recover | 54,221 ns | 218,790 ns | 4.04x |
| ABI decode (dynamic) | 32 ns | 256 ns | 8.00x |
| ABI encode (static) | 24 ns | 97 ns | 4.04x |
| u256 mulDiv (512-bit) | 17 ns | 29 ns | 1.71x |
| u256 division | 7 ns | 24 ns | 3.43x |
| Keccak-256 (32b) | 259 ns | 336 ns | 1.30x |
| TX hash (EIP-1559) | 328 ns | 402 ns | 1.23x |

Full 26-op comparison: [RESULTS.md](https://github.com/StrobeLabs/eth.zig/blob/main/bench/RESULTS.md) (23 wins, 1 loss, 2 ties). Alloy's only win is SIMD hex parsing.

Zig's `comptime` lets us resolve ABI function selectors at compile time -- zero runtime keccak for dispatch. This isn't possible with Rust macros.

## Why we're posting here

We're not pitching "replace your Rust stack." The Alloy + Reth + Revm ecosystem is mature.

Our thesis is narrower: **L2 MEV is a compute game.** On Base, Arbitrum, OP Stack -- the sequencer is centralized, everyone has roughly equal latency. The edge shifts to how fast you decode, evaluate, and construct. These are exactly the operations where eth.zig is fastest.

## What we're building for searchers

We've opened issues for the features we think matter and would love feedback on priority and API design:

- [Batch eth_call](https://github.com/StrobeLabs/eth.zig/issues/11) -- N simulations in one round-trip
- [eth_call with state overrides](https://github.com/StrobeLabs/eth.zig/issues/12) -- simulate against modified state
- [Flashbots bundle submission](https://github.com/StrobeLabs/eth.zig/issues/13) -- eth_sendBundle / mev_sendBundle
- [Pending tx subscription](https://github.com/StrobeLabs/eth.zig/issues/14) -- full tx mempool monitoring via WS
- [UniswapV2/V3 router decoding](https://github.com/StrobeLabs/eth.zig/issues/15) -- comptime DEX swap decoders
- [Pure Zig DEX quote math](https://github.com/StrobeLabs/eth.zig/issues/16) -- off-chain V2/V3 getAmountOut

## Questions

1. **Does compute speed matter on L2?** When latency is equalized, is encoding/decoding the marginal edge, or is it something else entirely?
2. **What's your actual hot path?** RPC round-trips, tx decoding, quote calculation, signing?
3. **Would you try a non-Rust library** for a new L2 strategy, even if you'd never rewrite L1 infra?
4. **What's missing** from the feature list above?

Looking for honest signal, not validation.

[ethzig.org](https://ethzig.org) | [GitHub](https://github.com/StrobeLabs/eth.zig) | [@StrobeLabs](https://x.com/StrobeLabs)
