# Changelog

All notable changes to eth.zig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Pure-Zig Keccak-256 fallback (`keccak_optimized.zig`) now produces correct digests (#80): replaced the broken lane-complementing chi optimization with the standard chi step (which lowers to ANDN anyway). Verified against pinned vectors and cross-validated with stdlib across all block sizes.
- **Unit tests now actually run.** The test step aggregated module tests via `_ = eth.module` field access, which only forces semantic analysis -- it never collected the per-module `test` blocks, so assertions compiled but never executed (`zig build test` was green even with a deliberately failing test). The test artifact is now rooted at `src/root.zig`, whose test block direct-imports every module file. This surfaced real, previously-hidden defects, now fixed: `abi_json` still used the 0.15 `ArrayList` API (broken on 0.16); `rlp.bytesToUint` failed to compile for small integer types; `mnemonic.entropyToMnemonic` had a comptime-resolution bug and a u8 overflow for 24-word phrases; `parseInputs`/`parseParam` formed an inferred-error-set dependency loop; `rlp` struct reflection used the pre-0.17 `Type.Struct.fields` layout (now via `std.meta.fieldNames`, portable across 0.16 and 0.17-dev). Fixed several stale test expectations (`formatHash`/log-address length typos, a static-tuple ABI length, a fixed-size hex length error). Vendored XKCP/secp256k1 C is now built with `-fno-sanitize=undefined` so their intentional unaligned loads do not trap the Debug UBSan runtime.
- Quarantined four pre-existing correctness bugs the revived test suite exposed, tracked for follow-up: broken pure-Zig Keccak fallback (#80), `mulDiv` at the u256 boundary (#81), a BIP-39 passphrase seed vector (#82), and a DEX round-trip test assumption (#83). These are marked `error.SkipZigTest` so they remain visible as skips rather than silently passing.

### Changed
- Benchmark comparison refreshed against current alloy crates (alloy-primitives 1.6.0, alloy-sol-types 1.6.0, alloy-dyn-abi 1.6.0, alloy-consensus 2.0.5, alloy-signer 2.0.5, alloy-rlp 0.3.15); bench/alloy-bench migrated from alloy-primitives 0.8 / alloy 0.6. New score: eth.zig wins 18/26 (alloy improved Keccak on larger inputs, hex encoding, RLP u256 decoding, and UniswapV4-style swap math)

### Added
- `nonce_manager` module: atomic nonce manager for concurrent senders (#75). `NonceManager.init` seeds lazily from the `pending` transaction count (no RPC in `init`); `next()` is a lock-free atomic fetch-and-add so multiple threads never receive the same nonce; `peek()` reads the next nonce without advancing; `resync()`/`reset()` re-fetch from chain after dropped txs; and `onFailure(nonce)` returns a nonce to the pool only when it is the most recently issued one (a middle nonce cannot be safely reused once a higher one is in flight). Also adds `provider.getTransactionCountAt(address, tag)` so the nonce count can be read at any block tag (e.g. `.pending`)
- MEV-Share backrunner example (`examples/08_mev_share_backrunner.zig`): a teaching bot that matches the MEV-Share SSE event stream against comptime-computed Uniswap V2/V3 swap selectors and composes a backrun bundle (user tx hash + signed EIP-1559 backrun tx), with a safe `DRY_RUN` default that prints the `mev_sendBundle` params instead of submitting (#38)
- `mev_share` module: MEV-Share client mirroring `mev-share-client-ts` -- `sendTransaction` (eth_sendPrivateTransaction via `flashbots.Relay`), `simulateBundle` (mev_simBundle with `SimBundleOpts`/`SimBundleResult`), blocking SSE event stream subscription (`MevShareClient.on` with `PendingEvent`/`PendingTransaction`/`PendingBundle` and pure `parseEventData`), and `getEventHistory` (GET /api/v1/history) (#34)
- `eth_sendPrivateTransaction` (MEV-Share private transactions) on `flashbots.Relay`: submit a single private transaction with hint preferences (calldata, contract_address, logs, function_selector), builder selection, fast mode, and max inclusion block (#40)

### Fixed
- `sse_transport.SseParser.feedLine`: replaced the removed `std.mem.trimRight` with `std.mem.trimEnd` and gave the line-parse result an explicit struct type. These were latent Zig 0.16 migration misses that only surfaced when `feedLine` was semantically analyzed (it is not referenced by the unit-test root), and broke any consumer of `MevShareClient.on` -- surfaced while building the MEV-Share backrunner example (#38)

## [0.5.0] - 2026-06-10

### Changed
- Minimum supported Zig version is now 0.16.0. Transports (HTTP, WebSocket, SSE), retry backoff, and receipt polling were migrated to the new `std.Io` interface; the library constructs a default blocking `std.Io` internally, so public signatures are unchanged. This is a breaking change for Zig 0.15 users
- New `eth.runtime` module exposes the library's default `std.Io` (`defaultIo()`) plus `milliTimestamp()` and `sleepMs()` helpers replacing the removed `std.time.milliTimestamp` and `std.Thread.sleep`

### Added
- `log_watcher`: block-scoped log watching (#36). `LogWatcher.pollOnce()` drives per-block `eth_getLogs` from a `newHeads` subscription, back-fills blocks missed across reconnects, and re-fetches reorged ranges on parent-hash mismatch; `watchLogs` offers a callback loop
- `provider.parseBlockHeaderObject`: parse a `BlockHeader` from a bare JSON object

### Fixed
- `subscription.parseBlockFromNotification` referenced `std.json.stringifyAlloc`, which does not exist in Zig 0.15.2; it now parses the notification object directly without a stringify round-trip

## [0.4.0] - 2026-06-09

### Added
- `WsClient`: resilient WebSocket subscription client with transparent reconnect, exponential backoff with jitter, ping/pong keepalive, and multiplexed subscriptions over a single connection (#51)
- Full pending-transaction subscriptions: `newPendingTransactions` with `full: true` streams complete `RpcTransaction` values instead of hashes; tolerates nodes that fall back to hash-only notifications (#53)
- `RpcTransaction` type and `parseSingleTransaction` for `eth_getTransactionByHash`-shaped payloads (#53)
- `eth_call` state overrides: set balance, nonce, code, and storage (full state or diff) per call via `callWithOverrides` (#54)
- Server-Sent Events (SSE) transport with last-event-id reconnect support (#48)
- Typed subscription params and lifecycle management (#43)
- `RetryingProvider`: configurable retry middleware with exponential backoff and connection-error filtering (#41)
- Batch `eth_call` fan-out via `BatchCaller` (#42)
- Pure Zig DEX math for UniswapV2 (`getAmountOut`/`getAmountIn`) plus V3 and router scaffolding (#42)
- Makefile with `ci`, `test`, `fmt`, `integration-test`, and bench targets (#45)

### Changed
- Replaced all uses of the `**` array-repetition operator with `@splat`, restoring compatibility with Zig master (0.17.0-dev) while keeping 0.15.2 as the minimum supported version (#56)
- Malformed transaction fields from RPC (`transactionIndex`, `type`, missing `v`/`yParity`) now fail fast with `error.InvalidResponse` instead of being silently coerced (#53)

### Fixed
- 21 security, correctness, and code-quality issues across the library (#44)
- WebSocket resubscribe-after-reconnect edge case (#53)

### Security
- Docs site upgraded to Next 16 / Fumadocs 16, clearing all `pnpm audit` findings (#57)

## [0.3.0] - 2026-03-09

### Added
- Flashbots MEV support: `eth_sendBundle`, `eth_callBundle`, `eth_cancelBundle`, and MEV-Share `mev_sendBundle` with privacy hints and refund configs (#32)

### Changed
- Vendored libsecp256k1 (Bitcoin Core) with native u128 `mulDiv`; 23/26 benchmark wins vs alloy.rs (#31)
- u256 limb-native compound arithmetic: UniswapV2 `getAmountOut` 87ns -> 20ns, beating the Rust implementation (#30, #29)
- Replaced stdlib Keccak with XKCP (CPU-adaptive AVX512/AVX2/plain64) for ~1.4x hashing speedup (#28)
- Benchmarks migrated to zbench (#24)

### Removed
- `abi_comptime` module: selector and event-topic hashing unified under a single comptime-friendly API (**breaking**) (#25)

## [0.2.3] - 2026-02-28

### Added
- Documentation site at [ethzig.org](https://ethzig.org) (#8)

### Changed
- GLV endomorphism for secp256k1 and lane-complementing Keccak; fastest crypto benchmarks vs Voltaire across the board (#22)

### Fixed
- Deprecated allocator initialization patterns; fixed an LLVM crash in tests (#10)

## [0.2.2] - 2026-02-26

### Added
- ~90 cross-validation tests asserting byte-for-byte parity with alloy.rs outputs (#5)
- `SECURITY.md` and pull-request template

### Changed
- Performance optimizations: 19/26 benchmark wins vs alloy.rs (#4)

### Fixed
- Test nitpicks: pinned expected digests, reused helpers, f64 precision (#7)

## [0.2.1] - 2026-02-26

### Changed
- Performance optimizations across u256, ABI, and crypto paths: 18/24 benchmark wins vs alloy.rs (#3)

## [0.2.0] - 2026-02-26

### Added
- ERC-20 and ERC-721 typed contract wrappers (#1)
- JSON ABI parser for Solidity compiler output (#1)
- Runnable examples under `examples/` (#1)
- Anvil-backed integration test suite (#2)

### Fixed
- Zig 0.15.2 compatibility (#1)

## [0.1.0] - 2026-02-26

Initial release of eth.zig -- a feature-complete, pure Zig Ethereum client library.

### Added

**Primitives**
- `Address` (20 bytes), `Hash` (32 bytes), `Bytes32` types with hex conversions
- EIP-55 checksummed address formatting
- `u256` helpers: `fromBigEndianBytes`, `toBigEndianBytes`, `fromHex`, `toHex`
- Hex encode/decode utilities

**Encoding**
- RLP encoding/decoding per Ethereum Yellow Paper (structs, tuples, slices, integers)
- ABI encoding: all Solidity types (uint8..uint256, address, bool, bytes, string, arrays, tuples)
- ABI decoding: typed decoding of return values and event data
- Comptime ABI: compile-time function selector and event topic computation
- JSON ABI parser: parse Solidity JSON ABI files into eth.zig types

**Crypto**
- Keccak-256 hashing (wraps `std.crypto.hash.sha3.Keccak256`)
- secp256k1 ECDSA signing with recovery ID (RFC 6979, EIP-2 low-S)
- Signature types with compact format support
- EIP-155 replay protection

**Transaction Types**
- Legacy, EIP-2930, EIP-1559, EIP-4844 transaction types
- Transaction serialization (unsigned and signed)
- Receipt, block header, log, and access list types
- EIP-4844 blob types and sidecar construction helpers

**Accounts**
- BIP-39 mnemonic generation and validation (2048-word English wordlist)
- BIP-32/44 HD wallet key derivation
- Private key signing: messages (EIP-191) and transactions

**Transport**
- HTTP JSON-RPC transport (`std.http.Client`)
- WebSocket JSON-RPC transport with TLS support
- Subscription management (newHeads, logs, newPendingTransactions)
- JSON-RPC 2.0 request/response types with batch support

**Client**
- Provider: 24+ read-only RPC methods (getBalance, getBlock, call, estimateGas, getLogs, etc.)
- Wallet: signing client with sendTransaction, waitForReceipt, auto nonce/gas
- Contract: high-level read/write helpers with ABI encoding
- Multicall3: batched contract calls in a single RPC round-trip
- Event log decoding and filtering

**Standards**
- EIP-712 typed structured data hashing and signing
- ENS resolution: forward (name -> address), reverse (address -> name), namehash
- ERC-20 and ERC-721 contract interaction helpers

**Chains**
- Chain definitions: Ethereum, Arbitrum, Optimism, Base, Polygon (mainnet + testnets)
- Includes Multicall3 addresses, ENS registries, block explorer URLs

**Utilities**
- Wei/Gwei/Ether unit conversions
- Common constants (zero address, max uint256, etc.)
