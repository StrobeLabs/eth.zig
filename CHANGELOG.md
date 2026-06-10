# Changelog

All notable changes to eth.zig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `mev_share` module: MEV-Share client mirroring `mev-share-client-ts` -- `sendTransaction` (eth_sendPrivateTransaction via `flashbots.Relay`), `simulateBundle` (mev_simBundle with `SimBundleOpts`/`SimBundleResult`), blocking SSE event stream subscription (`MevShareClient.on` with `PendingEvent`/`PendingTransaction`/`PendingBundle` and pure `parseEventData`), and `getEventHistory` (GET /api/v1/history) (#34)
- `eth_sendPrivateTransaction` (MEV-Share private transactions) on `flashbots.Relay`: submit a single private transaction with hint preferences (calldata, contract_address, logs, function_selector), builder selection, fast mode, and max inclusion block (#40)

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
