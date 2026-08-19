# Changelog

All notable changes to eth.zig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1](https://github.com/StrobeLabs/eth.zig/compare/v0.9.0...v0.9.1) (2026-08-19)


### Bug Fixes

* record the underlying cause of transport failures for diagnostics ([#115](https://github.com/StrobeLabs/eth.zig/issues/115)) ([508a9eb](https://github.com/StrobeLabs/eth.zig/commit/508a9eb82307a4371047a960269226399508091d))

## [0.9.0](https://github.com/StrobeLabs/eth.zig/compare/v0.8.1...v0.9.0) (2026-08-03)


### Features

* Universal Resolver migration with full ENSIP-15 normalization ([#113](https://github.com/StrobeLabs/eth.zig/issues/113)) ([df58766](https://github.com/StrobeLabs/eth.zig/commit/df5876663112f232f5f2072893cebfe81ab80d23))


### Bug Fixes

* double deinit of response buffer on non-200 HTTP responses ([#112](https://github.com/StrobeLabs/eth.zig/issues/112)) ([75aaafb](https://github.com/StrobeLabs/eth.zig/commit/75aaafbfa0f20f84acab19c8939402b26c0fd1b5))


### Performance Improvements

* route safeDiv through divLimbsDirect (not the builtin u256 /) ([#107](https://github.com/StrobeLabs/eth.zig/issues/107)) ([9da2547](https://github.com/StrobeLabs/eth.zig/commit/9da2547ecb333fd5aa32dbbee05b543f30389067))

## [Unreleased]

### Added
- abigen writes: state-changing contract calls via `*Wallet` -- `send(self, wallet, comptime name, args) ![32]u8` and `sendValue(..., value)` build the same `selector ++ encode(args)` calldata as `call` (shared `encodeCall`) and submit through `Wallet.sendTransaction`; `sendAndWait(..., max_attempts) !TransactionReceipt` waits for the receipt. Naming a `view`/`pure` function in `send` is a `@compileError` pointing you to `call`. Completes the abigen reads + events + writes surface (#68)
- `kzg` module: real EIP-4844 KZG support, vendoring the C reference implementations (`c-kzg-4844` v2.1.1 + its `blst` v0.3.14 dependency) and exposing a small Zig API for building blob-transaction sidecars. `kzg.init(allocator)`/`kzg.deinit()` load and free the mainnet trusted setup, which is `@embedFile`d (the KZG ceremony `trusted_setup.txt`) so consumers need no external file; init is idempotent and guarded by an atomic once-flag. `kzg.blobToKzgCommitment(blob)` -> `[48]u8` (c-kzg `blob_to_kzg_commitment`), `kzg.computeBlobKzgProof(blob, commitment)` -> `[48]u8` (`compute_blob_kzg_proof`), `kzg.verifyBlobKzgProof(blob, commitment, proof)` -> `bool` (`verify_blob_kzg_proof`), plus `kzg.verifyBlobKzgProofBatch(...)`. c-kzg's `C_KZG_RET` codes map to a Zig `KzgError` set. `blob.buildSidecar(allocator, raw_blob)` fills a `BlobSidecar` (blob + commitment + proof) via the above, and `blob.computeVersionedHash` derives the EIP-4844 versioned hash from a commitment. blst is built in its portable no-assembly C mode (`-D__BLST_NO_ASM__ -D__BLST_PORTABLE__`, 32-bit limbs) so the build is robust across targets with no per-arch assembly. Verified byte-for-byte against the official ethereum/c-kzg-4844 v2.1.1 test vectors (`blob_to_kzg_commitment`, `compute_blob_kzg_proof`, `verify_blob_kzg_proof` correct/incorrect) embedded under `src/crypto/c-kzg/test_vectors/`, plus round-trip and init/deinit lifecycle tests
- `abigen` module: comptime contract bindings (#68). `eth.bind(@embedFile("erc20.json"))` (alias for `eth.abigen.Bind`) parses a Solidity JSON ABI **at compile time** and returns a fully typed contract struct -- zero runtime ABI parsing, with selectors and event topic0s precomputed at comptime. The ABI is read by a purpose-built comptime JSON tokenizer (std.json needs a runtime allocator and does not run at comptime in 0.16), and generated structs are reified with `@Struct` while typed reads/decodes dispatch on a comptime function name so the argument-tuple and return types are fully resolved per call site. Public surface: `Self.at(address)`; `call(self, provider, comptime name, args) !Ret` (ABI-encodes `selector ++ encode(args)`, runs `eth_call`, decodes into the mapped return type); `selectorOf(name)`/`ArgsOf(name)`/`ReturnOf(name)`; and for events `decodeEvent(name, log) !EventStruct` (indexed params from `log.topics[1..]`, non-indexed from `log.data`, validating `topics[0]`), `topicOf(name)`, and `EventOf(name)`. ABI integers map to the smallest fitting Zig integer (`uint8` -> `u8`, `uint112` -> `u112`), matching zabi's `AbiParameterToPrimative`; `address` -> `[20]u8`, `bool` -> `bool`, `bytesN` -> `[N]u8`, `bytes`/`string` -> `[]const u8`. Read functions and events this release; state-changing writes (taking a `*Wallet`) are a documented follow-up. Tuple/array params and overloaded-function redeclarations are parsed but not yet addressable, and naming an unsupported entry is a clear `@compileError`. Asserts the comptime-derived selectors against known values (`balanceOf(address)` == 0x70a08231, `transfer(address,uint256)` == 0xa9059cbb) and the ERC-20 `Transfer` topic0, and exercises calldata encoding and a full `Transfer` log decode without a network. Builds and tests green on both Zig 0.16 and 0.17-dev

## [0.7.0] - 2026-06-11

### Added
- EIP-7702 SetCode transactions (type 0x04), shipped in Pectra and live on mainnet (#66). New `transaction.Authorization` tuple `{chain_id, address, nonce, y_parity, r, s}` and `transaction.Eip7702Transaction` (note: `to` is non-nullable -- type-0x04 cannot create contracts), wired into the `Transaction` union and the `serializeForSigning`/`hashForSigning`/`serializeSigned` dispatch. The signing payload is `0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, authorization_list])` (signed appends `y_parity, r, s`), each authorization encoded as `[chain_id, address, nonce, y_parity, r, s]`. `signer.signAuthorization(allocator, chain_id, address, nonce)` signs the authorization hash `keccak256(0x05 || rlp([chain_id, address, nonce]))` (MAGIC = 0x05) and fills `y_parity/r/s`; `signer.hashAuthorization` exposes that hash. `rpc_transaction.RpcTransaction` gains an optional `authorization_list`, parsed best-effort from an RPC `authorizationList`. Verified via sign-then-recover round trip (recovered signer equals the authority) plus fixed RLP-shape assertions; no official EIP-7702 signing test vector was found in the EIP or this repo, so correctness rests on the round trip plus shape checks
- `fallback_provider` module: multi-RPC failover provider (#70). `FallbackProvider.init(allocator, endpoints, opts)` owns one `HttpTransport`+`Provider` per endpoint and exposes the same read method surface as `Provider` (`getBalance`, `getBlockNumber`, `call`, `getLogs`, `sendRawTransaction`, ...) as a drop-in replacement. On a transport/connection failure it fails over to the next healthy endpoint; after `failover_threshold` consecutive failures an endpoint is marked unhealthy and skipped, and a periodic probe (`recovery_probe_ms` after its last failure) restores it, with lower-index endpoints always preferred so a recovered primary is reclaimed. Crucially, failover fires ONLY on transport errors (`error.ConnectionFailed`/`error.HttpError`/socket errors); an `error.RpcError` is the node's real answer (a revert, unsupported method, rate-limit) and is returned to the caller WITHOUT failover. The failover/recovery state machine is a pure function `selectEndpoint(health, now_ms, opts, tried)` over injectable timestamps, and the failover-vs-RpcError decision is the pure `isFailoverError(err)`, both unit-tested deterministically without network
- `keystore` module: encrypted JSON keystore support (Web3 Secret Storage v3), the on-disk format used by geth/ethers/foundry/MyEtherWallet (#65). `decrypt(allocator, json, password)` parses a v3 document, derives the key via either KDF (`scrypt` or `pbkdf2`-HMAC-SHA256), verifies `MAC = keccak256(derived_key[16..32] ++ ciphertext)` in constant time (`std.crypto.timing_safe.eql`, returning `error.InvalidPassword` on mismatch), and AES-128-CTR decrypts to recover the 32-byte private key. `encrypt(allocator, key, password, io, opts)` produces a v3 JSON string (defaulting to scrypt N=2^18 + aes-128-ctr, with a v4 UUID and a random salt/IV drawn from the caller's `Io`). All derived keys, the plaintext key copy, and the ciphertext buffer are wiped with `secureZero` on exit. Verified against the canonical Web3 Secret Storage scrypt and pbkdf2 test vectors (both decrypt to `7a28b5ba...fe9d`), proving interop with geth/ethers/foundry

### Changed
- **BREAKING:** `std.Io` is now an explicit parameter on every network constructor and on the functions that need randomness or sleep, removing the hidden global `Io` and aligning with Zig 0.16's guidance to pass I/O handles explicitly rather than reaching for a global default. New signatures: `HttpTransport.init(allocator, url, io)`, `WsTransport.connect(allocator, url, io)`, `WsClient.connect(allocator, url, io, opts)`, `flashbots.Relay.init(allocator, url, auth_key, io)`, `FallbackProvider.init(allocator, endpoints, io, opts)`, `MevShareClient.init(allocator, relay_url, stream_url, auth_key, io)` / `initMainnet(allocator, auth_key, io)`, `mnemonic.generate(io, comptime entropy_size)`, `keystore.encrypt(allocator, key, password, io, opts)`, and the runtime helpers `runtime.milliTimestamp(io)` / `runtime.sleepMs(io, ms)`. `Provider`, `Wallet`, `RetryingProvider`, and `NonceManager` inherit the `Io` of the transport/provider they wrap (via `Provider.io()`), so they take no new parameter. `runtime.defaultIo()` is renamed to `runtime.blockingIo()` and is now just a convenient blocking `Io` value to pass explicitly -- pass `eth.runtime.blockingIo()` for the previous default blocking behavior. Because the `Io` is caller-provided, eth.zig can now run on your own event loop.

## [0.6.0] - 2026-06-10

### Added
- `nonce_manager` module: atomic nonce manager for concurrent senders (#75). `NonceManager.init` seeds lazily from the `pending` transaction count (no RPC in `init`); `next()` is a lock-free atomic fetch-and-add so multiple threads never receive the same nonce; `peek()` reads the next nonce without advancing; `resync()`/`reset()` re-fetch from chain after dropped txs; and `onFailure(nonce)` returns a nonce to the pool only when it is the most recently issued one (a middle nonce cannot be safely reused once a higher one is in flight). Also adds `provider.getTransactionCountAt(address, tag)` so the nonce count can be read at any block tag (e.g. `.pending`)
- MEV-Share backrunner example (`examples/08_mev_share_backrunner.zig`): a teaching bot that matches the MEV-Share SSE event stream against comptime-computed Uniswap V2/V3 swap selectors and composes a backrun bundle (user tx hash + signed EIP-1559 backrun tx), with a safe `DRY_RUN` default that prints the `mev_sendBundle` params instead of submitting (#38)
- `mev_share` module: MEV-Share client mirroring `mev-share-client-ts` -- `sendTransaction` (eth_sendPrivateTransaction via `flashbots.Relay`), `simulateBundle` (mev_simBundle with `SimBundleOpts`/`SimBundleResult`), blocking SSE event stream subscription (`MevShareClient.on` with `PendingEvent`/`PendingTransaction`/`PendingBundle` and pure `parseEventData`), and `getEventHistory` (GET /api/v1/history) (#34)
- `eth_sendPrivateTransaction` (MEV-Share private transactions) on `flashbots.Relay`: submit a single private transaction with hint preferences (calldata, contract_address, logs, function_selector), builder selection, fast mode, and max inclusion block (#40)

### Changed
- Benchmark comparison refreshed against current alloy crates (alloy-primitives 1.6.0, alloy-sol-types 1.6.0, alloy-dyn-abi 1.6.0, alloy-consensus 2.0.5, alloy-signer 2.0.5, alloy-rlp 0.3.15); bench/alloy-bench migrated from alloy-primitives 0.8 / alloy 0.6. New score: eth.zig wins 18/26 (alloy improved Keccak on larger inputs, hex encoding, RLP u256 decoding, and UniswapV4-style swap math)

### Fixed
- **Unit tests now actually run.** The test step aggregated module tests via `_ = eth.module` field access, which only forces semantic analysis -- it never collected the per-module `test` blocks, so assertions compiled but never executed (`zig build test` was green even with a deliberately failing test). The test artifact is now rooted at `src/root.zig`, whose test block direct-imports every module file. This surfaced real, previously-hidden defects, now fixed: `abi_json` still used the 0.15 `ArrayList` API (broken on 0.16); `rlp.bytesToUint` failed to compile for small integer types; `mnemonic.entropyToMnemonic` had a comptime-resolution bug and a u8 overflow for 24-word phrases; `parseInputs`/`parseParam` formed an inferred-error-set dependency loop; `rlp` struct reflection used the pre-0.17 `Type.Struct.fields` layout (now via `std.meta.fieldNames`, portable across 0.16 and 0.17-dev). Fixed several stale test expectations (`formatHash`/log-address length typos, a static-tuple ABI length, a fixed-size hex length error). Vendored XKCP/secp256k1 C is now built with `-fno-sanitize=undefined` so their intentional unaligned loads do not trap the Debug UBSan runtime.
- Pure-Zig Keccak-256 fallback (`keccak_optimized.zig`) now produces correct digests (#80): replaced the broken lane-complementing chi optimization with the standard chi step (which lowers to ANDN anyway). Verified against pinned vectors and cross-validated with stdlib across all block sizes.
- `mulDiv` now returns the correct result when the intermediate product overflows u256 with a full-width divisor, e.g. `mulDiv(MAX, MAX, MAX)` (#81). The limb-native Knuth-D divider mis-handled this boundary; the rare overflow path now computes exactly in native u512 (the benchmarked u128 fast path is unchanged).
- BIP-39 seed derivation (`mnemonic.toSeed`) was correct; its Trezor passphrase test had a wrong expected vector. Corrected the test to the canonical vector (verified against `std.crypto` PBKDF2) and un-quarantined it (#82).
- DEX `getAmountIn`/`getAmountOut` are correct standard Uniswap V2; the `getAmountIn inverse` round-trip test used unrealistic tiny-reserve parameters where flooring a small output legitimately breaks the within-2-units invariant. Corrected the test to balanced reserves and un-quarantined it (#83). The full unit suite now runs with zero skips.
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
