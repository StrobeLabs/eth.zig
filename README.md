# eth.zig

[![CI](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-ethzig.org-blue)](https://ethzig.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-%E2%89%A5%200.16.0-orange)](https://ziglang.org/)

**The fastest Ethereum library.** Beats Rust's alloy.rs on 18 out of 26 benchmarks.

A complete Ethereum client library written in Zig -- ABI encoding, RLP serialization, secp256k1 signing, Keccak-256 hashing, HD wallets, ERC-20/721 tokens, JSON-RPC, ENS, and more.

**[Read the docs at ethzig.org](https://ethzig.org)**

## Why eth.zig?

**Fastest Ethereum library** -- eth.zig [beats alloy.rs](bench/RESULTS.md) (Rust's leading Ethereum library, backed by Paradigm) on **18 out of 26 benchmarks**, measured 2026-06-10 against current alloy 1.6/2.0. RLP transaction encoding 24.33x faster, ABI decoding up to 8.41x, secp256k1 recovery 4.23x, ECDSA signing 2.34x, u256 division 3.43x, mulDiv 1.82x. See the [full results](bench/RESULTS.md).

**Comptime-first** -- Function selectors and event topics are computed at compile time with zero runtime cost. The compiler does the hashing so your program doesn't have to.

**Complete** -- ABI, RLP, secp256k1, Keccak-256, BIP-32/39/44 HD wallets, EIP-712, JSON-RPC, WebSocket, ENS, ERC-20/721 -- everything you need for Ethereum in one package.

## Performance vs alloy.rs

eth.zig wins **18/26 benchmarks** against [alloy.rs](https://alloy.rs) (alloy-primitives 1.6.0, alloy-consensus 2.0.5; run 2026-06-10). Measured on Apple Silicon, `ReleaseFast` (Zig) vs `--release` (Rust). Criterion-style harness with 0.5s warmup and 2s measurement.

| Operation | eth.zig | alloy.rs | Winner |
|-----------|---------|----------|--------|
| secp256k1 sign | 22,033 ns | 51,490 ns | **zig 2.34x** |
| secp256k1 sign+recover | 52,095 ns | 220,150 ns | **zig 4.23x** |
| Keccak-256 (32B) | 263 ns | 319 ns | **zig 1.21x** |
| Keccak-256 (4KB) | 7,732 ns | 7,838 ns | **zig 1.01x** |
| ABI encode (static) | 25 ns | 97 ns | **zig 3.88x** |
| ABI encode (dynamic) | 171 ns | 337 ns | **zig 1.97x** |
| ABI decode (uint256) | 14 ns | 51 ns | **zig 3.64x** |
| ABI decode (dynamic) | 32 ns | 269 ns | **zig 8.41x** |
| RLP encode (EIP-1559 tx) | 3 ns | 73 ns | **zig 24.33x** |
| u256 mulDiv (512-bit) | 17 ns | 31 ns | **zig 1.82x** |
| u256 division | 7 ns | 24 ns | **zig 3.43x** |
| u256 multiply | 5 ns | 10 ns | **zig 2.00x** |
| UniswapV2 getAmountOut | 24 ns | 24 ns | tie |
| UniswapV4 swap | 45 ns | 42 ns | rs 1.07x |
| TX hash (EIP-1559) | 271 ns | 361 ns | **zig 1.33x** |

alloy.rs wins on address hex parsing (1.55x -- SIMD), hex encoding (1.08x), UniswapV4 swap (1.07x), and Keccak at 256B/1KB inputs (within ~2%, measurement noise). See [full results](bench/RESULTS.md).

## Quick Start

### Derive an address from a private key

```zig
const eth = @import("eth");

const private_key = try eth.hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const signer = eth.signer.Signer.init(private_key);
const addr = try signer.address();
const checksum = eth.primitives.addressToChecksum(&addr);
// "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
```

### Sign and send a transaction

```zig
const eth = @import("eth");

var transport = eth.http_transport.HttpTransport.init(allocator, "https://rpc.example.com");
defer transport.deinit();
var provider = eth.provider.Provider.init(allocator, &transport);

var wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);
const tx_hash = try wallet.sendTransaction(.{
    .to = recipient_address,
    .value = eth.units.parseEther(1.0),
});
```

### Read an ERC-20 token

```zig
const eth = @import("eth");

// Comptime selectors -- zero runtime cost
const balance_sel = eth.erc20.selectors.balanceOf;

// Or use the typed wrapper
var token = eth.erc20.ERC20.init(allocator, token_addr, &provider);
const balance = try token.balanceOf(holder_addr);
const name = try token.name();
defer allocator.free(name);
```

### Simulate eth_call with state overrides

Lets searchers answer "what if?" questions without forking a node: what if this token balance were larger, what if this storage slot held a different value, what if this address ran alternative bytecode? Maps to the geth-style third argument to `eth_call`.

```zig
const eth = @import("eth");

var overrides = eth.state_overrides.StateOverrides.init(allocator);
defer overrides.deinit();

// Pretend this account is rich, has nonce 0, and the pool has a hand-tuned reserve.
try overrides.setBalance(searcher_addr, 1_000_000 * std.math.pow(u256, 10, 18));
try overrides.setNonce(searcher_addr, 0);
try overrides.setStorageAt(pool_addr, reserves_slot, new_reserves_word);

const result = try provider.callWithOverrides(target_contract, calldata, &overrides);
defer allocator.free(result);
```

### Function selectors and event topics

```zig
const eth = @import("eth");

// Computed at compile time -- zero runtime cost
const transfer_sel = comptime eth.keccak.selector("transfer(address,uint256)");
// transfer_sel == [4]u8{ 0xa9, 0x05, 0x9c, 0xbb }

// Same function works at runtime too
const runtime_sel = eth.keccak.selector(runtime_signature);

const transfer_topic = comptime eth.keccak.hash("Transfer(address,address,uint256)");
// transfer_topic == keccak256("Transfer(address,address,uint256)")
```

### HD wallet from mnemonic

```zig
const eth = @import("eth");

const words = [_][]const u8{
    "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "about",
};
const seed = try eth.mnemonic.toSeed(&words, "");
const key = try eth.hd_wallet.deriveEthAccount(seed, 0);
const addr = key.toAddress();
```

### Resilient WebSocket subscriptions (production bots)

`ws_client.WsClient` wraps `ws_transport` with three features bots need: transparent reconnect with exponential backoff + jitter, multiplexed subscriptions on a single socket, and an application-layer ping keepalive. Subscription handles stay valid across reconnects -- the underlying server-side sub-id is swapped automatically.

```zig
const eth = @import("eth");

const client = try eth.ws_client.WsClient.connect(allocator, "wss://mainnet.example.com/ws", .{});
defer client.deinit();

const heads = try client.subscribe(.{ .new_heads = {} });
const transfers = try client.subscribe(.{ .logs = .{
    .address = usdc_address,
    .topics = &.{transfer_event_topic},
} });
// MEV searchers: stream full pending transactions (geth-style).
const pending = try client.subscribe(.{ .new_pending_transactions = .{ .full = true } });

while (true) {
    const event = try client.next();
    defer allocator.free(event.payload);
    if (event.sub == heads) {
        const header = try eth.subscription.parseBlockFromNotification(allocator, event.payload);
        // ... handle new block
    } else if (event.sub == transfers) {
        const log = try eth.subscription.parseLogFromNotification(allocator, event.payload);
        // ... handle Transfer log
    } else if (event.sub == pending) {
        const tx = try eth.subscription.parseTransactionFromNotification(allocator, event.payload);
        defer eth.rpc_transaction.freeRpcTransaction(allocator, tx);
        // ... evaluate the pending tx (sandwich, backrun, ...)
    }
}
```

Lower-level building blocks remain available: `ws_transport.WsTransport` for raw frames and `ws_transport.connectWithReconnect()` for a callback-style reconnect loop without subscription state.

### Block-scoped log watching (keepers and searchers)

`log_watcher.LogWatcher` packages the canonical bot loop -- on each new head, fetch filtered logs for that block -- on top of `WsClient` + `eth_getLogs`. Blocks missed across reconnects are back-filled and reorged ranges are re-fetched automatically:

```zig
var watcher = try eth.log_watcher.LogWatcher.init(allocator, &provider, client, .{
    .address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
}, .{});
defer watcher.deinit();

while (true) {
    const logs = try watcher.pollOnce(); // blocks until the next head
    defer eth.log_watcher.freeLogs(allocator, logs);
    for (logs) |log| { /* liquidate, arb, ... */ }
}
```

## Built with eth.zig

Real production bots and SDKs built on eth.zig:

| Project | Description | Language |
|---------|-------------|----------|
| [perpcity-zig-sdk](https://github.com/StrobeLabs/perpcity-zig-sdk) | High-performance SDK for the PerpCity perpetual futures protocol on Base. Comptime ABI encoding, lock-free nonce management, 2-tier price cache. | Zig |
| [gator-liquidators](https://github.com/StrobeLabs/gator-liquidators) | Production liquidation keeper for PerpCity. Batch-checks positions via Multicall3, pre-signs liquidation txs, submits to Base sequencer. | Zig |

```text
eth.zig
  └── perpcity-zig-sdk   (protocol SDK with comptime contract ABIs)
        └── gator-liquidators   (production liquidation bot on Base)
```

Built something with eth.zig? Open a PR to add it here.

## Installation

**One-liner:**

<!-- x-release-please-start-version -->
```bash
zig fetch --save git+https://github.com/StrobeLabs/eth.zig.git#v0.8.0
```
<!-- x-release-please-end -->

**Or add manually** to your `build.zig.zon`:

<!-- x-release-please-start-version -->
```zig
.dependencies = .{
    .eth = .{
        .url = "git+https://github.com/StrobeLabs/eth.zig.git#v0.8.0",
        .hash = "...", // run `zig build` and it will tell you the expected hash
    },
},
```
<!-- x-release-please-end -->

Then import in your `build.zig`:

```zig
const eth_dep = b.dependency("eth", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("eth", eth_dep.module("eth"));
```

## Examples

The [`examples/`](examples/) directory contains self-contained programs demonstrating each major feature:

| Example | Description | Requires RPC |
|---------|-------------|:---:|
| `01_derive_address` | Derive address from private key | No |
| `02_check_balance` | Query ETH balance via JSON-RPC | Yes |
| `03_sign_message` | EIP-191 personal message signing | No |
| `04_send_transaction` | Send ETH with Wallet | Yes (Anvil) |
| `05_read_erc20` | ERC-20 module API showcase | Yes |
| `06_hd_wallet` | BIP-44 HD wallet derivation | No |
| `07_comptime_selectors` | Comptime function selectors | No |
| `08_mev_share_backrunner` | MEV-Share backrunner bot (SSE stream + bundle) | No (dry-run) |

Run any example:

```bash
cd examples && zig build && ./zig-out/bin/01_derive_address
```

## Modules

| Layer | Modules | Description |
|-------|---------|-------------|
| **Primitives** | `primitives`, `uint256`, `hex` | Address, Hash, Bytes32, u256, hex encoding |
| **Encoding** | `rlp`, `abi_encode`, `abi_decode`, `abi_types` | RLP and ABI encoding/decoding |
| **Crypto** | `secp256k1`, `signer`, `signature`, `keccak`, `eip155`, `kzg` | ECDSA signing (RFC 6979), Keccak-256, EIP-155, EIP-4844 KZG |
| **Types** | `transaction`, `receipt`, `block`, `blob`, `access_list` | Legacy, EIP-2930, EIP-1559, EIP-4844 transactions |
| **Accounts** | `mnemonic`, `hd_wallet` | BIP-32/39/44 HD wallets and mnemonic generation |
| **Transport** | `http_transport`, `ws_transport`, `sse_transport`, `json_rpc`, `provider`, `subscription`, `ws_client` | HTTP, WebSocket, and SSE transports; resilient WS client with auto-reconnect |
| **ENS** | `ens_namehash`, `ens_resolver`, `ens_reverse` | ENS name resolution and reverse lookup |
| **Client** | `wallet`, `contract`, `multicall`, `event`, `erc20`, `erc721` | Signing wallet, contract interaction, Multicall3, token wrappers |
| **Standards** | `eip712`, `abi_json` | EIP-712 typed data signing, Solidity JSON ABI parsing |
| **Chains** | `chains` | Ethereum, Arbitrum, Optimism, Base, Polygon definitions |

## Features

| Feature | Status |
|---------|--------|
| Primitives (Address, Hash, u256) | Complete |
| RLP encoding/decoding | Complete |
| ABI encoding/decoding (all Solidity types) | Complete |
| Keccak-256 hashing | Complete |
| secp256k1 ECDSA signing (RFC 6979, EIP-2 low-S) | Complete |
| Transaction types (Legacy, EIP-2930, EIP-1559, EIP-4844) | Complete |
| EIP-4844 KZG (blob commitments/proofs, vendored c-kzg-4844 + blst) | Complete |
| EIP-155 replay protection | Complete |
| EIP-191 personal message signing | Complete |
| EIP-712 typed structured data signing | Complete |
| EIP-55 address checksums | Complete |
| BIP-32/39/44 HD wallets | Complete |
| HTTP transport | Complete |
| WebSocket transport (with TLS) | Complete |
| Resilient WS client (auto-reconnect + resubscribe + keepalive) | Complete |
| JSON-RPC provider (24+ methods) | Complete |
| ENS resolution (forward + reverse) | Complete |
| Contract read/write helpers | Complete |
| Multicall3 batch calls | Complete |
| Event log decoding and filtering | Complete |
| Chain definitions (5 networks) | Complete |
| Unit conversions (Wei/Gwei/Ether) | Complete |
| ERC-20 typed wrapper | Complete |
| ERC-721 typed wrapper | Complete |
| JSON ABI parsing | Complete |
| EIP-7702 transactions | Planned |
| IPC transport | Planned |
| Provider middleware (retry, caching) | Planned |
| Hardware wallet signers | Planned |

## Comparison with Other Libraries

### Performance vs alloy.rs (Rust)

| Category | eth.zig | alloy.rs |
|----------|---------|----------|
| Benchmarks won | **18/26** | 5/26 |
| secp256k1 signing | Faster (2.34-4.23x) | -- |
| ABI encoding/decoding | Faster (1.96-8.41x) | -- |
| Hashing (Keccak) | Faster on small inputs (1.19-1.21x) | Within ~2% on 256B-1KB |
| u256 arithmetic | Faster on mul/div/mulDiv (1.82-3.43x) | UniswapV4 swap (1.07x) |
| Hex operations | Faster decoding (1.17x) | Faster encoding (1.08x) and parsing (1.55x, SIMD) |

### Features vs Zabi (Zig)

| Feature | eth.zig | Zabi |
|---------|---------|------|
| Comptime selectors | Yes | No |
| secp256k1 ECDSA | Yes (libsecp256k1 + Zig fallback) | Yes (C binding) |
| ABI encode/decode | Yes | Yes |
| HD wallets (BIP-32/39/44) | Yes | Yes |
| ERC-20/721 wrappers | Yes | No |
| JSON ABI parsing | Yes | Yes |
| WebSocket transport | Yes | Yes |
| ENS resolution | Yes | Yes |
| EIP-712 typed data | Yes | Yes |
| Multicall3 | Yes | No |

## Requirements

- Zig >= 0.16.0

## Running Tests

```bash
zig build test                # Unit tests
zig build integration-test    # Integration tests (requires Anvil)
```

## Benchmarks

One command to run the full comparison (requires Zig, Rust, Python 3):

```bash
bash bench/compare.sh
```

Or run individually:

```bash
zig build bench          # eth.zig only
```

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/StrobeLabs/eth.zig).

Before submitting:

1. Run `zig build test` and ensure all tests pass.
2. Follow the existing code style -- comptime where possible.
3. Add tests for any new functionality.

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright 2025-2026 Strobe Labs
