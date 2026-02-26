# eth.zig

[![CI](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-ethzig.org-blue)](https://ethzig.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-%E2%89%A5%200.15.2-orange)](https://ziglang.org/)

**The fastest Ethereum library. Pure Zig. Zero dependencies.**

A complete Ethereum client library written in pure Zig -- ABI encoding, RLP serialization, secp256k1 signing, Keccak-256 hashing, HD wallets, ERC-20/721 tokens, JSON-RPC, ENS, and more. No C bindings. No system libraries. Just `zig build`.

**[Read the docs at ethzig.org](https://ethzig.org)**

## Why eth.zig?

**Faster than Rust** -- eth.zig [beats alloy.rs](bench/RESULTS.md) (Rust's leading Ethereum library, backed by Paradigm) on **19 out of 26 benchmarks**, including UniswapV4 mulDiv. ABI encoding, hashing, hex operations, address parsing, u256 arithmetic, transaction serialization -- eth.zig is faster on the majority of operations.

**Zero dependencies** -- Built entirely on Zig's standard library. No C bindings, no vendored C code, no system libraries.

**Comptime-first** -- Function selectors and event topics are computed at compile time with zero runtime cost. The compiler does the hashing so your program doesn't have to.

**Pure Zig crypto** -- secp256k1 ECDSA, Keccak-256, BIP-32/39/44 HD wallets -- all implemented in pure Zig. No OpenSSL, no libsecp256k1, no FFI.

## Performance vs alloy.rs

eth.zig wins **19/26 benchmarks** against [alloy.rs](https://alloy.rs). Measured on Apple Silicon, `ReleaseFast` (Zig) vs `--release` (Rust).

| Operation | eth.zig | alloy.rs | Winner |
|-----------|---------|----------|--------|
| Keccak-256 (32B) | 128 ns | 175 ns | **zig 1.37x** |
| Keccak-256 (4KB) | 4,008 ns | 4,772 ns | **zig 1.19x** |
| ABI encode (static) | 26 ns | 50 ns | **zig 1.92x** |
| ABI encode (dynamic) | 114 ns | 175 ns | **zig 1.54x** |
| ABI decode (uint256) | 22 ns | 26 ns | **zig 1.18x** |
| ABI decode (dynamic) | 75 ns | 133 ns | **zig 1.77x** |
| Address derivation | 135 ns | 190 ns | **zig 1.41x** |
| Address from hex | 8 ns | 13 ns | **zig 1.62x** |
| Address checksum | 159 ns | 201 ns | **zig 1.26x** |
| u256 multiply | 2 ns | 5 ns | **zig 2.50x** |
| u256 division | 3 ns | 12 ns | **zig 4.00x** |
| u256 mulDiv (V4) | 11 ns | 14 ns | **zig 1.27x** |
| UniswapV4 swap | 21 ns | 24 ns | **zig 1.14x** |
| Hex encode (32B) | 11 ns | 11 ns | tie |
| Hex decode (32B) | 12 ns | 24 ns | **zig 2.00x** |
| RLP decode u256 | 3 ns | 6 ns | **zig 2.00x** |
| TX hash (EIP-1559) | 184 ns | 210 ns | **zig 1.14x** |

alloy.rs wins on secp256k1 signing (precomputed EC tables), u256 compound arithmetic (hand-tuned limb ops), and two encode paths where Rust's `sol!` macro generates specialized code at compile time. See [full results](bench/RESULTS.md).

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

### Comptime function selectors and event topics

```zig
const eth = @import("eth");

// Computed at compile time -- zero runtime cost
const transfer_sel = eth.abi_comptime.comptimeSelector("transfer(address,uint256)");
// transfer_sel == [4]u8{ 0xa9, 0x05, 0x9c, 0xbb }

const transfer_topic = eth.abi_comptime.comptimeTopic("Transfer(address,address,uint256)");
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

## Installation

**One-liner:**

```bash
zig fetch --save git+https://github.com/StrobeLabs/eth.zig.git#v0.2.2
```

**Or add manually** to your `build.zig.zon`:

```zig
.dependencies = .{
    .eth = .{
        .url = "git+https://github.com/StrobeLabs/eth.zig.git#v0.2.2",
        .hash = "...", // run `zig build` and it will tell you the expected hash
    },
},
```

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

Run any example:

```bash
cd examples && zig build && ./zig-out/bin/01_derive_address
```

## Modules

| Layer | Modules | Description |
|-------|---------|-------------|
| **Primitives** | `primitives`, `uint256`, `hex` | Address, Hash, Bytes32, u256, hex encoding |
| **Encoding** | `rlp`, `abi_encode`, `abi_decode`, `abi_types`, `abi_comptime` | RLP and ABI encoding/decoding, comptime selectors |
| **Crypto** | `secp256k1`, `signer`, `signature`, `keccak`, `eip155` | ECDSA signing (RFC 6979), Keccak-256, EIP-155 |
| **Types** | `transaction`, `receipt`, `block`, `blob`, `access_list` | Legacy, EIP-2930, EIP-1559, EIP-4844 transactions |
| **Accounts** | `mnemonic`, `hd_wallet` | BIP-32/39/44 HD wallets and mnemonic generation |
| **Transport** | `http_transport`, `ws_transport`, `json_rpc`, `provider`, `subscription` | HTTP and WebSocket JSON-RPC transports |
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
| EIP-155 replay protection | Complete |
| EIP-191 personal message signing | Complete |
| EIP-712 typed structured data signing | Complete |
| EIP-55 address checksums | Complete |
| BIP-32/39/44 HD wallets | Complete |
| HTTP transport | Complete |
| WebSocket transport (with TLS) | Complete |
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
| Benchmarks won | **19/26** | 5/26 |
| ABI encoding | Faster (1.18-1.92x) | Faster on 1 specialized path |
| Hashing (Keccak) | Faster (1.19-1.45x) | -- |
| Hex operations | Faster (1.00-2.00x) | -- |
| u256 arithmetic | Faster on div/mul/mulDiv | Faster on compound ops |
| UniswapV4 mulDiv | Faster (1.27x) | -- |
| secp256k1 signing | -- | Faster (precomputed tables) |

### Features vs Zabi (Zig)

| Feature | eth.zig | Zabi |
|---------|---------|------|
| Dependencies | 0 | 0 |
| Comptime selectors | Yes | No |
| Pure Zig crypto (secp256k1) | Yes | No (C binding) |
| ABI encode/decode | Yes | Yes |
| HD wallets (BIP-32/39/44) | Yes | Yes |
| ERC-20/721 wrappers | Yes | No |
| JSON ABI parsing | Yes | Yes |
| WebSocket transport | Yes | Yes |
| ENS resolution | Yes | Yes |
| EIP-712 typed data | Yes | Yes |
| Multicall3 | Yes | No |

## Requirements

- Zig >= 0.15.2

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
2. Follow the existing code style -- no external dependencies, comptime where possible.
3. Add tests for any new functionality.

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright 2025-2026 Strobe Labs
