# eth.zig

[![CI](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/strobelabs/eth.zig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-%E2%89%A5%200.15.2-orange)](https://ziglang.org/)

**The Ethereum library for Zig.**

eth.zig provides everything you need to interact with Ethereum from Zig -- signing transactions, encoding ABI calls, managing HD wallets, reading ERC-20 tokens, talking to nodes over JSON-RPC, and more.

## Why eth.zig?

**Zero dependencies** -- Built entirely on Zig's standard library. No C bindings, no vendored C code, no system libraries. Just `zig build` and go.

**Comptime-first** -- Function selectors and event topics are computed at compile time with zero runtime cost. The compiler does the hashing so your program doesn't have to.

**Pure Zig crypto** -- secp256k1 ECDSA, Keccak-256, BIP-32/39/44 HD wallets -- all implemented in pure Zig. No OpenSSL, no libsecp256k1, no FFI.

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
zig fetch --save git+https://github.com/StrobeLabs/eth.zig.git#v0.1.0
```

**Or add manually** to your `build.zig.zon`:

```zig
.dependencies = .{
    .eth = .{
        .url = "git+https://github.com/StrobeLabs/eth.zig.git#v0.1.0",
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

## Feature Comparison vs Zabi

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

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/StrobeLabs/eth.zig).

Before submitting:

1. Run `zig build test` and ensure all tests pass.
2. Follow the existing code style -- no external dependencies, comptime where possible.
3. Add tests for any new functionality.

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright 2025-2026 Strobe Labs
