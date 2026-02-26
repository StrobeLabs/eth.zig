# Changelog

All notable changes to eth.zig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
