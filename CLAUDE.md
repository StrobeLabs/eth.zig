# eth.zig

Pure Zig Ethereum client library. Fastest EVM library across any language (23/26 benchmarks vs alloy.rs). Zero external dependencies -- stdlib + vendored C crypto only.

## Commands

```bash
make ci                # build + fmt check + unit tests (run before every commit)
make test              # unit tests only (no network required)
make integration-test  # requires Anvil on localhost:8545
make fmt-fix           # auto-format with zig fmt
make bench             # full benchmark suite (ReleaseFast)
```

Requires Zig >= 0.15.2. Avoid Zig 0.16.0-dev -- it enforces runtime safety checks on struct copy/move for types containing `std.Thread.Mutex`. If you must use 0.16.x, ensure mutex-containing types are never copied or moved (use pointers or arena allocation).

## Architecture -- Layered Dependencies

Each layer imports ONLY from layers below it. **Never import from a higher layer.** This is the most important structural rule in the codebase.

```text
Layer 1:  Primitives     (zero deps, no allocator needed)
          primitives.zig, uint256.zig, hex.zig

Layer 2:  Encoding       (-> primitives)
          rlp.zig, abi_encode.zig, abi_decode.zig, abi_types.zig

Layer 3:  Crypto         (-> primitives)
          keccak.zig, secp256k1.zig, signature.zig

Layer 4:  Types          (-> primitives, encoding, crypto)
          transaction.zig, receipt.zig, block.zig, log.zig, access_list.zig, blob.zig

Layer 5:  Accounts       (-> crypto, types)
          signer.zig, eip155.zig, hd_wallet.zig, mnemonic.zig

Layer 6:  Transport      (-> types)
          http_transport.zig, ws_transport.zig, json_rpc.zig, subscription.zig

Layer 7:  ENS            (-> transport, crypto)
          ens/namehash.zig, ens/resolver.zig, ens/reverse.zig

Layer 8:  Client         (-> transport, types, encoding, signer)
          provider.zig, wallet.zig, contract.zig, event.zig, multicall.zig

Layer 9:  Standards      (-> client, contract, crypto)
          eip712.zig, abi_json.zig

Layer 10: Chains         (pure data, zero deps)
          chains/
```

Layers 1-3 have zero I/O. Layers 1-5 have zero network dependencies. When adding a new file, decide which layer it belongs to and add it to `src/root.zig` in the correct section.

## Zig Style

### Naming

| What | Convention | Example |
|------|-----------|---------|
| Types, structs, enums | `PascalCase` | `Signature`, `AbiValue`, `HexError` |
| Functions | `camelCase` | `addressFromHex`, `charToNibble`, `toBigEndianBytes` |
| Variables, fields | `snake_case` | `private_key`, `gas_limit`, `max_fee_per_gas` |
| Constants | `SCREAMING_SNAKE` | `ZERO_ADDRESS`, `CURVE_ORDER_BYTES`, `GLV_BETA` |
| File names | `snake_case` | `hd_wallet.zig`, `abi_encode.zig`, `json_rpc.zig` |
| Error set members | `PascalCase` | `InvalidHexCharacter`, `SigningFailed` |

### Formatting

`zig fmt` is the law. CI enforces `zig fmt --check src/ tests/`. No exceptions, no custom formatting.

### Imports

Order: `std` first, then local modules alphabetically. Use `_mod` suffix when aliasing a module to avoid collision with a type name. Import types directly when used frequently.

```zig
const std = @import("std");
const hex_mod = @import("hex.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const Signature = @import("signature.zig").Signature;
```

### Struct Organization

Fields first, then `pub` methods (`init`/`deinit` at top), then private helpers. Tests at the bottom of the file.

```zig
pub const Wallet = struct {
    // Fields
    signer_instance: signer_mod.Signer,
    provider: *provider_mod.Provider,
    allocator: std.mem.Allocator,

    // Public methods
    pub fn init(...) Wallet { ... }
    pub fn deinit(self: *Wallet) void { ... }
    pub fn address(self: *const Wallet) ![20]u8 { ... }

    // Private helpers
    fn ensureChainId(self: *Wallet) !u64 { ... }
};
```

## Comptime Discipline

Comptime is a core design principle. Prefer comptime over runtime when the value is known at compile time.

**Lookup tables** -- generate at comptime, use at runtime with zero cost:
```zig
const hex_lut: [256]u8 = blk: {
    var table: [256]u8 = .{0xFF} ** 256;
    for ('0'..('9' + 1)) |c| table[c] = c - '0';
    // ...
    break :blk table;
};
```

**Function selectors and event topics** -- compute at comptime:
```zig
const transfer_sel = comptime eth.keccak.selector("transfer(address,uint256)");
```

**Runtime/comptime dispatch** -- use `@inComptime()` when runtime and comptime need different implementations:
```zig
pub fn hash(data: []const u8) Hash {
    if (@inComptime()) {
        @setEvalBranchQuota(10000);
        var result: Hash = undefined;
        StdlibKeccak256.hash(data, &result, .{});
        return result;
    }
    return xkcp.hash(data);
}
```

**Generic functions** -- use `comptime` parameters:
```zig
pub fn hexToBytesFixed(comptime N: usize, hex_str: []const u8) HexError![N]u8 { ... }
```

Use `@setEvalBranchQuota()` when comptime computation is heavy (e.g., precomputed EC point tables need 50000+).

## Memory Management

**Allocator passing**: Functions that allocate take `allocator: std.mem.Allocator` as a parameter. Never hide allocations.

**Ownership documentation**: Always document who owns returned memory:
```zig
/// Encode bytes to hex string with "0x" prefix.
/// Caller owns the returned memory.
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
```

**Cleanup**: Use `defer` for guaranteed cleanup, `errdefer` for error-path-only cleanup:
```zig
const result = try allocator.alloc(u8, len);
errdefer allocator.free(result);
// ... fill result, may return error ...
return result;
```

**Stack vs heap**: Use fixed-size arrays on the stack for known sizes (`[20]u8` for addresses, `[32]u8` for hashes). Only heap-allocate for variable-length data.

**Secure zeroing** for cryptographic material (private keys, seeds, nonces):
```zig
fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const volatile_ptr: *volatile u8 = b;
        volatile_ptr.* = 0;
    }
}
```

## Error Handling

**Custom error sets** -- define specific errors per module, not catch-all errors:
```zig
pub const HexError = error{
    InvalidHexCharacter,
    InvalidHexLength,
    OddHexLength,
    OutputTooSmall,
};
```

**Propagation**: Use `try` to propagate errors to callers. Use `catch` only when you can meaningfully handle the error.

**Optionals**: Return `?T` when absence is a valid, non-exceptional result:
```zig
pub fn recoverFromEip155V(v: u256, chain_id: u64) ?u8 { ... }
```

**No panicking in library code**. Use `@panic()` only for true invariant violations (e.g., division by zero in math utilities), never for recoverable conditions. Use `@branchHint(.cold)` before panic paths.

**Error union return types**: Specify the error set explicitly when the set is small and known. Use `!T` (inferred) when the error set is complex or composed from multiple sources.

## Testing

**Inline tests**: Tests live in the same file as the code they test, at the bottom.

**Descriptive names**: Use `test "functionName - scenario"` format:
```zig
test "addressFromHex" { ... }
test "addressToChecksum - vitalik.eth" { ... }
test "addressToChecksum - all zeros" { ... }
```

**Assertions**: Use typed assertions from `std.testing`:
```zig
try std.testing.expectEqual(@as(u8, 0xd8), addr[0]);
try std.testing.expectEqualSlices(u8, &expected, &actual);
try std.testing.expectEqualStrings("0xdeadbeef", result);
try std.testing.expectError(error.InvalidHexCharacter, charToNibble('g'));
try std.testing.expect(addressEql(&a, &b));
```

**Test allocator**: Use `std.testing.allocator` for tests that allocate -- it detects leaks:
```zig
test "bytesToHex roundtrip" {
    const allocator = std.testing.allocator;
    const result = try bytesToHex(allocator, &.{ 0xde, 0xad });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xdead", result);
}
```

**Known test vectors**: For crypto code, always test against published vectors (EIP-55, RFC 6979, BIP-32/39/44). Never invent your own test values for cryptographic operations.

**Unit vs integration**: Unit tests (`make test`) require no network. Integration tests (`make integration-test`) require Anvil. Never add network dependencies to unit tests.

**Registration**: When adding a new module, add `_ = @import("your_module.zig");` to the `test` block in `src/root.zig` so its tests are included in `make test`.

## Performance

**Inline sparingly**: Use `inline` only for small, hot functions where the compiler can't inline on its own (e.g., `mulLimbs`, `fastDiv`). Overuse bloats code and hurts icache.

**Branch hints**: Mark error/panic paths as cold:
```zig
if (b == 0) {
    @branchHint(.cold);
    @panic("division by zero");
}
```

**u256 arithmetic**: Use the limb-based `fastDiv`/`divLimbs` in `uint256.zig` instead of Zig's native u256 division, which falls back to LLVM's slow `__udivti3`.

**Bit manipulation**: Prefer shifts and masks over division/modulo for powers of 2:
```zig
result[2 + i * 2] = hex_chars[byte >> 4];
result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
```

**Benchmarks**: Run `make bench` before and after performance-sensitive changes. Compare against the existing numbers in README.md.

## Cryptographic Safety

- **Constant-time operations**: Use `cmov`-style patterns for secret-dependent branches. Never branch on secret data.
- **Volatile zeroing**: Always zero private keys, seeds, and nonces after use with volatile writes (prevents compiler from optimizing away the zeroing).
- **RFC compliance**: Follow published standards exactly (RFC 6979 for deterministic k, BIP-32/39/44 for HD wallets, EIP-155 for replay protection).
- **No custom crypto**: Use vendored libsecp256k1 (Bitcoin Core) for EC operations and XKCP for Keccak. Do not implement your own elliptic curve math or hash functions.
- **Scalar validation**: Always validate private keys are non-zero and less than the curve order before use.

## Known LLVM Traps (aarch64)

These are compiler bugs, not code bugs. They crash LLVM on Apple Silicon and other ARM64 targets.

**`@intFromFloat` and `@floatFromInt` with u256**: Crashes LLVM backend.
```zig
// BAD -- crashes LLVM on aarch64
const x: u256 = @intFromFloat(some_float);

// GOOD -- convert via u128 intermediate
const intermediate: u128 = @intFromFloat(some_float);
const x: u256 = @as(u256, intermediate);
```

**u512 division**: Not supported on aarch64. Crashes LLVM.
```zig
// BAD -- crashes on aarch64
const result = a_u512 / b_u512;

// GOOD -- restructure to avoid u512 division entirely
// For Uniswap TickMath: use std.math.maxInt(u256) / ratio instead
```

If you need wide integer arithmetic, keep operations at u256 or below and use the limb-based helpers in `uint256.zig`.

## Rules

- **No external dependencies**. Everything builds on Zig stdlib + vendored C crypto. If you need new functionality, implement it.
- **No emojis** in code, comments, logs, or error messages. They break log search.
- **Never ignore CI**. `make ci` must pass before committing.
- **Never push directly to main**. Always create a branch and PR.
- **No hidden allocations**. Every allocation must take an explicit allocator parameter.
- **No `std.debug.print` in library code**. Tests and examples only.
- **Prefer `const` over `var`**. Mutable state should be the exception.
- **Tagged unions over type erasure**. Use `union(enum)` for polymorphism (see `AbiValue`, `Transaction`).
- **Anonymous struct returns** are fine for multi-value returns: `struct { q: u64, r: u64 }`.
- **Array repetition** for initialization: `[_]u8{0} ** 32`, `.{0xFF} ** 256`.
- **`@memcpy` and `@memset`** over manual loops for bulk memory operations.
- **Slice-to-array** with `.*`: `const key = mac[0..32].*;`
