//! ENS forward resolution via the ENSIP-10 Universal Resolver.
//!
//! `resolve` / `getText` / `getContentHash` each normalize the name per
//! ENSIP-15, derive the namehash and the ENSIP-10 DNS-wire encoding from the
//! same normalized string, wrap the inner resolver call
//! (`addr` / `text` / `contenthash`) and send a single `resolve(bytes,bytes)`
//! call to the Universal Resolver. The UR follows CCIP-Read / wildcard
//! resolution and returns `(bytes result, address resolver)`. Its custom-error
//! reverts map to `null` (no record) or to `error.OffchainLookupRequired`.

const std = @import("std");
const keccak = @import("../keccak.zig");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");
const abi_encode = @import("../abi_encode.zig");
const abi_decode = @import("../abi_decode.zig");
const abi_types = @import("../abi_types.zig");
const namehash_mod = @import("namehash.zig");
const ens_normalize = @import("normalize.zig");
const contenthash = @import("contenthash.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Address = primitives.Address;

/// The ENS Universal Resolver, deployed at the same address on Ethereum mainnet
/// and Sepolia: `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe`.
pub const UNIVERSAL_RESOLVER: Address = .{
    0xeE, 0xeE, 0xEE, 0xeE, 0x14, 0xD7, 0x18, 0xC2, 0xB4, 0x7D,
    0x99, 0x23, 0xDe, 0xab, 0x13, 0x35, 0xE1, 0x44, 0xEe, 0xEe,
};

/// `resolve(bytes,bytes)` selector on the Universal Resolver: `0x9061b923`.
const RESOLVE_SELECTOR: [4]u8 = keccak.selector("resolve(bytes,bytes)");
/// `addr(bytes32)` selector: `0x3b3b57de`.
const ADDR_SELECTOR: [4]u8 = keccak.selector("addr(bytes32)");
/// `text(bytes32,string)` selector: `0x59d1d43c`.
const TEXT_SELECTOR: [4]u8 = keccak.selector("text(bytes32,string)");
/// `contenthash(bytes32)` selector: `0xbc1c58d1`.
const CONTENTHASH_SELECTOR: [4]u8 = keccak.selector("contenthash(bytes32)");

// Universal Resolver custom-error selectors (ens-contracts
// AbstractUniversalResolver / IUniversalResolver). Verified with `cast sig`.
/// `OffchainLookup(address,string[],bytes,bytes4,bytes)`: `0x556f1830`.
const OFFCHAIN_LOOKUP_SELECTOR: [4]u8 = keccak.selector("OffchainLookup(address,string[],bytes,bytes4,bytes)");
/// `ResolverNotFound(bytes)`: `0x77209fe8`.
const RESOLVER_NOT_FOUND_SELECTOR: [4]u8 = keccak.selector("ResolverNotFound(bytes)");
/// `ResolverNotContract(bytes,address)`: `0x1e9535f2`.
const RESOLVER_NOT_CONTRACT_SELECTOR: [4]u8 = keccak.selector("ResolverNotContract(bytes,address)");
/// `UnsupportedResolverProfile(bytes4)`: `0x7b1c461b`.
const UNSUPPORTED_RESOLVER_PROFILE_SELECTOR: [4]u8 = keccak.selector("UnsupportedResolverProfile(bytes4)");
/// `ResolverError(bytes)`: `0x95c0c752`.
const RESOLVER_ERROR_SELECTOR: [4]u8 = keccak.selector("ResolverError(bytes)");

/// Errors that can occur during ENS forward resolution.
pub const ResolveError = error{
    /// The ABI-encoded response was too short or malformed.
    InvalidResponse,
    /// Memory allocation failure.
    OutOfMemory,
    /// The provider call failed (transport error, or a revert we cannot map).
    ProviderError,
    /// The Universal Resolver reverted with an EIP-3668 `OffchainLookup`; the
    /// record lives off-chain and requires a CCIP-Read gateway round-trip that
    /// this synchronous API does not perform.
    OffchainLookupRequired,
} || ens_normalize.NormalizeError || error{LabelTooLong};

/// Resolve an ENS name to an Ethereum address via the Universal Resolver.
///
/// Normalizes the name (ENSIP-15), then calls `addr(bytes32)` through the UR.
/// Returns null when there is no resolver or the record is the zero address.
pub fn resolve(allocator: std.mem.Allocator, provider: anytype, name: []const u8) ResolveError!?Address {
    const normalized = try ens_normalize.normalize(allocator, name);
    defer allocator.free(normalized);

    const node = namehash_mod.namehash(normalized);
    const inner = try buildBytes32Call(allocator, ADDR_SELECTOR, node);
    defer allocator.free(inner);

    const result = (try callUniversalResolver(allocator, provider, normalized, inner)) orelse return null;
    defer allocator.free(result);

    const types = [_]AbiType{.address};
    const decoded = try decodeOrInvalid(result, &types, allocator);
    defer abi_decode.freeValues(decoded, allocator);
    if (decoded.len < 1) return error.InvalidResponse;

    const addr = decoded[0].address;
    if (std.mem.eql(u8, &addr, &primitives.ZERO_ADDRESS)) return null;
    return addr;
}

/// Look up a text record for an ENS name via the Universal Resolver.
///
/// Calls `text(bytes32,string)` through the UR. Returns null when there is no
/// resolver or the record is empty. Caller owns the returned memory.
pub fn getText(allocator: std.mem.Allocator, provider: anytype, name: []const u8, key: []const u8) ResolveError!?[]u8 {
    const normalized = try ens_normalize.normalize(allocator, name);
    defer allocator.free(normalized);

    const node = namehash_mod.namehash(normalized);
    const inner = try buildTextCall(allocator, node, key);
    defer allocator.free(inner);

    const result = (try callUniversalResolver(allocator, provider, normalized, inner)) orelse return null;
    defer allocator.free(result);

    const types = [_]AbiType{.string};
    const decoded = try decodeOrInvalid(result, &types, allocator);
    defer abi_decode.freeValues(decoded, allocator);
    if (decoded.len < 1) return error.InvalidResponse;

    const text = decoded[0].string;
    if (text.len == 0) return null;
    return try allocator.dupe(u8, text);
}

/// Look up the EIP-1577 contenthash record for an ENS name via the UR.
///
/// Calls `contenthash(bytes32)` through the UR and decodes the result. Returns
/// null when there is no resolver or the record is empty. Caller owns the
/// returned `ContentHash` and must call `deinit`.
pub fn getContentHash(allocator: std.mem.Allocator, provider: anytype, name: []const u8) ResolveError!?contenthash.ContentHash {
    const normalized = try ens_normalize.normalize(allocator, name);
    defer allocator.free(normalized);

    const node = namehash_mod.namehash(normalized);
    const inner = try buildBytes32Call(allocator, CONTENTHASH_SELECTOR, node);
    defer allocator.free(inner);

    const result = (try callUniversalResolver(allocator, provider, normalized, inner)) orelse return null;
    defer allocator.free(result);

    const types = [_]AbiType{.bytes};
    const decoded = try decodeOrInvalid(result, &types, allocator);
    defer abi_decode.freeValues(decoded, allocator);
    if (decoded.len < 1) return error.InvalidResponse;

    const ch_bytes = decoded[0].bytes;
    if (ch_bytes.len == 0) return null;

    return contenthash.decode(allocator, ch_bytes) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
}

/// Send `resolve(bytes,bytes)` to the Universal Resolver for `normalized_name`
/// with the given inner resolver calldata, and return the inner result bytes
/// extracted from the `(bytes result, address resolver)` tuple. Returns null
/// when the resolver is absent (zero address, or a UR custom error that maps to
/// "no record"). Caller owns the returned slice.
fn callUniversalResolver(
    allocator: std.mem.Allocator,
    provider: anytype,
    normalized_name: []const u8,
    inner_calldata: []const u8,
) ResolveError!?[]u8 {
    const dns = namehash_mod.dnsEncode(allocator, normalized_name) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.LabelTooLong => return error.LabelTooLong,
    };
    defer allocator.free(dns);

    const values = [_]AbiValue{ .{ .bytes = dns }, .{ .bytes = inner_calldata } };
    const outer = try encodeCall(allocator, RESOLVE_SELECTOR, &values);
    defer allocator.free(outer);

    const response = provider.call(UNIVERSAL_RESOLVER, outer) catch {
        return mapRevert(provider);
    };
    defer allocator.free(response);

    const types = [_]AbiType{ .bytes, .address };
    const decoded = try decodeOrInvalid(response, &types, allocator);
    defer abi_decode.freeValues(decoded, allocator);
    if (decoded.len < 2) return error.InvalidResponse;

    const resolver = decoded[1].address;
    if (std.mem.eql(u8, &resolver, &primitives.ZERO_ADDRESS)) return null;

    return try allocator.dupe(u8, decoded[0].bytes);
}

/// Inspect the provider's last revert and map the Universal Resolver custom
/// error selector to a resolution outcome: null (no record), or an error.
///
/// Exposed (not just `resolver.zig`-private) so `reverse.zig` can reuse the
/// same forward-resolution "not found" family mapping for `reverse()` reverts.
/// This is an internal helper exported for reuse within eth.zig's ENS
/// modules, not a stable public API.
pub fn mapRevert(provider: anytype) ResolveError!?[]u8 {
    const info = provider.lastError() orelse return error.ProviderError;
    const selector = parseSelector(info.data) orelse return error.ProviderError;

    if (std.mem.eql(u8, &selector, &OFFCHAIN_LOOKUP_SELECTOR)) return error.OffchainLookupRequired;
    if (std.mem.eql(u8, &selector, &RESOLVER_NOT_FOUND_SELECTOR)) return null;
    if (std.mem.eql(u8, &selector, &RESOLVER_NOT_CONTRACT_SELECTOR)) return null;
    if (std.mem.eql(u8, &selector, &UNSUPPORTED_RESOLVER_PROFILE_SELECTOR)) return null;
    if (std.mem.eql(u8, &selector, &RESOLVER_ERROR_SELECTOR)) return null;
    return error.ProviderError;
}

/// Parse the leading 4-byte selector out of a hex revert-data string such as
/// `"0x556f1830...."`. Returns null if there are fewer than 4 hex-encoded bytes.
///
/// Exported so `reverse.zig` can reuse it for `ReverseAddressMismatch`
/// detection. This is an internal helper exported for reuse within eth.zig's
/// ENS modules, not a stable public API.
pub fn parseSelector(data: []const u8) ?[4]u8 {
    var s = data;
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) s = s[2..];
    if (s.len < 8) return null;
    var out: [4]u8 = undefined;
    for (0..4) |i| {
        const hi = hex_mod.charToNibble(s[i * 2]) catch return null;
        const lo = hex_mod.charToNibble(s[i * 2 + 1]) catch return null;
        out[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return out;
}

/// Decode ABI values, mapping every decode failure except OOM to InvalidResponse.
fn decodeOrInvalid(data: []const u8, types: []const AbiType, allocator: std.mem.Allocator) ResolveError![]AbiValue {
    return abi_decode.decodeValues(data, types, allocator) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
}

/// Build calldata for a `f(bytes32)` resolver profile (`addr` / `contenthash`).
fn buildBytes32Call(allocator: std.mem.Allocator, selector: [4]u8, node: [32]u8) ResolveError![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);
    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    return encodeCall(allocator, selector, &values);
}

/// Build calldata for `text(bytes32,string)`.
fn buildTextCall(allocator: std.mem.Allocator, node: [32]u8, key: []const u8) ResolveError![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);
    const values = [_]AbiValue{ .{ .fixed_bytes = fb }, .{ .string = key } };
    return encodeCall(allocator, TEXT_SELECTOR, &values);
}

/// `encodeFunctionCall` narrowed to `ResolveError` (we never exceed the value
/// count, so `TooManyValues` is unreachable and mapped to InvalidResponse).
fn encodeCall(allocator: std.mem.Allocator, selector: [4]u8, values: []const AbiValue) ResolveError![]u8 {
    return abi_encode.encodeFunctionCall(allocator, selector, values) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooManyValues => error.InvalidResponse,
    };
}

// ============================================================================
// Tests
// ============================================================================

const Provider = @import("../provider.zig").Provider;

/// Minimal `provider: anytype` test double capturing the last call and
/// optionally faking a revert (`fail=true` + `err_data`).
const MockProvider = struct {
    response: []const u8 = "",
    err_data: []const u8 = "",
    fail: bool = false,
    captured_to: [20]u8 = undefined,
    captured_data: []u8 = &.{},
    allocator: std.mem.Allocator,

    fn deinit(self: *MockProvider) void {
        if (self.captured_data.len > 0) self.allocator.free(self.captured_data);
        self.captured_data = &.{};
    }

    pub fn call(self: *MockProvider, to: [20]u8, data: []const u8) ![]u8 {
        self.captured_to = to;
        if (self.captured_data.len > 0) self.allocator.free(self.captured_data);
        self.captured_data = try self.allocator.dupe(u8, data);
        if (self.fail) return error.RpcError;
        return self.allocator.dupe(u8, self.response);
    }

    pub fn lastError(self: *const MockProvider) ?Provider.ErrorInfo {
        if (!self.fail) return null;
        return .{ .code = 3, .message = "execution reverted", .data = self.err_data };
    }
};

/// Encode `(bytes result, address resolver)` as the UR would return it.
fn encodeUrTuple(allocator: std.mem.Allocator, inner_result: []const u8, resolver: Address) ![]u8 {
    const values = [_]AbiValue{ .{ .bytes = inner_result }, .{ .address = resolver } };
    return abi_encode.encodeValues(allocator, &values);
}

test "selectors match known hashes" {
    try std.testing.expectEqualSlices(u8, &.{ 0x90, 0x61, 0xb9, 0x23 }, &RESOLVE_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x3b, 0x3b, 0x57, 0xde }, &ADDR_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x59, 0xd1, 0xd4, 0x3c }, &TEXT_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0xbc, 0x1c, 0x58, 0xd1 }, &CONTENTHASH_SELECTOR);
}

test "UR custom-error selectors match cast sig output" {
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x6f, 0x18, 0x30 }, &OFFCHAIN_LOOKUP_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x77, 0x20, 0x9f, 0xe8 }, &RESOLVER_NOT_FOUND_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x1e, 0x95, 0x35, 0xf2 }, &RESOLVER_NOT_CONTRACT_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x7b, 0x1c, 0x46, 0x1b }, &UNSUPPORTED_RESOLVER_PROFILE_SELECTOR);
    try std.testing.expectEqualSlices(u8, &.{ 0x95, 0xc0, 0xc7, 0x52 }, &RESOLVER_ERROR_SELECTOR);
}

test "UNIVERSAL_RESOLVER address is correct" {
    const expected = try hex_mod.hexToBytesFixed(20, "eEeEEEeE14D718C2B47D9923Deab1335E144EeEe");
    try std.testing.expectEqualSlices(u8, &expected, &UNIVERSAL_RESOLVER);
}

test "resolve builds resolve(bytes,bytes) outer calldata" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator };
    defer mock.deinit();

    // Response is empty -> decode fails after the call, but calldata is captured.
    _ = resolve(allocator, &mock, "vitalik.eth") catch {};

    const cd = mock.captured_data;
    // 4 (selector) + 64 (2 head slots) + 64 (dns: len+padded 13) + 96 (inner: len+padded 36).
    try std.testing.expectEqual(@as(usize, 228), cd.len);
    try std.testing.expectEqualSlices(u8, &UNIVERSAL_RESOLVER, &mock.captured_to);
    try std.testing.expectEqualSlices(u8, &RESOLVE_SELECTOR, cd[0..4]);
    // Head: offset0 = 0x40, offset1 = 0x80.
    try std.testing.expectEqual(@as(u8, 0x40), cd[35]);
    try std.testing.expectEqual(@as(u8, 0x80), cd[67]);
    // arg0 (dns) length = 13, then the DNS-wire bytes.
    try std.testing.expectEqual(@as(u8, 13), cd[99]);
    try std.testing.expectEqualSlices(u8, "\x07vitalik\x03eth\x00", cd[100..113]);
    // arg1 (inner addr(bytes32)) length = 36, selector, then the namehash.
    try std.testing.expectEqual(@as(u8, 36), cd[163]);
    try std.testing.expectEqualSlices(u8, &ADDR_SELECTOR, cd[164..168]);
    const node = namehash_mod.namehash("vitalik.eth");
    try std.testing.expectEqualSlices(u8, &node, cd[168..200]);
}

test "resolve decodes address from UR tuple" {
    const allocator = std.testing.allocator;
    const want = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const resolver_addr: Address = @splat(0x22);

    // Inner result = abi(address); outer = abi(bytes result, address resolver).
    const inner_values = [_]AbiValue{.{ .address = want }};
    const inner_result = try abi_encode.encodeValues(allocator, &inner_values);
    defer allocator.free(inner_result);
    const response = try encodeUrTuple(allocator, inner_result, resolver_addr);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    const got = (try resolve(allocator, &mock, "vitalik.eth")).?;
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "resolve returns null when tuple resolver is zero" {
    const allocator = std.testing.allocator;
    const inner_values = [_]AbiValue{.{ .address = @as(Address, @splat(0x11)) }};
    const inner_result = try abi_encode.encodeValues(allocator, &inner_values);
    defer allocator.free(inner_result);
    const response = try encodeUrTuple(allocator, inner_result, primitives.ZERO_ADDRESS);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    try std.testing.expectEqual(@as(?Address, null), try resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve maps ResolverNotFound revert to null" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0x77209fe8" };
    defer mock.deinit();
    try std.testing.expectEqual(@as(?Address, null), try resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve maps ResolverError revert to null" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0x95c0c752" };
    defer mock.deinit();
    try std.testing.expectEqual(@as(?Address, null), try resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve maps OffchainLookup revert to error" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0x556f1830deadbeef" };
    defer mock.deinit();
    try std.testing.expectError(error.OffchainLookupRequired, resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve maps unknown revert to ProviderError" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0xdeadbeef" };
    defer mock.deinit();
    try std.testing.expectError(error.ProviderError, resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve maps revert with no data to ProviderError" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "" };
    defer mock.deinit();
    try std.testing.expectError(error.ProviderError, resolve(allocator, &mock, "vitalik.eth"));
}

test "resolve case-folds name before building calldata" {
    const allocator = std.testing.allocator;
    var mock_upper = MockProvider{ .allocator = allocator };
    defer mock_upper.deinit();
    var mock_lower = MockProvider{ .allocator = allocator };
    defer mock_lower.deinit();

    _ = resolve(allocator, &mock_upper, "Vitalik.ETH") catch {};
    _ = resolve(allocator, &mock_lower, "vitalik.eth") catch {};

    try std.testing.expectEqualSlices(u8, mock_lower.captured_data, mock_upper.captured_data);
}

test "getText decodes string from UR tuple" {
    const allocator = std.testing.allocator;
    const inner_values = [_]AbiValue{.{ .string = "https://vitalik.ca" }};
    const inner_result = try abi_encode.encodeValues(allocator, &inner_values);
    defer allocator.free(inner_result);
    const response = try encodeUrTuple(allocator, inner_result, @as(Address, @splat(0x22)));
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    const got = (try getText(allocator, &mock, "vitalik.eth", "url")).?;
    defer allocator.free(got);
    try std.testing.expectEqualStrings("https://vitalik.ca", got);
}

test "getText builds text(bytes32,string) inner calldata" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator };
    defer mock.deinit();
    _ = getText(allocator, &mock, "vitalik.eth", "url") catch {};

    // Head(64) + dns(64) => arg1 length word at [128..160), inner calldata at [160...).
    const cd = mock.captured_data;
    try std.testing.expectEqualSlices(u8, &TEXT_SELECTOR, cd[164..168]);
}

test "getContentHash decodes ipfs record end to end" {
    const allocator = std.testing.allocator;
    // contenthash bytes for ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4
    var ch_bytes: [38]u8 = undefined;
    _ = try hex_mod.hexToBytes(&ch_bytes, "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f");

    const inner_values = [_]AbiValue{.{ .bytes = &ch_bytes }};
    const inner_result = try abi_encode.encodeValues(allocator, &inner_values);
    defer allocator.free(inner_result);
    const response = try encodeUrTuple(allocator, inner_result, @as(Address, @splat(0x22)));
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    var got = (try getContentHash(allocator, &mock, "vitalik.eth")).?;
    defer got.deinit(allocator);
    try std.testing.expectEqual(contenthash.Protocol.ipfs, got.protocol);
    try std.testing.expectEqualStrings("ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", got.uri);
}

test "resolve rejects invalid names via normalize" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator };
    defer mock.deinit();
    // Empty label (leading dot) is rejected by ENSIP-15 normalize.
    try std.testing.expectError(error.EmptyLabel, resolve(allocator, &mock, ".eth"));
}
