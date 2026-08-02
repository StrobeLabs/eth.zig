//! ENS reverse resolution via the ENSIP-19 Universal Resolver `reverse` profile.
//!
//! `lookupAddress` sends a single `reverse(bytes,uint256)` call to the
//! Universal Resolver with coinType 60 (the default ETH address record). The
//! UR resolves the `<addr>.addr.reverse` name, reads its primary name, and
//! additionally verifies the forward record (`addr(bytes32)` for coinType 60)
//! matches the address being reverse-resolved -- reverting with
//! `ReverseAddressMismatch` when it does not. The name the UR returns is
//! checked against its own ENSIP-15 normalized form: ENS treats an
//! unnormalized primary name as equivalent to no primary name being set, so
//! this function returns `null` rather than rewriting it to a name whose
//! forward record the UR never verified.

const std = @import("std");
const keccak = @import("../keccak.zig");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");
const abi_encode = @import("../abi_encode.zig");
const abi_decode = @import("../abi_decode.zig");
const abi_types = @import("../abi_types.zig");
const namehash_mod = @import("namehash.zig");
const ens_normalize = @import("normalize.zig");
const resolver_mod = @import("resolver.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Address = primitives.Address;

/// The suffix used for reverse resolution.
const REVERSE_SUFFIX = ".addr.reverse";

/// `reverse(bytes,uint256)` selector on the Universal Resolver: `0x5d78a217`.
const REVERSE_SELECTOR: [4]u8 = keccak.selector("reverse(bytes,uint256)");

/// `ReverseAddressMismatch(string,bytes)` custom-error selector: `0xef9c03ce`.
/// Raised by the Universal Resolver when the coinType-60 forward record for
/// the resolved primary name does not match the address being reverse
/// resolved. Not part of `resolver_mod.mapRevert`'s "not found" family (that
/// set is for forward `resolve()` reverts), so it is mapped here.
const REVERSE_ADDRESS_MISMATCH_SELECTOR: [4]u8 = keccak.selector("ReverseAddressMismatch(string,bytes)");

/// ENSIP-9 coinType for the default (ETH mainnet) address record, used by
/// `addr.reverse` primary-name resolution.
const COIN_TYPE_ETH: u256 = 60;

/// Build the reverse ENS name for an address.
/// For address 0xABCD...1234, returns "abcd...1234.addr.reverse".
/// Caller owns the returned memory.
pub fn reverseNameOf(allocator: std.mem.Allocator, address: Address) ![]u8 {
    const hex_chars = "0123456789abcdef";

    // 40 hex chars + ".addr.reverse" = 40 + 13 = 53 chars
    const result = try allocator.alloc(u8, 40 + REVERSE_SUFFIX.len);
    errdefer allocator.free(result);

    // Convert address bytes to lowercase hex (no 0x prefix)
    for (address, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    // Append ".addr.reverse"
    @memcpy(result[40..], REVERSE_SUFFIX);

    return result;
}

/// Reverse-resolve an address to its verified primary ENS name via the
/// Universal Resolver (coinType 60). The UR checks the forward match
/// on-chain; the returned name is additionally checked against its own
/// ENSIP-15 normalized form.
///
/// Returns null when there is no reverse record, the record is empty, the
/// stored primary name is not ENSIP-15 normalized (ENS treats this as
/// equivalent to no primary name being set), or the UR reports the forward
/// record does not match (`ReverseAddressMismatch`) or a "not found" family
/// revert. Caller owns the returned memory.
pub fn lookupAddress(allocator: std.mem.Allocator, provider: anytype, address: Address) resolver_mod.ResolveError!?[]u8 {
    const calldata = try buildReverseCall(allocator, address);
    defer allocator.free(calldata);

    const response = provider.call(resolver_mod.UNIVERSAL_RESOLVER, calldata) catch |e| {
        // Only a revert carries diagnostics; any other failure (including an
        // allocation failure) must not read a stale `lastError()` from an
        // earlier call.
        if (e == error.OutOfMemory) return error.OutOfMemory;
        if (e == error.RpcError) return mapReverseRevert(provider);
        return error.ProviderError;
    };
    defer allocator.free(response);

    const types = [_]AbiType{ .string, .address, .address };
    const decoded = abi_decode.decodeValues(response, &types, allocator) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
    defer abi_decode.freeValues(decoded, allocator);
    if (decoded.len < 3) return error.InvalidResponse;

    const name = decoded[0].string;
    if (name.len == 0) return null;

    // ENSIP-19: the UR verifies the forward record for the primary name
    // exactly as stored. An unnormalized primary name is invalid -- ENS
    // treats it as no primary name being set -- so do not rewrite it to a
    // name the UR never verified.
    const normalized = try ens_normalize.normalize(allocator, name);
    if (!std.mem.eql(u8, normalized, name)) {
        allocator.free(normalized);
        return null;
    }
    return normalized;
}

/// Build calldata for `reverse(bytes,uint256)`: the 20 raw address bytes
/// being reverse-resolved, and the ENSIP-9 ETH coinType (60).
fn buildReverseCall(allocator: std.mem.Allocator, address: Address) resolver_mod.ResolveError![]u8 {
    const values = [_]AbiValue{
        .{ .bytes = &address },
        .{ .uint256 = COIN_TYPE_ETH },
    };
    return abi_encode.encodeFunctionCall(allocator, REVERSE_SELECTOR, &values) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooManyValues => error.InvalidResponse,
    };
}

/// Inspect the provider's last revert and map it to a reverse-resolution
/// outcome. `ReverseAddressMismatch` maps to null (no verified primary name);
/// everything else defers to `resolver_mod.mapRevert`'s forward "not found"
/// family / `OffchainLookupRequired` / `ProviderError` mapping.
fn mapReverseRevert(provider: anytype) resolver_mod.ResolveError!?[]u8 {
    const info = provider.lastError() orelse return error.ProviderError;
    if (resolver_mod.parseSelector(info.data)) |selector| {
        if (std.mem.eql(u8, &selector, &REVERSE_ADDRESS_MISMATCH_SELECTOR)) return null;
    }
    return resolver_mod.mapRevert(provider);
}

// ============================================================================
// Tests
// ============================================================================

const Provider = @import("../provider.zig").Provider;

/// Minimal `provider: anytype` test double capturing the last call and
/// optionally faking a revert (`fail=true` + `err_data`). Same shape as
/// `resolver.zig`'s `MockProvider`, duplicated locally per Task 9's brief.
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

/// Encode `(string primary, address resolver, address reverseResolver)` as
/// the UR's `reverse(bytes,uint256)` returns it.
fn encodeReverseTuple(allocator: std.mem.Allocator, name: []const u8, resolver_addr: Address, reverse_resolver_addr: Address) ![]u8 {
    const values = [_]AbiValue{ .{ .string = name }, .{ .address = resolver_addr }, .{ .address = reverse_resolver_addr } };
    return abi_encode.encodeValues(allocator, &values);
}

test "REVERSE_SELECTOR matches cast sig output" {
    try std.testing.expectEqualSlices(u8, &.{ 0x5d, 0x78, 0xa2, 0x17 }, &REVERSE_SELECTOR);
}

test "REVERSE_ADDRESS_MISMATCH_SELECTOR matches cast sig output" {
    try std.testing.expectEqualSlices(u8, &.{ 0xef, 0x9c, 0x03, 0xce }, &REVERSE_ADDRESS_MISMATCH_SELECTOR);
}

test "reverseNameOf produces correct format" {
    const allocator = std.testing.allocator;

    // Test with the zero address
    const zero_result = try reverseNameOf(allocator, primitives.ZERO_ADDRESS);
    defer allocator.free(zero_result);
    try std.testing.expectEqualStrings("0000000000000000000000000000000000000000.addr.reverse", zero_result);

    // Test with a known address: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const result = try reverseNameOf(allocator, addr);
    defer allocator.free(result);
    // Should be lowercase hex
    try std.testing.expectEqualStrings("d8da6bf26964af9d7eed9e03e53415d37aa96045.addr.reverse", result);
}

test "reverseNameOf length is always 53" {
    const allocator = std.testing.allocator;
    const addr: Address = @as([20]u8, @splat(0xff));
    const result = try reverseNameOf(allocator, addr);
    defer allocator.free(result);

    // 40 hex chars + 13 suffix chars = 53
    try std.testing.expectEqual(@as(usize, 53), result.len);
    try std.testing.expect(std.mem.endsWith(u8, result, ".addr.reverse"));
}

test "reverseNameOf namehash is deterministic" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    const name1 = try reverseNameOf(allocator, addr);
    defer allocator.free(name1);
    const hash1 = namehash_mod.namehash(name1);

    const name2 = try reverseNameOf(allocator, addr);
    defer allocator.free(name2);
    const hash2 = namehash_mod.namehash(name2);

    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "reverse name and forward namehash are different" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    const reverse_name = try reverseNameOf(allocator, addr);
    defer allocator.free(reverse_name);

    const reverse_hash = namehash_mod.namehash(reverse_name);
    const forward_hash = namehash_mod.namehash("vitalik.eth");

    // The reverse hash and forward hash must be different
    try std.testing.expect(!std.mem.eql(u8, &reverse_hash, &forward_hash));
}

test "lookupAddress builds reverse(bytes,uint256) calldata" {
    const allocator = std.testing.allocator;
    var mock = MockProvider{ .allocator = allocator };
    defer mock.deinit();

    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    // Response is empty -> decode fails after the call, but calldata is captured.
    _ = lookupAddress(allocator, &mock, addr) catch {};

    const cd = mock.captured_data;
    // 4 (selector) + 32 (bytes-arg offset) + 32 (coinType) + 32 (bytes len) + 32 (bytes padded) = 132.
    try std.testing.expectEqual(@as(usize, 132), cd.len);
    try std.testing.expectEqualSlices(u8, &resolver_mod.UNIVERSAL_RESOLVER, &mock.captured_to);
    try std.testing.expectEqualSlices(u8, &REVERSE_SELECTOR, cd[0..4]);
    // Head: offset to the `bytes` arg tail = 0x40 (two head slots).
    try std.testing.expectEqual(@as(u8, 0x40), cd[35]);
    // Head: coinType = 60.
    try std.testing.expectEqual(@as(u8, 60), cd[67]);
    // Tail: bytes length = 20, then the raw address bytes, right-padded to 32.
    try std.testing.expectEqual(@as(u8, 20), cd[99]);
    try std.testing.expectEqualSlices(u8, &addr, cd[100..120]);
    try std.testing.expect(std.mem.allEqual(u8, cd[120..132], 0));
}

test "lookupAddress decodes verified name from UR tuple" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const resolver_addr: Address = @splat(0x22);

    const response = try encodeReverseTuple(allocator, "vitalik.eth", addr, resolver_addr);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    const got = (try lookupAddress(allocator, &mock, addr)).?;
    defer allocator.free(got);
    try std.testing.expectEqualStrings("vitalik.eth", got);
}

test "lookupAddress rejects an unnormalized stored primary name" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const resolver_addr: Address = @splat(0x22);

    // The stored primary name is not ENSIP-15 normalized ("Vitalik.ETH" !=
    // normalize("Vitalik.ETH") == "vitalik.eth"). ENS treats this as no
    // primary name being set: the UR verified the forward record for
    // "Vitalik.ETH" exactly as stored, never for the lowercased form, so it
    // must not be rewritten and returned as if it were verified.
    const response = try encodeReverseTuple(allocator, "Vitalik.ETH", resolver_addr, resolver_addr);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try lookupAddress(allocator, &mock, addr));
}

test "lookupAddress returns an already-normalized stored primary name unchanged" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const resolver_addr: Address = @splat(0x22);

    // The stored primary name is already ENSIP-15 normalized, so it is
    // returned as-is (it IS the verified stored name, not a rewrite).
    const response = try encodeReverseTuple(allocator, "vitalik.eth", resolver_addr, resolver_addr);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    const got = (try lookupAddress(allocator, &mock, addr)).?;
    defer allocator.free(got);
    try std.testing.expectEqualStrings("vitalik.eth", got);
}

test "lookupAddress returns null for empty name" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const resolver_addr: Address = @splat(0x22);

    const response = try encodeReverseTuple(allocator, "", addr, resolver_addr);
    defer allocator.free(response);

    var mock = MockProvider{ .allocator = allocator, .response = response };
    defer mock.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try lookupAddress(allocator, &mock, addr));
}

test "lookupAddress maps ReverseAddressMismatch revert to null" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0xef9c03ce" };
    defer mock.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try lookupAddress(allocator, &mock, addr));
}

test "lookupAddress maps ResolverNotFound revert to null" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0x77209fe8" };
    defer mock.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try lookupAddress(allocator, &mock, addr));
}

test "lookupAddress maps OffchainLookup revert to error" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0x556f1830deadbeef" };
    defer mock.deinit();

    try std.testing.expectError(error.OffchainLookupRequired, lookupAddress(allocator, &mock, addr));
}

test "lookupAddress maps unknown revert to ProviderError" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    var mock = MockProvider{ .allocator = allocator, .fail = true, .err_data = "0xdeadbeef" };
    defer mock.deinit();

    try std.testing.expectError(error.ProviderError, lookupAddress(allocator, &mock, addr));
}
