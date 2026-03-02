const std = @import("std");
const keccak = @import("../keccak.zig");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");
const abi_encode = @import("../abi_encode.zig");
const abi_decode = @import("../abi_decode.zig");
const abi_types = @import("../abi_types.zig");
const namehash_mod = @import("namehash.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Address = primitives.Address;

/// ENS Registry contract address on Ethereum mainnet.
/// 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
pub const ENS_REGISTRY: Address = .{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x2E, 0x07, 0x4e, 0xC6,
    0x9A, 0x0D, 0xFb, 0x29, 0x97, 0xBA, 0x6C, 0x7d, 0x2e, 0x1e,
};

/// Function selector for resolver(bytes32): 0x0178b8bf
const RESOLVER_SELECTOR: [4]u8 = keccak.selector("resolver(bytes32)");

/// Function selector for addr(bytes32): 0x3b3b57de
const ADDR_SELECTOR: [4]u8 = keccak.selector("addr(bytes32)");

/// Function selector for text(bytes32,string): 0x59d1d43c
const TEXT_SELECTOR: [4]u8 = keccak.selector("text(bytes32,string)");

/// Errors that can occur during ENS resolution.
pub const ResolveError = error{
    /// The ABI-encoded response was too short or malformed.
    InvalidResponse,
    /// No resolver is set for this name.
    NoResolver,
    /// Memory allocation failure.
    OutOfMemory,
    /// The provider call failed.
    ProviderError,
};

/// Resolve an ENS name to an Ethereum address.
///
/// Performs two on-chain lookups:
/// 1. Calls the ENS registry to get the resolver address for the name.
/// 2. Calls the resolver's addr(bytes32) function to get the address.
///
/// Returns null if the name has no resolver or resolves to the zero address.
pub fn resolve(allocator: std.mem.Allocator, provider: anytype, name: []const u8) !?Address {
    const node = namehash_mod.namehash(name);

    // Step 1: Get the resolver address from the ENS registry.
    const resolver_addr = try getResolver(allocator, provider, node) orelse return null;

    // Step 2: Call addr(bytes32) on the resolver.
    const addr_calldata = try buildAddrCalldata(allocator, node);
    defer allocator.free(addr_calldata);

    const addr_response = provider.call(resolver_addr, addr_calldata) catch return ResolveError.ProviderError;
    defer allocator.free(addr_response);

    if (addr_response.len < 32) return ResolveError.InvalidResponse;

    // Decode the address from the response (address is in bytes 12..32 of the first word).
    const result_types = [_]AbiType{.address};
    const decoded = abi_decode.decodeValues(addr_response, &result_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ResolveError.InvalidResponse;

    const addr = decoded[0].address;

    // Return null if the resolved address is the zero address.
    if (std.mem.eql(u8, &addr, &primitives.ZERO_ADDRESS)) return null;

    return addr;
}

/// Look up a text record for an ENS name.
///
/// Calls text(bytes32,string) on the name's resolver.
/// Returns null if there is no resolver or the text record is empty.
/// Caller owns the returned memory.
pub fn getText(allocator: std.mem.Allocator, provider: anytype, name: []const u8, key: []const u8) !?[]u8 {
    const node = namehash_mod.namehash(name);

    // Step 1: Get the resolver address from the ENS registry.
    const resolver_addr = try getResolver(allocator, provider, node) orelse return null;

    // Step 2: Call text(bytes32,string) on the resolver.
    const text_calldata = try buildTextCalldata(allocator, node, key);
    defer allocator.free(text_calldata);

    const text_response = provider.call(resolver_addr, text_calldata) catch return ResolveError.ProviderError;
    defer allocator.free(text_response);

    if (text_response.len < 64) return ResolveError.InvalidResponse;

    // Decode the string from the response.
    const result_types = [_]AbiType{.string};
    const decoded = abi_decode.decodeValues(text_response, &result_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ResolveError.InvalidResponse;

    const text = decoded[0].string;

    // Return null if the text record is empty.
    if (text.len == 0) return null;

    // Copy the string since we are freeing the decoded values.
    const result = try allocator.alloc(u8, text.len);
    @memcpy(result, text);
    return result;
}

/// Get the resolver address for a given node from the ENS registry.
/// Returns null if the resolver is the zero address.
fn getResolver(allocator: std.mem.Allocator, provider: anytype, node: [32]u8) !?Address {
    const resolver_calldata = try buildResolverCalldata(allocator, node);
    defer allocator.free(resolver_calldata);

    const resolver_response = provider.call(ENS_REGISTRY, resolver_calldata) catch return ResolveError.ProviderError;
    defer allocator.free(resolver_response);

    if (resolver_response.len < 32) return ResolveError.InvalidResponse;

    // Decode the address from the response.
    const result_types = [_]AbiType{.address};
    const decoded = abi_decode.decodeValues(resolver_response, &result_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ResolveError.InvalidResponse;

    const resolver_addr = decoded[0].address;

    // Return null if the resolver address is zero (no resolver set).
    if (std.mem.eql(u8, &resolver_addr, &primitives.ZERO_ADDRESS)) return null;

    return resolver_addr;
}

/// Build the ABI-encoded calldata for resolver(bytes32 node).
fn buildResolverCalldata(allocator: std.mem.Allocator, node: [32]u8) ![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);

    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    return abi_encode.encodeFunctionCall(allocator, RESOLVER_SELECTOR, &values);
}

/// Build the ABI-encoded calldata for addr(bytes32 node).
fn buildAddrCalldata(allocator: std.mem.Allocator, node: [32]u8) ![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);

    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    return abi_encode.encodeFunctionCall(allocator, ADDR_SELECTOR, &values);
}

/// Build the ABI-encoded calldata for text(bytes32 node, string key).
fn buildTextCalldata(allocator: std.mem.Allocator, node: [32]u8, key: []const u8) ![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);

    const values = [_]AbiValue{
        .{ .fixed_bytes = fb },
        .{ .string = key },
    };
    return abi_encode.encodeFunctionCall(allocator, TEXT_SELECTOR, &values);
}

// ============================================================================
// Tests
// ============================================================================

test "ENS_REGISTRY address is correct" {
    const expected = try hex_mod.hexToBytesFixed(20, "00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    try std.testing.expectEqualSlices(u8, &expected, &ENS_REGISTRY);
}

test "resolver selector is correct" {
    // keccak256("resolver(bytes32)")[0:4] = 0x0178b8bf
    const expected = [_]u8{ 0x01, 0x78, 0xb8, 0xbf };
    try std.testing.expectEqualSlices(u8, &expected, &RESOLVER_SELECTOR);
}

test "addr selector is correct" {
    // keccak256("addr(bytes32)")[0:4] = 0x3b3b57de
    const expected = [_]u8{ 0x3b, 0x3b, 0x57, 0xde };
    try std.testing.expectEqualSlices(u8, &expected, &ADDR_SELECTOR);
}

test "text selector is correct" {
    // keccak256("text(bytes32,string)")[0:4] = 0x59d1d43c
    const expected = [_]u8{ 0x59, 0xd1, 0xd4, 0x3c };
    try std.testing.expectEqualSlices(u8, &expected, &TEXT_SELECTOR);
}

test "buildResolverCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const node = namehash_mod.namehash("vitalik.eth");
    const calldata = try buildResolverCalldata(allocator, node);
    defer allocator.free(calldata);

    // Should be 4 (selector) + 32 (bytes32 node) = 36 bytes
    try std.testing.expectEqual(@as(usize, 36), calldata.len);

    // First 4 bytes are the resolver selector
    try std.testing.expectEqualSlices(u8, &RESOLVER_SELECTOR, calldata[0..4]);

    // Next 32 bytes are the node hash
    try std.testing.expectEqualSlices(u8, &node, calldata[4..36]);
}

test "buildAddrCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const node = namehash_mod.namehash("vitalik.eth");
    const calldata = try buildAddrCalldata(allocator, node);
    defer allocator.free(calldata);

    // Should be 4 (selector) + 32 (bytes32 node) = 36 bytes
    try std.testing.expectEqual(@as(usize, 36), calldata.len);

    // First 4 bytes are the addr selector
    try std.testing.expectEqualSlices(u8, &ADDR_SELECTOR, calldata[0..4]);

    // Next 32 bytes are the node hash
    try std.testing.expectEqualSlices(u8, &node, calldata[4..36]);
}

test "buildTextCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const node = namehash_mod.namehash("vitalik.eth");
    const calldata = try buildTextCalldata(allocator, node, "url");
    defer allocator.free(calldata);

    // Should be: 4 (selector) + 32 (bytes32 node) + 32 (offset to string) + 32 (string length) + 32 (padded "url")
    // = 4 + 32 + 32 + 32 + 32 = 132 bytes
    try std.testing.expectEqual(@as(usize, 132), calldata.len);

    // First 4 bytes are the text selector
    try std.testing.expectEqualSlices(u8, &TEXT_SELECTOR, calldata[0..4]);

    // Bytes 4..36 are the node hash
    try std.testing.expectEqualSlices(u8, &node, calldata[4..36]);

    // Bytes 36..68: offset to string data = 64 (0x40) since there are 2 head slots
    try std.testing.expectEqual(@as(u8, 0x40), calldata[67]);

    // Bytes 68..100: string length = 3
    try std.testing.expectEqual(@as(u8, 3), calldata[99]);

    // Bytes 100..103: "url"
    try std.testing.expectEqualSlices(u8, "url", calldata[100..103]);
}

test "buildTextCalldata with longer key" {
    const allocator = std.testing.allocator;
    const node = namehash_mod.namehash("nick.eth");
    const calldata = try buildTextCalldata(allocator, node, "com.twitter");
    defer allocator.free(calldata);

    // 4 + 32 + 32 + 32 + 32 = 132 bytes (string "com.twitter" is 11 bytes, fits in one 32-byte word)
    try std.testing.expectEqual(@as(usize, 132), calldata.len);

    // Selector
    try std.testing.expectEqualSlices(u8, &TEXT_SELECTOR, calldata[0..4]);

    // String length = 11
    try std.testing.expectEqual(@as(u8, 11), calldata[99]);

    // String content
    try std.testing.expectEqualSlices(u8, "com.twitter", calldata[100..111]);
}
