const std = @import("std");
const keccak = @import("../keccak.zig");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");
const abi_encode = @import("../abi_encode.zig");
const abi_decode = @import("../abi_decode.zig");
const abi_types = @import("../abi_types.zig");
const namehash_mod = @import("namehash.zig");
const resolver_mod = @import("resolver.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Address = primitives.Address;

/// Function selector for name(bytes32): 0x691f3431
const NAME_SELECTOR: [4]u8 = keccak.selector("name(bytes32)");

/// The suffix used for reverse resolution.
const REVERSE_SUFFIX = ".addr.reverse";

/// Errors that can occur during reverse resolution.
pub const ReverseResolveError = error{
    /// The ABI-encoded response was too short or malformed.
    InvalidResponse,
    /// No resolver is set for the reverse record.
    NoResolver,
    /// Memory allocation failure.
    OutOfMemory,
    /// The provider call failed.
    ProviderError,
};

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

/// Look up the ENS name for an Ethereum address (reverse resolution).
///
/// Performs the following steps:
/// 1. Builds the reverse name: lowercase_hex(address) + ".addr.reverse"
/// 2. Computes the namehash of the reverse name
/// 3. Gets the resolver from the ENS registry
/// 4. Calls name(bytes32 node) on the resolver
///
/// Returns null if there is no reverse record set.
/// Caller owns the returned memory.
pub fn lookupAddress(allocator: std.mem.Allocator, provider: anytype, address: Address) !?[]u8 {
    // Step 1: Build the reverse name.
    const reverse_name = try reverseNameOf(allocator, address);
    defer allocator.free(reverse_name);

    // Step 2: Compute the namehash of the reverse name.
    const node = namehash_mod.namehash(reverse_name);

    // Step 3: Get the resolver address from the ENS registry.
    const resolver_calldata = try buildResolverCalldata(allocator, node);
    defer allocator.free(resolver_calldata);

    const resolver_response = provider.call(resolver_mod.ENS_REGISTRY, resolver_calldata) catch
        return ReverseResolveError.ProviderError;
    defer allocator.free(resolver_response);

    if (resolver_response.len < 32) return ReverseResolveError.InvalidResponse;

    const resolver_types = [_]AbiType{.address};
    const resolver_decoded = abi_decode.decodeValues(resolver_response, &resolver_types, allocator) catch
        return ReverseResolveError.InvalidResponse;
    defer abi_decode.freeValues(resolver_decoded, allocator);

    if (resolver_decoded.len < 1) return ReverseResolveError.InvalidResponse;

    const resolver_addr = resolver_decoded[0].address;

    // No resolver set.
    if (std.mem.eql(u8, &resolver_addr, &primitives.ZERO_ADDRESS)) return null;

    // Step 4: Call name(bytes32 node) on the resolver.
    const name_calldata = try buildNameCalldata(allocator, node);
    defer allocator.free(name_calldata);

    const name_response = provider.call(resolver_addr, name_calldata) catch
        return ReverseResolveError.ProviderError;
    defer allocator.free(name_response);

    if (name_response.len < 64) return ReverseResolveError.InvalidResponse;

    // Decode the string from the response.
    const name_types = [_]AbiType{.string};
    const name_decoded = abi_decode.decodeValues(name_response, &name_types, allocator) catch
        return ReverseResolveError.InvalidResponse;
    defer abi_decode.freeValues(name_decoded, allocator);

    if (name_decoded.len < 1) return ReverseResolveError.InvalidResponse;

    const name_str = name_decoded[0].string;

    // Return null if the name is empty.
    if (name_str.len == 0) return null;

    // Copy the string since we are freeing the decoded values.
    const result = try allocator.alloc(u8, name_str.len);
    @memcpy(result, name_str);
    return result;
}

/// Build the ABI-encoded calldata for resolver(bytes32 node).
fn buildResolverCalldata(allocator: std.mem.Allocator, node: [32]u8) ![]u8 {
    const resolver_selector: [4]u8 = keccak.selector("resolver(bytes32)");
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);

    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    return abi_encode.encodeFunctionCall(allocator, resolver_selector, &values);
}

/// Build the ABI-encoded calldata for name(bytes32 node).
fn buildNameCalldata(allocator: std.mem.Allocator, node: [32]u8) ![]u8 {
    var fb = AbiValue.FixedBytes{ .len = 32 };
    @memcpy(&fb.data, &node);

    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    return abi_encode.encodeFunctionCall(allocator, NAME_SELECTOR, &values);
}

// ============================================================================
// Tests
// ============================================================================

test "name selector is correct" {
    // keccak256("name(bytes32)")[0:4] = 0x691f3431
    const expected = [_]u8{ 0x69, 0x1f, 0x34, 0x31 };
    try std.testing.expectEqualSlices(u8, &expected, &NAME_SELECTOR);
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

test "buildNameCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const node = namehash_mod.namehash("vitalik.eth");
    const calldata = try buildNameCalldata(allocator, node);
    defer allocator.free(calldata);

    // Should be 4 (selector) + 32 (bytes32 node) = 36 bytes
    try std.testing.expectEqual(@as(usize, 36), calldata.len);

    // First 4 bytes are the name selector
    try std.testing.expectEqualSlices(u8, &NAME_SELECTOR, calldata[0..4]);

    // Next 32 bytes are the node hash
    try std.testing.expectEqualSlices(u8, &node, calldata[4..36]);
}

test "buildResolverCalldata for reverse name" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    const reverse_name = try reverseNameOf(allocator, addr);
    defer allocator.free(reverse_name);

    const node = namehash_mod.namehash(reverse_name);
    const calldata = try buildResolverCalldata(allocator, node);
    defer allocator.free(calldata);

    // Should be 4 (selector) + 32 (bytes32 node) = 36 bytes
    try std.testing.expectEqual(@as(usize, 36), calldata.len);

    // Verify the resolver selector
    const resolver_selector: [4]u8 = keccak.selector("resolver(bytes32)");
    try std.testing.expectEqualSlices(u8, &resolver_selector, calldata[0..4]);
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
