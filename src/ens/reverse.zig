const std = @import("std");
const keccak = @import("../keccak.zig");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");
const abi_encode = @import("../abi_encode.zig");
const abi_decode = @import("../abi_decode.zig");
const abi_types = @import("../abi_types.zig");
const resolver_mod = @import("resolver.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Address = primitives.Address;

/// Function selector for Universal Resolver reverse(bytes,uint256).
const REVERSE_SELECTOR: [4]u8 = keccak.selector("reverse(bytes,uint256)");

/// SLIP-44 coin type for Ethereum (used by Universal Resolver reverse).
const COIN_TYPE_ETH: u256 = 60;

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

/// Look up the ENS name for an Ethereum address via the Universal Resolver.
///
/// Calls `reverse(bytes lookupAddress, uint256 coinType)` on the Universal
/// Resolver with coin type 60 (ETH). The UR verifies that the primary name
/// forward-resolves back to the address.
///
/// Returns null if there is no primary name set.
/// Caller owns the returned memory.
/// Does not yet follow EIP-3668 OffchainLookup reverts.
pub fn lookupAddress(allocator: std.mem.Allocator, provider: anytype, address: Address) !?[]u8 {
    const calldata = try buildReverseCalldata(allocator, address);
    defer allocator.free(calldata);

    const response = provider.call(resolver_mod.UNIVERSAL_RESOLVER, calldata) catch
        return ReverseResolveError.ProviderError;
    defer allocator.free(response);

    // reverse(bytes,uint256) returns (string primary, address resolver, address reverseResolver)
    const result_types = [_]AbiType{ .string, .address, .address };
    const decoded = abi_decode.decodeValues(response, &result_types, allocator) catch
        return ReverseResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ReverseResolveError.InvalidResponse;

    const name_str = decoded[0].string;
    if (name_str.len == 0) return null;

    const result = try allocator.alloc(u8, name_str.len);
    @memcpy(result, name_str);
    return result;
}

/// Build calldata for Universal Resolver reverse(bytes lookupAddress, uint256 coinType).
fn buildReverseCalldata(allocator: std.mem.Allocator, address: Address) ![]u8 {
    const values = [_]AbiValue{
        .{ .bytes = &address },
        .{ .uint256 = COIN_TYPE_ETH },
    };
    return abi_encode.encodeFunctionCall(allocator, REVERSE_SELECTOR, &values);
}

// ============================================================================
// Tests
// ============================================================================

test "reverse selector is correct" {
    // keccak256("reverse(bytes,uint256)")[0:4] = 0x5d78a217
    const expected = [_]u8{ 0x5d, 0x78, 0xa2, 0x17 };
    try std.testing.expectEqualSlices(u8, &expected, &REVERSE_SELECTOR);
}

test "buildReverseCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const addr = try hex_mod.hexToBytesFixed(20, "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const calldata = try buildReverseCalldata(allocator, addr);
    defer allocator.free(calldata);

    try std.testing.expectEqualSlices(u8, &REVERSE_SELECTOR, calldata[0..4]);
    // selector + 2 head words (offset, coinType) + bytes length/data
    try std.testing.expect(calldata.len > 4 + 64);
    // coin type 60 in the second head word
    try std.testing.expectEqual(@as(u8, 60), calldata[4 + 63]);
}

const http_transport_mod = @import("../http_transport.zig");
const provider_mod = @import("../provider.zig");
const runtime_mod = @import("../runtime.zig");

test "lookupAddress devrel.enslabs.eth on mainnet via Universal Resolver" {
    const allocator = std.testing.allocator;

    var transport = http_transport_mod.HttpTransport.init(allocator, resolver_mod.mainnetTestRpcUrl(), runtime_mod.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    const addr = try hex_mod.hexToBytesFixed(20, "0xeE9eeaAB0Bb7D9B969D701f6f8212609EDeA252E");
    const name = lookupAddress(allocator, &provider, addr) catch |err| {
        if (err == ReverseResolveError.ProviderError) return;
        return err;
    };
    defer if (name) |n| allocator.free(n);

    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("devrel.enslabs.eth", name.?);
}
