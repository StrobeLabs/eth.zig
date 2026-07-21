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

/// ENS Universal Resolver (mainnet / testnets proxy).
/// 0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe
/// Canonical entrypoint for forward resolution (ENSIP-10).
pub const UNIVERSAL_RESOLVER: Address = .{
    0xeE, 0xeE, 0xEE, 0xeE, 0x14, 0xD7, 0x18, 0xC2, 0xB4, 0x7D,
    0x99, 0x23, 0xDe, 0xab, 0x13, 0x35, 0xE1, 0x44, 0xEe, 0xEe,
};

/// Function selector for addr(bytes32): 0x3b3b57de
const ADDR_SELECTOR: [4]u8 = keccak.selector("addr(bytes32)");

/// Function selector for text(bytes32,string): 0x59d1d43c
const TEXT_SELECTOR: [4]u8 = keccak.selector("text(bytes32,string)");

/// Function selector for resolve(bytes,bytes) on the Universal Resolver.
const RESOLVE_SELECTOR: [4]u8 = keccak.selector("resolve(bytes,bytes)");

/// Errors that can occur during ENS resolution.
pub const ResolveError = error{
    /// The ABI-encoded response was too short or malformed.
    InvalidResponse,
    /// No resolver is set for this name.
    NoResolver,
    /// A DNS label exceeded 63 bytes.
    LabelTooLong,
    /// Memory allocation failure.
    OutOfMemory,
    /// The provider call failed.
    ProviderError,
};

/// Resolve an ENS name to an Ethereum address via the Universal Resolver.
///
/// Calls `resolve(bytes name, bytes data)` on the Universal Resolver with
/// DNS-encoded `name` and an `addr(bytes32)` calldata payload (ENSIP-10).
/// This is the ENSv2-ready path: names like `ur.integration-tests.eth`
/// resolve to `0x2222…2222` here, whereas the legacy registry/`addr` path
/// returns `0x1111…1111`.
///
/// Returns null if the name resolves to the zero address.
/// Does not yet follow EIP-3668 OffchainLookup reverts.
pub fn resolve(allocator: std.mem.Allocator, provider: anytype, name: []const u8) !?Address {
    const node = namehash_mod.namehash(name);

    const addr_calldata = try buildAddrCalldata(allocator, node);
    defer allocator.free(addr_calldata);

    const result_bytes = try callUniversalResolve(allocator, provider, name, addr_calldata);
    defer allocator.free(result_bytes);

    if (result_bytes.len < 32) return ResolveError.InvalidResponse;

    const addr_types = [_]AbiType{.address};
    const addr_decoded = abi_decode.decodeValues(result_bytes, &addr_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(addr_decoded, allocator);

    if (addr_decoded.len < 1) return ResolveError.InvalidResponse;

    const addr = addr_decoded[0].address;
    if (std.mem.eql(u8, &addr, &primitives.ZERO_ADDRESS)) return null;

    return addr;
}

/// Look up a text record for an ENS name via the Universal Resolver.
///
/// Calls `resolve(bytes name, bytes data)` with a `text(bytes32,string)`
/// payload (ENSIP-10). Returns null if the text record is empty.
/// Caller owns the returned memory.
/// Does not yet follow EIP-3668 OffchainLookup reverts.
pub fn getText(allocator: std.mem.Allocator, provider: anytype, name: []const u8, key: []const u8) !?[]u8 {
    const node = namehash_mod.namehash(name);

    const text_calldata = try buildTextCalldata(allocator, node, key);
    defer allocator.free(text_calldata);

    const result_bytes = try callUniversalResolve(allocator, provider, name, text_calldata);
    defer allocator.free(result_bytes);

    if (result_bytes.len < 64) return ResolveError.InvalidResponse;

    const result_types = [_]AbiType{.string};
    const decoded = abi_decode.decodeValues(result_bytes, &result_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ResolveError.InvalidResponse;

    const text = decoded[0].string;
    if (text.len == 0) return null;

    const result = try allocator.alloc(u8, text.len);
    @memcpy(result, text);
    return result;
}

/// Call Universal Resolver `resolve(bytes,bytes)` and return the inner `bytes` result.
/// Caller owns the returned memory.
fn callUniversalResolve(
    allocator: std.mem.Allocator,
    provider: anytype,
    name: []const u8,
    data: []const u8,
) ![]u8 {
    const dns_name = namehash_mod.dnsEncode(allocator, name) catch |err| switch (err) {
        error.LabelTooLong => return ResolveError.LabelTooLong,
        error.OutOfMemory => return ResolveError.OutOfMemory,
    };
    defer allocator.free(dns_name);

    const resolve_calldata = try buildResolveCalldata(allocator, dns_name, data);
    defer allocator.free(resolve_calldata);

    const response = provider.call(UNIVERSAL_RESOLVER, resolve_calldata) catch return ResolveError.ProviderError;
    defer allocator.free(response);

    // resolve(bytes,bytes) returns (bytes data, address resolver)
    const result_types = [_]AbiType{ .bytes, .address };
    const decoded = abi_decode.decodeValues(response, &result_types, allocator) catch
        return ResolveError.InvalidResponse;
    defer abi_decode.freeValues(decoded, allocator);

    if (decoded.len < 1) return ResolveError.InvalidResponse;

    const result_bytes = decoded[0].bytes;
    const copy = try allocator.alloc(u8, result_bytes.len);
    @memcpy(copy, result_bytes);
    return copy;
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

/// Build the ABI-encoded calldata for Universal Resolver resolve(bytes name, bytes data).
fn buildResolveCalldata(allocator: std.mem.Allocator, dns_name: []const u8, data: []const u8) ![]u8 {
    const values = [_]AbiValue{
        .{ .bytes = dns_name },
        .{ .bytes = data },
    };
    return abi_encode.encodeFunctionCall(allocator, RESOLVE_SELECTOR, &values);
}

// ============================================================================
// Tests
// ============================================================================

test "UNIVERSAL_RESOLVER address is correct" {
    const expected = try hex_mod.hexToBytesFixed(20, "eEeEEEeE14D718C2B47D9923Deab1335E144EeEe");
    try std.testing.expectEqualSlices(u8, &expected, &UNIVERSAL_RESOLVER);
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

test "resolve selector is correct" {
    // keccak256("resolve(bytes,bytes)")[0:4] = 0x9061b923
    const expected = [_]u8{ 0x90, 0x61, 0xb9, 0x23 };
    try std.testing.expectEqualSlices(u8, &expected, &RESOLVE_SELECTOR);
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

test "buildResolveCalldata encodes correctly" {
    const allocator = std.testing.allocator;
    const dns_name = try namehash_mod.dnsEncode(allocator, "foo.eth");
    defer allocator.free(dns_name);
    const node = namehash_mod.namehash("foo.eth");
    const addr_data = try buildAddrCalldata(allocator, node);
    defer allocator.free(addr_data);

    const calldata = try buildResolveCalldata(allocator, dns_name, addr_data);
    defer allocator.free(calldata);

    try std.testing.expectEqualSlices(u8, &RESOLVE_SELECTOR, calldata[0..4]);
    // Two dynamic bytes args: head is 2 offsets (64 bytes) after selector
    try std.testing.expect(calldata.len > 4 + 64);
}

const http_transport_mod = @import("../http_transport.zig");
const provider_mod = @import("../provider.zig");
const runtime_mod = @import("../runtime.zig");

const MAINNET_RPC_URL = "https://ethereum-rpc.publicnode.com";

test "resolve ur.integration-tests.eth on mainnet via Universal Resolver" {
    const allocator = std.testing.allocator;

    var transport = http_transport_mod.HttpTransport.init(allocator, MAINNET_RPC_URL, runtime_mod.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    // ENSv2 readiness sentinel: Universal Resolver returns 0x2222…2222;
    // the legacy registry/addr path returns 0x1111…1111.
    const addr = resolve(allocator, &provider, "ur.integration-tests.eth") catch |err| {
        if (err == ResolveError.ProviderError) return;
        return err;
    };

    const expected = try hex_mod.hexToBytesFixed(20, "2222222222222222222222222222222222222222");
    try std.testing.expect(addr != null);
    try std.testing.expectEqualSlices(u8, &expected, &addr.?);
}

test "getText ur.integration-tests.eth description on mainnet via Universal Resolver" {
    const allocator = std.testing.allocator;

    var transport = http_transport_mod.HttpTransport.init(allocator, MAINNET_RPC_URL, runtime_mod.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    const text = getText(allocator, &provider, "ur.integration-tests.eth", "description") catch |err| {
        if (err == ResolveError.ProviderError) return;
        return err;
    };
    defer if (text) |t| allocator.free(t);

    try std.testing.expect(text != null);
    try std.testing.expectEqualStrings("✅️ Universal Resolver", text.?);
}
