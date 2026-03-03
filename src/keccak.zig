const std = @import("std");

/// XKCP-accelerated backend for runtime hashing.
const xkcp = @import("keccak_xkcp.zig");

/// Zig stdlib Keccak-256 (used for comptime evaluation where C FFI is unavailable).
const StdlibKeccak256 = std.crypto.hash.sha3.Keccak256;

/// 32-byte hash output type.
pub const Hash = [32]u8;

/// For API compatibility: expose the stdlib type for code that uses the hasher directly.
pub const Keccak256 = StdlibKeccak256;

/// Compute the Keccak-256 hash of the given data.
/// Works at both comptime and runtime.
pub fn hash(data: []const u8) Hash {
    if (@inComptime()) {
        @setEvalBranchQuota(10000);
        var result: Hash = undefined;
        StdlibKeccak256.hash(data, &result, .{});
        return result;
    }
    return xkcp.hash(data);
}

/// Compute the Keccak-256 hash of multiple concatenated slices.
pub fn hashConcat(slices: []const []const u8) Hash {
    var hasher = xkcp.Hasher.init();
    for (slices) |slice| {
        hasher.update(slice);
    }
    return hasher.final();
}

/// Compute the first 4 bytes of the Keccak-256 hash (function selector).
pub fn selector(signature: []const u8) [4]u8 {
    const h = hash(signature);
    return h[0..4].*;
}

// Tests
test "keccak256 empty" {
    const result = hash("");
    const hex = @import("hex.zig");
    const expected = try hex.hexToBytesFixed(32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "keccak256 hello world" {
    // keccak256("Hello, World!") - well-known test vector
    const result = hash("Hello, World!");
    const hex = @import("hex.zig");
    const expected = try hex.hexToBytesFixed(32, "acaf3289d7b601cbd114fb36c4d29c85bbfd5e133f14cb355c3fd8d99367964f");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "keccak256 transfer selector" {
    // transfer(address,uint256) selector = 0xa9059cbb
    const sel = selector("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &sel);
}

test "keccak256 hashConcat" {
    const a = hash("HelloWorld");
    const b = hashConcat(&.{ "Hello", "World" });
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "comptime hash equals runtime hash" {
    const comptime_result = comptime hash("test");
    const runtime_result = hash("test");
    try std.testing.expectEqualSlices(u8, &comptime_result, &runtime_result);
}

test "keccak256 abc" {
    const result = hash("abc");
    const hex = @import("hex.zig");
    const expected = try hex.hexToBytesFixed(32, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "keccak256 testing" {
    const result = hash("testing");
    const hex = @import("hex.zig");
    const expected = try hex.hexToBytesFixed(32, "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "keccak256 256 zero bytes" {
    const zero_bytes = [_]u8{0} ** 256;
    const result1 = hash(&zero_bytes);
    const result2 = hash(&zero_bytes);
    // Verify 32-byte output
    try std.testing.expectEqual(@as(usize, 32), result1.len);
    // Verify determinism
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "keccak256 4KB input" {
    const big_input = [_]u8{0x42} ** 4096;
    const result1 = hash(&big_input);
    const result2 = hash(&big_input);
    // Verify determinism
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "keccak256 is not SHA3-256" {
    const hex = @import("hex.zig");
    const result = hash("");
    // Keccak-256 of empty string
    const keccak_expected = try hex.hexToBytesFixed(32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try std.testing.expectEqualSlices(u8, &keccak_expected, &result);
    // SHA3-256 of empty string (must NOT match)
    const sha3_expected = try hex.hexToBytesFixed(32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    try std.testing.expect(!std.mem.eql(u8, &sha3_expected, &result));
}

test "DeFi function selectors" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x09, 0x5e, 0xa7, 0xb3 }, &selector("approve(address,uint256)"));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x23, 0xb8, 0x72, 0xdd }, &selector("transferFrom(address,address,uint256)"));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x18, 0x16, 0x0d, 0xdd }, &selector("totalSupply()"));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x31, 0x3c, 0xe5, 0x67 }, &selector("decimals()"));
}
