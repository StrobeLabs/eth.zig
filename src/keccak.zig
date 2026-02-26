const std = @import("std");

/// Ethereum-compatible Keccak-256 hash (0x01 padding, NOT SHA3's 0x06).
/// Zig's stdlib provides this as a distinct type from Sha3_256.
pub const Keccak256 = std.crypto.hash.sha3.Keccak256;

/// 32-byte hash output type.
pub const Hash = [32]u8;

/// Compute the Keccak-256 hash of the given data.
pub fn hash(data: []const u8) Hash {
    var result: Hash = undefined;
    Keccak256.hash(data, &result, .{});
    return result;
}

/// Compute Keccak-256 hash at comptime.
pub fn comptimeHash(comptime data: []const u8) Hash {
    comptime {
        @setEvalBranchQuota(10000);
        var result: Hash = undefined;
        Keccak256.hash(data, &result, .{});
        return result;
    }
}

/// Compute the Keccak-256 hash of multiple concatenated slices.
pub fn hashConcat(slices: []const []const u8) Hash {
    var hasher = Keccak256.init(.{});
    for (slices) |slice| {
        hasher.update(slice);
    }
    var result: Hash = undefined;
    hasher.final(&result);
    return result;
}

/// Compute the first 4 bytes of the Keccak-256 hash (function selector).
pub fn selector(signature: []const u8) [4]u8 {
    const h = hash(signature);
    return h[0..4].*;
}

/// Compute function selector at comptime.
pub fn comptimeSelector(comptime signature: []const u8) [4]u8 {
    comptime {
        const h = comptimeHash(signature);
        return h[0..4].*;
    }
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
    const sel = comptimeSelector("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &sel);
}

test "keccak256 hashConcat" {
    const a = hash("HelloWorld");
    const b = hashConcat(&.{ "Hello", "World" });
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "comptime hash equals runtime hash" {
    const comptime_result = comptimeHash("test");
    const runtime_result = hash("test");
    try std.testing.expectEqualSlices(u8, &comptime_result, &runtime_result);
}
