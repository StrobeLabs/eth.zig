const std = @import("std");
const hex = @import("hex.zig");

/// Convert a u256 to a big-endian 32-byte array.
pub fn toBigEndianBytes(value: u256) [32]u8 {
    return @bitCast(@byteSwap(value));
}

/// Convert a big-endian 32-byte array to u256.
pub fn fromBigEndianBytes(bytes: [32]u8) u256 {
    return @byteSwap(@as(u256, @bitCast(bytes)));
}

/// Convert a hex string (with optional "0x" prefix) to u256.
pub fn fromHex(hex_str: []const u8) (hex.HexError || error{Overflow})!u256 {
    const src = if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X'))
        hex_str[2..]
    else
        hex_str;

    if (src.len == 0) return 0;
    if (src.len > 64) return error.Overflow;

    var result: u256 = 0;
    for (src) |c| {
        const nibble = try hex.charToNibble(c);
        result = (result << 4) | @as(u256, nibble);
    }
    return result;
}

/// Convert a u256 to a hex string with "0x" prefix.
/// Caller owns the returned memory.
pub fn toHex(allocator: std.mem.Allocator, value: u256) std.mem.Allocator.Error![]u8 {
    if (value == 0) {
        const result = try allocator.alloc(u8, 3);
        result[0] = '0';
        result[1] = 'x';
        result[2] = '0';
        return result;
    }

    const bytes = toBigEndianBytes(value);

    // Find first non-zero byte
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}

    const significant = bytes[start..];
    return hex.bytesToHex(allocator, significant);
}

/// Saturating addition for u256.
pub fn safeAdd(a: u256, b: u256) ?u256 {
    const result = @addWithOverflow(a, b);
    if (result[1] != 0) return null;
    return result[0];
}

/// Saturating subtraction for u256.
pub fn safeSub(a: u256, b: u256) ?u256 {
    const result = @subWithOverflow(a, b);
    if (result[1] != 0) return null;
    return result[0];
}

/// Saturating multiplication for u256.
pub fn safeMul(a: u256, b: u256) ?u256 {
    const result = @mulWithOverflow(a, b);
    if (result[1] != 0) return null;
    return result[0];
}

/// Division (returns null on divide by zero).
pub fn safeDiv(a: u256, b: u256) ?u256 {
    if (b == 0) return null;
    return a / b;
}

/// Fast u256 division that uses narrower operations when values fit.
/// This avoids LLVM's slow generic 256-bit division for common cases.
pub fn fastDiv(a: u256, b: u256) u256 {
    // Both fit in u128 - use LLVM's faster 128-bit division
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return @as(u128, @truncate(a)) / @as(u128, @truncate(b));
    }
    // Full u256 division for large values
    return a / b;
}

/// Maximum u256 value.
pub const MAX: u256 = std.math.maxInt(u256);

/// Zero value.
pub const ZERO: u256 = 0;

/// One value.
pub const ONE: u256 = 1;

// Tests
test "toBigEndianBytes and fromBigEndianBytes roundtrip" {
    const value: u256 = 0xdeadbeef;
    const bytes = toBigEndianBytes(value);
    const recovered = fromBigEndianBytes(bytes);
    try std.testing.expectEqual(value, recovered);
}

test "toBigEndianBytes known value" {
    const value: u256 = 1;
    const bytes = toBigEndianBytes(value);
    // Last byte should be 1, all others 0
    try std.testing.expectEqual(@as(u8, 1), bytes[31]);
    try std.testing.expectEqual(@as(u8, 0), bytes[0]);
}

test "fromHex basic" {
    try std.testing.expectEqual(@as(u256, 0xdeadbeef), try fromHex("0xdeadbeef"));
    try std.testing.expectEqual(@as(u256, 255), try fromHex("ff"));
    try std.testing.expectEqual(@as(u256, 0), try fromHex("0x"));
}

test "fromHex max u256" {
    const max_hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    try std.testing.expectEqual(MAX, try fromHex(max_hex));
}

test "fromHex overflow" {
    // 65 hex chars = 260 bits > 256 bits
    const too_big = "0x1" ++ "0" ** 64;
    try std.testing.expectError(error.Overflow, fromHex(too_big));
}

test "toHex basic" {
    const allocator = std.testing.allocator;

    const result = try toHex(allocator, 0xdeadbeef);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xdeadbeef", result);

    const zero = try toHex(allocator, 0);
    defer allocator.free(zero);
    try std.testing.expectEqualStrings("0x0", zero);
}

test "toHex fromHex roundtrip" {
    const allocator = std.testing.allocator;
    const original: u256 = 0x123456789abcdef0;
    const hex_str = try toHex(allocator, original);
    defer allocator.free(hex_str);
    const recovered = try fromHex(hex_str);
    try std.testing.expectEqual(original, recovered);
}

test "safeAdd" {
    try std.testing.expectEqual(@as(?u256, 3), safeAdd(1, 2));
    try std.testing.expectEqual(@as(?u256, null), safeAdd(MAX, 1));
}

test "safeSub" {
    try std.testing.expectEqual(@as(?u256, 1), safeSub(3, 2));
    try std.testing.expectEqual(@as(?u256, null), safeSub(0, 1));
}

test "safeMul" {
    try std.testing.expectEqual(@as(?u256, 6), safeMul(2, 3));
    try std.testing.expectEqual(@as(?u256, null), safeMul(MAX, 2));
}

test "safeDiv" {
    try std.testing.expectEqual(@as(?u256, 2), safeDiv(6, 3));
    try std.testing.expectEqual(@as(?u256, null), safeDiv(1, 0));
}
