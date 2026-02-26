const std = @import("std");

pub const HexError = error{
    InvalidHexCharacter,
    InvalidHexLength,
    OddHexLength,
    OutputTooSmall,
};

/// Comptime-generated lookup table for hex decoding.
/// Maps ASCII byte -> nibble value (0-15), or 0xFF for invalid characters.
const hex_lut: [256]u8 = blk: {
    var table: [256]u8 = .{0xFF} ** 256;
    for ('0'..('9' + 1)) |c| table[c] = c - '0';
    for ('a'..('f' + 1)) |c| table[c] = c - 'a' + 10;
    for ('A'..('F' + 1)) |c| table[c] = c - 'A' + 10;
    break :blk table;
};

/// Decode a single hex character to its 4-bit value.
pub fn charToNibble(c: u8) HexError!u4 {
    const v = hex_lut[c];
    if (v == 0xFF) return error.InvalidHexCharacter;
    return @intCast(v);
}

/// Decode hex string to bytes. Accepts optional "0x" prefix.
/// Returns the number of bytes written.
pub fn hexToBytes(dest: []u8, hex_str: []const u8) HexError![]u8 {
    const src = if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X'))
        hex_str[2..]
    else
        hex_str;

    if (src.len % 2 != 0) return error.OddHexLength;

    const byte_len = src.len / 2;
    if (dest.len < byte_len) return error.OutputTooSmall;

    for (0..byte_len) |i| {
        const hi = try charToNibble(src[i * 2]);
        const lo = try charToNibble(src[i * 2 + 1]);
        dest[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }

    return dest[0..byte_len];
}

/// Decode hex string to a fixed-size byte array.
pub fn hexToBytesFixed(comptime N: usize, hex_str: []const u8) HexError![N]u8 {
    var result: [N]u8 = undefined;
    const decoded = try hexToBytes(&result, hex_str);
    if (decoded.len != N) return error.InvalidHexLength;
    return result;
}

const hex_chars = "0123456789abcdef";

/// Encode bytes to hex string with "0x" prefix.
/// Caller owns the returned memory.
pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const result = try allocator.alloc(u8, 2 + bytes.len * 2);
    result[0] = '0';
    result[1] = 'x';
    for (bytes, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Encode bytes to hex string into a comptime-sized buffer (with "0x" prefix).
pub fn bytesToHexBuf(comptime N: usize, bytes: *const [N]u8) [2 + N * 2]u8 {
    var result: [2 + N * 2]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    for (bytes, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Check if a string is valid hex (with optional "0x" prefix).
pub fn isValidHex(str: []const u8) bool {
    const src = if (str.len >= 2 and str[0] == '0' and (str[1] == 'x' or str[1] == 'X'))
        str[2..]
    else
        str;

    if (src.len % 2 != 0) return false;

    for (src) |c| {
        _ = charToNibble(c) catch return false;
    }
    return true;
}

// Tests
test "charToNibble" {
    try std.testing.expectEqual(@as(u4, 0), try charToNibble('0'));
    try std.testing.expectEqual(@as(u4, 9), try charToNibble('9'));
    try std.testing.expectEqual(@as(u4, 10), try charToNibble('a'));
    try std.testing.expectEqual(@as(u4, 15), try charToNibble('f'));
    try std.testing.expectEqual(@as(u4, 10), try charToNibble('A'));
    try std.testing.expectEqual(@as(u4, 15), try charToNibble('F'));
    try std.testing.expectError(error.InvalidHexCharacter, charToNibble('g'));
    try std.testing.expectError(error.InvalidHexCharacter, charToNibble(' '));
}

test "hexToBytes basic" {
    var buf: [4]u8 = undefined;
    const result = try hexToBytes(&buf, "deadbeef");
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, result);
}

test "hexToBytes with 0x prefix" {
    var buf: [4]u8 = undefined;
    const result = try hexToBytes(&buf, "0xdeadbeef");
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, result);
}

test "hexToBytes empty" {
    var buf: [0]u8 = undefined;
    const result = try hexToBytes(&buf, "0x");
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "hexToBytes odd length" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.OddHexLength, hexToBytes(&buf, "0xdea"));
}

test "hexToBytesFixed" {
    const result = try hexToBytesFixed(4, "0xdeadbeef");
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &result);
}

test "hexToBytesFixed wrong length" {
    try std.testing.expectError(error.InvalidHexLength, hexToBytesFixed(3, "0xdeadbeef"));
}

test "bytesToHex" {
    const allocator = std.testing.allocator;
    const result = try bytesToHex(allocator, &.{ 0xde, 0xad, 0xbe, 0xef });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xdeadbeef", result);
}

test "bytesToHexBuf" {
    const input = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const result = bytesToHexBuf(4, &input);
    try std.testing.expectEqualStrings("0xdeadbeef", &result);
}

test "isValidHex" {
    try std.testing.expect(isValidHex("0xdeadbeef"));
    try std.testing.expect(isValidHex("deadbeef"));
    try std.testing.expect(isValidHex("0x"));
    try std.testing.expect(!isValidHex("0xdea")); // odd
    try std.testing.expect(!isValidHex("0xgg")); // invalid chars
}
