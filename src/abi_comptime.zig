const std = @import("std");
const keccak = @import("keccak.zig");

/// Deprecated: use keccak.selector() directly. Works at both comptime and runtime.
///
/// Example:
///   const sel = keccak.selector("transfer(address,uint256)");
///   // sel == [4]u8{ 0xa9, 0x05, 0x9c, 0xbb }
pub fn comptimeSelector(signature: []const u8) [4]u8 {
    return keccak.selector(signature);
}

/// Deprecated: use keccak.hash() directly. Works at both comptime and runtime.
///
/// Example:
///   const topic = keccak.hash("Transfer(address,address,uint256)");
///   // topic == keccak256("Transfer(address,address,uint256)")
pub fn comptimeTopic(signature: []const u8) [32]u8 {
    return keccak.hash(signature);
}

// ============================================================================
// Tests
// ============================================================================

const hex_mod = @import("hex.zig");

test "comptimeSelector - transfer(address,uint256)" {
    const sel = comptimeSelector("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &sel);
}

test "comptimeSelector - balanceOf(address)" {
    const sel = comptimeSelector("balanceOf(address)");
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &sel);
}

test "comptimeSelector - approve(address,uint256)" {
    const sel = comptimeSelector("approve(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x5e, 0xa7, 0xb3 }, &sel);
}

test "comptimeSelector - transferFrom(address,address,uint256)" {
    const sel = comptimeSelector("transferFrom(address,address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0xb8, 0x72, 0xdd }, &sel);
}

test "comptimeSelector - totalSupply()" {
    const sel = comptimeSelector("totalSupply()");
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x16, 0x0d, 0xdd }, &sel);
}

test "comptimeSelector - name()" {
    const sel = comptimeSelector("name()");
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0xfd, 0xde, 0x03 }, &sel);
}

test "comptimeSelector - symbol()" {
    const sel = comptimeSelector("symbol()");
    try std.testing.expectEqualSlices(u8, &.{ 0x95, 0xd8, 0x9b, 0x41 }, &sel);
}

test "comptimeSelector - decimals()" {
    const sel = comptimeSelector("decimals()");
    try std.testing.expectEqualSlices(u8, &.{ 0x31, 0x3c, 0xe5, 0x67 }, &sel);
}

test "comptimeTopic - Transfer(address,address,uint256)" {
    const topic = comptimeTopic("Transfer(address,address,uint256)");
    const expected = try hex_mod.hexToBytesFixed(32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    try std.testing.expectEqualSlices(u8, &expected, &topic);
}

test "comptimeTopic - Approval(address,address,uint256)" {
    const topic = comptimeTopic("Approval(address,address,uint256)");
    const expected = try hex_mod.hexToBytesFixed(32, "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");
    try std.testing.expectEqualSlices(u8, &expected, &topic);
}

test "comptimeTopic - OwnershipTransferred(address,address)" {
    const topic = comptimeTopic("OwnershipTransferred(address,address)");
    const expected = try hex_mod.hexToBytesFixed(32, "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0");
    try std.testing.expectEqualSlices(u8, &expected, &topic);
}

test "comptimeSelector equals runtime selector" {
    const comptime_sel = comptimeSelector("transfer(address,uint256)");
    const runtime_sel = keccak.selector("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &comptime_sel, &runtime_sel);
}

test "comptimeTopic equals runtime topic" {
    const comptime_topic = comptimeTopic("Transfer(address,address,uint256)");
    const runtime_topic = keccak.hash("Transfer(address,address,uint256)");
    try std.testing.expectEqualSlices(u8, &comptime_topic, &runtime_topic);
}
