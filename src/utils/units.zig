const std = @import("std");

/// 1 Ether = 10^18 Wei
pub const ETHER: u256 = 1_000_000_000_000_000_000;

/// 1 Gwei = 10^9 Wei
pub const GWEI: u256 = 1_000_000_000;

/// 1 Wei = 1
pub const WEI: u256 = 1;

/// Convert ether (as f64) to wei (u256).
pub fn parseEther(ether: f64) u256 {
    const wei_f = ether * @as(f64, @floatFromInt(ETHER));
    return @intFromFloat(wei_f);
}

/// Convert gwei (as f64) to wei (u256).
pub fn parseGwei(gwei: f64) u256 {
    const wei_f = gwei * @as(f64, @floatFromInt(GWEI));
    return @intFromFloat(wei_f);
}

/// Convert wei to ether (as f64). May lose precision for very large values.
pub fn formatEther(wei: u256) f64 {
    return @as(f64, @floatFromInt(wei)) / @as(f64, @floatFromInt(ETHER));
}

/// Convert wei to gwei (as f64). May lose precision for very large values.
pub fn formatGwei(wei: u256) f64 {
    return @as(f64, @floatFromInt(wei)) / @as(f64, @floatFromInt(GWEI));
}

// Tests
test "parseEther" {
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), parseEther(1.0));
    try std.testing.expectEqual(@as(u256, 500_000_000_000_000_000), parseEther(0.5));
}

test "parseGwei" {
    try std.testing.expectEqual(@as(u256, 1_000_000_000), parseGwei(1.0));
    try std.testing.expectEqual(@as(u256, 20_000_000_000), parseGwei(20.0));
}

test "formatEther" {
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), formatEther(1_000_000_000_000_000_000), 1e-10);
}

test "formatGwei" {
    try std.testing.expectApproxEqAbs(@as(f64, 20.0), formatGwei(20_000_000_000), 1e-10);
}

test "parseEther zero" {
    try std.testing.expectEqual(@as(u256, 0), parseEther(0.0));
}

test "parseEther large value" {
    try std.testing.expectEqual(@as(u256, 10_000_000_000_000_000_000_000), parseEther(10000.0));
}

test "formatEther zero" {
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), formatEther(0), 1e-10);
}

test "formatGwei zero" {
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), formatGwei(0), 1e-10);
}

test "parseEther formatEther roundtrip" {
    try std.testing.expectApproxEqAbs(@as(f64, 1.5), formatEther(parseEther(1.5)), 1e-6);
}

test "parseGwei formatGwei roundtrip" {
    try std.testing.expectApproxEqAbs(@as(f64, 30.0), formatGwei(parseGwei(30.0)), 1e-6);
}
