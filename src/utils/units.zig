const std = @import("std");

/// 1 Ether = 10^18 Wei
pub const ETHER: u256 = 1_000_000_000_000_000_000;

/// 1 Gwei = 10^9 Wei
pub const GWEI: u256 = 1_000_000_000;

/// 1 Wei = 1
pub const WEI: u256 = 1;

// Avoid runtime @floatFromInt/@intFromFloat on u256, which triggers
// LLVM bug https://github.com/ziglang/zig/issues/18820 on aarch64.
const ETHER_F64: f64 = @as(f64, @floatFromInt(ETHER));
const GWEI_F64: f64 = @as(f64, @floatFromInt(GWEI));
const TWO_POW_128_F64: f64 = 2.0 * @as(f64, @floatFromInt(@as(u128, 1) << 127));

inline fn f64ToU256(value: f64) u256 {
    return @as(u256, @as(u128, @intFromFloat(value)));
}

inline fn u256ToF64(value: u256) f64 {
    const hi: u128 = @truncate(value >> 128);
    if (hi == 0) {
        return @as(f64, @floatFromInt(@as(u128, @truncate(value))));
    }
    const lo: u128 = @truncate(value);
    return @as(f64, @floatFromInt(hi)) * TWO_POW_128_F64 + @as(f64, @floatFromInt(lo));
}

/// Convert ether (as f64) to wei (u256).
pub fn parseEther(ether: f64) u256 {
    return f64ToU256(ether * ETHER_F64);
}

/// Convert gwei (as f64) to wei (u256).
pub fn parseGwei(gwei: f64) u256 {
    return f64ToU256(gwei * GWEI_F64);
}

/// Convert wei to ether (as f64). May lose precision for very large values.
pub fn formatEther(wei: u256) f64 {
    return u256ToF64(wei) / ETHER_F64;
}

/// Convert wei to gwei (as f64). May lose precision for very large values.
pub fn formatGwei(wei: u256) f64 {
    return u256ToF64(wei) / GWEI_F64;
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
    // 9007.0 is exact in f64, but 9007.0 * 1e18 exceeds f64 mantissa precision.
    // Allow up to 1 ULP of error at this magnitude (~2^20 = 1_048_576).
    const result = parseEther(9007.0);
    const expected: u256 = 9007_000_000_000_000_000_000;
    const diff = if (result > expected) result - expected else expected - result;
    try std.testing.expect(diff < 1_048_576);
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

test "formatEther is finite and monotonic for very large u256 values" {
    const huge = (@as(u256, 1) << 200);
    const larger = huge + (@as(u256, 1) << 199);

    const f_huge = formatEther(huge);
    const f_larger = formatEther(larger);

    try std.testing.expect(std.math.isFinite(f_huge));
    try std.testing.expect(std.math.isFinite(f_larger));
    try std.testing.expect(f_huge > 0.0);
    try std.testing.expect(f_larger > f_huge);
}

test "formatGwei is finite and monotonic for very large u256 values" {
    const huge = (@as(u256, 1) << 200);
    const larger = huge + (@as(u256, 1) << 199);

    const f_huge = formatGwei(huge);
    const f_larger = formatGwei(larger);

    try std.testing.expect(std.math.isFinite(f_huge));
    try std.testing.expect(std.math.isFinite(f_larger));
    try std.testing.expect(f_huge > 0.0);
    try std.testing.expect(f_larger > f_huge);
}
