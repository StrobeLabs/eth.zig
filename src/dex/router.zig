const std = @import("std");
const v2 = @import("v2.zig");
const v3 = @import("v3.zig");

// ============================================================================
// Types
// ============================================================================

/// A pool in a multi-hop path. Can be V2 (constant-product) or V3 (concentrated liquidity).
pub const Pool = union(enum) {
    v2: V2Pool,
    v3: V3Pool,

    pub const V2Pool = struct {
        reserve_in: u256,
        reserve_out: u256,
        fee_numerator: u64 = 997,
        fee_denominator: u64 = 1000,
    };

    pub const V3Pool = struct {
        sqrt_price_x96: u256,
        liquidity: u128,
        ticks: []const v3.TickInfo,
        fee_pips: u24,
        zero_for_one: bool,
    };
};

pub const ArbOpportunity = struct {
    profit: u256,
    optimal_input: u256,
};

// ============================================================================
// Routing
// ============================================================================

/// Quote exact input through a mixed V2/V3 path.
/// Returns the final output amount, or null if any hop fails.
pub fn quoteExactInput(amount_in: u256, hops: []const Pool) ?u256 {
    if (hops.len == 0) return null;
    if (amount_in == 0) return @as(u256, 0);

    var current = amount_in;
    for (hops) |pool| {
        current = quotePool(current, pool) orelse return null;
        if (current == 0) return null;
    }
    return current;
}

/// Quote exact output through a mixed V2/V3 path (reverse).
/// Returns the required input amount, or null if any hop fails.
/// Only supports V2 hops (V3 reverse quoting requires tick state traversal).
pub fn quoteExactOutput(amount_out: u256, hops: []const Pool) ?u256 {
    if (hops.len == 0) return null;

    var current = amount_out;
    var i: usize = hops.len;
    while (i > 0) {
        i -= 1;
        switch (hops[i]) {
            .v2 => |p| {
                current = v2.getAmountIn(current, p.reserve_in, p.reserve_out, p.fee_numerator, p.fee_denominator) orelse return null;
            },
            .v3 => {
                // V3 reverse quoting is complex (requires iterating ticks in reverse)
                // Return null to signal unsupported for now
                return null;
            },
        }
    }
    return current;
}

/// Find the optimal input amount for a circular arb path using binary search.
/// Profit is concave for constant-product AMMs, so binary search on the derivative works.
/// Returns null if no profitable opportunity exists.
pub fn findArbOpportunity(hops: []const Pool, max_input: u256) ?ArbOpportunity {
    if (hops.len == 0) return null;
    if (max_input == 0) return null;

    // Probe with a small amount to check if arb exists
    const small_amount = @min(@as(u256, 1000), max_input);
    const small_output = quoteExactInput(small_amount, hops) orelse return null;
    if (small_output <= small_amount) return null;

    // Binary search for optimal input (profit is concave for constant-product AMMs)
    var lo: u256 = 1;
    var hi: u256 = max_input;

    var iterations: u32 = 0;
    while (lo + 1 < hi and iterations < 128) : (iterations += 1) {
        const mid = lo + (hi - lo) / 2;

        const mid_output = quoteExactInput(mid, hops) orelse break;
        if (mid == std.math.maxInt(u256)) break;
        const mid_plus = quoteExactInput(mid + 1, hops) orelse break;

        // Check marginal profit: is f(mid+1) - f(mid) > 1?
        if (mid_plus > mid_output and mid_plus - mid_output > 1) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    // Evaluate both endpoints, pick the better one
    const lo_output = quoteExactInput(lo, hops);
    const hi_output = quoteExactInput(hi, hops);
    const lo_profit: u256 = if (lo_output) |o| (if (o > lo) o - lo else 0) else 0;
    const hi_profit: u256 = if (hi_output) |o| (if (o > hi) o - hi else 0) else 0;

    if (lo_profit == 0 and hi_profit == 0) return null;

    return if (hi_profit > lo_profit)
        .{ .profit = hi_profit, .optimal_input = hi }
    else
        .{ .profit = lo_profit, .optimal_input = lo };
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Quote a single pool hop.
fn quotePool(amount_in: u256, pool: Pool) ?u256 {
    switch (pool) {
        .v2 => |p| {
            const result = v2.getAmountOut(amount_in, p.reserve_in, p.reserve_out, p.fee_numerator, p.fee_denominator);
            return if (result == 0) null else result;
        },
        .v3 => |p| {
            const result = v3.simulateSwap(
                p.sqrt_price_x96,
                p.liquidity,
                p.ticks,
                amount_in,
                p.zero_for_one,
                p.fee_pips,
            );
            return if (result.amount_out == 0) null else result.amount_out;
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

test "quoteExactInput V2 single hop" {
    const hops = [_]Pool{
        .{ .v2 = .{
            .reserve_in = 100_000_000_000_000_000_000,
            .reserve_out = 200_000_000_000,
        } },
    };

    const result = quoteExactInput(1_000_000_000_000_000_000, &hops);
    try std.testing.expect(result != null);

    // Should match direct V2 calculation
    const direct = v2.getAmountOut(1_000_000_000_000_000_000, 100_000_000_000_000_000_000, 200_000_000_000, 997, 1000);
    try std.testing.expectEqual(direct, result.?);
}

test "quoteExactInput V2 multi-hop" {
    const hops = [_]Pool{
        .{ .v2 = .{
            .reserve_in = 100_000_000_000_000_000_000,
            .reserve_out = 200_000_000_000,
        } },
        .{ .v2 = .{
            .reserve_in = 300_000_000_000,
            .reserve_out = 50_000_000_000_000_000_000,
        } },
    };

    const result = quoteExactInput(1_000_000_000_000_000_000, &hops);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "quoteExactInput V3 single hop" {
    const current_sqrt = v3.getSqrtRatioAtTick(0).?;
    const tick_info = [_]v3.TickInfo{
        .{
            .tick = -100,
            .liquidity_net = 500_000_000_000_000_000,
            .sqrt_price_x96 = v3.getSqrtRatioAtTick(-100).?,
        },
    };

    const hops = [_]Pool{
        .{ .v3 = .{
            .sqrt_price_x96 = current_sqrt,
            .liquidity = 1_000_000_000_000_000_000,
            .ticks = &tick_info,
            .fee_pips = 3000,
            .zero_for_one = true,
        } },
    };

    const result = quoteExactInput(1_000_000, &hops);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "quoteExactInput mixed V2+V3" {
    const current_sqrt = v3.getSqrtRatioAtTick(0).?;
    const tick_info = [_]v3.TickInfo{
        .{
            .tick = -100,
            .liquidity_net = 500_000_000_000_000_000,
            .sqrt_price_x96 = v3.getSqrtRatioAtTick(-100).?,
        },
    };

    const hops = [_]Pool{
        // V2 hop first
        .{ .v2 = .{
            .reserve_in = 100_000_000_000_000_000_000,
            .reserve_out = 200_000_000_000,
        } },
        // V3 hop second
        .{ .v3 = .{
            .sqrt_price_x96 = current_sqrt,
            .liquidity = 1_000_000_000_000_000_000,
            .ticks = &tick_info,
            .fee_pips = 3000,
            .zero_for_one = true,
        } },
    };

    const result = quoteExactInput(1_000_000_000_000_000_000, &hops);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "quoteExactInput zero amount" {
    const hops = [_]Pool{
        .{ .v2 = .{
            .reserve_in = 100_000_000_000,
            .reserve_out = 200_000_000_000,
        } },
    };

    const result = quoteExactInput(0, &hops);
    try std.testing.expectEqual(@as(?u256, 0), result);
}

test "quoteExactInput empty path" {
    const result = quoteExactInput(1000, &.{});
    try std.testing.expectEqual(@as(?u256, null), result);
}

test "quoteExactOutput V2 single hop" {
    const hops = [_]Pool{
        .{ .v2 = .{
            .reserve_in = 100_000_000_000_000_000_000,
            .reserve_out = 200_000_000_000,
        } },
    };

    const result = quoteExactOutput(1_000_000_000, &hops);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "findArbOpportunity profitable V2" {
    // Imbalanced pools create arb opportunity
    const hops = [_]Pool{
        .{ .v2 = .{ .reserve_in = 1_000_000, .reserve_out = 2_000_000_000 } },
        .{ .v2 = .{ .reserve_in = 2_000_000_000, .reserve_out = 2_000_000 } },
    };

    const result = findArbOpportunity(&hops, 1_000_000);
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.profit > 0);
    try std.testing.expect(result.?.optimal_input > 0);
}

test "findArbOpportunity unprofitable" {
    // Equal pools with fees = no arb
    const hops = [_]Pool{
        .{ .v2 = .{ .reserve_in = 1_000_000_000, .reserve_out = 1_000_000_000 } },
        .{ .v2 = .{ .reserve_in = 1_000_000_000, .reserve_out = 1_000_000_000 } },
    };

    const result = findArbOpportunity(&hops, 1_000_000_000);
    try std.testing.expectEqual(@as(?ArbOpportunity, null), result);
}
