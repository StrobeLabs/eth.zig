const std = @import("std");
const uint256_mod = @import("../uint256.zig");

const u256ToLimbs = uint256_mod.u256ToLimbs;
const limbsToU256 = uint256_mod.limbsToU256;
const mulLimbs = uint256_mod.mulLimbs;
const mulLimbScalar = uint256_mod.mulLimbScalar;
const divLimbsDirect = uint256_mod.divLimbsDirect;
const addLimbs = uint256_mod.addLimbs;

// ============================================================================
// Types
// ============================================================================

pub const Pair = struct {
    reserve_in: u256,
    reserve_out: u256,
    fee_numerator: u64 = 997,
    fee_denominator: u64 = 1000,
};

// ============================================================================
// Core Functions
// ============================================================================

/// Compute UniswapV2 getAmountOut with configurable fee, entirely in u64-limb space.
/// Formula: (amountIn * feeNum * reserveOut) / (reserveIn * feeDenom + amountIn * feeNum)
pub fn getAmountOut(amount_in: u256, reserve_in: u256, reserve_out: u256, fee_numerator: u64, fee_denominator: u64) ?u256 {
    if (amount_in == 0) return 0;
    if (reserve_in == 0 or reserve_out == 0) return 0;
    if (fee_denominator == 0) return null;

    const ai = u256ToLimbs(amount_in);
    const ri = u256ToLimbs(reserve_in);
    const ro = u256ToLimbs(reserve_out);

    const amount_in_with_fee = mulLimbScalar(ai, fee_numerator);
    const numerator = mulLimbs(amount_in_with_fee, ro);
    const denominator = addLimbs(mulLimbScalar(ri, fee_denominator), amount_in_with_fee);

    if (denominator[0] == 0 and denominator[1] == 0 and denominator[2] == 0 and denominator[3] == 0) {
        return null;
    }

    return limbsToU256(divLimbsDirect(numerator, denominator));
}

/// Compute UniswapV2 getAmountIn with configurable fee.
/// Formula: (reserveIn * amountOut * feeDenom) / ((reserveOut - amountOut) * feeNum) + 1
/// Returns null if amount_out >= reserve_out (insufficient liquidity).
pub fn getAmountIn(amount_out: u256, reserve_in: u256, reserve_out: u256, fee_numerator: u64, fee_denominator: u64) ?u256 {
    if (amount_out == 0) return @as(u256, 0);
    if (reserve_in == 0 or reserve_out == 0) return null;
    if (fee_denominator == 0) return null;
    if (fee_numerator == 0) return null;
    if (amount_out >= reserve_out) return null;

    const reserve_diff = reserve_out - amount_out;

    const ri = u256ToLimbs(reserve_in);
    const ao = u256ToLimbs(amount_out);
    const rd = u256ToLimbs(reserve_diff);

    // numerator = reserveIn * amountOut * feeDenom
    const ri_times_ao = mulLimbs(ri, ao);
    const numerator = mulLimbScalar(ri_times_ao, fee_denominator);

    // denominator = (reserveOut - amountOut) * feeNum
    const denominator = mulLimbScalar(rd, fee_numerator);

    if (denominator[0] == 0 and denominator[1] == 0 and denominator[2] == 0 and denominator[3] == 0) {
        return null;
    }

    // Uniswap V2 always adds 1 (ceiling)
    const quotient = limbsToU256(divLimbsDirect(numerator, denominator));
    return quotient + 1;
}

// ============================================================================
// Multi-hop Functions
// ============================================================================

/// Chain forward swaps: each hop's output feeds the next hop's input.
/// Returns null if any intermediate output is 0.
pub fn getAmountsOut(amount_in: u256, path: []const Pair) ?u256 {
    if (path.len == 0) return null;

    var current = amount_in;
    for (path) |pair| {
        current = getAmountOut(current, pair.reserve_in, pair.reserve_out, pair.fee_numerator, pair.fee_denominator) orelse return null;
        if (current == 0) return null;
    }
    return current;
}

/// Chain backward swaps: start from desired output, work backwards to find required input.
/// Returns null if any getAmountIn returns null.
pub fn getAmountsIn(amount_out: u256, path: []const Pair) ?u256 {
    if (path.len == 0) return null;

    var current = amount_out;
    var i: usize = path.len;
    while (i > 0) {
        i -= 1;
        current = getAmountIn(current, path[i].reserve_in, path[i].reserve_out, path[i].fee_numerator, path[i].fee_denominator) orelse return null;
    }
    return current;
}

/// Run getAmountsOut and return profit (output - input) if positive, else null.
pub fn calculateProfit(amount_in: u256, path: []const Pair) ?u256 {
    const output = getAmountsOut(amount_in, path) orelse return null;
    if (output > amount_in) {
        return output - amount_in;
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "getAmountOut known value" {
    // 1 ETH in, 100 ETH / 200k USDC pool, 0.3% fee
    // Expected: (1e18 * 997 * 200e9) / (100e18 * 1000 + 1e18 * 997) = 1_974_316_068
    const v2_result = getAmountOut(1_000_000_000_000_000_000, 100_000_000_000_000_000_000, 200_000_000_000, 997, 1000).?;
    try std.testing.expectEqual(@as(u256, 1_974_316_068), v2_result);
}

test "getAmountOut zero reserves" {
    try std.testing.expectEqual(@as(?u256, 0), getAmountOut(1000, 0, 200_000, 997, 1000));
    try std.testing.expectEqual(@as(?u256, 0), getAmountOut(1000, 100_000, 0, 997, 1000));
    try std.testing.expectEqual(@as(?u256, null), getAmountOut(1000, 100_000, 200_000, 997, 0));
}

test "getAmountOut different fees" {
    const amount_in: u256 = 1_000_000_000_000_000_000;
    const reserve_in: u256 = 100_000_000_000_000_000_000;
    const reserve_out: u256 = 200_000_000_000;

    // PancakeSwap uses 9975/10000 (0.25% fee) vs Uniswap 997/1000 (0.3% fee)
    const pancake = getAmountOut(amount_in, reserve_in, reserve_out, 9975, 10000).?;
    const uniswap = getAmountOut(amount_in, reserve_in, reserve_out, 997, 1000).?;

    // Lower fee => more output
    try std.testing.expect(pancake > uniswap);
}

test "getAmountOut zero input" {
    const result = getAmountOut(0, 100_000, 200_000, 997, 1000);
    try std.testing.expectEqual(@as(?u256, 0), result);
}

test "getAmountOut result less than reserve" {
    const amounts = [_]u256{ 1, 1000, 1_000_000_000_000_000_000, 50_000_000_000_000_000_000 };
    const reserve_in: u256 = 100_000_000_000_000_000_000;
    const reserve_out: u256 = 200_000_000_000;

    for (amounts) |amount_in| {
        const result = getAmountOut(amount_in, reserve_in, reserve_out, 997, 1000).?;
        try std.testing.expect(result < reserve_out);
    }
}

test "getAmountIn inverse" {
    const amount_in: u256 = 1_000_000_000_000_000_000;
    const reserve_in: u256 = 100_000_000_000_000_000_000;
    // Reserves of comparable magnitude so the (floored) output is large. The
    // round-trip invariant only holds when flooring the output discards less
    // than the +1-unit ceiling getAmountIn adds back; with a tiny reserve_out
    // the floored output loses far more than 2 units of input-equivalent and
    // recovered_input legitimately falls below amount_in (Uniswap behaviour,
    // not a bug).
    const reserve_out: u256 = 200_000_000_000_000_000_000;

    const output = getAmountOut(amount_in, reserve_in, reserve_out, 997, 1000).?;
    const recovered_input = getAmountIn(output, reserve_in, reserve_out, 997, 1000) orelse unreachable;

    // Due to ceiling division (+1), recovered_input >= amount_in, within 2 units.
    try std.testing.expect(recovered_input >= amount_in);
    try std.testing.expect(recovered_input - amount_in <= 2);
}

test "getAmountIn insufficient liquidity" {
    const reserve_in: u256 = 100_000_000_000_000_000_000;
    const reserve_out: u256 = 200_000_000_000;

    // amount_out == reserve_out
    try std.testing.expectEqual(@as(?u256, null), getAmountIn(reserve_out, reserve_in, reserve_out, 997, 1000));

    // amount_out > reserve_out
    try std.testing.expectEqual(@as(?u256, null), getAmountIn(reserve_out + 1, reserve_in, reserve_out, 997, 1000));
}

test "getAmountsOut multi-hop" {
    const path = [_]Pair{
        .{ .reserve_in = 100_000_000_000_000_000_000, .reserve_out = 200_000_000_000 }, // ETH -> USDC
        .{ .reserve_in = 300_000_000_000, .reserve_out = 50_000_000_000_000_000_000 }, // USDC -> DAI
    };

    const amount_in: u256 = 1_000_000_000_000_000_000; // 1 ETH
    const result = getAmountsOut(amount_in, &path);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "getAmountsIn multi-hop" {
    const path = [_]Pair{
        .{ .reserve_in = 100_000_000_000_000_000_000, .reserve_out = 200_000_000_000 },
        .{ .reserve_in = 300_000_000_000, .reserve_out = 50_000_000_000_000_000_000 },
    };

    const desired_output: u256 = 500_000_000_000_000_000; // 0.5 DAI
    const required_input = getAmountsIn(desired_output, &path);
    try std.testing.expect(required_input != null);
    try std.testing.expect(required_input.? > 0);
}

test "calculateProfit unprofitable" {
    // Equal reserves with 0.3% fee each way => guaranteed loss
    const path = [_]Pair{
        .{ .reserve_in = 1_000_000_000, .reserve_out = 1_000_000_000 },
        .{ .reserve_in = 1_000_000_000, .reserve_out = 1_000_000_000 },
    };

    const result = calculateProfit(1_000_000, &path);
    try std.testing.expectEqual(@as(?u256, null), result);
}

test "calculateProfit arithmetic" {
    // Imbalanced pools create arbitrage opportunity:
    // Pool 1: buy cheap (low reserve_in, high reserve_out)
    // Pool 2: sell expensive (high reserve_in, low reserve_out relative to what we got)
    const path = [_]Pair{
        .{ .reserve_in = 1_000_000, .reserve_out = 2_000_000_000 }, // very cheap
        .{ .reserve_in = 2_000_000_000, .reserve_out = 2_000_000 }, // sell back
    };

    const result = calculateProfit(1000, &path);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}
