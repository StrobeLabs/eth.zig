const std = @import("std");
const uint256_mod = @import("../uint256.zig");

const mulDiv = uint256_mod.mulDiv;
const mulDivRoundingUp = uint256_mod.mulDivRoundingUp;
const u256ToLimbs = uint256_mod.u256ToLimbs;
const limbsToU256 = uint256_mod.limbsToU256;
const mulLimbs = uint256_mod.mulLimbs;
const mulLimbScalar = uint256_mod.mulLimbScalar;
const divLimbsDirect = uint256_mod.divLimbsDirect;
const addLimbs = uint256_mod.addLimbs;
const fastMul = uint256_mod.fastMul;
const fastDiv = uint256_mod.fastDiv;
const mulWide = uint256_mod.mulWide;
const MAX = uint256_mod.MAX;
const ZERO = uint256_mod.ZERO;

// ============================================================================
// Constants
// ============================================================================

pub const Q96: u256 = uint256_mod.Q96; // 1 << 96
pub const Q128: u256 = @as(u256, 1) << 128;
pub const MIN_TICK: i24 = -887272;
pub const MAX_TICK: i24 = 887272;
pub const MIN_SQRT_RATIO: u256 = 4295128739;
pub const MAX_SQRT_RATIO: u256 = 1461446703485210103287273052203988822378723970342;

// ============================================================================
// TickMath
// ============================================================================

/// Precomputed magic constants: sqrt(1.0001^(2^i)) in Q128.128 format.
/// From Uniswap V3 TickMath.sol.
const TICK_RATIOS = [20]u256{
    0xfffcb933bd6fad37aa2d162d1a594001, // bit 0:  sqrt(1.0001^1)
    0xfff97272373d413259a46990580e213a, // bit 1:  sqrt(1.0001^2)
    0xfff2e50f5f656932ef12357cf3c7fdcc, // bit 2:  sqrt(1.0001^4)
    0xffe5caca7e10e4e61c3624eaa0941cd0, // bit 3:  sqrt(1.0001^8)
    0xffcb9843d60f6159c9db58835c926644, // bit 4:  sqrt(1.0001^16)
    0xff973b41fa98c081472e6896dfb254c0, // bit 5:  sqrt(1.0001^32)
    0xff2ea16466c96a3843ec78b326b52861, // bit 6:  sqrt(1.0001^64)
    0xfe5dee046a99a2a811c461f1969c3053, // bit 7:  sqrt(1.0001^128)
    0xfcbe86c7900a88aedcffc83b479aa3a4, // bit 8:  sqrt(1.0001^256)
    0xf987a7253ac413176f2b074cf7815e54, // bit 9:  sqrt(1.0001^512)
    0xf3392b0822b70005940c7a398e4b70f3, // bit 10: sqrt(1.0001^1024)
    0xe7159475a2c29b7443b29c7fa6e889d9, // bit 11: sqrt(1.0001^2048)
    0xd097f3bdfd2022b8845ad8f792aa5825, // bit 12: sqrt(1.0001^4096)
    0xa9f746462d870fdf8a65dc1f90e061e5, // bit 13: sqrt(1.0001^8192)
    0x70d869a156d2a1b890bb3df62baf32f7, // bit 14: sqrt(1.0001^16384)
    0x31be135f97d08fd981231505542fcfa6, // bit 15: sqrt(1.0001^32768)
    0x9aa508b5b7a84e1c677de54f3e99bc9, //  bit 16: sqrt(1.0001^65536)
    0x5d6af8dedb81196699c329225ee604, //   bit 17: sqrt(1.0001^131072)
    0x2216e584f5fa1ea926041bedfe98, //     bit 18: sqrt(1.0001^262144)
    0x48a170391f7dc42444e8fa2, //          bit 19: sqrt(1.0001^524288)
};

/// Get sqrtPriceX96 from a tick index.
/// Port of Uniswap V3 TickMath.getSqrtRatioAtTick.
pub fn getSqrtRatioAtTick(tick: i24) ?u256 {
    // Validate tick range
    if (tick < MIN_TICK or tick > MAX_TICK) return null;

    const abs_tick: u24 = @abs(tick);

    // Initialize ratio based on bit 0
    var ratio: u256 = if (abs_tick & 0x1 != 0)
        TICK_RATIOS[0]
    else
        0x100000000000000000000000000000000; // Q128.128 representation of 1.0

    // Apply conditional multiplications for bits 1-19
    if (abs_tick & 0x2 != 0) ratio = mulDiv(ratio, TICK_RATIOS[1], Q128) orelse return null;
    if (abs_tick & 0x4 != 0) ratio = mulDiv(ratio, TICK_RATIOS[2], Q128) orelse return null;
    if (abs_tick & 0x8 != 0) ratio = mulDiv(ratio, TICK_RATIOS[3], Q128) orelse return null;
    if (abs_tick & 0x10 != 0) ratio = mulDiv(ratio, TICK_RATIOS[4], Q128) orelse return null;
    if (abs_tick & 0x20 != 0) ratio = mulDiv(ratio, TICK_RATIOS[5], Q128) orelse return null;
    if (abs_tick & 0x40 != 0) ratio = mulDiv(ratio, TICK_RATIOS[6], Q128) orelse return null;
    if (abs_tick & 0x80 != 0) ratio = mulDiv(ratio, TICK_RATIOS[7], Q128) orelse return null;
    if (abs_tick & 0x100 != 0) ratio = mulDiv(ratio, TICK_RATIOS[8], Q128) orelse return null;
    if (abs_tick & 0x200 != 0) ratio = mulDiv(ratio, TICK_RATIOS[9], Q128) orelse return null;
    if (abs_tick & 0x400 != 0) ratio = mulDiv(ratio, TICK_RATIOS[10], Q128) orelse return null;
    if (abs_tick & 0x800 != 0) ratio = mulDiv(ratio, TICK_RATIOS[11], Q128) orelse return null;
    if (abs_tick & 0x1000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[12], Q128) orelse return null;
    if (abs_tick & 0x2000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[13], Q128) orelse return null;
    if (abs_tick & 0x4000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[14], Q128) orelse return null;
    if (abs_tick & 0x8000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[15], Q128) orelse return null;
    if (abs_tick & 0x10000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[16], Q128) orelse return null;
    if (abs_tick & 0x20000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[17], Q128) orelse return null;
    if (abs_tick & 0x40000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[18], Q128) orelse return null;
    if (abs_tick & 0x80000 != 0) ratio = mulDiv(ratio, TICK_RATIOS[19], Q128) orelse return null;

    // If tick > 0, invert the ratio
    if (tick > 0) {
        ratio = MAX / ratio;
    }

    // Convert from Q128.128 to Q96.96: right-shift by 32, rounding up if remainder
    const remainder = ratio & ((@as(u256, 1) << 32) - 1);
    const shifted = ratio >> 32;
    return shifted + if (remainder == 0) @as(u256, 0) else @as(u256, 1);
}

/// Get tick index from sqrtPriceX96.
/// Port of Uniswap V3 TickMath.getTickAtSqrtRatio.
pub fn getTickAtSqrtRatio(sqrt_price_x96: u256) ?i24 {
    // Validate: MIN_SQRT_RATIO <= sqrt_price_x96 < MAX_SQRT_RATIO
    if (sqrt_price_x96 < MIN_SQRT_RATIO or sqrt_price_x96 >= MAX_SQRT_RATIO) return null;

    // Convert Q96 to Q128
    const ratio: u256 = sqrt_price_x96 << 32;

    var r: u256 = ratio;
    var msb: u256 = 0;

    // Find MSB via binary search (8 stages)
    {
        const f: u256 = if (r > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) @as(u256, 128) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0xFFFFFFFFFFFFFFFF) @as(u256, 64) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0xFFFFFFFF) @as(u256, 32) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0xFFFF) @as(u256, 16) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0xFF) @as(u256, 8) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0xF) @as(u256, 4) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0x3) @as(u256, 2) else 0;
        msb |= f;
        r >>= @intCast(f);
    }
    {
        const f: u256 = if (r > 0x1) @as(u256, 1) else 0;
        msb |= f;
    }

    // Normalize r so MSB is at bit 127
    if (msb >= 128) {
        r = ratio >> @intCast(msb - 127);
    } else {
        r = ratio << @intCast(127 - msb);
    }

    // Initialize log_2 as signed Q64.64
    // log_2 = (msb - 128) << 64
    var log_2: i256 = (@as(i256, @intCast(msb)) - 128) << 64;

    // 14 iterations of squaring to compute fractional bits of log2
    // Each iteration: r = (r * r) >> 127, f = r >> 128, log_2 |= f << (63 - i), r >>= f
    // NOTE: Solidity uses wrapping mul (mod 2^256) then shr, NOT full-precision mulDiv.
    inline for (0..14) |iteration| {
        // r = (r *% r) >> 127  (wrapping multiply, matching Solidity assembly `mul`)
        r = fastMul(r, r) >> 127;
        const f: u256 = r >> 128;
        log_2 = log_2 | @as(i256, @intCast(f << (63 - iteration)));
        r >>= @intCast(f);
    }

    // Convert log_2 (base 2) to log_sqrt10001 (base sqrt(1.0001))
    const log_sqrt10001: i256 = log_2 * 255738958999603826347141;

    // Compute tick bounds
    const tick_low: i24 = @intCast(@as(i256, (log_sqrt10001 - 3402992956809132418596140100660247210) >> 128));
    const tick_high: i24 = @intCast(@as(i256, (log_sqrt10001 + 291339464771989622907027621153398088495) >> 128));

    if (tick_low == tick_high) {
        return tick_low;
    }

    // Check which tick is correct
    const sqrt_ratio_at_high = getSqrtRatioAtTick(tick_high) orelse return null;
    if (sqrt_ratio_at_high <= sqrt_price_x96) {
        return tick_high;
    } else {
        return tick_low;
    }
}

// ============================================================================
// SqrtPriceMath
// ============================================================================

/// Unsafe division rounding up: ceil(a / b). Assumes b != 0.
fn divRoundingUp(a: u256, b: u256) u256 {
    const quotient = fastDiv(a, b);
    if (a % b != 0) {
        return quotient + 1;
    }
    return quotient;
}

/// Amount of token0 for a price move. Uses mulDiv for precision.
/// Calculates: liquidity * (sqrtB - sqrtA) / (sqrtA * sqrtB) in Q96 space.
pub fn getAmount0Delta(sqrt_ratio_a_x96: u256, sqrt_ratio_b_x96: u256, liquidity: u128, round_up: bool) ?u256 {
    var lower = sqrt_ratio_a_x96;
    var upper = sqrt_ratio_b_x96;
    if (lower > upper) {
        const tmp = lower;
        lower = upper;
        upper = tmp;
    }
    if (lower == 0) return null;

    const numerator1: u256 = @as(u256, liquidity) << 96;
    const numerator2: u256 = upper - lower;

    if (round_up) {
        const inner = mulDivRoundingUp(numerator1, numerator2, upper) orelse return null;
        return divRoundingUp(inner, lower);
    } else {
        const inner = mulDiv(numerator1, numerator2, upper) orelse return null;
        return inner / lower;
    }
}

/// Amount of token1 for a price move.
/// Calculates: liquidity * (sqrtB - sqrtA) / Q96.
pub fn getAmount1Delta(sqrt_ratio_a_x96: u256, sqrt_ratio_b_x96: u256, liquidity: u128, round_up: bool) ?u256 {
    var lower = sqrt_ratio_a_x96;
    var upper = sqrt_ratio_b_x96;
    if (lower > upper) {
        const tmp = lower;
        lower = upper;
        upper = tmp;
    }

    const diff = upper - lower;

    if (round_up) {
        return mulDivRoundingUp(@as(u256, liquidity), diff, Q96);
    } else {
        return mulDiv(@as(u256, liquidity), diff, Q96);
    }
}

/// Get next sqrt price from token0 amount change, rounding up.
/// When add=true (input token0), price goes down.
/// When add=false (output token0), price goes up.
pub fn getNextSqrtPriceFromAmount0RoundingUp(sqrt_price_x96: u256, liquidity: u128, amount: u256, add: bool) ?u256 {
    if (amount == 0) return sqrt_price_x96;
    const numerator1: u256 = @as(u256, liquidity) << 96;

    if (add) {
        // product = amount * sqrt_price_x96 -- check for overflow
        const ov = @mulWithOverflow(amount, sqrt_price_x96);
        if (ov[1] == 0) {
            const product = ov[0];
            // Verify: product / amount == sqrt_price_x96 (no truncation)
            if (product / amount == sqrt_price_x96) {
                const denominator_ov = @addWithOverflow(numerator1, product);
                if (denominator_ov[1] == 0 and denominator_ov[0] >= numerator1) {
                    return mulDivRoundingUp(numerator1, sqrt_price_x96, denominator_ov[0]);
                }
            }
        }
        // Fallback for overflow: numerator1 / (numerator1 / sqrt_price_x96 + amount)
        const div_result = fastDiv(numerator1, sqrt_price_x96);
        const sum_ov = @addWithOverflow(div_result, amount);
        if (sum_ov[1] != 0) return null;
        return divRoundingUp(numerator1, sum_ov[0]);
    } else {
        // Subtract: price goes up
        const ov = @mulWithOverflow(amount, sqrt_price_x96);
        if (ov[1] != 0) return null;
        const product = ov[0];
        // Verify no truncation
        if (product / amount != sqrt_price_x96) return null;
        if (numerator1 <= product) return null;
        const denominator = numerator1 - product;
        return mulDivRoundingUp(numerator1, sqrt_price_x96, denominator);
    }
}

/// Get next sqrt price from token1 amount change, rounding down.
/// When add=true (input token1), price goes up.
/// When add=false (output token1), price goes down.
pub fn getNextSqrtPriceFromAmount1RoundingDown(sqrt_price_x96: u256, liquidity: u128, amount: u256, add: bool) ?u256 {
    if (add) {
        // quotient = amount * Q96 / liquidity (or amount << 96 / liquidity if fits)
        const quotient: u256 = if (amount <= (@as(u256, 1) << 160) - 1)
            (amount << 96) / @as(u256, liquidity)
        else
            mulDiv(amount, Q96, @as(u256, liquidity)) orelse return null;

        const result_ov = @addWithOverflow(sqrt_price_x96, quotient);
        if (result_ov[1] != 0) return null;
        return result_ov[0];
    } else {
        // quotient = mulDivRoundingUp(amount, Q96, liquidity) or divRoundingUp(amount << 96, liquidity) if fits
        const quotient: u256 = if (amount <= (@as(u256, 1) << 160) - 1)
            divRoundingUp(amount << 96, @as(u256, liquidity))
        else
            mulDivRoundingUp(amount, Q96, @as(u256, liquidity)) orelse return null;

        if (sqrt_price_x96 <= quotient) return null;
        return sqrt_price_x96 - quotient;
    }
}

/// Get next sqrt price from input amount.
pub fn getNextSqrtPriceFromInput(sqrt_price_x96: u256, liquidity: u128, amount_in: u256, zero_for_one: bool) ?u256 {
    if (sqrt_price_x96 == 0) return null;
    if (liquidity == 0) return null;

    return if (zero_for_one)
        getNextSqrtPriceFromAmount0RoundingUp(sqrt_price_x96, liquidity, amount_in, true)
    else
        getNextSqrtPriceFromAmount1RoundingDown(sqrt_price_x96, liquidity, amount_in, true);
}

/// Get next sqrt price from output amount.
pub fn getNextSqrtPriceFromOutput(sqrt_price_x96: u256, liquidity: u128, amount_out: u256, zero_for_one: bool) ?u256 {
    if (sqrt_price_x96 == 0) return null;
    if (liquidity == 0) return null;

    return if (zero_for_one)
        getNextSqrtPriceFromAmount1RoundingDown(sqrt_price_x96, liquidity, amount_out, false)
    else
        getNextSqrtPriceFromAmount0RoundingUp(sqrt_price_x96, liquidity, amount_out, false);
}

// ============================================================================
// SwapMath
// ============================================================================

pub const SwapStepResult = struct {
    sqrt_ratio_next_x96: u256,
    amount_in: u256,
    amount_out: u256,
    fee_amount: u256,
};

/// Compute a single swap step within one tick range.
/// Port of Uniswap V3 SwapMath.computeSwapStep.
pub fn computeSwapStep(
    sqrt_ratio_current_x96: u256,
    sqrt_ratio_target_x96: u256,
    liquidity: u128,
    amount_remaining: i256,
    fee_pips: u24, // e.g. 3000 = 0.3%
) SwapStepResult {
    const zero_for_one = sqrt_ratio_current_x96 >= sqrt_ratio_target_x96;
    const exact_in = amount_remaining >= 0;

    var sqrt_ratio_next_x96: u256 = 0;
    var amount_in: u256 = 0;
    var amount_out: u256 = 0;
    var fee_amount: u256 = 0;

    if (exact_in) {
        const amount_remaining_u: u256 = @intCast(amount_remaining);
        const amount_remaining_less_fee = mulDiv(amount_remaining_u, 1_000_000 - @as(u256, fee_pips), 1_000_000) orelse 0;

        amount_in = if (zero_for_one)
            getAmount0Delta(sqrt_ratio_target_x96, sqrt_ratio_current_x96, liquidity, true) orelse 0
        else
            getAmount1Delta(sqrt_ratio_current_x96, sqrt_ratio_target_x96, liquidity, true) orelse 0;

        if (amount_remaining_less_fee >= amount_in) {
            sqrt_ratio_next_x96 = sqrt_ratio_target_x96;
        } else {
            sqrt_ratio_next_x96 = getNextSqrtPriceFromInput(
                sqrt_ratio_current_x96,
                liquidity,
                amount_remaining_less_fee,
                zero_for_one,
            ) orelse sqrt_ratio_current_x96;
        }
    } else {
        // exact_out: amount_remaining is negative
        const neg_amount: u256 = @intCast(-amount_remaining);

        amount_out = if (zero_for_one)
            getAmount1Delta(sqrt_ratio_target_x96, sqrt_ratio_current_x96, liquidity, false) orelse 0
        else
            getAmount0Delta(sqrt_ratio_current_x96, sqrt_ratio_target_x96, liquidity, false) orelse 0;

        if (neg_amount >= amount_out) {
            sqrt_ratio_next_x96 = sqrt_ratio_target_x96;
        } else {
            sqrt_ratio_next_x96 = getNextSqrtPriceFromOutput(
                sqrt_ratio_current_x96,
                liquidity,
                neg_amount,
                zero_for_one,
            ) orelse sqrt_ratio_current_x96;
        }
    }

    const max = sqrt_ratio_target_x96 == sqrt_ratio_next_x96;

    // Recalculate amounts based on whether we hit the target
    if (zero_for_one) {
        if (!(max and exact_in)) {
            amount_in = getAmount0Delta(sqrt_ratio_next_x96, sqrt_ratio_current_x96, liquidity, true) orelse 0;
        }
        if (!(max and !exact_in)) {
            amount_out = getAmount1Delta(sqrt_ratio_next_x96, sqrt_ratio_current_x96, liquidity, false) orelse 0;
        }
    } else {
        if (!(max and exact_in)) {
            amount_in = getAmount1Delta(sqrt_ratio_current_x96, sqrt_ratio_next_x96, liquidity, true) orelse 0;
        }
        if (!(max and !exact_in)) {
            amount_out = getAmount0Delta(sqrt_ratio_current_x96, sqrt_ratio_next_x96, liquidity, false) orelse 0;
        }
    }

    // Cap output amount to not exceed remaining output amount
    if (!exact_in) {
        const neg_amount: u256 = @intCast(-amount_remaining);
        if (amount_out > neg_amount) {
            amount_out = neg_amount;
        }
    }

    // Fee computation
    if (exact_in and sqrt_ratio_next_x96 != sqrt_ratio_target_x96) {
        // Didn't reach target: remainder of input goes to fee
        const amount_remaining_u: u256 = @intCast(amount_remaining);
        fee_amount = amount_remaining_u - amount_in;
    } else {
        fee_amount = mulDivRoundingUp(amount_in, @as(u256, fee_pips), 1_000_000 - @as(u256, fee_pips)) orelse 0;
    }

    return .{
        .sqrt_ratio_next_x96 = sqrt_ratio_next_x96,
        .amount_in = amount_in,
        .amount_out = amount_out,
        .fee_amount = fee_amount,
    };
}

// ============================================================================
// Tick-crossing simulation
// ============================================================================

pub const TickInfo = struct {
    tick: i24,
    liquidity_net: i128,
    sqrt_price_x96: u256, // precomputed getSqrtRatioAtTick(tick)
};

pub const SwapResult = struct {
    amount_in_consumed: u256,
    amount_out: u256,
    sqrt_price_final_x96: u256,
    ticks_crossed: usize,
};

/// Simulate a full swap across multiple ticks.
/// ticks must be sorted (ascending for !zero_for_one, descending for zero_for_one).
pub fn simulateSwap(
    sqrt_price_x96: u256,
    liquidity: u128,
    ticks: []const TickInfo,
    amount_in: u256,
    zero_for_one: bool,
    fee_pips: u24,
) SwapResult {
    var current_sqrt_price: u256 = sqrt_price_x96;
    var current_liquidity: u128 = liquidity;
    var amount_remaining: u256 = amount_in;
    var total_amount_out: u256 = 0;
    var ticks_crossed: usize = 0;

    for (ticks) |tick_info| {
        if (amount_remaining == 0) break;

        const step = computeSwapStep(
            current_sqrt_price,
            tick_info.sqrt_price_x96,
            current_liquidity,
            @as(i256, @intCast(amount_remaining)), // exact_in (positive)
            fee_pips,
        );

        // Deduct consumed amount + fee from remaining
        const consumed = step.amount_in + step.fee_amount;
        if (consumed >= amount_remaining) {
            amount_remaining = 0;
        } else {
            amount_remaining -= consumed;
        }
        total_amount_out += step.amount_out;
        current_sqrt_price = step.sqrt_ratio_next_x96;

        // If we reached the tick boundary, update liquidity
        if (current_sqrt_price == tick_info.sqrt_price_x96) {
            if (zero_for_one) {
                // Moving left: subtract liquidity_net
                if (tick_info.liquidity_net < 0) {
                    current_liquidity += @as(u128, @abs(tick_info.liquidity_net));
                } else {
                    const net_u: u128 = @intCast(tick_info.liquidity_net);
                    if (net_u > current_liquidity) {
                        current_liquidity = 0;
                    } else {
                        current_liquidity -= net_u;
                    }
                }
            } else {
                // Moving right: add liquidity_net
                if (tick_info.liquidity_net >= 0) {
                    current_liquidity += @intCast(tick_info.liquidity_net);
                } else {
                    const net_u: u128 = @abs(tick_info.liquidity_net);
                    if (net_u > current_liquidity) {
                        current_liquidity = 0;
                    } else {
                        current_liquidity -= net_u;
                    }
                }
            }
            ticks_crossed += 1;
        }
    }

    return .{
        .amount_in_consumed = amount_in - amount_remaining,
        .amount_out = total_amount_out,
        .sqrt_price_final_x96 = current_sqrt_price,
        .ticks_crossed = ticks_crossed,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "getSqrtRatioAtTick(0) == Q96" {
    // tick 0 = price 1.0, sqrtPrice = 1.0 * 2^96
    try std.testing.expectEqual(Q96, getSqrtRatioAtTick(0).?);
}

test "getSqrtRatioAtTick(MIN_TICK) == MIN_SQRT_RATIO" {
    try std.testing.expectEqual(MIN_SQRT_RATIO, getSqrtRatioAtTick(MIN_TICK).?);
}

test "getSqrtRatioAtTick(MAX_TICK) == MAX_SQRT_RATIO" {
    try std.testing.expectEqual(MAX_SQRT_RATIO, getSqrtRatioAtTick(MAX_TICK).?);
}

test "getSqrtRatioAtTick out of range" {
    try std.testing.expectEqual(@as(?u256, null), getSqrtRatioAtTick(MIN_TICK - 1));
    try std.testing.expectEqual(@as(?u256, null), getSqrtRatioAtTick(MAX_TICK + 1));
}

test "getTickAtSqrtRatio roundtrip" {
    // Test various ticks. Note: MAX_TICK is excluded because getSqrtRatioAtTick(MAX_TICK) == MAX_SQRT_RATIO,
    // which is outside getTickAtSqrtRatio's domain [MIN_SQRT_RATIO, MAX_SQRT_RATIO).
    const test_ticks = [_]i24{ 0, 1, -1, 100, -100, -887272, 50, -50, 10000, -10000, 887271 };
    for (test_ticks) |tick| {
        const sqrt_ratio = getSqrtRatioAtTick(tick).?;
        const recovered_tick = getTickAtSqrtRatio(sqrt_ratio).?;
        try std.testing.expectEqual(tick, recovered_tick);
    }
}

test "getTickAtSqrtRatio boundary" {
    try std.testing.expectEqual(@as(?i24, null), getTickAtSqrtRatio(MIN_SQRT_RATIO - 1));
    try std.testing.expectEqual(@as(?i24, null), getTickAtSqrtRatio(MAX_SQRT_RATIO));
}

test "getAmount0Delta known value" {
    // Known V3 test vector: liquidity = 1e18, price range 1.0 to 1.01
    const sqrt_a = getSqrtRatioAtTick(0).?; // price 1.0
    const sqrt_b = getSqrtRatioAtTick(100).?; // price ~1.01
    const result = getAmount0Delta(sqrt_a, sqrt_b, 1_000_000_000_000_000_000, true);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "getAmount1Delta known value" {
    const sqrt_a = getSqrtRatioAtTick(0).?;
    const sqrt_b = getSqrtRatioAtTick(100).?;
    const result = getAmount1Delta(sqrt_a, sqrt_b, 1_000_000_000_000_000_000, true);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "getAmount0Delta symmetry" {
    // getAmount0Delta(a, b, ...) == getAmount0Delta(b, a, ...) (auto-sorts)
    const sqrt_a = getSqrtRatioAtTick(0).?;
    const sqrt_b = getSqrtRatioAtTick(100).?;
    const liq: u128 = 1_000_000_000_000_000_000;
    const result1 = getAmount0Delta(sqrt_a, sqrt_b, liq, true);
    const result2 = getAmount0Delta(sqrt_b, sqrt_a, liq, true);
    try std.testing.expectEqual(result1, result2);
}

test "getAmount1Delta symmetry" {
    const sqrt_a = getSqrtRatioAtTick(0).?;
    const sqrt_b = getSqrtRatioAtTick(100).?;
    const liq: u128 = 1_000_000_000_000_000_000;
    const result1 = getAmount1Delta(sqrt_a, sqrt_b, liq, true);
    const result2 = getAmount1Delta(sqrt_b, sqrt_a, liq, true);
    try std.testing.expectEqual(result1, result2);
}

test "getNextSqrtPriceFromInput zero_for_one" {
    const current = getSqrtRatioAtTick(0).?;
    const liq: u128 = 1_000_000_000_000_000_000;
    const result = getNextSqrtPriceFromInput(current, liq, 100_000, true);
    try std.testing.expect(result != null);
    // Selling token0 should decrease price
    try std.testing.expect(result.? < current);
}

test "getNextSqrtPriceFromInput !zero_for_one" {
    const current = getSqrtRatioAtTick(0).?;
    const liq: u128 = 1_000_000_000_000_000_000;
    const result = getNextSqrtPriceFromInput(current, liq, 100_000, false);
    try std.testing.expect(result != null);
    // Selling token1 should increase price
    try std.testing.expect(result.? > current);
}

test "getNextSqrtPriceFromOutput" {
    const current = getSqrtRatioAtTick(0).?;
    const liq: u128 = 1_000_000_000_000_000_000;
    // zero_for_one output: buying token1
    const result = getNextSqrtPriceFromOutput(current, liq, 100_000, true);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? < current);
}

test "computeSwapStep exact input within range" {
    // Simple swap that stays within one tick range
    const current = getSqrtRatioAtTick(0).?;
    const target = getSqrtRatioAtTick(-100).?;
    const result = computeSwapStep(current, target, 1_000_000_000_000_000_000, 100_000, 3000);
    try std.testing.expect(result.amount_in > 0);
    try std.testing.expect(result.amount_out > 0);
    try std.testing.expect(result.fee_amount > 0);
}

test "computeSwapStep exact output" {
    const current = getSqrtRatioAtTick(0).?;
    const target = getSqrtRatioAtTick(-100).?;
    // Negative amount_remaining means exact output
    const result = computeSwapStep(current, target, 1_000_000_000_000_000_000, -50_000, 3000);
    try std.testing.expect(result.amount_in > 0);
    try std.testing.expect(result.amount_out > 0);
}

test "computeSwapStep hits target exactly" {
    // Small amount that can fully consume to target
    const current = getSqrtRatioAtTick(0).?;
    const target = getSqrtRatioAtTick(-1).?;
    const liq: u128 = 100; // very small liquidity
    // Very large input should hit the target
    const result = computeSwapStep(current, target, liq, 1_000_000_000_000_000_000, 3000);
    try std.testing.expectEqual(target, result.sqrt_ratio_next_x96);
}

test "simulateSwap basic" {
    const current_tick: i24 = 0;
    const current_sqrt_price = getSqrtRatioAtTick(current_tick).?;
    const liq: u128 = 1_000_000_000_000_000_000;

    // Set up two ticks below current price (for zero_for_one swap)
    const tick1: i24 = -100;
    const tick2: i24 = -200;
    const ticks = [_]TickInfo{
        .{
            .tick = tick1,
            .liquidity_net = 500_000_000_000_000_000,
            .sqrt_price_x96 = getSqrtRatioAtTick(tick1).?,
        },
        .{
            .tick = tick2,
            .liquidity_net = 500_000_000_000_000_000,
            .sqrt_price_x96 = getSqrtRatioAtTick(tick2).?,
        },
    };

    const result = simulateSwap(
        current_sqrt_price,
        liq,
        &ticks,
        1_000_000,
        true, // zero_for_one
        3000, // 0.3% fee
    );

    try std.testing.expect(result.amount_in_consumed > 0);
    try std.testing.expect(result.amount_out > 0);
    try std.testing.expect(result.sqrt_price_final_x96 < current_sqrt_price);
}

test "simulateSwap zero amount" {
    const current_sqrt_price = getSqrtRatioAtTick(0).?;
    const ticks = [_]TickInfo{};

    const result = simulateSwap(
        current_sqrt_price,
        1_000_000_000_000_000_000,
        &ticks,
        0,
        true,
        3000,
    );

    try std.testing.expectEqual(@as(u256, 0), result.amount_in_consumed);
    try std.testing.expectEqual(@as(u256, 0), result.amount_out);
    try std.testing.expectEqual(@as(usize, 0), result.ticks_crossed);
}

test "mulDivRoundingUp basic" {
    // 7 * 1 / 2 = 3.5 -> rounds up to 4
    try std.testing.expectEqual(@as(?u256, 4), mulDivRoundingUp(7, 1, 2));
    // 6 * 1 / 2 = 3.0 -> exact, no rounding
    try std.testing.expectEqual(@as(?u256, 3), mulDivRoundingUp(6, 1, 2));
    // div by zero
    try std.testing.expectEqual(@as(?u256, null), mulDivRoundingUp(1, 1, 0));
}

test "getTickAtSqrtRatio known values" {
    // MIN_SQRT_RATIO should give MIN_TICK
    try std.testing.expectEqual(@as(?i24, MIN_TICK), getTickAtSqrtRatio(MIN_SQRT_RATIO));
    // MAX_SQRT_RATIO - 1 should give MAX_TICK - 1
    const result = getTickAtSqrtRatio(MAX_SQRT_RATIO - 1);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(i24, MAX_TICK - 1), result.?);
}

test "getSqrtRatioAtTick monotonic" {
    // Verify that higher ticks produce higher sqrt ratios
    var prev: u256 = 0;
    const test_ticks = [_]i24{ -887272, -10000, -1000, -100, -10, -1, 0, 1, 10, 100, 1000, 10000, 887272 };
    for (test_ticks) |tick| {
        const ratio = getSqrtRatioAtTick(tick).?;
        try std.testing.expect(ratio > prev);
        prev = ratio;
    }
}
