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

/// Fast u256 division using u64-limb schoolbook algorithm.
/// Avoids LLVM's slow generic u256 runtime library calls (~280ns)
/// by using native u64/u128 operations (~10-30ns).
pub fn fastDiv(a: u256, b: u256) u256 {
    if (b == 0) @panic("division by zero");
    // Both fit in u128 - use LLVM's native 128-bit division
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return @as(u128, @truncate(a)) / @as(u128, @truncate(b));
    }
    if (a < b) return 0;
    if (a == b) return 1;
    return divLimbs(a, b);
}

// ---- u64-limb division (Knuth Algorithm D) ----

fn u256ToLimbs(v: u256) [4]u64 {
    return .{
        @truncate(v),
        @truncate(v >> 64),
        @truncate(v >> 128),
        @truncate(v >> 192),
    };
}

fn limbsToU256(l: [4]u64) u256 {
    return @as(u256, l[3]) << 192 |
        @as(u256, l[2]) << 128 |
        @as(u256, l[1]) << 64 |
        @as(u256, l[0]);
}

fn countLimbs(limbs: [4]u64) usize {
    var n: usize = 4;
    while (n > 0 and limbs[n - 1] == 0) n -= 1;
    return n;
}

fn divSingleLimb(num: [4]u64, nn: usize, d: u64) u256 {
    return limbsToU256(divSingleLimbRaw(num, nn, d));
}

fn divSingleLimbRaw(num: [4]u64, nn: usize, d: u64) [4]u64 {
    var q: [4]u64 = .{ 0, 0, 0, 0 };
    var rem: u128 = 0;
    var i: usize = nn;
    while (i > 0) {
        i -= 1;
        rem = (rem << 64) | num[i];
        q[i] = @truncate(rem / d);
        rem %= d;
    }
    return q;
}

fn divLimbs(numerator: u256, divisor: u256) u256 {
    return limbsToU256(divLimbsRaw(u256ToLimbs(numerator), u256ToLimbs(divisor)));
}

fn divLimbsRaw(num: [4]u64, div: [4]u64) [4]u64 {
    const nn = countLimbs(num);
    const dd = countLimbs(div);

    if (dd == 1) return divSingleLimbRaw(num, nn, div[0]);

    // Knuth Algorithm D: normalize so top bit of divisor's top limb is set
    const s: u6 = @intCast(@clz(div[dd - 1]));

    var v: [4]u64 = .{ 0, 0, 0, 0 };
    var u_arr: [5]u64 = .{ 0, 0, 0, 0, 0 };

    if (s > 0) {
        const rs: u6 = @intCast(@as(u7, 64) - s);
        // Shift divisor
        var i: usize = dd;
        while (i > 1) {
            i -= 1;
            v[i] = (div[i] << s) | (div[i - 1] >> rs);
        }
        v[0] = div[0] << s;
        // Shift numerator (may produce extra limb)
        u_arr[nn] = num[nn - 1] >> rs;
        i = nn;
        while (i > 1) {
            i -= 1;
            u_arr[i] = (num[i] << s) | (num[i - 1] >> rs);
        }
        u_arr[0] = num[0] << s;
    } else {
        for (0..dd) |i| v[i] = div[i];
        for (0..nn) |i| u_arr[i] = num[i];
    }

    // Main loop: produce quotient digits from MSB to LSB
    var q: [4]u64 = .{ 0, 0, 0, 0 };
    var j: usize = nn - dd + 1;
    while (j > 0) {
        j -= 1;

        // Trial quotient from top two limbs of current remainder
        const hi2: u128 = (@as(u128, u_arr[j + dd]) << 64) | u_arr[j + dd - 1];
        var qhat: u128 = hi2 / v[dd - 1];
        var rhat: u128 = hi2 % v[dd - 1];

        // Refine: ensures qhat is exact or at most 1 too large
        while (true) {
            if (qhat >= (@as(u128, 1) << 64) or
                qhat * v[dd - 2] > (rhat << 64) | u_arr[j + dd - 2])
            {
                qhat -= 1;
                rhat += v[dd - 1];
                if (rhat >= (@as(u128, 1) << 64)) break;
            } else break;
        }

        // Multiply qhat * v and subtract from u_arr[j..j+dd]
        var prod: [5]u64 = .{ 0, 0, 0, 0, 0 };
        var carry: u128 = 0;
        for (0..dd) |i| {
            carry += qhat * v[i];
            prod[i] = @truncate(carry);
            carry >>= 64;
        }
        prod[dd] = @truncate(carry);

        var borrow: u1 = 0;
        for (0..dd + 1) |i| {
            const s1 = @subWithOverflow(u_arr[j + i], prod[i]);
            const s2 = @subWithOverflow(s1[0], @as(u64, borrow));
            u_arr[j + i] = s2[0];
            borrow = s1[1] | s2[1];
        }

        // Add back if qhat was 1 too large (rare)
        if (borrow != 0) {
            qhat -= 1;
            var c: u1 = 0;
            for (0..dd) |i| {
                const a1 = @addWithOverflow(u_arr[j + i], v[i]);
                const a2 = @addWithOverflow(a1[0], @as(u64, c));
                u_arr[j + i] = a2[0];
                c = a1[1] | a2[1];
            }
            u_arr[j + dd] +%= @as(u64, c);
        }

        q[j] = @truncate(qhat);
    }

    return q;
}

/// Fast u256 multiplication that uses narrower operations when values fit.
/// This avoids LLVM's slow generic 256-bit multiplication for common cases.
pub fn fastMul(a: u256, b: u256) u256 {
    // Both fit in u128 - use LLVM's faster 128-bit multiplication
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return @as(u256, @as(u128, @truncate(a))) *% @as(u256, @as(u128, @truncate(b)));
    }
    // Full u256 multiplication for large values
    return a *% b;
}

/// Full-precision multiply-then-divide: (a * b) / denominator.
/// Uses a 512-bit intermediate to avoid overflow. This is the core primitive
/// used by UniswapV3/V4 (Solidity's FullMath.mulDiv).
/// Returns null on division by zero or if the result overflows u256.
pub fn mulDiv(a: u256, b: u256, denominator: u256) ?u256 {
    if (denominator == 0) return null;

    // Fast path: both fit in u128, product fits in u256 -- no overflow possible
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return fastDiv(fastMul(a, b), denominator);
    }

    // Medium path: if a * b doesn't overflow u256, use direct division
    const ov = @mulWithOverflow(a, b);
    if (ov[1] == 0) {
        return fastDiv(ov[0], denominator);
    }

    // 512-bit multiplication using 4 u128 limbs
    // a = a_hi * 2^128 + a_lo, b = b_hi * 2^128 + b_lo
    const a_lo: u256 = @as(u128, @truncate(a));
    const a_hi: u256 = a >> 128;
    const b_lo: u256 = @as(u128, @truncate(b));
    const b_hi: u256 = b >> 128;

    // Partial products (each fits in u256)
    const p0 = a_lo * b_lo; // low * low
    const p1 = a_lo * b_hi; // low * high
    const p2 = a_hi * b_lo; // high * low
    const p3 = a_hi * b_hi; // high * high

    // Accumulate into [r_hi:r_lo] (512 bits)
    // r_lo = p0 + (lower 128 bits of p1+p2) << 128
    // r_hi = p3 + (upper 128 bits of p1+p2) + carry from r_lo
    const mid_sum = @addWithOverflow(p1, p2);
    const mid: u256 = mid_sum[0];
    const mid_carry: u256 = @as(u256, mid_sum[1]) << 128; // carry is worth 2^256

    const mid_lo: u256 = @as(u128, @truncate(mid));
    const mid_hi: u256 = mid >> 128;

    const r_lo_sum = @addWithOverflow(p0, mid_lo << 128);
    const r_lo: u256 = r_lo_sum[0];
    const r_lo_carry: u256 = r_lo_sum[1];

    const r_hi: u256 = p3 +% mid_hi +% mid_carry +% r_lo_carry;

    // Now divide [r_hi:r_lo] by denominator
    // If r_hi >= denominator, result overflows u256
    if (r_hi >= denominator) return null;

    // Long division: [r_hi:r_lo] / denominator
    if (r_hi == 0) {
        return fastDiv(r_lo, denominator);
    }

    // Binary long division of 512-bit / 256-bit
    var quotient: u256 = 0;
    var remainder: u256 = r_hi;

    // Process r_lo from MSB to LSB, 1 bit at a time
    var i: u9 = 256;
    while (i > 0) {
        i -= 1;
        // Shift remainder left by 1 and bring in next bit from r_lo
        const bit: u256 = (r_lo >> @intCast(i)) & 1;
        const shifted = @shlWithOverflow(remainder, 1);
        if (shifted[1] != 0 or (shifted[0] | bit) >= denominator) {
            remainder = (shifted[0] | bit) -% denominator;
            quotient |= @as(u256, 1) << @intCast(i);
        } else {
            remainder = shifted[0] | bit;
        }
    }

    return quotient;
}

/// Q96 constant (2^96) used in UniswapV3/V4 fixed-point arithmetic.
pub const Q96: u256 = @as(u256, 1) << 96;

/// Maximum u256 value.
pub const MAX: u256 = std.math.maxInt(u256);

/// Zero value.
pub const ZERO: u256 = 0;

/// One value.
pub const ONE: u256 = 1;

// ============================================================================
// U256Limb: limb-native u256 for compound arithmetic
// ============================================================================

/// A u256 stored as 4 u64 limbs (little-endian: limbs[0] is least significant).
/// Provides arithmetic that stays in limb space across operations, avoiding
/// the overhead of u256 <-> u128 conversions that LLVM's native u256 incurs
/// on each operation. Critical for compound DeFi math (UniswapV2 getAmountOut).
pub const U256Limb = struct {
    limbs: [4]u64,

    pub fn fromU256(val: u256) U256Limb {
        return .{ .limbs = u256ToLimbs(val) };
    }

    pub fn toU256(self: U256Limb) u256 {
        return limbsToU256(self.limbs);
    }

    /// Multiply by a small u64 constant (e.g., 997, 1000, 10000).
    /// 4 u64*u64 multiplies with carry chain. This is the critical hot path
    /// for DEX math where u256 values are scaled by small fee constants.
    pub fn mulSmall(self: U256Limb, b: u64) U256Limb {
        var result: [4]u64 = .{ 0, 0, 0, 0 };
        var carry: u64 = 0;
        inline for (0..4) |i| {
            const prod: u128 = @as(u128, self.limbs[i]) * b + carry;
            result[i] = @truncate(prod);
            carry = @intCast(prod >> 64);
        }
        return .{ .limbs = result };
    }

    /// Schoolbook 4x4 limb multiplication, truncated to 256 bits.
    /// 10 u64*u64 multiplies (only lower 4 result limbs needed).
    pub fn mul(self: U256Limb, b: U256Limb) U256Limb {
        const a = self.limbs;
        const bl = b.limbs;
        var result: [4]u64 = .{ 0, 0, 0, 0 };

        // For each source limb pair where i+j < 4
        inline for (0..4) |i| {
            var carry: u64 = 0;
            inline for (0..4) |j| {
                if (i + j < 4) {
                    const prod: u128 = @as(u128, a[i]) * bl[j] + result[i + j] + carry;
                    result[i + j] = @truncate(prod);
                    carry = @intCast(prod >> 64);
                }
            }
        }

        return .{ .limbs = result };
    }

    /// Addition with wrapping (mod 2^256).
    pub fn addWrap(self: U256Limb, b: U256Limb) U256Limb {
        var result: [4]u64 = undefined;
        var carry: u1 = 0;
        inline for (0..4) |i| {
            const s1 = @addWithOverflow(self.limbs[i], b.limbs[i]);
            const s2 = @addWithOverflow(s1[0], @as(u64, carry));
            result[i] = s2[0];
            carry = s1[1] | s2[1];
        }
        return .{ .limbs = result };
    }

    /// Division using Knuth Algorithm D on limbs directly.
    pub fn div(self: U256Limb, b: U256Limb) U256Limb {
        // Check for zero divisor
        if (b.limbs[0] == 0 and b.limbs[1] == 0 and b.limbs[2] == 0 and b.limbs[3] == 0) {
            @panic("division by zero");
        }
        // Quick comparisons
        const cmp = limbCmp(self.limbs, b.limbs);
        if (cmp == .lt) return .{ .limbs = .{ 0, 0, 0, 0 } };
        if (cmp == .eq) return .{ .limbs = .{ 1, 0, 0, 0 } };
        return .{ .limbs = divLimbsRaw(self.limbs, b.limbs) };
    }

    fn limbCmp(a: [4]u64, b: [4]u64) std.math.Order {
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (a[i] < b[i]) return .lt;
            if (a[i] > b[i]) return .gt;
        }
        return .eq;
    }
};

/// Compute UniswapV2 getAmountOut entirely in limb space.
/// amount_out = (amount_in * 997 * reserve_out) / (reserve_in * 1000 + amount_in * 997)
pub fn uniswapV2AmountOut(amount_in: u256, reserve_in: u256, reserve_out: u256) u256 {
    const a = U256Limb.fromU256(amount_in);
    const ri = U256Limb.fromU256(reserve_in);
    const ro = U256Limb.fromU256(reserve_out);
    const a_fee = a.mulSmall(997);
    const num = a_fee.mul(ro);
    const den = ri.mulSmall(1000).addWrap(a_fee);
    return num.div(den).toU256();
}

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

test "fastDiv u256 large values" {
    // Divisor > u128 (exercises Knuth Algorithm D multi-limb path)
    const a: u256 = (@as(u256, 1) << 200) + 12345;
    const b: u256 = (@as(u256, 1) << 130) + 99;
    try std.testing.expectEqual(a / b, fastDiv(a, b));

    // Divisor fits in u64 (exercises single-limb path)
    const c: u256 = (@as(u256, 7_922_816_251_426_433) << 128) | 12345678;
    const d: u256 = 1_000_000_007;
    try std.testing.expectEqual(c / d, fastDiv(c, d));

    // Numerator barely larger than divisor
    const e: u256 = MAX;
    const f: u256 = MAX - 1;
    try std.testing.expectEqual(@as(u256, 1), fastDiv(e, f));

    // Large numerator, 2-limb divisor
    const g: u256 = (@as(u256, 1) << 192) | (@as(u256, 1) << 64);
    const h: u256 = (@as(u256, 1) << 65) + 3;
    try std.testing.expectEqual(g / h, fastDiv(g, h));
}

test "mulDiv basic" {
    // Simple case: no overflow
    try std.testing.expectEqual(@as(?u256, 6), mulDiv(2, 3, 1));
    try std.testing.expectEqual(@as(?u256, 2), mulDiv(6, 1, 3));
    // Divide by zero
    try std.testing.expectEqual(@as(?u256, null), mulDiv(1, 1, 0));
}

test "mulDiv overflow intermediate" {
    // MAX * 2 overflows u256, but MAX * 2 / 2 = MAX
    try std.testing.expectEqual(@as(?u256, MAX), mulDiv(MAX, 2, 2));
    // MAX * MAX / MAX = MAX
    try std.testing.expectEqual(@as(?u256, MAX), mulDiv(MAX, MAX, MAX));
}

test "mulDiv UniswapV4 Q96 style" {
    // Simulates sqrtPriceX96 computation: liquidity * sqrtPrice / denominator
    const liquidity: u256 = 1_000_000_000_000_000_000; // 1e18
    const sqrt_price: u256 = @as(u256, 79228162514264337593543950336); // ~1.0 in Q96
    const denom: u256 = liquidity + 1_000_000;
    const result = mulDiv(liquidity, sqrt_price, denom);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? > 0);
}

test "mulDiv result overflow" {
    // (MAX * MAX) / 1 overflows u256
    try std.testing.expectEqual(@as(?u256, null), mulDiv(MAX, MAX, 1));
}

test "fastDiv power-of-2 divisors" {
    try std.testing.expectEqual(MAX / (@as(u256, 1) << 64), fastDiv(MAX, @as(u256, 1) << 64));
    try std.testing.expectEqual(MAX / (@as(u256, 1) << 128), fastDiv(MAX, @as(u256, 1) << 128));
    try std.testing.expectEqual(MAX / (@as(u256, 1) << 192), fastDiv(MAX, @as(u256, 1) << 192));
}

test "fastDiv 1-limb values" {
    // Both fit in u64
    try std.testing.expectEqual(@as(u256, 142857), fastDiv(1_000_000, 7));
}

test "fastDiv 2-limb numerator 1-limb divisor" {
    const a: u256 = (@as(u256, 1) << 100) + 999;
    const b: u256 = 1_000_000_007;
    try std.testing.expectEqual(a / b, fastDiv(a, b));
}

test "fastDiv identity a / 1" {
    try std.testing.expectEqual(@as(u256, 0), fastDiv(0, 1));
    try std.testing.expectEqual(@as(u256, 1), fastDiv(1, 1));
    try std.testing.expectEqual(MAX, fastDiv(MAX, 1));
}

test "fastDiv identity a / a" {
    try std.testing.expectEqual(@as(u256, 1), fastDiv(1, 1));
    try std.testing.expectEqual(@as(u256, 1), fastDiv(42, 42));
    try std.testing.expectEqual(@as(u256, 1), fastDiv(MAX, MAX));
}

test "mulDiv edge cases" {
    try std.testing.expectEqual(@as(?u256, 0), mulDiv(0, MAX, 1));
    try std.testing.expectEqual(@as(?u256, 1), mulDiv(1, 1, 1));
    try std.testing.expectEqual(@as(?u256, 1), mulDiv(MAX, 1, MAX));
    try std.testing.expectEqual(@as(?u256, 0), mulDiv(0, 0, 1));
}

test "mulDiv Q96 arithmetic" {
    // Identity: Q96 * Q96 / Q96 == Q96
    try std.testing.expectEqual(@as(?u256, Q96), mulDiv(Q96, Q96, Q96));
    // (Q96 * 2) * Q96 / (Q96 * 2) == Q96
    try std.testing.expectEqual(@as(?u256, Q96), mulDiv(Q96 * 2, Q96, Q96 * 2));
}

test "mulDiv large non-overflow" {
    // (1 << 200) * (1 << 55) = 1 << 255 fits in u256
    // (1 << 255) / (1 << 100) = 1 << 155
    const a: u256 = @as(u256, 1) << 200;
    const b: u256 = @as(u256, 1) << 55;
    const d: u256 = @as(u256, 1) << 100;
    try std.testing.expectEqual(@as(?u256, @as(u256, 1) << 155), mulDiv(a, b, d));
}

test "fromHex toHex roundtrip comprehensive" {
    const allocator = std.testing.allocator;
    const values = [_]u256{ 0, 1, 0xFF, 0x100, 0x1234567890abcdef, MAX };
    for (values) |v| {
        const hex_str = try toHex(allocator, v);
        defer allocator.free(hex_str);
        const recovered = try fromHex(hex_str);
        try std.testing.expectEqual(v, recovered);
    }
}

test "fromBigEndianBytes zero" {
    const zero_bytes = [_]u8{0} ** 32;
    try std.testing.expectEqual(@as(u256, 0), fromBigEndianBytes(zero_bytes));
}

test "fromBigEndianBytes and toBigEndianBytes MAX" {
    const bytes = toBigEndianBytes(MAX);
    const recovered = fromBigEndianBytes(bytes);
    try std.testing.expectEqual(MAX, recovered);
}

test "fastMul small values" {
    try std.testing.expectEqual(@as(u256, 20000), fastMul(100, 200));
    try std.testing.expectEqual(@as(u256, 0), fastMul(0, MAX));
    try std.testing.expectEqual(MAX, fastMul(1, MAX));
}

// U256Limb tests

test "U256Limb fromU256/toU256 roundtrip" {
    const values = [_]u256{ 0, 1, 0xFF, 1_000_000_000_000_000_000, MAX };
    for (values) |v| {
        try std.testing.expectEqual(v, U256Limb.fromU256(v).toU256());
    }
}

test "U256Limb mulSmall matches native" {
    const a: u256 = 1_000_000_000_000_000_000;
    const la = U256Limb.fromU256(a);
    try std.testing.expectEqual(a *% 997, la.mulSmall(997).toU256());
    try std.testing.expectEqual(a *% 1000, la.mulSmall(1000).toU256());
    try std.testing.expectEqual(a *% 10000, la.mulSmall(10000).toU256());

    // Large value
    const b: u256 = (@as(u256, 1) << 200) + 999;
    const lb = U256Limb.fromU256(b);
    try std.testing.expectEqual(b *% 997, lb.mulSmall(997).toU256());
}

test "U256Limb mul matches native" {
    const a: u256 = 1_000_000_000_000_000_000;
    const b: u256 = 200_000_000_000;
    const la = U256Limb.fromU256(a);
    const lb = U256Limb.fromU256(b);
    try std.testing.expectEqual(a *% b, la.mul(lb).toU256());

    // Larger values
    const c: u256 = (@as(u256, 1) << 130) + 42;
    const d: u256 = (@as(u256, 1) << 120) + 7;
    const lc = U256Limb.fromU256(c);
    const ld = U256Limb.fromU256(d);
    try std.testing.expectEqual(c *% d, lc.mul(ld).toU256());
}

test "U256Limb addWrap matches native" {
    const a: u256 = 100_000_000_000_000_000_000;
    const b: u256 = 997_000_000_000_000_000_000;
    const la = U256Limb.fromU256(a);
    const lb = U256Limb.fromU256(b);
    try std.testing.expectEqual(a +% b, la.addWrap(lb).toU256());

    // Wrapping case
    const lmax = U256Limb.fromU256(MAX);
    const lone = U256Limb.fromU256(1);
    try std.testing.expectEqual(MAX +% 1, lmax.addWrap(lone).toU256());
}

test "U256Limb div matches fastDiv" {
    const a: u256 = 997_000_000_000_000_000_000;
    const b: u256 = 1_000_000_000_000_000_000;
    const la = U256Limb.fromU256(a);
    const lb = U256Limb.fromU256(b);
    try std.testing.expectEqual(fastDiv(a, b), la.div(lb).toU256());

    // Large values requiring Knuth Algorithm D
    const c: u256 = (@as(u256, 1) << 200) + 12345;
    const d: u256 = (@as(u256, 1) << 130) + 99;
    const lc = U256Limb.fromU256(c);
    const ld = U256Limb.fromU256(d);
    try std.testing.expectEqual(fastDiv(c, d), lc.div(ld).toU256());
}

test "uniswapV2AmountOut correctness" {
    const amount_in: u256 = 1_000_000_000_000_000_000; // 1 ETH
    const reserve_in: u256 = 100_000_000_000_000_000_000; // 100 ETH
    const reserve_out: u256 = 200_000_000_000; // 200k USDC (6 decimals)

    // Compute expected result using native u256
    const amount_in_with_fee = fastMul(amount_in, 997);
    const numerator = fastMul(amount_in_with_fee, reserve_out);
    const denominator = fastMul(reserve_in, 1000) +% amount_in_with_fee;
    const expected = fastDiv(numerator, denominator);

    const result = uniswapV2AmountOut(amount_in, reserve_in, reserve_out);
    try std.testing.expectEqual(expected, result);
}

test "uniswapV2AmountOut edge cases" {
    // Small swap
    const result1 = uniswapV2AmountOut(1000, 1_000_000, 1_000_000);
    try std.testing.expect(result1 > 0);

    // Large reserves
    const result2 = uniswapV2AmountOut(
        1_000_000_000_000_000_000,
        @as(u256, 1_000_000) * 1_000_000_000_000_000_000,
        @as(u256, 2_000_000_000) * 1_000_000,
    );
    try std.testing.expect(result2 > 0);
}
