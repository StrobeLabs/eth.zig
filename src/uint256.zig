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
    var q: [4]u64 = .{ 0, 0, 0, 0 };
    var rem: u128 = 0;
    var i: usize = nn;
    while (i > 0) {
        i -= 1;
        rem = (rem << 64) | num[i];
        q[i] = @truncate(rem / d);
        rem %= d;
    }
    return limbsToU256(q);
}

fn divLimbs(numerator: u256, divisor: u256) u256 {
    const num = u256ToLimbs(numerator);
    const div = u256ToLimbs(divisor);
    const nn = countLimbs(num);
    const dd = countLimbs(div);

    if (dd == 1) return divSingleLimb(num, nn, div[0]);

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

    return limbsToU256(q);
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
