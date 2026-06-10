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
pub inline fn fastDiv(a: u256, b: u256) u256 {
    if (b == 0) {
        @branchHint(.cold);
        @panic("division by zero");
    }
    // Both fit in u128 - use LLVM's native 128-bit division
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return @as(u128, @truncate(a)) / @as(u128, @truncate(b));
    }
    if (a < b) return 0;
    if (a == b) return 1;
    return divLimbs(a, b);
}

// ---- u64-limb arithmetic ----

pub fn u256ToLimbs(v: u256) [4]u64 {
    return @bitCast(v);
}

pub fn limbsToU256(l: [4]u64) u256 {
    return @bitCast(l);
}

fn countLimbs(limbs: [4]u64) usize {
    var n: usize = 4;
    while (n > 0 and limbs[n - 1] == 0) n -= 1;
    return n;
}

/// Schoolbook 4x4 wrapping multiply on u64 limbs.
/// Only computes the lower 4 limbs (256-bit result).
/// Uses inline for so LLVM sees comptime-known loop bounds and fully unrolls.
pub inline fn mulLimbs(a: [4]u64, b: [4]u64) [4]u64 {
    var r: [4]u64 = .{ 0, 0, 0, 0 };
    // Accumulate partial products a[i]*b[j] into r[i+j] (only where i+j < 4)
    inline for (0..4) |i| {
        var carry: u64 = 0;
        inline for (0..4) |j| {
            if (i + j < 4) {
                const prod: u128 = @as(u128, a[i]) * @as(u128, b[j]) +
                    @as(u128, r[i + j]) + @as(u128, carry);
                r[i + j] = @truncate(prod);
                carry = @truncate(prod >> 64);
            }
        }
    }
    return r;
}

/// Widening 4x4→8 limb multiply. Produces full 512-bit result.
/// Used by mulDiv's overflow path for true 512-bit intermediate arithmetic.
pub inline fn mulWide(a: [4]u64, b: [4]u64) [8]u64 {
    var r: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    inline for (0..4) |i| {
        var carry: u64 = 0;
        inline for (0..4) |j| {
            const prod: u128 = @as(u128, a[i]) * @as(u128, b[j]) +
                @as(u128, r[i + j]) + @as(u128, carry);
            r[i + j] = @truncate(prod);
            carry = @truncate(prod >> 64);
        }
        r[i + 4] = carry;
    }
    return r;
}

/// Multiply [4]u64 limbs by a single u64 scalar (wrapping to 256 bits).
/// Only 4 mul/umulh pairs vs 10 for full 4x4 schoolbook -- 2.5x fewer multiplies.
pub inline fn mulLimbScalar(a: [4]u64, b: u64) [4]u64 {
    var r: [4]u64 = undefined;
    var carry: u64 = 0;
    inline for (0..4) |i| {
        const prod: u128 = @as(u128, a[i]) * @as(u128, b) + @as(u128, carry);
        r[i] = @truncate(prod);
        carry = @truncate(prod >> 64);
    }
    return r;
}

/// Carry-propagated addition on u64 limbs (wrapping).
pub inline fn addLimbs(a: [4]u64, b: [4]u64) [4]u64 {
    var r: [4]u64 = undefined;
    var carry: u1 = 0;
    inline for (0..4) |i| {
        const s1 = @addWithOverflow(a[i], b[i]);
        const s2 = @addWithOverflow(s1[0], @as(u64, carry));
        r[i] = s2[0];
        carry = s1[1] | s2[1];
    }
    return r;
}

/// 128-bit / 64-bit division using half-word approach (Hacker's Delight divlu).
/// Uses 2 hardware 64-bit UDIV instructions instead of __udivti3 software routine.
/// Requires: u1 < d (quotient fits in u64).
/// Returns: quotient and remainder.
fn div128by64(n_hi: u64, n_lo: u64, d: u64) struct { q: u64, r: u64 } {
    const b: u64 = 1 << 32;

    // Normalize: shift so top bit of divisor is set
    const s: u6 = @intCast(@clz(d));
    const v = d << s;
    const vn1 = v >> 32;
    const vn0 = v & 0xFFFF_FFFF;

    // Shift numerator by same amount
    const un32 = if (s > 0) (n_hi << s) | (n_lo >> @intCast(@as(u7, 64) - s)) else n_hi;
    const un10 = n_lo << s;
    const un1 = un10 >> 32;
    const un0 = un10 & 0xFFFF_FFFF;

    // First quotient digit (high 32 bits)
    var q1 = un32 / vn1;
    var rhat = un32 % vn1;

    while (q1 >= b or q1 * vn0 > (rhat << 32) + un1) {
        q1 -= 1;
        rhat += vn1;
        if (rhat >= b) break;
    }

    const un21 = un32 *% b +% un1 -% q1 *% v;

    // Second quotient digit (low 32 bits)
    var q0 = un21 / vn1;
    rhat = un21 % vn1;

    while (q0 >= b or q0 * vn0 > (rhat << 32) + un0) {
        q0 -= 1;
        rhat += vn1;
        if (rhat >= b) break;
    }

    return .{
        .q = q1 * b + q0,
        .r = (un21 *% b +% un0 -% q0 *% v) >> s,
    };
}

/// Specialized 128-by-128 division (2-limb / 2-limb). Quotient fits in u64.
/// Avoids Knuth D's runtime-loop array overhead by operating on registers directly.
inline fn div2by2(n0: u64, n1: u64, d0: u64, d1: u64) u64 {
    const s: u6 = @intCast(@clz(d1));

    // Normalized divisor
    var nv1: u64 = d1;
    var nv0: u64 = d0;
    // Normalized numerator (3 limbs)
    var nu2: u64 = 0;
    var nu1: u64 = n1;
    var nu0: u64 = n0;

    if (s > 0) {
        const rs: u6 = @intCast(@as(u7, 64) - s);
        nv1 = (d1 << s) | (d0 >> rs);
        nv0 = d0 << s;
        nu2 = n1 >> rs;
        nu1 = (n1 << s) | (n0 >> rs);
        nu0 = n0 << s;
    }

    // Trial quotient via div128by64
    const result = div128by64(nu2, nu1, nv1);
    var qhat: u128 = result.q;
    var rhat: u128 = result.r;

    // Refine with second divisor limb
    while (qhat >= (@as(u128, 1) << 64) or
        qhat * @as(u128, nv0) > (rhat << 64) | @as(u128, nu0))
    {
        qhat -= 1;
        rhat += nv1;
        if (rhat >= (@as(u128, 1) << 64)) break;
    }

    // Multiply-back check: qhat * [nv1,nv0] must not exceed [nu2,nu1,nu0]
    // After refinement, correction probability is ~2/2^64, but include for correctness.
    const p_lo: u128 = qhat * @as(u128, nv0);
    const p_mid: u128 = qhat * @as(u128, nv1) + (p_lo >> 64);
    const prod0: u64 = @truncate(p_lo);
    const prod1: u64 = @truncate(p_mid);
    const prod2: u64 = @truncate(p_mid >> 64);

    // Subtract product from normalized numerator
    const sb1 = @subWithOverflow(nu0, prod0);
    const sb2 = @subWithOverflow(nu1, prod1);
    const sb3 = @subWithOverflow(sb2[0], @as(u64, sb1[1]));
    const borrow = sb2[1] | sb3[1];
    const diff2 = nu2 -% prod2 -% @as(u64, borrow);

    // If underflow, qhat was 1 too large (extremely rare)
    if (diff2 != 0) {
        @branchHint(.cold);
        return @truncate(qhat - 1);
    }
    return @truncate(qhat);
}

/// Knuth Algorithm D core: multi-limb division using div128by64 for trial quotients.
/// Shared by both divLimbsDirect and divLimbs.
/// Requires dd >= 2 and nn >= dd. Returns quotient as [4]u64.
fn knuthDivCore(num: [4]u64, nn: usize, div: [4]u64, dd: usize) [4]u64 {
    // Normalize so top bit of divisor's top limb is set
    const s: u6 = @intCast(@clz(div[dd - 1]));

    var v: [4]u64 = .{ 0, 0, 0, 0 };
    var u_arr: [5]u64 = .{ 0, 0, 0, 0, 0 };

    if (s > 0) {
        const rs: u6 = @intCast(@as(u7, 64) - s);
        var i: usize = dd;
        while (i > 1) {
            i -= 1;
            v[i] = (div[i] << s) | (div[i - 1] >> rs);
        }
        v[0] = div[0] << s;
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

        // Trial quotient using div128by64 (avoids __udivti3)
        const result = div128by64(u_arr[j + dd], u_arr[j + dd - 1], v[dd - 1]);
        var qhat: u128 = result.q;
        var rhat: u128 = result.r;

        // Refine with second divisor limb
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

        // Add back if qhat was 1 too large (probability ~2/2^64)
        if (borrow != 0) {
            @branchHint(.cold);
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

/// Division on limbs, returning [4]u64 directly (avoids u256 round-trip).
/// Uses div128by64 (hardware UDIV) for single-limb divisors and knuthDivCore for multi-limb.
pub fn divLimbsDirect(numerator: [4]u64, divisor: [4]u64) [4]u64 {
    const nn = countLimbs(numerator);
    const dd = countLimbs(divisor);
    if (dd == 0) @panic("division by zero");

    // Compare: if numerator < divisor, return 0
    {
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            if (numerator[i] != divisor[i]) {
                if (numerator[i] < divisor[i]) return .{ 0, 0, 0, 0 };
                break;
            }
        }
    }
    if (dd == 1) {
        // Single-limb divisor: use div128by64 for each quotient digit
        var q: [4]u64 = .{ 0, 0, 0, 0 };
        var rem: u64 = 0;
        var i: usize = nn;
        while (i > 0) {
            i -= 1;
            const result = div128by64(rem, numerator[i], divisor[0]);
            q[i] = result.q;
            rem = result.r;
        }
        return q;
    }

    // Fast path: 2-limb / 2-limb -- inline specialized division (no array overhead)
    if (dd == 2 and nn <= 2) {
        return .{ div2by2(numerator[0], numerator[1], divisor[0], divisor[1]), 0, 0, 0 };
    }

    return knuthDivCore(numerator, nn, divisor, dd);
}

fn divSingleLimb(num: [4]u64, nn: usize, d: u64) u256 {
    var q: [4]u64 = .{ 0, 0, 0, 0 };
    var rem: u64 = 0;
    var i: usize = nn;
    while (i > 0) {
        i -= 1;
        const result = div128by64(rem, num[i], d);
        q[i] = result.q;
        rem = result.r;
    }
    return limbsToU256(q);
}

fn divLimbs(numerator: u256, divisor: u256) u256 {
    const num = u256ToLimbs(numerator);
    const div = u256ToLimbs(divisor);
    const nn = countLimbs(num);
    const dd = countLimbs(div);

    if (dd == 1) return divSingleLimb(num, nn, div[0]);

    return limbsToU256(knuthDivCore(num, nn, div, dd));
}

/// Divide [8]u64 numerator by [4]u64 divisor, returning [4]u64 quotient.
/// Returns null if result overflows u256 (high 4 limbs >= divisor).
/// Uses Knuth Algorithm D for multi-limb division (replaces binary long division).
fn divWide(num: [8]u64, div: [4]u64) ?[4]u64 {
    const dd = countLimbs(div);
    if (dd == 0) return null;

    var nn: usize = 8;
    while (nn > 0 and num[nn - 1] == 0) nn -= 1;
    if (nn == 0) return .{ 0, 0, 0, 0 };

    // If numerator fits in 4 limbs, use regular division
    if (nn <= 4) {
        const lo = [4]u64{ num[0], num[1], num[2], num[3] };
        return divLimbsDirect(lo, div);
    }

    // Check overflow: if high part >= divisor, result > u256
    // This means the quotient would need more than 4 limbs
    if (nn - dd >= 4) {
        // More than 4 quotient digits possible -- check if highest actually needed
        // If nn > dd + 4, definitely overflows
        if (nn > dd + 4) return null;
        // nn == dd + 4: need to check if quotient fits in 4 limbs
        // (handled by the division itself -- if q[4+] != 0, overflow)
    }

    if (dd == 1) {
        // Single-limb divisor fast path
        var q: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
        var rem: u64 = 0;
        var i: usize = nn;
        while (i > 0) {
            i -= 1;
            const result = div128by64(rem, num[i], div[0]);
            q[i] = result.q;
            rem = result.r;
        }
        // Check overflow: quotient must fit in 4 limbs
        if (q[4] != 0 or q[5] != 0 or q[6] != 0 or q[7] != 0) return null;
        return .{ q[0], q[1], q[2], q[3] };
    }

    // Full Knuth Algorithm D with extended arrays for 8-limb numerator
    const s: u6 = @intCast(@clz(div[dd - 1]));

    var v: [4]u64 = .{ 0, 0, 0, 0 };
    var u_arr: [9]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    // Normalize: shift divisor and numerator left by s bits
    if (s > 0) {
        const rs: u6 = @intCast(@as(u7, 64) - s);
        var i: usize = dd;
        while (i > 1) {
            i -= 1;
            v[i] = (div[i] << s) | (div[i - 1] >> rs);
        }
        v[0] = div[0] << s;
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
    var q: [8]u64 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    var j: usize = nn - dd + 1;
    while (j > 0) {
        j -= 1;

        const result = div128by64(u_arr[j + dd], u_arr[j + dd - 1], v[dd - 1]);
        var qhat: u128 = result.q;
        var rhat: u128 = result.r;

        // Refine with second divisor limb
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

        // Add back if qhat was 1 too large
        if (borrow != 0) {
            @branchHint(.cold);
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

    // Check overflow: quotient must fit in 4 limbs
    if (q[4] != 0 or q[5] != 0 or q[6] != 0 or q[7] != 0) return null;
    return .{ q[0], q[1], q[2], q[3] };
}

/// Inline single-limb division helper for mulDiv fast path.
/// Uses native u128 division — LLVM lowers to optimal hardware UDIV on ARM64.
/// Comptime-unrolled: LLVM sees 4 straight-line division blocks.
inline fn divProductBySingleLimb(p: [4]u64, d: u64) u256 {
    var q: [4]u64 = .{ 0, 0, 0, 0 };
    var rem: u64 = 0;

    comptime var idx: usize = 4;
    inline while (idx > 0) {
        idx -= 1;
        const full: u128 = (@as(u128, rem) << 64) | p[idx];
        q[idx] = @truncate(full / d);
        rem = @truncate(full % d);
    }
    return limbsToU256(q);
}

/// Fast u256 multiplication that uses narrower operations when values fit.
/// This avoids LLVM's slow generic 256-bit multiplication for common cases.
pub inline fn fastMul(a: u256, b: u256) u256 {
    // Both fit in u128 - use LLVM's faster 128-bit multiplication
    if ((a >> 128) == 0 and (b >> 128) == 0) {
        return @as(u256, @as(u128, @truncate(a))) *% @as(u256, @as(u128, @truncate(b)));
    }
    // Full u256 multiplication via schoolbook 4x4 on limbs (avoids __multi3)
    return limbsToU256(mulLimbs(u256ToLimbs(a), u256ToLimbs(b)));
}

/// Full-precision multiply-then-divide: (a * b) / denominator.
/// Uses a 512-bit intermediate to avoid overflow. This is the core primitive
/// used by UniswapV3/V4 (Solidity's FullMath.mulDiv).
/// Returns null on division by zero or if the result overflows u256.
pub inline fn mulDiv(a: u256, b: u256, denominator: u256) ?u256 {
    // Work in limb space throughout to avoid expensive u256 shift operations
    const d_limbs = u256ToLimbs(denominator);
    if (d_limbs[0] == 0 and d_limbs[1] == 0 and d_limbs[2] == 0 and d_limbs[3] == 0) return null;

    const a_limbs = u256ToLimbs(a);
    const b_limbs = u256ToLimbs(b);

    // === Fast path: both fit in u128 (common DeFi case) ===
    if (a_limbs[2] == 0 and a_limbs[3] == 0 and b_limbs[2] == 0 and b_limbs[3] == 0) {
        const al: u128 = @bitCast([2]u64{ a_limbs[0], a_limbs[1] });
        const bl: u128 = @bitCast([2]u64{ b_limbs[0], b_limbs[1] });
        const product: u256 = @as(u256, al) * @as(u256, bl);
        const p_limbs = u256ToLimbs(product);

        // Single-limb divisor: inline division (most DeFi denominators fit in u64)
        if (d_limbs[1] == 0 and d_limbs[2] == 0 and d_limbs[3] == 0) {
            return divProductBySingleLimb(p_limbs, d_limbs[0]);
        }

        // Multi-limb denominator
        return limbsToU256(divLimbsDirect(p_limbs, d_limbs));
    }

    // === Medium path: product fits in u256 ===
    const ov = @mulWithOverflow(a, b);
    if (ov[1] == 0) {
        return limbsToU256(divLimbsDirect(u256ToLimbs(ov[0]), d_limbs));
    }

    // === Overflow path: 512-bit intermediate via limb-native mulWide + divWide ===
    const wide = mulWide(a_limbs, b_limbs);
    return if (divWide(wide, d_limbs)) |q| limbsToU256(q) else null;
}

/// mulDiv with rounding up: ceil(a * b / denominator)
pub fn mulDivRoundingUp(a: u256, b: u256, denominator: u256) ?u256 {
    const result = mulDiv(a, b, denominator) orelse return null;
    // Check remainder: if result * denominator != a * b, round up
    const a_limbs = u256ToLimbs(a);
    const b_limbs = u256ToLimbs(b);
    const wide_ab = mulWide(a_limbs, b_limbs);
    const result_limbs = u256ToLimbs(result);
    const d_limbs = u256ToLimbs(denominator);
    const wide_rd = mulWide(result_limbs, d_limbs);
    var has_remainder = false;
    var i: usize = 7;
    while (true) : (i -= 1) {
        if (wide_ab[i] != wide_rd[i]) {
            has_remainder = wide_ab[i] > wide_rd[i];
            break;
        }
        if (i == 0) break;
    }
    if (has_remainder) {
        if (result == MAX) return null;
        return result + 1;
    }
    return result;
}

/// Compute UniswapV2 getAmountOut entirely in u64-limb space.
/// Formula: (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
/// Delegates to dex/v2.zig with the standard Uniswap V2 fee (997/1000).
pub fn getAmountOut(amount_in: u256, reserve_in: u256, reserve_out: u256) ?u256 {
    const dex_v2 = @import("dex/v2.zig");
    return dex_v2.getAmountOut(amount_in, reserve_in, reserve_out, 997, 1000);
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
    const too_big = "0x1" ++ @as([64]u8, @splat('0'));
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
    const zero_bytes = @as([32]u8, @splat(0));
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

test "mulLimbs correctness" {
    // Small values
    const a = u256ToLimbs(100);
    const b = u256ToLimbs(200);
    try std.testing.expectEqual(@as(u256, 20000), limbsToU256(mulLimbs(a, b)));

    // Values from UniswapV2 benchmark
    const eth_1 = u256ToLimbs(1_000_000_000_000_000_000);
    const fee = [4]u64{ 997, 0, 0, 0 };
    const result = limbsToU256(mulLimbs(eth_1, fee));
    try std.testing.expectEqual(@as(u256, 997_000_000_000_000_000_000), result);

    // Large values - verify wrapping matches native
    const x: u256 = (@as(u256, 1) << 200) + 12345;
    const y: u256 = (@as(u256, 1) << 130) + 999;
    try std.testing.expectEqual(x *% y, limbsToU256(mulLimbs(u256ToLimbs(x), u256ToLimbs(y))));

    // MAX * MAX wrapping
    try std.testing.expectEqual(MAX *% MAX, limbsToU256(mulLimbs(u256ToLimbs(MAX), u256ToLimbs(MAX))));

    // MAX * 2 wrapping
    try std.testing.expectEqual(MAX *% 2, limbsToU256(mulLimbs(u256ToLimbs(MAX), u256ToLimbs(2))));
}

test "addLimbs correctness" {
    // Simple addition
    const a = u256ToLimbs(100);
    const b = u256ToLimbs(200);
    try std.testing.expectEqual(@as(u256, 300), limbsToU256(addLimbs(a, b)));

    // Carry propagation across limbs
    const max_u64 = u256ToLimbs(std.math.maxInt(u64));
    const one = u256ToLimbs(1);
    const expected: u256 = @as(u256, std.math.maxInt(u64)) + 1;
    try std.testing.expectEqual(expected, limbsToU256(addLimbs(max_u64, one)));

    // Full carry chain
    const max_val = u256ToLimbs(MAX);
    try std.testing.expectEqual(MAX +% 1, limbsToU256(addLimbs(max_val, one)));
}

test "getAmountOut correctness" {
    const amount_in: u256 = 1_000_000_000_000_000_000; // 1 ETH
    const reserve_in: u256 = 100_000_000_000_000_000_000; // 100 ETH
    const reserve_out: u256 = 200_000_000_000; // 200k USDC (6 decimals)

    // Compute expected via standard u256 arithmetic
    const amount_in_with_fee = fastMul(amount_in, 997);
    const numerator = fastMul(amount_in_with_fee, reserve_out);
    const denominator = fastMul(reserve_in, 1000) +% amount_in_with_fee;
    const expected = fastDiv(numerator, denominator);

    const result = getAmountOut(amount_in, reserve_in, reserve_out).?;
    try std.testing.expectEqual(expected, result);
    try std.testing.expect(result > 0);
    try std.testing.expect(result < reserve_out);
}

test "getAmountOut edge cases" {
    // Small amount in
    const r1 = getAmountOut(1, 1_000_000, 1_000_000).?;
    try std.testing.expect(r1 < 1_000_000);

    // Equal reserves
    const r2 = getAmountOut(1_000_000, 1_000_000_000, 1_000_000_000).?;
    try std.testing.expect(r2 > 0);
    try std.testing.expect(r2 < 1_000_000);
}

test "fastMul large values via schoolbook" {
    // Values that exceed u128, exercising the schoolbook path
    const a: u256 = (@as(u256, 1) << 200) + 12345;
    const b: u256 = (@as(u256, 1) << 130) + 999;
    try std.testing.expectEqual(a *% b, fastMul(a, b));

    // Both MAX
    try std.testing.expectEqual(MAX *% MAX, fastMul(MAX, MAX));
}
