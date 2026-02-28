const std = @import("std");
const mem = std.mem;
const math = std.math;

// Keccak-256 rate: 1600 - 2*256 = 1088 bits = 136 bytes
const RATE = 136;

// Round constants for Keccak-f[1600]
const RC = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

// Rotation offsets for rho step (indexed by pi permutation order)
const RHO = [25]u6{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

// Lane complementing mask: lanes {1,2,8,12,17,20} are complemented.
// This converts the chi step's NOT+AND into ANDN (single instruction on ARM/x86).
const COMPLEMENT_LANES = [25]bool{
    false, true,  true,  false, false,
    false, false, false, true,  false,
    false, false, true,  false, false,
    false, false, true,  false, false,
    true,  false, false, false, false,
};

/// Optimized Keccak-256 hash. Lane complementing + interleaved rounds.
pub fn keccak256(data: []const u8) [32]u8 {
    var state: [25]u64 = [_]u64{0} ** 25;

    // Apply lane complement to initial zero state (complement of 0 = ~0)
    inline for (0..25) |i| {
        if (COMPLEMENT_LANES[i]) state[i] = ~@as(u64, 0);
    }

    // Absorb
    var offset: usize = 0;
    while (offset + RATE <= data.len) : (offset += RATE) {
        xorBlock(&state, data[offset..][0..RATE]);
        keccakF(&state);
    }

    // Final block with padding (Keccak: 0x01 || 0x00...0x00 || 0x80)
    var last: [RATE]u8 = [_]u8{0} ** RATE;
    const remaining = data.len - offset;
    @memcpy(last[0..remaining], data[offset..][0..remaining]);
    last[remaining] = 0x01;
    last[RATE - 1] |= 0x80;
    xorBlock(&state, &last);
    keccakF(&state);

    // Squeeze 32 bytes, removing lane complement
    var out: [32]u8 = undefined;
    inline for (0..4) |i| {
        var lane = state[i];
        if (COMPLEMENT_LANES[i]) lane = ~lane;
        mem.writeInt(u64, out[i * 8 ..][0..8], lane, .little);
    }
    return out;
}

fn xorBlock(state: *[25]u64, block: *const [RATE]u8) void {
    inline for (0..17) |i| { // RATE / 8 = 17
        state[i] ^= mem.readInt(u64, block[i * 8 ..][0..8], .little);
    }
}

fn keccakF(state: *[25]u64) void {
    for (RC) |rc| {
        round(state, rc);
    }
}

inline fn round(a: *[25]u64, rc: u64) void {
    // Theta: column parity
    const c = [5]u64{
        a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20],
        a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21],
        a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22],
        a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23],
        a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24],
    };

    const d = [5]u64{
        c[4] ^ math.rotl(u64, c[1], 1),
        c[0] ^ math.rotl(u64, c[2], 1),
        c[1] ^ math.rotl(u64, c[3], 1),
        c[2] ^ math.rotl(u64, c[4], 1),
        c[3] ^ math.rotl(u64, c[0], 1),
    };

    // Theta + Rho + Pi (interleaved)
    var b: [25]u64 = undefined;

    const PI_DST = [25]u5{
        0,  10, 20, 5,  15,
        16, 1,  11, 21, 6,
        7,  17, 2,  12, 22,
        23, 8,  18, 3,  13,
        14, 24, 9,  19, 4,
    };

    inline for (0..25) |i| {
        b[PI_DST[i]] = math.rotl(u64, a[i] ^ d[i % 5], RHO[i]);
    }

    // Chi with lane complementing.
    // Standard chi: a[i] = b[i] ^ (~b[i+1] & b[i+2])
    // With lane complementing, some b values are already complemented,
    // allowing us to use AND/ANDN/OR patterns instead of NOT+AND.
    //
    // For each row (y*5 .. y*5+4), the pattern depends on which of the
    // 3 operands (b[x], b[x+1], b[x+2]) are complemented.
    // Patterns: ~b&c -> ANDN, b&~c -> ANDN, ~b|c -> ORN, b|~c -> ORN
    inline for (0..5) |y| {
        const base = y * 5;
        const b0 = b[base + 0];
        const b1 = b[base + 1];
        const b2 = b[base + 2];
        const b3 = b[base + 3];
        const b4 = b[base + 4];

        const c0 = COMPLEMENT_LANES[base + 0];
        const c1 = COMPLEMENT_LANES[base + 1];
        const c2 = COMPLEMENT_LANES[base + 2];
        const c3 = COMPLEMENT_LANES[base + 3];
        const c4 = COMPLEMENT_LANES[base + 4];

        // a[base+x] = b[x] ^ chi_op(b[x+1], b[x+2])
        // chi_op depends on complement status of b[x+1]:
        //   if b[x+1] complemented: chi_op = b[x+1] & b[x+2]  (NOT already applied)
        //   if b[x+1] NOT complemented: chi_op = ~b[x+1] & b[x+2]
        // But we also need to maintain the complement invariant for the output lane.
        //
        a[base + 0] = chiLane(b0, b1, b2, c1, c2);
        a[base + 1] = chiLane(b1, b2, b3, c2, c3);
        a[base + 2] = chiLane(b2, b3, b4, c3, c4);
        a[base + 3] = chiLane(b3, b4, b0, c4, c0);
        a[base + 4] = chiLane(b4, b0, b1, c0, c1);
    }

    // Iota
    a[0] ^= rc;
}

inline fn chiLane(
    bx: u64,
    bx1: u64,
    bx2: u64,
    comptime cx1: bool,
    comptime cx2: bool,
) u64 {
    // Chi step with lane complementing (XKCP opt64).
    // The operation depends on the complement status of bx1 and bx2:
    //   (false, false): ~bx1 & bx2           -> standard ANDN
    //   (true, false):  bx1 & bx2            -> AND (bx1 already ~'d)
    //   (false, true):  ~bx1 | bx2           -> ORN (De Morgan)
    //   (true, true):   bx1 | bx2            -> OR  (both ~'d: De Morgan)
    //
    const chi_term = if (!cx1 and !cx2)
        ~bx1 & bx2
    else if (cx1 and !cx2)
        bx1 & bx2
    else if (!cx1 and cx2)
        ~bx1 | bx2
    else // cx1 and cx2
        bx1 | bx2;

    return bx ^ chi_term;
}

// ============================================================================
// Tests: cross-validate against stdlib Keccak-256
// ============================================================================

const Keccak256Std = std.crypto.hash.sha3.Keccak256;

fn stdlibHash(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Keccak256Std.hash(data, &out, .{});
    return out;
}

test "optimized keccak256 empty input" {
    const result = keccak256("");
    const expected = stdlibHash("");
    try std.testing.expectEqualSlices(u8, &expected, &result);
    // Pinned digest: keccak256("")
    const hex = @import("hex.zig");
    const pinned = try hex.hexToBytesFixed(32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try std.testing.expectEqualSlices(u8, &pinned, &result);
}

test "optimized keccak256 abc" {
    const result = keccak256("abc");
    const expected = stdlibHash("abc");
    try std.testing.expectEqualSlices(u8, &expected, &result);
    const hex = @import("hex.zig");
    const pinned = try hex.hexToBytesFixed(32, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    try std.testing.expectEqualSlices(u8, &pinned, &result);
}

test "optimized keccak256 Hello World" {
    const result = keccak256("Hello, World!");
    const expected = stdlibHash("Hello, World!");
    try std.testing.expectEqualSlices(u8, &expected, &result);
    const hex = @import("hex.zig");
    const pinned = try hex.hexToBytesFixed(32, "acaf3289d7b601cbd114fb36c4d29c85bbfd5e133f14cb355c3fd8d99367964f");
    try std.testing.expectEqualSlices(u8, &pinned, &result);
}

test "optimized keccak256 testing" {
    const result = keccak256("testing");
    const expected = stdlibHash("testing");
    try std.testing.expectEqualSlices(u8, &expected, &result);
    const hex = @import("hex.zig");
    const pinned = try hex.hexToBytesFixed(32, "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02");
    try std.testing.expectEqualSlices(u8, &pinned, &result);
}

test "optimized keccak256 exactly 1 block (136 bytes)" {
    const data = [_]u8{0x42} ** 136;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 rate-1 boundary (135 bytes)" {
    const data = [_]u8{0xAB} ** 135;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 rate+1 boundary (137 bytes)" {
    const data = [_]u8{0xCD} ** 137;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 multi-block 256 bytes" {
    const data = [_]u8{0xAB} ** 256;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 multi-block 1KB" {
    const data = [_]u8{0xAB} ** 1024;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 multi-block 4KB" {
    const data = [_]u8{0x42} ** 4096;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 large input 64KB" {
    const data = [_]u8{0xFF} ** 65536;
    const result = keccak256(&data);
    const expected = stdlibHash(&data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "optimized keccak256 cross-validation sweep" {
    // Test every size from 0 to 299 against stdlib
    var data: [300]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 137 +% 42);

    for (0..300) |size| {
        const result = keccak256(data[0..size]);
        const expected = stdlibHash(data[0..size]);
        try std.testing.expectEqualSlices(u8, &expected, &result);
    }
}

test "optimized keccak256 DeFi selectors" {
    // transfer(address,uint256) -> 0xa9059cbb
    const transfer = keccak256("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xa9, 0x05, 0x9c, 0xbb }, transfer[0..4]);

    // approve(address,uint256) -> 0x095ea7b3
    const approve = keccak256("approve(address,uint256)");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x09, 0x5e, 0xa7, 0xb3 }, approve[0..4]);
}
