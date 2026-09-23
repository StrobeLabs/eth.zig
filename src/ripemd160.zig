const std = @import("std");

const KL = [_]u32{ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
const KR = [_]u32{ 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

const ZL = [_]u8{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};
const ZR = [_]u8{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};
const SL = [_]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};
const SR = [_]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

fn f(j: u8, x: u32, y: u32, z: u32) u32 {
    return switch (j / 16) {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        4 => x ^ (y | ~z),
        else => unreachable,
    };
}

fn process(h: *[5]u32, block: *const [64]u8) void {
    var x: [16]u32 = undefined;
    for (0..16) |i| {
        x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
    }
    var al, var bl, var cl, var dl, var el = .{ h[0], h[1], h[2], h[3], h[4] };
    var ar, var br, var cr, var dr, var er = .{ h[0], h[1], h[2], h[3], h[4] };
    for (0..80) |j| {
        const jl: u8 = @intCast(j);
        var t = al +% f(jl, bl, cl, dl) +% x[ZL[j]] +% KL[j / 16];
        t = std.math.rotl(u32, t, SL[j]) +% el;
        al = el;
        el = dl;
        dl = std.math.rotl(u32, cl, 10);
        cl = bl;
        bl = t;
        t = ar +% f(79 - jl, br, cr, dr) +% x[ZR[j]] +% KR[j / 16];
        t = std.math.rotl(u32, t, SR[j]) +% er;
        ar = er;
        er = dr;
        dr = std.math.rotl(u32, cr, 10);
        cr = br;
        br = t;
    }
    const t = h[1] +% cl +% dr;
    h[1] = h[2] +% dl +% er;
    h[2] = h[3] +% el +% ar;
    h[3] = h[4] +% al +% br;
    h[4] = h[0] +% bl +% cr;
    h[0] = t;
}

pub fn hash(msg: []const u8, out: *[20]u8) void {
    var h = [_]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    var i: usize = 0;
    while (i + 64 <= msg.len) : (i += 64) {
        process(&h, msg[i..][0..64]);
    }
    var block: [64]u8 = @splat(0);
    const rem = msg.len - i;
    @memcpy(block[0..rem], msg[i..]);
    block[rem] = 0x80;
    const bit_len: u64 = @as(u64, msg.len) * 8;
    if (rem >= 56) {
        process(&h, &block);
        block = @splat(0);
    }
    std.mem.writeInt(u64, block[56..64], bit_len, .little);
    process(&h, &block);
    for (h, 0..) |w, n| {
        std.mem.writeInt(u32, out[n * 4 ..][0..4], w, .little);
    }
}

test "ripemd160 abc" {
    var out: [20]u8 = undefined;
    hash("abc", &out);
    try std.testing.expectEqualStrings(
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        &std.fmt.bytesToHex(out, .lower),
    );
}
