const std = @import("std");
const uint256 = @import("uint256.zig");

/// ECDSA signature with recovery ID for Ethereum.
/// Contains r, s as 32-byte big-endian values and v as recovery ID (0 or 1).
pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,
    v: u8,

    /// Serialize the signature as r ++ s ++ v (65 bytes).
    pub fn toBytes(self: Signature) [65]u8 {
        var result: [65]u8 = undefined;
        @memcpy(result[0..32], &self.r);
        @memcpy(result[32..64], &self.s);
        result[64] = self.v;
        return result;
    }

    /// Deserialize a 65-byte signature (r ++ s ++ v).
    pub fn fromBytes(bytes: [65]u8) Signature {
        return .{
            .r = bytes[0..32].*,
            .s = bytes[32..64].*,
            .v = bytes[64],
        };
    }

    /// Convert r and s to u256 for numeric access.
    pub fn toRSV(self: Signature) struct { r: u256, s: u256, v: u8 } {
        return .{
            .r = uint256.fromBigEndianBytes(self.r),
            .s = uint256.fromBigEndianBytes(self.s),
            .v = self.v,
        };
    }

    /// Construct a Signature from numeric r, s, and recovery ID v.
    pub fn fromRSV(r: u256, s: u256, v: u8) Signature {
        return .{
            .r = uint256.toBigEndianBytes(r),
            .s = uint256.toBigEndianBytes(s),
            .v = v,
        };
    }

    /// Check if two signatures are equal.
    pub fn eql(a: Signature, b: Signature) bool {
        return std.mem.eql(u8, &a.r, &b.r) and
            std.mem.eql(u8, &a.s, &b.s) and
            a.v == b.v;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Signature toBytes and fromBytes roundtrip" {
    const sig = Signature{
        .r = @as([31]u8, @splat(0)) ++ [_]u8{0x01},
        .s = @as([31]u8, @splat(0)) ++ [_]u8{0x02},
        .v = 1,
    };

    const bytes = sig.toBytes();
    const recovered = Signature.fromBytes(bytes);

    try std.testing.expectEqualSlices(u8, &sig.r, &recovered.r);
    try std.testing.expectEqualSlices(u8, &sig.s, &recovered.s);
    try std.testing.expectEqual(@as(u8, 1), recovered.v);
}

test "Signature toBytes layout" {
    var sig: Signature = undefined;
    @memset(&sig.r, 0xAA);
    @memset(&sig.s, 0xBB);
    sig.v = 0x01;

    const bytes = sig.toBytes();

    // First 32 bytes are r
    for (0..32) |i| {
        try std.testing.expectEqual(@as(u8, 0xAA), bytes[i]);
    }
    // Next 32 bytes are s
    for (32..64) |i| {
        try std.testing.expectEqual(@as(u8, 0xBB), bytes[i]);
    }
    // Last byte is v
    try std.testing.expectEqual(@as(u8, 0x01), bytes[64]);
}

test "Signature toRSV and fromRSV roundtrip" {
    const r_val: u256 = 0xdeadbeef;
    const s_val: u256 = 0xcafebabe;
    const v_val: u8 = 1;

    const sig = Signature.fromRSV(r_val, s_val, v_val);
    const rsv = sig.toRSV();

    try std.testing.expectEqual(r_val, rsv.r);
    try std.testing.expectEqual(s_val, rsv.s);
    try std.testing.expectEqual(v_val, rsv.v);
}

test "Signature fromRSV produces correct big-endian bytes" {
    const sig = Signature.fromRSV(1, 2, 0);

    // r = 1 should be 0x00...01 in big-endian
    try std.testing.expectEqual(@as(u8, 0), sig.r[0]);
    try std.testing.expectEqual(@as(u8, 1), sig.r[31]);

    // s = 2 should be 0x00...02 in big-endian
    try std.testing.expectEqual(@as(u8, 0), sig.s[0]);
    try std.testing.expectEqual(@as(u8, 2), sig.s[31]);
}

test "Signature eql" {
    const a = Signature.fromRSV(100, 200, 0);
    const b = Signature.fromRSV(100, 200, 0);
    const c = Signature.fromRSV(100, 200, 1);
    const d = Signature.fromRSV(101, 200, 0);

    try std.testing.expect(a.eql(b));
    try std.testing.expect(!a.eql(c));
    try std.testing.expect(!a.eql(d));
}

test "Signature fromBytes with zero signature" {
    const bytes = @as([65]u8, @splat(0));
    const sig = Signature.fromBytes(bytes);

    try std.testing.expectEqual(@as(u256, 0), sig.toRSV().r);
    try std.testing.expectEqual(@as(u256, 0), sig.toRSV().s);
    try std.testing.expectEqual(@as(u8, 0), sig.v);
}

test "Signature toRSV with max values" {
    var sig: Signature = undefined;
    @memset(&sig.r, 0xFF);
    @memset(&sig.s, 0xFF);
    sig.v = 1;

    const rsv = sig.toRSV();
    try std.testing.expectEqual(std.math.maxInt(u256), rsv.r);
    try std.testing.expectEqual(std.math.maxInt(u256), rsv.s);
}
