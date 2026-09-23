//! Minimal MessagePack subset used to talk to Barretenberg's `bbapi` C entrypoint.
//!
//! Only the families the bbapi request/response shapes need are implemented:
//! nil, bool, unsigned integers, str, bin, array and map (`skipValue` also
//! steps over int, float and ext values so an unexpected field can be skipped
//! deterministically). The encoder always emits the canonical shortest form,
//! exactly as msgpack-c does for these types; this matters because
//! Barretenberg v5.2.0 decodes requests outside its exception guard and a
//! malformed request terminates the host process rather than returning an
//! error.
//!
//! The decoder is strict about family and bounds, not about canonical form:
//! every typed read checks the head byte and returns `error.TypeMismatch` on
//! any other family, and every length is bounds-checked (`error.Truncated`),
//! so a schema change in a future library version surfaces as a Zig error
//! instead of undefined behavior. It does accept any encoding of the right
//! family, so a value written in a longer form than necessary (`str8` for a
//! short string, `map16` for a one-entry map) decodes normally. That is
//! deliberate: responses come from the linked library, and accepting a
//! non-minimal encoding of the expected shape cannot turn a rejection into an
//! acceptance. Only the encoder needs to be canonical.
//!
//! Spec: https://github.com/msgpack/msgpack/blob/master/spec.md

const std = @import("std");

pub const EncodeError = std.mem.Allocator.Error || error{
    /// A string, binary blob, array or map is longer than 2^32 - 1 elements.
    TooLong,
};

pub const DecodeError = error{
    /// The input ended inside a value.
    Truncated,
    /// The head byte does not belong to the family the caller asked for.
    TypeMismatch,
    /// The reserved head byte 0xc1 was encountered.
    Reserved,
    /// Nested containers deeper than `max_depth` while skipping a value.
    TooDeep,
};

/// Maximum container nesting `Decoder.skipValue` will follow.
pub const max_depth: usize = 32;

// ============================================================================
// Encoder
// ============================================================================

/// Appends canonical msgpack encodings to a growable buffer.
pub const Encoder = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Encoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Encoder) void {
        self.buf.deinit(self.allocator);
    }

    /// The bytes encoded so far (still owned by the encoder).
    pub fn bytes(self: *const Encoder) []const u8 {
        return self.buf.items;
    }

    /// Hand the encoded bytes to the caller; the encoder is left empty.
    pub fn toOwnedSlice(self: *Encoder) std.mem.Allocator.Error![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    pub fn writeNil(self: *Encoder) EncodeError!void {
        try self.buf.append(self.allocator, 0xc0);
    }

    pub fn writeBool(self: *Encoder, value: bool) EncodeError!void {
        try self.buf.append(self.allocator, if (value) 0xc3 else 0xc2);
    }

    /// Unsigned integer in its shortest form: positive fixint, uint 8/16/32/64.
    pub fn writeUint(self: *Encoder, value: u64) EncodeError!void {
        if (value < 0x80) {
            try self.buf.append(self.allocator, @intCast(value));
        } else if (value <= std.math.maxInt(u8)) {
            try self.buf.append(self.allocator, 0xcc);
            try self.buf.append(self.allocator, @intCast(value));
        } else if (value <= std.math.maxInt(u16)) {
            try self.buf.append(self.allocator, 0xcd);
            try self.appendBigEndian(u16, @intCast(value));
        } else if (value <= std.math.maxInt(u32)) {
            try self.buf.append(self.allocator, 0xce);
            try self.appendBigEndian(u32, @intCast(value));
        } else {
            try self.buf.append(self.allocator, 0xcf);
            try self.appendBigEndian(u64, value);
        }
    }

    /// UTF-8 string: fixstr (< 32 bytes), str 8/16/32.
    pub fn writeStr(self: *Encoder, value: []const u8) EncodeError!void {
        if (value.len < 32) {
            try self.buf.append(self.allocator, 0xa0 | @as(u8, @intCast(value.len)));
        } else {
            try self.writeLengthPrefixed(value.len, 0xd9, 0xda, 0xdb);
        }
        try self.buf.appendSlice(self.allocator, value);
    }

    /// Raw bytes: bin 8/16/32.
    pub fn writeBin(self: *Encoder, value: []const u8) EncodeError!void {
        try self.writeLengthPrefixed(value.len, 0xc4, 0xc5, 0xc6);
        try self.buf.appendSlice(self.allocator, value);
    }

    /// Array header for `count` elements; the caller then writes the elements.
    pub fn writeArrayHeader(self: *Encoder, count: usize) EncodeError!void {
        if (count < 16) {
            try self.buf.append(self.allocator, 0x90 | @as(u8, @intCast(count)));
        } else {
            try self.writeLength16or32(count, 0xdc, 0xdd);
        }
    }

    /// Map header for `count` key/value pairs; the caller then writes 2*count values.
    pub fn writeMapHeader(self: *Encoder, count: usize) EncodeError!void {
        if (count < 16) {
            try self.buf.append(self.allocator, 0x80 | @as(u8, @intCast(count)));
        } else {
            try self.writeLength16or32(count, 0xde, 0xdf);
        }
    }

    fn writeLengthPrefixed(self: *Encoder, len: usize, tag8: u8, tag16: u8, tag32: u8) EncodeError!void {
        if (len <= std.math.maxInt(u8)) {
            try self.buf.append(self.allocator, tag8);
            try self.buf.append(self.allocator, @intCast(len));
        } else {
            try self.writeLength16or32(len, tag16, tag32);
        }
    }

    fn writeLength16or32(self: *Encoder, len: usize, tag16: u8, tag32: u8) EncodeError!void {
        if (len <= std.math.maxInt(u16)) {
            try self.buf.append(self.allocator, tag16);
            try self.appendBigEndian(u16, @intCast(len));
        } else if (len <= std.math.maxInt(u32)) {
            try self.buf.append(self.allocator, tag32);
            try self.appendBigEndian(u32, @intCast(len));
        } else {
            return error.TooLong;
        }
    }

    fn appendBigEndian(self: *Encoder, comptime T: type, value: T) EncodeError!void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, value, .big);
        try self.buf.appendSlice(self.allocator, &tmp);
    }
};

// ============================================================================
// Decoder
// ============================================================================

/// Strict cursor over a msgpack byte string. Typed reads fail with
/// `error.TypeMismatch` unless the next value is of the requested family.
pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Decoder {
        return .{ .data = data };
    }

    /// True once every input byte has been consumed.
    pub fn finished(self: *const Decoder) bool {
        return self.pos == self.data.len;
    }

    pub fn remaining(self: *const Decoder) usize {
        return self.data.len - self.pos;
    }

    pub fn readNil(self: *Decoder) DecodeError!void {
        const head = try self.peek();
        if (head != 0xc0) return error.TypeMismatch;
        self.pos += 1;
    }

    pub fn readBool(self: *Decoder) DecodeError!bool {
        const head = try self.peek();
        switch (head) {
            0xc2 => {
                self.pos += 1;
                return false;
            },
            0xc3 => {
                self.pos += 1;
                return true;
            },
            else => return error.TypeMismatch,
        }
    }

    pub fn readUint(self: *Decoder) DecodeError!u64 {
        const head = try self.peek();
        switch (head) {
            0x00...0x7f => {
                self.pos += 1;
                return head;
            },
            0xcc => {
                self.pos += 1;
                return try self.readBigEndian(u8);
            },
            0xcd => {
                self.pos += 1;
                return try self.readBigEndian(u16);
            },
            0xce => {
                self.pos += 1;
                return try self.readBigEndian(u32);
            },
            0xcf => {
                self.pos += 1;
                return try self.readBigEndian(u64);
            },
            else => return error.TypeMismatch,
        }
    }

    /// Returns a view into the input; valid as long as the input is.
    pub fn readStr(self: *Decoder) DecodeError![]const u8 {
        const head = try self.peek();
        const len: usize = switch (head) {
            0xa0...0xbf => blk: {
                self.pos += 1;
                break :blk head & 0x1f;
            },
            0xd9 => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u8);
            },
            0xda => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u16);
            },
            0xdb => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u32);
            },
            else => return error.TypeMismatch,
        };
        return self.take(len);
    }

    /// Returns a view into the input; valid as long as the input is.
    pub fn readBin(self: *Decoder) DecodeError![]const u8 {
        const head = try self.peek();
        const len: usize = switch (head) {
            0xc4 => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u8);
            },
            0xc5 => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u16);
            },
            0xc6 => blk: {
                self.pos += 1;
                break :blk try self.readBigEndian(u32);
            },
            else => return error.TypeMismatch,
        };
        return self.take(len);
    }

    /// Number of elements that follow.
    pub fn readArrayHeader(self: *Decoder) DecodeError!usize {
        const head = try self.peek();
        switch (head) {
            0x90...0x9f => {
                self.pos += 1;
                return head & 0x0f;
            },
            0xdc => {
                self.pos += 1;
                return try self.readBigEndian(u16);
            },
            0xdd => {
                self.pos += 1;
                return try self.readBigEndian(u32);
            },
            else => return error.TypeMismatch,
        }
    }

    /// Number of key/value pairs that follow.
    pub fn readMapHeader(self: *Decoder) DecodeError!usize {
        const head = try self.peek();
        switch (head) {
            0x80...0x8f => {
                self.pos += 1;
                return head & 0x0f;
            },
            0xde => {
                self.pos += 1;
                return try self.readBigEndian(u16);
            },
            0xdf => {
                self.pos += 1;
                return try self.readBigEndian(u32);
            },
            else => return error.TypeMismatch,
        }
    }

    /// Step over one complete value of any family without interpreting it.
    pub fn skipValue(self: *Decoder) DecodeError!void {
        return self.skipValueDepth(0);
    }

    fn skipValueDepth(self: *Decoder, depth: usize) DecodeError!void {
        if (depth >= max_depth) return error.TooDeep;
        const head = try self.peek();
        self.pos += 1;
        switch (head) {
            0x00...0x7f, 0xe0...0xff, 0xc0, 0xc2, 0xc3 => {},
            0xc1 => return error.Reserved,
            0x80...0x8f => try self.skipN(2 * @as(usize, head & 0x0f), depth),
            0x90...0x9f => try self.skipN(head & 0x0f, depth),
            0xa0...0xbf => _ = try self.take(head & 0x1f),
            0xc4, 0xd9 => _ = try self.take(try self.readBigEndian(u8)),
            0xc5, 0xda => _ = try self.take(try self.readBigEndian(u16)),
            0xc6, 0xdb => _ = try self.take(try self.readBigEndian(u32)),
            // ext 8/16/32: length, then one type byte, then the payload.
            0xc7 => _ = try self.take(@as(usize, try self.readBigEndian(u8)) + 1),
            0xc8 => _ = try self.take(@as(usize, try self.readBigEndian(u16)) + 1),
            0xc9 => _ = try self.take(@as(usize, try self.readBigEndian(u32)) + 1),
            0xca, 0xcc, 0xd0, 0xcd, 0xd1, 0xcb, 0xce, 0xd2, 0xcf, 0xd3 => _ = try self.take(scalarWidth(head)),
            // fixext 1/2/4/8/16: one type byte plus the payload.
            0xd4 => _ = try self.take(2),
            0xd5 => _ = try self.take(3),
            0xd6 => _ = try self.take(5),
            0xd7 => _ = try self.take(9),
            0xd8 => _ = try self.take(17),
            0xdc => try self.skipN(try self.readBigEndian(u16), depth),
            0xdd => try self.skipN(try self.readBigEndian(u32), depth),
            0xde => try self.skipN(2 * @as(usize, try self.readBigEndian(u16)), depth),
            0xdf => try self.skipN(2 * @as(usize, try self.readBigEndian(u32)), depth),
        }
    }

    fn scalarWidth(head: u8) usize {
        return switch (head) {
            0xcc, 0xd0 => 1,
            0xcd, 0xd1 => 2,
            0xca, 0xce, 0xd2 => 4,
            0xcb, 0xcf, 0xd3 => 8,
            else => unreachable,
        };
    }

    fn skipN(self: *Decoder, count: usize, depth: usize) DecodeError!void {
        var i: usize = 0;
        while (i < count) : (i += 1) try self.skipValueDepth(depth + 1);
    }

    fn peek(self: *const Decoder) DecodeError!u8 {
        if (self.pos >= self.data.len) return error.Truncated;
        return self.data[self.pos];
    }

    fn take(self: *Decoder, len: usize) DecodeError![]const u8 {
        if (len > self.data.len - self.pos) return error.Truncated;
        const out = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }

    fn readBigEndian(self: *Decoder, comptime T: type) DecodeError!T {
        const raw = try self.take(@sizeOf(T));
        return std.mem.readInt(T, raw[0..@sizeOf(T)], .big);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn expectEncoded(expected: []const u8, comptime write: anytype, arg: anytype) !void {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try write(&enc, arg);
    try testing.expectEqualSlices(u8, expected, enc.bytes());
}

test "msgpack: nil and bool" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.writeNil();
    try enc.writeBool(false);
    try enc.writeBool(true);
    try testing.expectEqualSlices(u8, &.{ 0xc0, 0xc2, 0xc3 }, enc.bytes());
}

test "msgpack: uint boundaries use the shortest encoding" {
    try expectEncoded(&.{0x00}, Encoder.writeUint, @as(u64, 0));
    try expectEncoded(&.{0x7f}, Encoder.writeUint, @as(u64, 0x7f));
    try expectEncoded(&.{ 0xcc, 0x80 }, Encoder.writeUint, @as(u64, 0x80));
    try expectEncoded(&.{ 0xcc, 0xff }, Encoder.writeUint, @as(u64, 0xff));
    try expectEncoded(&.{ 0xcd, 0x01, 0x00 }, Encoder.writeUint, @as(u64, 0x100));
    try expectEncoded(&.{ 0xcd, 0xff, 0xff }, Encoder.writeUint, @as(u64, 0xffff));
    try expectEncoded(&.{ 0xce, 0x00, 0x01, 0x00, 0x00 }, Encoder.writeUint, @as(u64, 0x10000));
    try expectEncoded(&.{ 0xce, 0xff, 0xff, 0xff, 0xff }, Encoder.writeUint, @as(u64, 0xffff_ffff));
    try expectEncoded(&.{ 0xcf, 0, 0, 0, 1, 0, 0, 0, 0 }, Encoder.writeUint, @as(u64, 0x1_0000_0000));
}

test "msgpack: str boundaries" {
    try expectEncoded(&.{0xa0}, Encoder.writeStr, "");
    try expectEncoded("\xa3abc", Encoder.writeStr, "abc");
    const s31 = "a" ** 31;
    try expectEncoded("\xbf" ++ s31, Encoder.writeStr, s31);
    const s32 = "a" ** 32;
    try expectEncoded("\xd9\x20" ++ s32, Encoder.writeStr, s32);
    const s255 = "a" ** 255;
    try expectEncoded("\xd9\xff" ++ s255, Encoder.writeStr, s255);
    const s256 = "a" ** 256;
    try expectEncoded("\xda\x01\x00" ++ s256, Encoder.writeStr, s256);
}

test "msgpack: bin boundaries" {
    try expectEncoded(&.{ 0xc4, 0x00 }, Encoder.writeBin, "");
    try expectEncoded("\xc4\x03\x01\x02\x03", Encoder.writeBin, "\x01\x02\x03");
    const b255 = "\x5a" ** 255;
    try expectEncoded("\xc4\xff" ++ b255, Encoder.writeBin, b255);
    const b256 = "\x5a" ** 256;
    try expectEncoded("\xc5\x01\x00" ++ b256, Encoder.writeBin, b256);
    const b65536 = "\x5a" ** 65536;
    try expectEncoded("\xc6\x00\x01\x00\x00" ++ b65536, Encoder.writeBin, b65536);
}

test "msgpack: array and map headers" {
    try expectEncoded(&.{0x90}, Encoder.writeArrayHeader, @as(usize, 0));
    try expectEncoded(&.{0x9f}, Encoder.writeArrayHeader, @as(usize, 15));
    try expectEncoded(&.{ 0xdc, 0x00, 0x10 }, Encoder.writeArrayHeader, @as(usize, 16));
    try expectEncoded(&.{ 0xdc, 0x01, 0xca }, Encoder.writeArrayHeader, @as(usize, 458));
    try expectEncoded(&.{ 0xdd, 0x00, 0x01, 0x00, 0x00 }, Encoder.writeArrayHeader, @as(usize, 65536));
    try expectEncoded(&.{0x80}, Encoder.writeMapHeader, @as(usize, 0));
    try expectEncoded(&.{0x84}, Encoder.writeMapHeader, @as(usize, 4));
    try expectEncoded(&.{ 0xde, 0x00, 0x10 }, Encoder.writeMapHeader, @as(usize, 16));
    try expectEncoded(&.{ 0xdf, 0x00, 0x01, 0x00, 0x00 }, Encoder.writeMapHeader, @as(usize, 65536));
}

test "msgpack: toOwnedSlice hands over the buffer" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.writeStr("hi");
    const owned = try enc.toOwnedSlice();
    defer testing.allocator.free(owned);
    try testing.expectEqualSlices(u8, "\xa2hi", owned);
    try testing.expectEqual(@as(usize, 0), enc.bytes().len);
}

test "msgpack: decoder round trip" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.writeArrayHeader(2);
    try enc.writeStr("CircuitVerifyResponse");
    try enc.writeMapHeader(3);
    try enc.writeStr("verified");
    try enc.writeBool(true);
    try enc.writeStr("count");
    try enc.writeUint(70000);
    try enc.writeStr("blob");
    try enc.writeBin(&.{ 1, 2, 3 });

    var dec = Decoder.init(enc.bytes());
    try testing.expectEqual(@as(usize, 2), try dec.readArrayHeader());
    try testing.expectEqualStrings("CircuitVerifyResponse", try dec.readStr());
    try testing.expectEqual(@as(usize, 3), try dec.readMapHeader());
    try testing.expectEqualStrings("verified", try dec.readStr());
    try testing.expect(try dec.readBool());
    try testing.expectEqualStrings("count", try dec.readStr());
    try testing.expectEqual(@as(u64, 70000), try dec.readUint());
    try testing.expectEqualStrings("blob", try dec.readStr());
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, try dec.readBin());
    try testing.expect(dec.finished());
}

test "msgpack: decoder reads every uint width" {
    const input = [_]u8{ 0x05, 0xcc, 0xfe, 0xcd, 0x12, 0x34, 0xce, 0, 0, 0x10, 0, 0xcf, 0, 0, 0, 1, 0, 0, 0, 0 };
    var dec = Decoder.init(&input);
    try testing.expectEqual(@as(u64, 5), try dec.readUint());
    try testing.expectEqual(@as(u64, 0xfe), try dec.readUint());
    try testing.expectEqual(@as(u64, 0x1234), try dec.readUint());
    try testing.expectEqual(@as(u64, 0x1000), try dec.readUint());
    try testing.expectEqual(@as(u64, 0x1_0000_0000), try dec.readUint());
    try testing.expect(dec.finished());
}

test "msgpack: strict decoder rejects the wrong family" {
    var dec = Decoder.init(&.{0xc3});
    try testing.expectError(error.TypeMismatch, dec.readStr());
    try testing.expectError(error.TypeMismatch, dec.readUint());
    try testing.expectError(error.TypeMismatch, dec.readArrayHeader());
    try testing.expectError(error.TypeMismatch, dec.readMapHeader());
    try testing.expectError(error.TypeMismatch, dec.readBin());
    try testing.expectError(error.TypeMismatch, dec.readNil());
    // A failed read consumes nothing.
    try testing.expect(try dec.readBool());
}

test "msgpack: strict decoder rejects truncated input" {
    var empty = Decoder.init(&.{});
    try testing.expectError(error.Truncated, empty.readBool());
    try testing.expectError(error.Truncated, empty.skipValue());

    // fixstr claiming 5 bytes with only 2 present.
    var short_str = Decoder.init("\xa5ab");
    try testing.expectError(error.Truncated, short_str.readStr());

    // bin16 header cut off after one length byte.
    var short_len = Decoder.init(&.{ 0xc5, 0x01 });
    try testing.expectError(error.Truncated, short_len.readBin());

    // array16 header with a missing length.
    var short_arr = Decoder.init(&.{0xdc});
    try testing.expectError(error.Truncated, short_arr.readArrayHeader());
}

test "msgpack: skipValue steps over nested containers and foreign families" {
    // [ -1, 1.5f32, {"k": [nil, ext]}, "s" ] followed by a trailing bool.
    const input = [_]u8{
        0x94,
        0xff, // negative fixint -1
        0xca, 0x3f, 0xc0, 0x00, 0x00, // float32 1.5
        0x81, 0xa1, 'k',  0x92, 0xc0, 0xd4, 0x01, 0xaa, // {"k": [nil, fixext1(type 1, 0xaa)]}
        0xa1, 's',  0xc3,
    };
    var dec = Decoder.init(&input);
    try dec.skipValue();
    try testing.expect(try dec.readBool());
    try testing.expect(dec.finished());
}

test "msgpack: decoder accepts non-minimal encodings of the expected family" {
    // Same values as the canonical forms, written in longer encodings: str8
    // instead of fixstr, array16/map16 instead of the fixed headers, and
    // uint64 instead of a positive fixint.
    const input = "\xdc\x00\x02" ++ // array16 with 2 elements
        "\xd9\x02ok" ++ // str8 "ok"
        "\xde\x00\x01" ++ // map16 with 1 entry
        "\xd9\x01n" ++ // str8 "n"
        "\xcf\x00\x00\x00\x00\x00\x00\x00\x07"; // uint64 7
    var dec = Decoder.init(input);
    try testing.expectEqual(@as(usize, 2), try dec.readArrayHeader());
    try testing.expectEqualStrings("ok", try dec.readStr());
    try testing.expectEqual(@as(usize, 1), try dec.readMapHeader());
    try testing.expectEqualStrings("n", try dec.readStr());
    try testing.expectEqual(@as(u64, 7), try dec.readUint());
    try testing.expect(dec.finished());

    // The encoder, by contrast, only ever emits the shortest form.
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.writeArrayHeader(2);
    try enc.writeStr("ok");
    try enc.writeMapHeader(1);
    try enc.writeStr("n");
    try enc.writeUint(7);
    try testing.expectEqualSlices(u8, "\x92\xa2ok\x81\xa1n\x07", enc.bytes());
    try testing.expect(enc.bytes().len < input.len);
}

test "msgpack: skipValue rejects the reserved byte and runaway nesting" {
    var reserved = Decoder.init(&.{0xc1});
    try testing.expectError(error.Reserved, reserved.skipValue());

    // 40 nested single-element arrays exceed max_depth.
    const nested = [_]u8{0x91} ** 40 ++ [_]u8{0xc0};
    var deep = Decoder.init(&nested);
    try testing.expectError(error.TooDeep, deep.skipValue());
}
