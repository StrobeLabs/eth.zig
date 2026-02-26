const std = @import("std");

pub const RlpError = error{
    InvalidRlp,
    InputTooShort,
    LeadingZero,
    NonCanonical,
    ListLengthMismatch,
    Overflow,
    UnsupportedType,
};

// ============================================================================
// Encoding
// ============================================================================

/// Encode a value to RLP. Returns allocated bytes.
pub fn encode(allocator: std.mem.Allocator, value: anytype) (std.mem.Allocator.Error || RlpError)![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try encodeInto(allocator, &list, value);
    return list.toOwnedSlice(allocator);
}

/// Encode a value and append to the given ArrayList.
pub fn encodeInto(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: anytype) (std.mem.Allocator.Error || RlpError)!void {
    const T = @TypeOf(value);
    const info = @typeInfo(T);

    switch (info) {
        .bool => {
            if (value) {
                try list.append(allocator, 0x01);
            } else {
                try list.append(allocator, 0x80);
            }
        },
        .int, .comptime_int => {
            try encodeUint(allocator, list, value);
        },
        .pointer => |ptr| {
            switch (ptr.size) {
                .one => {
                    // Pointer to array (e.g., *const [N]u8)
                    try encodeInto(allocator, list, value.*);
                },
                .slice => {
                    if (ptr.child == u8) {
                        // Byte slice: encode as string
                        try encodeBytes(allocator, list, value);
                    } else {
                        // Slice of non-bytes: encode as list
                        try encodeList(allocator, list, value);
                    }
                },
                else => @compileError("unsupported pointer type for RLP encoding"),
            }
        },
        .array => |arr| {
            if (arr.child == u8) {
                // [N]u8: encode as string
                try encodeBytes(allocator, list, &value);
            } else {
                // [N]T: encode as list
                try encodeList(allocator, list, &value);
            }
        },
        .@"struct" => |s| {
            // Structs encode as RLP lists of their fields
            var temp: std.ArrayList(u8) = .empty;
            defer temp.deinit(allocator);

            inline for (s.fields) |field| {
                try encodeInto(allocator, &temp, @field(value, field.name));
            }

            try encodeLength(allocator, list, temp.items.len, 0xc0);
            try list.appendSlice(allocator, temp.items);
        },
        .optional => {
            if (value) |v| {
                try encodeInto(allocator, list, v);
            } else {
                // None encodes as empty string
                try list.append(allocator, 0x80);
            }
        },
        else => return error.UnsupportedType,
    }
}

fn encodeUint(allocator: std.mem.Allocator, list: *std.ArrayList(u8), value: anytype) std.mem.Allocator.Error!void {
    const val: u256 = @intCast(value);

    if (val == 0) {
        try list.append(allocator, 0x80);
        return;
    }

    if (val < 128) {
        try list.append(allocator, @intCast(val));
        return;
    }

    // Determine byte length needed
    var byte_len: usize = 0;
    var temp = val;
    while (temp > 0) : (temp >>= 8) {
        byte_len += 1;
    }

    try encodeLength(allocator, list, byte_len, 0x80);

    // Write big-endian bytes
    var i: usize = byte_len;
    while (i > 0) {
        i -= 1;
        const shift: u8 = @intCast(i * 8);
        try list.append(allocator, @truncate(val >> shift));
    }
}

fn encodeBytes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), bytes: []const u8) std.mem.Allocator.Error!void {
    if (bytes.len == 1 and bytes[0] < 0x80) {
        try list.append(allocator, bytes[0]);
    } else {
        try encodeLength(allocator, list, bytes.len, 0x80);
        try list.appendSlice(allocator, bytes);
    }
}

fn encodeList(allocator: std.mem.Allocator, list: *std.ArrayList(u8), items: anytype) (std.mem.Allocator.Error || RlpError)!void {
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(allocator);

    for (items) |item| {
        try encodeInto(allocator, &temp, item);
    }

    try encodeLength(allocator, list, temp.items.len, 0xc0);
    try list.appendSlice(allocator, temp.items);
}

fn encodeLength(allocator: std.mem.Allocator, list: *std.ArrayList(u8), len: usize, offset: u8) std.mem.Allocator.Error!void {
    if (len < 56) {
        try list.append(allocator, offset + @as(u8, @intCast(len)));
    } else {
        // Compute byte length of len
        var len_bytes: usize = 0;
        var temp = len;
        while (temp > 0) : (temp >>= 8) {
            len_bytes += 1;
        }

        try list.append(allocator, offset + 55 + @as(u8, @intCast(len_bytes)));

        // Write length in big-endian
        var i: usize = len_bytes;
        while (i > 0) {
            i -= 1;
            try list.append(allocator, @intCast((len >> @intCast(i * 8)) & 0xff));
        }
    }
}

// ============================================================================
// Decoding
// ============================================================================

/// Result of decoding: the value and the remaining unprocessed bytes.
pub fn Decoded(comptime T: type) type {
    return struct {
        value: T,
        rest: []const u8,
    };
}

/// Decode a value from RLP bytes.
pub fn decode(comptime T: type, data: []const u8) (RlpError || error{OutOfMemory})!Decoded(T) {
    if (data.len == 0) return error.InputTooShort;

    const info = @typeInfo(T);
    switch (info) {
        .int => {
            const item = try decodeItem(data);
            if (item.kind != .string) return error.InvalidRlp;
            const val = try bytesToUint(T, item.payload);
            return .{ .value = val, .rest = item.rest };
        },
        .bool => {
            const item = try decodeItem(data);
            if (item.kind != .string) return error.InvalidRlp;
            if (item.payload.len == 0) return .{ .value = false, .rest = item.rest };
            if (item.payload.len == 1 and item.payload[0] == 0x01) return .{ .value = true, .rest = item.rest };
            return error.InvalidRlp;
        },
        .array => |arr| {
            if (arr.child == u8) {
                // [N]u8
                const item = try decodeItem(data);
                if (item.kind != .string) return error.InvalidRlp;
                if (item.payload.len != arr.len) return error.InvalidRlp;
                var result: T = undefined;
                @memcpy(&result, item.payload);
                return .{ .value = result, .rest = item.rest };
            } else {
                @compileError("RLP decode for non-byte arrays not yet supported");
            }
        },
        else => @compileError("RLP decode not supported for type " ++ @typeName(T)),
    }
}

const ItemKind = enum { string, list };

const Item = struct {
    kind: ItemKind,
    payload: []const u8,
    rest: []const u8,
};

fn decodeItem(data: []const u8) RlpError!Item {
    if (data.len == 0) return error.InputTooShort;

    const prefix = data[0];

    if (prefix < 0x80) {
        // Single byte
        return .{ .kind = .string, .payload = data[0..1], .rest = data[1..] };
    } else if (prefix <= 0xb7) {
        // Short string (0-55 bytes)
        const len: usize = prefix - 0x80;
        if (data.len < 1 + len) return error.InputTooShort;
        // Canonical check: single byte < 0x80 should not use this form
        if (len == 1 and data[1] < 0x80) return error.NonCanonical;
        return .{ .kind = .string, .payload = data[1 .. 1 + len], .rest = data[1 + len ..] };
    } else if (prefix <= 0xbf) {
        // Long string (>55 bytes)
        const len_bytes: usize = prefix - 0xb7;
        if (data.len < 1 + len_bytes) return error.InputTooShort;
        const len = try readLength(data[1 .. 1 + len_bytes]);
        if (len < 56) return error.NonCanonical;
        if (data.len < 1 + len_bytes + len) return error.InputTooShort;
        return .{
            .kind = .string,
            .payload = data[1 + len_bytes .. 1 + len_bytes + len],
            .rest = data[1 + len_bytes + len ..],
        };
    } else if (prefix <= 0xf7) {
        // Short list (0-55 bytes total)
        const len: usize = prefix - 0xc0;
        if (data.len < 1 + len) return error.InputTooShort;
        return .{ .kind = .list, .payload = data[1 .. 1 + len], .rest = data[1 + len ..] };
    } else {
        // Long list (>55 bytes total)
        const len_bytes: usize = prefix - 0xf7;
        if (data.len < 1 + len_bytes) return error.InputTooShort;
        const len = try readLength(data[1 .. 1 + len_bytes]);
        if (len < 56) return error.NonCanonical;
        if (data.len < 1 + len_bytes + len) return error.InputTooShort;
        return .{
            .kind = .list,
            .payload = data[1 + len_bytes .. 1 + len_bytes + len],
            .rest = data[1 + len_bytes + len ..],
        };
    }
}

fn readLength(bytes: []const u8) RlpError!usize {
    if (bytes.len == 0) return error.InputTooShort;
    if (bytes[0] == 0) return error.LeadingZero;

    var result: usize = 0;
    for (bytes) |b| {
        result = std.math.mul(usize, result, 256) catch return error.Overflow;
        result = std.math.add(usize, result, b) catch return error.Overflow;
    }
    return result;
}

fn bytesToUint(comptime T: type, bytes: []const u8) RlpError!T {
    if (bytes.len == 0) return 0;
    if (bytes.len > @sizeOf(T)) return error.Overflow;
    if (bytes.len > 1 and bytes[0] == 0) return error.LeadingZero;

    var result: T = 0;
    for (bytes) |b| {
        result = (result << 8) | @as(T, b);
    }
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "encode single byte" {
    const allocator = std.testing.allocator;

    // 0x00 encodes as 0x00
    const zero = try encode(allocator, @as(u8, 0));
    defer allocator.free(zero);
    try std.testing.expectEqualSlices(u8, &.{0x80}, zero);

    // 0x01 encodes as 0x01
    const one = try encode(allocator, @as(u8, 1));
    defer allocator.free(one);
    try std.testing.expectEqualSlices(u8, &.{0x01}, one);

    // 0x7f encodes as 0x7f
    const max_single = try encode(allocator, @as(u8, 127));
    defer allocator.free(max_single);
    try std.testing.expectEqualSlices(u8, &.{0x7f}, max_single);
}

test "encode u16" {
    const allocator = std.testing.allocator;

    // 128 -> 0x81 0x80
    const val = try encode(allocator, @as(u16, 128));
    defer allocator.free(val);
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0x80 }, val);

    // 1024 -> 0x82 0x04 0x00
    const val2 = try encode(allocator, @as(u16, 1024));
    defer allocator.free(val2);
    try std.testing.expectEqualSlices(u8, &.{ 0x82, 0x04, 0x00 }, val2);
}

test "encode bytes" {
    const allocator = std.testing.allocator;

    // Empty bytes -> 0x80
    const empty = try encode(allocator, @as([]const u8, ""));
    defer allocator.free(empty);
    try std.testing.expectEqualSlices(u8, &.{0x80}, empty);

    // "dog" -> 0x83 'd' 'o' 'g'
    const dog = try encode(allocator, @as([]const u8, "dog"));
    defer allocator.free(dog);
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 'd', 'o', 'g' }, dog);
}

test "encode short list" {
    const allocator = std.testing.allocator;

    // Encode struct as RLP list
    const TestStruct = struct {
        a: u8,
        b: u16,
    };

    const result = try encode(allocator, TestStruct{ .a = 1, .b = 1024 });
    defer allocator.free(result);

    // Expected: 0xc4 (list, 4 bytes) 0x01 (a=1) 0x82 0x04 0x00 (b=1024)
    try std.testing.expectEqualSlices(u8, &.{ 0xc4, 0x01, 0x82, 0x04, 0x00 }, result);
}

test "encode bool" {
    const allocator = std.testing.allocator;

    const t = try encode(allocator, true);
    defer allocator.free(t);
    try std.testing.expectEqualSlices(u8, &.{0x01}, t);

    const f = try encode(allocator, false);
    defer allocator.free(f);
    try std.testing.expectEqualSlices(u8, &.{0x80}, f);
}

test "encode fixed bytes [4]u8" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const result = try encode(allocator, data);
    defer allocator.free(result);
    try std.testing.expectEqualSlices(u8, &.{ 0x84, 0xde, 0xad, 0xbe, 0xef }, result);
}

test "decode u8" {
    const result = try decode(u8, &.{0x01});
    try std.testing.expectEqual(@as(u8, 1), result.value);
    try std.testing.expectEqual(@as(usize, 0), result.rest.len);
}

test "decode u16" {
    const result = try decode(u16, &.{ 0x82, 0x04, 0x00 });
    try std.testing.expectEqual(@as(u16, 1024), result.value);
}

test "decode u256" {
    // Encode 0xdeadbeef, then decode
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, @as(u256, 0xdeadbeef));
    defer allocator.free(encoded);

    const decoded = try decode(u256, encoded);
    try std.testing.expectEqual(@as(u256, 0xdeadbeef), decoded.value);
}

test "decode bool" {
    const t = try decode(bool, &.{0x01});
    try std.testing.expect(t.value);

    const f = try decode(bool, &.{0x80});
    try std.testing.expect(!f.value);
}

test "decode [20]u8" {
    var data: [21]u8 = undefined;
    data[0] = 0x94; // 0x80 + 20
    for (0..20) |i| {
        data[1 + i] = @intCast(i);
    }

    const result = try decode([20]u8, &data);
    for (0..20) |i| {
        try std.testing.expectEqual(@as(u8, @intCast(i)), result.value[i]);
    }
}

test "encode-decode roundtrip u256 max" {
    const allocator = std.testing.allocator;
    const max: u256 = std.math.maxInt(u256);
    const encoded = try encode(allocator, max);
    defer allocator.free(encoded);

    const decoded = try decode(u256, encoded);
    try std.testing.expectEqual(max, decoded.value);
}
