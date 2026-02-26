const std = @import("std");
const uint256_mod = @import("uint256.zig");

/// Tagged union representing any ABI-encodable value.
pub const AbiValue = union(enum) {
    /// Unsigned 256-bit integer (covers uint8 through uint256).
    uint256: u256,
    /// Signed 256-bit integer (covers int8 through int256).
    int256: i256,
    /// 20-byte Ethereum address.
    address: [20]u8,
    /// Boolean value.
    boolean: bool,
    /// Fixed-size byte array (1-32 bytes, right-padded).
    fixed_bytes: FixedBytes,
    /// Dynamic byte array.
    bytes: []const u8,
    /// Dynamic string (encoded identically to bytes).
    string: []const u8,
    /// Dynamic array of values.
    array: []const AbiValue,
    /// Fixed-length array of values.
    fixed_array: []const AbiValue,
    /// Tuple of values.
    tuple: []const AbiValue,

    pub const FixedBytes = struct {
        data: [32]u8 = [_]u8{0} ** 32,
        len: u8,
    };

    /// Returns true if this value is a dynamic type in ABI encoding.
    pub fn isDynamic(self: AbiValue) bool {
        return switch (self) {
            .bytes, .string, .array => true,
            .fixed_array => |items| {
                // A fixed array is dynamic if its element type is dynamic
                for (items) |item| {
                    if (item.isDynamic()) return true;
                }
                return false;
            },
            .tuple => |items| {
                for (items) |item| {
                    if (item.isDynamic()) return true;
                }
                return false;
            },
            else => false,
        };
    }
};

/// Errors during ABI encoding.
pub const EncodeError = error{
    OutOfMemory,
};

/// Encode a slice of ABI values according to the Solidity ABI specification.
/// Returns the encoded bytes. Caller owns the returned memory.
pub fn encodeValues(allocator: std.mem.Allocator, values: []const AbiValue) EncodeError![]u8 {
    const total = calcEncodedSize(values);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    writeValuesDirect(buf, values);
    return buf;
}

/// Encode a function call: 4-byte selector followed by ABI-encoded arguments.
/// Returns the encoded bytes. Caller owns the returned memory.
pub fn encodeFunctionCall(allocator: std.mem.Allocator, selector: [4]u8, values: []const AbiValue) EncodeError![]u8 {
    const total = 4 + calcEncodedSize(values);
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    @memcpy(buf[0..4], &selector);
    writeValuesDirect(buf[4..], values);
    return buf;
}

/// Calculate the encoded size of a dynamic value's tail (excluding head offset word).
fn dynamicTailSize(val: AbiValue) usize {
    return switch (val) {
        .bytes => |d| 32 + d.len + ((32 - (d.len % 32)) % 32),
        .string => |d| 32 + d.len + ((32 - (d.len % 32)) % 32),
        .array => |items| 32 + calcEncodedSize(items),
        .fixed_array => |items| calcEncodedSize(items),
        .tuple => |items| calcEncodedSize(items),
        else => 0,
    };
}

/// Calculate the inline encoded size of a static ABI value.
/// Static fixed_arrays and tuples are encoded inline and may exceed 32 bytes.
fn staticEncodedSize(val: AbiValue) usize {
    return switch (val) {
        .fixed_array, .tuple => |items| {
            var size: usize = 0;
            for (items) |item| size += staticEncodedSize(item);
            return size;
        },
        else => 32,
    };
}

/// Calculate the total encoded size of a slice of values (head + tail).
fn calcEncodedSize(values: []const AbiValue) usize {
    var size: usize = 0;
    for (values) |val| {
        if (val.isDynamic()) {
            size += 32; // offset pointer
            size += dynamicTailSize(val);
        } else {
            size += staticEncodedSize(val);
        }
    }
    return size;
}

/// Encode values into an existing ArrayList.
fn encodeValuesInto(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), values: []const AbiValue) EncodeError!void {
    const n = values.len;
    if (n == 0) return;

    // Pre-calculate total size and ensure capacity in one allocation
    const total_size = calcEncodedSize(values);
    try buf.ensureTotalCapacity(allocator, buf.items.len + total_size);

    // Calculate tail offset: starts after all head words
    const head_size = n * 32;
    var tail_offset: usize = head_size;

    // First pass: calculate tail offsets for dynamic values
    // and pre-compute the offset each dynamic value will be at
    var offsets: [32]usize = undefined; // max 32 values in a single tuple
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            offsets[i] = tail_offset;
            tail_offset += dynamicTailSize(val);
        }
    }

    // Second pass: write head section
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            writeUint256NoAlloc(buf, @intCast(offsets[i]));
        } else {
            encodeStaticValueNoAlloc(buf, val);
        }
    }

    // Third pass: write tail section directly into buf (no temp allocations)
    for (values) |val| {
        if (val.isDynamic()) {
            encodeDynamicValueInto(allocator, buf, val);
        }
    }
}

/// Write a u256 as a big-endian 32-byte word without allocation (capacity must be pre-ensured).
fn writeUint256NoAlloc(buf: *std.ArrayList(u8), value: u256) void {
    const bytes = uint256_mod.toBigEndianBytes(value);
    buf.appendSliceAssumeCapacity(&bytes);
}

/// Encode a static value directly as a 32-byte word without allocation.
fn encodeStaticValueNoAlloc(buf: *std.ArrayList(u8), val: AbiValue) void {
    switch (val) {
        .uint256 => |v| {
            writeUint256NoAlloc(buf, v);
        },
        .int256 => |v| {
            const unsigned: u256 = @bitCast(v);
            writeUint256NoAlloc(buf, unsigned);
        },
        .address => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            @memcpy(word[12..32], &v);
            buf.appendSliceAssumeCapacity(&word);
        },
        .boolean => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            if (v) word[31] = 1;
            buf.appendSliceAssumeCapacity(&word);
        },
        .fixed_bytes => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            const size: usize = @intCast(v.len);
            @memcpy(word[0..size], v.data[0..size]);
            buf.appendSliceAssumeCapacity(&word);
        },
        .fixed_array => |items| {
            for (items) |item| {
                encodeStaticValueNoAlloc(buf, item);
            }
        },
        .tuple => |items| {
            for (items) |item| {
                encodeStaticValueNoAlloc(buf, item);
            }
        },
        else => unreachable,
    }
}

/// Encode a static value directly as a 32-byte word (allocating variant for backward compat).
fn encodeStaticValue(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), val: AbiValue) EncodeError!void {
    switch (val) {
        .uint256 => |v| {
            try writeUint256(allocator, buf, v);
        },
        .int256 => |v| {
            try writeInt256(allocator, buf, v);
        },
        .address => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            @memcpy(word[12..32], &v);
            try buf.appendSlice(allocator, &word);
        },
        .boolean => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            if (v) word[31] = 1;
            try buf.appendSlice(allocator, &word);
        },
        .fixed_bytes => |v| {
            var word: [32]u8 = [_]u8{0} ** 32;
            const size: usize = @intCast(v.len);
            @memcpy(word[0..size], v.data[0..size]);
            try buf.appendSlice(allocator, &word);
        },
        .fixed_array => |items| {
            for (items) |item| {
                try encodeStaticValue(allocator, buf, item);
            }
        },
        .tuple => |items| {
            for (items) |item| {
                try encodeStaticValue(allocator, buf, item);
            }
        },
        else => unreachable,
    }
}

/// Encode a dynamic value directly into the output buffer (no temp allocation).
fn encodeDynamicValueInto(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), val: AbiValue) void {
    _ = allocator;

    switch (val) {
        .bytes => |data| {
            writeUint256NoAlloc(buf, @intCast(data.len));
            buf.appendSliceAssumeCapacity(data);
            const padding = (32 - (data.len % 32)) % 32;
            buf.appendNTimesAssumeCapacity(0, padding);
        },
        .string => |data| {
            writeUint256NoAlloc(buf, @intCast(data.len));
            buf.appendSliceAssumeCapacity(data);
            const padding = (32 - (data.len % 32)) % 32;
            buf.appendNTimesAssumeCapacity(0, padding);
        },
        .array => |items| {
            writeUint256NoAlloc(buf, @intCast(items.len));
            encodeValuesIntoNoAlloc(buf, items);
        },
        .fixed_array => |items| {
            encodeValuesIntoNoAlloc(buf, items);
        },
        .tuple => |items| {
            encodeValuesIntoNoAlloc(buf, items);
        },
        else => unreachable,
    }
}

/// Encode values into an ArrayList that already has sufficient capacity.
fn encodeValuesIntoNoAlloc(buf: *std.ArrayList(u8), values: []const AbiValue) void {
    const n = values.len;
    if (n == 0) return;

    const head_size = n * 32;
    var tail_offset: usize = head_size;

    // Calculate offsets for dynamic values
    var offsets: [32]usize = undefined;
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            offsets[i] = tail_offset;
            tail_offset += dynamicTailSize(val);
        }
    }

    // Write heads
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            writeUint256NoAlloc(buf, @intCast(offsets[i]));
        } else {
            encodeStaticValueNoAlloc(buf, val);
        }
    }

    // Write tails
    for (values) |val| {
        if (val.isDynamic()) {
            encodeDynamicValueInto(undefined, buf, val);
        }
    }
}

/// Write values directly into a raw buffer (zero ArrayList overhead).
fn writeValuesDirect(buf: []u8, values: []const AbiValue) void {
    const n = values.len;
    if (n == 0) return;

    // Fast path: if all values are static, skip offset calculation entirely
    var has_dynamic = false;
    for (values) |val| {
        if (val.isDynamic()) {
            has_dynamic = true;
            break;
        }
    }

    if (!has_dynamic) {
        var pos: usize = 0;
        for (values) |val| {
            writeStaticValueDirect(buf[pos..], val);
            pos += staticEncodedSize(val);
        }
        return;
    }

    // Dynamic path: calculate head section size and offsets
    var head_size: usize = 0;
    for (values) |val| {
        head_size += if (val.isDynamic()) 32 else staticEncodedSize(val);
    }
    var tail_offset: usize = head_size;

    var offsets: [32]usize = undefined;
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            offsets[i] = tail_offset;
            tail_offset += dynamicTailSize(val);
        }
    }

    // Write heads
    var pos: usize = 0;
    for (values, 0..) |val, i| {
        if (val.isDynamic()) {
            writeU256Direct(buf[pos..][0..32], @intCast(offsets[i]));
            pos += 32;
        } else {
            writeStaticValueDirect(buf[pos..], val);
            pos += staticEncodedSize(val);
        }
    }

    // Write tails
    for (values) |val| {
        if (val.isDynamic()) {
            pos += writeDynamicValueDirect(buf[pos..], val);
        }
    }
}

/// Write a u256 as big-endian 32-byte word directly into buffer.
fn writeU256Direct(dest: *[32]u8, value: u256) void {
    dest.* = uint256_mod.toBigEndianBytes(value);
}

/// Write a static value directly into buffer as 32-byte word.
fn writeStaticValueDirect(buf: []u8, val: AbiValue) void {
    switch (val) {
        .uint256 => |v| writeU256Direct(buf[0..32], v),
        .int256 => |v| writeU256Direct(buf[0..32], @bitCast(v)),
        .address => |v| {
            @memset(buf[0..12], 0);
            @memcpy(buf[12..32], &v);
        },
        .boolean => |v| {
            @memset(buf[0..31], 0);
            buf[31] = if (v) 1 else 0;
        },
        .fixed_bytes => |v| {
            const size: usize = @intCast(v.len);
            @memcpy(buf[0..size], v.data[0..size]);
            @memset(buf[size..32], 0);
        },
        .fixed_array, .tuple => |items| {
            var pos: usize = 0;
            for (items) |item| {
                writeStaticValueDirect(buf[pos..], item);
                pos += 32;
            }
        },
        else => unreachable,
    }
}

/// Write a dynamic value directly into buffer. Returns bytes written.
fn writeDynamicValueDirect(buf: []u8, val: AbiValue) usize {
    switch (val) {
        .bytes, .string => |data| {
            writeU256Direct(buf[0..32], @intCast(data.len));
            @memcpy(buf[32..][0..data.len], data);
            const padding = (32 - (data.len % 32)) % 32;
            @memset(buf[32 + data.len ..][0..padding], 0);
            return 32 + data.len + padding;
        },
        .array => |items| {
            writeU256Direct(buf[0..32], @intCast(items.len));
            writeValuesDirect(buf[32..], items);
            return 32 + calcEncodedSize(items);
        },
        .fixed_array, .tuple => |items| {
            writeValuesDirect(buf, items);
            return calcEncodedSize(items);
        },
        else => unreachable,
    }
}

/// Write a u256 as a big-endian 32-byte word.
fn writeUint256(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: u256) EncodeError!void {
    const bytes = uint256_mod.toBigEndianBytes(value);
    try buf.appendSlice(allocator, &bytes);
}

/// Write an i256 as a big-endian 32-byte two's complement word.
fn writeInt256(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: i256) EncodeError!void {
    // Two's complement: cast to u256 bit pattern, then write as big-endian.
    const unsigned: u256 = @bitCast(value);
    try writeUint256(allocator, buf, unsigned);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const hex_mod = @import("hex.zig");

test "encode single uint256" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .uint256 = 100 }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    // 100 = 0x64, should be at byte 31
    try testing.expectEqual(@as(u8, 0x64), encoded[31]);
    // All other bytes should be 0
    for (encoded[0..31]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "encode single address" {
    const allocator = testing.allocator;
    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xde;
    addr[1] = 0xad;
    addr[18] = 0xbe;
    addr[19] = 0xef;

    const values = [_]AbiValue{.{ .address = addr }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    // First 12 bytes should be 0 (left-padding)
    for (encoded[0..12]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
    // Address starts at byte 12
    try testing.expectEqual(@as(u8, 0xde), encoded[12]);
    try testing.expectEqual(@as(u8, 0xad), encoded[13]);
    try testing.expectEqual(@as(u8, 0xbe), encoded[30]);
    try testing.expectEqual(@as(u8, 0xef), encoded[31]);
}

test "encode bool true and false" {
    const allocator = testing.allocator;

    const true_values = [_]AbiValue{.{ .boolean = true }};
    const true_encoded = try encodeValues(allocator, &true_values);
    defer allocator.free(true_encoded);

    try testing.expectEqual(@as(usize, 32), true_encoded.len);
    try testing.expectEqual(@as(u8, 1), true_encoded[31]);

    const false_values = [_]AbiValue{.{ .boolean = false }};
    const false_encoded = try encodeValues(allocator, &false_values);
    defer allocator.free(false_encoded);

    try testing.expectEqual(@as(usize, 32), false_encoded.len);
    try testing.expectEqual(@as(u8, 0), false_encoded[31]);
}

test "encode fixed bytes4" {
    const allocator = testing.allocator;
    var fb = AbiValue.FixedBytes{ .len = 4 };
    fb.data[0] = 0xde;
    fb.data[1] = 0xad;
    fb.data[2] = 0xbe;
    fb.data[3] = 0xef;

    const values = [_]AbiValue{.{ .fixed_bytes = fb }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    // Fixed bytes are right-padded: data in first 4 bytes, rest zeros
    try testing.expectEqual(@as(u8, 0xde), encoded[0]);
    try testing.expectEqual(@as(u8, 0xad), encoded[1]);
    try testing.expectEqual(@as(u8, 0xbe), encoded[2]);
    try testing.expectEqual(@as(u8, 0xef), encoded[3]);
    for (encoded[4..32]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "encode int256 negative" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .int256 = -1 }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    // -1 in two's complement is all 0xff bytes
    for (encoded) |b| {
        try testing.expectEqual(@as(u8, 0xff), b);
    }
}

test "encode dynamic bytes" {
    const allocator = testing.allocator;
    const data = "hello";
    const values = [_]AbiValue{.{ .bytes = data }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Head: 32 bytes (offset to tail = 0x20)
    // Tail: 32 bytes (length = 5) + 32 bytes (data padded)
    try testing.expectEqual(@as(usize, 96), encoded.len);

    // Offset should be 32 (0x20)
    try testing.expectEqual(@as(u8, 0x20), encoded[31]);

    // Length at offset 32 should be 5
    try testing.expectEqual(@as(u8, 5), encoded[63]);

    // Data starts at offset 64
    try testing.expectEqualSlices(u8, "hello", encoded[64..69]);

    // Padding bytes should be 0
    for (encoded[69..96]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "encode string" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .string = "hello world" }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Head: 32 bytes offset, Tail: 32 bytes length + 32 bytes padded data
    try testing.expectEqual(@as(usize, 96), encoded.len);

    // Offset = 32
    try testing.expectEqual(@as(u8, 0x20), encoded[31]);

    // Length = 11
    try testing.expectEqual(@as(u8, 11), encoded[63]);

    // Data
    try testing.expectEqualSlices(u8, "hello world", encoded[64..75]);
}

test "encode dynamic array" {
    const allocator = testing.allocator;
    const items = [_]AbiValue{
        .{ .uint256 = 1 },
        .{ .uint256 = 2 },
        .{ .uint256 = 3 },
    };
    const values = [_]AbiValue{.{ .array = &items }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Head: 32 bytes (offset)
    // Tail: 32 bytes (length=3) + 3*32 bytes (elements)
    try testing.expectEqual(@as(usize, 32 + 32 + 3 * 32), encoded.len);

    // Offset = 32
    try testing.expectEqual(@as(u8, 0x20), encoded[31]);

    // Length = 3
    try testing.expectEqual(@as(u8, 3), encoded[63]);

    // Elements
    try testing.expectEqual(@as(u8, 1), encoded[95]);
    try testing.expectEqual(@as(u8, 2), encoded[127]);
    try testing.expectEqual(@as(u8, 3), encoded[159]);
}

test "encode multiple static values" {
    const allocator = testing.allocator;
    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[19] = 0x01;

    const values = [_]AbiValue{
        .{ .address = addr },
        .{ .uint256 = 100 },
        .{ .boolean = true },
    };
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 96), encoded.len);

    // Address at word 0
    try testing.expectEqual(@as(u8, 0x01), encoded[31]);

    // uint256(100) at word 1
    try testing.expectEqual(@as(u8, 0x64), encoded[63]);

    // bool(true) at word 2
    try testing.expectEqual(@as(u8, 0x01), encoded[95]);
}

test "encode mixed static and dynamic" {
    const allocator = testing.allocator;
    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[19] = 0x01;

    const values = [_]AbiValue{
        .{ .uint256 = 42 },
        .{ .string = "hi" },
        .{ .uint256 = 7 },
    };
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Head: 3 * 32 = 96 bytes
    //   word 0: uint256(42) = static
    //   word 1: offset to string tail = 96 (0x60)
    //   word 2: uint256(7) = static
    // Tail for string "hi":
    //   word 3: length = 2
    //   word 4: "hi" padded to 32 bytes
    try testing.expectEqual(@as(usize, 5 * 32), encoded.len);

    // word 0: 42
    try testing.expectEqual(@as(u8, 42), encoded[31]);

    // word 1: offset 96 = 0x60
    try testing.expectEqual(@as(u8, 0x60), encoded[63]);

    // word 2: 7
    try testing.expectEqual(@as(u8, 7), encoded[95]);

    // word 3: length 2
    try testing.expectEqual(@as(u8, 2), encoded[127]);

    // word 4: "hi"
    try testing.expectEqualSlices(u8, "hi", encoded[128..130]);
}

test "encodeFunctionCall - transfer(address,uint256)" {
    const allocator = testing.allocator;
    const selector = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb };

    // transfer(0x000...0001, 100)
    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[19] = 0x01;

    const values = [_]AbiValue{
        .{ .address = addr },
        .{ .uint256 = 100 },
    };
    const encoded = try encodeFunctionCall(allocator, selector, &values);
    defer allocator.free(encoded);

    // 4 bytes selector + 2 * 32 bytes args
    try testing.expectEqual(@as(usize, 68), encoded.len);

    // Selector
    try testing.expectEqualSlices(u8, &selector, encoded[0..4]);

    // Address at word 0 (offset 4)
    try testing.expectEqual(@as(u8, 0x01), encoded[35]);

    // uint256(100) at word 1 (offset 36)
    try testing.expectEqual(@as(u8, 0x64), encoded[67]);
}

test "encodeFunctionCall - full transfer encoding" {
    // This test verifies the exact encoding of transfer(address,uint256) with specific values.
    // transfer(0xdEAD000000000000000000000000000000000000, 100)
    const allocator = testing.allocator;

    const keccak_mod = @import("keccak.zig");
    const sel = keccak_mod.selector("transfer(address,uint256)");
    try testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &sel);

    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xdE;
    addr[1] = 0xAD;

    const values = [_]AbiValue{
        .{ .address = addr },
        .{ .uint256 = 100 },
    };
    const encoded = try encodeFunctionCall(allocator, sel, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 68), encoded.len);

    // Selector bytes
    try testing.expectEqual(@as(u8, 0xa9), encoded[0]);
    try testing.expectEqual(@as(u8, 0x05), encoded[1]);
    try testing.expectEqual(@as(u8, 0x9c), encoded[2]);
    try testing.expectEqual(@as(u8, 0xbb), encoded[3]);

    // Address: 12 zero bytes + 0xdEAD + 18 zero bytes
    for (encoded[4..16]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
    try testing.expectEqual(@as(u8, 0xdE), encoded[16]);
    try testing.expectEqual(@as(u8, 0xAD), encoded[17]);

    // Amount: 100 = 0x64
    try testing.expectEqual(@as(u8, 0x64), encoded[67]);
}

test "encode empty values" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 0), encoded.len);
}

test "encode tuple static" {
    const allocator = testing.allocator;
    const tuple_vals = [_]AbiValue{
        .{ .uint256 = 1 },
        .{ .uint256 = 2 },
    };
    const values = [_]AbiValue{.{ .tuple = &tuple_vals }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Static tuple with 2 uint256 values = 2 * 32 = 64 bytes
    // But since tuple is always dynamic, it uses offset encoding:
    // Head: 32 bytes (offset = 32)
    // Tail: 2 * 32 = 64 bytes (the two uint256 values)
    try testing.expectEqual(@as(usize, 96), encoded.len);
}

test "encode large uint256" {
    const allocator = testing.allocator;
    const max_u256: u256 = std.math.maxInt(u256);
    const values = [_]AbiValue{.{ .uint256 = max_u256 }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    for (encoded) |b| {
        try testing.expectEqual(@as(u8, 0xff), b);
    }
}

test "encode int256 positive" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .int256 = 42 }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    try testing.expectEqual(@as(u8, 42), encoded[31]);
    for (encoded[0..31]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "encode int256 min value" {
    const allocator = testing.allocator;
    const min_i256: i256 = std.math.minInt(i256);
    const values = [_]AbiValue{.{ .int256 = min_i256 }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 32), encoded.len);
    // min i256 = 0x80000...0
    try testing.expectEqual(@as(u8, 0x80), encoded[0]);
    for (encoded[1..]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "encode bytes exactly 32 bytes - no padding needed" {
    const allocator = testing.allocator;
    const data = [_]u8{0xab} ** 32;
    const values = [_]AbiValue{.{ .bytes = &data }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // offset (32) + length (32) + data (32, already aligned)
    try testing.expectEqual(@as(usize, 96), encoded.len);
}

test "encode empty bytes" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .bytes = "" }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // offset (32) + length (32) + data (0, no padding needed)
    try testing.expectEqual(@as(usize, 64), encoded.len);
    // offset = 32
    try testing.expectEqual(@as(u8, 0x20), encoded[31]);
    // length = 0
    try testing.expectEqual(@as(u8, 0), encoded[63]);
}

test "encode empty string" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{.{ .string = "" }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 64), encoded.len);
}

test "encode empty dynamic array" {
    const allocator = testing.allocator;
    const items = [_]AbiValue{};
    const values = [_]AbiValue{.{ .array = &items }};
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // offset (32) + length (32) = 64
    try testing.expectEqual(@as(usize, 64), encoded.len);
    // offset = 32
    try testing.expectEqual(@as(u8, 0x20), encoded[31]);
    // length = 0
    try testing.expectEqual(@as(u8, 0), encoded[63]);
}

test "encode two dynamic values" {
    const allocator = testing.allocator;
    const values = [_]AbiValue{
        .{ .string = "abc" },
        .{ .string = "def" },
    };
    const encoded = try encodeValues(allocator, &values);
    defer allocator.free(encoded);

    // Head: 2 * 32 = 64 bytes (two offsets)
    // Tail for "abc": 32 (length) + 32 (padded data) = 64
    // Tail for "def": 32 (length) + 32 (padded data) = 64
    // Total: 64 + 64 + 64 = 192
    try testing.expectEqual(@as(usize, 192), encoded.len);

    // First offset = 64 (0x40)
    try testing.expectEqual(@as(u8, 0x40), encoded[31]);

    // Second offset = 64 + 64 = 128 (0x80)
    try testing.expectEqual(@as(u8, 0x80), encoded[63]);

    // First string length = 3
    try testing.expectEqual(@as(u8, 3), encoded[95]);
    try testing.expectEqualSlices(u8, "abc", encoded[96..99]);

    // Second string length = 3
    try testing.expectEqual(@as(u8, 3), encoded[159]);
    try testing.expectEqualSlices(u8, "def", encoded[160..163]);
}

test "encodeFunctionCall - balanceOf(address)" {
    const allocator = testing.allocator;
    const keccak_mod = @import("keccak.zig");
    const sel = keccak_mod.selector("balanceOf(address)");
    try testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &sel);

    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xd8;
    addr[1] = 0xdA;
    addr[19] = 0x45;

    const values = [_]AbiValue{.{ .address = addr }};
    const encoded = try encodeFunctionCall(allocator, sel, &values);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 36), encoded.len);
    try testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, encoded[0..4]);
}
