const std = @import("std");
const uint256_mod = @import("uint256.zig");
const abi_types = @import("abi_types.zig");
const abi_encode = @import("abi_encode.zig");
const AbiType = abi_types.AbiType;
const AbiValue = abi_encode.AbiValue;

/// Errors that can occur during ABI decoding.
pub const DecodeError = error{
    /// The encoded data is shorter than expected.
    DataTooShort,
    /// An offset points outside the data bounds.
    OffsetOutOfBounds,
    /// A length value would cause out-of-bounds access.
    LengthOutOfBounds,
    /// The encoded data is not properly aligned to 32-byte words.
    InvalidAlignment,
    /// A boolean value is not 0 or 1.
    InvalidBoolValue,
    /// An address has non-zero bytes in the padding area.
    InvalidAddressPadding,
    /// A fixed bytes value has non-zero bytes in the padding area.
    InvalidFixedBytesPadding,
    /// Allocation failure.
    OutOfMemory,
    /// The type requires component information (tuple, fixed_array, dynamic_array).
    UnsupportedType,
};

/// Decode ABI-encoded data into a slice of AbiValues according to the provided types.
/// Caller owns all returned memory (the slice and any inner allocations).
pub fn decodeValues(data: []const u8, types: []const AbiType, allocator: std.mem.Allocator) DecodeError![]AbiValue {
    return decodeValuesAt(data, 0, types, allocator);
}

/// Decode ABI-encoded function return data. This is identical to decodeValues since
/// function return data uses the same ABI encoding as arguments.
pub fn decodeFunctionReturn(data: []const u8, output_types: []const AbiType, allocator: std.mem.Allocator) DecodeError![]AbiValue {
    return decodeValues(data, output_types, allocator);
}

/// Free a slice of AbiValues that was returned by decodeValues or decodeFunctionReturn.
pub fn freeValues(values: []AbiValue, allocator: std.mem.Allocator) void {
    for (values) |*val| {
        freeValue(val, allocator);
    }
    allocator.free(values);
}

/// Free a single AbiValue's inner allocations.
fn freeValue(val: *AbiValue, allocator: std.mem.Allocator) void {
    switch (val.*) {
        .bytes => |data| {
            if (data.len > 0) allocator.free(data);
        },
        .string => |data| {
            if (data.len > 0) allocator.free(data);
        },
        .array => |items| {
            for (@constCast(items)) |*item| {
                freeValue(item, allocator);
            }
            allocator.free(items);
        },
        .fixed_array => |items| {
            for (@constCast(items)) |*item| {
                freeValue(item, allocator);
            }
            allocator.free(items);
        },
        .tuple => |items| {
            for (@constCast(items)) |*item| {
                freeValue(item, allocator);
            }
            allocator.free(items);
        },
        else => {},
    }
}

/// Decode values starting at a given base offset within data.
fn decodeValuesAt(data: []const u8, base: usize, types: []const AbiType, allocator: std.mem.Allocator) DecodeError![]AbiValue {
    const n = types.len;
    if (n == 0) {
        return try allocator.alloc(AbiValue, 0);
    }

    var result = try allocator.alloc(AbiValue, n);
    errdefer {
        for (result[0..n]) |*val| {
            freeValue(val, allocator);
        }
        allocator.free(result);
    }

    // Each value in the head takes 32 bytes.
    for (types, 0..) |abi_type, i| {
        const head_offset = base + i * 32;
        if (head_offset + 32 > data.len) return error.DataTooShort;

        if (abi_type.isDynamic()) {
            // Dynamic type: head contains offset relative to base
            const rel_offset = readUint256AsUsize(data[head_offset..][0..32]);
            const abs_offset = base + rel_offset;
            result[i] = try decodeDynamicValue(data, abs_offset, abi_type, allocator);
        } else {
            result[i] = try decodeStaticValue(data[head_offset..][0..32], abi_type, allocator);
        }
    }

    return result;
}

/// Decode a static value from a 32-byte word.
fn decodeStaticValue(word: *const [32]u8, abi_type: AbiType, allocator: std.mem.Allocator) DecodeError!AbiValue {
    _ = allocator;

    if (abi_type.isUint()) {
        return .{ .uint256 = uint256_mod.fromBigEndianBytes(word.*) };
    }

    if (abi_type.isInt()) {
        const unsigned = uint256_mod.fromBigEndianBytes(word.*);
        return .{ .int256 = @bitCast(unsigned) };
    }

    if (abi_type == .address) {
        var addr: [20]u8 = undefined;
        @memcpy(&addr, word[12..32]);
        return .{ .address = addr };
    }

    if (abi_type == .bool) {
        const val = uint256_mod.fromBigEndianBytes(word.*);
        if (val == 0) return .{ .boolean = false };
        if (val == 1) return .{ .boolean = true };
        return error.InvalidBoolValue;
    }

    if (abi_type.isFixedBytes()) {
        const size = abi_type.fixedBytesSize().?;
        var fb = AbiValue.FixedBytes{ .len = @intCast(size) };
        @memcpy(fb.data[0..size], word[0..size]);
        return .{ .fixed_bytes = fb };
    }

    // tuple, fixed_array, dynamic_array without components are unsupported
    return error.UnsupportedType;
}

/// Decode a dynamic value starting at the given absolute offset.
fn decodeDynamicValue(data: []const u8, offset: usize, abi_type: AbiType, allocator: std.mem.Allocator) DecodeError!AbiValue {
    switch (abi_type) {
        .bytes => {
            return decodeDynamicBytes(data, offset, allocator, .bytes);
        },
        .string => {
            return decodeDynamicBytes(data, offset, allocator, .string);
        },
        .dynamic_array => {
            // Without element type info we can only decode as raw bytes
            // For a full implementation, element type would be needed.
            // We decode as an array of uint256 values as the most common case.
            return decodeDynamicArray(data, offset, .uint256, allocator);
        },
        .tuple => {
            // Without component info, we cannot decode tuples.
            return error.UnsupportedType;
        },
        else => return error.UnsupportedType,
    }
}

/// Decode dynamic bytes or string from the data at the given offset.
fn decodeDynamicBytes(data: []const u8, offset: usize, allocator: std.mem.Allocator, tag: enum { bytes, string }) DecodeError!AbiValue {
    if (offset + 32 > data.len) return error.OffsetOutOfBounds;

    const length = readUint256AsUsize(data[offset..][0..32]);
    const data_start = offset + 32;

    if (data_start + length > data.len) return error.LengthOutOfBounds;

    if (length == 0) {
        const empty: []const u8 = &.{};
        return switch (tag) {
            .bytes => .{ .bytes = empty },
            .string => .{ .string = empty },
        };
    }

    const result = try allocator.alloc(u8, length);
    errdefer allocator.free(result);
    @memcpy(result, data[data_start .. data_start + length]);

    return switch (tag) {
        .bytes => .{ .bytes = result },
        .string => .{ .string = result },
    };
}

/// Decode a dynamic array of a given element type.
fn decodeDynamicArray(data: []const u8, offset: usize, element_type: AbiType, allocator: std.mem.Allocator) DecodeError!AbiValue {
    if (offset + 32 > data.len) return error.OffsetOutOfBounds;

    const length = readUint256AsUsize(data[offset..][0..32]);
    const elements_start = offset + 32;

    if (length == 0) {
        const empty: []const AbiValue = &.{};
        return .{ .array = empty };
    }

    const types = try allocator.alloc(AbiType, length);
    defer allocator.free(types);
    for (types) |*t| {
        t.* = element_type;
    }

    const items = try decodeValuesAt(data, elements_start, types, allocator);
    return .{ .array = items };
}

/// Read a 32-byte big-endian word as a usize.
/// Returns max usize if the value overflows, which will cause a bounds check later.
fn readUint256AsUsize(word: *const [32]u8) usize {
    const val = uint256_mod.fromBigEndianBytes(word.*);
    if (val > std.math.maxInt(usize)) return std.math.maxInt(usize);
    return @intCast(val);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "decode single uint256" {
    const allocator = testing.allocator;

    // Encode uint256(100) = 32 zero bytes with 0x64 at position 31
    var data: [32]u8 = [_]u8{0} ** 32;
    data[31] = 0x64;

    const types = [_]AbiType{.uint256};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expectEqual(@as(u256, 100), values[0].uint256);
}

test "decode single address" {
    const allocator = testing.allocator;

    // Address is left-padded: 12 zero bytes + 20 address bytes
    var data: [32]u8 = [_]u8{0} ** 32;
    data[12] = 0xdE;
    data[13] = 0xAD;
    data[30] = 0xBE;
    data[31] = 0xEF;

    const types = [_]AbiType{.address};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expectEqual(@as(u8, 0xdE), values[0].address[0]);
    try testing.expectEqual(@as(u8, 0xAD), values[0].address[1]);
    try testing.expectEqual(@as(u8, 0xBE), values[0].address[18]);
    try testing.expectEqual(@as(u8, 0xEF), values[0].address[19]);
}

test "decode bool true and false" {
    const allocator = testing.allocator;

    var true_data: [32]u8 = [_]u8{0} ** 32;
    true_data[31] = 1;

    const types = [_]AbiType{.bool};
    const true_values = try decodeValues(&true_data, &types, allocator);
    defer freeValues(true_values, allocator);
    try testing.expect(true_values[0].boolean);

    var false_data: [32]u8 = [_]u8{0} ** 32;
    const false_values = try decodeValues(&false_data, &types, allocator);
    defer freeValues(false_values, allocator);
    try testing.expect(!false_values[0].boolean);
}

test "decode int256 negative" {
    const allocator = testing.allocator;

    // -1 in two's complement = all 0xff bytes
    var data: [32]u8 = [_]u8{0xff} ** 32;

    const types = [_]AbiType{.int256};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(i256, -1), values[0].int256);
}

test "decode fixed bytes4" {
    const allocator = testing.allocator;

    var data: [32]u8 = [_]u8{0} ** 32;
    data[0] = 0xde;
    data[1] = 0xad;
    data[2] = 0xbe;
    data[3] = 0xef;

    const types = [_]AbiType{.bytes4};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(u8, 4), values[0].fixed_bytes.len);
    try testing.expectEqual(@as(u8, 0xde), values[0].fixed_bytes.data[0]);
    try testing.expectEqual(@as(u8, 0xad), values[0].fixed_bytes.data[1]);
    try testing.expectEqual(@as(u8, 0xbe), values[0].fixed_bytes.data[2]);
    try testing.expectEqual(@as(u8, 0xef), values[0].fixed_bytes.data[3]);
}

test "decode multiple static values" {
    const allocator = testing.allocator;

    // address, uint256, bool
    var data: [96]u8 = [_]u8{0} ** 96;
    // Address at word 0
    data[31] = 0x01;
    // uint256(100) at word 1
    data[63] = 0x64;
    // bool(true) at word 2
    data[95] = 0x01;

    const types = [_]AbiType{ .address, .uint256, .bool };
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 3), values.len);
    try testing.expectEqual(@as(u8, 0x01), values[0].address[19]);
    try testing.expectEqual(@as(u256, 100), values[1].uint256);
    try testing.expect(values[2].boolean);
}

test "decode dynamic bytes" {
    const allocator = testing.allocator;

    // Encoding of a single bytes value: "hello"
    // Word 0: offset = 32 (0x20)
    // Word 1: length = 5
    // Word 2: "hello" + padding
    var data: [96]u8 = [_]u8{0} ** 96;
    data[31] = 0x20; // offset = 32
    data[63] = 0x05; // length = 5
    data[64] = 'h';
    data[65] = 'e';
    data[66] = 'l';
    data[67] = 'l';
    data[68] = 'o';

    const types = [_]AbiType{.bytes};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expectEqualSlices(u8, "hello", values[0].bytes);
}

test "decode string" {
    const allocator = testing.allocator;

    var data: [96]u8 = [_]u8{0} ** 96;
    data[31] = 0x20; // offset = 32
    data[63] = 0x0b; // length = 11
    @memcpy(data[64..75], "hello world");

    const types = [_]AbiType{.string};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expectEqualSlices(u8, "hello world", values[0].string);
}

test "decode empty bytes" {
    const allocator = testing.allocator;

    var data: [64]u8 = [_]u8{0} ** 64;
    data[31] = 0x20; // offset = 32
    // length = 0 (all zeros)

    const types = [_]AbiType{.bytes};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 0), values[0].bytes.len);
}

test "decode mixed static and dynamic" {
    const allocator = testing.allocator;

    // Encode: uint256(42), string("hi"), uint256(7)
    // Word 0: 42
    // Word 1: offset to string = 96 (0x60) (3 head words)
    // Word 2: 7
    // Word 3: string length = 2
    // Word 4: "hi" padded
    var data: [160]u8 = [_]u8{0} ** 160;
    data[31] = 42; // uint256(42)
    data[63] = 0x60; // offset = 96
    data[95] = 7; // uint256(7)
    data[127] = 2; // string length = 2
    data[128] = 'h';
    data[129] = 'i';

    const types = [_]AbiType{ .uint256, .string, .uint256 };
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 3), values.len);
    try testing.expectEqual(@as(u256, 42), values[0].uint256);
    try testing.expectEqualSlices(u8, "hi", values[1].string);
    try testing.expectEqual(@as(u256, 7), values[2].uint256);
}

test "decode too short data returns error" {
    const allocator = testing.allocator;

    const data = [_]u8{0} ** 16; // Only 16 bytes, need at least 32
    const types = [_]AbiType{.uint256};
    const result = decodeValues(&data, &types, allocator);
    try testing.expectError(error.DataTooShort, result);
}

test "decode empty types returns empty slice" {
    const allocator = testing.allocator;
    const data = [_]u8{0} ** 32;
    const types = [_]AbiType{};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);
    try testing.expectEqual(@as(usize, 0), values.len);
}

test "decode invalid bool returns error" {
    const allocator = testing.allocator;

    var data: [32]u8 = [_]u8{0} ** 32;
    data[31] = 2; // Invalid bool value

    const types = [_]AbiType{.bool};
    const result = decodeValues(&data, &types, allocator);
    try testing.expectError(error.InvalidBoolValue, result);
}

test "encode then decode roundtrip - static types" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xdE;
    addr[1] = 0xAD;
    addr[19] = 0xEF;

    const original = [_]AbiValue{
        .{ .address = addr },
        .{ .uint256 = 12345 },
        .{ .boolean = true },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{ .address, .uint256, .bool };
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqual(@as(usize, 3), decoded.len);
    try testing.expectEqualSlices(u8, &addr, &decoded[0].address);
    try testing.expectEqual(@as(u256, 12345), decoded[1].uint256);
    try testing.expect(decoded[2].boolean);
}

test "encode then decode roundtrip - dynamic bytes" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    const original = [_]AbiValue{
        .{ .bytes = "hello world" },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{.bytes};
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqualSlices(u8, "hello world", decoded[0].bytes);
}

test "encode then decode roundtrip - string" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    const original = [_]AbiValue{
        .{ .string = "ethereum" },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{.string};
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqualSlices(u8, "ethereum", decoded[0].string);
}

test "encode then decode roundtrip - mixed static and dynamic" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xAB;

    const original = [_]AbiValue{
        .{ .uint256 = 999 },
        .{ .string = "test data" },
        .{ .address = addr },
        .{ .bytes = "raw bytes here" },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{ .uint256, .string, .address, .bytes };
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqual(@as(usize, 4), decoded.len);
    try testing.expectEqual(@as(u256, 999), decoded[0].uint256);
    try testing.expectEqualSlices(u8, "test data", decoded[1].string);
    try testing.expectEqualSlices(u8, &addr, &decoded[2].address);
    try testing.expectEqualSlices(u8, "raw bytes here", decoded[3].bytes);
}

test "encode then decode roundtrip - int256 negative" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    const original = [_]AbiValue{
        .{ .int256 = -42 },
        .{ .int256 = 0 },
        .{ .int256 = 42 },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{ .int256, .int256, .int256 };
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqual(@as(i256, -42), decoded[0].int256);
    try testing.expectEqual(@as(i256, 0), decoded[1].int256);
    try testing.expectEqual(@as(i256, 42), decoded[2].int256);
}

test "decodeFunctionReturn works same as decodeValues" {
    const allocator = testing.allocator;

    // Encode a simple return: bool(true)
    var data: [32]u8 = [_]u8{0} ** 32;
    data[31] = 1;

    const types = [_]AbiType{.bool};
    const values = try decodeFunctionReturn(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expect(values[0].boolean);
}

test "decode uint8 and uint128" {
    const allocator = testing.allocator;

    var data: [64]u8 = [_]u8{0} ** 64;
    data[31] = 0xFF; // uint8 max = 255
    data[47] = 0x01; // uint128 = 1 << 120
    // rest zeros

    const types = [_]AbiType{ .uint8, .uint128 };
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(u256, 255), values[0].uint256);
}

test "decode fixed bytes32" {
    const allocator = testing.allocator;

    var data: [32]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @intCast(i);
    }

    const types = [_]AbiType{.bytes32};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(u8, 32), values[0].fixed_bytes.len);
    for (0..32) |i| {
        try testing.expectEqual(@as(u8, @intCast(i)), values[0].fixed_bytes.data[i]);
    }
}

test "decode two dynamic strings" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    const original = [_]AbiValue{
        .{ .string = "abc" },
        .{ .string = "def" },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{ .string, .string };
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqualSlices(u8, "abc", decoded[0].string);
    try testing.expectEqualSlices(u8, "def", decoded[1].string);
}

test "encode-decode roundtrip fixed_bytes1" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    var fb = AbiValue.FixedBytes{ .len = 1 };
    fb.data[0] = 0xAB;

    const original = [_]AbiValue{
        .{ .fixed_bytes = fb },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{.bytes1};
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqual(@as(u8, 1), decoded[0].fixed_bytes.len);
    try testing.expectEqual(@as(u8, 0xAB), decoded[0].fixed_bytes.data[0]);
}

test "encode-decode roundtrip fixed_bytes16" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    var fb = AbiValue.FixedBytes{ .len = 16 };
    for (0..16) |i| {
        fb.data[i] = 0xCC;
    }

    const original = [_]AbiValue{
        .{ .fixed_bytes = fb },
    };

    const encoded = try encode_mod.encodeValues(allocator, &original);
    defer allocator.free(encoded);

    const types = [_]AbiType{.bytes16};
    const decoded = try decodeValues(encoded, &types, allocator);
    defer freeValues(decoded, allocator);

    try testing.expectEqual(@as(u8, 16), decoded[0].fixed_bytes.len);
    for (0..16) |i| {
        try testing.expectEqual(@as(u8, 0xCC), decoded[0].fixed_bytes.data[i]);
    }
}

test "decode large dynamic bytes 100 bytes" {
    const allocator = testing.allocator;

    // Word 0: offset = 0x20 (32)
    // Word 1: length = 100 (0x64)
    // Words 2-5: 100 bytes of 0xAA + 28 bytes zero padding = 128 bytes
    // Total: 32 + 32 + 128 = 192 bytes
    var data: [192]u8 = [_]u8{0} ** 192;
    data[31] = 0x20; // offset = 32
    data[63] = 0x64; // length = 100
    for (64..164) |i| {
        data[i] = 0xAA;
    }

    const types = [_]AbiType{.bytes};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 100), values[0].bytes.len);
    for (values[0].bytes) |b| {
        try testing.expectEqual(@as(u8, 0xAA), b);
    }
}

test "decode large string 128 bytes" {
    const allocator = testing.allocator;

    // Word 0: offset = 0x20 (32)
    // Word 1: length = 128 (0x80)
    // Words 2-5: 128 bytes of 'B' (0x42), exactly 4 words, no padding needed
    // Total: 32 + 32 + 128 = 192 bytes
    var data: [192]u8 = [_]u8{0} ** 192;
    data[31] = 0x20; // offset = 32
    data[62] = 0x00;
    data[63] = 0x80; // length = 128
    for (64..192) |i| {
        data[i] = 0x42; // 'B'
    }

    const types = [_]AbiType{.string};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 128), values[0].string.len);
    for (values[0].string) |b| {
        try testing.expectEqual(@as(u8, 'B'), b);
    }
}

test "decode offset out of bounds" {
    const allocator = testing.allocator;

    // 64-byte buffer where word 0 has offset pointing to position 200
    var data: [64]u8 = [_]u8{0} ** 64;
    data[31] = 200; // offset = 200 (way past end of 64-byte buffer)

    const types = [_]AbiType{.bytes};
    const result = decodeValues(&data, &types, allocator);
    try testing.expectError(error.OffsetOutOfBounds, result);
}

test "decode length out of bounds" {
    const allocator = testing.allocator;

    // 96-byte buffer: word 0 = offset 0x20, word 1 = length 9999
    var data: [96]u8 = [_]u8{0} ** 96;
    data[31] = 0x20; // offset = 32
    data[62] = 0x27; // 9999 = 0x270F
    data[63] = 0x0F;

    const types = [_]AbiType{.bytes};
    const result = decodeValues(&data, &types, allocator);
    try testing.expectError(error.LengthOutOfBounds, result);
}

test "decode bytes exact 32-byte alignment" {
    const allocator = testing.allocator;

    // 64 bytes of data = exactly 2 words, no padding needed
    // Word 0: offset = 0x20, Word 1: length = 64, Words 2-3: 64 bytes of 0xBB
    // Total: 32 + 32 + 64 = 128 bytes
    var data: [128]u8 = [_]u8{0} ** 128;
    data[31] = 0x20; // offset = 32
    data[63] = 0x40; // length = 64
    for (64..128) |i| {
        data[i] = 0xBB;
    }

    const types = [_]AbiType{.bytes};
    const values = try decodeValues(&data, &types, allocator);
    defer freeValues(values, allocator);

    try testing.expectEqual(@as(usize, 64), values[0].bytes.len);
    for (values[0].bytes) |b| {
        try testing.expectEqual(@as(u8, 0xBB), b);
    }
}

test "encode-decode ERC20 transfer return bool true" {
    const allocator = testing.allocator;
    const encode_mod = @import("abi_encode.zig");

    // Encode bool(true), decode, verify
    const original_true = [_]AbiValue{
        .{ .boolean = true },
    };

    const encoded_true = try encode_mod.encodeValues(allocator, &original_true);
    defer allocator.free(encoded_true);

    const types = [_]AbiType{.bool};
    const decoded_true = try decodeValues(encoded_true, &types, allocator);
    defer freeValues(decoded_true, allocator);

    try testing.expect(decoded_true[0].boolean);

    // Encode bool(false), decode, verify
    const original_false = [_]AbiValue{
        .{ .boolean = false },
    };

    const encoded_false = try encode_mod.encodeValues(allocator, &original_false);
    defer allocator.free(encoded_false);

    const decoded_false = try decodeValues(encoded_false, &types, allocator);
    defer freeValues(decoded_false, allocator);

    try testing.expect(!decoded_false[0].boolean);
}
