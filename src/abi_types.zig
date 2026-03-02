const std = @import("std");
const keccak = @import("keccak.zig");

/// All Solidity ABI types.
pub const AbiType = enum {
    // Unsigned integers
    uint8,
    uint16,
    uint24,
    uint32,
    uint40,
    uint48,
    uint56,
    uint64,
    uint72,
    uint80,
    uint88,
    uint96,
    uint104,
    uint112,
    uint120,
    uint128,
    uint136,
    uint144,
    uint152,
    uint160,
    uint168,
    uint176,
    uint184,
    uint192,
    uint200,
    uint208,
    uint216,
    uint224,
    uint232,
    uint240,
    uint248,
    uint256,

    // Signed integers
    int8,
    int16,
    int24,
    int32,
    int40,
    int48,
    int56,
    int64,
    int72,
    int80,
    int88,
    int96,
    int104,
    int112,
    int120,
    int128,
    int136,
    int144,
    int152,
    int160,
    int168,
    int176,
    int184,
    int192,
    int200,
    int208,
    int216,
    int224,
    int232,
    int240,
    int248,
    int256,

    // Address
    address,

    // Bool
    bool,

    // Fixed-size byte arrays
    bytes1,
    bytes2,
    bytes3,
    bytes4,
    bytes5,
    bytes6,
    bytes7,
    bytes8,
    bytes9,
    bytes10,
    bytes11,
    bytes12,
    bytes13,
    bytes14,
    bytes15,
    bytes16,
    bytes17,
    bytes18,
    bytes19,
    bytes20,
    bytes21,
    bytes22,
    bytes23,
    bytes24,
    bytes25,
    bytes26,
    bytes27,
    bytes28,
    bytes29,
    bytes30,
    bytes31,
    bytes32,

    // Dynamic types
    bytes,
    string,

    // Composite types
    tuple,
    fixed_array,
    dynamic_array,

    /// Returns true if this type is dynamically sized in ABI encoding.
    pub fn isDynamic(self: AbiType) bool {
        return switch (self) {
            .bytes, .string, .dynamic_array, .tuple => true,
            else => false,
        };
    }

    /// Returns the number of bytes for a fixed bytesN type (1-32), or null if not a bytesN type.
    pub fn fixedBytesSize(self: AbiType) ?usize {
        return switch (self) {
            .bytes1 => 1,
            .bytes2 => 2,
            .bytes3 => 3,
            .bytes4 => 4,
            .bytes5 => 5,
            .bytes6 => 6,
            .bytes7 => 7,
            .bytes8 => 8,
            .bytes9 => 9,
            .bytes10 => 10,
            .bytes11 => 11,
            .bytes12 => 12,
            .bytes13 => 13,
            .bytes14 => 14,
            .bytes15 => 15,
            .bytes16 => 16,
            .bytes17 => 17,
            .bytes18 => 18,
            .bytes19 => 19,
            .bytes20 => 20,
            .bytes21 => 21,
            .bytes22 => 22,
            .bytes23 => 23,
            .bytes24 => 24,
            .bytes25 => 25,
            .bytes26 => 26,
            .bytes27 => 27,
            .bytes28 => 28,
            .bytes29 => 29,
            .bytes30 => 30,
            .bytes31 => 31,
            .bytes32 => 32,
            else => null,
        };
    }

    /// Returns the bit width for uint types, or null if not a uint type.
    pub fn uintBits(self: AbiType) ?u16 {
        return switch (self) {
            .uint8 => 8,
            .uint16 => 16,
            .uint24 => 24,
            .uint32 => 32,
            .uint40 => 40,
            .uint48 => 48,
            .uint56 => 56,
            .uint64 => 64,
            .uint72 => 72,
            .uint80 => 80,
            .uint88 => 88,
            .uint96 => 96,
            .uint104 => 104,
            .uint112 => 112,
            .uint120 => 120,
            .uint128 => 128,
            .uint136 => 136,
            .uint144 => 144,
            .uint152 => 152,
            .uint160 => 160,
            .uint168 => 168,
            .uint176 => 176,
            .uint184 => 184,
            .uint192 => 192,
            .uint200 => 200,
            .uint208 => 208,
            .uint216 => 216,
            .uint224 => 224,
            .uint232 => 232,
            .uint240 => 240,
            .uint248 => 248,
            .uint256 => 256,
            else => null,
        };
    }

    /// Returns the bit width for int types, or null if not an int type.
    pub fn intBits(self: AbiType) ?u16 {
        return switch (self) {
            .int8 => 8,
            .int16 => 16,
            .int24 => 24,
            .int32 => 32,
            .int40 => 40,
            .int48 => 48,
            .int56 => 56,
            .int64 => 64,
            .int72 => 72,
            .int80 => 80,
            .int88 => 88,
            .int96 => 96,
            .int104 => 104,
            .int112 => 112,
            .int120 => 120,
            .int128 => 128,
            .int136 => 136,
            .int144 => 144,
            .int152 => 152,
            .int160 => 160,
            .int168 => 168,
            .int176 => 176,
            .int184 => 184,
            .int192 => 192,
            .int200 => 200,
            .int208 => 208,
            .int216 => 216,
            .int224 => 224,
            .int232 => 232,
            .int240 => 240,
            .int248 => 248,
            .int256 => 256,
            else => null,
        };
    }

    /// Returns true if this is any unsigned integer type.
    pub fn isUint(self: AbiType) bool {
        return self.uintBits() != null;
    }

    /// Returns true if this is any signed integer type.
    pub fn isInt(self: AbiType) bool {
        return self.intBits() != null;
    }

    /// Returns true if this is a fixed-size bytesN type.
    pub fn isFixedBytes(self: AbiType) bool {
        return self.fixedBytesSize() != null;
    }
};

/// Describes a single parameter in a function/event/error signature.
pub const AbiParam = struct {
    /// Parameter name (may be empty).
    name: []const u8 = "",
    /// The ABI type of this parameter.
    abi_type: AbiType,
    /// For tuple types, the component parameters.
    components: []const AbiParam = &.{},
    /// For event parameters, whether this parameter is indexed.
    indexed: bool = false,
};

/// State mutability of a function.
pub const StateMutability = enum {
    pure,
    view,
    nonpayable,
    payable,
};

/// Describes an ABI function.
pub const Function = struct {
    /// Function name.
    name: []const u8,
    /// Input parameters.
    inputs: []const AbiParam = &.{},
    /// Output parameters.
    outputs: []const AbiParam = &.{},
    /// State mutability.
    state_mutability: StateMutability = .nonpayable,
};

/// Describes an ABI event.
pub const Event = struct {
    /// Event name.
    name: []const u8,
    /// Input parameters (may be indexed).
    inputs: []const AbiParam = &.{},
    /// Whether this event is anonymous.
    anonymous: bool = false,
};

/// Describes an ABI error.
pub const AbiError = struct {
    /// Error name.
    name: []const u8,
    /// Input parameters.
    inputs: []const AbiParam = &.{},
};

/// Compute the 4-byte function selector from a canonical signature string.
/// e.g., "transfer(address,uint256)" -> [4]u8{ 0xa9, 0x05, 0x9c, 0xbb }
pub fn selectorFromSignature(signature: []const u8) [4]u8 {
    return keccak.selector(signature);
}

/// Compute the 32-byte event topic from a canonical signature string.
/// e.g., "Transfer(address,address,uint256)" -> keccak256 hash
pub fn topicFromSignature(signature: []const u8) [32]u8 {
    return keccak.hash(signature);
}

// ============================================================================
// Tests
// ============================================================================

test "AbiType.isDynamic" {
    try std.testing.expect(!AbiType.uint256.isDynamic());
    try std.testing.expect(!AbiType.address.isDynamic());
    try std.testing.expect(!AbiType.bool.isDynamic());
    try std.testing.expect(!AbiType.bytes32.isDynamic());
    try std.testing.expect(AbiType.bytes.isDynamic());
    try std.testing.expect(AbiType.string.isDynamic());
    try std.testing.expect(AbiType.dynamic_array.isDynamic());
    try std.testing.expect(AbiType.tuple.isDynamic());
}

test "AbiType.fixedBytesSize" {
    try std.testing.expectEqual(@as(?usize, 1), AbiType.bytes1.fixedBytesSize());
    try std.testing.expectEqual(@as(?usize, 20), AbiType.bytes20.fixedBytesSize());
    try std.testing.expectEqual(@as(?usize, 32), AbiType.bytes32.fixedBytesSize());
    try std.testing.expectEqual(@as(?usize, null), AbiType.uint256.fixedBytesSize());
    try std.testing.expectEqual(@as(?usize, null), AbiType.bytes.fixedBytesSize());
}

test "AbiType.uintBits" {
    try std.testing.expectEqual(@as(?u16, 8), AbiType.uint8.uintBits());
    try std.testing.expectEqual(@as(?u16, 256), AbiType.uint256.uintBits());
    try std.testing.expectEqual(@as(?u16, null), AbiType.int256.uintBits());
    try std.testing.expectEqual(@as(?u16, null), AbiType.address.uintBits());
}

test "AbiType.intBits" {
    try std.testing.expectEqual(@as(?u16, 8), AbiType.int8.intBits());
    try std.testing.expectEqual(@as(?u16, 256), AbiType.int256.intBits());
    try std.testing.expectEqual(@as(?u16, null), AbiType.uint256.intBits());
}

test "AbiType.isUint and isInt" {
    try std.testing.expect(AbiType.uint8.isUint());
    try std.testing.expect(AbiType.uint256.isUint());
    try std.testing.expect(!AbiType.int256.isUint());
    try std.testing.expect(!AbiType.address.isUint());

    try std.testing.expect(AbiType.int8.isInt());
    try std.testing.expect(AbiType.int256.isInt());
    try std.testing.expect(!AbiType.uint256.isInt());
}

test "AbiType.isFixedBytes" {
    try std.testing.expect(AbiType.bytes1.isFixedBytes());
    try std.testing.expect(AbiType.bytes32.isFixedBytes());
    try std.testing.expect(!AbiType.bytes.isFixedBytes());
    try std.testing.expect(!AbiType.uint256.isFixedBytes());
}

test "selectorFromSignature - transfer" {
    const sel = selectorFromSignature("transfer(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &sel);
}

test "selectorFromSignature - balanceOf" {
    const sel = selectorFromSignature("balanceOf(address)");
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &sel);
}

test "selectorFromSignature - approve" {
    const sel = selectorFromSignature("approve(address,uint256)");
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x5e, 0xa7, 0xb3 }, &sel);
}

test "topicFromSignature - Transfer event" {
    const topic = topicFromSignature("Transfer(address,address,uint256)");
    // keccak256("Transfer(address,address,uint256)") is the well-known ERC20 Transfer topic
    const hex_mod = @import("hex.zig");
    const expected = try hex_mod.hexToBytesFixed(32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    try std.testing.expectEqualSlices(u8, &expected, &topic);
}

test "AbiParam defaults" {
    const param = AbiParam{ .abi_type = .uint256 };
    try std.testing.expectEqualStrings("", param.name);
    try std.testing.expectEqual(AbiType.uint256, param.abi_type);
    try std.testing.expectEqual(@as(usize, 0), param.components.len);
    try std.testing.expect(!param.indexed);
}

test "Function struct" {
    const func = Function{
        .name = "transfer",
        .inputs = &.{
            AbiParam{ .name = "to", .abi_type = .address },
            AbiParam{ .name = "amount", .abi_type = .uint256 },
        },
        .outputs = &.{
            AbiParam{ .name = "", .abi_type = .bool },
        },
        .state_mutability = .nonpayable,
    };
    try std.testing.expectEqualStrings("transfer", func.name);
    try std.testing.expectEqual(@as(usize, 2), func.inputs.len);
    try std.testing.expectEqual(@as(usize, 1), func.outputs.len);
    try std.testing.expectEqual(StateMutability.nonpayable, func.state_mutability);
}

test "Event struct" {
    const event = Event{
        .name = "Transfer",
        .inputs = &.{
            AbiParam{ .name = "from", .abi_type = .address, .indexed = true },
            AbiParam{ .name = "to", .abi_type = .address, .indexed = true },
            AbiParam{ .name = "value", .abi_type = .uint256 },
        },
    };
    try std.testing.expectEqualStrings("Transfer", event.name);
    try std.testing.expectEqual(@as(usize, 3), event.inputs.len);
    try std.testing.expect(event.inputs[0].indexed);
    try std.testing.expect(event.inputs[1].indexed);
    try std.testing.expect(!event.inputs[2].indexed);
    try std.testing.expect(!event.anonymous);
}

test "AbiError struct" {
    const err = AbiError{
        .name = "InsufficientBalance",
        .inputs = &.{
            AbiParam{ .name = "available", .abi_type = .uint256 },
            AbiParam{ .name = "required", .abi_type = .uint256 },
        },
    };
    try std.testing.expectEqualStrings("InsufficientBalance", err.name);
    try std.testing.expectEqual(@as(usize, 2), err.inputs.len);
}
