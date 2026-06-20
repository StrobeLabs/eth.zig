const std = @import("std");
const abi_types = @import("abi_types.zig");
const keccak_mod = @import("keccak.zig");

const AbiType = abi_types.AbiType;
const AbiParam = abi_types.AbiParam;
const StateMutability = abi_types.StateMutability;

/// A parsed Solidity JSON ABI (output of solc / forge build).
pub const ContractAbi = struct {
    functions: []const abi_types.Function,
    events: []const abi_types.Event,
    errors: []const abi_types.AbiError,
    /// Owns every allocation backing the parsed ABI. A single arena means there
    /// is no hand-written recursive free, and a failure partway through parsing
    /// cannot leak already-built entries: the `errdefer` in `fromJson` (and
    /// `deinit` on success) frees the whole tree in one shot.
    arena: *std.heap.ArenaAllocator,

    /// Parse a Solidity JSON ABI string into a ContractAbi.
    /// Caller must call deinit() to free all memory.
    pub fn fromJson(gpa: std.mem.Allocator, json: []const u8) !ContractAbi {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        errdefer gpa.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        // Parse "leaky" into the arena: the JSON DOM lives in the same arena as
        // the parsed ABI, so it is reclaimed by deinit() with everything else.
        // Surface allocator exhaustion as itself; only genuine parse failures
        // collapse to InvalidJson.
        const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, json, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
        if (root != .array) return error.InvalidAbiFormat;

        var functions: std.ArrayList(abi_types.Function) = .empty;
        var events: std.ArrayList(abi_types.Event) = .empty;
        var errors: std.ArrayList(abi_types.AbiError) = .empty;

        for (root.array.items) |item| {
            if (item != .object) continue;
            const obj = item.object;

            const type_str = jsonGetString(obj, "type") orelse continue;

            if (std.mem.eql(u8, type_str, "function")) {
                try functions.append(allocator, try parseFunction(allocator, obj));
            } else if (std.mem.eql(u8, type_str, "event")) {
                try events.append(allocator, try parseEvent(allocator, obj));
            } else if (std.mem.eql(u8, type_str, "error")) {
                try errors.append(allocator, try parseError(allocator, obj));
            }
            // Skip constructor, fallback, receive -- not needed for call encoding
        }

        return .{
            .functions = try functions.toOwnedSlice(allocator),
            .events = try events.toOwnedSlice(allocator),
            .errors = try errors.toOwnedSlice(allocator),
            .arena = arena,
        };
    }

    /// Free all memory allocated by fromJson.
    pub fn deinit(self: *ContractAbi) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    /// Find a function by name. Returns null if not found.
    pub fn getFunction(self: *const ContractAbi, func_name: []const u8) ?abi_types.Function {
        for (self.functions) |func| {
            if (std.mem.eql(u8, func.name, func_name)) return func;
        }
        return null;
    }

    /// Find an event by name. Returns null if not found.
    pub fn getEvent(self: *const ContractAbi, event_name: []const u8) ?abi_types.Event {
        for (self.events) |evt| {
            if (std.mem.eql(u8, evt.name, event_name)) return evt;
        }
        return null;
    }

    /// Find an error by name. Returns null if not found.
    pub fn getError(self: *const ContractAbi, error_name: []const u8) ?abi_types.AbiError {
        for (self.errors) |err| {
            if (std.mem.eql(u8, err.name, error_name)) return err;
        }
        return null;
    }
};

// All parse helpers below allocate into the caller's arena. There is no
// per-helper cleanup on error: a failure unwinds to ContractAbi.fromJson, whose
// errdefer tears down the whole arena, so partially-built entries cannot leak.

fn parseFunction(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !abi_types.Function {
    const name_str = jsonGetString(obj, "name") orelse return error.MissingName;
    return .{
        .name = try allocator.dupe(u8, name_str),
        .inputs = try parseInputs(allocator, obj, "inputs"),
        .outputs = try parseInputs(allocator, obj, "outputs"),
        .state_mutability = parseMutability(obj),
    };
}

fn parseEvent(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !abi_types.Event {
    const name_str = jsonGetString(obj, "name") orelse return error.MissingName;
    return .{
        .name = try allocator.dupe(u8, name_str),
        .inputs = try parseInputs(allocator, obj, "inputs"),
        .anonymous = jsonGetBool(obj, "anonymous") orelse false,
    };
}

fn parseError(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !abi_types.AbiError {
    const name_str = jsonGetString(obj, "name") orelse return error.MissingName;
    return .{
        .name = try allocator.dupe(u8, name_str),
        .inputs = try parseInputs(allocator, obj, "inputs"),
    };
}

/// Explicit error set shared by the mutually-recursive `parseInputs` and
/// `parseParam` (tuple components recurse). An inferred error set here forms a
/// dependency loop that fails to compile under Zig 0.16.
const ComponentError = std.mem.Allocator.Error || error{ MissingType, UnknownType };

fn parseInputs(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ComponentError![]const AbiParam {
    const val = obj.get(key) orelse return &.{};
    if (val != .array) return &.{};

    var params: std.ArrayList(AbiParam) = .empty;
    for (val.array.items) |item| {
        if (item != .object) continue;
        try params.append(allocator, try parseParam(allocator, item.object));
    }

    return params.toOwnedSlice(allocator);
}

fn parseParam(allocator: std.mem.Allocator, obj: std.json.ObjectMap) ComponentError!AbiParam {
    const type_str = jsonGetString(obj, "type") orelse return error.MissingType;
    const name_str = jsonGetString(obj, "name") orelse "";
    const indexed = jsonGetBool(obj, "indexed") orelse false;

    const abi_type = parseType(type_str) orelse return error.UnknownType;
    const name = if (name_str.len > 0) try allocator.dupe(u8, name_str) else name_str;

    var components: []const AbiParam = &.{};
    if (abi_type == .tuple) {
        components = try parseInputs(allocator, obj, "components");
    }

    return .{
        .name = name,
        .abi_type = abi_type,
        .components = components,
        .indexed = indexed,
    };
}

fn parseMutability(obj: std.json.ObjectMap) StateMutability {
    const val = jsonGetString(obj, "stateMutability") orelse return .nonpayable;
    if (std.mem.eql(u8, val, "pure")) return .pure;
    if (std.mem.eql(u8, val, "view")) return .view;
    if (std.mem.eql(u8, val, "payable")) return .payable;
    return .nonpayable;
}

/// Parse a Solidity type string into an AbiType.
pub fn parseType(type_str: []const u8) ?AbiType {
    // Handle array suffixes
    if (std.mem.endsWith(u8, type_str, "[]")) return .dynamic_array;

    // Check for fixed array (e.g., "uint256[3]")
    if (type_str.len > 0 and type_str[type_str.len - 1] == ']') return .fixed_array;

    // Exact matches for common types
    if (std.mem.eql(u8, type_str, "address")) return .address;
    if (std.mem.eql(u8, type_str, "bool")) return .bool;
    if (std.mem.eql(u8, type_str, "string")) return .string;
    if (std.mem.eql(u8, type_str, "bytes")) return .bytes;
    if (std.mem.eql(u8, type_str, "tuple")) return .tuple;

    // uint types
    if (std.mem.startsWith(u8, type_str, "uint")) {
        return parseUintType(type_str) orelse .uint256;
    }

    // int types
    if (std.mem.startsWith(u8, type_str, "int")) {
        return parseIntType(type_str) orelse .int256;
    }

    // bytesN types
    if (std.mem.startsWith(u8, type_str, "bytes")) {
        return parseBytesType(type_str) orelse .bytes;
    }

    return null; // unknown type
}

fn parseUintType(type_str: []const u8) ?AbiType {
    const bits_str = type_str[4..];
    if (bits_str.len == 0) return .uint256;
    const bits = std.fmt.parseInt(u16, bits_str, 10) catch return null;
    return switch (bits) {
        8 => .uint8,
        16 => .uint16,
        24 => .uint24,
        32 => .uint32,
        40 => .uint40,
        48 => .uint48,
        56 => .uint56,
        64 => .uint64,
        72 => .uint72,
        80 => .uint80,
        88 => .uint88,
        96 => .uint96,
        104 => .uint104,
        112 => .uint112,
        120 => .uint120,
        128 => .uint128,
        136 => .uint136,
        144 => .uint144,
        152 => .uint152,
        160 => .uint160,
        168 => .uint168,
        176 => .uint176,
        184 => .uint184,
        192 => .uint192,
        200 => .uint200,
        208 => .uint208,
        216 => .uint216,
        224 => .uint224,
        232 => .uint232,
        240 => .uint240,
        248 => .uint248,
        256 => .uint256,
        else => null,
    };
}

fn parseIntType(type_str: []const u8) ?AbiType {
    const bits_str = type_str[3..];
    if (bits_str.len == 0) return .int256;
    const bits = std.fmt.parseInt(u16, bits_str, 10) catch return null;
    return switch (bits) {
        8 => .int8,
        16 => .int16,
        24 => .int24,
        32 => .int32,
        40 => .int40,
        48 => .int48,
        56 => .int56,
        64 => .int64,
        72 => .int72,
        80 => .int80,
        88 => .int88,
        96 => .int96,
        104 => .int104,
        112 => .int112,
        120 => .int120,
        128 => .int128,
        136 => .int136,
        144 => .int144,
        152 => .int152,
        160 => .int160,
        168 => .int168,
        176 => .int176,
        184 => .int184,
        192 => .int192,
        200 => .int200,
        208 => .int208,
        216 => .int216,
        224 => .int224,
        232 => .int232,
        240 => .int240,
        248 => .int248,
        256 => .int256,
        else => null,
    };
}

fn parseBytesType(type_str: []const u8) ?AbiType {
    const size_str = type_str[5..];
    if (size_str.len == 0) return .bytes;
    const size = std.fmt.parseInt(u8, size_str, 10) catch return null;
    return switch (size) {
        1 => .bytes1,
        2 => .bytes2,
        3 => .bytes3,
        4 => .bytes4,
        5 => .bytes5,
        6 => .bytes6,
        7 => .bytes7,
        8 => .bytes8,
        9 => .bytes9,
        10 => .bytes10,
        11 => .bytes11,
        12 => .bytes12,
        13 => .bytes13,
        14 => .bytes14,
        15 => .bytes15,
        16 => .bytes16,
        17 => .bytes17,
        18 => .bytes18,
        19 => .bytes19,
        20 => .bytes20,
        21 => .bytes21,
        22 => .bytes22,
        23 => .bytes23,
        24 => .bytes24,
        25 => .bytes25,
        26 => .bytes26,
        27 => .bytes27,
        28 => .bytes28,
        29 => .bytes29,
        30 => .bytes30,
        31 => .bytes31,
        32 => .bytes32,
        else => null,
    };
}

fn jsonGetString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn jsonGetBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .bool => |b| b,
        else => null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseType - basic types" {
    try std.testing.expectEqual(AbiType.address, parseType("address"));
    try std.testing.expectEqual(AbiType.bool, parseType("bool"));
    try std.testing.expectEqual(AbiType.string, parseType("string"));
    try std.testing.expectEqual(AbiType.bytes, parseType("bytes"));
    try std.testing.expectEqual(AbiType.tuple, parseType("tuple"));
    try std.testing.expectEqual(AbiType.uint256, parseType("uint256"));
    try std.testing.expectEqual(AbiType.uint8, parseType("uint8"));
    try std.testing.expectEqual(AbiType.int256, parseType("int256"));
    try std.testing.expectEqual(AbiType.int128, parseType("int128"));
    try std.testing.expectEqual(AbiType.bytes32, parseType("bytes32"));
    try std.testing.expectEqual(AbiType.bytes4, parseType("bytes4"));
    try std.testing.expectEqual(AbiType.dynamic_array, parseType("uint256[]"));
    try std.testing.expectEqual(AbiType.fixed_array, parseType("uint256[3]"));
}

test "parseType - uint without bits defaults to uint256" {
    try std.testing.expectEqual(AbiType.uint256, parseType("uint"));
}

test "parseType - int without bits defaults to int256" {
    try std.testing.expectEqual(AbiType.int256, parseType("int"));
}

test "parseType - unknown type returns null" {
    try std.testing.expectEqual(@as(?AbiType, null), parseType("foobar"));
    try std.testing.expectEqual(@as(?AbiType, null), parseType("custom_type"));
}

test "ContractAbi.fromJson - ERC20 ABI" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {
        \\    "type": "function",
        \\    "name": "transfer",
        \\    "inputs": [
        \\      {"name": "to", "type": "address"},
        \\      {"name": "amount", "type": "uint256"}
        \\    ],
        \\    "outputs": [
        \\      {"name": "", "type": "bool"}
        \\    ],
        \\    "stateMutability": "nonpayable"
        \\  },
        \\  {
        \\    "type": "function",
        \\    "name": "balanceOf",
        \\    "inputs": [
        \\      {"name": "account", "type": "address"}
        \\    ],
        \\    "outputs": [
        \\      {"name": "", "type": "uint256"}
        \\    ],
        \\    "stateMutability": "view"
        \\  },
        \\  {
        \\    "type": "event",
        \\    "name": "Transfer",
        \\    "inputs": [
        \\      {"name": "from", "type": "address", "indexed": true},
        \\      {"name": "to", "type": "address", "indexed": true},
        \\      {"name": "value", "type": "uint256", "indexed": false}
        \\    ]
        \\  },
        \\  {
        \\    "type": "error",
        \\    "name": "InsufficientBalance",
        \\    "inputs": [
        \\      {"name": "available", "type": "uint256"},
        \\      {"name": "required", "type": "uint256"}
        \\    ]
        \\  }
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    // Functions
    try std.testing.expectEqual(@as(usize, 2), abi.functions.len);
    try std.testing.expectEqualStrings("transfer", abi.functions[0].name);
    try std.testing.expectEqual(@as(usize, 2), abi.functions[0].inputs.len);
    try std.testing.expectEqual(AbiType.address, abi.functions[0].inputs[0].abi_type);
    try std.testing.expectEqualStrings("to", abi.functions[0].inputs[0].name);
    try std.testing.expectEqual(AbiType.uint256, abi.functions[0].inputs[1].abi_type);
    try std.testing.expectEqual(@as(usize, 1), abi.functions[0].outputs.len);
    try std.testing.expectEqual(AbiType.bool, abi.functions[0].outputs[0].abi_type);
    try std.testing.expectEqual(StateMutability.nonpayable, abi.functions[0].state_mutability);

    try std.testing.expectEqualStrings("balanceOf", abi.functions[1].name);
    try std.testing.expectEqual(StateMutability.view, abi.functions[1].state_mutability);

    // Events
    try std.testing.expectEqual(@as(usize, 1), abi.events.len);
    try std.testing.expectEqualStrings("Transfer", abi.events[0].name);
    try std.testing.expectEqual(@as(usize, 3), abi.events[0].inputs.len);
    try std.testing.expect(abi.events[0].inputs[0].indexed);
    try std.testing.expect(abi.events[0].inputs[1].indexed);
    try std.testing.expect(!abi.events[0].inputs[2].indexed);

    // Errors
    try std.testing.expectEqual(@as(usize, 1), abi.errors.len);
    try std.testing.expectEqualStrings("InsufficientBalance", abi.errors[0].name);
}

test "ContractAbi.getFunction" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "function", "name": "transfer", "inputs": [], "outputs": []},
        \\  {"type": "function", "name": "approve", "inputs": [], "outputs": []}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    const transfer = abi.getFunction("transfer");
    try std.testing.expect(transfer != null);
    try std.testing.expectEqualStrings("transfer", transfer.?.name);

    const nonexistent = abi.getFunction("nonexistent");
    try std.testing.expect(nonexistent == null);
}

test "ContractAbi.getEvent" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "event", "name": "Transfer", "inputs": []},
        \\  {"type": "event", "name": "Approval", "inputs": []}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    const transfer = abi.getEvent("Transfer");
    try std.testing.expect(transfer != null);

    const nonexistent = abi.getEvent("nonexistent");
    try std.testing.expect(nonexistent == null);
}

test "ContractAbi.getError" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "error", "name": "InsufficientBalance", "inputs": []}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    const err = abi.getError("InsufficientBalance");
    try std.testing.expect(err != null);

    const nonexistent = abi.getError("nonexistent");
    try std.testing.expect(nonexistent == null);
}

test "ContractAbi.fromJson - empty ABI" {
    const allocator = std.testing.allocator;
    var abi = try ContractAbi.fromJson(allocator, "[]");
    defer abi.deinit();

    try std.testing.expectEqual(@as(usize, 0), abi.functions.len);
    try std.testing.expectEqual(@as(usize, 0), abi.events.len);
    try std.testing.expectEqual(@as(usize, 0), abi.errors.len);
}

test "ContractAbi.fromJson - skips constructor and fallback" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "constructor", "inputs": []},
        \\  {"type": "fallback"},
        \\  {"type": "receive", "stateMutability": "payable"},
        \\  {"type": "function", "name": "foo", "inputs": [], "outputs": []}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    try std.testing.expectEqual(@as(usize, 1), abi.functions.len);
    try std.testing.expectEqualStrings("foo", abi.functions[0].name);
}

test "ContractAbi.fromJson - tuple components" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {
        \\    "type": "function",
        \\    "name": "multicall",
        \\    "inputs": [
        \\      {
        \\        "name": "calls",
        \\        "type": "tuple",
        \\        "components": [
        \\          {"name": "target", "type": "address"},
        \\          {"name": "callData", "type": "bytes"}
        \\        ]
        \\      }
        \\    ],
        \\    "outputs": [],
        \\    "stateMutability": "nonpayable"
        \\  }
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    try std.testing.expectEqual(@as(usize, 1), abi.functions.len);
    try std.testing.expectEqual(AbiType.tuple, abi.functions[0].inputs[0].abi_type);
    try std.testing.expectEqual(@as(usize, 2), abi.functions[0].inputs[0].components.len);
    try std.testing.expectEqualStrings("target", abi.functions[0].inputs[0].components[0].name);
    try std.testing.expectEqual(AbiType.address, abi.functions[0].inputs[0].components[0].abi_type);
    try std.testing.expectEqualStrings("callData", abi.functions[0].inputs[0].components[1].name);
    try std.testing.expectEqual(AbiType.bytes, abi.functions[0].inputs[0].components[1].abi_type);
}

test "ContractAbi.fromJson - state mutability variants" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "function", "name": "pure_fn", "inputs": [], "outputs": [], "stateMutability": "pure"},
        \\  {"type": "function", "name": "view_fn", "inputs": [], "outputs": [], "stateMutability": "view"},
        \\  {"type": "function", "name": "payable_fn", "inputs": [], "outputs": [], "stateMutability": "payable"},
        \\  {"type": "function", "name": "nonpayable_fn", "inputs": [], "outputs": [], "stateMutability": "nonpayable"}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    try std.testing.expectEqual(StateMutability.pure, abi.functions[0].state_mutability);
    try std.testing.expectEqual(StateMutability.view, abi.functions[1].state_mutability);
    try std.testing.expectEqual(StateMutability.payable, abi.functions[2].state_mutability);
    try std.testing.expectEqual(StateMutability.nonpayable, abi.functions[3].state_mutability);
}

test "ContractAbi.fromJson - anonymous event" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type": "event", "name": "AnonymousEvent", "inputs": [], "anonymous": true}
        \\]
    ;

    var abi = try ContractAbi.fromJson(allocator, json);
    defer abi.deinit();

    try std.testing.expect(abi.events[0].anonymous);
}

test "ContractAbi.fromJson - invalid JSON returns error" {
    const allocator = std.testing.allocator;
    const result = ContractAbi.fromJson(allocator, "not json");
    try std.testing.expectError(error.InvalidJson, result);
}

test "ContractAbi.fromJson - non-array returns error" {
    const allocator = std.testing.allocator;
    const result = ContractAbi.fromJson(allocator, "{}");
    try std.testing.expectError(error.InvalidAbiFormat, result);
}

test "ContractAbi.fromJson - no leak when a later entry fails to parse" {
    // The first function parses and is appended; the second fails on an unknown
    // input type. With per-allocation cleanup this leaked the already-built
    // first entry's name/params -- std.testing.allocator turns that into a test
    // failure. The arena makes the error path leak-free.
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type":"function","name":"good","inputs":[{"name":"a","type":"uint256"}],"outputs":[]},
        \\  {"type":"function","name":"bad","inputs":[{"name":"x","type":"not_a_real_type"}],"outputs":[]}
        \\]
    ;
    try std.testing.expectError(error.UnknownType, ContractAbi.fromJson(allocator, json));
}
