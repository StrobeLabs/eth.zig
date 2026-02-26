const std = @import("std");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const uint256_mod = @import("uint256.zig");

// ============================================================================
// Types
// ============================================================================

/// A field definition within a struct type (name + Solidity type string).
pub const FieldDef = struct {
    name: []const u8,
    type_str: []const u8,
};

/// A named struct type with its fields.
pub const TypeDef = struct {
    name: []const u8,
    fields: []const FieldDef,
};

/// A runtime-typed value that mirrors Solidity's EIP-712 encoding rules.
pub const TypedValue = union(enum) {
    uint256: u256,
    int256: i256,
    address: [20]u8,
    bool_val: bool,
    bytes32: [32]u8,
    bytes_val: []const u8,
    string_val: []const u8,
    array_val: []const TypedValue,
    struct_val: StructValue,
};

/// A struct instance: a type name plus an ordered list of field values.
pub const StructValue = struct {
    type_name: []const u8,
    fields: []const FieldValue,
};

/// A single field within a struct instance.
pub const FieldValue = struct {
    name: []const u8,
    type_str: []const u8,
    value: TypedValue,
};

/// EIP-712 domain separator fields. All fields are optional.
pub const DomainSeparator = struct {
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    chain_id: ?u256 = null,
    verifying_contract: ?[20]u8 = null,
    salt: ?[32]u8 = null,
};

// ============================================================================
// Public API
// ============================================================================

/// Produce the EIP-712 type encoding string for a struct type.
///
/// For example: `"Mail(address from,address to,string contents)"`
///
/// If the struct references other struct types, they are appended in sorted
/// (alphabetical) order. Caller owns the returned memory.
pub fn encodeType(
    allocator: std.mem.Allocator,
    type_name: []const u8,
    fields: []const FieldDef,
    referenced_types: []const TypeDef,
) std.mem.Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Primary type
    try appendTypeString(allocator, &buf, type_name, fields);

    // Referenced types sorted alphabetically by name
    if (referenced_types.len > 0) {
        // Sort the referenced types by name. We need a mutable copy of the slice
        // of indices so we can sort without mutating the input.
        const indices = try allocator.alloc(usize, referenced_types.len);
        defer allocator.free(indices);
        for (indices, 0..) |*idx, i| {
            idx.* = i;
        }

        const Context = struct {
            types: []const TypeDef,
        };
        const ctx = Context{ .types = referenced_types };

        std.mem.sortUnstable(usize, indices, ctx, struct {
            fn lessThan(c: Context, a: usize, b: usize) bool {
                return std.mem.order(u8, c.types[a].name, c.types[b].name) == .lt;
            }
        }.lessThan);

        for (indices) |idx| {
            try appendTypeString(allocator, &buf, referenced_types[idx].name, referenced_types[idx].fields);
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Compute the type hash: `keccak256(encodeType(...))`.
pub fn hashType(
    allocator: std.mem.Allocator,
    type_name: []const u8,
    fields: []const FieldDef,
    referenced_types: []const TypeDef,
) std.mem.Allocator.Error![32]u8 {
    const encoded = try encodeType(allocator, type_name, fields, referenced_types);
    defer allocator.free(encoded);
    return keccak.hash(encoded);
}

/// ABI-encode a single typed value to 32 bytes, following EIP-712 rules.
///
/// - Atomic types (address, bool, uint256, int256, bytes32): left-padded to 32 bytes.
/// - `bytes` and `string`: `keccak256(value)`.
/// - Arrays: `keccak256(concat(encodeData(item) for each item))`.
/// - Structs: `hashStruct(value)` (recursive).
///
/// Caller owns the returned 32-byte slice.
pub fn encodeData(
    allocator: std.mem.Allocator,
    value: TypedValue,
    type_str: []const u8,
    type_defs: []const TypeDef,
) std.mem.Allocator.Error![32]u8 {
    switch (value) {
        .uint256 => |v| {
            return uint256_mod.toBigEndianBytes(v);
        },
        .int256 => |v| {
            // Two's complement big-endian encoding
            const as_u256: u256 = @bitCast(v);
            return uint256_mod.toBigEndianBytes(as_u256);
        },
        .address => |v| {
            var result: [32]u8 = [_]u8{0} ** 32;
            @memcpy(result[12..32], &v);
            return result;
        },
        .bool_val => |v| {
            var result: [32]u8 = [_]u8{0} ** 32;
            if (v) result[31] = 1;
            return result;
        },
        .bytes32 => |v| {
            // Right-padded (bytesN are right-padded in ABI, but for bytes32
            // the value is already exactly 32 bytes).
            return v;
        },
        .bytes_val => |v| {
            return keccak.hash(v);
        },
        .string_val => |v| {
            return keccak.hash(v);
        },
        .array_val => |items| {
            // keccak256(concat(encodeData(item) for each item))
            // We need the element type (strip trailing "[]")
            const elem_type = stripArraySuffix(type_str);
            var concat_buf: std.ArrayList(u8) = .empty;
            defer concat_buf.deinit(allocator);

            for (items) |item| {
                const encoded = try encodeData(allocator, item, elem_type, type_defs);
                try concat_buf.appendSlice(allocator, &encoded);
            }

            return keccak.hash(concat_buf.items);
        },
        .struct_val => |sv| {
            return hashStruct(allocator, sv, type_defs);
        },
    }
}

/// Compute `hashStruct(s) = keccak256(typeHash || encodeData(s))`.
pub fn hashStruct(
    allocator: std.mem.Allocator,
    struct_val: StructValue,
    type_defs: []const TypeDef,
) std.mem.Allocator.Error![32]u8 {
    // Find the type definition for this struct
    const td = findTypeDef(type_defs, struct_val.type_name);

    // Collect referenced types (types that this struct depends on, transitively)
    const ref_types = try collectReferencedTypes(allocator, struct_val.type_name, type_defs);
    defer allocator.free(ref_types);

    // Compute typeHash
    const fields = if (td) |t| t.fields else fieldDefsFromFieldValues(struct_val.fields);
    const type_hash = try hashType(allocator, struct_val.type_name, fields, ref_types);

    // Build the data: typeHash || encodeData(field1) || encodeData(field2) || ...
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, &type_hash);

    for (struct_val.fields) |field| {
        const encoded = try encodeData(allocator, field.value, field.type_str, type_defs);
        try buf.appendSlice(allocator, &encoded);
    }

    return keccak.hash(buf.items);
}

/// Compute the EIP-712 domain separator hash.
pub fn hashDomain(
    allocator: std.mem.Allocator,
    domain: DomainSeparator,
) std.mem.Allocator.Error![32]u8 {
    // Build the EIP712Domain type string dynamically based on which fields are present
    var domain_fields: std.ArrayList(FieldDef) = .empty;
    defer domain_fields.deinit(allocator);

    var domain_values: std.ArrayList(FieldValue) = .empty;
    defer domain_values.deinit(allocator);

    if (domain.name) |name| {
        try domain_fields.append(allocator, .{ .name = "name", .type_str = "string" });
        try domain_values.append(allocator, .{
            .name = "name",
            .type_str = "string",
            .value = .{ .string_val = name },
        });
    }
    if (domain.version) |version| {
        try domain_fields.append(allocator, .{ .name = "version", .type_str = "string" });
        try domain_values.append(allocator, .{
            .name = "version",
            .type_str = "string",
            .value = .{ .string_val = version },
        });
    }
    if (domain.chain_id) |chain_id| {
        try domain_fields.append(allocator, .{ .name = "chainId", .type_str = "uint256" });
        try domain_values.append(allocator, .{
            .name = "chainId",
            .type_str = "uint256",
            .value = .{ .uint256 = chain_id },
        });
    }
    if (domain.verifying_contract) |contract| {
        try domain_fields.append(allocator, .{ .name = "verifyingContract", .type_str = "address" });
        try domain_values.append(allocator, .{
            .name = "verifyingContract",
            .type_str = "address",
            .value = .{ .address = contract },
        });
    }
    if (domain.salt) |salt| {
        try domain_fields.append(allocator, .{ .name = "salt", .type_str = "bytes32" });
        try domain_values.append(allocator, .{
            .name = "salt",
            .type_str = "bytes32",
            .value = .{ .bytes32 = salt },
        });
    }

    const sv = StructValue{
        .type_name = "EIP712Domain",
        .fields = domain_values.items,
    };

    // For the domain separator, the type definition is generated from the present fields.
    // We pass a single TypeDef for EIP712Domain itself.
    const domain_type_def = TypeDef{
        .name = "EIP712Domain",
        .fields = domain_fields.items,
    };
    const type_defs: []const TypeDef = &.{domain_type_def};

    return hashStruct(allocator, sv, type_defs);
}

/// Compute the final EIP-712 hash to be signed:
/// `keccak256(0x19 0x01 || domainSeparator || hashStruct(message))`
pub fn hashTypedData(
    allocator: std.mem.Allocator,
    domain: DomainSeparator,
    struct_val: StructValue,
    type_defs: []const TypeDef,
) std.mem.Allocator.Error![32]u8 {
    const domain_hash = try hashDomain(allocator, domain);
    const struct_hash = try hashStruct(allocator, struct_val, type_defs);

    return keccak.hashConcat(&.{
        &[_]u8{ 0x19, 0x01 },
        &domain_hash,
        &struct_hash,
    });
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Append "TypeName(type1 name1,type2 name2,...)" to the buffer.
fn appendTypeString(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), type_name: []const u8, fields: []const FieldDef) std.mem.Allocator.Error!void {
    try buf.appendSlice(allocator, type_name);
    try buf.append(allocator, '(');
    for (fields, 0..) |field, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, field.type_str);
        try buf.append(allocator, ' ');
        try buf.appendSlice(allocator, field.name);
    }
    try buf.append(allocator, ')');
}

/// Strip the trailing "[]" from an array type string. E.g., "Person[]" -> "Person".
fn stripArraySuffix(type_str: []const u8) []const u8 {
    if (type_str.len >= 2 and std.mem.endsWith(u8, type_str, "[]")) {
        return type_str[0 .. type_str.len - 2];
    }
    return type_str;
}

/// Find a TypeDef by name in the provided list.
fn findTypeDef(type_defs: []const TypeDef, name: []const u8) ?TypeDef {
    for (type_defs) |td| {
        if (std.mem.eql(u8, td.name, name)) return td;
    }
    return null;
}

/// Build FieldDefs from FieldValues (for when we don't have an explicit TypeDef).
fn fieldDefsFromFieldValues(fields: []const FieldValue) []const FieldDef {
    // FieldValue has the same layout prefix as FieldDef (name, type_str),
    // but they are different types. We cannot simply reinterpret. Instead,
    // we note that since FieldValue starts with { name, type_str, value },
    // and FieldDef is { name, type_str }, we need to produce a FieldDef slice.
    //
    // Since this function cannot allocate and we need a slice, we use a
    // static buffer approach with a reasonable max. For production use,
    // callers should always provide TypeDefs.
    const max_fields = 32;
    const S = struct {
        var buf: [max_fields]FieldDef = undefined;
    };
    const count = @min(fields.len, max_fields);
    for (0..count) |i| {
        S.buf[i] = .{ .name = fields[i].name, .type_str = fields[i].type_str };
    }
    return S.buf[0..count];
}

/// Check if a type string refers to a struct type (i.e., not a built-in Solidity type).
fn isStructType(type_str: []const u8) bool {
    // Strip array suffix if present
    const base = stripArraySuffix(type_str);

    // Built-in types
    if (std.mem.eql(u8, base, "address")) return false;
    if (std.mem.eql(u8, base, "bool")) return false;
    if (std.mem.eql(u8, base, "string")) return false;
    if (std.mem.eql(u8, base, "bytes")) return false;

    // uintN, intN
    if (std.mem.startsWith(u8, base, "uint")) return false;
    if (std.mem.startsWith(u8, base, "int")) return false;

    // bytesN (bytes1 .. bytes32) -- but not "bytes" (dynamic, already handled)
    if (base.len > 5 and std.mem.startsWith(u8, base, "bytes")) {
        // Check if the rest is a number
        const suffix = base[5..];
        var all_digits = true;
        for (suffix) |c| {
            if (c < '0' or c > '9') {
                all_digits = false;
                break;
            }
        }
        if (all_digits) return false;
    }

    return true;
}

/// Collect all referenced struct types (transitively) for a given primary type,
/// excluding the primary type itself. Returns a sorted (by name) list of TypeDefs.
fn collectReferencedTypes(
    allocator: std.mem.Allocator,
    primary_type_name: []const u8,
    type_defs: []const TypeDef,
) std.mem.Allocator.Error![]const TypeDef {
    // Use a simple string set to track visited type names
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    try visited.put(primary_type_name, {});

    // BFS / iterative expansion
    var queue: std.ArrayList([]const u8) = .empty;
    defer queue.deinit(allocator);

    // Seed the queue with struct types referenced by the primary type
    if (findTypeDef(type_defs, primary_type_name)) |td| {
        for (td.fields) |field| {
            const base = stripArraySuffix(field.type_str);
            if (isStructType(base)) {
                if (!visited.contains(base)) {
                    try visited.put(base, {});
                    try queue.append(allocator, base);
                }
            }
        }
    }

    // Process queue
    var head: usize = 0;
    while (head < queue.items.len) {
        const name = queue.items[head];
        head += 1;

        if (findTypeDef(type_defs, name)) |td| {
            for (td.fields) |field| {
                const base = stripArraySuffix(field.type_str);
                if (isStructType(base)) {
                    if (!visited.contains(base)) {
                        try visited.put(base, {});
                        try queue.append(allocator, base);
                    }
                }
            }
        }
    }

    // Build the result: all queued type names (excluding primary) as TypeDefs
    var result: std.ArrayList(TypeDef) = .empty;
    defer result.deinit(allocator);

    for (queue.items) |name| {
        if (findTypeDef(type_defs, name)) |td| {
            try result.append(allocator, td);
        }
    }

    // The sorting is done by encodeType, so we just return them unsorted here.
    // (encodeType sorts referenced types alphabetically.)
    return result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const hex = @import("hex.zig");

test "encodeType - simple struct no references" {
    const allocator = testing.allocator;

    const fields = [_]FieldDef{
        .{ .name = "from", .type_str = "address" },
        .{ .name = "to", .type_str = "address" },
        .{ .name = "contents", .type_str = "string" },
    };

    const result = try encodeType(allocator, "Mail", &fields, &.{});
    defer allocator.free(result);

    try testing.expectEqualStrings("Mail(address from,address to,string contents)", result);
}

test "encodeType - with referenced types" {
    const allocator = testing.allocator;

    const mail_fields = [_]FieldDef{
        .{ .name = "from", .type_str = "Person" },
        .{ .name = "to", .type_str = "Person" },
        .{ .name = "contents", .type_str = "string" },
    };

    const person_type = TypeDef{
        .name = "Person",
        .fields = &.{
            .{ .name = "name", .type_str = "string" },
            .{ .name = "wallet", .type_str = "address" },
        },
    };

    const result = try encodeType(allocator, "Mail", &mail_fields, &.{person_type});
    defer allocator.free(result);

    try testing.expectEqualStrings(
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)",
        result,
    );
}

test "encodeType - multiple referenced types sorted alphabetically" {
    const allocator = testing.allocator;

    const main_fields = [_]FieldDef{
        .{ .name = "z", .type_str = "Zebra" },
        .{ .name = "a", .type_str = "Apple" },
    };

    const ref_types = [_]TypeDef{
        .{
            .name = "Zebra",
            .fields = &.{.{ .name = "stripes", .type_str = "uint256" }},
        },
        .{
            .name = "Apple",
            .fields = &.{.{ .name = "color", .type_str = "string" }},
        },
    };

    const result = try encodeType(allocator, "Main", &main_fields, &ref_types);
    defer allocator.free(result);

    try testing.expectEqualStrings(
        "Main(Zebra z,Apple a)Apple(string color)Zebra(uint256 stripes)",
        result,
    );
}

test "hashType - Mail type from EIP-712 spec" {
    const allocator = testing.allocator;

    const mail_fields = [_]FieldDef{
        .{ .name = "from", .type_str = "Person" },
        .{ .name = "to", .type_str = "Person" },
        .{ .name = "contents", .type_str = "string" },
    };

    const person_type = TypeDef{
        .name = "Person",
        .fields = &.{
            .{ .name = "name", .type_str = "string" },
            .{ .name = "wallet", .type_str = "address" },
        },
    };

    const type_hash = try hashType(allocator, "Mail", &mail_fields, &.{person_type});
    const type_str = try encodeType(allocator, "Mail", &mail_fields, &.{person_type});
    defer allocator.free(type_str);

    // Verify the type string is correct
    try testing.expectEqualStrings(
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)",
        type_str,
    );

    // The typeHash is keccak256 of the type string
    const expected = keccak.hash(type_str);
    try testing.expectEqualSlices(u8, &expected, &type_hash);
}

test "encodeData - uint256" {
    const allocator = testing.allocator;
    const result = try encodeData(allocator, .{ .uint256 = 1 }, "uint256", &.{});
    var expected: [32]u8 = [_]u8{0} ** 32;
    expected[31] = 1;
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "encodeData - address" {
    const allocator = testing.allocator;
    var addr: [20]u8 = [_]u8{0} ** 20;
    addr[0] = 0xCC;
    addr[19] = 0xCC;
    const result = try encodeData(allocator, .{ .address = addr }, "address", &.{});
    // Address is left-padded with 12 zero bytes
    try testing.expectEqual(@as(u8, 0), result[0]);
    try testing.expectEqual(@as(u8, 0), result[11]);
    try testing.expectEqual(@as(u8, 0xCC), result[12]);
    try testing.expectEqual(@as(u8, 0xCC), result[31]);
}

test "encodeData - bool" {
    const allocator = testing.allocator;
    const true_result = try encodeData(allocator, .{ .bool_val = true }, "bool", &.{});
    try testing.expectEqual(@as(u8, 1), true_result[31]);
    try testing.expectEqual(@as(u8, 0), true_result[0]);

    const false_result = try encodeData(allocator, .{ .bool_val = false }, "bool", &.{});
    try testing.expectEqual(@as(u8, 0), false_result[31]);
}

test "encodeData - string hashed" {
    const allocator = testing.allocator;
    const result = try encodeData(allocator, .{ .string_val = "Hello, Bob!" }, "string", &.{});
    const expected = keccak.hash("Hello, Bob!");
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "encodeData - bytes hashed" {
    const allocator = testing.allocator;
    const data: []const u8 = &.{ 0x01, 0x02, 0x03 };
    const result = try encodeData(allocator, .{ .bytes_val = data }, "bytes", &.{});
    const expected = keccak.hash(data);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "encodeData - int256 negative" {
    const allocator = testing.allocator;
    const result = try encodeData(allocator, .{ .int256 = -1 }, "int256", &.{});
    // -1 in two's complement is all 0xFF bytes
    var expected: [32]u8 = [_]u8{0xFF} ** 32;
    _ = &expected;
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "hashDomain - EIP-712 spec domain" {
    const allocator = testing.allocator;

    const domain = DomainSeparator{
        .name = "Ether Mail",
        .version = "1",
        .chain_id = 1,
        .verifying_contract = try hex.hexToBytesFixed(20, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
    };

    const domain_hash = try hashDomain(allocator, domain);
    const expected = try hex.hexToBytesFixed(32, "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");

    try testing.expectEqualSlices(u8, &expected, &domain_hash);
}

test "hashStruct - EIP-712 spec Mail message" {
    const allocator = testing.allocator;

    const person_type = TypeDef{
        .name = "Person",
        .fields = &.{
            .{ .name = "name", .type_str = "string" },
            .{ .name = "wallet", .type_str = "address" },
        },
    };

    const mail_type = TypeDef{
        .name = "Mail",
        .fields = &.{
            .{ .name = "from", .type_str = "Person" },
            .{ .name = "to", .type_str = "Person" },
            .{ .name = "contents", .type_str = "string" },
        },
    };

    const type_defs = [_]TypeDef{ mail_type, person_type };

    const from_person = StructValue{
        .type_name = "Person",
        .fields = &.{
            .{
                .name = "name",
                .type_str = "string",
                .value = .{ .string_val = "Cow" },
            },
            .{
                .name = "wallet",
                .type_str = "address",
                .value = .{ .address = try hex.hexToBytesFixed(20, "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826") },
            },
        },
    };

    const to_person = StructValue{
        .type_name = "Person",
        .fields = &.{
            .{
                .name = "name",
                .type_str = "string",
                .value = .{ .string_val = "Bob" },
            },
            .{
                .name = "wallet",
                .type_str = "address",
                .value = .{ .address = try hex.hexToBytesFixed(20, "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB") },
            },
        },
    };

    const mail = StructValue{
        .type_name = "Mail",
        .fields = &.{
            .{
                .name = "from",
                .type_str = "Person",
                .value = .{ .struct_val = from_person },
            },
            .{
                .name = "to",
                .type_str = "Person",
                .value = .{ .struct_val = to_person },
            },
            .{
                .name = "contents",
                .type_str = "string",
                .value = .{ .string_val = "Hello, Bob!" },
            },
        },
    };

    const struct_hash = try hashStruct(allocator, mail, &type_defs);
    const expected = try hex.hexToBytesFixed(32, "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");

    try testing.expectEqualSlices(u8, &expected, &struct_hash);
}

test "hashTypedData - EIP-712 spec full test vector" {
    const allocator = testing.allocator;

    const domain = DomainSeparator{
        .name = "Ether Mail",
        .version = "1",
        .chain_id = 1,
        .verifying_contract = try hex.hexToBytesFixed(20, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
    };

    const person_type = TypeDef{
        .name = "Person",
        .fields = &.{
            .{ .name = "name", .type_str = "string" },
            .{ .name = "wallet", .type_str = "address" },
        },
    };

    const mail_type = TypeDef{
        .name = "Mail",
        .fields = &.{
            .{ .name = "from", .type_str = "Person" },
            .{ .name = "to", .type_str = "Person" },
            .{ .name = "contents", .type_str = "string" },
        },
    };

    const type_defs = [_]TypeDef{ mail_type, person_type };

    const from_person = StructValue{
        .type_name = "Person",
        .fields = &.{
            .{
                .name = "name",
                .type_str = "string",
                .value = .{ .string_val = "Cow" },
            },
            .{
                .name = "wallet",
                .type_str = "address",
                .value = .{ .address = try hex.hexToBytesFixed(20, "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826") },
            },
        },
    };

    const to_person = StructValue{
        .type_name = "Person",
        .fields = &.{
            .{
                .name = "name",
                .type_str = "string",
                .value = .{ .string_val = "Bob" },
            },
            .{
                .name = "wallet",
                .type_str = "address",
                .value = .{ .address = try hex.hexToBytesFixed(20, "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB") },
            },
        },
    };

    const mail = StructValue{
        .type_name = "Mail",
        .fields = &.{
            .{
                .name = "from",
                .type_str = "Person",
                .value = .{ .struct_val = from_person },
            },
            .{
                .name = "to",
                .type_str = "Person",
                .value = .{ .struct_val = to_person },
            },
            .{
                .name = "contents",
                .type_str = "string",
                .value = .{ .string_val = "Hello, Bob!" },
            },
        },
    };

    const final_hash = try hashTypedData(allocator, domain, mail, &type_defs);
    const expected = try hex.hexToBytesFixed(32, "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");

    try testing.expectEqualSlices(u8, &expected, &final_hash);
}

test "hashDomain - minimal domain (name only)" {
    const allocator = testing.allocator;

    const domain = DomainSeparator{
        .name = "Test",
    };

    // Should not panic; just verify it produces a 32-byte hash
    const result = try hashDomain(allocator, domain);
    try testing.expectEqual(@as(usize, 32), result.len);
}

test "hashDomain - empty domain" {
    const allocator = testing.allocator;

    const domain = DomainSeparator{};

    // Empty domain with no fields
    const result = try hashDomain(allocator, domain);
    try testing.expectEqual(@as(usize, 32), result.len);

    // The type string should be "EIP712Domain()" and the hash is keccak256 of just the typeHash
    const type_hash = keccak.hash("EIP712Domain()");
    const expected = keccak.hash(&type_hash);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "hashDomain - with salt" {
    const allocator = testing.allocator;

    const domain = DomainSeparator{
        .name = "Test",
        .salt = [_]u8{0xAB} ** 32,
    };

    const result = try hashDomain(allocator, domain);
    try testing.expectEqual(@as(usize, 32), result.len);
}

test "encodeData - array of uint256" {
    const allocator = testing.allocator;

    const items = [_]TypedValue{
        .{ .uint256 = 1 },
        .{ .uint256 = 2 },
        .{ .uint256 = 3 },
    };

    const result = try encodeData(allocator, .{ .array_val = &items }, "uint256[]", &.{});

    // Should be keccak256 of the concatenated encodings
    var concat: [96]u8 = undefined;
    const enc1 = uint256_mod.toBigEndianBytes(1);
    const enc2 = uint256_mod.toBigEndianBytes(2);
    const enc3 = uint256_mod.toBigEndianBytes(3);
    @memcpy(concat[0..32], &enc1);
    @memcpy(concat[32..64], &enc2);
    @memcpy(concat[64..96], &enc3);

    const expected = keccak.hash(&concat);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "encodeData - bytes32" {
    const allocator = testing.allocator;
    var val: [32]u8 = [_]u8{0} ** 32;
    val[0] = 0xDE;
    val[31] = 0xAD;
    const result = try encodeData(allocator, .{ .bytes32 = val }, "bytes32", &.{});
    try testing.expectEqualSlices(u8, &val, &result);
}

test "isStructType helper" {
    try testing.expect(!isStructType("address"));
    try testing.expect(!isStructType("bool"));
    try testing.expect(!isStructType("string"));
    try testing.expect(!isStructType("bytes"));
    try testing.expect(!isStructType("uint256"));
    try testing.expect(!isStructType("int8"));
    try testing.expect(!isStructType("bytes32"));
    try testing.expect(!isStructType("uint256[]"));
    try testing.expect(isStructType("Person"));
    try testing.expect(isStructType("Mail"));
    try testing.expect(isStructType("Person[]"));
    try testing.expect(isStructType("EIP712Domain"));
}

test "collectReferencedTypes - transitive references" {
    const allocator = testing.allocator;

    const type_defs = [_]TypeDef{
        .{
            .name = "Order",
            .fields = &.{
                .{ .name = "item", .type_str = "Item" },
                .{ .name = "buyer", .type_str = "Person" },
            },
        },
        .{
            .name = "Item",
            .fields = &.{
                .{ .name = "name", .type_str = "string" },
                .{ .name = "price", .type_str = "uint256" },
            },
        },
        .{
            .name = "Person",
            .fields = &.{
                .{ .name = "name", .type_str = "string" },
                .{ .name = "wallet", .type_str = "address" },
            },
        },
    };

    const refs = try collectReferencedTypes(allocator, "Order", &type_defs);
    defer allocator.free(refs);

    // Should find both Item and Person
    try testing.expectEqual(@as(usize, 2), refs.len);

    // Check that both are present (order may vary)
    var found_item = false;
    var found_person = false;
    for (refs) |ref| {
        if (std.mem.eql(u8, ref.name, "Item")) found_item = true;
        if (std.mem.eql(u8, ref.name, "Person")) found_person = true;
    }
    try testing.expect(found_item);
    try testing.expect(found_person);
}

test "hashStruct - deeply nested struct" {
    const allocator = testing.allocator;

    // Verify that nested structs are hashed recursively without crashing
    const inner_type = TypeDef{
        .name = "Inner",
        .fields = &.{
            .{ .name = "value", .type_str = "uint256" },
        },
    };

    const outer_type = TypeDef{
        .name = "Outer",
        .fields = &.{
            .{ .name = "inner", .type_str = "Inner" },
            .{ .name = "label", .type_str = "string" },
        },
    };

    const type_defs = [_]TypeDef{ outer_type, inner_type };

    const inner = StructValue{
        .type_name = "Inner",
        .fields = &.{
            .{ .name = "value", .type_str = "uint256", .value = .{ .uint256 = 42 } },
        },
    };

    const outer = StructValue{
        .type_name = "Outer",
        .fields = &.{
            .{ .name = "inner", .type_str = "Inner", .value = .{ .struct_val = inner } },
            .{ .name = "label", .type_str = "string", .value = .{ .string_val = "test" } },
        },
    };

    const result = try hashStruct(allocator, outer, &type_defs);
    try testing.expectEqual(@as(usize, 32), result.len);

    // Verify determinism: hash the same struct again
    const result2 = try hashStruct(allocator, outer, &type_defs);
    try testing.expectEqualSlices(u8, &result, &result2);
}

test "hashTypedData - verify domain and struct hashes independently" {
    const allocator = testing.allocator;

    // Use the EIP-712 spec example to verify that the domain hash and struct hash
    // are computed correctly before being combined.
    const domain = DomainSeparator{
        .name = "Ether Mail",
        .version = "1",
        .chain_id = 1,
        .verifying_contract = try hex.hexToBytesFixed(20, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
    };

    const domain_hash = try hashDomain(allocator, domain);
    const expected_domain = try hex.hexToBytesFixed(32, "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
    try testing.expectEqualSlices(u8, &expected_domain, &domain_hash);

    // Manually compute the final hash to verify the combination
    const struct_hash = try hex.hexToBytesFixed(32, "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");

    const manual_final = keccak.hashConcat(&.{
        &[_]u8{ 0x19, 0x01 },
        &domain_hash,
        &struct_hash,
    });

    const expected_final = try hex.hexToBytesFixed(32, "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
    try testing.expectEqualSlices(u8, &expected_final, &manual_final);
}
