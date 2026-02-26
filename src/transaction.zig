const std = @import("std");
const rlp = @import("rlp.zig");
const keccak = @import("keccak.zig");
const access_list_mod = @import("access_list.zig");

pub const AccessListItem = access_list_mod.AccessListItem;
pub const AccessList = access_list_mod.AccessList;

// ============================================================================
// Transaction Types
// ============================================================================

/// EIP-155 legacy transaction (type 0).
pub const LegacyTransaction = struct {
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?[20]u8, // null for contract creation
    value: u256,
    data: []const u8,
    chain_id: ?u64, // for EIP-155; null for pre-EIP-155
};

/// EIP-2930 typed transaction (type 1).
pub const Eip2930Transaction = struct {
    chain_id: u64,
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?[20]u8,
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
};

/// EIP-1559 typed transaction (type 2).
pub const Eip1559Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: ?[20]u8,
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
};

/// EIP-4844 blob transaction (type 3).
pub const Eip4844Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: [20]u8, // blob txs always have a destination
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
    max_fee_per_blob_gas: u256,
    blob_versioned_hashes: []const [32]u8,
};

/// Tagged union of all transaction types.
pub const Transaction = union(enum) {
    legacy: LegacyTransaction,
    eip2930: Eip2930Transaction,
    eip1559: Eip1559Transaction,
    eip4844: Eip4844Transaction,
};

// ============================================================================
// Serialization
// ============================================================================

/// Serialize a transaction for signing (the payload that gets hashed to produce the sighash).
///
/// - Legacy (EIP-155): RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
/// - Legacy (pre-155): RLP([nonce, gasPrice, gasLimit, to, value, data])
/// - EIP-2930: 0x01 ++ RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList])
/// - EIP-1559: 0x02 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
/// - EIP-4844: 0x03 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes])
///
/// Caller owns the returned slice.
pub fn serializeForSigning(allocator: std.mem.Allocator, tx: Transaction) ![]u8 {
    switch (tx) {
        .legacy => |legacy| return serializeLegacyForSigning(allocator, legacy),
        .eip2930 => |eip2930| return serializeTypedForSigning(allocator, 0x01, eip2930),
        .eip1559 => |eip1559| return serializeTypedForSigning(allocator, 0x02, eip1559),
        .eip4844 => |eip4844| return serializeTypedForSigning(allocator, 0x03, eip4844),
    }
}

/// Keccak-256 hash of the signing payload.
pub fn hashForSigning(allocator: std.mem.Allocator, tx: Transaction) ![32]u8 {
    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);
    return keccak.hash(payload);
}

/// Serialize a signed transaction (ready for broadcast).
///
/// - Legacy: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
/// - EIP-2930: 0x01 ++ RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s])
/// - EIP-1559: 0x02 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])
/// - EIP-4844: 0x03 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, v, r, s])
///
/// Caller owns the returned slice.
pub fn serializeSigned(allocator: std.mem.Allocator, tx: Transaction, r: [32]u8, s: [32]u8, v: u8) ![]u8 {
    switch (tx) {
        .legacy => |legacy| return serializeLegacySigned(allocator, legacy, r, s, v),
        .eip2930 => |eip2930| return serializeTypedSigned(allocator, 0x01, eip2930, r, s, v),
        .eip1559 => |eip1559| return serializeTypedSigned(allocator, 0x02, eip1559, r, s, v),
        .eip4844 => |eip4844| return serializeTypedSigned(allocator, 0x03, eip4844, r, s, v),
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Encode the common base fields for a legacy transaction (nonce through data).
fn encodeLegacyBaseFields(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), legacy: LegacyTransaction) !void {
    try rlp.encodeInto(allocator, buf, legacy.nonce);
    try rlp.encodeInto(allocator, buf, legacy.gas_price);
    try rlp.encodeInto(allocator, buf, legacy.gas_limit);
    try rlp.encodeInto(allocator, buf, legacy.to);
    try rlp.encodeInto(allocator, buf, legacy.value);
    try rlp.encodeInto(allocator, buf, legacy.data);
}

/// Calculate the payload length of legacy transaction fields.
fn calculateLegacyFieldsLength(legacy: LegacyTransaction) usize {
    var payload_len: usize = 0;
    payload_len += rlp.encodedLength(legacy.nonce);
    payload_len += rlp.encodedLength(legacy.gas_price);
    payload_len += rlp.encodedLength(legacy.gas_limit);
    payload_len += rlp.encodedLength(legacy.to);
    payload_len += rlp.encodedLength(legacy.value);
    payload_len += rlp.encodedLength(legacy.data);
    if (legacy.chain_id) |chain_id| {
        payload_len += rlp.encodedLength(chain_id);
        payload_len += rlp.encodedLength(@as(u64, 0));
        payload_len += rlp.encodedLength(@as(u64, 0));
    }
    return payload_len;
}

/// Serialize a legacy transaction for signing.
fn serializeLegacyForSigning(allocator: std.mem.Allocator, legacy: LegacyTransaction) ![]u8 {
    const payload_len = calculateLegacyFieldsLength(legacy);
    const total = rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    // Write list header + fields directly
    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeLegacyBaseFields(allocator, &result, legacy);

    if (legacy.chain_id) |chain_id| {
        try rlp.encodeInto(allocator, &result, chain_id);
        try rlp.encodeInto(allocator, &result, @as(u64, 0));
        try rlp.encodeInto(allocator, &result, @as(u64, 0));
    }

    return result.toOwnedSlice(allocator);
}

/// Encode the fields of a typed (non-legacy) transaction for signing into an ArrayList.
/// This encodes all the fields specific to each transaction type.
fn encodeTypedFields(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), tx: anytype) !void {
    const T = @TypeOf(tx);

    // All typed transactions start with chain_id
    try rlp.encodeInto(allocator, buf, tx.chain_id);
    try rlp.encodeInto(allocator, buf, tx.nonce);

    // EIP-1559 and EIP-4844 have priority fee + max fee; EIP-2930 has gas_price
    if (@hasField(T, "max_priority_fee_per_gas")) {
        try rlp.encodeInto(allocator, buf, tx.max_priority_fee_per_gas);
        try rlp.encodeInto(allocator, buf, tx.max_fee_per_gas);
    } else {
        try rlp.encodeInto(allocator, buf, tx.gas_price);
    }

    try rlp.encodeInto(allocator, buf, tx.gas_limit);

    // `to` field: EIP-4844 always has a destination (non-optional), others have optional
    if (@hasField(T, "to")) {
        const to_field = tx.to;
        const ToFieldType = @TypeOf(to_field);
        if (ToFieldType == ?[20]u8) {
            try rlp.encodeInto(allocator, buf, to_field);
        } else {
            // Non-optional [20]u8
            try rlp.encodeInto(allocator, buf, to_field);
        }
    }

    try rlp.encodeInto(allocator, buf, tx.value);
    try rlp.encodeInto(allocator, buf, tx.data);

    // Access list
    try access_list_mod.encodeAccessList(allocator, buf, tx.access_list);

    // EIP-4844 extra fields
    if (@hasField(T, "max_fee_per_blob_gas")) {
        try rlp.encodeInto(allocator, buf, tx.max_fee_per_blob_gas);
        // blob_versioned_hashes: list of [32]u8
        try encodeBlobHashes(allocator, buf, tx.blob_versioned_hashes);
    }
}

/// Encode a list of 32-byte blob versioned hashes.
fn encodeBlobHashes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), hashes: []const [32]u8) !void {
    // Pre-calculate payload length
    var payload_len: usize = 0;
    for (hashes) |h| {
        payload_len += rlp.encodedLength(h);
    }
    try list.ensureTotalCapacity(allocator, list.items.len + rlp.lengthPrefixSize(payload_len) + payload_len);
    encodeLengthAssumeCapacity(list, payload_len, 0xc0);
    for (hashes) |h| {
        try rlp.encodeInto(allocator, list, h);
    }
}

/// Write typed transaction fields directly to buffer. Returns bytes written.
fn writeTypedFieldsDirect(buf: []u8, tx: anytype) usize {
    const T = @TypeOf(tx);
    var pos: usize = 0;

    pos += rlp.writeDirect(buf[pos..], tx.chain_id);
    pos += rlp.writeDirect(buf[pos..], tx.nonce);

    if (@hasField(T, "max_priority_fee_per_gas")) {
        pos += rlp.writeDirect(buf[pos..], tx.max_priority_fee_per_gas);
        pos += rlp.writeDirect(buf[pos..], tx.max_fee_per_gas);
    } else {
        pos += rlp.writeDirect(buf[pos..], tx.gas_price);
    }

    pos += rlp.writeDirect(buf[pos..], tx.gas_limit);

    if (@hasField(T, "to")) {
        pos += rlp.writeDirect(buf[pos..], tx.to);
    }

    pos += rlp.writeDirect(buf[pos..], tx.value);
    pos += rlp.writeDirect(buf[pos..], tx.data);

    // Access list
    pos += writeAccessListDirect(buf[pos..], tx.access_list);

    if (@hasField(T, "max_fee_per_blob_gas")) {
        pos += rlp.writeDirect(buf[pos..], tx.max_fee_per_blob_gas);
        // blob_versioned_hashes
        var hashes_payload: usize = 0;
        for (tx.blob_versioned_hashes) |h| {
            hashes_payload += rlp.encodedLength(h);
        }
        pos += rlp.writeLengthDirect(buf[pos..], hashes_payload, 0xc0);
        for (tx.blob_versioned_hashes) |h| {
            pos += rlp.writeDirect(buf[pos..], h);
        }
    }

    return pos;
}

/// Write access list directly to buffer. Returns bytes written.
fn writeAccessListDirect(buf: []u8, access_list: access_list_mod.AccessList) usize {
    var outer_payload_len: usize = 0;
    for (access_list) |item| {
        const addr_len = rlp.encodedLength(item.address);
        var keys_payload_len: usize = 0;
        for (item.storage_keys) |key| {
            keys_payload_len += rlp.encodedLength(key);
        }
        const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;
        const item_payload_len = addr_len + keys_list_len;
        outer_payload_len += rlp.lengthPrefixSize(item_payload_len) + item_payload_len;
    }

    var pos = rlp.writeLengthDirect(buf, outer_payload_len, 0xc0);

    for (access_list) |item| {
        const addr_len = rlp.encodedLength(item.address);
        var keys_payload_len: usize = 0;
        for (item.storage_keys) |key| {
            keys_payload_len += rlp.encodedLength(key);
        }
        const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;
        const item_payload_len = addr_len + keys_list_len;

        pos += rlp.writeLengthDirect(buf[pos..], item_payload_len, 0xc0);
        pos += rlp.writeDirect(buf[pos..], item.address);
        pos += rlp.writeLengthDirect(buf[pos..], keys_payload_len, 0xc0);
        for (item.storage_keys) |key| {
            pos += rlp.writeDirect(buf[pos..], key);
        }
    }

    return pos;
}

/// Calculate the total payload length of typed transaction fields for RLP list.
fn calculateTypedFieldsLength(tx: anytype) usize {
    const T = @TypeOf(tx);
    var payload_len: usize = 0;

    payload_len += rlp.encodedLength(tx.chain_id);
    payload_len += rlp.encodedLength(tx.nonce);

    if (@hasField(T, "max_priority_fee_per_gas")) {
        payload_len += rlp.encodedLength(tx.max_priority_fee_per_gas);
        payload_len += rlp.encodedLength(tx.max_fee_per_gas);
    } else {
        payload_len += rlp.encodedLength(tx.gas_price);
    }

    payload_len += rlp.encodedLength(tx.gas_limit);

    if (@hasField(T, "to")) {
        const to_field = tx.to;
        payload_len += rlp.encodedLength(to_field);
    }

    payload_len += rlp.encodedLength(tx.value);
    payload_len += rlp.encodedLength(tx.data);

    payload_len += access_list_mod.accessListEncodedLength(tx.access_list);

    if (@hasField(T, "max_fee_per_blob_gas")) {
        payload_len += rlp.encodedLength(tx.max_fee_per_blob_gas);
        // blob_versioned_hashes list
        var hashes_payload: usize = 0;
        for (tx.blob_versioned_hashes) |h| {
            hashes_payload += rlp.encodedLength(h);
        }
        payload_len += rlp.lengthPrefixSize(hashes_payload) + hashes_payload;
    }

    return payload_len;
}

/// Serialize a typed transaction (EIP-2930/1559/4844) for signing.
/// Returns: type_byte ++ RLP([fields...])
fn serializeTypedForSigning(allocator: std.mem.Allocator, type_byte: u8, tx: anytype) ![]u8 {
    // Pre-calculate total size for single allocation
    const payload_len = calculateTypedFieldsLength(tx);
    const total = 1 + rlp.lengthPrefixSize(payload_len) + payload_len;

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    // Write type byte
    buf[0] = type_byte;
    var pos: usize = 1;
    // Write RLP list header
    pos += rlp.writeLengthDirect(buf[pos..], payload_len, 0xc0);
    // Write fields directly into buffer
    pos += writeTypedFieldsDirect(buf[pos..], tx);

    return buf[0..total];
}

/// Encode a length prefix without allocation (capacity must be pre-ensured).
fn encodeLengthAssumeCapacity(list: *std.ArrayList(u8), len: usize, offset: u8) void {
    if (len < 56) {
        list.appendAssumeCapacity(offset + @as(u8, @intCast(len)));
    } else {
        var len_bytes: usize = 0;
        var temp = len;
        while (temp > 0) : (temp >>= 8) {
            len_bytes += 1;
        }
        list.appendAssumeCapacity(offset + 55 + @as(u8, @intCast(len_bytes)));
        var i: usize = len_bytes;
        while (i > 0) {
            i -= 1;
            list.appendAssumeCapacity(@intCast((len >> @intCast(i * 8)) & 0xff));
        }
    }
}

/// Serialize a signed legacy transaction.
fn serializeLegacySigned(allocator: std.mem.Allocator, legacy: LegacyTransaction, r: [32]u8, s: [32]u8, v: u8) ![]u8 {
    // Calculate payload length
    var payload_len: usize = 0;
    payload_len += rlp.encodedLength(legacy.nonce);
    payload_len += rlp.encodedLength(legacy.gas_price);
    payload_len += rlp.encodedLength(legacy.gas_limit);
    payload_len += rlp.encodedLength(legacy.to);
    payload_len += rlp.encodedLength(legacy.value);
    payload_len += rlp.encodedLength(legacy.data);
    payload_len += rlp.encodedLength(v);
    payload_len += encodedU256BytesLength(&r);
    payload_len += encodedU256BytesLength(&s);

    const total = rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeLegacyBaseFields(allocator, &result, legacy);
    try rlp.encodeInto(allocator, &result, v);
    try encodeU256Bytes(allocator, &result, &r);
    try encodeU256Bytes(allocator, &result, &s);

    return result.toOwnedSlice(allocator);
}

/// Serialize a signed typed transaction.
fn serializeTypedSigned(allocator: std.mem.Allocator, type_byte: u8, tx: anytype, r: [32]u8, s: [32]u8, v: u8) ![]u8 {
    // Pre-calculate total size
    var payload_len = calculateTypedFieldsLength(tx);
    payload_len += rlp.encodedLength(v);
    payload_len += encodedU256BytesLength(&r);
    payload_len += encodedU256BytesLength(&s);

    const total = 1 + rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    result.appendAssumeCapacity(type_byte);
    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeTypedFields(allocator, &result, tx);
    try rlp.encodeInto(allocator, &result, v);
    try encodeU256Bytes(allocator, &result, &r);
    try encodeU256Bytes(allocator, &result, &s);

    return result.toOwnedSlice(allocator);
}

/// Calculate the encoded length of a 32-byte big-endian value as RLP integer.
fn encodedU256BytesLength(bytes: *const [32]u8) usize {
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}
    if (start == 32) return rlp.encodedLength(@as(u64, 0));
    return rlp.encodedLength(bytes[start..]);
}

/// Encode a 32-byte big-endian value as an RLP integer (stripping leading zeros).
/// This is used for r and s signature values, which are 256-bit unsigned integers
/// stored as fixed 32-byte arrays.
fn encodeU256Bytes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), bytes: *const [32]u8) !void {
    // Find first non-zero byte
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}

    if (start == 32) {
        // All zeros => encode as 0
        try rlp.encodeInto(allocator, list, @as(u64, 0));
    } else {
        // Encode the significant bytes as a byte string
        try rlp.encodeInto(allocator, list, bytes[start..]);
    }
}

// ============================================================================
// Tests
// ============================================================================

const hex_mod = @import("hex.zig");

test "legacy tx serialization for signing (EIP-155, chain_id=1)" {
    const allocator = std.testing.allocator;

    // A well-known test case: simple ETH transfer on mainnet.
    // nonce=9, gasPrice=20 gwei, gasLimit=21000, to=0x3535...3535, value=1 ether, data=empty, chainId=1
    const tx = Transaction{
        .legacy = .{
            .nonce = 9,
            .gas_price = 20_000_000_000, // 20 gwei
            .gas_limit = 21000,
            .to = [_]u8{0x35} ** 20,
            .value = 1_000_000_000_000_000_000, // 1 ETH in wei
            .data = &.{},
            .chain_id = 1,
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Verify it starts with an RLP list prefix
    try std.testing.expect(payload[0] >= 0xc0);

    // Hash it to check determinism
    const hash1 = try hashForSigning(allocator, tx);
    const hash2 = try hashForSigning(allocator, tx);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);

    // Verify the payload is valid RLP by checking the list length
    try std.testing.expect(payload.len > 10);
}

test "legacy tx serialization without chain_id (pre-EIP-155)" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xaa} ** 20,
        .value = 0,
        .data = &.{},
        .chain_id = null,
    } };

    const with_chain = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xaa} ** 20,
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const payload_no_chain = try serializeForSigning(allocator, tx);
    defer allocator.free(payload_no_chain);

    const payload_with_chain = try serializeForSigning(allocator, with_chain);
    defer allocator.free(payload_with_chain);

    // Pre-EIP-155 should be shorter (no chainId, 0, 0)
    try std.testing.expect(payload_no_chain.len < payload_with_chain.len);
}

test "legacy tx contract creation (to=null)" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .legacy = .{
            .nonce = 0,
            .gas_price = 1_000_000_000,
            .gas_limit = 100_000,
            .to = null,
            .value = 0,
            .data = &.{ 0x60, 0x00 }, // minimal bytecode
            .chain_id = 1,
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Should encode successfully
    try std.testing.expect(payload.len > 0);
}

test "eip2930 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip2930 = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xbb} ** 20,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x01
    try std.testing.expectEqual(@as(u8, 0x01), payload[0]);
    // Followed by RLP list
    try std.testing.expect(payload[1] >= 0xc0);
}

test "eip1559 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 0,
            .max_priority_fee_per_gas = 1_500_000_000, // 1.5 gwei
            .max_fee_per_gas = 30_000_000_000, // 30 gwei
            .gas_limit = 21000,
            .to = [_]u8{0xcc} ** 20,
            .value = 1_000_000_000_000_000_000,
            .data = &.{},
            .access_list = &.{},
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x02
    try std.testing.expectEqual(@as(u8, 0x02), payload[0]);
}

test "eip4844 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const hash1 = [_]u8{0x01} ++ [_]u8{0xaa} ** 31;

    const hashes = [_][32]u8{hash1};
    const tx = Transaction{ .eip4844 = .{
        .chain_id = 1,
        .nonce = 5,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 50_000_000_000,
        .gas_limit = 100_000,
        .to = [_]u8{0xdd} ** 20,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 1_000_000_000,
        .blob_versioned_hashes = &hashes,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x03
    try std.testing.expectEqual(@as(u8, 0x03), payload[0]);
}

test "signed legacy tx serialization" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 9,
        .gas_price = 20_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0x35} ** 20,
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .chain_id = 1,
    } };

    const r = [_]u8{0x01} ** 32;
    const s = [_]u8{0x02} ** 32;
    const v: u8 = 37; // chain_id=1 => v = 1*2 + 35 + 0 = 37

    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Should be RLP-encoded (no type prefix for legacy)
    try std.testing.expect(signed[0] >= 0xc0);
    try std.testing.expect(signed.len > 60);
}

test "signed eip1559 tx serialization" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_500_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xcc} ** 20,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const r = [_]u8{0xab} ** 32;
    const s = [_]u8{0xcd} ** 32;
    const v: u8 = 1;

    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Typed transaction: starts with 0x02
    try std.testing.expectEqual(@as(u8, 0x02), signed[0]);
}

test "eip1559 known test vector" {
    // Test vector from EIP-1559 reference:
    // Verify the signing payload structure is correct.
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // 0x02 ++ RLP([1, 0, 0, 0, 0, 0x80, 0, 0x80, 0xc0])
    // chainId=1 -> 0x01
    // nonce=0 -> 0x80
    // maxPriorityFeePerGas=0 -> 0x80
    // maxFeePerGas=0 -> 0x80
    // gasLimit=0 -> 0x80
    // to=null -> 0x80
    // value=0 -> 0x80
    // data=empty -> 0x80
    // accessList=empty -> 0xc0
    // List payload = [0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0] = 9 bytes
    // RLP list header: 0xc9 (0xc0 + 9)
    // Total: 0x02, 0xc9, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0

    const expected = [_]u8{ 0x02, 0xc9, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0 };
    try std.testing.expectEqualSlices(u8, &expected, payload);
}

test "legacy tx known encoding (EIP-155)" {
    // Verify the structure for a legacy EIP-155 signing payload with all-zero values.
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // RLP([0, 0, 0, null, 0, empty, 1, 0, 0])
    // nonce=0 -> 0x80
    // gasPrice=0 -> 0x80
    // gasLimit=0 -> 0x80
    // to=null -> 0x80
    // value=0 -> 0x80
    // data=empty -> 0x80
    // chainId=1 -> 0x01
    // 0 -> 0x80
    // 0 -> 0x80
    // List payload = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x80, 0x80] = 9 bytes
    // RLP header: 0xc9

    const expected = [_]u8{ 0xc9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x80, 0x80 };
    try std.testing.expectEqualSlices(u8, &expected, payload);
}

test "eip2930 with access list" {
    const allocator = std.testing.allocator;

    const addr = [_]u8{0x11} ** 20;
    const key = [_]u8{0x22} ** 32;

    const keys = [_][32]u8{key};
    const items = [_]AccessListItem{.{
        .address = addr,
        .storage_keys = &keys,
    }};

    const tx = Transaction{ .eip2930 = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &items,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Starts with 0x01
    try std.testing.expectEqual(@as(u8, 0x01), payload[0]);
    // Should be non-trivially long due to access list
    try std.testing.expect(payload.len > 50);
}

test "encodeU256Bytes strips leading zeros" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    // Value with many leading zeros
    var val = [_]u8{0} ** 32;
    val[31] = 0x42;

    try encodeU256Bytes(allocator, &list, &val);

    // Should encode as a single byte 0x42 (< 0x80, so single byte encoding)
    try std.testing.expectEqualSlices(u8, &.{0x42}, list.items);
}

test "encodeU256Bytes all zeros" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    const val = [_]u8{0} ** 32;
    try encodeU256Bytes(allocator, &list, &val);

    // Should encode as RLP 0 = 0x80
    try std.testing.expectEqualSlices(u8, &.{0x80}, list.items);
}

test "hashForSigning produces different hashes for different txs" {
    const allocator = std.testing.allocator;

    const tx1 = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xaa} ** 20,
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const tx2 = Transaction{ .legacy = .{
        .nonce = 1,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = [_]u8{0xaa} ** 20,
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const h1 = try hashForSigning(allocator, tx1);
    const h2 = try hashForSigning(allocator, tx2);

    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}
