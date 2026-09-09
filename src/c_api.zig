//! C ABI translation layer. The header is also imported here so C and Zig
//! share struct layouts and error constants. Serialization workspace is
//! caller-owned; secp256k1 uses its existing process-wide backend context.
const std = @import("std");
const c = @cImport(@cInclude("eth.h"));
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const secp = @import("secp256k1.zig");
const tx_mod = @import("transaction.zig");
const abi_encode = @import("abi_encode.zig");
const abi_decode = @import("abi_decode.zig");
const abi_types = @import("abi_types.zig");
const uint256 = @import("uint256.zig");
const rlp = @import("rlp.zig");

fn status(err: anyerror) c_int {
    return switch (err) {
        error.OutOfMemory => c.ETH_ERR_BUFFER_TOO_SMALL,
        error.InvalidArgument => c.ETH_ERR_INVALID_ARGUMENT,
        error.InvalidPrivateKey => c.ETH_ERR_INVALID_KEY,
        error.InvalidSignature, error.InvalidRecoveryId, error.RecoveryFailed => c.ETH_ERR_INVALID_SIGNATURE,
        error.SigningFailed => c.ETH_ERR_CRYPTO,
        error.UnsupportedType, error.TooManyValues => c.ETH_ERR_UNSUPPORTED,
        error.Overflow => c.ETH_ERR_OVERFLOW,
        else => c.ETH_ERR_INVALID_ENCODING,
    };
}

fn bytes(ptr: [*c]const u8, len: usize) ![]const u8 {
    if (len == 0) return &.{};
    if (ptr == null) return error.InvalidArgument;
    return ptr[0..len];
}

fn output(ptr: [*c]u8, len: usize) ![]u8 {
    if (len == 0) return &.{};
    if (ptr == null) return error.InvalidArgument;
    return ptr[0..len];
}

fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b);
}

fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b);
}

export fn eth_keccak256(data: [*c]const u8, len: usize, out: [*c]u8) c_int {
    if (out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    const input = bytes(data, len) catch |err| return status(err);
    out[0..32].* = keccak.hash(input);
    return c.ETH_OK;
}

export fn eth_address_from_pubkey(pubkey: [*c]const u8, out: [*c]u8) c_int {
    if (pubkey == null or out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    // Validate SEC1 before hashing: pubkeyToAddress intentionally trusts input.
    _ = std.crypto.ecc.Secp256k1.fromSec1(pubkey[0..65]) catch return c.ETH_ERR_INVALID_ARGUMENT;
    if (pubkey[0] != 4) return c.ETH_ERR_INVALID_ARGUMENT;
    out[0..20].* = secp.pubkeyToAddress(pubkey[0..65].*);
    return c.ETH_OK;
}

export fn eth_address_checksum(address: [*c]const u8, out: [*c]u8) c_int {
    if (address == null or out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    out[0..42].* = primitives.addressToChecksum(address[0..20]);
    out[42] = 0;
    return c.ETH_OK;
}

export fn eth_sign(key: [*c]const u8, hash: [*c]const u8, out: [*c]u8) c_int {
    if (key == null or hash == null or out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    const sig = secp.sign(key[0..32].*, hash[0..32].*) catch |err| return status(err);
    out[0..32].* = sig.r;
    out[32..64].* = sig.s;
    out[64] = sig.v;
    return c.ETH_OK;
}

export fn eth_recover(signature: [*c]const u8, hash: [*c]const u8, out: [*c]u8) c_int {
    if (signature == null or hash == null or out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    out[0..20].* = secp.recoverAddress(.{
        .r = signature[0..32].*,
        .s = signature[32..64].*,
        .v = signature[64],
    }, hash[0..32].*) catch |err| return status(err);
    return c.ETH_OK;
}

fn txCapacity(tx: *const c.eth_eip1559_tx) !usize {
    if (tx.has_to > 1 or (tx.data_len != 0 and tx.data == null) or
        (tx.access_list_len != 0 and tx.access_list == null)) return error.InvalidArgument;
    if (uint256.fromBigEndianBytes(tx.max_priority_fee_per_gas) >
        uint256.fromBigEndianBytes(tx.max_fee_per_gas)) return error.InvalidArgument;
    var encoded = try add(512, tx.data_len);
    encoded = try add(encoded, try mul(tx.access_list_len, 64));
    for (0..tx.access_list_len) |i| {
        const item = tx.access_list[i];
        if (item.storage_keys_len != 0 and item.storage_keys == null) return error.InvalidArgument;
        encoded = try add(encoded, try mul(item.storage_keys_len, 33));
    }
    // Signed serialization uses ArrayList growth. Twice the encoding bound
    // plus slack covers its capacity, while the preimage allocation is freed
    // before signing. Metadata remains allocated until serialization ends.
    const metadata = try mul(tx.access_list_len, @sizeOf(tx_mod.AccessListItem));
    return add(try add(metadata, @alignOf(tx_mod.AccessListItem)), try add(try mul(encoded, 2), 64));
}

export fn eth_tx_sign_max_len(tx: ?*const c.eth_eip1559_tx) usize {
    return txCapacity(tx orelse return 0) catch 0;
}

export fn eth_tx_sign(tx_ptr: ?*const c.eth_eip1559_tx, key: [*c]const u8, out: [*c]u8, capacity: usize, written: ?*usize) c_int {
    const count = written orelse return c.ETH_ERR_INVALID_ARGUMENT;
    count.* = 0;
    const tx = tx_ptr orelse return c.ETH_ERR_INVALID_ARGUMENT;
    if (key == null) return c.ETH_ERR_INVALID_ARGUMENT;
    const required = txCapacity(tx) catch |err| return status(err);
    if (capacity < required) return c.ETH_ERR_BUFFER_TOO_SMALL;
    const buffer = output(out, capacity) catch |err| return status(err);
    var fba = std.heap.FixedBufferAllocator.init(buffer);
    const allocator = fba.allocator();
    const access_list = allocator.alloc(tx_mod.AccessListItem, tx.access_list_len) catch |err| return status(err);
    for (access_list, 0..) |*item, i| {
        const input = tx.access_list[i];
        item.* = .{
            .address = input.address,
            .storage_keys = if (input.storage_keys_len == 0) &.{} else input.storage_keys[0..input.storage_keys_len],
        };
    }
    const native = tx_mod.Transaction{ .eip1559 = .{
        .chain_id = tx.chain_id,
        .nonce = tx.nonce,
        .max_priority_fee_per_gas = uint256.fromBigEndianBytes(tx.max_priority_fee_per_gas),
        .max_fee_per_gas = uint256.fromBigEndianBytes(tx.max_fee_per_gas),
        .gas_limit = tx.gas_limit,
        .to = if (tx.has_to == 1) tx.to else null,
        .value = uint256.fromBigEndianBytes(tx.value),
        .data = bytes(tx.data, tx.data_len) catch |err| return status(err),
        .access_list = access_list,
    } };
    const hash = tx_mod.hashForSigning(allocator, native) catch |err| return status(err);
    const sig = secp.sign(key[0..32].*, hash) catch |err| return status(err);
    const signed = tx_mod.serializeSigned(allocator, native, sig.r, sig.s, sig.v) catch |err| return status(err);
    std.mem.copyForwards(u8, buffer[0..signed.len], signed);
    count.* = signed.len;
    return c.ETH_OK;
}

export fn eth_tx_hash(signed_tx: [*c]const u8, len: usize, out: [*c]u8) c_int {
    if (len == 0) return c.ETH_ERR_INVALID_ARGUMENT;
    return eth_keccak256(signed_tx, len, out);
}

export fn eth_abi_selector(signature: [*c]const u8, out: [*c]u8) c_int {
    if (signature == null or out == null) return c.ETH_ERR_INVALID_ARGUMENT;
    out[0..4].* = keccak.selector(std.mem.span(signature));
    return c.ETH_OK;
}

fn abiType(tag: c_int) !abi_types.AbiType {
    return switch (tag) {
        c.ETH_ABI_UINT256 => .uint256,
        c.ETH_ABI_INT256 => .int256,
        c.ETH_ABI_ADDRESS => .address,
        c.ETH_ABI_BOOL => .bool,
        c.ETH_ABI_BYTES32 => .bytes32,
        c.ETH_ABI_BYTES => .bytes,
        c.ETH_ABI_STRING => .string,
        else => error.UnsupportedType,
    };
}

fn abiValue(value: c.eth_abi_value) !abi_encode.AbiValue {
    _ = try abiType(value.type);
    return switch (value.type) {
        c.ETH_ABI_UINT256 => .{ .uint256 = uint256.fromBigEndianBytes(value.word) },
        c.ETH_ABI_INT256 => .{ .int256 = @bitCast(uint256.fromBigEndianBytes(value.word)) },
        c.ETH_ABI_ADDRESS => blk: {
            if (!std.mem.allEqual(u8, value.word[0..12], 0)) return error.InvalidArgument;
            break :blk .{ .address = value.word[12..32].* };
        },
        c.ETH_ABI_BOOL => blk: {
            const n = uint256.fromBigEndianBytes(value.word);
            if (n > 1) return error.InvalidArgument;
            break :blk .{ .boolean = n == 1 };
        },
        c.ETH_ABI_BYTES32 => .{ .fixed_bytes = .{ .data = value.word, .len = 32 } },
        c.ETH_ABI_BYTES => .{ .bytes = try bytes(value.data, value.data_len) },
        c.ETH_ABI_STRING => .{ .string = try bytes(value.data, value.data_len) },
        else => unreachable,
    };
}

fn abiCapacity(values: [*c]const c.eth_abi_value, count: usize) !usize {
    // This is also the entire workspace bound: encodeValues must allocate
    // only its exact output size, with no temporary allocations.
    if (count > c.ETH_ABI_MAX_VALUES) return error.TooManyValues;
    if (count != 0 and values == null) return error.InvalidArgument;
    var total = try mul(count, 32);
    for (0..count) |i| {
        const value = values[i];
        const native = try abiValue(value);
        if (native.isDynamic()) {
            const padded = (try add(value.data_len, 31)) & ~@as(usize, 31);
            total = try add(total, try add(32, padded));
        }
    }
    return total;
}

export fn eth_abi_encode_max_len(values: [*c]const c.eth_abi_value, count: usize) usize {
    // Empty tuple needs no space; reserve one byte to distinguish success.
    return @max(@as(usize, 1), abiCapacity(values, count) catch return 0);
}

export fn eth_abi_encode(values: [*c]const c.eth_abi_value, count: usize, out: [*c]u8, capacity: usize, written: ?*usize) c_int {
    const n = written orelse return c.ETH_ERR_INVALID_ARGUMENT;
    n.* = 0;
    const required = abiCapacity(values, count) catch |err| return status(err);
    if (capacity < required) return c.ETH_ERR_BUFFER_TOO_SMALL;
    var native: [c.ETH_ABI_MAX_VALUES]abi_encode.AbiValue = undefined;
    for (0..count) |i| native[i] = abiValue(values[i]) catch |err| return status(err);
    var fba = std.heap.FixedBufferAllocator.init(output(out, capacity) catch |err| return status(err));
    // The encoder's single exact-size allocation places the result at out.
    // Temporary allocations would require increasing abiCapacity's bound.
    const encoded = abi_encode.encodeValues(fba.allocator(), native[0..count]) catch |err| return status(err);
    n.* = encoded.len;
    return c.ETH_OK;
}

export fn eth_abi_decode_max_len(encoded_len: usize, count: usize) usize {
    if (count > c.ETH_ABI_MAX_VALUES) return 0;
    // Dynamic offsets may alias: allow each value its own copy of the input.
    const payload = mul(encoded_len, count) catch return 0;
    const metadata = mul(count, @sizeOf(abi_encode.AbiValue)) catch return 0;
    return add(add(payload, metadata) catch return 0, @alignOf(abi_encode.AbiValue)) catch 0;
}

fn validateAbi(data: []const u8, types: []const abi_types.AbiType) !void {
    const head_len = types.len * 32;
    if (data.len < head_len) return error.DataTooShort;
    if (data.len % 32 != 0) return error.InvalidAlignment;
    for (types, 0..) |kind, i| {
        const word = data[i * 32 ..][0..32];
        if (kind == .address and !std.mem.allEqual(u8, word[0..12], 0)) return error.InvalidAddressPadding;
        if (kind.isDynamic()) {
            const wide = uint256.fromBigEndianBytes(word.*);
            if (wide > data.len or wide < head_len or wide % 32 != 0) return error.OffsetOutOfBounds;
            const offset: usize = @intCast(wide);
            if (data.len - offset < 32) return error.DataTooShort;
            const len = uint256.fromBigEndianBytes(data[offset..][0..32].*);
            if (len > data.len - offset - 32) return error.LengthOutOfBounds;
            const byte_len: usize = @intCast(len);
            const padding = (32 - byte_len % 32) % 32;
            if (padding > data.len - offset - 32 - byte_len) return error.LengthOutOfBounds;
            if (!std.mem.allEqual(u8, data[offset + 32 + byte_len ..][0..padding], 0)) return error.InvalidFixedBytesPadding;
        }
    }
}

export fn eth_abi_decode(encoded: [*c]const u8, len: usize, types: [*c]const c_int, count: usize, out_values: [*c]c.eth_abi_value, storage: [*c]u8, storage_capacity: usize, written: ?*usize) c_int {
    const n = written orelse return c.ETH_ERR_INVALID_ARGUMENT;
    n.* = 0;
    if (count > c.ETH_ABI_MAX_VALUES) return c.ETH_ERR_UNSUPPORTED;
    if (count != 0 and (types == null or out_values == null)) return c.ETH_ERR_INVALID_ARGUMENT;
    const input = bytes(encoded, len) catch |err| return status(err);
    var native_types: [c.ETH_ABI_MAX_VALUES]abi_types.AbiType = undefined;
    for (0..count) |i| native_types[i] = abiType(types[i]) catch |err| return status(err);
    validateAbi(input, native_types[0..count]) catch |err| return status(err);
    var fba = std.heap.FixedBufferAllocator.init(output(storage, storage_capacity) catch |err| return status(err));
    const decoded = abi_decode.decodeValues(input, native_types[0..count], fba.allocator()) catch |err| return status(err);
    for (decoded, 0..) |value, i| {
        var item: c.eth_abi_value = std.mem.zeroes(c.eth_abi_value);
        item.type = types[i];
        switch (value) {
            .uint256 => |v| item.word = uint256.toBigEndianBytes(v),
            .int256 => |v| item.word = uint256.toBigEndianBytes(@bitCast(v)),
            .address => |v| @memcpy(item.word[12..32], &v),
            .boolean => |v| item.word[31] = @intFromBool(v),
            .fixed_bytes => |v| item.word = v.data,
            .bytes, .string => |v| {
                item.data = if (v.len == 0) null else v.ptr;
                item.data_len = v.len;
            },
            else => unreachable,
        }
        out_values[i] = item;
    }
    n.* = fba.end_index;
    return c.ETH_OK;
}

export fn eth_rlp_encode_max_len(payload_len: usize) usize {
    return add(payload_len, rlp.lengthPrefixSize(payload_len)) catch 0;
}

export fn eth_rlp_encode(kind: c_int, payload: [*c]const u8, len: usize, out: [*c]u8, capacity: usize, written: ?*usize) c_int {
    const n = written orelse return c.ETH_ERR_INVALID_ARGUMENT;
    n.* = 0;
    const input = bytes(payload, len) catch |err| return status(err);
    const required = eth_rlp_encode_max_len(len);
    if (required == 0) return c.ETH_ERR_OVERFLOW;
    if (capacity < required) return c.ETH_ERR_BUFFER_TOO_SMALL;
    const buf = output(out, capacity) catch |err| return status(err);
    switch (kind) {
        c.ETH_RLP_STRING => n.* = rlp.writeDirect(buf, input),
        c.ETH_RLP_LIST => {
            const prefix = rlp.writeLengthDirect(buf, len, 0xc0);
            @memcpy(buf[prefix..][0..len], input);
            n.* = prefix + len;
        },
        else => return c.ETH_ERR_INVALID_ARGUMENT,
    }
    return c.ETH_OK;
}

export fn eth_rlp_decode_max_len(encoded_len: usize) usize {
    return @max(@as(usize, 1), encoded_len);
}

export fn eth_rlp_decode(encoded: [*c]const u8, len: usize, kind: ?*c_int, out: [*c]u8, capacity: usize, written: ?*usize, consumed: ?*usize) c_int {
    const n = written orelse return c.ETH_ERR_INVALID_ARGUMENT;
    n.* = 0;
    const used = consumed orelse return c.ETH_ERR_INVALID_ARGUMENT;
    used.* = 0;
    const tag = kind orelse return c.ETH_ERR_INVALID_ARGUMENT;
    const input = bytes(encoded, len) catch |err| return status(err);
    const item = rlp.decodeItem(input) catch |err| return status(err);
    if (capacity < item.payload.len) return c.ETH_ERR_BUFFER_TOO_SMALL;
    const buf = output(out, capacity) catch |err| return status(err);
    @memcpy(buf[0..item.payload.len], item.payload);
    tag.* = if (item.kind == .string) c.ETH_RLP_STRING else c.ETH_RLP_LIST;
    n.* = item.payload.len;
    used.* = input.len - item.rest.len;
    return c.ETH_OK;
}
