const std = @import("std");
const rlp = @import("rlp.zig");

/// A single entry in an EIP-2930 access list: an address plus the storage slots it accesses.
pub const AccessListItem = struct {
    address: [20]u8,
    storage_keys: []const [32]u8,
};

/// EIP-2930 access list: a list of address/storage-key pairs that the transaction accesses.
pub const AccessList = []const AccessListItem;

/// Calculate the encoded length of an access list item.
fn accessListItemLength(item: AccessListItem) usize {
    // address: 1 byte prefix (0x94) + 20 bytes = 21 bytes
    const addr_len = rlp.encodedLength(item.address);

    // keys list: each key is 1 byte prefix (0xa0) + 32 bytes = 33 bytes
    var keys_payload_len: usize = 0;
    for (item.storage_keys) |key| {
        keys_payload_len += rlp.encodedLength(key);
    }
    const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;

    // item is a list of [address, keys_list]
    const item_payload_len = addr_len + keys_list_len;
    return rlp.lengthPrefixSize(item_payload_len) + item_payload_len;
}

/// Calculate the total encoded length of an access list.
pub fn accessListEncodedLength(access_list: AccessList) usize {
    var outer_payload_len: usize = 0;
    for (access_list) |item| {
        outer_payload_len += accessListItemLength(item);
    }
    return rlp.lengthPrefixSize(outer_payload_len) + outer_payload_len;
}

/// RLP-encode an access list into the given ArrayList.
/// Each item is encoded as: [address, [key0, key1, ...]].
pub fn encodeAccessList(allocator: std.mem.Allocator, list: *std.ArrayList(u8), access_list: AccessList) (std.mem.Allocator.Error || rlp.RlpError)!void {
    // Pre-calculate outer payload length to avoid temp buffers
    var outer_payload_len: usize = 0;
    for (access_list) |item| {
        outer_payload_len += accessListItemLength(item);
    }

    try encodeLength(allocator, list, outer_payload_len, 0xc0);

    for (access_list) |item| {
        // Pre-calculate item payload length
        const addr_len = rlp.encodedLength(item.address);
        var keys_payload_len: usize = 0;
        for (item.storage_keys) |key| {
            keys_payload_len += rlp.encodedLength(key);
        }
        const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;
        const item_payload_len = addr_len + keys_list_len;

        // Write item list header
        try encodeLength(allocator, list, item_payload_len, 0xc0);
        // Write address
        try rlp.encodeInto(allocator, list, item.address);
        // Write keys list header
        try encodeLength(allocator, list, keys_payload_len, 0xc0);
        // Write each key
        for (item.storage_keys) |key| {
            try rlp.encodeInto(allocator, list, key);
        }
    }
}

/// Encode a length prefix (same logic as rlp.zig's internal encodeLength, re-implemented
/// here since that function is not pub).
fn encodeLength(allocator: std.mem.Allocator, list: *std.ArrayList(u8), len: usize, offset: u8) std.mem.Allocator.Error!void {
    if (len < 56) {
        try list.append(allocator, offset + @as(u8, @intCast(len)));
    } else {
        var len_bytes: usize = 0;
        var temp = len;
        while (temp > 0) : (temp >>= 8) {
            len_bytes += 1;
        }
        try list.append(allocator, offset + 55 + @as(u8, @intCast(len_bytes)));
        var i: usize = len_bytes;
        while (i > 0) {
            i -= 1;
            try list.append(allocator, @intCast((len >> @intCast(i * 8)) & 0xff));
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "empty access list encodes as empty RLP list" {
    const allocator = std.testing.allocator;
    const empty: AccessList = &.{};

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try encodeAccessList(allocator, &list, empty);

    // Empty list = 0xc0
    try std.testing.expectEqualSlices(u8, &.{0xc0}, list.items);
}

test "access list with one item, no storage keys" {
    const allocator = std.testing.allocator;
    const addr = [_]u8{0xaa} ** 20;

    const items = [_]AccessListItem{
        .{
            .address = addr,
            .storage_keys = &.{},
        },
    };
    const access_list: AccessList = &items;

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try encodeAccessList(allocator, &list, access_list);

    // Inner item: [address(21 bytes), emptyList(1 byte)] = 22 bytes payload
    // address encoding: 0x94 + 20 bytes = 21 bytes
    // empty list: 0xc0 = 1 byte
    // item list header: 0xc0 + 22 = 0xd6
    // outer list header: 0xc0 + 23 = 0xd7
    try std.testing.expectEqual(@as(u8, 0xd7), list.items[0]); // outer list
    try std.testing.expectEqual(@as(u8, 0xd6), list.items[1]); // item list
    try std.testing.expectEqual(@as(u8, 0x94), list.items[2]); // address prefix (0x80 + 20)
}

test "access list with one item and one storage key" {
    const allocator = std.testing.allocator;
    const addr = [_]u8{0xbb} ** 20;
    const key = [_]u8{0xcc} ** 32;

    const keys = [_][32]u8{key};
    const items = [_]AccessListItem{
        .{
            .address = addr,
            .storage_keys = &keys,
        },
    };
    const access_list: AccessList = &items;

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try encodeAccessList(allocator, &list, access_list);

    // address: 0x94 + 20 bytes = 21 bytes
    // key: 0xa0 + 32 bytes = 33 bytes
    // keys list: 0xe1 (0xc0 + 33) + 33 bytes = 34 bytes
    // item payload: 21 + 34 = 55 bytes
    // item list: 0xf7 (0xc0 + 55) + 55 bytes = 56 bytes
    // outer payload: 56 bytes (>= 56, so long form)
    // outer list: 0xf8 0x38 + 56 bytes = 58 bytes
    try std.testing.expectEqual(@as(usize, 58), list.items.len);
}

test "access list item struct has correct fields" {
    const item = AccessListItem{
        .address = [_]u8{0} ** 20,
        .storage_keys = &.{},
    };
    try std.testing.expectEqual(@as(usize, 20), item.address.len);
    try std.testing.expectEqual(@as(usize, 0), item.storage_keys.len);
}
