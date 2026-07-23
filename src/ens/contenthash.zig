//! EIP-1577 `contenthash` decoding for ENS records.
//!
//! Decodes the multicodec-prefixed byte string stored in an ENS
//! `contenthash(bytes32)` record into a human-readable URI. Supports the three
//! protocols in common use: IPFS (`ipfs://`), IPNS (`ipns://`) and Swarm
//! (`bzz://`).
//!
//! The wire format is `<varint multicodec><cid>` where the multicodec names the
//! namespace (`0xe3` ipfs-ns, `0xe5` ipns-ns, `0xe4` swarm-ns) and the CID is a
//! self-describing content identifier. See EIP-1577 and the multiformats specs.

const std = @import("std");

/// The content-addressing protocol carried by a `contenthash` record.
pub const Protocol = enum { ipfs, ipns, swarm };

/// A decoded EIP-1577 contenthash.
pub const ContentHash = struct {
    /// Which namespace the record used.
    protocol: Protocol,
    /// Decoded URI, e.g. `ipfs://Qm...` / `ipns://k51...` / `bzz://<hex>`.
    /// Heap-allocated; the caller owns it and must call `deinit`.
    uri: []u8,

    /// Free the owned `uri` buffer.
    pub fn deinit(self: *ContentHash, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        self.uri = &.{};
    }
};

/// Errors returned by `decode`.
pub const DecodeError = error{
    /// The multicodec prefix is not one of ipfs-ns / ipns-ns / swarm-ns.
    UnsupportedProtocol,
    /// The bytes are not a well-formed contenthash / CID.
    InvalidContentHash,
    /// Allocation failure.
    OutOfMemory,
};

// Multicodec namespace codes (varint-encoded in the wire format).
const IPFS_NS: u64 = 0xe3;
const IPNS_NS: u64 = 0xe5;
const SWARM_NS: u64 = 0xe4;

/// Decode EIP-1577 contenthash bytes into a `ContentHash`.
///
/// Returns `null` for empty input (an unset record) and
/// `error.UnsupportedProtocol` for unknown multicodec prefixes. The caller owns
/// the returned `ContentHash` and must call `deinit`.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!?ContentHash {
    if (bytes.len == 0) return null;

    const codec = readVarint(bytes) orelse return error.InvalidContentHash;
    const payload = bytes[codec.len..];

    return switch (codec.value) {
        IPFS_NS => try decodeIpfs(allocator, payload),
        IPNS_NS => try decodeIpns(allocator, payload),
        SWARM_NS => try decodeSwarm(allocator, payload),
        else => error.UnsupportedProtocol,
    };
}

/// Result of decoding a single unsigned LEB128 varint.
const Varint = struct { value: u64, len: usize };

/// Decode an unsigned LEB128 varint from the front of `bytes`. Returns null on
/// truncated input or on a value wider than 64 bits.
fn readVarint(bytes: []const u8) ?Varint {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (bytes, 0..) |b, i| {
        value |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return .{ .value = value, .len = i + 1 };
        if (shift >= 63) return null;
        shift += 7;
    }
    return null;
}

/// Build an owned URI string `scheme ++ body`.
fn buildUri(allocator: std.mem.Allocator, scheme: []const u8, body: []const u8) DecodeError![]u8 {
    const uri = try allocator.alloc(u8, scheme.len + body.len);
    @memcpy(uri[0..scheme.len], scheme);
    @memcpy(uri[scheme.len..], body);
    return uri;
}

/// Decode an ipfs-ns CID. A dag-pb (0x70) CIDv1 with a sha2-256 multihash, or a
/// raw CIDv0 multihash, is rendered as a base58btc CIDv0 (`Qm...`, the EIP-1577
/// canonical form). Any other CID is rendered as a base32 lowercase CIDv1
/// (`b...`).
fn decodeIpfs(allocator: std.mem.Allocator, payload: []const u8) DecodeError!?ContentHash {
    // Raw CIDv0 multihash: sha2-256 (0x12) + length 32 (0x20) + 32-byte digest.
    if (payload.len == 34 and payload[0] == 0x12 and payload[1] == 0x20) {
        const body = try baseNEncode(allocator, base58_alphabet, payload);
        defer allocator.free(body);
        return .{ .protocol = .ipfs, .uri = try buildUri(allocator, "ipfs://", body) };
    }

    const version = readVarint(payload) orelse return error.InvalidContentHash;
    if (version.value == 1) {
        const after_version = payload[version.len..];
        const codec = readVarint(after_version) orelse return error.InvalidContentHash;
        const multihash = after_version[codec.len..];
        if (codec.value == 0x70 and multihash.len == 34 and multihash[0] == 0x12 and multihash[1] == 0x20) {
            const body = try baseNEncode(allocator, base58_alphabet, multihash);
            defer allocator.free(body);
            return .{ .protocol = .ipfs, .uri = try buildUri(allocator, "ipfs://", body) };
        }
    }

    // CIDv1 in base32: multibase prefix 'b' + base32(cid bytes).
    const b32 = try base32LowerEncode(allocator, payload);
    defer allocator.free(b32);
    const uri = try allocator.alloc(u8, "ipfs://b".len + b32.len);
    @memcpy(uri[0.."ipfs://b".len], "ipfs://b");
    @memcpy(uri["ipfs://b".len..], b32);
    return .{ .protocol = .ipfs, .uri = uri };
}

/// Decode an ipns-ns CID as a base36 lowercase CIDv1 (`k...`).
fn decodeIpns(allocator: std.mem.Allocator, payload: []const u8) DecodeError!?ContentHash {
    const b36 = try baseNEncode(allocator, base36_alphabet, payload);
    defer allocator.free(b36);
    // multibase prefix 'k' + base36(cid bytes).
    const uri = try allocator.alloc(u8, "ipns://k".len + b36.len);
    @memcpy(uri[0.."ipns://k".len], "ipns://k");
    @memcpy(uri["ipns://k".len..], b36);
    return .{ .protocol = .ipns, .uri = uri };
}

/// Decode a swarm-ns CID: extract the multihash digest and hex-encode it as a
/// `bzz://<64 hex chars>` URI.
fn decodeSwarm(allocator: std.mem.Allocator, payload: []const u8) DecodeError!?ContentHash {
    const version = readVarint(payload) orelse return error.InvalidContentHash;
    if (version.value != 1) return error.InvalidContentHash;
    const after_version = payload[version.len..];
    const codec = readVarint(after_version) orelse return error.InvalidContentHash;
    const multihash = after_version[codec.len..];
    // multihash: <hash-fn varint><length varint><digest>.
    const hash_fn = readVarint(multihash) orelse return error.InvalidContentHash;
    const after_fn = multihash[hash_fn.len..];
    const length = readVarint(after_fn) orelse return error.InvalidContentHash;
    const digest = after_fn[length.len..];
    if (digest.len < length.value) return error.InvalidContentHash;
    const digest32 = digest[0..@intCast(length.value)];

    const hex_chars = "0123456789abcdef";
    const uri = try allocator.alloc(u8, "bzz://".len + digest32.len * 2);
    @memcpy(uri[0.."bzz://".len], "bzz://");
    for (digest32, 0..) |byte, i| {
        uri["bzz://".len + i * 2] = hex_chars[byte >> 4];
        uri["bzz://".len + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return .{ .protocol = .swarm, .uri = uri };
}

// ============================================================================
// Base encoding primitives
// ============================================================================

/// Bitcoin base58btc alphabet (used for CIDv0 / `Qm...` IPFS identifiers).
const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// base36 lowercase alphabet (used for `k...` IPNS libp2p-key CIDv1 identifiers).
const base36_alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
/// RFC4648 base32 lowercase alphabet (used for `b...` CIDv1 identifiers).
const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";

/// Encode a big-endian byte array into an arbitrary base using repeated
/// big-number division (the classic base58 algorithm). Leading zero bytes are
/// preserved as leading `alphabet[0]` characters, per the base58/base36
/// multibase convention. Caller owns the returned slice.
fn baseNEncode(allocator: std.mem.Allocator, alphabet: []const u8, bytes: []const u8) DecodeError![]u8 {
    const base: u32 = @intCast(alphabet.len);

    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) : (zeros += 1) {}

    // ceil(log(256)/log(base)) < 2 for base >= 16, so len*2+1 bytes is ample.
    const cap = bytes.len * 2 + 1;
    const buf = try allocator.alloc(u8, cap);
    defer allocator.free(buf);
    @memset(buf, 0);

    var length: usize = 0;
    for (bytes[zeros..]) |byte| {
        var carry: u32 = byte;
        var i: usize = 0;
        var k: usize = cap;
        while (k > 0) {
            k -= 1;
            if (i >= length and carry == 0) break;
            carry += @as(u32, buf[k]) * 256;
            buf[k] = @intCast(carry % base);
            carry /= base;
            i += 1;
        }
        length = i;
    }

    const result = try allocator.alloc(u8, zeros + length);
    errdefer allocator.free(result);
    @memset(result[0..zeros], alphabet[0]);
    var j: usize = zeros;
    var m: usize = cap - length;
    while (m < cap) : (m += 1) {
        result[j] = alphabet[buf[m]];
        j += 1;
    }
    return result;
}

/// RFC4648 base32 lowercase encode with no padding. Caller owns the result.
fn base32LowerEncode(allocator: std.mem.Allocator, data: []const u8) DecodeError![]u8 {
    const out_len = (data.len * 8 + 4) / 5;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var acc: u32 = 0;
    var nbits: usize = 0;
    var oi: usize = 0;
    for (data) |byte| {
        acc = (acc << 8) | byte;
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            const idx: usize = @intCast((acc >> @intCast(nbits)) & 0x1f);
            out[oi] = base32_alphabet[idx];
            oi += 1;
        }
    }
    if (nbits > 0) {
        const idx: usize = @intCast((acc << @intCast(5 - nbits)) & 0x1f);
        out[oi] = base32_alphabet[idx];
        oi += 1;
    }
    return out[0..oi];
}

// ============================================================================
// Tests
// ============================================================================

/// Decode a hex string (no `0x`) into a freshly allocated byte slice.
fn hexAlloc(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(buf);
    for (buf, 0..) |*b, i| {
        const hi = try std.fmt.charToDigit(hex_str[i * 2], 16);
        const lo = try std.fmt.charToDigit(hex_str[i * 2 + 1], 16);
        b.* = (hi << 4) | lo;
    }
    return buf;
}

test "contenthash decodes ipfs CIDv0" {
    const allocator = std.testing.allocator;
    // EIP-1577 example: ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4
    const bytes_hex = "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f";
    const raw = try hexAlloc(allocator, bytes_hex);
    defer allocator.free(raw);
    var ch = (try decode(allocator, raw)).?;
    defer ch.deinit(allocator);
    try std.testing.expectEqual(Protocol.ipfs, ch.protocol);
    try std.testing.expectEqualStrings("ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", ch.uri);
}

test "contenthash decodes ipns ED25519 libp2p-key" {
    const allocator = std.testing.allocator;
    // Source: @ensdomains/content-hash src/index.test.ts
    //   ipns_ED25519_contentHash -> ipns_libp2pKey_CIDv1
    const bytes_hex = "e50101720024080112205cbd1cc86ac20d6640795809c2a185bb2504538a2de8076da5a6971b8acb4715";
    const raw = try hexAlloc(allocator, bytes_hex);
    defer allocator.free(raw);
    var ch = (try decode(allocator, raw)).?;
    defer ch.deinit(allocator);
    try std.testing.expectEqual(Protocol.ipns, ch.protocol);
    try std.testing.expectEqualStrings("ipns://k51qzi5uqu5dihst24f3rp2ej4co9berxohfkxaenbq1wjty7nrd5e9xp4afx1", ch.uri);
}

test "contenthash decodes swarm bzz" {
    const allocator = std.testing.allocator;
    // Source: @ensdomains/content-hash src/index.test.ts (swarm_contentHash -> swarm)
    // and the EIP-1577 swarm example.
    const bytes_hex = "e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    const raw = try hexAlloc(allocator, bytes_hex);
    defer allocator.free(raw);
    var ch = (try decode(allocator, raw)).?;
    defer ch.deinit(allocator);
    try std.testing.expectEqual(Protocol.swarm, ch.protocol);
    try std.testing.expectEqualStrings("bzz://d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162", ch.uri);
}

test "contenthash empty input is null" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(?ContentHash, null), try decode(allocator, ""));
}

test "contenthash unknown multicodec is UnsupportedProtocol" {
    const allocator = std.testing.allocator;
    // onion-ns (0x01bc) is a valid multicodec but not supported here.
    const raw = try hexAlloc(allocator, "bc037a716b746c776934666563766f367269");
    defer allocator.free(raw);
    try std.testing.expectError(error.UnsupportedProtocol, decode(allocator, raw));
}

test "base32 lower encodes CIDv1 (multiformats vector)" {
    const allocator = std.testing.allocator;
    // base32-lower of the CIDv1 bytes 01 70 12 20 <sha2-256 digest> ==
    //   bafybeibj6lixxzqtsb45ysdjnupvqkufgdvzqbnvmhw2kf7cfkesy7r7d4
    // Source: @ensdomains/content-hash src/index.test.ts (ipfs_CIDv1).
    const cid = try hexAlloc(allocator, "0170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f");
    defer allocator.free(cid);
    const out = try base32LowerEncode(allocator, cid);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("afybeibj6lixxzqtsb45ysdjnupvqkufgdvzqbnvmhw2kf7cfkesy7r7d4", out);
}

test "base58btc encodes CIDv0 multihash (multiformats vector)" {
    const allocator = std.testing.allocator;
    const mh = try hexAlloc(allocator, "122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f");
    defer allocator.free(mh);
    const out = try baseNEncode(allocator, base58_alphabet, mh);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", out);
}

test "baseN preserves leading zero bytes" {
    const allocator = std.testing.allocator;
    const input = [_]u8{ 0x00, 0x00, 0x01 };
    const out = try baseNEncode(allocator, base58_alphabet, &input);
    defer allocator.free(out);
    // Two leading zero bytes -> two leading '1' (base58 alphabet[0]); 0x01 -> '2'.
    try std.testing.expectEqualStrings("112", out);
}
