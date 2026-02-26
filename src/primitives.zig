const std = @import("std");
const hex_mod = @import("hex.zig");
const keccak = @import("keccak.zig");

// -- Address --

/// 20-byte Ethereum address.
pub const Address = [20]u8;

/// Zero address (0x0000...0000).
pub const ZERO_ADDRESS: Address = [_]u8{0} ** 20;

/// Parse an address from a hex string (with optional "0x" prefix).
pub fn addressFromHex(hex_str: []const u8) hex_mod.HexError!Address {
    return hex_mod.hexToBytesFixed(20, hex_str);
}

/// Format an address as an EIP-55 checksummed hex string.
/// Returns "0x" + 40 hex chars.
pub fn addressToChecksum(addr: *const Address) [42]u8 {
    const hex_chars_lower = "0123456789abcdef";

    // First pass: produce lowercase hex
    var hex_only: [40]u8 = undefined;
    for (addr, 0..) |byte, i| {
        hex_only[i * 2] = hex_chars_lower[byte >> 4];
        hex_only[i * 2 + 1] = hex_chars_lower[byte & 0x0f];
    }

    // Hash the lowercase hex
    const addr_hash = keccak.hash(&hex_only);

    // Second pass: apply checksum (capitalize if hash nibble >= 8)
    var result: [42]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';

    for (0..40) |i| {
        const hash_byte = addr_hash[i / 2];
        const hash_nibble = if (i % 2 == 0) (hash_byte >> 4) else (hash_byte & 0x0f);

        if (hash_nibble >= 8 and hex_only[i] >= 'a' and hex_only[i] <= 'f') {
            result[2 + i] = hex_only[i] - 32; // uppercase
        } else {
            result[2 + i] = hex_only[i];
        }
    }
    return result;
}

/// Format an address as lowercase hex with "0x" prefix.
pub fn addressToHex(addr: *const Address) [42]u8 {
    var result: [42]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex_chars = "0123456789abcdef";
    for (addr, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Compare two addresses for equality.
pub fn addressEql(a: *const Address, b: *const Address) bool {
    return std.mem.eql(u8, a, b);
}

// -- Hash / Bytes32 --

/// 32-byte hash (Keccak-256 output, transaction hashes, etc.).
pub const Hash = [32]u8;

/// 32-byte value (perp IDs, storage slots, etc.).
pub const Bytes32 = [32]u8;

/// Zero hash.
pub const ZERO_HASH: Hash = [_]u8{0} ** 32;

/// Parse a Hash/Bytes32 from a hex string.
pub fn hashFromHex(hex_str: []const u8) hex_mod.HexError!Hash {
    return hex_mod.hexToBytesFixed(32, hex_str);
}

/// Format a Hash/Bytes32 as hex with "0x" prefix.
pub fn hashToHex(h: *const Hash) [66]u8 {
    return hex_mod.bytesToHexBuf(32, h);
}

/// Compare two hashes for equality.
pub fn hashEql(a: *const Hash, b: *const Hash) bool {
    return std.mem.eql(u8, a, b);
}

// Tests
test "addressFromHex" {
    const addr = try addressFromHex("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    // vitalik.eth
    try std.testing.expectEqual(@as(u8, 0xd8), addr[0]);
    try std.testing.expectEqual(@as(u8, 0x45), addr[19]);
}

test "addressToChecksum - vitalik.eth" {
    const addr = try addressFromHex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const checksum = addressToChecksum(&addr);
    try std.testing.expectEqualStrings("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", &checksum);
}

test "addressToChecksum - all zeros" {
    const checksum = addressToChecksum(&ZERO_ADDRESS);
    try std.testing.expectEqualStrings("0x0000000000000000000000000000000000000000", &checksum);
}

test "addressEql" {
    const a = try addressFromHex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const b = try addressFromHex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const c = ZERO_ADDRESS;
    try std.testing.expect(addressEql(&a, &b));
    try std.testing.expect(!addressEql(&a, &c));
}

test "hashFromHex and hashToHex roundtrip" {
    const hex_str = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const h = try hashFromHex(hex_str);
    const back = hashToHex(&h);
    try std.testing.expectEqualStrings(hex_str, &back);
}

test "ZERO_ADDRESS is 20 zero bytes" {
    for (ZERO_ADDRESS) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "ZERO_HASH is 32 zero bytes" {
    for (ZERO_HASH) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "EIP-55 all lowercase vector" {
    const addr = try addressFromHex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    const checksum = addressToChecksum(&addr);
    try std.testing.expectEqualStrings("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", &checksum);
}

test "EIP-55 all uppercase vector" {
    const addr = try addressFromHex("0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359");
    const checksum = addressToChecksum(&addr);
    try std.testing.expectEqualStrings("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", &checksum);
}

test "EIP-55 mixed case vectors" {
    {
        const addr = try addressFromHex("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
        const checksum = addressToChecksum(&addr);
        try std.testing.expectEqualStrings("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", &checksum);
    }
    {
        const addr = try addressFromHex("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
        const checksum = addressToChecksum(&addr);
        try std.testing.expectEqualStrings("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", &checksum);
    }
}

test "addressFromHex invalid hex error" {
    try std.testing.expectError(error.InvalidHexCharacter, addressFromHex("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"));
}

test "addressFromHex wrong length error" {
    try std.testing.expectError(error.InvalidHexLength, addressFromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"));
}

test "addressToHex all-0xFF roundtrip" {
    const addr: Address = [_]u8{0xFF} ** 20;
    const hex = addressToHex(&addr);
    try std.testing.expectEqualStrings("0xffffffffffffffffffffffffffffffffffffffff", &hex);

    const parsed = try addressFromHex(&hex);
    try std.testing.expect(addressEql(&addr, &parsed));
}
