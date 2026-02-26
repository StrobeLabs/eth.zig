const std = @import("std");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");

/// BIP-32 Hierarchical Deterministic key derivation.
/// Supports BIP-44 Ethereum derivation path: m/44'/60'/0'/0/{index}
pub const HdWalletError = error{
    InvalidSeed,
    InvalidPath,
    InvalidChildIndex,
    DerivationFailed,
};

/// Extended key (private or public) with chain code.
pub const ExtendedKey = struct {
    key: [32]u8, // private key bytes
    chain_code: [32]u8,

    /// Derive the Ethereum address from this private key.
    pub fn toAddress(self: ExtendedKey) [20]u8 {
        // Get public key from private key
        const Secp256k1 = std.crypto.ecc.Secp256k1;
        const privkey_scalar = Secp256k1.scalar.Scalar.fromBytes(self.key, .big) catch return std.mem.zeroes([20]u8);
        const pubkey_point = Secp256k1.basePoint.mul(privkey_scalar.toBytes(.big), .big) catch return std.mem.zeroes([20]u8);
        const pubkey_bytes = pubkey_point.toUncompressedSec1();

        // Address = last 20 bytes of keccak256(pubkey[1..])
        const hash = keccak.hash(pubkey_bytes[1..]);
        var addr: [20]u8 = undefined;
        @memcpy(&addr, hash[12..32]);
        return addr;
    }
};

/// Hardened derivation flag.
pub const HARDENED: u32 = 0x80000000;

/// BIP-44 constants for Ethereum.
pub const ETH_COIN_TYPE: u32 = 60;

const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

/// Derive the master key from a BIP-39 seed.
pub fn masterKeyFromSeed(seed: [64]u8) HdWalletError!ExtendedKey {
    // HMAC-SHA512 with key "Bitcoin seed"
    var mac: [64]u8 = undefined;
    HmacSha512.create(&mac, &seed, "Bitcoin seed");

    const key = mac[0..32].*;
    const chain_code = mac[32..64].*;

    // Validate key is valid (non-zero, less than curve order)
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    _ = Secp256k1.scalar.Scalar.fromBytes(key, .big) catch return error.InvalidSeed;

    return .{ .key = key, .chain_code = chain_code };
}

/// Derive a child key at the given index.
/// Use index | HARDENED for hardened derivation.
pub fn deriveChild(parent: ExtendedKey, index: u32) HdWalletError!ExtendedKey {
    var data: [37]u8 = undefined;

    if (index >= HARDENED) {
        // Hardened: 0x00 || private_key || index
        data[0] = 0;
        @memcpy(data[1..33], &parent.key);
    } else {
        // Normal: public_key_compressed || index
        const Secp256k1 = std.crypto.ecc.Secp256k1;
        const privkey_scalar = Secp256k1.scalar.Scalar.fromBytes(parent.key, .big) catch return error.DerivationFailed;
        const pubkey_point = Secp256k1.basePoint.mul(privkey_scalar.toBytes(.big), .big) catch return error.DerivationFailed;
        const compressed = pubkey_point.toCompressedSec1();
        @memcpy(data[0..33], &compressed);
    }

    // Append index as big-endian u32
    std.mem.writeInt(u32, data[33..37], index, .big);

    // HMAC-SHA512
    var mac: [64]u8 = undefined;
    HmacSha512.create(&mac, &data, &parent.chain_code);

    const il = mac[0..32].*;
    const ir = mac[32..64].*;

    // child_key = (il + parent_key) mod n
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const il_scalar = Secp256k1.scalar.Scalar.fromBytes(il, .big) catch return error.DerivationFailed;
    const parent_scalar = Secp256k1.scalar.Scalar.fromBytes(parent.key, .big) catch return error.DerivationFailed;
    const child_scalar = il_scalar.add(parent_scalar);

    if (child_scalar.isZero()) return error.DerivationFailed;

    return .{
        .key = child_scalar.toBytes(.big),
        .chain_code = ir,
    };
}

/// Derive a key from a BIP-32 path string (e.g., "m/44'/60'/0'/0/0").
pub fn derivePath(seed: [64]u8, path: []const u8) HdWalletError!ExtendedKey {
    var key = try masterKeyFromSeed(seed);

    // Skip "m/" prefix
    var remaining = path;
    if (remaining.len >= 2 and remaining[0] == 'm' and remaining[1] == '/') {
        remaining = remaining[2..];
    } else if (remaining.len == 1 and remaining[0] == 'm') {
        return key; // Just "m" = master key
    }

    // Parse each component
    var iter = std.mem.splitScalar(u8, remaining, '/');
    while (iter.next()) |component| {
        if (component.len == 0) continue;

        var is_hardened = false;
        var num_str = component;

        if (component[component.len - 1] == '\'') {
            is_hardened = true;
            num_str = component[0 .. component.len - 1];
        }

        const index = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidPath;
        const child_index = if (is_hardened) index | HARDENED else index;

        key = try deriveChild(key, child_index);
    }

    return key;
}

/// Convenience: derive an Ethereum account key at BIP-44 path m/44'/60'/0'/0/{index}.
pub fn deriveEthAccount(seed: [64]u8, account_index: u32) HdWalletError!ExtendedKey {
    var key = try masterKeyFromSeed(seed);
    key = try deriveChild(key, 44 | HARDENED); // purpose
    key = try deriveChild(key, ETH_COIN_TYPE | HARDENED); // coin type
    key = try deriveChild(key, 0 | HARDENED); // account
    key = try deriveChild(key, 0); // change
    key = try deriveChild(key, account_index); // address index
    return key;
}

// Tests
test "masterKeyFromSeed produces deterministic results" {
    const seed = [_]u8{0x01} ** 64;
    const key1 = try masterKeyFromSeed(seed);
    const key2 = try masterKeyFromSeed(seed);
    try std.testing.expectEqualSlices(u8, &key1.key, &key2.key);
    try std.testing.expectEqualSlices(u8, &key1.chain_code, &key2.chain_code);
}

test "deriveChild produces different keys for different indices" {
    const seed = [_]u8{0x42} ** 64;
    const master = try masterKeyFromSeed(seed);
    const child0 = try deriveChild(master, HARDENED);
    const child1 = try deriveChild(master, 1 | HARDENED);
    try std.testing.expect(!std.mem.eql(u8, &child0.key, &child1.key));
}

test "derivePath m/44'/60'/0'/0/0" {
    const seed = [_]u8{0xab} ** 64;
    const key_path = try derivePath(seed, "m/44'/60'/0'/0/0");
    const key_manual = try deriveEthAccount(seed, 0);
    try std.testing.expectEqualSlices(u8, &key_path.key, &key_manual.key);
}

test "derivePath just m returns master key" {
    const seed = [_]u8{0xcd} ** 64;
    const master = try masterKeyFromSeed(seed);
    const key_m = try derivePath(seed, "m");
    try std.testing.expectEqualSlices(u8, &master.key, &key_m.key);
}

test "toAddress produces 20-byte address" {
    const seed = [_]u8{0xef} ** 64;
    const key = try deriveEthAccount(seed, 0);
    const addr = key.toAddress();
    // Just verify it's not all zeros
    var all_zero = true;
    for (addr) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "different accounts produce different addresses" {
    const seed = [_]u8{0x11} ** 64;
    const key0 = try deriveEthAccount(seed, 0);
    const key1 = try deriveEthAccount(seed, 1);
    const addr0 = key0.toAddress();
    const addr1 = key1.toAddress();
    try std.testing.expect(!std.mem.eql(u8, &addr0, &addr1));
}

test "known BIP-39 mnemonic to address" {
    // "abandon" x 11 + "about" with empty passphrase
    const mnemonic_mod = @import("mnemonic.zig");
    const words = [_][]const u8{
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "about",
    };
    const seed = try mnemonic_mod.toSeed(&words, "");

    const key = try deriveEthAccount(seed, 0);
    const addr = key.toAddress();

    // The address should be deterministic - verify non-zero
    var all_zero = true;
    for (addr) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Verify it matches when derived again
    const key2 = try deriveEthAccount(seed, 0);
    const addr2 = key2.toAddress();
    try std.testing.expectEqualSlices(u8, &addr, &addr2);
}
