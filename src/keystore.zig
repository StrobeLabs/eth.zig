const std = @import("std");
const keccak = @import("keccak.zig");
const hex = @import("hex.zig");
const runtime = @import("runtime.zig");
const secureZero = @import("utils/constants.zig").secureZero;

/// Web3 Secret Storage Definition v3 (encrypted JSON keystore).
///
/// This is the on-disk format used by geth, ethers.js, foundry/cast, and
/// MyEtherWallet to store a 32-byte secp256k1 private key encrypted with a
/// user password. See:
/// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
///
/// Supported KDFs: `scrypt` and `pbkdf2` (HMAC-SHA256).
/// Supported cipher: `aes-128-ctr`.
/// MAC: keccak256(derived_key[16..32] ++ ciphertext), verified in constant time.
pub const KeystoreError = error{
    /// The supplied password produced a MAC that does not match the keystore.
    InvalidPassword,
    /// The JSON is not a valid v3 keystore (wrong version, missing fields, ...).
    InvalidKeystore,
    /// The keystore uses a KDF this implementation does not support.
    UnsupportedKdf,
    /// The keystore uses a cipher this implementation does not support.
    UnsupportedCipher,
};

/// Key derivation function selection for `encrypt`.
pub const Kdf = enum {
    scrypt,
    pbkdf2,
};

/// Options for `encrypt`.
///
/// The defaults match what geth/ethers produce: scrypt with n=2^18 (262144),
/// r=8, p=1 and the `aes-128-ctr` cipher. Tests should override `scrypt_n`
/// with a small value (e.g. 4096 / `scrypt_log_n = 12`) so they run quickly.
pub const EncryptOptions = struct {
    kdf: Kdf = .scrypt,

    // -- scrypt parameters --
    /// log2(N). Default 18 => N = 262144 (the geth/ethers "standard" cost).
    /// For tests use 12 (N = 4096) for speed.
    scrypt_log_n: u6 = 18,
    scrypt_r: u30 = 8,
    scrypt_p: u30 = 1,

    // -- pbkdf2 parameters (only used when kdf == .pbkdf2) --
    /// Iteration count for PBKDF2-HMAC-SHA256.
    pbkdf2_c: u32 = 262144,
};

const dklen: usize = 32;
const salt_len: usize = 32;
const iv_len: usize = 16;

/// Decrypt a v3 keystore JSON document and recover the 32-byte private key.
///
/// Returns `error.InvalidPassword` if the MAC does not match (wrong password or
/// corrupted file). The MAC comparison is constant time.
pub fn decrypt(allocator: std.mem.Allocator, json: []const u8, password: []const u8) ![32]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch {
        return KeystoreError.InvalidKeystore;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return KeystoreError.InvalidKeystore;
    const root = parsed.value.object;

    // version must be 3
    const version = root.get("version") orelse return KeystoreError.InvalidKeystore;
    const version_ok = switch (version) {
        .integer => |i| i == 3,
        .float => |f| f == 3.0,
        else => false,
    };
    if (!version_ok) return KeystoreError.InvalidKeystore;

    const crypto_val = root.get("crypto") orelse root.get("Crypto") orelse
        return KeystoreError.InvalidKeystore;
    if (crypto_val != .object) return KeystoreError.InvalidKeystore;
    const crypto = crypto_val.object;

    // -- cipher --
    const cipher = jsonStr(crypto, "cipher") orelse return KeystoreError.InvalidKeystore;
    if (!std.mem.eql(u8, cipher, "aes-128-ctr")) return KeystoreError.UnsupportedCipher;

    const cipherparams_val = crypto.get("cipherparams") orelse return KeystoreError.InvalidKeystore;
    if (cipherparams_val != .object) return KeystoreError.InvalidKeystore;
    const cipherparams = cipherparams_val.object;
    const iv_hex = jsonStr(cipherparams, "iv") orelse return KeystoreError.InvalidKeystore;
    const iv = hex.hexToBytesFixed(iv_len, iv_hex) catch return KeystoreError.InvalidKeystore;

    // -- ciphertext --
    const ciphertext_hex = jsonStr(crypto, "ciphertext") orelse return KeystoreError.InvalidKeystore;
    if (ciphertext_hex.len % 2 != 0) return KeystoreError.InvalidKeystore;
    const ciphertext = try allocator.alloc(u8, ciphertext_hex.len / 2);
    defer allocator.free(ciphertext);
    _ = hex.hexToBytes(ciphertext, ciphertext_hex) catch return KeystoreError.InvalidKeystore;

    // -- kdf -> derived key --
    const kdf = jsonStr(crypto, "kdf") orelse return KeystoreError.InvalidKeystore;
    const kdfparams_val = crypto.get("kdfparams") orelse return KeystoreError.InvalidKeystore;
    if (kdfparams_val != .object) return KeystoreError.InvalidKeystore;
    const kdfparams = kdfparams_val.object;

    var derived_key: [dklen]u8 = undefined;
    defer secureZero(&derived_key);

    if (std.mem.eql(u8, kdf, "scrypt")) {
        try deriveScrypt(allocator, &derived_key, password, kdfparams);
    } else if (std.mem.eql(u8, kdf, "pbkdf2")) {
        try derivePbkdf2(&derived_key, password, kdfparams);
    } else {
        return KeystoreError.UnsupportedKdf;
    }

    // -- MAC check: keccak256(derived_key[16..32] ++ ciphertext), constant time --
    const expected_mac_hex = jsonStr(crypto, "mac") orelse return KeystoreError.InvalidKeystore;
    const expected_mac = hex.hexToBytesFixed(32, expected_mac_hex) catch
        return KeystoreError.InvalidKeystore;

    const computed_mac = computeMac(derived_key, ciphertext);
    if (!std.crypto.timing_safe.eql([32]u8, computed_mac, expected_mac)) {
        return KeystoreError.InvalidPassword;
    }

    // -- decrypt: AES-128-CTR with derived_key[0..16] --
    if (ciphertext.len != 32) return KeystoreError.InvalidKeystore;
    var key_out: [32]u8 = undefined;
    aes128Ctr(derived_key[0..16].*, iv, key_out[0..ciphertext.len], ciphertext);
    return key_out;
}

/// Encrypt a 32-byte private key into a v3 keystore JSON document.
///
/// The caller owns the returned slice. Defaults to scrypt (N=2^18) + aes-128-ctr.
pub fn encrypt(
    allocator: std.mem.Allocator,
    key: [32]u8,
    password: []const u8,
    io: std.Io,
    opts: EncryptOptions,
) ![]u8 {
    // Random salt and IV via the caller's Io (std.crypto.random was removed in 0.16).
    var salt: [salt_len]u8 = undefined;
    var iv: [iv_len]u8 = undefined;
    io.random(&salt);
    io.random(&iv);

    var derived_key: [dklen]u8 = undefined;
    defer secureZero(&derived_key);

    switch (opts.kdf) {
        .scrypt => try std.crypto.pwhash.scrypt.kdf(
            allocator,
            &derived_key,
            password,
            &salt,
            .{ .ln = opts.scrypt_log_n, .r = opts.scrypt_r, .p = opts.scrypt_p },
        ),
        .pbkdf2 => try std.crypto.pwhash.pbkdf2(
            &derived_key,
            password,
            &salt,
            opts.pbkdf2_c,
            std.crypto.auth.hmac.sha2.HmacSha256,
        ),
    }

    // Encrypt the key: AES-128-CTR with derived_key[0..16].
    var ciphertext: [32]u8 = undefined;
    defer secureZero(&ciphertext);
    {
        var key_copy = key;
        defer secureZero(&key_copy);
        aes128Ctr(derived_key[0..16].*, iv, &ciphertext, &key_copy);
    }

    // MAC = keccak256(derived_key[16..32] ++ ciphertext).
    const mac = computeMac(derived_key, &ciphertext);

    // Random UUID (v4) for the keystore id.
    var uuid_bytes: [16]u8 = undefined;
    io.random(&uuid_bytes);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; // version 4
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // variant 1

    // Build the JSON document manually (small, fixed schema).
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"version\":3,\"id\":\"");
    try appendUuid(&out, allocator, uuid_bytes);
    try out.appendSlice(allocator, "\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"");
    try appendHexLower(&out, allocator, &iv);
    try out.appendSlice(allocator, "\"},\"ciphertext\":\"");
    try appendHexLower(&out, allocator, &ciphertext);
    try out.appendSlice(allocator, "\",\"kdf\":\"");

    switch (opts.kdf) {
        .scrypt => {
            const n: u64 = @as(u64, 1) << opts.scrypt_log_n;
            try out.print(allocator, "scrypt\",\"kdfparams\":{{\"dklen\":{d},\"n\":{d},\"p\":{d},\"r\":{d},\"salt\":\"", .{
                dklen, n, opts.scrypt_p, opts.scrypt_r,
            });
            try appendHexLower(&out, allocator, &salt);
            try out.appendSlice(allocator, "\"}");
        },
        .pbkdf2 => {
            try out.print(allocator, "pbkdf2\",\"kdfparams\":{{\"c\":{d},\"dklen\":{d},\"prf\":\"hmac-sha256\",\"salt\":\"", .{
                opts.pbkdf2_c, dklen,
            });
            try appendHexLower(&out, allocator, &salt);
            try out.appendSlice(allocator, "\"}");
        },
    }

    try out.appendSlice(allocator, ",\"mac\":\"");
    try appendHexLower(&out, allocator, &mac);
    try out.appendSlice(allocator, "\"}}");

    return out.toOwnedSlice(allocator);
}

// -- internals --

/// MAC = keccak256(derived_key[16..32] ++ ciphertext).
fn computeMac(derived_key: [dklen]u8, ciphertext: []const u8) [32]u8 {
    return keccak.hashConcat(&.{ derived_key[16..32], ciphertext });
}

/// AES-128 in CTR mode (big-endian counter, per the Web3 spec).
fn aes128Ctr(key: [16]u8, iv: [16]u8, dst: []u8, src: []const u8) void {
    const aes = std.crypto.core.aes.Aes128.initEnc(key);
    std.crypto.core.modes.ctr(@TypeOf(aes), aes, dst, src, iv, .big);
}

fn deriveScrypt(
    allocator: std.mem.Allocator,
    derived_key: *[dklen]u8,
    password: []const u8,
    kdfparams: std.json.ObjectMap,
) !void {
    const n = jsonU64(kdfparams, "n") orelse return KeystoreError.InvalidKeystore;
    const r = jsonU64(kdfparams, "r") orelse return KeystoreError.InvalidKeystore;
    const p = jsonU64(kdfparams, "p") orelse return KeystoreError.InvalidKeystore;
    const dk = jsonU64(kdfparams, "dklen") orelse return KeystoreError.InvalidKeystore;
    const salt_hex = jsonStr(kdfparams, "salt") orelse return KeystoreError.InvalidKeystore;

    if (dk != dklen) return KeystoreError.InvalidKeystore;
    if (n < 2 or (n & (n - 1)) != 0) return KeystoreError.InvalidKeystore; // power of two
    const ln: u6 = @intCast(std.math.log2_int(u64, n));
    if (r == 0 or r > std.math.maxInt(u30)) return KeystoreError.InvalidKeystore;
    if (p == 0 or p > std.math.maxInt(u30)) return KeystoreError.InvalidKeystore;

    var salt_buf: [256]u8 = undefined;
    const salt = hex.hexToBytes(&salt_buf, salt_hex) catch return KeystoreError.InvalidKeystore;

    std.crypto.pwhash.scrypt.kdf(allocator, derived_key, password, salt, .{
        .ln = ln,
        .r = @intCast(r),
        .p = @intCast(p),
    }) catch return KeystoreError.InvalidKeystore;
}

fn derivePbkdf2(
    derived_key: *[dklen]u8,
    password: []const u8,
    kdfparams: std.json.ObjectMap,
) !void {
    const c = jsonU64(kdfparams, "c") orelse return KeystoreError.InvalidKeystore;
    const dk = jsonU64(kdfparams, "dklen") orelse return KeystoreError.InvalidKeystore;
    const salt_hex = jsonStr(kdfparams, "salt") orelse return KeystoreError.InvalidKeystore;

    if (dk != dklen) return KeystoreError.InvalidKeystore;
    if (c == 0 or c > std.math.maxInt(u32)) return KeystoreError.InvalidKeystore;

    // Only HMAC-SHA256 PRF is defined by the spec.
    if (jsonStr(kdfparams, "prf")) |prf| {
        if (!std.mem.eql(u8, prf, "hmac-sha256")) return KeystoreError.UnsupportedKdf;
    }

    var salt_buf: [256]u8 = undefined;
    const salt = hex.hexToBytes(&salt_buf, salt_hex) catch return KeystoreError.InvalidKeystore;

    std.crypto.pwhash.pbkdf2(
        derived_key,
        password,
        salt,
        @intCast(c),
        std.crypto.auth.hmac.sha2.HmacSha256,
    ) catch return KeystoreError.InvalidKeystore;
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| if (i < 0) null else @intCast(i),
        .float => |f| if (f < 0 or f != @floor(f)) null else @intFromFloat(f),
        // Numbers larger than i64 are parsed as number_string.
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        .string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

const hex_chars = "0123456789abcdef";

fn appendHexLower(out: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    for (bytes) |b| {
        try out.append(allocator, hex_chars[b >> 4]);
        try out.append(allocator, hex_chars[b & 0x0f]);
    }
}

fn appendUuid(out: *std.ArrayList(u8), allocator: std.mem.Allocator, b: [16]u8) !void {
    // 8-4-4-4-12
    try appendHexLower(out, allocator, b[0..4]);
    try out.append(allocator, '-');
    try appendHexLower(out, allocator, b[4..6]);
    try out.append(allocator, '-');
    try appendHexLower(out, allocator, b[6..8]);
    try out.append(allocator, '-');
    try appendHexLower(out, allocator, b[8..10]);
    try out.append(allocator, '-');
    try appendHexLower(out, allocator, b[10..16]);
}

// -- tests --

const testing = std.testing;

// Light scrypt params so the round-trip tests run fast (N = 4096).
const test_opts: EncryptOptions = .{ .kdf = .scrypt, .scrypt_log_n = 12, .scrypt_r = 8, .scrypt_p = 1 };

test "round-trip scrypt" {
    const allocator = testing.allocator;
    const key = try hex.hexToBytesFixed(32, "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");

    const json = try encrypt(allocator, key, "testpassword", runtime.blockingIo(), test_opts);
    defer allocator.free(json);

    const recovered = try decrypt(allocator, json, "testpassword");
    try testing.expectEqualSlices(u8, &key, &recovered);
}

test "round-trip pbkdf2" {
    const allocator = testing.allocator;
    const key = try hex.hexToBytesFixed(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    const json = try encrypt(allocator, key, "hunter2", runtime.blockingIo(), .{ .kdf = .pbkdf2, .pbkdf2_c = 4096 });
    defer allocator.free(json);

    const recovered = try decrypt(allocator, json, "hunter2");
    try testing.expectEqualSlices(u8, &key, &recovered);
}

test "round-trip multiple keys" {
    const allocator = testing.allocator;
    const keys = [_][]const u8{
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "4646464646464646464646464646464646464646464646464646464646464646",
    };
    for (keys) |kh| {
        const key = try hex.hexToBytesFixed(32, kh);
        const json = try encrypt(allocator, key, "pw", runtime.blockingIo(), test_opts);
        defer allocator.free(json);
        const recovered = try decrypt(allocator, json, "pw");
        try testing.expectEqualSlices(u8, &key, &recovered);
    }
}

test "wrong password returns InvalidPassword" {
    const allocator = testing.allocator;
    const key = try hex.hexToBytesFixed(32, "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");

    const json = try encrypt(allocator, key, "correct horse", runtime.blockingIo(), test_opts);
    defer allocator.free(json);

    try testing.expectError(KeystoreError.InvalidPassword, decrypt(allocator, json, "wrong horse"));
}

// Canonical Web3 Secret Storage Definition test vectors.
// Both decrypt to private key 7a28b5ba...fe9d with password "testpassword".
// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
const canonical_key_hex = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";

const canonical_scrypt_json =
    \\{
    \\    "crypto" : {
    \\        "cipher" : "aes-128-ctr",
    \\        "cipherparams" : {
    \\            "iv" : "83dbcc02d8ccb40e466191a123791e0e"
    \\        },
    \\        "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
    \\        "kdf" : "scrypt",
    \\        "kdfparams" : {
    \\            "dklen" : 32,
    \\            "n" : 262144,
    \\            "r" : 1,
    \\            "p" : 8,
    \\            "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
    \\        },
    \\        "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
    \\    },
    \\    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    \\    "version" : 3
    \\}
;

const canonical_pbkdf2_json =
    \\{
    \\    "crypto" : {
    \\        "cipher" : "aes-128-ctr",
    \\        "cipherparams" : {
    \\            "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
    \\        },
    \\        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
    \\        "kdf" : "pbkdf2",
    \\        "kdfparams" : {
    \\            "c" : 262144,
    \\            "dklen" : 32,
    \\            "prf" : "hmac-sha256",
    \\            "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
    \\        },
    \\        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    \\    },
    \\    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    \\    "version" : 3
    \\}
;

test "canonical scrypt vector decrypts" {
    const allocator = testing.allocator;
    const expected = try hex.hexToBytesFixed(32, canonical_key_hex);
    const recovered = try decrypt(allocator, canonical_scrypt_json, "testpassword");
    try testing.expectEqualSlices(u8, &expected, &recovered);
}

test "canonical pbkdf2 vector decrypts" {
    const allocator = testing.allocator;
    const expected = try hex.hexToBytesFixed(32, canonical_key_hex);
    const recovered = try decrypt(allocator, canonical_pbkdf2_json, "testpassword");
    try testing.expectEqualSlices(u8, &expected, &recovered);
}

test "canonical vector wrong password" {
    const allocator = testing.allocator;
    try testing.expectError(
        KeystoreError.InvalidPassword,
        decrypt(allocator, canonical_pbkdf2_json, "notthepassword"),
    );
}

test "rejects non-v3 keystore" {
    const allocator = testing.allocator;
    const json = "{\"version\":1,\"crypto\":{}}";
    try testing.expectError(KeystoreError.InvalidKeystore, decrypt(allocator, json, "x"));
}

test "rejects unsupported cipher" {
    const allocator = testing.allocator;
    const json =
        \\{"version":3,"crypto":{"cipher":"aes-256-cbc","cipherparams":{"iv":"00000000000000000000000000000000"},"ciphertext":"00","kdf":"scrypt","kdfparams":{},"mac":"00"}}
    ;
    try testing.expectError(KeystoreError.UnsupportedCipher, decrypt(allocator, json, "x"));
}

test "refAllDecls" {
    testing.refAllDecls(@This());
}
