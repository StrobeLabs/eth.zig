const std = @import("std");
const mnemonic = @import("mnemonic.zig");

const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const Ed25519 = std.crypto.sign.Ed25519;

const HARDENED: u32 = 0x8000_0000;
const PATH_SOL = [_]u32{ 44 | HARDENED, 501 | HARDENED, HARDENED, HARDENED };
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// SLIP-0010 ed25519 child derivation. All indices are hardened.
pub fn slip10(seed: []const u8, path: []const u32) [32]u8 {
    var out: [64]u8 = undefined;
    HmacSha512.create(&out, seed, "ed25519 seed");
    var key = out[0..32].*;
    var chain_code = out[32..64].*;
    for (path) |index| {
        var data: [37]u8 = undefined;
        data[0] = 0;
        data[1..33].* = key;
        std.mem.writeInt(u32, data[33..37], index, .big);
        HmacSha512.create(&out, &data, &chain_code);
        key = out[0..32].*;
        chain_code = out[32..64].*;
    }
    return key;
}

fn b58Encode(bytes: *const [32]u8, dest: *[44]u8) []const u8 {
    var digits: [44]u8 = @splat(0);
    var len: usize = 1;
    for (bytes) |b| {
        var carry: u32 = b;
        var i: usize = 0;
        while (i < len or carry != 0) : (i += 1) {
            carry += 256 * @as(u32, digits[i]);
            digits[i] = @intCast(carry % 58);
            carry /= 58;
            if (i + 1 > len) len = i + 1;
        }
    }
    var zeros: usize = 0;
    while (zeros < 32 and bytes[zeros] == 0) : (zeros += 1) {}
    var n: usize = 0;
    for (0..zeros) |_| {
        dest[n] = '1';
        n += 1;
    }
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        dest[n] = B58[digits[i]];
        n += 1;
    }
    return dest[0..n];
}

/// Solana address at `m/44'/501'/0'/0'` (SLIP-0010 ed25519).
pub fn address(seed: [64]u8, buf: *[44]u8) ![]const u8 {
    const key = slip10(&seed, &PATH_SOL);
    const kp = try Ed25519.KeyPair.generateDeterministic(key);
    return b58Encode(&kp.public_key.toBytes(), buf);
}

test "slip10 spec vector m/0'" {
    const seed = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const key = slip10(&seed, &.{HARDENED});
    try std.testing.expectEqualStrings(
        "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        &std.fmt.bytesToHex(key, .lower),
    );
}

test "solana abandon m/44'/501'/0'/0'" {
    const words = [_][]const u8{
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "about",
    };
    const seed = try mnemonic.toSeed(&words, "");
    var buf: [44]u8 = undefined;
    const addr = try address(seed, &buf);
    try std.testing.expectEqualStrings("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk", addr);
}
