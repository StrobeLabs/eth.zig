const std = @import("std");
const hd_wallet = @import("hd_wallet.zig");
const mnemonic = @import("mnemonic.zig");
const ripemd160 = @import("ripemd160.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Secp256k1 = std.crypto.ecc.Secp256k1;

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn hash160(compressed: *const [33]u8) [20]u8 {
    var sha: [32]u8 = undefined;
    Sha256.hash(compressed, &sha, .{});
    var out: [20]u8 = undefined;
    ripemd160.hash(&sha, &out);
    return out;
}

fn bech32Polymod(values: []const u8) u32 {
    const gen = [_]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |v| {
        const top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        for (gen, 0..) |g, i| {
            if ((top >> @intCast(i)) & 1 == 1) chk ^= g;
        }
    }
    return chk;
}

fn encodeP2wpkh(prog: *const [20]u8) [42]u8 {
    var data5: [33]u8 = undefined;
    data5[0] = 0;
    var acc: u32 = 0;
    var bits: u32 = 0;
    var n: usize = 1;
    for (prog) |b| {
        acc = acc << 8 | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data5[n] = @truncate(acc >> @intCast(bits) & 31);
            n += 1;
        }
    }
    if (bits > 0) {
        data5[n] = @truncate(acc << @intCast(5 - bits) & 31);
        n += 1;
    }

    var values: [44]u8 = undefined;
    values[0] = 'b' >> 5;
    values[1] = 'c' >> 5;
    values[2] = 0;
    values[3] = 'b' & 31;
    values[4] = 'c' & 31;
    @memcpy(values[5 .. 5 + n], data5[0..n]);
    @memset(values[5 + n .. 5 + n + 6], 0);
    const pc = bech32Polymod(values[0 .. 5 + n + 6]) ^ 1;

    var out: [42]u8 = undefined;
    out[0] = 'b';
    out[1] = 'c';
    out[2] = '1';
    for (0..n) |i| out[3 + i] = CHARSET[data5[i]];
    for (0..6) |i| out[3 + n + i] = CHARSET[(pc >> @intCast(5 * (5 - i))) & 31];
    return out;
}

/// BIP-84 native segwit P2WPKH (`bc1q…`) at `m/84'/0'/0'/0/{index}`.
pub fn p2wpkh(seed: [64]u8, index: u32) ![42]u8 {
    const key = try hd_wallet.deriveBtcAccount(seed, index);
    const point = Secp256k1.basePoint.mul(key.key, .big) catch return error.DerivationFailed;
    const pk = point.toCompressedSec1();
    const prog = hash160(&pk);
    return encodeP2wpkh(&prog);
}

test "bip84 p2wpkh abandon index 0" {
    const words = [_][]const u8{
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "about",
    };
    const seed = try mnemonic.toSeed(&words, "");
    const addr = try p2wpkh(seed, 0);
    try std.testing.expectEqualStrings(
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        &addr,
    );
}
