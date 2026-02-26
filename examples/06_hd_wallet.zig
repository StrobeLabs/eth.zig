// Example 06: HD wallet derivation from mnemonic
//
// Pure compute -- no RPC connection needed.
// Derives multiple Ethereum addresses from a BIP-39 mnemonic.

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    // Standard test mnemonic (DO NOT use in production)
    const words = [_][]const u8{
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "about",
    };

    // Convert mnemonic to seed
    const seed = try eth.mnemonic.toSeed(&words, "");

    try stdout.print("Mnemonic: abandon abandon ... about\n\n", .{});
    try stdout.print("Derived accounts (BIP-44: m/44'/60'/0'/0/i):\n", .{});

    // Derive first 5 accounts
    for (0..5) |i| {
        const key = try eth.hd_wallet.deriveEthAccount(seed, @intCast(i));
        const addr = key.toAddress();
        const checksum = eth.primitives.addressToChecksum(&addr);
        try stdout.print("  [{d}] {s}\n", .{ i, checksum });
    }
    try stdout.flush();
}
