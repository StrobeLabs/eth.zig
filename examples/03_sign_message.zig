// Example 03: Sign a message with EIP-191 personal message prefix
//
// Pure compute -- no RPC connection needed.

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    // Hardhat/Anvil account #0 private key
    const private_key = try eth.hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const signer = eth.signer.Signer.init(private_key);
    const addr = try signer.address();
    const checksum = eth.primitives.addressToChecksum(&addr);

    // Sign a personal message (EIP-191)
    const message = "Hello, Ethereum!";
    const sig = try signer.signMessage(message);

    try stdout.print("Signer:  {s}\n", .{checksum});
    try stdout.print("Message: \"{s}\"\n", .{message});
    try stdout.print("v: {d}\n", .{sig.v});
    try stdout.print("r: ", .{});
    for (sig.r) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\ns: ", .{});
    for (sig.s) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n", .{});
    try stdout.flush();
}
