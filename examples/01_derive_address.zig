// Example 01: Derive an Ethereum address from a private key
//
// Pure compute -- no RPC connection needed.

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    // Hardhat/Anvil account #0 private key (DO NOT use in production)
    const private_key = try eth.hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // Create a signer from the private key
    const signer = eth.signer.Signer.init(private_key);

    // Derive the Ethereum address
    const addr = try signer.address();
    const checksum = eth.primitives.addressToChecksum(&addr);

    try stdout.print("Private key: 0xac0974...f2ff80\n", .{});
    try stdout.print("Address:     {s}\n", .{checksum});
    // Expected: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    try stdout.flush();
}
