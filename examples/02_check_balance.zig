// Example 02: Check an account balance via JSON-RPC
//
// Requires a running Ethereum node (e.g., Anvil at localhost:8545).
// Start Anvil with: anvil

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Connect to local node
    var transport = eth.http_transport.HttpTransport.init(allocator, "http://127.0.0.1:8545");
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // Anvil account #0
    const addr = try eth.primitives.addressFromHex("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const balance = provider.getBalance(addr) catch |err| {
        try stdout.print("Failed to connect to RPC: {}\n", .{err});
        try stdout.print("\nTo run this example, start Anvil:\n  anvil\n", .{});
        try stdout.flush();
        return;
    };

    const ether = eth.units.formatEther(balance);
    const checksum = eth.primitives.addressToChecksum(&addr);
    try stdout.print("Address: {s}\n", .{checksum});
    try stdout.print("Balance: {d:.4} ETH\n", .{ether});
    try stdout.flush();
}
