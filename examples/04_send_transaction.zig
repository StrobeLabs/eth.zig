// Example 04: Send a transaction using the Wallet
//
// Requires Anvil running at localhost:8545.
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

    // Connect to local Anvil node
    var transport = eth.http_transport.HttpTransport.init(allocator, "http://127.0.0.1:8545");
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // Test connection first
    _ = provider.getChainId() catch |err| {
        try stdout.print("Failed to connect to RPC: {}\n", .{err});
        try stdout.print("\nTo run this example, start Anvil:\n  anvil\n", .{});
        try stdout.flush();
        return;
    };

    // Anvil account #0
    const private_key = try eth.hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);
    const sender = try wallet.address();
    const sender_checksum = eth.primitives.addressToChecksum(&sender);

    // Send 0.1 ETH to account #1
    const recipient = try eth.primitives.addressFromHex("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    const recipient_checksum = eth.primitives.addressToChecksum(&recipient);
    const value = eth.units.parseEther(0.1);

    try stdout.print("Sending 0.1 ETH\n", .{});
    try stdout.print("  From: {s}\n", .{sender_checksum});
    try stdout.print("  To:   {s}\n", .{recipient_checksum});

    const tx_hash = try wallet.sendTransaction(.{
        .to = recipient,
        .value = value,
    });

    try stdout.print("Tx hash: 0x", .{});
    for (tx_hash) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n", .{});
    try stdout.flush();
}
