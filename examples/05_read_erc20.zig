// Example 05: Read ERC-20 token data using the ERC20 convenience module
//
// Requires Anvil running at localhost:8545 with a deployed ERC-20 token.
// This example demonstrates the API -- it will fail without a deployed contract.

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

    // Test connection
    _ = provider.getChainId() catch |err| {
        try stdout.print("Failed to connect to RPC: {}\n", .{err});
        try stdout.print("\nTo run this example, start Anvil:\n  anvil\n", .{});
        try stdout.flush();
        return;
    };

    // Show the ERC-20 module API
    try stdout.print("ERC-20 Module API:\n\n", .{});
    try stdout.print("Comptime selectors (zero runtime cost):\n", .{});
    try stdout.print("  transfer:     0x", .{});
    for (eth.erc20.selectors.transfer) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  balanceOf:    0x", .{});
    for (eth.erc20.selectors.balanceOf) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  approve:      0x", .{});
    for (eth.erc20.selectors.approve) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  totalSupply:  0x", .{});
    for (eth.erc20.selectors.totalSupply) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n\n", .{});

    // Show how you would use it with a real token contract:
    try stdout.print("Usage:\n", .{});
    try stdout.print("  var token = eth.erc20.ERC20.init(allocator, token_addr, &provider);\n", .{});
    try stdout.print("  const balance = try token.balanceOf(holder_addr);\n", .{});
    try stdout.print("  const name = try token.name();\n", .{});
    try stdout.print("  defer allocator.free(name);\n", .{});
    try stdout.flush();
}
