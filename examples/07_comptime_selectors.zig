// Example 07: Comptime function selectors and event topics
//
// Pure compute -- no RPC connection needed.
// Showcases eth.zig's comptime-first approach: all selectors and topics
// are computed at compile time with zero runtime cost.

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    // Use runtime selectors in examples (comptime selectors are used inside the library
    // where the eval branch quota is pre-configured).
    const transfer_sel = eth.keccak.selector("transfer(address,uint256)");
    const approve_sel = eth.keccak.selector("approve(address,uint256)");
    const balance_sel = eth.keccak.selector("balanceOf(address)");

    const transfer_topic = eth.keccak.hash("Transfer(address,address,uint256)");
    const approval_topic = eth.keccak.hash("Approval(address,address,uint256)");

    try stdout.print("Function Selectors:\n", .{});
    try stdout.print("  transfer(address,uint256):     0x", .{});
    for (transfer_sel) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  approve(address,uint256):      0x", .{});
    for (approve_sel) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  balanceOf(address):            0x", .{});
    for (balance_sel) |b| try stdout.print("{x:0>2}", .{b});

    try stdout.print("\n\nEvent Topics:\n", .{});
    try stdout.print("  Transfer(address,address,uint256):\n    0x", .{});
    for (transfer_topic) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  Approval(address,address,uint256):\n    0x", .{});
    for (approval_topic) |b| try stdout.print("{x:0>2}", .{b});

    try stdout.print("\n\nInside the library, these are computed at compile time:\n", .{});
    try stdout.print("  const sel = eth.abi_comptime.comptimeSelector(\"transfer(address,uint256)\");\n", .{});
    try stdout.print("  // sel == [4]u8{{ 0xa9, 0x05, 0x9c, 0xbb }} -- zero runtime cost\n", .{});
    try stdout.flush();
}
