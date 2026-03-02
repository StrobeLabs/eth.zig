// Example 07: Function selectors and event topics
//
// Pure compute -- no RPC connection needed.
// keccak.selector() and keccak.hash() work at both comptime and runtime.
// The caller decides by using the `comptime` keyword or not.

const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var stdout_impl = std.fs.File.stdout().writer(&buf);
    const stdout = &stdout_impl.interface;

    // Comptime: evaluated at compile time, zero runtime cost
    const transfer_sel = comptime eth.keccak.selector("transfer(address,uint256)");
    const approve_sel = comptime eth.keccak.selector("approve(address,uint256)");
    const balance_sel = comptime eth.keccak.selector("balanceOf(address)");

    const transfer_topic = comptime eth.keccak.hash("Transfer(address,address,uint256)");
    const approval_topic = comptime eth.keccak.hash("Approval(address,address,uint256)");

    // Runtime: the same functions also work with runtime-known strings
    const runtime_sig: []const u8 = "transfer(address,uint256)";
    const runtime_sel = eth.keccak.selector(runtime_sig);

    try stdout.print("Comptime Selectors (zero runtime cost):\n", .{});
    try stdout.print("  transfer(address,uint256):     0x", .{});
    for (transfer_sel) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  approve(address,uint256):      0x", .{});
    for (approve_sel) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  balanceOf(address):            0x", .{});
    for (balance_sel) |b| try stdout.print("{x:0>2}", .{b});

    try stdout.print("\n\nRuntime Selector (same function, runtime string):\n", .{});
    try stdout.print("  transfer(address,uint256):     0x", .{});
    for (runtime_sel) |b| try stdout.print("{x:0>2}", .{b});

    try stdout.print("\n\nEvent Topics:\n", .{});
    try stdout.print("  Transfer(address,address,uint256):\n    0x", .{});
    for (transfer_topic) |b| try stdout.print("{x:0>2}", .{b});
    try stdout.print("\n  Approval(address,address,uint256):\n    0x", .{});
    for (approval_topic) |b| try stdout.print("{x:0>2}", .{b});

    try stdout.print("\n\nUnified API -- one function, caller decides:\n", .{});
    try stdout.print("  const sel = comptime eth.keccak.selector(\"transfer(address,uint256)\");\n", .{});
    try stdout.print("  // sel == [4]u8{{ 0xa9, 0x05, 0x9c, 0xbb }} -- zero runtime cost\n", .{});
    try stdout.flush();
}
