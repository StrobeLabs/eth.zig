const std = @import("std");
const eth = @import("eth");
const zbench = @import("zbench");

// Test data
const DATA_32: [32]u8 = .{0xAB} ** 32;
const DATA_256: [256]u8 = .{0xAB} ** 256;
const DATA_1K: [1024]u8 = .{0xAB} ** 1024;
const DATA_4K: [4096]u8 = .{0xAB} ** 4096;

// -- eth.zig keccak (lane-complementing optimized) --

fn benchEthKeccakEmpty(_: std.mem.Allocator) void {
    const r = eth.keccak.hash("");
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak32(_: std.mem.Allocator) void {
    const r = eth.keccak.hash(&DATA_32);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak256(_: std.mem.Allocator) void {
    const r = eth.keccak.hash(&DATA_256);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak1k(_: std.mem.Allocator) void {
    const r = eth.keccak.hash(&DATA_1K);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak4k(_: std.mem.Allocator) void {
    const r = eth.keccak.hash(&DATA_4K);
    std.mem.doNotOptimizeAway(&r);
}

// -- Zig stdlib keccak --

fn benchStdlibKeccakEmpty(_: std.mem.Allocator) void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("", &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak32(_: std.mem.Allocator) void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_32, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak256(_: std.mem.Allocator) void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_256, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak1k(_: std.mem.Allocator) void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_1K, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak4k(_: std.mem.Allocator) void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_4K, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

pub fn main() !void {
    var bench = zbench.Benchmark.init(std.heap.page_allocator, .{});
    defer bench.deinit();

    // eth.zig
    try bench.add("eth.zig keccak empty", benchEthKeccakEmpty, .{});
    try bench.add("eth.zig keccak 32b", benchEthKeccak32, .{});
    try bench.add("eth.zig keccak 256b", benchEthKeccak256, .{});
    try bench.add("eth.zig keccak 1kb", benchEthKeccak1k, .{});
    try bench.add("eth.zig keccak 4kb", benchEthKeccak4k, .{});

    // stdlib
    try bench.add("stdlib keccak empty", benchStdlibKeccakEmpty, .{});
    try bench.add("stdlib keccak 32b", benchStdlibKeccak32, .{});
    try bench.add("stdlib keccak 256b", benchStdlibKeccak256, .{});
    try bench.add("stdlib keccak 1kb", benchStdlibKeccak1k, .{});
    try bench.add("stdlib keccak 4kb", benchStdlibKeccak4k, .{});

    var buf: [16384]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    try bench.run(&w.interface);
    try w.interface.flush();
}
