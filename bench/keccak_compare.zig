const std = @import("std");
const eth = @import("eth");

// Test data
const DATA_32: [32]u8 = @splat(0xAB);
const DATA_256: [256]u8 = @splat(0xAB);
const DATA_1K: [1024]u8 = @splat(0xAB);
const DATA_4K: [4096]u8 = @splat(0xAB);

// ============================================================================
// Benchmark harness (same as bench.zig / u256_bench.zig)
// ============================================================================

const WARMUP_NS: u64 = 500_000_000;
const BENCH_NS: u64 = 2_000_000_000;
const Timer = std.time.Timer;

const BenchResult = struct { ns_per_op: u64, iters: u64 };

fn runBench(comptime func: fn () void) BenchResult {
    var timer = Timer.start() catch @panic("timer unsupported");

    timer.reset();
    while (true) {
        inline for (0..64) |_| func();
        if (timer.read() >= WARMUP_NS) break;
    }

    var batch: u64 = 64;
    while (true) {
        timer.reset();
        for (0..batch) |_| func();
        if (timer.read() >= 100_000_000) break;
        batch *= 2;
    }

    var total_iters: u64 = 0;
    timer.reset();
    while (timer.read() < BENCH_NS) {
        for (0..batch) |_| func();
        total_iters += batch;
    }

    const total_ns = timer.read();
    return .{ .ns_per_op = if (total_iters > 0) total_ns / total_iters else 0, .iters = total_iters };
}

fn runAndPrint(comptime name: []const u8, comptime func: fn () void, stdout: anytype) !void {
    const result = runBench(func);
    try stdout.print("{s:<30} {d:>9} ns {d:>14}\n", .{ name, result.ns_per_op, result.iters });
}

// -- eth.zig keccak (lane-complementing optimized) --

fn benchEthKeccakEmpty() void {
    const r = eth.keccak.hash("");
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak32() void {
    const r = eth.keccak.hash(&DATA_32);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak256() void {
    const r = eth.keccak.hash(&DATA_256);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak1k() void {
    const r = eth.keccak.hash(&DATA_1K);
    std.mem.doNotOptimizeAway(&r);
}

fn benchEthKeccak4k() void {
    const r = eth.keccak.hash(&DATA_4K);
    std.mem.doNotOptimizeAway(&r);
}

// -- Zig stdlib keccak --

fn benchStdlibKeccakEmpty() void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("", &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak32() void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_32, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak256() void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_256, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak1k() void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_1K, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

fn benchStdlibKeccak4k() void {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&DATA_4K, &result, .{});
    std.mem.doNotOptimizeAway(&result);
}

pub fn main() !void {
    var out_buf: [8192]u8 = undefined;
    var w = std.fs.File.stdout().writer(&out_buf);
    const stdout = &w.interface;

    try stdout.print("\n{s:<30} {s:>12} {s:>14}\n", .{ "Benchmark", "ns/op", "iters" });
    try stdout.print("{s}\n", .{"" ++ @as([60]u8, @splat('-'))});

    // eth.zig
    try runAndPrint("eth.zig keccak empty", benchEthKeccakEmpty, stdout);
    try runAndPrint("eth.zig keccak 32b", benchEthKeccak32, stdout);
    try runAndPrint("eth.zig keccak 256b", benchEthKeccak256, stdout);
    try runAndPrint("eth.zig keccak 1kb", benchEthKeccak1k, stdout);
    try runAndPrint("eth.zig keccak 4kb", benchEthKeccak4k, stdout);

    try stdout.print("\n", .{});

    // stdlib
    try runAndPrint("stdlib keccak empty", benchStdlibKeccakEmpty, stdout);
    try runAndPrint("stdlib keccak 32b", benchStdlibKeccak32, stdout);
    try runAndPrint("stdlib keccak 256b", benchStdlibKeccak256, stdout);
    try runAndPrint("stdlib keccak 1kb", benchStdlibKeccak1k, stdout);
    try runAndPrint("stdlib keccak 4kb", benchStdlibKeccak4k, stdout);

    try stdout.print("\n", .{});
    try stdout.flush();
}
