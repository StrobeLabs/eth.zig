const std = @import("std");
const eth = @import("eth");

// ============================================================================
// Test values -- identical to alloy-bench/benches/u256_comparison.rs
// ============================================================================

const ONE_ETH: u256 = 1_000_000_000_000_000_000;
const RESERVE_IN: u256 = 100_000_000_000_000_000_000; // 100 ETH
const RESERVE_OUT: u256 = 200_000_000_000; // 200k USDC (6 decimals)

// 2^96 -- used in UniswapV3/V4 sqrtPriceX96
const SQRT_PRICE: u256 = 79228162514264337593543950336;
const AMOUNT_IN_SMALL: u256 = 1_000_000_000_000_000; // 0.001 ETH

// Full-width 256-bit values for mul/div stress tests
const FULL_A: u256 = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0_DEADBEEF_CAFEBABE_12345678_9ABCDEF0;
const FULL_B: u256 = 0x12345678_9ABCDEF0_DEADBEEF_CAFEBABE_12345678_9ABCDEF0_DEADBEEF_CAFEBABE;
const FULL_C: u256 = 0x00000001_00000000_00000000_00000000_00000000_00000000_00000000_00000001;

// ============================================================================
// Benchmark harness -- criterion-style: run N iters, measure wall time, report ns/op
// ============================================================================

const WARMUP_NS: u64 = 500_000_000; // 0.5s warmup
const BENCH_NS: u64 = 2_000_000_000; // 2s measurement

const Timer = std.time.Timer;

const BenchResult = struct {
    ns_per_op: u64,
    iters: u64,
};

fn runBench(comptime func: fn () void) BenchResult {
    var timer = Timer.start() catch @panic("timer unsupported");

    // Warmup: run until WARMUP_NS elapsed
    timer.reset();
    while (true) {
        inline for (0..64) |_| func();
        if (timer.read() >= WARMUP_NS) break;
    }

    // Calibrate: find iteration count that fills ~100ms
    var batch: u64 = 64;
    while (true) {
        timer.reset();
        for (0..batch) |_| func();
        if (timer.read() >= 100_000_000) break; // 100ms
        batch *= 2;
    }

    // Measure: collect samples over BENCH_NS
    var total_iters: u64 = 0;
    timer.reset();

    while (timer.read() < BENCH_NS) {
        for (0..batch) |_| func();
        total_iters += batch;
    }

    const total_ns = timer.read();
    const ns_per_op = if (total_iters > 0) total_ns / total_iters else 0;
    return .{ .ns_per_op = ns_per_op, .iters = total_iters };
}

// ============================================================================
// Benchmark functions
// ============================================================================

fn benchAdd() void {
    var a: u256 = ONE_ETH;
    var b: u256 = 997_000_000_000_000_000;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = a +% b;
    std.mem.doNotOptimizeAway(&result);
}

fn benchMulSmall() void {
    var a: u256 = ONE_ETH;
    var b: u256 = 997;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = eth.uint256.fastMul(a, b);
    std.mem.doNotOptimizeAway(&result);
}

fn benchMulFull() void {
    var a: u256 = FULL_A;
    var b: u256 = FULL_B;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = eth.uint256.fastMul(a, b);
    std.mem.doNotOptimizeAway(&result);
}

fn benchDivSmall() void {
    var a: u256 = 997_000_000_000_000_000_000;
    var b: u256 = ONE_ETH;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = eth.uint256.fastDiv(a, b);
    std.mem.doNotOptimizeAway(&result);
}

fn benchDivFull() void {
    var a: u256 = FULL_A;
    var b: u256 = FULL_C;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = eth.uint256.fastDiv(a, b);
    std.mem.doNotOptimizeAway(&result);
}

// UniswapV2 getAmountOut -- step-by-step on [4]u64 limbs (apples-to-apples with Rust's [u64; 4])
// Uses fp256 hand-optimized aarch64 assembly for mul/add, u128 fast path for division.
fn benchUniswapV2Naive() void {
    var amount_in = eth.uint256.u256ToLimbs(ONE_ETH);
    var reserve_in = eth.uint256.u256ToLimbs(RESERVE_IN);
    var reserve_out = eth.uint256.u256ToLimbs(RESERVE_OUT);
    std.mem.doNotOptimizeAway(&amount_in);
    std.mem.doNotOptimizeAway(&reserve_in);
    std.mem.doNotOptimizeAway(&reserve_out);

    const amount_in_with_fee = eth.uint256.mulLimbScalar(amount_in, 997);
    const numerator = eth.uint256.mulLimbs(amount_in_with_fee, reserve_out);
    const denominator = eth.uint256.addLimbs(eth.uint256.mulLimbScalar(reserve_in, 1000), amount_in_with_fee);
    const amount_out = eth.uint256.divLimbsDirect(numerator, denominator);
    std.mem.doNotOptimizeAway(&amount_out);
}

// UniswapV2 getAmountOut -- compound limb function (zig-only optimization)
fn benchUniswapV2Optimized() void {
    var amount_in: u256 = ONE_ETH;
    var reserve_in: u256 = RESERVE_IN;
    var reserve_out: u256 = RESERVE_OUT;
    std.mem.doNotOptimizeAway(&amount_in);
    std.mem.doNotOptimizeAway(&reserve_in);
    std.mem.doNotOptimizeAway(&reserve_out);

    const amount_out = eth.uint256.getAmountOut(amount_in, reserve_in, reserve_out);
    std.mem.doNotOptimizeAway(&amount_out);
}

// mulDiv: (a * b) / c with true 512-bit intermediate
fn benchMulDiv() void {
    var a: u256 = ONE_ETH;
    var b: u256 = SQRT_PRICE;
    var c: u256 = ONE_ETH + 1_000_000;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    std.mem.doNotOptimizeAway(&c);
    const result = eth.uint256.mulDiv(a, b, c);
    std.mem.doNotOptimizeAway(&result);
}

// DEX V2 getAmountOut with configurable fee (dex/v2.zig)
fn benchDexV2AmountOut() void {
    var amount_in: u256 = ONE_ETH;
    var reserve_in: u256 = RESERVE_IN;
    var reserve_out: u256 = RESERVE_OUT;
    std.mem.doNotOptimizeAway(&amount_in);
    std.mem.doNotOptimizeAway(&reserve_in);
    std.mem.doNotOptimizeAway(&reserve_out);

    const amount_out = eth.dex_v2.getAmountOut(amount_in, reserve_in, reserve_out, 997, 1000);
    std.mem.doNotOptimizeAway(&amount_out);
}

// DEX V2 multi-hop: 3-hop path
fn benchDexV2MultiHop() void {
    const path = [_]eth.dex_v2.Pair{
        .{ .reserve_in = RESERVE_IN, .reserve_out = RESERVE_OUT },
        .{ .reserve_in = 200_000_000_000, .reserve_out = 50_000_000_000_000_000_000 },
        .{ .reserve_in = 50_000_000_000_000_000_000, .reserve_out = 100_000_000_000 },
    };
    var amount_in: u256 = ONE_ETH;
    std.mem.doNotOptimizeAway(&amount_in);

    const result = eth.dex_v2.getAmountsOut(amount_in, &path);
    std.mem.doNotOptimizeAway(&result);
}

// DEX V3 getSqrtRatioAtTick
fn benchDexV3TickToPrice() void {
    var tick: i24 = 10000;
    std.mem.doNotOptimizeAway(&tick);
    const result = eth.dex_v3.getSqrtRatioAtTick(tick);
    std.mem.doNotOptimizeAway(&result);
}

// DEX V3 computeSwapStep
fn benchDexV3SwapStep() void {
    var current: u256 = SQRT_PRICE;
    var target: u256 = eth.dex_v3.getSqrtRatioAtTick(-100).?;
    std.mem.doNotOptimizeAway(&current);
    std.mem.doNotOptimizeAway(&target);
    const result = eth.dex_v3.computeSwapStep(current, target, 1_000_000_000_000_000_000, 1_000_000, 3000);
    std.mem.doNotOptimizeAway(&result);
}

// UniswapV4 getNextSqrtPriceFromAmount0RoundingUp
fn benchUniswapV4Swap() void {
    var liquidity: u256 = ONE_ETH;
    var sqrt_price: u256 = SQRT_PRICE;
    var amount_in: u256 = AMOUNT_IN_SMALL;
    std.mem.doNotOptimizeAway(&liquidity);
    std.mem.doNotOptimizeAway(&sqrt_price);
    std.mem.doNotOptimizeAway(&amount_in);

    const product = eth.uint256.fastMul(amount_in, sqrt_price);
    const denominator = liquidity +% product;
    const next_sqrt_price = eth.uint256.mulDiv(liquidity, sqrt_price, denominator);
    std.mem.doNotOptimizeAway(&next_sqrt_price);
}

// ============================================================================
// Main
// ============================================================================

fn runAndPrint(comptime name: []const u8, comptime func: fn () void, stdout: anytype) !void {
    const result = runBench(func);
    try stdout.print("{s:<32} {d:>9} ns {d:>14}\n", .{ name, result.ns_per_op, result.iters });
}

fn runAndJson(comptime name: []const u8, comptime func: fn () void, stdout: anytype) !void {
    const result = runBench(func);
    try stdout.print("BENCH_JSON|{{\"name\":\"{s}\",\"ns_per_op\":{d}}}\n", .{ name, result.ns_per_op });
}

pub fn main() !void {
    var buf: [8192]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const stdout = &w.interface;

    try stdout.print("\n{s:<32} {s:>12} {s:>14}\n", .{ "Benchmark", "ns/op", "iters" });
    try stdout.print("{s}\n", .{"" ++ @as([62]u8, @splat('-'))});

    try runAndPrint("u256_add", benchAdd, stdout);
    try runAndPrint("u256_mul_small", benchMulSmall, stdout);
    try runAndPrint("u256_mul_full", benchMulFull, stdout);
    try runAndPrint("u256_div_small", benchDivSmall, stdout);
    try runAndPrint("u256_div_full", benchDivFull, stdout);
    try runAndPrint("u256_uniswapv2_naive", benchUniswapV2Naive, stdout);
    try runAndPrint("u256_uniswapv2_optimized", benchUniswapV2Optimized, stdout);
    try runAndPrint("u256_mulDiv", benchMulDiv, stdout);
    try runAndPrint("u256_uniswapv4_swap", benchUniswapV4Swap, stdout);
    // DEX benchmarks
    try runAndPrint("dex_v2_amount_out", benchDexV2AmountOut, stdout);
    try runAndPrint("dex_v2_multi_hop_3", benchDexV2MultiHop, stdout);
    try runAndPrint("dex_v3_tick_to_price", benchDexV3TickToPrice, stdout);
    try runAndPrint("dex_v3_swap_step", benchDexV3SwapStep, stdout);

    try stdout.print("\n", .{});

    // Machine-readable JSON lines for compare script
    try runAndJson("u256_add", benchAdd, stdout);
    try runAndJson("u256_mul_small", benchMulSmall, stdout);
    try runAndJson("u256_mul_full", benchMulFull, stdout);
    try runAndJson("u256_div_small", benchDivSmall, stdout);
    try runAndJson("u256_div_full", benchDivFull, stdout);
    try runAndJson("u256_uniswapv2_naive", benchUniswapV2Naive, stdout);
    try runAndJson("u256_uniswapv2_optimized", benchUniswapV2Optimized, stdout);
    try runAndJson("u256_mulDiv", benchMulDiv, stdout);
    try runAndJson("u256_uniswapv4_swap", benchUniswapV4Swap, stdout);
    try runAndJson("dex_v2_amount_out", benchDexV2AmountOut, stdout);
    try runAndJson("dex_v2_multi_hop_3", benchDexV2MultiHop, stdout);
    try runAndJson("dex_v3_tick_to_price", benchDexV3TickToPrice, stdout);
    try runAndJson("dex_v3_swap_step", benchDexV3SwapStep, stdout);

    try stdout.flush();
}
