//! eth.zig benchmark suite: the ten operations that dominate a trading bot,
//! liquidator or searcher hot loop, measured against eth.zig's own past
//! results rather than other libraries.
//!
//!   zig build bench                                  run all ten
//!   zig build bench -- --filter keccak               run a subset
//!   zig build bench -- --save bench/baselines/x.json record a baseline
//!   zig build bench -- --baseline bench/baselines/x.json [--fail-on-regression]
//!
//! Measurement: each benchmark is warmed up, then timed in batches sized to
//! ~10 ms. The reported figure is the median ns/op over `--samples` batches
//! (default 31), with the minimum and the median absolute deviation (as a
//! percentage of the median) alongside. Inputs are read through an optimizer
//! barrier on every call so the compiler cannot constant-fold the work away.
//! On macOS the process requests the user-interactive QoS class so it stays
//! on performance cores. Compare versions with bench/ab.py, which interleaves
//! runs so machine-load drift affects every binary equally.
const std = @import("std");
const eth = @import("eth");

// ============================================================================
// Inputs. Module-level `var`s read through `opaqueInput` on every call.
// ============================================================================

// Anvil account 0 -- well-known test key.
var private_key: [32]u8 = .{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};

// keccak256("")
var msg_hash: [32]u8 = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

var test_addr: [20]u8 = .{
    0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce,
    0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf, 0xfF, 0xb9, 0x22, 0x66,
};

var data_1kb: [1024]u8 = @splat(0xAB);

const transfer_selector: [4]u8 = .{ 0xa9, 0x05, 0x9c, 0xbb };

// A real PancakeSwap Universal Router `execute` (BSC tx 0x6cf50c46...,
// block 123681598): stable swap, V2 swap, pay-portion and sweep commands.
var ur_execute: [1252]u8 = blk: {
    @setEvalBranchQuota(100_000);
    break :blk eth.hex.hexToBytesFixed(1252, "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006ab4a0e400000000000000000000000000000000000000000000000000000000000000042208060400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000ea26b78255df2bbc31c1ebf60010d78670185bd0000000000000000000000000000000000000000000000002c3c465ca58ec0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000055d398326f99059ff775485246999027b31979550000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000430bd0d47ee2c000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d0000000000000000000000002170ed0880ac9a755fd29b2688956bd959f933f800000000000000000000000000000000000000000000000000000000000000600000000000000000000000002170ed0880ac9a755fd29b2688956bd959f933f80000000000000000000000006a80f57ac54123cb71e6c79b3935a381b87b4308000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000600000000000000000000000002170ed0880ac9a755fd29b2688956bd959f933f800000000000000000000000026a50b11214838d5b46060e6ddd851baee4ced810000000000000000000000000000000000000000000000000042e07a6a081c85") catch unreachable;
};

// Filled in `main` before any benchmark runs.
var signature: eth.signature.Signature = undefined;
var abi_dynamic: []const u8 = &.{};

/// Hide `p` from the optimizer: after this, the compiler must assume the
/// pointee may have changed, so it reloads the input instead of folding it.
inline fn opaqueInput(p: anytype) @TypeOf(p) {
    var q = p;
    std.mem.doNotOptimizeAway(&q);
    return q;
}

// ============================================================================
// The ten benchmarks
// ============================================================================

const Bench = struct {
    name: []const u8,
    /// What the number stands for, shown with `--list`.
    what: []const u8,
    func: *const fn () void,
};

const benches = [_]Bench{
    .{ .name = "keccak256_32b", .what = "selector / storage-slot / mapping-key hash", .func = benchKeccak32 },
    .{ .name = "keccak256_1kb", .what = "calldata and transaction-sized hash", .func = benchKeccak1k },
    .{ .name = "secp256k1_sign", .what = "sign a transaction hash", .func = benchSign },
    .{ .name = "secp256k1_recover", .what = "recover a sender from a signature", .func = benchRecover },
    .{ .name = "tx_hash_eip1559", .what = "RLP-encode an EIP-1559 tx and hash it", .func = benchTxHash },
    .{ .name = "abi_encode_transfer", .what = "encode transfer(address,uint256) calldata", .func = benchAbiEncodeTransfer },
    .{ .name = "abi_decode_dynamic", .what = "decode (string,bytes) return data", .func = benchAbiDecodeDynamic },
    .{ .name = "u256_mulDiv", .what = "full-precision a*b/c (512-bit intermediate)", .func = benchMulDiv },
    .{ .name = "u256_uniswapv4_swap", .what = "one exact-in swap step price update", .func = benchV4Swap },
    .{ .name = "dex_decode_universal_router", .what = "decode a 4-command Universal Router execute", .func = benchDexDecode },
};

fn benchKeccak32() void {
    const h = eth.keccak.hash(opaqueInput(&msg_hash));
    std.mem.doNotOptimizeAway(&h);
}

fn benchKeccak1k() void {
    const h = eth.keccak.hash(opaqueInput(&data_1kb));
    std.mem.doNotOptimizeAway(&h);
}

fn benchSign() void {
    const sig = eth.secp256k1.sign(opaqueInput(&private_key).*, opaqueInput(&msg_hash).*) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

fn benchRecover() void {
    const pubkey = eth.secp256k1.recover(opaqueInput(&signature).*, opaqueInput(&msg_hash).*) catch unreachable;
    std.mem.doNotOptimizeAway(&pubkey);
}

fn benchTxHash() void {
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const tx = eth.transaction.Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = opaqueInput(&@as(u64, 42)).*,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21000,
        .to = opaqueInput(&test_addr).*,
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .access_list = &.{},
    } };
    const h = eth.transaction.hashForSigning(fba.allocator(), tx) catch unreachable;
    std.mem.doNotOptimizeAway(&h);
}

fn benchAbiEncodeTransfer() void {
    var buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = opaqueInput(&test_addr).* },
        .{ .uint256 = 1_000_000_000_000_000_000 },
    };
    const out = eth.abi_encode.encodeFunctionCall(fba.allocator(), transfer_selector, &args) catch unreachable;
    std.mem.doNotOptimizeAway(out.ptr);
}

fn benchAbiDecodeDynamic() void {
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const types = [_]eth.abi_types.AbiType{ .string, .bytes };
    const values = eth.abi_decode.decodeValues(opaqueInput(&abi_dynamic).*, &types, fba.allocator()) catch unreachable;
    std.mem.doNotOptimizeAway(values.ptr);
}

fn benchMulDiv() void {
    var a: u256 = 1_000_000_000_000_000_000;
    var b: u256 = 79228162514264337593543950336;
    var c: u256 = 1_000_000_000_000_001_000;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    std.mem.doNotOptimizeAway(&c);
    const r = eth.uint256.mulDiv(a, b, c);
    std.mem.doNotOptimizeAway(&r);
}

fn benchV4Swap() void {
    var liquidity: u256 = 1_000_000_000_000_000_000;
    var sqrt_price: u256 = 79228162514264337593543950336;
    var amount_in: u256 = 1_000_000_000_000_000;
    std.mem.doNotOptimizeAway(&liquidity);
    std.mem.doNotOptimizeAway(&sqrt_price);
    std.mem.doNotOptimizeAway(&amount_in);
    const product = eth.uint256.fastMul(amount_in, sqrt_price);
    const next = eth.uint256.mulDiv(liquidity, sqrt_price, liquidity +% product);
    std.mem.doNotOptimizeAway(&next);
}

fn benchDexDecode() void {
    const decoded = eth.dex.decodeFor(.pancake_ur, opaqueInput(&ur_execute)) orelse unreachable;
    var it = decoded.universal_router_execute.iterator();
    var n: usize = 0;
    while (it.next()) |cmd| : (n += 1) std.mem.doNotOptimizeAway(&cmd);
    std.mem.doNotOptimizeAway(&n);
}

// ============================================================================
// Harness
// ============================================================================

const Options = struct {
    filter: ?[]const u8 = null,
    samples: usize = 31,
    json: bool = false,
    save: ?[]const u8 = null,
    baseline: ?[]const u8 = null,
    /// A benchmark regresses when its median is this much slower than the
    /// baseline AND the slowdown exceeds its own measured noise.
    threshold_pct: f64 = 5,
    fail_on_regression: bool = false,
};

const Result = struct {
    name: []const u8,
    median_ns: f64,
    min_ns: f64,
    /// Median absolute deviation as a percentage of the median.
    mad_pct: f64,
    iters: u64,
};

/// On macOS, ask the scheduler to keep the benchmark on performance cores;
/// without it a run can land partly on efficiency cores and read 1.5-2x slower.
fn pinToPerformanceCores() void {
    if (@import("builtin").target.os.tag != .macos) return;
    const QOS_CLASS_USER_INTERACTIVE: c_uint = 0x21;
    const pthread_set_qos_class_self_np = @extern(*const fn (c_uint, c_int) callconv(.c) c_int, .{ .name = "pthread_set_qos_class_self_np" });
    _ = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
}

const max_samples = 255;
const warmup_ns: u64 = 200_000_000;
const target_batch_ns: u64 = 10_000_000;

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.now(.awake, io).nanoseconds;
}

fn elapsedSince(io: std.Io, t0: i96) u64 {
    const d = nowNs(io) - t0;
    return if (d > 0) @intCast(d) else 0;
}

fn measure(io: std.Io, b: Bench, samples_wanted: usize) Result {
    const n_samples = @min(samples_wanted, max_samples);

    // Warm caches, branch predictors and CPU frequency.
    var t0 = nowNs(io);
    while (elapsedSince(io, t0) < warmup_ns) {
        for (0..64) |_| b.func();
    }

    // Size a batch to ~target_batch_ns so clock overhead is negligible.
    var batch: u64 = 16;
    while (true) {
        t0 = nowNs(io);
        for (0..batch) |_| b.func();
        if (elapsedSince(io, t0) >= target_batch_ns or batch >= 1 << 30) break;
        batch *= 2;
    }

    var samples: [max_samples]f64 = undefined;
    for (samples[0..n_samples]) |*s| {
        t0 = nowNs(io);
        for (0..batch) |_| b.func();
        s.* = @as(f64, @floatFromInt(elapsedSince(io, t0))) / @as(f64, @floatFromInt(batch));
    }
    const sorted = samples[0..n_samples];
    std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
    const median = sorted[n_samples / 2];

    var dev: [max_samples]f64 = undefined;
    for (sorted, 0..) |s, i| dev[i] = @abs(s - median);
    std.mem.sort(f64, dev[0..n_samples], {}, std.sort.asc(f64));
    const mad = dev[n_samples / 2];

    return .{
        .name = b.name,
        .median_ns = median,
        .min_ns = sorted[0],
        .mad_pct = if (median > 0) mad / median * 100 else 0,
        .iters = batch * n_samples,
    };
}

fn matches(opts: Options, name: []const u8) bool {
    const f = opts.filter orelse return true;
    return std.mem.indexOf(u8, name, f) != null;
}

fn parseArgs(args: []const [:0]const u8) !Options {
    var opts: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--json")) {
            opts.json = true;
        } else if (std.mem.eql(u8, a, "--fail-on-regression")) {
            opts.fail_on_regression = true;
        } else if (i + 1 < args.len and std.mem.eql(u8, a, "--filter")) {
            i += 1;
            opts.filter = args[i];
        } else if (i + 1 < args.len and std.mem.eql(u8, a, "--save")) {
            i += 1;
            opts.save = args[i];
        } else if (i + 1 < args.len and std.mem.eql(u8, a, "--baseline")) {
            i += 1;
            opts.baseline = args[i];
        } else if (i + 1 < args.len and std.mem.eql(u8, a, "--samples")) {
            i += 1;
            opts.samples = try std.fmt.parseInt(usize, args[i], 10);
        } else if (i + 1 < args.len and std.mem.eql(u8, a, "--threshold")) {
            i += 1;
            opts.threshold_pct = try std.fmt.parseFloat(f64, args[i]);
        } else if (std.mem.eql(u8, a, "--list")) {
            for (benches) |b| std.debug.print("{s:<30} {s}\n", .{ b.name, b.what });
            std.process.exit(0);
        } else {
            std.debug.print("unknown or incomplete argument: {s}\n", .{a});
            return error.InvalidArgument;
        }
    }
    if (opts.samples < 3) return error.InvalidArgument;
    return opts;
}

const BaselineEntry = struct { name: []const u8, median_ns: f64, mad_pct: f64 = 0 };
const BaselineFile = struct { results: []const BaselineEntry };

fn findBaseline(base: []const BaselineEntry, name: []const u8) ?BaselineEntry {
    for (base) |e| if (std.mem.eql(u8, e.name, name)) return e;
    return null;
}

fn writeJson(w: *std.Io.Writer, results: []const Result) !void {
    try w.print("{{\n  \"zig\": \"{s}\",\n  \"target\": \"{s}-{s}\",\n  \"results\": [\n", .{
        @import("builtin").zig_version_string,
        @tagName(@import("builtin").target.cpu.arch),
        @tagName(@import("builtin").target.os.tag),
    });
    for (results, 0..) |r, i| {
        try w.print("    {{\"name\": \"{s}\", \"median_ns\": {d:.2}, \"min_ns\": {d:.2}, \"mad_pct\": {d:.2}, \"iters\": {d}}}{s}\n", .{
            r.name, r.median_ns, r.min_ns, r.mad_pct, r.iters, if (i + 1 < results.len) "," else "",
        });
    }
    try w.writeAll("  ]\n}\n");
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const opts = try parseArgs(args);
    pinToPerformanceCores();

    // Inputs that need eth.zig to build.
    signature = try eth.secp256k1.sign(private_key, msg_hash);
    const dyn_args = [_]eth.abi_encode.AbiValue{
        .{ .string = "The quick brown fox jumps over the lazy dog" },
        .{ .bytes = "hello world, this is a dynamic bytes benchmark test payload" },
    };
    const dyn = try eth.abi_encode.encodeValues(gpa, &dyn_args);
    defer gpa.free(dyn);
    abi_dynamic = dyn;

    var baseline_parsed: ?std.json.Parsed(BaselineFile) = null;
    defer if (baseline_parsed) |*p| p.deinit();
    if (opts.baseline) |path| {
        const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
        defer gpa.free(raw);
        baseline_parsed = try std.json.parseFromSlice(BaselineFile, gpa, raw, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    }
    const base: []const BaselineEntry = if (baseline_parsed) |p| p.value.results else &.{};

    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &out.interface;

    var results: [benches.len]Result = undefined;
    var n: usize = 0;
    var regressions: usize = 0;

    if (!opts.json) {
        try w.print("\n{s:<30} {s:>12} {s:>12} {s:>8}", .{ "benchmark", "median", "min", "+/-" });
        if (base.len > 0) try w.print(" {s:>12} {s:>9}", .{ "baseline", "change" });
        try w.writeAll("\n");
        try w.flush();
    }

    for (benches) |b| {
        if (!matches(opts, b.name)) continue;
        const r = measure(io, b, opts.samples);
        results[n] = r;
        n += 1;

        // Classify against the baseline before any output decision, so
        // --fail-on-regression also works together with --json.
        var tag: []const u8 = "";
        var change: f64 = 0;
        const baseline_entry = findBaseline(base, r.name);
        if (baseline_entry) |e| {
            change = (r.median_ns - e.median_ns) / e.median_ns * 100;
            // Only call it a regression if it clears both the threshold and the
            // combined noise of the two runs.
            const noise = 2 * (r.mad_pct + e.mad_pct);
            if (change > opts.threshold_pct and change > noise) {
                regressions += 1;
                tag = "  REGRESSION";
            } else if (change < -opts.threshold_pct and -change > noise) {
                tag = "  faster";
            }
        }
        if (opts.json) continue;

        try w.print("{s:<30} {d:>9.2} ns {d:>9.2} ns {d:>7.1}%", .{ r.name, r.median_ns, r.min_ns, r.mad_pct });
        if (baseline_entry) |e| {
            try w.print(" {d:>9.2} ns {s}{d:>7.1}%{s}", .{ e.median_ns, if (change >= 0) "+" else "-", @abs(change), tag });
        } else if (base.len > 0) {
            try w.writeAll(" (not in baseline)");
        }
        try w.writeAll("\n");
        try w.flush();
    }

    if (opts.json) try writeJson(w, results[0..n]);
    if (!opts.json and base.len > 0)
        try w.print("\n{d} regression(s) beyond {d:.0}% and noise\n", .{ regressions, opts.threshold_pct });
    try w.flush();

    if (opts.save) |path| {
        var file_buf: [8192]u8 = undefined;
        var fw: std.Io.Writer = .fixed(&file_buf);
        try writeJson(&fw, results[0..n]);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = fw.buffered() });
        std.debug.print("saved {d} results to {s}\n", .{ n, path });
    }

    if (opts.fail_on_regression and regressions > 0) std.process.exit(1);
}
