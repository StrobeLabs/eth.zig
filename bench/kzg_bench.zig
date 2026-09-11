//! KZG micro-benchmark: times the c-kzg-4844 + blst operations behind
//! `eth.kzg` on one deterministic blob. Each operation is run a fixed number
//! of times and the minimum and median wall-clock times are reported in
//! milliseconds; the minimum is the number to compare across builds (blst
//! assembly vs portable C), the median shows run-to-run noise.
//!
//! Run: zig build bench-kzg

const std = @import("std");
const eth = @import("eth");

const kzg = eth.kzg;
const blob_mod = eth.blob;

fn nowNs() i96 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.now(.awake, io).nanoseconds;
}

const Sample = struct {
    min_ns: u64,
    median_ns: u64,
    iters: usize,
};

/// Time `func(ctx)` `iters` times; returns min and median per-call latency.
fn measure(iters: usize, ctx: anytype, comptime func: anytype) !Sample {
    var samples: [64]u64 = undefined;
    const n = @min(iters, samples.len);
    for (samples[0..n]) |*s| {
        const t0 = nowNs();
        try func(ctx);
        const t1 = nowNs();
        s.* = @intCast(t1 - t0);
    }
    std.mem.sort(u64, samples[0..n], {}, std.sort.asc(u64));
    return .{ .min_ns = samples[0], .median_ns = samples[n / 2], .iters = n };
}

fn printRow(stdout: anytype, name: []const u8, s: Sample) !void {
    const min_ms = @as(f64, @floatFromInt(s.min_ns)) / 1e6;
    const med_ms = @as(f64, @floatFromInt(s.median_ns)) / 1e6;
    try stdout.print("{s:<32} {d:>10.3} ms {d:>10.3} ms {d:>6}\n", .{ name, min_ms, med_ms, s.iters });
    try stdout.print("BENCH_JSON|{{\"name\":\"{s}\",\"min_ns\":{d},\"median_ns\":{d},\"iters\":{d}}}\n", .{ name, s.min_ns, s.median_ns, s.iters });
}

const Fixture = struct {
    blob: *const blob_mod.Blob,
    commitment: blob_mod.KzgCommitment,
    proof: blob_mod.KzgProof,
};

fn opCommit(f: *const Fixture) !void {
    _ = try kzg.blobToKzgCommitment(f.blob);
}

fn opProof(f: *const Fixture) !void {
    _ = try kzg.computeBlobKzgProof(f.blob, f.commitment);
}

fn opVerify(f: *const Fixture) !void {
    if (!try kzg.verifyBlobKzgProof(f.blob, f.commitment, f.proof)) return error.ProofDidNotVerify;
}

fn opVerifyBatch(f: *const Fixture) !void {
    const blobs = [_]blob_mod.Blob{f.blob.*};
    const commits = [_]blob_mod.KzgCommitment{f.commitment};
    const proofs = [_]blob_mod.KzgProof{f.proof};
    if (!try kzg.verifyBlobKzgProofBatch(&blobs, &commits, &proofs)) return error.ProofDidNotVerify;
}

pub fn main() !void {
    var out_buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(std.Io.Threaded.global_single_threaded.io(), &out_buf);
    const stdout = &w.interface;

    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const allocator = dbg.allocator();

    // Trusted-setup load time (one-shot; dominated by G1/G2 point parsing).
    const t_init0 = nowNs();
    try kzg.init(allocator);
    const t_init1 = nowNs();
    defer kzg.deinit();

    // Deterministic pseudo-random blob with full-width field elements. Tiny
    // scalars would let the Pippenger MSM skip most windows and understate the
    // commitment cost. Masking the top byte to 6 bits keeps every 32-byte
    // big-endian element below the BLS12-381 scalar modulus (0x73ed...).
    const blob = try allocator.create(blob_mod.Blob);
    defer allocator.destroy(blob);
    var prng = std.Random.DefaultPrng.init(0x6b7a67);
    prng.random().bytes(blob);
    var i: usize = 0;
    while (i < blob_mod.BLOB_SIZE) : (i += 32) {
        blob[i] &= 0x3f;
    }

    var fx = Fixture{ .blob = blob, .commitment = undefined, .proof = undefined };
    fx.commitment = try kzg.blobToKzgCommitment(blob);
    fx.proof = try kzg.computeBlobKzgProof(blob, fx.commitment);

    try stdout.print("\n{s:<32} {s:>13} {s:>13} {s:>6}\n", .{ "kzg op", "min", "median", "iters" });
    try stdout.print("{s}\n", .{"" ++ @as([68]u8, @splat('-'))});
    try printRow(stdout, "init (trusted setup load)", .{ .min_ns = @intCast(t_init1 - t_init0), .median_ns = @intCast(t_init1 - t_init0), .iters = 1 });
    try printRow(stdout, "blob_to_kzg_commitment", try measure(10, &fx, opCommit));
    try printRow(stdout, "compute_blob_kzg_proof", try measure(10, &fx, opProof));
    try printRow(stdout, "verify_blob_kzg_proof", try measure(30, &fx, opVerify));
    try printRow(stdout, "verify_blob_kzg_proof_batch(1)", try measure(30, &fx, opVerifyBatch));
    try stdout.print("\n", .{});
    try stdout.flush();
}
