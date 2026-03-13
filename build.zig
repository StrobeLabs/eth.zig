const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library module
    const eth_module = b.addModule("eth", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addXkcp(b, eth_module, target);
    addSecp256k1(b, eth_module);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "eth", .module = eth_module },
            },
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests (requires Anvil)
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "eth", .module = eth_module },
            },
        }),
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_step = b.step("integration-test", "Run integration tests (requires Anvil)");
    integration_step.dependOn(&run_integration_tests.step);

    // Benchmarks (always ReleaseFast for meaningful numbers)
    const bench_module = b.addModule("eth_bench", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = true,
    });
    addXkcp(b, bench_module, target);
    addSecp256k1(b, bench_module);

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
            },
        }),
    });

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks (ReleaseFast)");
    bench_step.dependOn(&run_bench.step);

    // u256-only benchmark (custom harness, no zbench dependency)
    const u256_bench_exe = b.addExecutable(.{
        .name = "u256-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/u256_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
            },
        }),
    });

    const run_u256_bench = b.addRunArtifact(u256_bench_exe);
    const u256_bench_step = b.step("bench-u256", "Run u256-only benchmarks (ReleaseFast)");
    u256_bench_step.dependOn(&run_u256_bench.step);

    // Keccak comparison benchmark (eth.zig vs stdlib)
    const keccak_compare_exe = b.addExecutable(.{
        .name = "keccak-compare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/keccak_compare.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
            },
        }),
    });

    const run_keccak_compare = b.addRunArtifact(keccak_compare_exe);
    const keccak_compare_step = b.step("bench-keccak", "Compare eth.zig Keccak vs stdlib (ReleaseFast)");
    keccak_compare_step.dependOn(&run_keccak_compare.step);

    // Keccak CLI benchmark (for hyperfine comparison)
    const keccak_bench_exe = b.addExecutable(.{
        .name = "keccak-bench-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/keccak_bench_cli.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
            },
        }),
    });
    b.installArtifact(keccak_bench_exe);
}

/// Add XKCP keccak C sources to a module with CPU-appropriate backend selection.
fn addXkcp(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    // XKCP's plain64 backend casts input data to uint64_t* without alignment
    // guarantees (KeccakP1600_plain64_AddLanes). Disable alignment sanitizer to
    // avoid UBSan traps in debug builds; unaligned u64 loads are fast on all
    // modern targets (x86_64, aarch64).
    const c_flags = &.{ "-O3", "-fno-sanitize=alignment" };

    // Common include paths
    module.addIncludePath(b.path("src/crypto/xkcp/common"));
    module.addIncludePath(b.path("src/crypto/xkcp/high"));

    // Select backend based on target CPU
    const arch = target.result.cpu.arch;
    if (arch == .aarch64) {
        // XKCP's ARMv8A NEON assembly uses GAS syntax incompatible with clang's
        // integrated assembler. Use the optimized generic 64-bit C backend instead,
        // which LLVM will optimize with NEON auto-vectorization.
        module.addIncludePath(b.path("src/crypto/xkcp/plain64"));
        module.addCSourceFile(.{
            .file = b.path("src/crypto/xkcp/plain64/KeccakP-1600-opt64.c"),
            .flags = c_flags,
        });
    } else if (arch == .x86_64) {
        const features = target.result.cpu.features;
        const avx512f = @intFromEnum(std.Target.x86.Feature.avx512f);
        const avx2 = @intFromEnum(std.Target.x86.Feature.avx2);

        if (features.isEnabled(avx512f)) {
            // AVX512 SnP header must come before plain64 to shadow KeccakP-1600-SnP.h
            module.addIncludePath(b.path("src/crypto/xkcp/avx512"));
            module.addIncludePath(b.path("src/crypto/xkcp/plain64"));
            module.addAssemblyFile(b.path("src/crypto/xkcp/avx512/KeccakP-1600-AVX512.s"));
        } else if (features.isEnabled(avx2)) {
            // AVX2 SnP header must come before plain64 to shadow KeccakP-1600-SnP.h
            module.addIncludePath(b.path("src/crypto/xkcp/avx2"));
            module.addIncludePath(b.path("src/crypto/xkcp/plain64"));
            module.addAssemblyFile(b.path("src/crypto/xkcp/avx2/KeccakP-1600-AVX2.s"));
        } else {
            module.addIncludePath(b.path("src/crypto/xkcp/plain64"));
            module.addCSourceFile(.{
                .file = b.path("src/crypto/xkcp/plain64/KeccakP-1600-opt64.c"),
                .flags = c_flags,
            });
        }
    } else {
        // Generic 64-bit fallback
        module.addIncludePath(b.path("src/crypto/xkcp/plain64"));
        module.addCSourceFile(.{
            .file = b.path("src/crypto/xkcp/plain64/KeccakP-1600-opt64.c"),
            .flags = c_flags,
        });
    }

    // High-level API (sponge + hash)
    module.addCSourceFile(.{
        .file = b.path("src/crypto/xkcp/high/KeccakSponge.c"),
        .flags = c_flags,
    });
    module.addCSourceFile(.{
        .file = b.path("src/crypto/xkcp/high/KeccakHash.c"),
        .flags = c_flags,
    });
}

/// Add libsecp256k1 (Bitcoin Core) C sources for high-performance EC operations.
fn addSecp256k1(b: *std.Build, module: *std.Build.Module) void {
    const c_flags = &.{
        "-DENABLE_MODULE_RECOVERY=1", // ecrecover -- essential for Ethereum
        "-DENABLE_MODULE_ECDH=1",
        "-DENABLE_MODULE_EXTRAKEYS=1",
        "-DENABLE_MODULE_SCHNORRSIG=1",
        "-DENABLE_MODULE_ELLSWIFT=1",
        "-DECMULT_WINDOW_SIZE=15",
        "-DCOMB_BLOCKS=43",
        "-DCOMB_TEETH=6",
        "-O2",
        "-Wno-unused-function",
    };

    module.addIncludePath(b.path("src/crypto/secp256k1/include"));
    module.addIncludePath(b.path("src/crypto/secp256k1/src"));

    // Unity build: 3 C files
    const src_files = [_][]const u8{
        "src/crypto/secp256k1/src/secp256k1.c",
        "src/crypto/secp256k1/src/precomputed_ecmult.c",
        "src/crypto/secp256k1/src/precomputed_ecmult_gen.c",
    };
    for (src_files) |src| {
        module.addCSourceFile(.{
            .file = b.path(src),
            .flags = c_flags,
        });
    }
}
