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

    const zbench_dep = b.dependency("zbench", .{});
    const zbench_mod = zbench_dep.module("zbench");

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
                .{ .name = "zbench", .module = zbench_mod },
            },
        }),
    });

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks (ReleaseFast)");
    bench_step.dependOn(&run_bench.step);

    // Keccak comparison benchmark (eth.zig vs stdlib)
    const keccak_compare_exe = b.addExecutable(.{
        .name = "keccak-compare",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/keccak_compare.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "eth", .module = bench_module },
                .{ .name = "zbench", .module = zbench_mod },
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
    const c_flags = &.{"-O3"};

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
