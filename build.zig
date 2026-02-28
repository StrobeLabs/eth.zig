const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library module
    const eth_module = b.addModule("eth", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

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
    });

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
}
