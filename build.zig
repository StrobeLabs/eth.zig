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
    addKzg(b, eth_module);

    // Unit tests. Root the test artifact at src/root.zig so its test block
    // (which direct-imports every module file) actually collects and runs the
    // per-module `test` blocks. Aggregating via `_ = eth.module` field access
    // only forces semantic analysis -- it does NOT collect those tests, so the
    // previous tests-aggregator-rooted artifact compiled assertions without
    // ever executing them. The C backends (XKCP, secp256k1) must be re-attached
    // because this is a fresh module, not the published `eth` module.
    const unit_test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addXkcp(b, unit_test_module, target);
    addSecp256k1(b, unit_test_module);
    addKzg(b, unit_test_module);
    const unit_tests = b.addTest(.{
        .root_module = unit_test_module,
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
    addKzg(b, bench_module);

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
    // -fno-sanitize=undefined: the XKCP permutation does intentional unaligned
    // 64-bit loads (portable optimized C). In Debug builds Zig links the C UBSan
    // runtime, which traps those well-defined accesses; disable it for this
    // vendored third-party code. Production/benchmarks use ReleaseFast where
    // UBSan is off anyway.
    const c_flags = &.{ "-O3", "-fno-sanitize=undefined" };

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
        // Vendored audited C with intentional unaligned access; see addXkcp.
        "-fno-sanitize=undefined",
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

/// Add c-kzg-4844 + blst C sources for real EIP-4844 KZG operations.
///
/// blst is built in portable no-assembly C mode (`-D__BLST_NO_ASM__`) so it
/// uses its pure-C field arithmetic instead of per-arch assembly. This keeps
/// the build robust across targets (no GAS-vs-clang assembler conflicts) at a
/// modest performance cost, acceptable for sidecar construction. See
/// src/crypto/c-kzg/VENDOR.md for pinned versions and rationale.
fn addKzg(b: *std.Build, module: *std.Build.Module) void {
    // blst: portable C backend. `__BLST_PORTABLE__` additionally disables the
    // optional SHA CPU-intrinsics path in src/sha256.h. `-fno-sanitize=undefined`
    // mirrors the other vendored C: blst does intentional unaligned accesses.
    const blst_flags = &.{
        "-D__BLST_NO_ASM__",
        "-D__BLST_PORTABLE__",
        "-O2",
        "-fno-sanitize=undefined",
        "-Wno-unused-function",
    };
    module.addIncludePath(b.path("src/crypto/blst/bindings"));
    // server.c is blst's unity build: it #includes every other src/*.c.
    module.addCSourceFile(.{
        .file = b.path("src/crypto/blst/src/server.c"),
        .flags = blst_flags,
    });

    // c-kzg-4844: ckzg.c is the unity build including every other c-kzg .c file.
    // Needs its own src/ on the include path (so "common/...", "eip4844/..."
    // resolve) plus blst's bindings for "blst.h".
    const ckzg_flags = &.{
        "-O2",
        "-fno-sanitize=undefined",
        "-Wno-unused-function",
    };
    module.addIncludePath(b.path("src/crypto/c-kzg/src"));
    module.addIncludePath(b.path("src/crypto/blst/bindings"));
    module.addCSourceFile(.{
        .file = b.path("src/crypto/c-kzg/src/ckzg.c"),
        .flags = ckzg_flags,
    });
}
