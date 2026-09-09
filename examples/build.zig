const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const eth_dep = b.dependency("eth", .{
        .target = target,
        .optimize = optimize,
    });
    const eth_module = eth_dep.module("eth");

    const examples = .{
        .{ "01_derive_address", "01_derive_address.zig" },
        .{ "02_check_balance", "02_check_balance.zig" },
        .{ "03_sign_message", "03_sign_message.zig" },
        .{ "04_send_transaction", "04_send_transaction.zig" },
        .{ "05_read_erc20", "05_read_erc20.zig" },
        .{ "06_hd_wallet", "06_hd_wallet.zig" },
        .{ "07_selectors", "07_selectors.zig" },
        .{ "08_mev_share_backrunner", "08_mev_share_backrunner.zig" },
    };

    const check = b.step("check", "Compile all examples and run the four offline examples");
    inline for (examples, 0..) |example, i| {
        const exe = b.addExecutable(.{
            .name = example[0],
            .root_module = b.createModule(.{
                .root_source_file = b.path(example[1]),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "eth", .module = eth_module },
                },
            }),
        });
        b.installArtifact(exe);
        check.dependOn(&exe.step);
        if (i == 0 or i == 2 or i == 5 or i == 6) {
            check.dependOn(&b.addRunArtifact(exe).step);
        }
    }
}
