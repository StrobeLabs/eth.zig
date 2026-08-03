const std = @import("std");
const chain = @import("chain.zig");

const Chain = chain.Chain;
const NativeCurrency = chain.NativeCurrency;
const Contract = chain.Contract;
const BlockExplorer = chain.BlockExplorer;
const addressFromHex = chain.addressFromHex;

const eth_currency = NativeCurrency{
    .name = "Ether",
    .symbol = "ETH",
    .decimals = 18,
};

const multicall3 = Contract{
    .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
    .block_created = 7654707,
};

pub const one: Chain = .{
    .id = 42161,
    .name = "Arbitrum One",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Arbiscan", .url = "https://arbiscan.io" },
    },
    .multicall3 = multicall3,
};

pub const nova: Chain = .{
    .id = 42170,
    .name = "Arbitrum Nova",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Arbiscan Nova", .url = "https://nova.arbiscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 1746963,
    },
};

pub const sepolia: Chain = .{
    .id = 421614,
    .name = "Arbitrum Sepolia",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Arbiscan Sepolia", .url = "https://sepolia.arbiscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 81930,
    },
    .testnet = true,
};

// -- Tests --

test "arbitrum one chain id and name" {
    try std.testing.expectEqual(@as(u64, 42161), one.id);
    try std.testing.expectEqualStrings("Arbitrum One", one.name);
    try std.testing.expectEqual(false, one.testnet);
}

test "arbitrum one native currency is ETH" {
    try std.testing.expectEqualStrings("Ether", one.native_currency.name);
    try std.testing.expectEqualStrings("ETH", one.native_currency.symbol);
    try std.testing.expectEqual(@as(u8, 18), one.native_currency.decimals);
}

test "arbitrum one multicall3 address" {
    const expected = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expect(one.multicall3 != null);
    try std.testing.expect(std.mem.eql(u8, &one.multicall3.?.address, &expected));
}

test "arbitrum one block explorer" {
    try std.testing.expectEqual(@as(usize, 1), one.block_explorers.len);
    try std.testing.expectEqualStrings("https://arbiscan.io", one.block_explorers[0].url);
}

test "arbitrum nova chain id and name" {
    try std.testing.expectEqual(@as(u64, 42170), nova.id);
    try std.testing.expectEqualStrings("Arbitrum Nova", nova.name);
    try std.testing.expectEqual(false, nova.testnet);
}

test "arbitrum sepolia is testnet" {
    try std.testing.expectEqual(@as(u64, 421614), sepolia.id);
    try std.testing.expectEqualStrings("Arbitrum Sepolia", sepolia.name);
    try std.testing.expectEqual(true, sepolia.testnet);
}
