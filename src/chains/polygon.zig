const std = @import("std");
const chain = @import("chain.zig");

const Chain = chain.Chain;
const NativeCurrency = chain.NativeCurrency;
const Contract = chain.Contract;
const BlockExplorer = chain.BlockExplorer;
const addressFromHex = chain.addressFromHex;

const pol_currency = NativeCurrency{
    .name = "POL",
    .symbol = "POL",
    .decimals = 18,
};

pub const mainnet: Chain = .{
    .id = 137,
    .name = "Polygon",
    .native_currency = pol_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "PolygonScan", .url = "https://polygonscan.com" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 25770160,
    },
};

pub const amoy: Chain = .{
    .id = 80002,
    .name = "Polygon Amoy",
    .native_currency = pol_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "PolygonScan", .url = "https://amoy.polygonscan.com" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 3127388,
    },
    .testnet = true,
};

// -- Tests --

test "polygon mainnet chain id and name" {
    try std.testing.expectEqual(@as(u64, 137), mainnet.id);
    try std.testing.expectEqualStrings("Polygon", mainnet.name);
    try std.testing.expectEqual(false, mainnet.testnet);
}

test "polygon mainnet native currency is POL" {
    try std.testing.expectEqualStrings("POL", mainnet.native_currency.name);
    try std.testing.expectEqualStrings("POL", mainnet.native_currency.symbol);
    try std.testing.expectEqual(@as(u8, 18), mainnet.native_currency.decimals);
}

test "polygon mainnet multicall3 address" {
    const expected = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expect(mainnet.multicall3 != null);
    try std.testing.expect(std.mem.eql(u8, &mainnet.multicall3.?.address, &expected));
}

test "polygon mainnet block explorer" {
    try std.testing.expectEqual(@as(usize, 1), mainnet.block_explorers.len);
    try std.testing.expectEqualStrings("https://polygonscan.com", mainnet.block_explorers[0].url);
}

test "polygon amoy is testnet" {
    try std.testing.expectEqual(@as(u64, 80002), amoy.id);
    try std.testing.expectEqualStrings("Polygon Amoy", amoy.name);
    try std.testing.expectEqual(true, amoy.testnet);
}
