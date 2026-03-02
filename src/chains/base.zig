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

pub const mainnet: Chain = .{
    .id = 8453,
    .name = "Base",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "BaseScan", .url = "https://basescan.org" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 5022,
    },
};

pub const sepolia: Chain = .{
    .id = 84532,
    .name = "Base Sepolia",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "BaseScan", .url = "https://sepolia.basescan.org" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 1059647,
    },
    .testnet = true,
};

// -- Tests --

test "base mainnet chain id and name" {
    try std.testing.expectEqual(@as(u64, 8453), mainnet.id);
    try std.testing.expectEqualStrings("Base", mainnet.name);
    try std.testing.expectEqual(false, mainnet.testnet);
}

test "base mainnet native currency is ETH" {
    try std.testing.expectEqualStrings("Ether", mainnet.native_currency.name);
    try std.testing.expectEqualStrings("ETH", mainnet.native_currency.symbol);
    try std.testing.expectEqual(@as(u8, 18), mainnet.native_currency.decimals);
}

test "base mainnet multicall3 address" {
    const expected = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expect(mainnet.multicall3 != null);
    try std.testing.expect(std.mem.eql(u8, &mainnet.multicall3.?.address, &expected));
}

test "base mainnet block explorer" {
    try std.testing.expectEqual(@as(usize, 1), mainnet.block_explorers.len);
    try std.testing.expectEqualStrings("https://basescan.org", mainnet.block_explorers[0].url);
}

test "base sepolia is testnet" {
    try std.testing.expectEqual(@as(u64, 84532), sepolia.id);
    try std.testing.expectEqualStrings("Base Sepolia", sepolia.name);
    try std.testing.expectEqual(true, sepolia.testnet);
}

test "base chains have no ens_registry" {
    try std.testing.expect(mainnet.ens_registry == null);
    try std.testing.expect(sepolia.ens_registry == null);
}
