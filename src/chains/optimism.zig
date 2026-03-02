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
    .id = 10,
    .name = "OP Mainnet",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Etherscan", .url = "https://optimistic.etherscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 4286263,
    },
};

pub const sepolia: Chain = .{
    .id = 11155420,
    .name = "OP Sepolia",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Etherscan", .url = "https://sepolia-optimism.etherscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 1620204,
    },
    .testnet = true,
};

// -- Tests --

test "optimism mainnet chain id and name" {
    try std.testing.expectEqual(@as(u64, 10), mainnet.id);
    try std.testing.expectEqualStrings("OP Mainnet", mainnet.name);
    try std.testing.expectEqual(false, mainnet.testnet);
}

test "optimism mainnet native currency is ETH" {
    try std.testing.expectEqualStrings("Ether", mainnet.native_currency.name);
    try std.testing.expectEqualStrings("ETH", mainnet.native_currency.symbol);
    try std.testing.expectEqual(@as(u8, 18), mainnet.native_currency.decimals);
}

test "optimism mainnet multicall3 address" {
    const expected = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expect(mainnet.multicall3 != null);
    try std.testing.expect(std.mem.eql(u8, &mainnet.multicall3.?.address, &expected));
}

test "optimism mainnet block explorer" {
    try std.testing.expectEqual(@as(usize, 1), mainnet.block_explorers.len);
    try std.testing.expectEqualStrings("https://optimistic.etherscan.io", mainnet.block_explorers[0].url);
}

test "optimism sepolia is testnet" {
    try std.testing.expectEqual(@as(u64, 11155420), sepolia.id);
    try std.testing.expectEqualStrings("OP Sepolia", sepolia.name);
    try std.testing.expectEqual(true, sepolia.testnet);
}

test "optimism chains have no ens_registry" {
    try std.testing.expect(mainnet.ens_registry == null);
    try std.testing.expect(sepolia.ens_registry == null);
}
