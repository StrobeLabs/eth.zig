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

const multicall3_contract = Contract{
    .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
    .block_created = 14353601,
};

const ens_registry_contract = Contract{
    .address = addressFromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
    .block_created = 9380380,
};

pub const mainnet: Chain = .{
    .id = 1,
    .name = "Ethereum",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Etherscan", .url = "https://etherscan.io" },
    },
    .multicall3 = multicall3_contract,
    .ens_registry = ens_registry_contract,
    .testnet = false,
};

pub const sepolia: Chain = .{
    .id = 11155111,
    .name = "Sepolia",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Etherscan", .url = "https://sepolia.etherscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 751532,
    },
    .testnet = true,
};

pub const holesky: Chain = .{
    .id = 17000,
    .name = "Holesky",
    .native_currency = eth_currency,
    .rpc_urls = &.{},
    .block_explorers = &.{
        .{ .name = "Etherscan", .url = "https://holesky.etherscan.io" },
    },
    .multicall3 = .{
        .address = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11"),
        .block_created = 77,
    },
    .testnet = true,
};

// -- Tests --

test "mainnet chain id and name" {
    try std.testing.expectEqual(@as(u64, 1), mainnet.id);
    try std.testing.expectEqualStrings("Ethereum", mainnet.name);
    try std.testing.expectEqual(false, mainnet.testnet);
}

test "mainnet native currency" {
    try std.testing.expectEqualStrings("Ether", mainnet.native_currency.name);
    try std.testing.expectEqualStrings("ETH", mainnet.native_currency.symbol);
    try std.testing.expectEqual(@as(u8, 18), mainnet.native_currency.decimals);
}

test "mainnet multicall3 address" {
    const expected = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expect(mainnet.multicall3 != null);
    try std.testing.expect(std.mem.eql(u8, &mainnet.multicall3.?.address, &expected));
}

test "mainnet ens registry" {
    const expected = addressFromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    try std.testing.expect(mainnet.ens_registry != null);
    try std.testing.expect(std.mem.eql(u8, &mainnet.ens_registry.?.address, &expected));
}

test "mainnet block explorer" {
    try std.testing.expectEqual(@as(usize, 1), mainnet.block_explorers.len);
    try std.testing.expectEqualStrings("https://etherscan.io", mainnet.block_explorers[0].url);
}

test "sepolia is testnet" {
    try std.testing.expectEqual(@as(u64, 11155111), sepolia.id);
    try std.testing.expectEqualStrings("Sepolia", sepolia.name);
    try std.testing.expectEqual(true, sepolia.testnet);
}

test "holesky is testnet" {
    try std.testing.expectEqual(@as(u64, 17000), holesky.id);
    try std.testing.expectEqualStrings("Holesky", holesky.name);
    try std.testing.expectEqual(true, holesky.testnet);
}

test "sepolia has no ens_registry" {
    try std.testing.expect(sepolia.ens_registry == null);
}

test "holesky has no ens_registry" {
    try std.testing.expect(holesky.ens_registry == null);
}
