const std = @import("std");
const primitives = @import("../primitives.zig");
const hex_mod = @import("../hex.zig");

const ethereum = @import("ethereum.zig");
const arbitrum = @import("arbitrum.zig");
const optimism = @import("optimism.zig");
const base = @import("base.zig");
const polygon = @import("polygon.zig");

pub const Address = primitives.Address;

pub const NativeCurrency = struct {
    name: []const u8,
    symbol: []const u8,
    decimals: u8,
};

pub const Contract = struct {
    address: Address,
    block_created: ?u64 = null,
};

pub const BlockExplorer = struct {
    name: []const u8,
    url: []const u8,
};

pub const Chain = struct {
    id: u64,
    name: []const u8,
    native_currency: NativeCurrency,
    rpc_urls: []const []const u8,
    block_explorers: []const BlockExplorer,
    multicall3: ?Contract = null,
    ens_registry: ?Contract = null,
    testnet: bool = false,
};

/// Parse a hex address string into a 20-byte address.
/// Works at both comptime and runtime.
pub fn addressFromHex(hex_str: []const u8) Address {
    return hex_mod.hexToBytesFixed(20, hex_str) catch unreachable;
}

/// Look up a chain by ID.
pub fn getChain(id: u64) ?Chain {
    return switch (id) {
        // Ethereum
        1 => ethereum.mainnet,
        11155111 => ethereum.sepolia,
        17000 => ethereum.holesky,
        // Arbitrum
        42161 => arbitrum.one,
        42170 => arbitrum.nova,
        421614 => arbitrum.sepolia,
        // Optimism
        10 => optimism.mainnet,
        11155420 => optimism.sepolia,
        // Base
        8453 => base.mainnet,
        84532 => base.sepolia,
        // Polygon
        137 => polygon.mainnet,
        80002 => polygon.amoy,
        else => null,
    };
}

// -- Tests --

test "getChain returns known chains" {
    const eth_mainnet = getChain(1);
    try std.testing.expect(eth_mainnet != null);
    try std.testing.expectEqual(@as(u64, 1), eth_mainnet.?.id);
    try std.testing.expectEqualStrings("Ethereum", eth_mainnet.?.name);
    try std.testing.expectEqual(false, eth_mainnet.?.testnet);

    const arb_one = getChain(42161);
    try std.testing.expect(arb_one != null);
    try std.testing.expectEqual(@as(u64, 42161), arb_one.?.id);

    const op_mainnet = getChain(10);
    try std.testing.expect(op_mainnet != null);
    try std.testing.expectEqual(@as(u64, 10), op_mainnet.?.id);

    const base_mainnet = getChain(8453);
    try std.testing.expect(base_mainnet != null);
    try std.testing.expectEqual(@as(u64, 8453), base_mainnet.?.id);

    const poly_mainnet = getChain(137);
    try std.testing.expect(poly_mainnet != null);
    try std.testing.expectEqual(@as(u64, 137), poly_mainnet.?.id);
}

test "getChain returns null for unknown chain" {
    try std.testing.expect(getChain(999999) == null);
}

test "getChain testnets are marked correctly" {
    const sepolia = getChain(11155111);
    try std.testing.expect(sepolia != null);
    try std.testing.expectEqual(true, sepolia.?.testnet);

    const holesky = getChain(17000);
    try std.testing.expect(holesky != null);
    try std.testing.expectEqual(true, holesky.?.testnet);

    const arb_sepolia = getChain(421614);
    try std.testing.expect(arb_sepolia != null);
    try std.testing.expectEqual(true, arb_sepolia.?.testnet);
}

test "getChain multicall3 addresses match across chains" {
    const expected_multicall3 = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");

    const chain_ids = [_]u64{ 1, 11155111, 17000, 42161, 42170, 421614, 10, 11155420, 8453, 84532, 137, 80002 };

    for (chain_ids) |id| {
        const chain = getChain(id);
        try std.testing.expect(chain != null);
        const mc3 = chain.?.multicall3;
        try std.testing.expect(mc3 != null);
        try std.testing.expect(std.mem.eql(u8, &mc3.?.address, &expected_multicall3));
    }
}

test "addressFromHex produces correct bytes" {
    const addr = addressFromHex("0xcA11bde05977b3631167028862bE2a173976CA11");
    try std.testing.expectEqual(@as(u8, 0xca), addr[0]);
    try std.testing.expectEqual(@as(u8, 0x11), addr[1]);
    try std.testing.expectEqual(@as(u8, 0x11), addr[19]);
}

test "ethereum mainnet has ens_registry" {
    const eth_mainnet = getChain(1);
    try std.testing.expect(eth_mainnet != null);
    try std.testing.expect(eth_mainnet.?.ens_registry != null);

    const expected_ens = addressFromHex("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
    try std.testing.expect(std.mem.eql(u8, &eth_mainnet.?.ens_registry.?.address, &expected_ens));
}

test "non-ethereum chains have no ens_registry" {
    const arb = getChain(42161);
    try std.testing.expect(arb != null);
    try std.testing.expect(arb.?.ens_registry == null);

    const op = getChain(10);
    try std.testing.expect(op != null);
    try std.testing.expect(op.?.ens_registry == null);
}

test "all chains have empty rpc_urls" {
    const chain_ids = [_]u64{ 1, 11155111, 17000, 42161, 42170, 421614, 10, 11155420, 8453, 84532, 137, 80002 };

    for (chain_ids) |id| {
        const chain = getChain(id);
        try std.testing.expect(chain != null);
        try std.testing.expectEqual(@as(usize, 0), chain.?.rpc_urls.len);
    }
}
