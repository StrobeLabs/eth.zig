const std = @import("std");

/// Ethereum block header.
pub const BlockHeader = struct {
    number: u64,
    hash: [32]u8,
    parent_hash: [32]u8,
    nonce: ?u64,
    sha3_uncles: [32]u8,
    miner: [20]u8,
    state_root: [32]u8,
    transactions_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    difficulty: u256,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    mix_hash: [32]u8,
    base_fee_per_gas: ?u256, // EIP-1559 (London, post-block 12965000)
    blob_gas_used: ?u64, // EIP-4844 (Dencun)
    excess_blob_gas: ?u64, // EIP-4844 (Dencun)
};

/// Check whether the block header is post-EIP-1559 (London fork).
pub fn isEip1559(header: BlockHeader) bool {
    return header.base_fee_per_gas != null;
}

/// Check whether the block header is post-EIP-4844 (Dencun fork).
pub fn isEip4844(header: BlockHeader) bool {
    return header.blob_gas_used != null and header.excess_blob_gas != null;
}

/// Check whether the block is a proof-of-stake block (difficulty == 0, nonce == null or 0).
pub fn isProofOfStake(header: BlockHeader) bool {
    if (header.difficulty != 0) return false;
    if (header.nonce) |nonce| {
        return nonce == 0;
    }
    return true;
}

// ============================================================================
// Tests
// ============================================================================

test "BlockHeader struct layout" {
    const header = BlockHeader{
        .number = 17_000_000,
        .hash = @as([32]u8, @splat(0xaa)),
        .parent_hash = @as([32]u8, @splat(0xbb)),
        .nonce = 0,
        .sha3_uncles = @as([32]u8, @splat(0xcc)),
        .miner = @as([20]u8, @splat(0x11)),
        .state_root = @as([32]u8, @splat(0xdd)),
        .transactions_root = @as([32]u8, @splat(0xee)),
        .receipts_root = @as([32]u8, @splat(0xff)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_681_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 20_000_000_000,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    try std.testing.expectEqual(@as(u64, 17_000_000), header.number);
    try std.testing.expectEqual(@as(u64, 30_000_000), header.gas_limit);
    try std.testing.expectEqual(@as(?u256, 20_000_000_000), header.base_fee_per_gas);
    try std.testing.expect(header.blob_gas_used == null);
}

test "isEip1559" {
    const pre_london = BlockHeader{
        .number = 12_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 42,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 1_000_000,
        .gas_limit = 15_000_000,
        .gas_used = 10_000_000,
        .timestamp = 1_600_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    const post_london = BlockHeader{
        .number = 13_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 0,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 10_000_000_000,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    try std.testing.expect(!isEip1559(pre_london));
    try std.testing.expect(isEip1559(post_london));
}

test "isEip4844" {
    const dencun = BlockHeader{
        .number = 19_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 0,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_710_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 10_000_000_000,
        .blob_gas_used = 131072,
        .excess_blob_gas = 0,
    };

    const pre_dencun = BlockHeader{
        .number = 17_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 0,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_680_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 10_000_000_000,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    try std.testing.expect(isEip4844(dencun));
    try std.testing.expect(!isEip4844(pre_dencun));
}

test "isProofOfStake" {
    const pos = BlockHeader{
        .number = 17_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 0,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 10_000_000_000,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    const pow = BlockHeader{
        .number = 12_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = 12345,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 5_000_000_000_000,
        .gas_limit = 15_000_000,
        .gas_used = 10_000_000,
        .timestamp = 1_600_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    try std.testing.expect(isProofOfStake(pos));
    try std.testing.expect(!isProofOfStake(pow));
}

test "isProofOfStake with null nonce" {
    const pos_null_nonce = BlockHeader{
        .number = 17_000_000,
        .hash = @as([32]u8, @splat(0)),
        .parent_hash = @as([32]u8, @splat(0)),
        .nonce = null,
        .sha3_uncles = @as([32]u8, @splat(0)),
        .miner = @as([20]u8, @splat(0)),
        .state_root = @as([32]u8, @splat(0)),
        .transactions_root = @as([32]u8, @splat(0)),
        .receipts_root = @as([32]u8, @splat(0)),
        .logs_bloom = @as([256]u8, @splat(0)),
        .difficulty = 0,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{},
        .mix_hash = @as([32]u8, @splat(0)),
        .base_fee_per_gas = 10_000_000_000,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };

    try std.testing.expect(isProofOfStake(pos_null_nonce));
}
