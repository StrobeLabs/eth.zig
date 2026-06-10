const std = @import("std");

/// A transaction object as returned by Ethereum JSON-RPC methods like
/// `eth_getTransactionByHash`, `eth_getTransactionByBlockHashAndIndex`, and
/// the full-tx variant of `newPendingTransactions` (geth: `eth_subscribe(
/// "newPendingTransactions", true)`).
///
/// This is distinct from the canonical signing-time `Transaction` union in
/// `transaction.zig`. RPC responses include fields the signing types do not
/// (hash, recovered `from`, optional block-position fields), and gas-pricing
/// fields are sparse depending on the transaction type.
///
/// Fields whose presence depends on the transaction type:
///
/// - `gas_price` is set for legacy (type 0) and EIP-2930 (type 1). For
///   EIP-1559 (type 2) and EIP-4844 (type 3) it is the effective gas price
///   when the tx is mined; when pending, nodes return the legacy
///   gasPrice-equivalent computed from the priority fee.
/// - `max_fee_per_gas` and `max_priority_fee_per_gas` are set for EIP-1559
///   and EIP-4844.
/// - `max_fee_per_blob_gas` is set only for EIP-4844.
/// - `chain_id` is required for typed transactions and present for EIP-155
///   legacy transactions; null for pre-EIP-155 legacy.
/// - `block_hash`, `block_number`, `transaction_index` are null while the
///   transaction is in the mempool (pending) and set once mined.
///
/// The fields `access_list` and `blob_versioned_hashes` are intentionally
/// omitted from the v1 parser; both are rare in mempool sniping and add
/// significant parsing surface area. They can be added later without a
/// breaking change.
pub const RpcTransaction = struct {
    // ----- Identity & position -----
    hash: [32]u8,
    nonce: u64,
    block_hash: ?[32]u8,
    block_number: ?u64,
    transaction_index: ?u32,

    // ----- Parties & value -----
    from: [20]u8,
    /// Null for contract creation transactions.
    to: ?[20]u8,
    value: u256,

    // ----- Gas & pricing -----
    gas: u64,
    gas_price: ?u256,
    max_fee_per_gas: ?u256,
    max_priority_fee_per_gas: ?u256,
    max_fee_per_blob_gas: ?u256,

    // ----- Calldata (heap-owned) -----
    /// Caller owns this memory; free with `freeRpcTransaction`.
    input: []const u8,

    // ----- Signature -----
    /// EIP-2718 v value: 0/1 for typed transactions, 27/28 for pre-155
    /// legacy, chain_id*2+35 / chain_id*2+36 for EIP-155 legacy.
    v: u256,
    r: [32]u8,
    s: [32]u8,

    // ----- Type & chain -----
    /// 0 = legacy, 1 = EIP-2930, 2 = EIP-1559, 3 = EIP-4844.
    type_: u8,
    chain_id: ?u64,
};

/// Free heap-owned memory inside an RpcTransaction.
pub fn freeRpcTransaction(allocator: std.mem.Allocator, tx: RpcTransaction) void {
    allocator.free(tx.input);
}

// ============================================================================
// Tests
// ============================================================================

test "RpcTransaction struct layout" {
    const tx = RpcTransaction{
        .hash = @as([32]u8, @splat(0xaa)),
        .nonce = 5,
        .block_hash = null,
        .block_number = null,
        .transaction_index = null,
        .from = @as([20]u8, @splat(0x11)),
        .to = @as([20]u8, @splat(0x22)),
        .value = 1_000_000_000_000_000_000,
        .gas = 21_000,
        .gas_price = 20_000_000_000,
        .max_fee_per_gas = null,
        .max_priority_fee_per_gas = null,
        .max_fee_per_blob_gas = null,
        .input = &.{},
        .v = 27,
        .r = @as([32]u8, @splat(0x33)),
        .s = @as([32]u8, @splat(0x44)),
        .type_ = 0,
        .chain_id = 1,
    };

    try std.testing.expectEqual(@as(u64, 5), tx.nonce);
    try std.testing.expectEqual(@as(u8, 0), tx.type_);
    try std.testing.expect(tx.block_hash == null);
    try std.testing.expect(tx.gas_price != null);
    try std.testing.expect(tx.max_fee_per_gas == null);
}

test "freeRpcTransaction frees the input slice" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, 4);
    @memcpy(input, "abcd");
    const tx = RpcTransaction{
        .hash = @as([32]u8, @splat(0)),
        .nonce = 0,
        .block_hash = null,
        .block_number = null,
        .transaction_index = null,
        .from = @as([20]u8, @splat(0)),
        .to = null,
        .value = 0,
        .gas = 0,
        .gas_price = null,
        .max_fee_per_gas = null,
        .max_priority_fee_per_gas = null,
        .max_fee_per_blob_gas = null,
        .input = input,
        .v = 0,
        .r = @as([32]u8, @splat(0)),
        .s = @as([32]u8, @splat(0)),
        .type_ = 2,
        .chain_id = null,
    };
    // If freeRpcTransaction does not free input, the testing allocator
    // would report a leak.
    freeRpcTransaction(allocator, tx);
}
