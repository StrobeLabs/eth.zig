const std = @import("std");

/// EIP-155: Simple replay attack protection for legacy transactions.
///
/// For legacy transactions, the v value in the signature encodes both the
/// recovery ID (0 or 1) and the chain ID to prevent cross-chain replay attacks.
///
/// Formula: v = chain_id * 2 + 35 + recovery_id
///
/// Pre-EIP-155 values: v = 27 + recovery_id (chain-agnostic)
/// Apply EIP-155 encoding to a recovery ID for a given chain ID.
/// Returns the EIP-155 v value: chain_id * 2 + 35 + recovery_id.
///
/// For Ethereum mainnet (chain_id=1): v=37 (recovery_id=0) or v=38 (recovery_id=1)
pub fn applyEip155(v: u8, chain_id: u64) u256 {
    return @as(u256, chain_id) * 2 + 35 + @as(u256, v);
}

/// Extract the recovery ID (0 or 1) from an EIP-155 encoded v value.
/// Reverses the formula: recovery_id = v - chain_id * 2 - 35
pub fn recoverFromEip155V(v: u256, chain_id: u64) ?u8 {
    const base: u256 = @as(u256, chain_id) * 2 + 35;
    if (v < base) return null;
    const recovery_id = v - base;
    if (recovery_id > 1) return null;
    return @intCast(recovery_id);
}

/// Check if a v value indicates EIP-155 encoding.
///
/// Pre-EIP-155: v is 27 or 28.
/// EIP-155: v >= 35 (for chain_id >= 0, since chain_id * 2 + 35 >= 35).
///
/// More precisely, v is EIP-155 if v != 27 and v != 28 and v >= 35.
pub fn isEip155(v: u256) bool {
    if (v == 27 or v == 28) return false;
    return v >= 35;
}

/// Convert a pre-EIP-155 v value (27 or 28) to a recovery ID (0 or 1).
pub fn recoverFromLegacyV(v: u256) ?u8 {
    if (v == 27) return 0;
    if (v == 28) return 1;
    return null;
}

/// Convert a recovery ID (0 or 1) to a pre-EIP-155 v value (27 or 28).
pub fn toLegacyV(recovery_id: u8) u8 {
    return recovery_id + 27;
}

/// Extract the chain ID from an EIP-155 v value.
/// Returns null if the v value is not EIP-155 encoded.
pub fn chainIdFromV(v: u256) ?u64 {
    if (!isEip155(v)) return null;
    // chain_id = (v - 35) / 2
    const chain_id_256 = (v - 35) / 2;
    if (chain_id_256 > std.math.maxInt(u64)) return null;
    return @intCast(chain_id_256);
}

// ============================================================================
// Tests
// ============================================================================

test "applyEip155 - Ethereum mainnet (chain_id=1)" {
    // recovery_id=0: 1*2 + 35 + 0 = 37
    try std.testing.expectEqual(@as(u256, 37), applyEip155(0, 1));
    // recovery_id=1: 1*2 + 35 + 1 = 38
    try std.testing.expectEqual(@as(u256, 38), applyEip155(1, 1));
}

test "applyEip155 - BSC (chain_id=56)" {
    try std.testing.expectEqual(@as(u256, 147), applyEip155(0, 56));
    try std.testing.expectEqual(@as(u256, 148), applyEip155(1, 56));
}

test "applyEip155 - Polygon (chain_id=137)" {
    try std.testing.expectEqual(@as(u256, 309), applyEip155(0, 137));
    try std.testing.expectEqual(@as(u256, 310), applyEip155(1, 137));
}

test "applyEip155 - Arbitrum (chain_id=42161)" {
    try std.testing.expectEqual(@as(u256, 84357), applyEip155(0, 42161));
    try std.testing.expectEqual(@as(u256, 84358), applyEip155(1, 42161));
}

test "recoverFromEip155V - Ethereum mainnet" {
    try std.testing.expectEqual(@as(?u8, 0), recoverFromEip155V(37, 1));
    try std.testing.expectEqual(@as(?u8, 1), recoverFromEip155V(38, 1));
}

test "recoverFromEip155V - BSC" {
    try std.testing.expectEqual(@as(?u8, 0), recoverFromEip155V(147, 56));
    try std.testing.expectEqual(@as(?u8, 1), recoverFromEip155V(148, 56));
}

test "recoverFromEip155V - invalid v returns null" {
    try std.testing.expectEqual(@as(?u8, null), recoverFromEip155V(5, 1));
    try std.testing.expectEqual(@as(?u8, null), recoverFromEip155V(100, 1));
}

test "recoverFromEip155V roundtrip" {
    const chain_ids = [_]u64{ 1, 56, 137, 42161, 10, 8453 };
    for (chain_ids) |chain_id| {
        for ([_]u8{ 0, 1 }) |recovery_id| {
            const eip155_v = applyEip155(recovery_id, chain_id);
            const recovered = recoverFromEip155V(eip155_v, chain_id).?;
            try std.testing.expectEqual(recovery_id, recovered);
        }
    }
}

test "isEip155 - pre-EIP-155 values" {
    try std.testing.expect(!isEip155(27));
    try std.testing.expect(!isEip155(28));
}

test "isEip155 - EIP-155 values" {
    try std.testing.expect(isEip155(35)); // chain_id=0
    try std.testing.expect(isEip155(36)); // chain_id=0
    try std.testing.expect(isEip155(37)); // chain_id=1
    try std.testing.expect(isEip155(38)); // chain_id=1
    try std.testing.expect(isEip155(147)); // chain_id=56 (BSC)
}

test "isEip155 - edge cases" {
    try std.testing.expect(!isEip155(0));
    try std.testing.expect(!isEip155(1));
    try std.testing.expect(!isEip155(34));
}

test "recoverFromLegacyV" {
    try std.testing.expectEqual(@as(?u8, 0), recoverFromLegacyV(27));
    try std.testing.expectEqual(@as(?u8, 1), recoverFromLegacyV(28));
    try std.testing.expectEqual(@as(?u8, null), recoverFromLegacyV(37));
    try std.testing.expectEqual(@as(?u8, null), recoverFromLegacyV(0));
}

test "toLegacyV" {
    try std.testing.expectEqual(@as(u8, 27), toLegacyV(0));
    try std.testing.expectEqual(@as(u8, 28), toLegacyV(1));
}

test "chainIdFromV - known chains" {
    try std.testing.expectEqual(@as(?u64, 1), chainIdFromV(37)); // Ethereum mainnet
    try std.testing.expectEqual(@as(?u64, 1), chainIdFromV(38)); // Ethereum mainnet
    try std.testing.expectEqual(@as(?u64, 56), chainIdFromV(147)); // BSC
    try std.testing.expectEqual(@as(?u64, 56), chainIdFromV(148)); // BSC
}

test "chainIdFromV - pre-EIP-155 returns null" {
    try std.testing.expectEqual(@as(?u64, null), chainIdFromV(27));
    try std.testing.expectEqual(@as(?u64, null), chainIdFromV(28));
}

test "chainIdFromV - chain_id=0 edge case" {
    // v=35 or 36 means chain_id=0
    try std.testing.expectEqual(@as(?u64, 0), chainIdFromV(35));
    try std.testing.expectEqual(@as(?u64, 0), chainIdFromV(36));
}

test "applyEip155 and chainIdFromV roundtrip" {
    const chain_ids = [_]u64{ 0, 1, 56, 137, 42161, 10, 8453, 43114 };
    for (chain_ids) |chain_id| {
        const v0 = applyEip155(0, chain_id);
        const v1 = applyEip155(1, chain_id);

        try std.testing.expectEqual(@as(?u64, chain_id), chainIdFromV(v0));
        try std.testing.expectEqual(@as(?u64, chain_id), chainIdFromV(v1));
    }
}
