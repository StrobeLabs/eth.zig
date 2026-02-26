// Integration tests for eth.zig against a local Anvil instance.
// These tests require Anvil running at http://127.0.0.1:8545.
//
// Start Anvil before running:
//   anvil
//
// Run tests:
//   zig build integration-test

const std = @import("std");
const eth = @import("eth");

const ANVIL_URL = "http://127.0.0.1:8545";
const ANVIL_HOST = "127.0.0.1";
const ANVIL_PORT = 8545;

// Anvil pre-funded account #0
const ACCOUNT_0_KEY_HEX = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ACCOUNT_0_ADDR_HEX = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

// Anvil pre-funded account #1
const ACCOUNT_1_ADDR_HEX = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

// Anvil default chain ID
const ANVIL_CHAIN_ID: u64 = 31337;

/// Check if Anvil is reachable by opening a TCP connection to 127.0.0.1:8545.
/// This avoids going through the HTTP client which can crash on connection refused.
fn isAnvilAvailable() bool {
    const addr = std.net.Address.parseIp4(ANVIL_HOST, ANVIL_PORT) catch return false;
    const stream = std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0) catch return false;
    defer std.posix.close(stream);
    std.posix.connect(stream, &addr.any, addr.getOsSockLen()) catch return false;
    return true;
}

// ============================================================================
// Chain state tests
// ============================================================================

test "getChainId returns 31337 (Anvil default)" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const chain_id = try provider.getChainId();
    try std.testing.expectEqual(ANVIL_CHAIN_ID, chain_id);
}

test "getBlockNumber returns a value" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const block_number = try provider.getBlockNumber();
    // Anvil starts at block 0; any non-negative value is acceptable.
    try std.testing.expect(block_number >= 0);
}

// ============================================================================
// Account state tests
// ============================================================================

test "getBalance of funded account" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const addr = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    const balance = try provider.getBalance(addr);

    // Anvil accounts start with 10000 ETH. Even after some tests run the
    // balance should be well above 1 ETH (= 10^18 wei).
    const one_ether = eth.units.parseEther(1.0);
    try std.testing.expect(balance >= one_ether);
}

test "getTransactionCount of account" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const addr = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    const nonce = try provider.getTransactionCount(addr);

    // Nonce is a non-negative integer. On a fresh Anvil it is 0, but we
    // do not assert equality because prior test runs may have sent txns.
    try std.testing.expect(nonce >= 0);
}

test "getCode of EOA returns empty" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const addr = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    const code = try provider.getCode(addr);
    defer allocator.free(code);

    // An externally-owned account has no code.
    try std.testing.expectEqual(@as(usize, 0), code.len);
}

// ============================================================================
// Gas tests
// ============================================================================

test "getGasPrice returns non-zero" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const gas_price = try provider.getGasPrice();
    try std.testing.expect(gas_price > 0);
}

test "getMaxPriorityFee returns a value" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // This should not error. The value can be 0 on Anvil.
    _ = try provider.getMaxPriorityFee();
}

// ============================================================================
// Block tests
// ============================================================================

test "getBlock for block 0 returns genesis" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const maybe_block = try provider.getBlock(0);
    try std.testing.expect(maybe_block != null);

    const header = maybe_block.?;
    defer allocator.free(header.extra_data);

    try std.testing.expectEqual(@as(u64, 0), header.number);
    // Genesis block parent hash is all zeros.
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &header.parent_hash);
}

test "getBlock for non-existent block returns null" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // Use a very large block number that cannot exist.
    const maybe_block = try provider.getBlock(999_999_999);
    try std.testing.expect(maybe_block == null);
}

// ============================================================================
// Wallet address derivation test
// ============================================================================

test "Wallet.address derives correct address from private key" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const private_key = try eth.hex.hexToBytesFixed(32, ACCOUNT_0_KEY_HEX);
    const wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);

    const addr = try wallet.address();
    const expected = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    try std.testing.expectEqualSlices(u8, &expected, &addr);
}

// ============================================================================
// Transaction tests
// ============================================================================

test "send ETH transfer and verify receipt" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const private_key = try eth.hex.hexToBytesFixed(32, ACCOUNT_0_KEY_HEX);
    var wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);

    const recipient = try eth.primitives.addressFromHex(ACCOUNT_1_ADDR_HEX);
    const send_value = eth.units.parseEther(0.01);

    // Record initial balance of recipient.
    const balance_before = try provider.getBalance(recipient);

    // Send 0.01 ETH from account #0 to account #1.
    const tx_hash = try wallet.sendTransaction(.{
        .to = recipient,
        .value = send_value,
    });

    // Anvil mines transactions immediately, so the receipt should be available
    // right away. Poll up to 10 times (1 second each) just in case.
    const maybe_receipt = try wallet.waitForReceipt(tx_hash, 10);
    try std.testing.expect(maybe_receipt != null);

    const receipt = maybe_receipt.?;

    // Verify receipt fields.
    try std.testing.expectEqual(@as(u8, 1), receipt.status); // success
    try std.testing.expectEqualSlices(u8, &tx_hash, &receipt.transaction_hash);

    // Verify the recipient address in the receipt.
    if (receipt.to) |to_addr| {
        try std.testing.expectEqualSlices(u8, &recipient, &to_addr);
    } else {
        return error.TestUnexpectedResult;
    }

    // Verify the sender address in the receipt.
    const sender = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    try std.testing.expectEqualSlices(u8, &sender, &receipt.from);

    // Verify recipient balance increased by the sent amount.
    const balance_after = try provider.getBalance(recipient);
    try std.testing.expectEqual(balance_before + send_value, balance_after);
}

test "estimateGas for simple ETH transfer" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const from = try eth.primitives.addressFromHex(ACCOUNT_0_ADDR_HEX);
    const to = try eth.primitives.addressFromHex(ACCOUNT_1_ADDR_HEX);

    const gas = try provider.estimateGas(to, &.{}, from);

    // A simple ETH transfer costs exactly 21000 gas.
    try std.testing.expectEqual(@as(u64, 21000), gas);
}

test "sendTransactionAndWait returns receipt directly" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const private_key = try eth.hex.hexToBytesFixed(32, ACCOUNT_0_KEY_HEX);
    var wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);

    const recipient = try eth.primitives.addressFromHex(ACCOUNT_1_ADDR_HEX);
    const send_value = eth.units.parseEther(0.001);

    const receipt = try wallet.sendTransactionAndWait(.{
        .to = recipient,
        .value = send_value,
    }, 10);

    try std.testing.expectEqual(@as(u8, 1), receipt.status);
    try std.testing.expect(receipt.gas_used > 0);
}

test "getTransactionReceipt for unknown hash returns null" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // A made-up transaction hash that does not exist.
    const fake_hash = [_]u8{0xab} ** 32;
    const receipt = try provider.getTransactionReceipt(fake_hash);
    try std.testing.expect(receipt == null);
}

// ============================================================================
// Multiple calls test (stateful provider)
// ============================================================================

test "provider next_id increments across calls" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    try std.testing.expectEqual(@as(u64, 1), provider.next_id);

    _ = try provider.getChainId();
    try std.testing.expect(provider.next_id > 1);

    const id_after_first = provider.next_id;
    _ = try provider.getBlockNumber();
    try std.testing.expect(provider.next_id > id_after_first);
}
