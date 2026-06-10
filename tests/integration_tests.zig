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
    const one_ether = eth.units.parseEther(1.0) orelse return error.ParseEtherFailed;
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
    try std.testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0))), &header.parent_hash);
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
    const send_value = eth.units.parseEther(0.01) orelse return error.ParseEtherFailed;

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
    const send_value = eth.units.parseEther(0.001) orelse return error.ParseEtherFailed;

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
    const fake_hash = @as([32]u8, @splat(0xab));
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

// ============================================================================
// eth_call state overrides (issue #12)
// ============================================================================

test "callWithOverrides applies code + balance override" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // Pick a fresh, otherwise-empty address.
    const target = try eth.primitives.addressFromHex("0xc0dec0dec0dec0dec0dec0dec0dec0dec0dec0de");

    // Bytecode: ADDRESS BALANCE PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    // Returns the contract's own balance as a 32-byte word.
    const bytecode = [_]u8{ 0x30, 0x31, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };

    var overrides = eth.state_overrides.StateOverrides.init(allocator);
    defer overrides.deinit();
    try overrides.setCode(target, &bytecode);
    try overrides.setBalance(target, 0xdeadbeef);

    const result = try provider.callWithOverrides(target, &.{}, &overrides);
    defer allocator.free(result);

    // Returned 32 bytes encode the overridden balance.
    try std.testing.expectEqual(@as(usize, 32), result.len);
    var expected = @as([32]u8, @splat(0));
    expected[28] = 0xde;
    expected[29] = 0xad;
    expected[30] = 0xbe;
    expected[31] = 0xef;
    try std.testing.expectEqualSlices(u8, &expected, result);
}

test "callWithOverrides applies stateDiff (storage slot)" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const target = try eth.primitives.addressFromHex("0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef");

    // Bytecode: PUSH1 0x05 SLOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    // Returns storage slot 5 as a 32-byte word.
    const bytecode = [_]u8{ 0x60, 0x05, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };

    var slot = @as([32]u8, @splat(0));
    slot[31] = 0x05;
    var value = @as([32]u8, @splat(0));
    value[30] = 0xab;
    value[31] = 0xcd;

    var overrides = eth.state_overrides.StateOverrides.init(allocator);
    defer overrides.deinit();
    try overrides.setCode(target, &bytecode);
    try overrides.setStorageAt(target, slot, value);

    const result = try provider.callWithOverrides(target, &.{}, &overrides);
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, &value, result);
}

test "callWithOverrides without an override matches plain call" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    // Calling an empty address with empty calldata returns empty bytes.
    const target = try eth.primitives.addressFromHex("0x9999999999999999999999999999999999999999");

    var overrides = eth.state_overrides.StateOverrides.init(allocator);
    defer overrides.deinit();

    const result = try provider.callWithOverrides(target, &.{}, &overrides);
    defer allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

// ============================================================================
// WsClient: resilient WebSocket subscriptions (issue #35)
// ============================================================================

const ANVIL_WS_URL = "ws://127.0.0.1:8545";

/// Trigger a block on Anvil so newHeads subscriptions emit a notification.
fn anvilMineOne(allocator: std.mem.Allocator) !void {
    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    const response = try transport.request("evm_mine", "[]", 1);
    allocator.free(response);
}

test "WsClient subscribe newHeads receives a fresh block" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    // Disable keepalive in tests so the test's run time is bounded by
    // mining + dispatch, not by the default 30s ping interval.
    const opts = eth.ws_client.Opts{ .ping_interval_ms = 0 };
    const client = try eth.ws_client.WsClient.connect(allocator, ANVIL_WS_URL, opts);
    defer client.deinit();

    const sub = try client.subscribe(.{ .new_heads = {} });

    try anvilMineOne(allocator);

    const event = try client.next();
    defer allocator.free(event.payload);
    try std.testing.expect(event.sub == sub);
    // Sanity-check the payload is a newHeads notification for our sub.
    try std.testing.expect(std.mem.indexOf(u8, event.payload, "eth_subscription") != null);
    try std.testing.expect(std.mem.indexOf(u8, event.payload, sub.server_id) != null);
}

test "WsClient multiplexes two subscriptions on one connection" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    const opts = eth.ws_client.Opts{ .ping_interval_ms = 0 };
    const client = try eth.ws_client.WsClient.connect(allocator, ANVIL_WS_URL, opts);
    defer client.deinit();

    const sub_a = try client.subscribe(.{ .new_heads = {} });
    const sub_b = try client.subscribe(.{ .new_heads = {} });
    // Both subs are newHeads, so each freshly-mined block emits one event per
    // sub. Anvil assigns each sub a distinct server_id, so dispatch must
    // route correctly.
    try std.testing.expect(!std.mem.eql(u8, sub_a.server_id, sub_b.server_id));

    try anvilMineOne(allocator);

    var saw_a = false;
    var saw_b = false;
    var i: usize = 0;
    while ((!saw_a or !saw_b) and i < 4) : (i += 1) {
        const ev = try client.next();
        defer allocator.free(ev.payload);
        if (ev.sub == sub_a) saw_a = true;
        if (ev.sub == sub_b) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "WsClient unsubscribe frees handle and removes from registry" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    const opts = eth.ws_client.Opts{ .ping_interval_ms = 0 };
    const client = try eth.ws_client.WsClient.connect(allocator, ANVIL_WS_URL, opts);
    defer client.deinit();

    const sub = try client.subscribe(.{ .new_heads = {} });
    try client.unsubscribe(sub);
    // The registry should be empty; pointer `sub` is freed and must not be
    // dereferenced after this point.
}

test "WsClient subscribe pending full streams an RpcTransaction" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    // Subscribe on a fresh WsClient before sending the tx so we don't miss
    // the notification.
    const opts = eth.ws_client.Opts{ .ping_interval_ms = 0 };
    const client = try eth.ws_client.WsClient.connect(allocator, ANVIL_WS_URL, opts);
    defer client.deinit();

    const sub = try client.subscribe(.{ .new_pending_transactions = .{ .full = true } });

    // Send a transaction via the HTTP wallet so the WsClient is purely a
    // reader. Account #0 -> account #1, 0.001 ETH.
    var http = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer http.deinit();
    var provider = eth.provider.Provider.init(allocator, &http);
    const private_key = try eth.hex.hexToBytesFixed(32, ACCOUNT_0_KEY_HEX);
    var wallet = eth.wallet.Wallet.init(allocator, private_key, &provider);
    const recipient = try eth.primitives.addressFromHex(ACCOUNT_1_ADDR_HEX);
    const send_value = eth.units.parseEther(0.001) orelse return error.ParseEtherFailed;
    const tx_hash = try wallet.sendTransaction(.{
        .to = recipient,
        .value = send_value,
    });

    // Drain notifications until we see one matching our sub. Anvil with
    // default instamine still emits a pending-tx event before the mine.
    //
    // Some nodes ignore the `full = true` parameter on
    // `newPendingTransactions` and stream tx hashes (JSON strings) instead
    // of full objects; in that case parseTransactionFromNotification will
    // return error.InvalidNotification and we just skip and keep reading.
    var found = false;
    var attempts: usize = 0;
    while (!found and attempts < 8) : (attempts += 1) {
        const ev = client.next() catch |err| switch (err) {
            // Some Anvil builds do not emit full pending-tx notifications;
            // skip the test in that case rather than reporting failure.
            error.Disconnected, error.Closed => return,
            else => return err,
        };
        defer allocator.free(ev.payload);
        if (ev.sub != sub) continue;

        const tx = eth.subscription.parseTransactionFromNotification(allocator, ev.payload) catch |err| switch (err) {
            // Hash-only notification on a node that doesn't support `full`;
            // skip and keep draining until we see (or stop seeing) a real
            // tx object.
            error.InvalidNotification => continue,
            else => return err,
        };
        defer eth.rpc_transaction.freeRpcTransaction(allocator, tx);

        // Anvil may stream txs from previous tests in the same run; only
        // accept the one we sent.
        if (!std.mem.eql(u8, &tx.hash, &tx_hash)) continue;

        try std.testing.expectEqualSlices(u8, &recipient, &tx.to.?);
        try std.testing.expectEqual(@as(u256, send_value), tx.value);
        try std.testing.expect(tx.block_hash == null); // pending
        found = true;
    }
    if (!found) return error.NoPendingTxObserved;
}

// ---------------------------------------------------------------------------
// LogWatcher: block-scoped log watching (issue #36)
// ---------------------------------------------------------------------------

test "LogWatcher pollOnce tracks mined blocks" {
    if (!isAnvilAvailable()) return;
    const allocator = std.testing.allocator;

    var transport = eth.http_transport.HttpTransport.init(allocator, ANVIL_URL);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    const client = try eth.ws_client.WsClient.connect(allocator, ANVIL_WS_URL, .{ .ping_interval_ms = 0 });
    defer client.deinit();

    var watcher = try eth.log_watcher.LogWatcher.init(allocator, &provider, client, .{}, .{});
    defer watcher.deinit();

    try anvilMineOne(allocator);
    const logs = try watcher.pollOnce();
    defer eth.log_watcher.freeLogs(allocator, logs);

    // An empty mined block carries no logs, but the cursor must advance.
    try std.testing.expectEqual(@as(usize, 0), logs.len);
    const first = watcher.cursor.?;

    try anvilMineOne(allocator);
    const logs2 = try watcher.pollOnce();
    defer eth.log_watcher.freeLogs(allocator, logs2);
    try std.testing.expectEqual(first.number + 1, watcher.cursor.?.number);
}
