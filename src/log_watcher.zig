//! Block-scoped log watching: "on each new block, fetch filtered logs".
//!
//! Combines a `WsClient` newHeads subscription with `Provider.getLogs`,
//! back-filling blocks missed across reconnects and re-fetching ranges
//! when a reorg is detected (parent-hash mismatch on sequential heads).
//!
//! Two APIs are provided:
//! - `LogWatcher`: pull-based; call `pollOnce()` to block until the next
//!   head and receive the logs for the planned block range.
//! - `watchLogs`: callback-based convenience loop per issue #36.

const std = @import("std");
const block_mod = @import("block.zig");
const receipt_mod = @import("receipt.zig");
const json_rpc = @import("json_rpc.zig");
const provider_mod = @import("provider.zig");
const ws_client_mod = @import("ws_client.zig");
const subscription_mod = @import("subscription.zig");

pub const WatchOpts = struct {
    /// How many blocks behind the first observed head to start fetching
    /// from. Default: 0 (only the current head).
    start_block_lag: u64 = 0,
    /// Re-fetch logs for reorged ranges when a parent-hash mismatch is
    /// detected. Logs may be delivered more than once in that case;
    /// consumers should key on (block_hash, log_index). Default: true.
    handle_reorgs: bool = true,
};

/// The last block the watcher fully processed.
pub const Cursor = struct {
    number: u64,
    hash: [32]u8,
};

pub const RangePlan = struct {
    from: u64,
    to: u64,
    /// True when this range re-fetches blocks that were already
    /// delivered, because the chain reorged underneath us.
    reorg: bool,
};

/// Decide which block range to fetch logs for, given the previously
/// processed head (`last`) and a newly received header. Returns null when
/// the header should be skipped entirely (duplicate head with reorg
/// handling disabled).
pub fn planRange(last: ?Cursor, header: *const block_mod.BlockHeader, opts: WatchOpts) ?RangePlan {
    const cur = last orelse {
        const lag = @min(opts.start_block_lag, header.number);
        return .{ .from = header.number - lag, .to = header.number, .reorg = false };
    };

    if (header.number <= cur.number) {
        // The node re-announced an old height: a reorg replaced a block we
        // already processed. Re-fetch only that height -- the new chain may
        // be shorter than our previous head, and replacement heads for the
        // remaining heights arrive as their own notifications (the cursor
        // follows them once this header is processed).
        if (!opts.handle_reorgs) return null;
        return .{ .from = header.number, .to = header.number, .reorg = true };
    }

    if (header.number == cur.number + 1) {
        if (opts.handle_reorgs and !std.mem.eql(u8, &header.parent_hash, &cur.hash)) {
            // Sequential head whose parent is not the block we processed:
            // our head was reorged out. Re-fetch it together with the new
            // block.
            return .{ .from = cur.number, .to = header.number, .reorg = true };
        }
        return .{ .from = header.number, .to = header.number, .reorg = false };
    }

    // Gap (e.g. reconnect): back-fill everything we missed. Parent hashes
    // cannot be verified across a gap, so no reorg detection here.
    return .{ .from = cur.number + 1, .to = header.number, .reorg = false };
}

/// Free a slice of logs returned by `pollOnce`.
pub fn freeLogs(allocator: std.mem.Allocator, logs: []receipt_mod.Log) void {
    for (logs) |log| {
        allocator.free(log.data);
        if (log.topics.len > 0) allocator.free(log.topics);
    }
    if (logs.len > 0) allocator.free(logs);
}

pub const LogWatcher = struct {
    allocator: std.mem.Allocator,
    provider: *provider_mod.Provider,
    client: *ws_client_mod.WsClient,
    sub: *ws_client_mod.Subscription,
    /// Only `address` and `topics` are used; block bounds are set per
    /// fetched range.
    filter: json_rpc.LogFilter,
    opts: WatchOpts,
    cursor: ?Cursor,

    /// Subscribe to newHeads on `client` and watch logs matching `filter`.
    /// The watcher does not own `provider` or `client`; it does own the
    /// subscription it creates.
    pub fn init(
        allocator: std.mem.Allocator,
        provider: *provider_mod.Provider,
        client: *ws_client_mod.WsClient,
        filter: json_rpc.LogFilter,
        opts: WatchOpts,
    ) !LogWatcher {
        const sub = try client.subscribe(.{ .new_heads = {} });
        return .{
            .allocator = allocator,
            .provider = provider,
            .client = client,
            .sub = sub,
            .filter = filter,
            .opts = opts,
            .cursor = null,
        };
    }

    pub fn deinit(self: *LogWatcher) void {
        self.client.unsubscribe(self.sub) catch {};
    }

    /// Block until the next newHeads notification for this watcher's
    /// subscription, then fetch and return the logs for the planned block
    /// range. Returns an empty slice when the range contains no matching
    /// logs. Caller owns the result; free it with `freeLogs`.
    ///
    /// Notifications belonging to other subscriptions multiplexed on the
    /// same client are dropped; do not share the client's event stream
    /// with other consumers while a watcher is polling.
    pub fn pollOnce(self: *LogWatcher) ![]receipt_mod.Log {
        while (true) {
            const event = try self.client.next();
            defer self.allocator.free(event.payload);
            if (event.sub != self.sub) continue;

            const header = subscription_mod.parseBlockFromNotification(self.allocator, event.payload) catch {
                continue;
            };
            defer self.allocator.free(header.extra_data);

            const plan = planRange(self.cursor, &header, self.opts) orelse continue;
            const logs = try self.fetchRange(plan.from, plan.to);
            self.cursor = .{ .number = header.number, .hash = header.hash };
            return logs;
        }
    }

    fn fetchRange(self: *LogWatcher, from: u64, to: u64) ![]receipt_mod.Log {
        const from_hex = try std.fmt.allocPrint(self.allocator, "0x{x}", .{from});
        defer self.allocator.free(from_hex);
        const to_hex = try std.fmt.allocPrint(self.allocator, "0x{x}", .{to});
        defer self.allocator.free(to_hex);

        return self.provider.getLogs(.{
            .fromBlock = from_hex,
            .toBlock = to_hex,
            .address = self.filter.address,
            .topics = self.filter.topics,
        });
    }
};

/// Callback-based convenience wrapper (issue #36): subscribes to newHeads
/// and invokes `callback` for every matching log, forever. Only returns on
/// error (e.g. `error.Disconnected` once the client's retry budget is
/// exhausted). The log passed to the callback is freed after the callback
/// returns; copy anything that must outlive it.
pub fn watchLogs(
    allocator: std.mem.Allocator,
    provider: *provider_mod.Provider,
    client: *ws_client_mod.WsClient,
    filter: json_rpc.LogFilter,
    opts: WatchOpts,
    callback: *const fn (log: *const receipt_mod.Log) void,
) !void {
    var watcher = try LogWatcher.init(allocator, provider, client, filter, opts);
    defer watcher.deinit();

    while (true) {
        const logs = try watcher.pollOnce();
        defer freeLogs(allocator, logs);
        for (logs) |*log| callback(log);
    }
}

// -- Tests --

fn testHeader(number: u64, hash_byte: u8, parent_byte: u8) block_mod.BlockHeader {
    return .{
        .number = number,
        .hash = @splat(hash_byte),
        .parent_hash = @splat(parent_byte),
        .nonce = null,
        .sha3_uncles = @splat(0),
        .miner = @splat(0),
        .state_root = @splat(0),
        .transactions_root = @splat(0),
        .receipts_root = @splat(0),
        .logs_bloom = @splat(0),
        .difficulty = 0,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = &.{},
        .mix_hash = @splat(0),
        .base_fee_per_gas = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
    };
}

test "planRange - first head with no lag" {
    const header = testHeader(100, 0xaa, 0xbb);
    const plan = planRange(null, &header, .{}).?;
    try std.testing.expectEqual(@as(u64, 100), plan.from);
    try std.testing.expectEqual(@as(u64, 100), plan.to);
    try std.testing.expect(!plan.reorg);
}

test "planRange - first head applies start_block_lag" {
    const header = testHeader(100, 0xaa, 0xbb);
    const plan = planRange(null, &header, .{ .start_block_lag = 10 }).?;
    try std.testing.expectEqual(@as(u64, 90), plan.from);
    try std.testing.expectEqual(@as(u64, 100), plan.to);
}

test "planRange - start_block_lag saturates at genesis" {
    const header = testHeader(3, 0xaa, 0xbb);
    const plan = planRange(null, &header, .{ .start_block_lag = 10 }).?;
    try std.testing.expectEqual(@as(u64, 0), plan.from);
}

test "planRange - sequential head fetches exactly one block" {
    const header = testHeader(101, 0xcc, 0xaa);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    const plan = planRange(cursor, &header, .{}).?;
    try std.testing.expectEqual(@as(u64, 101), plan.from);
    try std.testing.expectEqual(@as(u64, 101), plan.to);
    try std.testing.expect(!plan.reorg);
}

test "planRange - gap back-fills missed blocks" {
    const header = testHeader(105, 0xcc, 0xdd);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    const plan = planRange(cursor, &header, .{}).?;
    try std.testing.expectEqual(@as(u64, 101), plan.from);
    try std.testing.expectEqual(@as(u64, 105), plan.to);
    try std.testing.expect(!plan.reorg);
}

test "planRange - parent mismatch re-fetches reorged head" {
    // New head 101 whose parent is NOT our processed block 100.
    const header = testHeader(101, 0xcc, 0xee);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    const plan = planRange(cursor, &header, .{}).?;
    try std.testing.expectEqual(@as(u64, 100), plan.from);
    try std.testing.expectEqual(@as(u64, 101), plan.to);
    try std.testing.expect(plan.reorg);
}

test "planRange - parent mismatch ignored when handle_reorgs is off" {
    const header = testHeader(101, 0xcc, 0xee);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    const plan = planRange(cursor, &header, .{ .handle_reorgs = false }).?;
    try std.testing.expectEqual(@as(u64, 101), plan.from);
    try std.testing.expect(!plan.reorg);
}

test "planRange - re-announced old height re-fetches that block" {
    const header = testHeader(99, 0xcc, 0xdd);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    const plan = planRange(cursor, &header, .{}).?;
    try std.testing.expectEqual(@as(u64, 99), plan.from);
    try std.testing.expectEqual(@as(u64, 99), plan.to);
    try std.testing.expect(plan.reorg);
}

test "planRange - old height skipped when handle_reorgs is off" {
    const header = testHeader(99, 0xcc, 0xdd);
    const cursor = Cursor{ .number = 100, .hash = @splat(0xaa) };
    try std.testing.expect(planRange(cursor, &header, .{ .handle_reorgs = false }) == null);
}
