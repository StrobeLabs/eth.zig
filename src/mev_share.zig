//! MEV-Share client (issue #34).
//!
//! Mirrors the API surface of the official `mev-share-client-ts`:
//! - `sendTransaction`: submit a private transaction with MEV hints
//!   (eth_sendPrivateTransaction, delegated to `flashbots.Relay`)
//! - `simulateBundle`: simulate a MEV-Share bundle (mev_simBundle)
//! - `on`: subscribe to the SSE event stream of pending transaction /
//!   bundle hints
//! - `getEventHistory`: fetch historical hints from the event stream API
//!
//! JSON-RPC submission goes through `flashbots.Relay` (X-Flashbots-Signature
//! auth); the event stream and history API are public and unauthenticated.

const std = @import("std");
const flashbots = @import("flashbots.zig");
const sse_transport = @import("sse_transport.zig");
const primitives = @import("primitives.zig");
const hex_mod = @import("hex.zig");
const uint256_mod = @import("uint256.zig");
const receipt_mod = @import("receipt.zig");
const provider_mod = @import("provider.zig");
const runtime = @import("runtime.zig");

// ============================================================================
// Endpoints
// ============================================================================

/// MEV-Share SSE event stream + history API (mainnet).
pub const mainnet_stream_url = "https://mev-share.flashbots.net";
/// MEV-Share SSE event stream + history API (Sepolia).
pub const sepolia_stream_url = "https://mev-share-sepolia.flashbots.net";
/// Flashbots relay JSON-RPC endpoint (mainnet).
pub const mainnet_relay_url = "https://relay.flashbots.net";

pub const MevShareError = error{
    InvalidEvent,
    InvalidResponse,
    RpcError,
    NullResult,
    HttpError,
    ConnectionFailed,
    BadStatus,
};

// ============================================================================
// Event stream types
// ============================================================================

/// A pending transaction hint from the MEV-Share event stream.
///
/// All fields except `hash` are hints the originator chose to reveal; absent
/// hints are null. Heap fields (`logs`, `calldata`) are owned by the caller
/// of the parse function; free with `freePendingEvent`.
pub const PendingTransaction = struct {
    /// Event identifier. Note: this is the keccak256 hash of the underlying
    /// transaction hash (double-hashed), not the transaction hash itself.
    /// For bundle body entries without a revealed hash this is all zeroes.
    hash: [32]u8,
    /// Revealed event logs (logs hint).
    logs: ?[]receipt_mod.Log = null,
    /// Revealed calldata (calldata hint).
    calldata: ?[]u8 = null,
    /// Revealed 4-byte function selector (function_selector hint).
    function_selector: ?[4]u8 = null,
    /// Revealed callee. The wire field is `to`; this is what the
    /// contract_address hint reveals, so both fields carry the same value.
    contract_address: ?[20]u8 = null,
    /// Revealed callee (wire field `to`). Same value as `contract_address`.
    to: ?[20]u8 = null,
    /// Revealed transaction value in wei.
    value: ?u256 = null,
};

/// A pending bundle hint (an event whose `txs` array has more than one
/// entry, matching the mev-share-client-ts heuristic).
pub const PendingBundle = struct {
    /// Event identifier (double-hashed, see PendingTransaction.hash).
    hash: [32]u8,
    /// Revealed event logs for the whole bundle.
    logs: ?[]receipt_mod.Log = null,
    /// Revealed per-transaction hints.
    txs: []PendingTransaction,
};

/// A single event from the MEV-Share SSE stream.
pub const PendingEvent = union(enum) {
    transaction: PendingTransaction,
    bundle: PendingBundle,
};

/// Free all heap data owned by a parsed event.
pub fn freePendingEvent(allocator: std.mem.Allocator, event: *const PendingEvent) void {
    switch (event.*) {
        .transaction => |*tx| freePendingTransaction(allocator, tx),
        .bundle => |*b| {
            if (b.logs) |logs| freeEventLogs(allocator, logs);
            for (b.txs) |*tx| freePendingTransaction(allocator, tx);
            allocator.free(b.txs);
        },
    }
}

fn freePendingTransaction(allocator: std.mem.Allocator, tx: *const PendingTransaction) void {
    if (tx.logs) |logs| freeEventLogs(allocator, logs);
    if (tx.calldata) |cd| allocator.free(cd);
}

/// Free a slice of logs as allocated by the event parsers
/// (same layout as log_watcher.freeLogs).
pub fn freeEventLogs(allocator: std.mem.Allocator, logs: []receipt_mod.Log) void {
    for (logs) |log| {
        allocator.free(log.data);
        if (log.topics.len > 0) allocator.free(log.topics);
    }
    if (logs.len > 0) allocator.free(logs);
}

// ============================================================================
// Event parsing
// ============================================================================

/// Parse one SSE `data:` payload from the MEV-Share event stream into a
/// `PendingEvent`. Pure function -- no I/O.
///
/// Wire shape (https://docs.flashbots.net/flashbots-mev-share/searchers/event-stream):
/// `{"hash":"0x..","logs":[...],"txs":[{"to":"0x..","functionSelector":"0x..","callData":"0x..",...}]}`
///
/// Events whose `txs` array contains more than one entry are classified as
/// bundles; everything else is a single pending transaction (matching the
/// mev-share-client-ts heuristic). Caller owns the result; free it with
/// `freePendingEvent`.
pub fn parseEventData(allocator: std.mem.Allocator, json_line: []const u8) !PendingEvent {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_line, .{}) catch {
        return error.InvalidEvent;
    };
    defer parsed.deinit();

    return parseEventValue(allocator, parsed.value);
}

/// Parse an already-decoded event JSON value (shared by `parseEventData`
/// and the history parser).
fn parseEventValue(allocator: std.mem.Allocator, root: std.json.Value) !PendingEvent {
    if (root != .object) return error.InvalidEvent;
    const obj = root.object;

    const hash_str = jsonGetString(obj, "hash") orelse return error.InvalidEvent;
    const hash = primitives.hashFromHex(hash_str) catch return error.InvalidEvent;

    const logs = try parseEventLogs(allocator, obj);
    errdefer if (logs) |l| freeEventLogs(allocator, l);

    const txs_arr: ?std.json.Array = if (obj.get("txs")) |tv| switch (tv) {
        .array => |a| a,
        .null => null,
        else => return error.InvalidEvent,
    } else null;
    const tx_count: usize = if (txs_arr) |a| a.items.len else 0;

    if (tx_count > 1) {
        const arr = txs_arr.?;
        const txs = try allocator.alloc(PendingTransaction, tx_count);
        var done: usize = 0;
        errdefer {
            for (txs[0..done]) |*tx| freePendingTransaction(allocator, tx);
            allocator.free(txs);
        }
        for (arr.items, 0..) |item, i| {
            if (item != .object) return error.InvalidEvent;
            const entry_hash: [32]u8 = if (jsonGetString(item.object, "hash")) |hs|
                primitives.hashFromHex(hs) catch return error.InvalidEvent
            else
                @splat(0);
            txs[i] = try parseTxEntry(allocator, item.object, entry_hash);
            done += 1;
        }
        return .{ .bundle = .{ .hash = hash, .logs = logs, .txs = txs } };
    }

    var tx: PendingTransaction = if (tx_count == 1) blk: {
        const item = txs_arr.?.items[0];
        if (item != .object) return error.InvalidEvent;
        break :blk try parseTxEntry(allocator, item.object, hash);
    } else .{ .hash = hash };
    tx.logs = logs;
    return .{ .transaction = tx };
}

/// Parse one entry of the `txs` array. `hash` is the identity to assign
/// (the top-level event hash for single-tx events, the entry's own hash --
/// or zeroes -- for bundle bodies).
fn parseTxEntry(allocator: std.mem.Allocator, obj: std.json.ObjectMap, hash: [32]u8) !PendingTransaction {
    var tx = PendingTransaction{ .hash = hash };

    if (jsonGetString(obj, "to")) |s| {
        const addr = primitives.addressFromHex(s) catch return error.InvalidEvent;
        tx.to = addr;
        tx.contract_address = addr;
    }
    if (jsonGetString(obj, "functionSelector")) |s| {
        tx.function_selector = hex_mod.hexToBytesFixed(4, s) catch return error.InvalidEvent;
    }
    if (jsonGetString(obj, "value")) |s| {
        tx.value = uint256_mod.fromHex(s) catch return error.InvalidEvent;
    }
    if (jsonGetString(obj, "callData")) |s| {
        tx.calldata = try hexBytesAlloc(allocator, s);
    }
    return tx;
}

/// Parse the optional top-level `logs` array. Returns null when absent,
/// JSON null, or empty.
fn parseEventLogs(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !?[]receipt_mod.Log {
    const logs_val = obj.get("logs") orelse return null;
    if (logs_val == .null) return null;
    if (logs_val != .array) return error.InvalidEvent;

    const arr = logs_val.array;
    if (arr.items.len == 0) return null;

    const logs = try allocator.alloc(receipt_mod.Log, arr.items.len);
    var done: usize = 0;
    errdefer {
        for (logs[0..done]) |log| {
            allocator.free(log.data);
            if (log.topics.len > 0) allocator.free(log.topics);
        }
        allocator.free(logs);
    }
    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidEvent;
        logs[i] = provider_mod.parseSingleLog(allocator, item.object) catch return error.InvalidEvent;
        done += 1;
    }
    return logs;
}

// ============================================================================
// mev_simBundle types
// ============================================================================

/// Simulation options for mev_simBundle
/// (https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#mev_simbundle).
/// All fields default to relay-side values derived from the parent block.
pub const SimBundleOpts = struct {
    /// Block used for simulation state. Default: latest block.
    parent_block: ?u64 = null,
    /// Simulated block number. Default: parentBlock.number + 1.
    block_number: ?u64 = null,
    /// Simulated coinbase. Default: parentBlock.coinbase.
    coinbase: ?[20]u8 = null,
    /// Simulated timestamp. Default: parentBlock.timestamp + 12.
    timestamp: ?u64 = null,
    /// Simulated gas limit. Default: parentBlock.gasLimit.
    gas_limit: ?u64 = null,
    /// Simulated base fee in wei. Default: parentBlock.baseFeePerGas.
    base_fee: ?u256 = null,
    /// Simulation timeout in seconds. Default: 5.
    /// TODO: the docs do not specify the wire encoding; sent as a plain
    /// JSON number (seconds), matching the documented default ("5").
    timeout: ?u64 = null,
};

/// Per-transaction logs emitted during bundle simulation.
/// TODO: nested `bundleLogs` (logs of inner bundles) are not parsed; the
/// exact recursive wire shape is only documented in mev-share-client-ts.
pub const SimBundleLogs = struct {
    tx_logs: ?[]receipt_mod.Log = null,
};

/// Result of mev_simBundle. Field set verified against the Flashbots RPC
/// docs example response.
pub const SimBundleResult = struct {
    success: bool,
    /// Error description when success is false. TODO: not shown in the
    /// docs example; field name taken from mev-share-client-ts
    /// (SimBundleResult.error).
    error_message: ?[]u8 = null,
    /// Block whose state the simulation ran on.
    state_block: u64 = 0,
    /// Adjusted gas price of the bundle (wei).
    mev_gas_price: u256 = 0,
    /// Total simulated profit (wei).
    profit: u256 = 0,
    /// Portion of the profit that is refundable to hint originators (wei).
    refundable_value: u256 = 0,
    /// Total gas used by the bundle.
    gas_used: u64 = 0,
    /// Logs per bundle body entry, when requested. Null when absent.
    logs: ?[]SimBundleLogs = null,
};

/// Free all heap data owned by a SimBundleResult.
pub fn freeSimBundleResult(allocator: std.mem.Allocator, result: *const SimBundleResult) void {
    if (result.error_message) |msg| allocator.free(msg);
    if (result.logs) |entries| {
        for (entries) |entry| {
            if (entry.tx_logs) |tx_logs| freeEventLogs(allocator, tx_logs);
        }
        allocator.free(entries);
    }
}

// ============================================================================
// Event history types
// ============================================================================

/// Query parameters for GET /api/v1/history.
pub const EventHistoryParams = struct {
    /// Earliest block to fetch hints from.
    block_start: ?u64 = null,
    /// Latest block to fetch hints from.
    block_end: ?u64 = null,
    /// Earliest unix timestamp to fetch hints from.
    timestamp_start: ?u64 = null,
    /// Latest unix timestamp to fetch hints from.
    timestamp_end: ?u64 = null,
    /// Maximum number of entries to return (server caps at maxLimit).
    limit: ?u64 = null,
    /// Offset into the result set, for pagination.
    offset: ?u64 = null,
};

/// One entry from GET /api/v1/history.
pub const EventHistoryEntry = struct {
    block: u64,
    timestamp: u64,
    /// The hint that was broadcast on the event stream.
    hint: PendingEvent,
};

/// Free a slice of history entries returned by `getEventHistory`.
pub fn freeEventHistory(allocator: std.mem.Allocator, entries: []EventHistoryEntry) void {
    for (entries) |*entry| freePendingEvent(allocator, &entry.hint);
    allocator.free(entries);
}

// ============================================================================
// Client
// ============================================================================

/// MEV-Share client: a `flashbots.Relay` (JSON-RPC + auth) plus the public
/// SSE event stream / history endpoint.
pub const MevShareClient = struct {
    allocator: std.mem.Allocator,
    relay: flashbots.Relay,
    /// Base URL of the event stream; also serves /api/v1/history.
    stream_url: []const u8,
    /// HTTP client for the unauthenticated stream/history endpoints.
    client: std.http.Client,

    /// Create a client for the given relay and event stream endpoints.
    /// `auth_key` is the Flashbots reputation key (not a funded key).
    pub fn init(
        allocator: std.mem.Allocator,
        relay_url: []const u8,
        stream_url: []const u8,
        auth_key: [32]u8,
    ) MevShareClient {
        return .{
            .allocator = allocator,
            .relay = flashbots.Relay.init(allocator, relay_url, auth_key),
            .stream_url = stream_url,
            .client = .{ .allocator = allocator, .io = runtime.defaultIo() },
        };
    }

    /// Convenience constructor for Ethereum mainnet.
    pub fn initMainnet(allocator: std.mem.Allocator, auth_key: [32]u8) MevShareClient {
        return init(allocator, mainnet_relay_url, mainnet_stream_url, auth_key);
    }

    pub fn deinit(self: *MevShareClient) void {
        self.relay.deinit();
        self.client.deinit();
    }

    /// Submit a private transaction with MEV hints
    /// (eth_sendPrivateTransaction). Delegates to
    /// `flashbots.Relay.sendPrivateTransaction`. Returns the tx hash.
    pub fn sendTransaction(self: *MevShareClient, opts: flashbots.SendPrivateTxOpts) ![32]u8 {
        const result = try self.relay.sendPrivateTransaction(opts);
        return result.tx_hash;
    }

    /// Simulate a MEV-Share bundle (mev_simBundle). The bundle is described
    /// with the same options as `flashbots.Relay.mevSendBundle`. Caller owns
    /// the result; free it with `freeSimBundleResult`.
    pub fn simulateBundle(
        self: *MevShareClient,
        opts: flashbots.MevSendBundleOpts,
        sim_opts: SimBundleOpts,
    ) !SimBundleResult {
        const params = try buildSimBundleParams(self.allocator, opts, sim_opts);
        defer self.allocator.free(params);

        const raw = try self.relay.authenticatedRequest("mev_simBundle", params);
        defer self.allocator.free(raw);

        return parseSimBundleResult(self.allocator, raw);
    }

    /// Subscribe to the MEV-Share event stream and invoke `callback` for
    /// each pending transaction or bundle hint.
    ///
    /// Blocking: streams until the server closes the connection (returns
    /// normally) or a transport error occurs. Events that fail to parse are
    /// skipped. The event passed to the callback is freed after the callback
    /// returns; copy anything that must outlive it. Wrap in a loop for
    /// reconnection.
    pub fn on(self: *MevShareClient, callback: *const fn (event: PendingEvent) void) !void {
        var parser = sse_transport.SseParser{};

        const uri = try std.Uri.parse(self.stream_url);
        var req = try self.client.request(.GET, uri, .{ .extra_headers = &.{
            .{ .name = "Accept", .value = "text/event-stream" },
            .{ .name = "Cache-Control", .value = "no-cache" },
        } });
        defer req.deinit();

        try req.sendBodiless();

        var redirect_buf: [4096]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);
        if (response.head.status != .ok) return error.BadStatus;

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);

        while (true) {
            const line_with_nl = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
                error.EndOfStream => return, // normal close
                else => return err,
            };
            const line = line_with_nl[0 .. line_with_nl.len - 1];

            if (parser.feedLine(line)) |evt| {
                const event = parseEventData(self.allocator, evt.data) catch continue;
                defer freePendingEvent(self.allocator, &event);
                callback(event);
            }
        }
    }

    /// Fetch historical event stream data (GET /api/v1/history). Caller
    /// owns the result; free it with `freeEventHistory`.
    pub fn getEventHistory(self: *MevShareClient, params: EventHistoryParams) ![]EventHistoryEntry {
        const query = try buildHistoryQuery(self.allocator, params);
        defer self.allocator.free(query);

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/history{s}",
            .{ self.stream_url, query },
        );
        defer self.allocator.free(url);

        var response_body: std.Io.Writer.Allocating = .init(self.allocator);
        defer response_body.deinit();

        const result = self.client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .response_writer = &response_body.writer,
        }) catch return error.ConnectionFailed;

        if (result.status != .ok) return error.HttpError;

        return parseEventHistoryResponse(self.allocator, response_body.writer.buffered());
    }
};

// ============================================================================
// JSON params builders
// ============================================================================

fn formatHexU64(buf: *[18]u8, value: u64) []const u8 {
    buf[0] = '0';
    buf[1] = 'x';
    const hex_chars = "0123456789abcdef";
    if (value == 0) {
        buf[2] = '0';
        return buf[0..3];
    }
    var val = value;
    var len: usize = 0;
    while (val > 0) : (val >>= 4) {
        len += 1;
    }
    val = value;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        buf[2 + i] = hex_chars[@intCast(val & 0xf)];
        val >>= 4;
    }
    return buf[0 .. 2 + len];
}

fn appendHexU64Field(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    first: *bool,
    name: []const u8,
    value: u64,
) !void {
    if (!first.*) try buf.append(allocator, ',');
    first.* = false;
    try buf.append(allocator, '"');
    try buf.appendSlice(allocator, name);
    try buf.appendSlice(allocator, "\":\"");
    var hex_buf: [18]u8 = undefined;
    try buf.appendSlice(allocator, formatHexU64(&hex_buf, value));
    try buf.append(allocator, '"');
}

/// Build the params array for mev_simBundle: `[{bundle},{simOptions}]`.
/// The bundle object is identical to mev_sendBundle's. Caller owns the
/// returned slice.
pub fn buildSimBundleParams(
    allocator: std.mem.Allocator,
    opts: flashbots.MevSendBundleOpts,
    sim_opts: SimBundleOpts,
) ![]u8 {
    // "[{bundle}]" -- splice the sim options object in before the closing ']'.
    const bundle_params = try flashbots.buildMevSendBundleParams(allocator, opts);
    defer allocator.free(bundle_params);

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, bundle_params[0 .. bundle_params.len - 1]);
    try buf.appendSlice(allocator, ",{");

    var first = true;
    if (sim_opts.parent_block) |v| try appendHexU64Field(allocator, &buf, &first, "parentBlock", v);
    if (sim_opts.block_number) |v| try appendHexU64Field(allocator, &buf, &first, "blockNumber", v);
    if (sim_opts.coinbase) |addr| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try buf.appendSlice(allocator, "\"coinbase\":\"");
        const addr_hex = primitives.addressToHex(&addr);
        try buf.appendSlice(allocator, &addr_hex);
        try buf.append(allocator, '"');
    }
    if (sim_opts.timestamp) |v| try appendHexU64Field(allocator, &buf, &first, "timestamp", v);
    if (sim_opts.gas_limit) |v| try appendHexU64Field(allocator, &buf, &first, "gasLimit", v);
    if (sim_opts.base_fee) |v| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try buf.appendSlice(allocator, "\"baseFee\":\"");
        const fee_hex = try uint256_mod.toHex(allocator, v);
        defer allocator.free(fee_hex);
        try buf.appendSlice(allocator, fee_hex);
        try buf.append(allocator, '"');
    }
    if (sim_opts.timeout) |v| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        try buf.appendSlice(allocator, "\"timeout\":");
        var num_buf: [20]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{v}) catch unreachable;
        try buf.appendSlice(allocator, num_str);
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

/// Build the query string for GET /api/v1/history ("" when no params set).
/// Caller owns the returned slice.
pub fn buildHistoryQuery(allocator: std.mem.Allocator, params: EventHistoryParams) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    const fields = [_]struct { name: []const u8, value: ?u64 }{
        .{ .name = "blockStart", .value = params.block_start },
        .{ .name = "blockEnd", .value = params.block_end },
        .{ .name = "timestampStart", .value = params.timestamp_start },
        .{ .name = "timestampEnd", .value = params.timestamp_end },
        .{ .name = "limit", .value = params.limit },
        .{ .name = "offset", .value = params.offset },
    };

    for (fields) |field| {
        const value = field.value orelse continue;
        try buf.append(allocator, if (buf.items.len == 0) '?' else '&');
        try buf.appendSlice(allocator, field.name);
        try buf.append(allocator, '=');
        var num_buf: [20]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{value}) catch unreachable;
        try buf.appendSlice(allocator, num_str);
    }

    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// Response parsing
// ============================================================================

/// Parse a mev_simBundle JSON-RPC response. Caller owns the result; free it
/// with `freeSimBundleResult`.
pub fn parseSimBundleResult(allocator: std.mem.Allocator, raw: []const u8) !SimBundleResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    if (root.object.get("error")) |err_val| {
        if (err_val == .object) return error.RpcError;
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return error.NullResult;
    if (result_val != .object) return error.InvalidResponse;

    const obj = result_val.object;

    const success = switch (obj.get("success") orelse return error.InvalidResponse) {
        .bool => |b| b,
        else => return error.InvalidResponse,
    };

    var result = SimBundleResult{
        .success = success,
        .state_block = (try jsonHexU64(obj, "stateBlock")) orelse 0,
        .mev_gas_price = (try jsonHexU256(obj, "mevGasPrice")) orelse 0,
        .profit = (try jsonHexU256(obj, "profit")) orelse 0,
        .refundable_value = (try jsonHexU256(obj, "refundableValue")) orelse 0,
        .gas_used = (try jsonHexU64(obj, "gasUsed")) orelse 0,
    };
    errdefer freeSimBundleResult(allocator, &result);

    if (jsonGetString(obj, "error")) |msg| {
        result.error_message = try allocator.dupe(u8, msg);
    }

    if (obj.get("logs")) |logs_val| {
        if (logs_val == .array and logs_val.array.items.len > 0) {
            const arr = logs_val.array;
            const entries = try allocator.alloc(SimBundleLogs, arr.items.len);
            var done: usize = 0;
            errdefer {
                for (entries[0..done]) |entry| {
                    if (entry.tx_logs) |tx_logs| freeEventLogs(allocator, tx_logs);
                }
                allocator.free(entries);
            }
            for (arr.items, 0..) |item, i| {
                if (item != .object) return error.InvalidResponse;
                entries[i] = .{ .tx_logs = try parseTxLogs(allocator, item.object) };
                done += 1;
            }
            result.logs = entries;
        }
    }

    return result;
}

/// Parse the optional `txLogs` array of one SimBundleLogs entry.
fn parseTxLogs(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !?[]receipt_mod.Log {
    const logs_val = obj.get("txLogs") orelse return null;
    if (logs_val == .null) return null;
    if (logs_val != .array) return error.InvalidResponse;

    const arr = logs_val.array;
    if (arr.items.len == 0) return null;

    const logs = try allocator.alloc(receipt_mod.Log, arr.items.len);
    var done: usize = 0;
    errdefer {
        for (logs[0..done]) |log| {
            allocator.free(log.data);
            if (log.topics.len > 0) allocator.free(log.topics);
        }
        allocator.free(logs);
    }
    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        logs[i] = provider_mod.parseSingleLog(allocator, item.object) catch return error.InvalidResponse;
        done += 1;
    }
    return logs;
}

/// Parse a GET /api/v1/history response body. Caller owns the result; free
/// it with `freeEventHistory`.
pub fn parseEventHistoryResponse(allocator: std.mem.Allocator, raw: []const u8) ![]EventHistoryEntry {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    if (parsed.value != .array) return error.InvalidResponse;
    const arr = parsed.value.array;

    const entries = try allocator.alloc(EventHistoryEntry, arr.items.len);
    var done: usize = 0;
    errdefer {
        for (entries[0..done]) |*entry| freePendingEvent(allocator, &entry.hint);
        allocator.free(entries);
    }

    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        const obj = item.object;

        const block = jsonGetU64(obj, "block") orelse return error.InvalidResponse;
        const timestamp = jsonGetU64(obj, "timestamp") orelse return error.InvalidResponse;
        const hint_val = obj.get("hint") orelse return error.InvalidResponse;
        const hint = parseEventValue(allocator, hint_val) catch return error.InvalidResponse;

        entries[i] = .{ .block = block, .timestamp = timestamp, .hint = hint };
        done += 1;
    }

    return entries;
}

// ============================================================================
// JSON helpers
// ============================================================================

fn jsonGetString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn jsonGetU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .integer => |i| if (i < 0) null else @intCast(i),
        else => null,
    };
}

/// Read an optional field that is a 0x-hex string or a JSON integer, as u256.
fn jsonHexU256(obj: std.json.ObjectMap, key: []const u8) !?u256 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .null => null,
        .string => |s| uint256_mod.fromHex(s) catch return error.InvalidResponse,
        .integer => |i| if (i < 0) error.InvalidResponse else @as(u256, @intCast(i)),
        else => error.InvalidResponse,
    };
}

/// Read an optional field that is a 0x-hex string or a JSON integer, as u64.
fn jsonHexU64(obj: std.json.ObjectMap, key: []const u8) !?u64 {
    const v = (try jsonHexU256(obj, key)) orelse return null;
    if (v > std.math.maxInt(u64)) return error.InvalidResponse;
    return @intCast(v);
}

/// Decode a 0x-hex string into a freshly allocated byte slice.
fn hexBytesAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const src = if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) s[2..] else s;
    if (src.len % 2 != 0) return error.InvalidEvent;
    const buf = try allocator.alloc(u8, src.len / 2);
    errdefer allocator.free(buf);
    _ = hex_mod.hexToBytes(buf, src) catch return error.InvalidEvent;
    return buf;
}

// ============================================================================
// Tests
// ============================================================================

test "parseEventData - full transaction event" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\"logs":[{"address":"0x1111111111111111111111111111111111111111",
        \\"topics":["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        \\"data":"0x1234"}],
        \\"txs":[{"to":"0x2222222222222222222222222222222222222222",
        \\"functionSelector":"0x23b872dd",
        \\"callData":"0x23b872dd0000",
        \\"value":"0x0de0b6b3a7640000"}]}
    ;

    var event = try parseEventData(allocator, raw);
    defer freePendingEvent(allocator, &event);

    try std.testing.expect(event == .transaction);
    const tx = event.transaction;

    const expected_hash = @as([32]u8, @splat(0xaa));
    try std.testing.expectEqualSlices(u8, &expected_hash, &tx.hash);

    const expected_to = @as([20]u8, @splat(0x22));
    try std.testing.expectEqualSlices(u8, &expected_to, &tx.to.?);
    try std.testing.expectEqualSlices(u8, &expected_to, &tx.contract_address.?);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x23, 0xb8, 0x72, 0xdd }, &tx.function_selector.?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x23, 0xb8, 0x72, 0xdd, 0x00, 0x00 }, tx.calldata.?);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), tx.value.?);

    const logs = tx.logs.?;
    try std.testing.expectEqual(@as(usize, 1), logs.len);
    const expected_log_addr = @as([20]u8, @splat(0x11));
    try std.testing.expectEqualSlices(u8, &expected_log_addr, &logs[0].address);
    try std.testing.expectEqual(@as(usize, 1), logs[0].topics.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34 }, logs[0].data);
}

test "parseEventData - minimal hash-only event" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
    ;

    var event = try parseEventData(allocator, raw);
    defer freePendingEvent(allocator, &event);

    try std.testing.expect(event == .transaction);
    const tx = event.transaction;
    const expected_hash = @as([32]u8, @splat(0xcc));
    try std.testing.expectEqualSlices(u8, &expected_hash, &tx.hash);
    try std.testing.expect(tx.logs == null);
    try std.testing.expect(tx.calldata == null);
    try std.testing.expect(tx.function_selector == null);
    try std.testing.expect(tx.to == null);
    try std.testing.expect(tx.contract_address == null);
    try std.testing.expect(tx.value == null);
}

test "parseEventData - bundle event with txs array" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\"txs":[
        \\{"hash":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        \\"to":"0x3333333333333333333333333333333333333333","callData":"0xabcd"},
        \\{"functionSelector":"0xa9059cbb"}
        \\]}
    ;

    var event = try parseEventData(allocator, raw);
    defer freePendingEvent(allocator, &event);

    try std.testing.expect(event == .bundle);
    const bundle = event.bundle;

    const expected_hash = @as([32]u8, @splat(0xdd));
    try std.testing.expectEqualSlices(u8, &expected_hash, &bundle.hash);
    try std.testing.expectEqual(@as(usize, 2), bundle.txs.len);

    const expected_tx0_hash = @as([32]u8, @splat(0xee));
    try std.testing.expectEqualSlices(u8, &expected_tx0_hash, &bundle.txs[0].hash);
    const expected_to = @as([20]u8, @splat(0x33));
    try std.testing.expectEqualSlices(u8, &expected_to, &bundle.txs[0].to.?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0xcd }, bundle.txs[0].calldata.?);

    // Second entry has no revealed hash -- zeroed identity.
    const zero_hash = @as([32]u8, @splat(0));
    try std.testing.expectEqualSlices(u8, &zero_hash, &bundle.txs[1].hash);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xa9, 0x05, 0x9c, 0xbb }, &bundle.txs[1].function_selector.?);
}

test "parseEventData - malformed payloads" {
    const allocator = std.testing.allocator;

    // Not JSON at all.
    try std.testing.expectError(error.InvalidEvent, parseEventData(allocator, "not json"));
    // Missing required hash.
    try std.testing.expectError(error.InvalidEvent, parseEventData(allocator, "{}"));
    // Hash is not valid hex.
    try std.testing.expectError(error.InvalidEvent, parseEventData(allocator, "{\"hash\":\"0xzz\"}"));
    // Root is not an object.
    try std.testing.expectError(error.InvalidEvent, parseEventData(allocator, "[1,2,3]"));
    // txs is not an array.
    try std.testing.expectError(
        error.InvalidEvent,
        parseEventData(allocator, "{\"hash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"txs\":5}"),
    );
}

test "buildSimBundleParams - bundle with sim options" {
    const allocator = std.testing.allocator;
    const tx_data = &[_]u8{ 0xde, 0xad };
    const body = [_]flashbots.MevBundleBody{
        .{ .tx = .{ .data = tx_data } },
    };

    const params = try buildSimBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 100 },
    }, .{
        .parent_block = 0x8b8da7,
        .timeout = 5,
    });
    defer allocator.free(params);

    try std.testing.expectEqualStrings(
        "[{\"version\":\"v0.1\",\"inclusion\":{\"block\":\"0x64\"},\"body\":[{\"tx\":\"0xdead\"}]},{\"parentBlock\":\"0x8b8da7\",\"timeout\":5}]",
        params,
    );
}

test "buildSimBundleParams - empty sim options emit empty object" {
    const allocator = std.testing.allocator;
    const tx_data = &[_]u8{0xff};
    const body = [_]flashbots.MevBundleBody{
        .{ .tx = .{ .data = tx_data } },
    };

    const params = try buildSimBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 1 },
    }, .{});
    defer allocator.free(params);

    try std.testing.expectEqualStrings(
        "[{\"version\":\"v0.1\",\"inclusion\":{\"block\":\"0x1\"},\"body\":[{\"tx\":\"0xff\"}]},{}]",
        params,
    );
}

test "buildSimBundleParams - all sim options" {
    const allocator = std.testing.allocator;
    const tx_data = &[_]u8{0x01};
    const body = [_]flashbots.MevBundleBody{
        .{ .tx = .{ .data = tx_data } },
    };
    const coinbase = @as([20]u8, @splat(0x42));

    const params = try buildSimBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 2 },
    }, .{
        .parent_block = 1,
        .block_number = 2,
        .coinbase = coinbase,
        .timestamp = 1700000000,
        .gas_limit = 30_000_000,
        .base_fee = 1_000_000_000,
        .timeout = 10,
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"parentBlock\":\"0x1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"blockNumber\":\"0x2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"coinbase\":\"0x4242424242424242424242424242424242424242\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"timestamp\":\"0x6553f100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"gasLimit\":\"0x1c9c380\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"baseFee\":\"0x3b9aca00\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"timeout\":10") != null);
}

test "parseSimBundleResult - success" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":{
        \\"success":true,
        \\"stateBlock":"0x8b8da8",
        \\"mevGasPrice":"0x74c7906005",
        \\"profit":"0x4bc800904fc000",
        \\"refundableValue":"0x4bc800904fc000",
        \\"gasUsed":"0xa620",
        \\"logs":[{"txLogs":[{"address":"0x1111111111111111111111111111111111111111",
        \\"topics":[],"data":"0x"}]},{}]
        \\}}
    ;

    var result = try parseSimBundleResult(allocator, raw);
    defer freeSimBundleResult(allocator, &result);

    try std.testing.expect(result.success);
    try std.testing.expect(result.error_message == null);
    try std.testing.expectEqual(@as(u64, 0x8b8da8), result.state_block);
    try std.testing.expectEqual(@as(u256, 0x74c7906005), result.mev_gas_price);
    try std.testing.expectEqual(@as(u256, 0x4bc800904fc000), result.profit);
    try std.testing.expectEqual(@as(u256, 0x4bc800904fc000), result.refundable_value);
    try std.testing.expectEqual(@as(u64, 0xa620), result.gas_used);

    const logs = result.logs.?;
    try std.testing.expectEqual(@as(usize, 2), logs.len);
    try std.testing.expectEqual(@as(usize, 1), logs[0].tx_logs.?.len);
    try std.testing.expect(logs[1].tx_logs == null);
}

test "parseSimBundleResult - failure with error string" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":{"success":false,"error":"execution reverted"}}
    ;

    var result = try parseSimBundleResult(allocator, raw);
    defer freeSimBundleResult(allocator, &result);

    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("execution reverted", result.error_message.?);
    try std.testing.expectEqual(@as(u64, 0), result.state_block);
}

test "parseSimBundleResult - rpc error" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"sim failed"}}
    ;
    try std.testing.expectError(error.RpcError, parseSimBundleResult(allocator, raw));
}

test "parseSimBundleResult - null result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;
    try std.testing.expectError(error.NullResult, parseSimBundleResult(allocator, raw));
}

test "buildHistoryQuery - empty params" {
    const allocator = std.testing.allocator;
    const query = try buildHistoryQuery(allocator, .{});
    defer allocator.free(query);
    try std.testing.expectEqualStrings("", query);
}

test "buildHistoryQuery - all params" {
    const allocator = std.testing.allocator;
    const query = try buildHistoryQuery(allocator, .{
        .block_start = 1,
        .block_end = 2,
        .timestamp_start = 3,
        .timestamp_end = 4,
        .limit = 10,
        .offset = 20,
    });
    defer allocator.free(query);
    try std.testing.expectEqualStrings(
        "?blockStart=1&blockEnd=2&timestampStart=3&timestampEnd=4&limit=10&offset=20",
        query,
    );
}

test "buildHistoryQuery - subset of params" {
    const allocator = std.testing.allocator;
    const query = try buildHistoryQuery(allocator, .{ .limit = 500, .block_start = 17_000_000 });
    defer allocator.free(query);
    try std.testing.expectEqualStrings("?blockStart=17000000&limit=500", query);
}

test "parseEventHistoryResponse - fixture" {
    const allocator = std.testing.allocator;
    const raw =
        \\[{"block":17000000,"timestamp":1680000000,
        \\"hint":{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\"txs":[{"to":"0x2222222222222222222222222222222222222222","callData":"0xdeadbeef"}]}},
        \\{"block":17000001,"timestamp":1680000012,
        \\"hint":{"hash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]
    ;

    const entries = try parseEventHistoryResponse(allocator, raw);
    defer freeEventHistory(allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(u64, 17000000), entries[0].block);
    try std.testing.expectEqual(@as(u64, 1680000000), entries[0].timestamp);
    try std.testing.expect(entries[0].hint == .transaction);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
        entries[0].hint.transaction.calldata.?,
    );

    try std.testing.expectEqual(@as(u64, 17000001), entries[1].block);
    const expected_hash = @as([32]u8, @splat(0xbb));
    try std.testing.expectEqualSlices(u8, &expected_hash, &entries[1].hint.transaction.hash);
}

test "parseEventHistoryResponse - malformed" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidResponse, parseEventHistoryResponse(allocator, "{}"));
    try std.testing.expectError(error.InvalidResponse, parseEventHistoryResponse(allocator, "not json"));
    try std.testing.expectError(
        error.InvalidResponse,
        parseEventHistoryResponse(allocator, "[{\"block\":1,\"timestamp\":2}]"),
    );
}

test "MevShareClient.init sets endpoints" {
    const auth_key = try hex_mod.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    var client = MevShareClient.initMainnet(std.testing.allocator, auth_key);
    defer client.deinit();

    try std.testing.expectEqualStrings(mainnet_relay_url, client.relay.url);
    try std.testing.expectEqualStrings(mainnet_stream_url, client.stream_url);
}

test "all public declarations compile" {
    // Network paths (on, getEventHistory, simulateBundle) have no unit
    // tests, so force semantic analysis of every declaration to keep
    // lazily-compiled API breakage out (see the Zig 0.16 migration).
    std.testing.refAllDeclsRecursive(@This());
}
