const std = @import("std");
const WsTransport = @import("ws_transport.zig").WsTransport;
const json_rpc = @import("json_rpc.zig");
const block_mod = @import("block.zig");
const receipt_mod = @import("receipt.zig");
const primitives = @import("primitives.zig");
const provider_mod = @import("provider.zig");

/// Types of Ethereum subscriptions available via eth_subscribe.
pub const SubscriptionType = enum {
    new_heads,
    logs,
    new_pending_transactions,

    /// Return the string parameter name used in the eth_subscribe call.
    pub fn toParamString(self: SubscriptionType) []const u8 {
        return switch (self) {
            .new_heads => "newHeads",
            .logs => "logs",
            .new_pending_transactions => "newPendingTransactions",
        };
    }
};

/// Filter parameters for log subscriptions.
pub const LogSubscriptionParams = struct {
    address: ?[20]u8 = null,
    topics: ?[]const ?[32]u8 = null,
};

/// Parameters for an eth_subscribe call.
pub const SubscriptionParams = union(enum) {
    new_heads: void,
    logs: LogSubscriptionParams,
    new_pending_transactions: void,

    /// Get the subscription type.
    pub fn subType(self: SubscriptionParams) SubscriptionType {
        return switch (self) {
            .new_heads => .new_heads,
            .logs => .logs,
            .new_pending_transactions => .new_pending_transactions,
        };
    }
};

/// An active Ethereum subscription over WebSocket.
///
/// Created via `subscribe()`, this reads notifications from the transport
/// and can be torn down via `unsubscribe()`.
pub const Subscription = struct {
    id: []const u8, // subscription ID returned by the node (hex string)
    sub_type: SubscriptionType,
    transport: *WsTransport,
    allocator: std.mem.Allocator,

    pub const SubscriptionError = error{
        SubscribeFailed,
        UnsubscribeFailed,
        InvalidResponse,
        ConnectionClosed,
        OutOfMemory,
        InvalidNotification,
        NullResult,
    };

    /// Subscribe to events via eth_subscribe.
    ///
    /// Sends the eth_subscribe JSON-RPC request and extracts the subscription
    /// ID from the response.
    pub fn subscribe(
        allocator: std.mem.Allocator,
        transport: *WsTransport,
        params: SubscriptionParams,
    ) !Subscription {
        const sub_type = params.subType();
        const params_json = try buildSubscribeParams(allocator, params);
        defer allocator.free(params_json);

        const response = transport.request(json_rpc.Method.eth_subscribe, params_json) catch
            return error.SubscribeFailed;
        defer allocator.free(response);

        // Extract subscription ID from the response.
        // Response format: {"jsonrpc":"2.0","id":N,"result":"0xabc123..."}
        const sub_id = extractResultString(allocator, response) catch
            return error.InvalidResponse;

        return .{
            .id = sub_id,
            .sub_type = sub_type,
            .transport = transport,
            .allocator = allocator,
        };
    }

    /// Unsubscribe from events via eth_unsubscribe.
    pub fn unsubscribe(self: *Subscription) !void {
        // Build params: ["0xsubscription_id"]
        const params_json = std.fmt.allocPrint(
            self.allocator,
            "[\"{s}\"]",
            .{self.id},
        ) catch return error.OutOfMemory;
        defer self.allocator.free(params_json);

        const response = self.transport.request(
            json_rpc.Method.eth_unsubscribe,
            params_json,
        ) catch return error.UnsubscribeFailed;
        defer self.allocator.free(response);

        // Free the subscription ID
        self.allocator.free(self.id);
        self.id = "";
    }

    /// Read the next notification (blocking).
    ///
    /// Reads frames from the transport until a subscription notification
    /// matching this subscription's ID is found.
    /// Returns the raw JSON notification. Caller owns the returned memory.
    pub fn next(self: *Subscription) ![]u8 {
        while (true) {
            const msg = self.transport.readMessage() catch return error.ConnectionClosed;
            errdefer self.allocator.free(msg);

            // Check if this is a subscription notification for our ID.
            // Notification format:
            // {"jsonrpc":"2.0","method":"eth_subscription",
            //  "params":{"subscription":"0xabc...","result":{...}}}
            if (isSubscriptionNotification(msg, self.id)) {
                return msg;
            }

            // Not for us - free and keep reading
            self.allocator.free(msg);
        }
    }

    /// Free resources associated with this subscription (does not unsubscribe).
    pub fn deinit(self: *Subscription) void {
        if (self.id.len > 0) {
            self.allocator.free(self.id);
            self.id = "";
        }
    }

    /// For new_heads subscriptions: parse and return the next block header.
    /// Caller owns the returned BlockHeader's allocated fields (extra_data).
    pub fn nextBlock(self: *Subscription, allocator: std.mem.Allocator) !block_mod.BlockHeader {
        const raw = try self.next();
        defer self.allocator.free(raw);
        return parseBlockFromNotification(allocator, raw);
    }

    /// For logs subscriptions: parse and return the next log.
    /// Caller owns the returned Log's allocated fields (topics, data).
    pub fn nextLog(self: *Subscription, allocator: std.mem.Allocator) !receipt_mod.Log {
        const raw = try self.next();
        defer self.allocator.free(raw);
        return parseLogFromNotification(allocator, raw);
    }

    /// For new_pending_transactions subscriptions: return the next transaction hash.
    pub fn nextTxHash(self: *Subscription) ![32]u8 {
        const raw = try self.next();
        defer self.allocator.free(raw);
        return parseTxHashFromNotification(self.allocator, raw);
    }
};

// ---------------------------------------------------------------------------
// Free-function notification parsers
//
// These are the raw building blocks for parsing eth_subscription notifications.
// Subscription's nextBlock/nextLog/nextTxHash methods are thin wrappers around
// them, and ws_client.WsClient uses the same parsers without needing a
// Subscription instance.
// ---------------------------------------------------------------------------

/// Parse a `newHeads` notification payload into a BlockHeader.
/// Caller owns the returned BlockHeader's allocated fields (extra_data).
pub fn parseBlockFromNotification(allocator: std.mem.Allocator, raw: []const u8) !block_mod.BlockHeader {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return error.InvalidNotification;
    defer parsed.deinit();

    const result_val = getNotificationResult(parsed.value) orelse return error.InvalidNotification;

    // Serialize result back and wrap as {"result":...} for reuse with parseBlockHeader.
    const result_json = try std.json.stringifyAlloc(allocator, result_val, .{});
    defer allocator.free(result_json);

    const wrapped = try std.fmt.allocPrint(allocator, "{{\"result\":{s}}}", .{result_json});
    defer allocator.free(wrapped);

    return (try provider_mod.parseBlockHeader(allocator, wrapped)) orelse error.NullResult;
}

/// Parse a `logs` notification payload into a Log.
/// Caller owns the returned Log's allocated fields (topics, data).
pub fn parseLogFromNotification(allocator: std.mem.Allocator, raw: []const u8) !receipt_mod.Log {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return error.InvalidNotification;
    defer parsed.deinit();

    const result_val = getNotificationResult(parsed.value) orelse return error.InvalidNotification;
    if (result_val != .object) return error.InvalidNotification;

    return try provider_mod.parseSingleLog(allocator, result_val.object);
}

/// Parse a `newPendingTransactions` notification payload into a 32-byte tx hash.
pub fn parseTxHashFromNotification(allocator: std.mem.Allocator, raw: []const u8) ![32]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return error.InvalidNotification;
    defer parsed.deinit();

    const result_val = getNotificationResult(parsed.value) orelse return error.InvalidNotification;
    if (result_val != .string) return error.InvalidNotification;

    return primitives.hashFromHex(result_val.string) catch error.InvalidNotification;
}

// ---------------------------------------------------------------------------
// Notification parsing helpers
// ---------------------------------------------------------------------------

/// Extract the `params.result` value from an eth_subscription notification.
/// Notification format: {"jsonrpc":"2.0","method":"eth_subscription",
///                       "params":{"subscription":"0x...","result":{...}}}
/// Returns null if the JSON does not match the expected notification structure.
pub fn getNotificationResult(root: std.json.Value) ?std.json.Value {
    if (root != .object) return null;
    const params_val = root.object.get("params") orelse return null;
    if (params_val != .object) return null;
    return params_val.object.get("result");
}

// ---------------------------------------------------------------------------
// JSON building helpers
// ---------------------------------------------------------------------------

/// Build the params array for an eth_subscribe call.
/// Returns an allocated JSON string like: ["newHeads"] or ["logs",{"address":"0x...","topics":["0x..."]}]
pub fn buildSubscribeParams(allocator: std.mem.Allocator, params: SubscriptionParams) ![]u8 {
    switch (params) {
        .new_heads => {
            return std.fmt.allocPrint(allocator, "[\"{s}\"]", .{SubscriptionType.new_heads.toParamString()}) catch return error.OutOfMemory;
        },
        .new_pending_transactions => {
            return std.fmt.allocPrint(allocator, "[\"{s}\"]", .{SubscriptionType.new_pending_transactions.toParamString()}) catch return error.OutOfMemory;
        },
        .logs => |log_params| {
            return buildLogSubscribeParams(allocator, log_params) catch return error.OutOfMemory;
        },
    }
}

/// Build params for a log subscription with optional address and topics filters.
fn buildLogSubscribeParams(allocator: std.mem.Allocator, params: LogSubscriptionParams) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[\"logs\",{");

    var has_field = false;

    if (params.address) |addr| {
        try buf.appendSlice(allocator, "\"address\":\"0x");
        var hex_buf: [40]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (addr, 0..) |byte, i| {
            hex_buf[i * 2] = hex_chars[byte >> 4];
            hex_buf[i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        try buf.appendSlice(allocator, &hex_buf);
        try buf.appendSlice(allocator, "\"");
        has_field = true;
    }

    if (params.topics) |topics| {
        if (has_field) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "\"topics\":[");

        for (topics, 0..) |topic_opt, i| {
            if (i > 0) try buf.appendSlice(allocator, ",");
            if (topic_opt) |topic| {
                try buf.appendSlice(allocator, "\"0x");
                var hex_buf: [64]u8 = undefined;
                const hex_chars = "0123456789abcdef";
                for (topic, 0..) |byte, j| {
                    hex_buf[j * 2] = hex_chars[byte >> 4];
                    hex_buf[j * 2 + 1] = hex_chars[byte & 0x0f];
                }
                try buf.appendSlice(allocator, &hex_buf);
                try buf.appendSlice(allocator, "\"");
            } else {
                try buf.appendSlice(allocator, "null");
            }
        }

        try buf.appendSlice(allocator, "]");
    }

    try buf.appendSlice(allocator, "}]");

    return buf.toOwnedSlice(allocator);
}

/// Format a 20-byte address as a "0x" + 40 hex chars string.
pub fn formatAddress(addr: [20]u8) [42]u8 {
    var result: [42]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex_chars = "0123456789abcdef";
    for (addr, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Format a 32-byte hash/topic as a "0x" + 64 hex chars string.
pub fn formatHash(hash: [32]u8) [66]u8 {
    var result: [66]u8 = undefined;
    result[0] = '0';
    result[1] = 'x';
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |byte, i| {
        result[2 + i * 2] = hex_chars[byte >> 4];
        result[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

// ---------------------------------------------------------------------------
// JSON parsing helpers (minimal, no full JSON parser)
//
// These scanners are deliberately not a full JSON parser. They locate a
// `"key" <ws>? : <ws>? value` pattern by string match. JSON spec allows
// arbitrary whitespace around the colon, so each scanner skips spaces and
// tabs (the only whitespace likely on the wire) on either side.
// ---------------------------------------------------------------------------

fn isJsonWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn skipWs(json: []const u8, idx: usize) usize {
    var i = idx;
    while (i < json.len and isJsonWs(json[i])) : (i += 1) {}
    return i;
}

/// Find the first occurrence of `key_quoted` (e.g. `"result"`) and advance
/// past the trailing colon and any surrounding whitespace. Returns the
/// index of the first character of the value, or null if no such pattern
/// exists.
fn findKeyValueStart(json: []const u8, key_quoted: []const u8) ?usize {
    var search_from: usize = 0;
    while (search_from < json.len) {
        const rel = std.mem.indexOf(u8, json[search_from..], key_quoted) orelse return null;
        const key_end = search_from + rel + key_quoted.len;
        var i = skipWs(json, key_end);
        if (i < json.len and json[i] == ':') {
            i = skipWs(json, i + 1);
            return i;
        }
        // Found the substring but it was not a key (e.g. it appeared inside
        // a value). Skip past this match and keep looking.
        search_from = search_from + rel + key_quoted.len;
    }
    return null;
}

/// Extract a string value from a "result": "..." pattern in a JSON response.
/// Tolerant of whitespace around the colon.
/// Caller owns the returned memory.
pub fn extractResultString(allocator: std.mem.Allocator, json: []const u8) ![]u8 {
    const value_start = findKeyValueStart(json, "\"result\"") orelse return error.InvalidResponse;
    if (value_start >= json.len or json[value_start] != '"') return error.InvalidResponse;
    const string_start = value_start + 1;
    const rel_end = std.mem.indexOfScalar(u8, json[string_start..], '"') orelse return error.InvalidResponse;
    const value = json[string_start .. string_start + rel_end];
    const result = try allocator.alloc(u8, value.len);
    @memcpy(result, value);
    return result;
}

/// Check if a JSON message is a subscription notification for the given ID.
pub fn isSubscriptionNotification(json: []const u8, subscription_id: []const u8) bool {
    if (std.mem.indexOf(u8, json, "\"eth_subscription\"") == null) return false;
    const id = getSubscriptionId(json) orelse return false;
    return std.mem.eql(u8, id, subscription_id);
}

/// Return a slice into `json` containing the subscription id from an
/// eth_subscription notification, or null if `json` is not such a
/// notification. The returned slice borrows `json` and is only valid for
/// its lifetime.
pub fn getSubscriptionId(json: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, json, "\"eth_subscription\"") == null) return null;
    const value_start = findKeyValueStart(json, "\"subscription\"") orelse return null;
    if (value_start >= json.len or json[value_start] != '"') return null;
    const id_start = value_start + 1;
    const rel_end = std.mem.indexOfScalar(u8, json[id_start..], '"') orelse return null;
    return json[id_start .. id_start + rel_end];
}

/// Extract a JSON-RPC `id` integer from a response payload by string match.
/// Returns null if the field is absent or the value is not a base-10 integer.
/// This is a fast path for matching responses without full JSON parsing.
pub fn extractResponseId(json: []const u8) ?u64 {
    const value_start = findKeyValueStart(json, "\"id\"") orelse return null;
    var i = value_start;
    while (i < json.len and json[i] >= '0' and json[i] <= '9') : (i += 1) {}
    if (i == value_start) return null;
    return std.fmt.parseInt(u64, json[value_start..i], 10) catch null;
}

// ============================================================================
// Tests
// ============================================================================

test "SubscriptionType toParamString" {
    try std.testing.expectEqualStrings("newHeads", SubscriptionType.new_heads.toParamString());
    try std.testing.expectEqualStrings("logs", SubscriptionType.logs.toParamString());
    try std.testing.expectEqualStrings("newPendingTransactions", SubscriptionType.new_pending_transactions.toParamString());
}

test "SubscriptionParams subType" {
    const heads: SubscriptionParams = .{ .new_heads = {} };
    try std.testing.expectEqual(SubscriptionType.new_heads, heads.subType());

    const logs: SubscriptionParams = .{ .logs = .{} };
    try std.testing.expectEqual(SubscriptionType.logs, logs.subType());

    const pending: SubscriptionParams = .{ .new_pending_transactions = {} };
    try std.testing.expectEqual(SubscriptionType.new_pending_transactions, pending.subType());
}

test "buildSubscribeParams - newHeads" {
    const allocator = std.testing.allocator;
    const params: SubscriptionParams = .{ .new_heads = {} };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("[\"newHeads\"]", result);
}

test "buildSubscribeParams - newPendingTransactions" {
    const allocator = std.testing.allocator;
    const params: SubscriptionParams = .{ .new_pending_transactions = {} };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("[\"newPendingTransactions\"]", result);
}

test "buildSubscribeParams - logs with address only" {
    const allocator = std.testing.allocator;
    const addr = [_]u8{0xde} ** 20;
    const params: SubscriptionParams = .{
        .logs = .{
            .address = addr,
            .topics = null,
        },
    };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "[\"logs\",{") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"address\":\"0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "dededededededededededededededededededededede") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "}]") != null);
}

test "buildSubscribeParams - logs with topics" {
    const allocator = std.testing.allocator;
    const topic1 = [_]u8{0xAA} ** 32;
    const topics = [_]?[32]u8{topic1};
    const params: SubscriptionParams = .{
        .logs = .{
            .address = null,
            .topics = &topics,
        },
    };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"topics\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"") != null);
}

test "buildSubscribeParams - logs with null topic" {
    const allocator = std.testing.allocator;
    const topics = [_]?[32]u8{null};
    const params: SubscriptionParams = .{
        .logs = .{
            .address = null,
            .topics = &topics,
        },
    };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"topics\":[null]") != null);
}

test "buildSubscribeParams - logs with address and topics" {
    const allocator = std.testing.allocator;
    const addr = [_]u8{0x11} ** 20;
    const topic1 = [_]u8{0x22} ** 32;
    const topic2 = [_]u8{0x33} ** 32;
    const topics = [_]?[32]u8{ topic1, null, topic2 };
    const params: SubscriptionParams = .{
        .logs = .{
            .address = addr,
            .topics = &topics,
        },
    };
    const result = try buildSubscribeParams(allocator, params);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"address\":\"0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"topics\":[\"0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "null") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "}]") != null);
}

test "extractResultString - valid response" {
    const allocator = std.testing.allocator;
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xabc123\"}";
    const result = try extractResultString(allocator, json);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("0xabc123", result);
}

test "extractResultString - no result field" {
    const allocator = std.testing.allocator;
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{}}";
    try std.testing.expectError(error.InvalidResponse, extractResultString(allocator, json));
}

test "extractResultString - subscription ID" {
    const allocator = std.testing.allocator;
    const json = "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":\"0xd4fa99a1c58b62afcf949be14e35b8cc\"}";
    const result = try extractResultString(allocator, json);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("0xd4fa99a1c58b62afcf949be14e35b8cc", result);
}

test "isSubscriptionNotification - matching" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"subscription\":\"0xabc\",\"result\":{\"number\":\"0x1\"}}}";

    try std.testing.expect(isSubscriptionNotification(json, "0xabc"));
}

test "isSubscriptionNotification - non-matching ID" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"subscription\":\"0xdef\",\"result\":{}}}";

    try std.testing.expect(!isSubscriptionNotification(json, "0xabc"));
}

test "isSubscriptionNotification - not a notification" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xabc\"}";
    try std.testing.expect(!isSubscriptionNotification(json, "0xabc"));
}

test "isSubscriptionNotification - newHeads notification" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"subscription\":\"0x9ce59a13059e417087c02d3236a0b1cc\"," ++
        "\"result\":{\"parentHash\":\"0x0000\",\"number\":\"0x1\"}}}";

    try std.testing.expect(isSubscriptionNotification(json, "0x9ce59a13059e417087c02d3236a0b1cc"));
    try std.testing.expect(!isSubscriptionNotification(json, "0xdeadbeef"));
}

test "formatAddress" {
    const addr = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const result = formatAddress(addr);
    try std.testing.expectEqualStrings("0xdeadbeef00112233445566778899aabbccddeeff", &result);
}

test "formatHash" {
    const hash = [_]u8{0xAB} ** 32;
    const result = formatHash(hash);
    try std.testing.expect(result[0] == '0');
    try std.testing.expect(result[1] == 'x');
    try std.testing.expectEqualStrings("0xabababababababababababababababababababababababababababababababababab", &result);
}

test "getNotificationResult - new_heads notification" {
    const json =
        \\{"jsonrpc":"2.0","method":"eth_subscription",
        \\ "params":{"subscription":"0xabc","result":{"number":"0x5","hash":"0xdeadbeef"}}}
    ;
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const result = getNotificationResult(parsed.value);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? == .object);
    try std.testing.expect(result.?.object.get("number") != null);
}

test "getNotificationResult - not a notification" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xabc\"}";
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const result = getNotificationResult(parsed.value);
    try std.testing.expect(result == null);
}

test "getNotificationResult - pending tx notification (string result)" {
    const json =
        \\{"jsonrpc":"2.0","method":"eth_subscription",
        \\ "params":{"subscription":"0xabc","result":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}
    ;
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const result = getNotificationResult(parsed.value);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? == .string);
}

test "Subscription struct layout" {
    // Verify the struct can be created with expected fields
    var sub = Subscription{
        .id = "0xtest",
        .sub_type = .new_heads,
        .transport = undefined,
        .allocator = std.testing.allocator,
    };

    try std.testing.expectEqualStrings("0xtest", sub.id);
    try std.testing.expectEqual(SubscriptionType.new_heads, sub.sub_type);

    // Prevent deinit from freeing non-allocated memory
    sub.id = "";
}

test "getSubscriptionId - matching" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"subscription\":\"0xabcdef\",\"result\":{}}}";
    const id = getSubscriptionId(json) orelse return error.TestExpectedSome;
    try std.testing.expectEqualStrings("0xabcdef", id);
}

test "getSubscriptionId - not a notification" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xabc\"}";
    try std.testing.expect(getSubscriptionId(json) == null);
}

test "getSubscriptionId - missing subscription field" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"result\":{}}}";
    try std.testing.expect(getSubscriptionId(json) == null);
}

test "extractResponseId - simple" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":\"0xabc\"}";
    try std.testing.expectEqual(@as(?u64, 42), extractResponseId(json));
}

test "extractResponseId - whitespace tolerant" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\": 7,\"result\":1}";
    try std.testing.expectEqual(@as(?u64, 7), extractResponseId(json));
}

test "extractResponseId - missing id" {
    const json = "{\"jsonrpc\":\"2.0\",\"method\":\"x\"}";
    try std.testing.expect(extractResponseId(json) == null);
}

test "extractResponseId - non-numeric id" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":1}";
    try std.testing.expect(extractResponseId(json) == null);
}

test "extractResultString - whitespace around colon" {
    const allocator = std.testing.allocator;
    const json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\" : \"0xabc\"}";
    const result = try extractResultString(allocator, json);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xabc", result);
}

test "getSubscriptionId - whitespace around colon" {
    const json =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{ \"subscription\" : \"0xWS\", \"result\":{}}}";
    const id = getSubscriptionId(json) orelse return error.TestExpectedSome;
    try std.testing.expectEqualStrings("0xWS", id);
}

test "extractResponseId - whitespace before colon" {
    const json = "{\"jsonrpc\":\"2.0\",\"id\" : 99,\"result\":1}";
    try std.testing.expectEqual(@as(?u64, 99), extractResponseId(json));
}

test "extractResultString - skips key found inside a value" {
    // `"result"` appears inside the error message, but is not a key. The
    // scanner must keep looking until it finds a real `"result":` key.
    const allocator = std.testing.allocator;
    const json =
        "{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"description\":\"the \\\"result\\\" was unexpected\"," ++
        "\"result\":\"0xreal\"}";
    const result = try extractResultString(allocator, json);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xreal", result);
}
