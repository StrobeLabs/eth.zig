const std = @import("std");
const WsTransport = @import("ws_transport.zig").WsTransport;
const json_rpc = @import("json_rpc.zig");

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
};

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
// ---------------------------------------------------------------------------

/// Extract a string value from a "result":"..." pattern in a JSON response.
/// Caller owns the returned memory.
fn extractResultString(allocator: std.mem.Allocator, json: []const u8) ![]u8 {
    // Look for "result":" pattern
    const needle = "\"result\":\"";
    const start = indexOfSubstring(json, needle) orelse return error.InvalidResponse;
    const value_start = start + needle.len;

    // Find closing quote
    const value_end = indexOfFrom(json, value_start, '"') orelse return error.InvalidResponse;

    const value = json[value_start..value_end];
    const result = try allocator.alloc(u8, value.len);
    @memcpy(result, value);
    return result;
}

/// Check if a JSON message is a subscription notification for the given ID.
fn isSubscriptionNotification(json: []const u8, subscription_id: []const u8) bool {
    // Must contain "eth_subscription" method
    if (!containsSubstring(json, "\"eth_subscription\"")) return false;

    // Must contain our subscription ID
    // Look for "subscription":"<id>" pattern
    const needle_prefix = "\"subscription\":\"";
    const prefix_pos = indexOfSubstring(json, needle_prefix) orelse return false;
    const id_start = prefix_pos + needle_prefix.len;

    if (id_start + subscription_id.len > json.len) return false;
    const candidate = json[id_start .. id_start + subscription_id.len];

    return std.mem.eql(u8, candidate, subscription_id);
}

// ---------------------------------------------------------------------------
// String utilities
// ---------------------------------------------------------------------------

fn containsSubstring(haystack: []const u8, needle: []const u8) bool {
    return indexOfSubstring(haystack, needle) != null;
}

fn indexOfSubstring(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len == 0) return 0;
    const limit = haystack.len - needle.len + 1;
    for (0..limit) |i| {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) {
            return i;
        }
    }
    return null;
}

fn indexOfFrom(haystack: []const u8, start: usize, needle: u8) ?usize {
    if (start >= haystack.len) return null;
    const idx = std.mem.indexOfScalar(u8, haystack[start..], needle);
    return if (idx) |i| i + start else null;
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

    try std.testing.expect(containsSubstring(result, "[\"logs\",{"));
    try std.testing.expect(containsSubstring(result, "\"address\":\"0x"));
    try std.testing.expect(containsSubstring(result, "dededededededededededededededededededededede"));
    try std.testing.expect(containsSubstring(result, "}]"));
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

    try std.testing.expect(containsSubstring(result, "\"topics\":["));
    try std.testing.expect(containsSubstring(result, "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
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

    try std.testing.expect(containsSubstring(result, "\"topics\":[null]"));
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

    try std.testing.expect(containsSubstring(result, "\"address\":\"0x"));
    try std.testing.expect(containsSubstring(result, "\"topics\":[\"0x"));
    try std.testing.expect(containsSubstring(result, "null"));
    try std.testing.expect(containsSubstring(result, "}]"));
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
