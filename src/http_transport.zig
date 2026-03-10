const std = @import("std");

/// HTTP JSON-RPC transport layer.
///
/// Sends JSON-RPC 2.0 requests over HTTP POST to an Ethereum node and returns
/// the raw response body for the caller to parse.
pub const HttpTransport = struct {
    url: []const u8,
    allocator: std.mem.Allocator,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, url: []const u8) HttpTransport {
        return .{
            .url = url,
            .allocator = allocator,
            .client = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *HttpTransport) void {
        self.client.deinit();
    }

    /// Build a JSON-RPC 2.0 request body from method, pre-serialized params, and id.
    pub fn buildRequestBody(allocator: std.mem.Allocator, method: []const u8, params_json: []const u8, id: u64) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "{\"jsonrpc\":\"2.0\",\"method\":\"");
        try buf.appendSlice(allocator, method);
        try buf.appendSlice(allocator, "\",\"params\":");
        try buf.appendSlice(allocator, params_json);
        try buf.appendSlice(allocator, ",\"id\":");

        // Format the id as a decimal string
        var id_buf: [20]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{id}) catch unreachable;
        try buf.appendSlice(allocator, id_str);

        try buf.append(allocator, '}');

        return buf.toOwnedSlice(allocator);
    }

    /// Build a JSON-RPC 2.0 batch request body from individual request bodies.
    /// Wraps them in a JSON array: [body1,body2,...bodyN]
    /// Caller owns the returned memory.
    pub fn buildBatchBody(allocator: std.mem.Allocator, bodies: []const []const u8) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.append(allocator, '[');
        for (bodies, 0..) |body, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, body);
        }
        try buf.append(allocator, ']');

        return buf.toOwnedSlice(allocator);
    }

    /// Send a batch JSON-RPC request and return the raw response body.
    /// Caller owns the returned memory.
    pub fn requestBatch(self: *HttpTransport, bodies: []const []const u8) ![]u8 {
        const batch_body = try buildBatchBody(self.allocator, bodies);
        defer self.allocator.free(batch_body);

        // Use an allocating writer to collect the response body.
        var response_body: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer response_body.deinit();

        const result = self.client.fetch(.{
            .location = .{ .url = self.url },
            .method = .POST,
            .payload = batch_body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .response_writer = &response_body.writer,
        });

        if (result) |res| {
            if (res.status != .ok) {
                response_body.deinit();
                return error.HttpError;
            }
            return response_body.toOwnedSlice();
        } else |_| {
            response_body.deinit();
            return error.ConnectionFailed;
        }
    }

    /// Send a JSON-RPC request and return the raw response body.
    /// Caller owns the returned memory.
    pub fn request(self: *HttpTransport, method: []const u8, params_json: []const u8, id: u64) ![]u8 {
        const body = try buildRequestBody(self.allocator, method, params_json, id);
        defer self.allocator.free(body);

        // Use an allocating writer to collect the response body.
        var response_body: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer response_body.deinit();

        const result = self.client.fetch(.{
            .location = .{ .url = self.url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .response_writer = &response_body.writer,
        });

        if (result) |res| {
            if (res.status != .ok) {
                response_body.deinit();
                return error.HttpError;
            }
            return response_body.toOwnedSlice();
        } else |_| {
            response_body.deinit();
            return error.ConnectionFailed;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "buildRequestBody - simple method" {
    const allocator = std.testing.allocator;
    const body = try HttpTransport.buildRequestBody(allocator, "eth_chainId", "[]", 1);
    defer allocator.free(body);

    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}",
        body,
    );
}

test "buildRequestBody - with params" {
    const allocator = std.testing.allocator;
    const body = try HttpTransport.buildRequestBody(
        allocator,
        "eth_getBalance",
        "[\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\",\"latest\"]",
        42,
    );
    defer allocator.free(body);

    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\",\"latest\"],\"id\":42}",
        body,
    );
}

test "buildRequestBody - large id" {
    const allocator = std.testing.allocator;
    const body = try HttpTransport.buildRequestBody(allocator, "eth_blockNumber", "[]", 999999);
    defer allocator.free(body);

    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":999999}",
        body,
    );
}

test "buildRequestBody - eth_call with object param" {
    const allocator = std.testing.allocator;
    const body = try HttpTransport.buildRequestBody(
        allocator,
        "eth_call",
        "[{\"to\":\"0xdead\",\"data\":\"0xbeef\"},\"latest\"]",
        7,
    );
    defer allocator.free(body);

    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0xdead\",\"data\":\"0xbeef\"},\"latest\"],\"id\":7}",
        body,
    );
}

test "init and deinit" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", transport.url);
}

test "buildBatchBody - empty" {
    const allocator = std.testing.allocator;
    const body = try HttpTransport.buildBatchBody(allocator, &.{});
    defer allocator.free(body);
    try std.testing.expectEqualStrings("[]", body);
}

test "buildBatchBody - single request" {
    const allocator = std.testing.allocator;
    const req = try HttpTransport.buildRequestBody(allocator, "eth_chainId", "[]", 1);
    defer allocator.free(req);
    const bodies: []const []const u8 = &.{req};
    const batch = try HttpTransport.buildBatchBody(allocator, bodies);
    defer allocator.free(batch);
    // Should be [{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}]
    try std.testing.expect(batch[0] == '[');
    try std.testing.expect(batch[batch.len - 1] == ']');
    try std.testing.expectEqualStrings(req, batch[1 .. batch.len - 1]);
}

test "buildBatchBody - multiple requests" {
    const allocator = std.testing.allocator;
    const req1 = try HttpTransport.buildRequestBody(allocator, "eth_chainId", "[]", 1);
    defer allocator.free(req1);
    const req2 = try HttpTransport.buildRequestBody(allocator, "eth_blockNumber", "[]", 2);
    defer allocator.free(req2);
    const bodies: []const []const u8 = &.{ req1, req2 };
    const batch = try HttpTransport.buildBatchBody(allocator, bodies);
    defer allocator.free(batch);
    try std.testing.expect(batch[0] == '[');
    try std.testing.expect(batch[batch.len - 1] == ']');
    // Should contain a comma between requests
    const comma_count = blk: {
        var count: usize = 0;
        // Count commas outside braces to find separator
        var depth: i32 = 0;
        for (batch) |c| {
            if (c == '{') depth += 1;
            if (c == '}') depth -= 1;
            if (c == ',' and depth == 0) count += 1;
        }
        break :blk count;
    };
    try std.testing.expectEqual(@as(usize, 1), comma_count);
}
