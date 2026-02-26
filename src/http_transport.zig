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
