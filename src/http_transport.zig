const std = @import("std");

/// HTTP JSON-RPC transport layer.
///
/// Sends JSON-RPC 2.0 requests over HTTP POST to an Ethereum node and returns
/// the raw response body for the caller to parse.
pub const HttpTransport = struct {
    url: []const u8,
    allocator: std.mem.Allocator,
    /// The `std.Io` this transport runs on. Exposed so wrappers (for example
    /// `Provider`) can inherit it as their single source of truth.
    io: std.Io,
    client: std.http.Client,
    /// Diagnostics for the most recent failed request. See lastFailure().
    last_failure: ?Failure = null,

    /// The underlying cause behind the most recent `error.ConnectionFailed`
    /// or `error.HttpError` from request()/requestBatch(). Those two error
    /// names alone are undiagnosable from logs (prod 2026-08-19: an hour of
    /// `ConnectionFailed` with no way to tell DNS from TLS from a dead pooled
    /// connection), so the transport records what actually happened.
    pub const Failure = union(enum) {
        /// `std.http.Client.fetch` failed before an HTTP response arrived
        /// (DNS, TCP connect, TLS handshake, broken pooled connection, ...).
        /// Surfaced to callers as `error.ConnectionFailed`.
        transport: anyerror,
        /// The endpoint answered with a non-200 status (e.g. 429 capacity
        /// limit). Surfaced to callers as `error.HttpError`.
        http_status: std.http.Status,
    };

    pub fn init(allocator: std.mem.Allocator, url: []const u8, io: std.Io) HttpTransport {
        return .{
            .url = url,
            .allocator = allocator,
            .io = io,
            .client = .{ .allocator = allocator, .io = io },
        };
    }

    /// The cause of the most recent request()/requestBatch() failure that was
    /// surfaced as `error.ConnectionFailed` or `error.HttpError`. Null after a
    /// successful request, but also after failures outside those two paths
    /// (e.g. request-body allocation), so null is not proof the last request
    /// succeeded. Valid until the next request on this transport.
    pub fn lastFailure(self: *const HttpTransport) ?Failure {
        return self.last_failure;
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
        self.last_failure = null;
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
                self.last_failure = .{ .http_status = res.status };
                return error.HttpError;
            }
            return response_body.toOwnedSlice();
        } else |err| {
            self.last_failure = .{ .transport = err };
            return error.ConnectionFailed;
        }
    }

    /// Send a JSON-RPC request and return the raw response body.
    /// Caller owns the returned memory.
    pub fn request(self: *HttpTransport, method: []const u8, params_json: []const u8, id: u64) ![]u8 {
        self.last_failure = null;
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
                self.last_failure = .{ .http_status = res.status };
                return error.HttpError;
            }
            return response_body.toOwnedSlice();
        } else |err| {
            self.last_failure = .{ .transport = err };
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
    const runtime = @import("runtime.zig");
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    try std.testing.expectEqualStrings("http://localhost:8545", transport.url);
}

test "init threads caller Io through to the transport" {
    const allocator = std.testing.allocator;
    const runtime = @import("runtime.zig");
    const io = runtime.blockingIo();
    var transport = HttpTransport.init(allocator, "http://localhost:8545", io);
    defer transport.deinit();

    // The transport exposes the exact Io it was constructed with, and forwards
    // it to the underlying http.Client.
    try std.testing.expectEqual(io.userdata, transport.io.userdata);
    try std.testing.expectEqual(io.vtable, transport.io.vtable);
    try std.testing.expectEqual(io.userdata, transport.client.io.userdata);
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

test "request surfaces HttpError on non-200 status without double-freeing the response buffer" {
    // Regression: a JSON-RPC endpoint answering with a non-200 status (e.g.
    // Alchemy's HTTP 429 "Monthly capacity limit exceeded") used to hit both
    // the explicit `response_body.deinit()` and the `errdefer` deinit on the
    // same buffer -- a double free that crashed the process instead of
    // returning `error.HttpError`. The testing allocator detects the double
    // free and fails this test on the old code.
    const allocator = std.testing.allocator;
    const runtime = @import("runtime.zig");
    const io = runtime.blockingIo();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(@TypeOf(bound));
    if (std.c.getsockname(server.socket.handle, @ptrCast(&bound), &bound_len) != 0)
        return error.GetSockNameFailed;
    const port = std.mem.bigToNative(u16, bound.port);

    const serve = struct {
        fn run(srv: *std.Io.net.Server, io_: std.Io) void {
            var served: usize = 0;
            while (served < 2) : (served += 1) {
                var stream = srv.accept(io_) catch return;
                defer stream.close(io_);

                // Read whatever part of the request has arrived (a single
                // recv is enough for the client to have flushed its write),
                // answer, then drain until the client closes so the response
                // is not lost to a reset.
                var scratch: [4096]u8 = undefined;
                _ = std.c.recv(stream.socket.handle, &scratch, scratch.len, 0);

                const resp = "HTTP/1.1 429 Too Many Requests\r\n" ++
                    "content-type: application/json\r\n" ++
                    "content-length: 2\r\n" ++
                    "connection: close\r\n\r\n{}";
                var wbuf: [256]u8 = undefined;
                var writer = stream.writer(io_, &wbuf);
                writer.interface.writeAll(resp) catch return;
                writer.interface.flush() catch return;
                stream.shutdown(io_, .send) catch {};
                while (true) {
                    const n = std.c.recv(stream.socket.handle, &scratch, scratch.len, 0);
                    if (n <= 0) break;
                }
            }
        }
    }.run;
    const server_thread = try std.Thread.spawn(.{}, serve, .{ &server, io });
    defer server_thread.join();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port});
    var transport = HttpTransport.init(allocator, url, io);
    defer transport.deinit();

    // Two calls: the second exercises the transport again after the first
    // error path, catching any allocator state corrupted by the first.
    try std.testing.expectError(error.HttpError, transport.request("eth_blockNumber", "[]", 1));
    try std.testing.expectEqual(
        HttpTransport.Failure{ .http_status = .too_many_requests },
        transport.lastFailure().?,
    );
    try std.testing.expectError(error.HttpError, transport.request("eth_blockNumber", "[]", 2));
    try std.testing.expectEqual(
        HttpTransport.Failure{ .http_status = .too_many_requests },
        transport.lastFailure().?,
    );
}

test "lastFailure captures the transport-level cause of ConnectionFailed" {
    const allocator = std.testing.allocator;
    const runtime = @import("runtime.zig");
    const io = runtime.blockingIo();

    // Bind an ephemeral port, then close the listener so connecting to it is
    // refused. The transport must surface error.ConnectionFailed to the
    // caller while recording the real cause in lastFailure().
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(@TypeOf(bound));
    if (std.c.getsockname(server.socket.handle, @ptrCast(&bound), &bound_len) != 0)
        return error.GetSockNameFailed;
    const port = std.mem.bigToNative(u16, bound.port);
    server.deinit(io);

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port});
    var transport = HttpTransport.init(allocator, url, io);
    defer transport.deinit();

    try std.testing.expect(transport.lastFailure() == null);
    try std.testing.expectError(error.ConnectionFailed, transport.request("eth_blockNumber", "[]", 1));
    const failure = transport.lastFailure() orelse return error.TestExpectedFailureRecorded;
    try std.testing.expect(failure == .transport);
    try std.testing.expectEqual(@as(anyerror, error.ConnectionRefused), failure.transport);
}
