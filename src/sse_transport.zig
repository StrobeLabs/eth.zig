const std = @import("std");

// ============================================================================
// Types
// ============================================================================

/// A parsed SSE event as defined by the W3C Server-Sent Events specification.
/// All fields borrow from the underlying line buffer -- they are only valid
/// until the next call to `SseParser.feedLine` or `SseParser.reset`.
pub const SseEvent = struct {
    /// The `event:` field value, or null if omitted (defaults to "message").
    event_type: ?[]const u8 = null,
    /// The `data:` field value, or null if no data line was present.
    data: ?[]const u8 = null,
};

pub const SseError = error{
    ConnectionFailed,
    BadStatus,
};

// ============================================================================
// Parser
// ============================================================================

/// Line-oriented SSE parser.
///
/// Feed lines one at a time via `feedLine`. The parser accumulates `event:`
/// and `data:` fields and emits an `SseEvent` when it sees a blank line
/// (the event boundary per the SSE spec).
///
/// Designed to be testable without any network I/O.
pub const SseParser = struct {
    current_event_type: ?[]const u8 = null,
    current_data: ?[]const u8 = null,

    /// Feed a single line (without trailing `\n` or `\r\n`) to the parser.
    /// Returns an `SseEvent` if a blank line was encountered (event boundary),
    /// or null otherwise.
    pub fn feedLine(self: *SseParser, line: []const u8) ?SseEvent {
        const trimmed = std.mem.trimRight(u8, line, "\r");

        // Blank line = event boundary.
        if (trimmed.len == 0) {
            if (self.current_event_type != null or self.current_data != null) {
                const evt = SseEvent{
                    .event_type = self.current_event_type,
                    .data = self.current_data,
                };
                self.current_event_type = null;
                self.current_data = null;
                return evt;
            }
            return null;
        }

        // Lines starting with ':' are comments -- ignore per spec.
        if (trimmed[0] == ':') return null;

        // Parse "field: value" or "field:value".
        if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
            const field = trimmed[0..colon_idx];
            var value = trimmed[colon_idx + 1 ..];
            // Strip optional single leading space after colon (SSE spec §9.2.6).
            if (value.len > 0 and value[0] == ' ') value = value[1..];

            if (std.mem.eql(u8, field, "event")) {
                self.current_event_type = value;
            } else if (std.mem.eql(u8, field, "data")) {
                self.current_data = value;
            }
            // Other fields (id, retry) are intentionally ignored.
        }

        return null;
    }

    /// Reset accumulated state, e.g. on reconnect.
    pub fn reset(self: *SseParser) void {
        self.current_event_type = null;
        self.current_data = null;
    }
};

// ============================================================================
// Transport
// ============================================================================

/// Connect to an SSE endpoint and call `callback` for each event until the
/// connection closes or an error occurs.
///
/// This function makes a single HTTP request and streams events until EOF.
/// It does NOT reconnect -- wrap this in a loop with exponential backoff for
/// production use (see `SseTransport.subscribeWithReconnect`).
///
/// `extra_headers` are appended after the required `Accept` and `Cache-Control`
/// headers. The caller is responsible for any authentication headers.
pub fn subscribe(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
    callback: *const fn (event: SseEvent) void,
) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    // Build header list: required SSE headers + caller extras.
    const base_headers: []const std.http.Header = &.{
        .{ .name = "Accept", .value = "text/event-stream" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    };
    const all_headers = try std.mem.concat(
        allocator,
        std.http.Header,
        &.{ base_headers, extra_headers },
    );
    defer allocator.free(all_headers);

    var req = try client.request(.GET, uri, .{ .extra_headers = all_headers });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok) {
        return error.BadStatus;
    }

    var parser = SseParser{};
    var transfer_buf: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buf);

    while (true) {
        const line_with_nl = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => return, // normal close
            else => return err,
        };
        const line = line_with_nl[0 .. line_with_nl.len - 1];

        if (parser.feedLine(line)) |evt| {
            callback(evt);
        }
    }
}

/// Options for `subscribeWithReconnect`.
pub const ReconnectOpts = struct {
    /// Initial backoff in milliseconds. Default: 1_000.
    initial_backoff_ms: u64 = 1_000,
    /// Maximum backoff in milliseconds. Default: 30_000.
    max_backoff_ms: u64 = 30_000,
    /// Optional callback invoked before each reconnect attempt.
    /// Receives the backoff delay that will be applied.
    on_reconnect: ?*const fn (backoff_ms: u64) void = null,
};

/// Connect to an SSE endpoint and stream events forever, reconnecting with
/// exponential backoff on disconnection or error.
///
/// This function never returns under normal operation. The caller's thread
/// will be blocked here.
pub fn subscribeWithReconnect(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
    opts: ReconnectOpts,
    callback: *const fn (event: SseEvent) void,
) void {
    var backoff_ms = opts.initial_backoff_ms;

    while (true) {
        if (subscribe(allocator, url, extra_headers, callback)) |_| {
            // Clean close -- reset backoff.
            backoff_ms = opts.initial_backoff_ms;
        } else |_| {}

        if (opts.on_reconnect) |cb| cb(backoff_ms);
        std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
        backoff_ms = @min(backoff_ms * 2, opts.max_backoff_ms);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "SseParser basic event" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: perp_price") == null);
    try std.testing.expect(parser.feedLine("data: {\"price\": 100}") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("perp_price", evt.event_type.?);
    try std.testing.expectEqualStrings("{\"price\": 100}", evt.data.?);
}

test "SseParser ignores comments" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine(": this is a comment") == null);
    try std.testing.expect(parser.feedLine("event: test") == null);
    try std.testing.expect(parser.feedLine(": another comment") == null);
    try std.testing.expect(parser.feedLine("data: hello") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("test", evt.event_type.?);
    try std.testing.expectEqualStrings("hello", evt.data.?);
}

test "SseParser blank line without prior data emits nothing" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("") == null);
    try std.testing.expect(parser.feedLine("") == null);
}

test "SseParser handles event with no data" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: heartbeat") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("heartbeat", evt.event_type.?);
    try std.testing.expect(evt.data == null);
}

test "SseParser handles data with no event type" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("data: orphan") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expect(evt.event_type == null);
    try std.testing.expectEqualStrings("orphan", evt.data.?);
}

test "SseParser resets state" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: test") == null);
    parser.reset();
    try std.testing.expect(parser.feedLine("") == null);
}

test "SseParser handles carriage return in line" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: test\r") == null);
    try std.testing.expect(parser.feedLine("data: value\r") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("test", evt.event_type.?);
    try std.testing.expectEqualStrings("value", evt.data.?);
}

test "SseParser colon without space" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event:no_space") == null);
    try std.testing.expect(parser.feedLine("data:also_no_space") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("no_space", evt.event_type.?);
    try std.testing.expectEqualStrings("also_no_space", evt.data.?);
}

test "SseParser multiple events in sequence" {
    var parser = SseParser{};
    _ = parser.feedLine("event: first");
    _ = parser.feedLine("data: 1");
    const ev1 = parser.feedLine("").?;
    try std.testing.expectEqualStrings("first", ev1.event_type.?);
    _ = parser.feedLine("event: second");
    _ = parser.feedLine("data: 2");
    const ev2 = parser.feedLine("").?;
    try std.testing.expectEqualStrings("second", ev2.event_type.?);
    try std.testing.expectEqualStrings("2", ev2.data.?);
}

test "SseParser data overwrites previous data within same event" {
    var parser = SseParser{};
    _ = parser.feedLine("event: test");
    _ = parser.feedLine("data: first");
    _ = parser.feedLine("data: second");
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("second", evt.data.?);
}

test "SseParser ignores unknown fields (id, retry)" {
    var parser = SseParser{};
    _ = parser.feedLine("id: 12345");
    _ = parser.feedLine("retry: 5000");
    _ = parser.feedLine("event: perp_price");
    _ = parser.feedLine("data: test_data");
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("perp_price", evt.event_type.?);
    try std.testing.expectEqualStrings("test_data", evt.data.?);
}
