const std = @import("std");
const runtime = @import("runtime.zig");

// ============================================================================
// Types
// ============================================================================

/// A parsed SSE event as defined by the W3C Server-Sent Events specification.
///
/// All slice fields point into buffers owned by the `SseParser` that produced
/// this event. They are valid until the next call to `SseParser.feedLine` or
/// `SseParser.reset`.
pub const SseEvent = struct {
    /// The `id:` field value, or null if omitted.
    id: ?[]const u8 = null,
    /// The `event:` field value, or null if omitted (default event type is "message").
    event: ?[]const u8 = null,
    /// The accumulated `data:` field value. Multiple `data:` lines within one
    /// event are joined with U+000A as required by the spec. Always present
    /// when the event is dispatched (may be an empty slice when the server sent
    /// a bare `data:` line with no value).
    data: []const u8,
};

pub const SseError = error{
    BadStatus,
};

// ============================================================================
// Parser
// ============================================================================

/// Line-oriented SSE parser.
///
/// Feed lines one at a time via `feedLine`. The parser accumulates `event:`,
/// `id:`, and `data:` fields and emits an `SseEvent` when it encounters a
/// blank line (the event boundary per the SSE spec).
///
/// All field values are copied into fixed internal buffers, so emitted
/// `SseEvent` slices remain valid until the next call to `feedLine` or
/// `reset` -- regardless of whether the caller's line buffer has been reused.
///
/// `last_event_id` and `retry_ms` persist across events and are intended for
/// use by reconnecting transports.
///
/// Designed to be testable without any network I/O.
pub const SseParser = struct {
    // Per-event buffers (cleared on event dispatch).
    event_buf: [256]u8 = undefined,
    event_len: usize = 0,
    id_buf: [512]u8 = undefined,
    id_len: usize = 0,
    /// True when the current event block contained at least one `id:` line,
    /// even if its value was empty. Distinguishes "id seen with empty value"
    /// (which clears last_event_id) from "id not present" (no change).
    has_id: bool = false,
    data_buf: [65536]u8 = undefined,
    data_len: usize = 0,
    /// True when the current event block contained at least one `data:` line,
    /// even if its value was empty (per spec, an empty `data:` still dispatches
    /// an event with data = "").
    has_data: bool = false,
    /// Set to true if the accumulated data for the current event exceeded
    /// `data_buf`. The event is still dispatched with the truncated data.
    /// Cleared on each event boundary alongside `data_len`.
    data_truncated: bool = false,

    // Persistent state (survives event boundaries and reconnects).
    /// The last `id:` value seen across all events. Sent as `Last-Event-ID`
    /// on reconnect. Empty slice means no id has been received yet.
    last_event_id_buf: [512]u8 = undefined,
    last_event_id_len: usize = 0,
    /// Server-specified reconnect delay in milliseconds (`retry:` field).
    /// Null means the server has not specified a value.
    retry_ms: ?u64 = null,

    /// Return the last received event id, or null if none has been seen.
    pub fn lastEventId(self: *const SseParser) ?[]const u8 {
        if (self.last_event_id_len == 0) return null;
        return self.last_event_id_buf[0..self.last_event_id_len];
    }

    /// Feed a single line (without trailing `\n` or `\r\n`) to the parser.
    /// Returns an `SseEvent` if a blank line was encountered (event boundary)
    /// AND at least one `data:` line was seen in this block (per spec §9.2.6),
    /// or null otherwise. The returned event's `data` field may be an empty
    /// slice when the server sent a bare `data:` with no value.
    pub fn feedLine(self: *SseParser, line: []const u8) ?SseEvent {
        const trimmed = std.mem.trimEnd(u8, line, "\r");

        // Blank line = event boundary.
        if (trimmed.len == 0) {
            // Always update last-event-id when an `id:` line was present in
            // this block, even when the value is empty (spec §9.2.6 step 1).
            if (self.has_id) {
                const copy_len = @min(self.id_len, self.last_event_id_buf.len);
                @memcpy(self.last_event_id_buf[0..copy_len], self.id_buf[0..copy_len]);
                self.last_event_id_len = copy_len;
            }

            // Per spec §9.2.6 step 2: dispatch only when at least one data:
            // line was seen (has_data). An empty-value data: line still counts.
            const evt: ?SseEvent = if (self.has_data) SseEvent{
                .id = if (self.id_len > 0) self.id_buf[0..self.id_len] else null,
                .event = if (self.event_len > 0) self.event_buf[0..self.event_len] else null,
                .data = self.data_buf[0..self.data_len],
            } else null;

            // Clear per-event state; last_event_id and retry_ms persist.
            self.event_len = 0;
            self.id_len = 0;
            self.has_id = false;
            self.data_len = 0;
            self.has_data = false;
            self.data_truncated = false;
            return evt;
        }

        // Lines starting with ':' are comments -- ignore per spec.
        if (trimmed[0] == ':') return null;

        // Parse "field: value", "field:value", or bare "field" (empty value).
        // Per spec §9.2.6: a line with no colon is a field name with empty value.
        const Parsed = struct { field: []const u8, value: []const u8 };
        const parsed: Parsed = if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| blk: {
            const raw_value = trimmed[colon_idx + 1 ..];
            // Strip optional single leading space after colon (SSE spec §9.2.6).
            const v = if (raw_value.len > 0 and raw_value[0] == ' ') raw_value[1..] else raw_value;
            break :blk .{ .field = trimmed[0..colon_idx], .value = v };
        } else .{ .field = trimmed, .value = "" };
        const field = parsed.field;
        const value = parsed.value;

        if (std.mem.eql(u8, field, "event")) {
            const copy_len = @min(value.len, self.event_buf.len);
            @memcpy(self.event_buf[0..copy_len], value[0..copy_len]);
            self.event_len = copy_len;
        } else if (std.mem.eql(u8, field, "data")) {
            // Append to data buffer, joining multiple data: lines with '\n'.
            // Mark that a data: line was seen even if the value is empty.
            if (self.has_data and self.data_len < self.data_buf.len) {
                self.data_buf[self.data_len] = '\n';
                self.data_len += 1;
            }
            self.has_data = true;
            const remaining = self.data_buf.len - self.data_len;
            if (value.len > remaining) self.data_truncated = true;
            const copy_len = @min(value.len, remaining);
            @memcpy(self.data_buf[self.data_len .. self.data_len + copy_len], value[0..copy_len]);
            self.data_len += copy_len;
        } else if (std.mem.eql(u8, field, "id")) {
            const copy_len = @min(value.len, self.id_buf.len);
            @memcpy(self.id_buf[0..copy_len], value[0..copy_len]);
            self.id_len = copy_len;
            self.has_id = true;
        } else if (std.mem.eql(u8, field, "retry")) {
            // Parse the retry value as a decimal integer of milliseconds.
            if (std.fmt.parseInt(u64, value, 10)) |ms| {
                self.retry_ms = ms;
            } else |_| {} // ignore malformed retry values per spec
        }

        return null;
    }

    /// Reset per-event accumulated state. Does NOT clear `last_event_id` or
    /// `retry_ms` -- those are persistent and survive reconnects.
    pub fn reset(self: *SseParser) void {
        self.event_len = 0;
        self.id_len = 0;
        self.has_id = false;
        self.data_len = 0;
        self.has_data = false;
        self.data_truncated = false;
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
/// production use (see `subscribeWithReconnect`).
///
/// `extra_headers` are appended after the required `Accept` and `Cache-Control`
/// headers. The caller is responsible for any authentication headers.
///
/// `parser` is caller-supplied so that `last_event_id` and `retry_ms` persist
/// across reconnects when used with `subscribeWithReconnect`.
pub fn subscribe(
    allocator: std.mem.Allocator,
    url: []const u8,
    extra_headers: []const std.http.Header,
    parser: *SseParser,
    callback: *const fn (event: SseEvent) void,
) !void {
    var client = std.http.Client{ .allocator = allocator, .io = runtime.defaultIo() };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    // Build header list: base SSE headers + Last-Event-ID (if any) + caller extras.
    const base_headers: []const std.http.Header = &.{
        .{ .name = "Accept", .value = "text/event-stream" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    };

    var last_id_header_buf: [512 + 20]u8 = undefined; // "Last-Event-ID: " + id
    var id_headers: []const std.http.Header = &.{};
    if (parser.lastEventId()) |last_id| {
        @memcpy(last_id_header_buf[0..last_id.len], last_id);
        id_headers = &.{.{
            .name = "Last-Event-ID",
            .value = last_id_header_buf[0..last_id.len],
        }};
    }

    const all_headers = try std.mem.concat(
        allocator,
        std.http.Header,
        &.{ base_headers, id_headers, extra_headers },
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

    // Reset per-event state but preserve last_event_id and retry_ms.
    parser.reset();

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
    /// Initial backoff in milliseconds. Overridden by the server's `retry:` value
    /// if one has been received. Default: 1_000.
    initial_backoff_ms: u64 = 1_000,
    /// Maximum backoff cap in milliseconds. Default: 30_000.
    max_backoff_ms: u64 = 30_000,
    /// Optional callback invoked before each reconnect attempt.
    /// Receives the backoff delay that will be applied.
    on_reconnect: ?*const fn (backoff_ms: u64) void = null,
};

/// Connect to an SSE endpoint and stream events forever, reconnecting with
/// exponential backoff on disconnection or error.
///
/// `Last-Event-ID` is automatically sent on reconnect if the server has
/// previously sent an `id:` field. The reconnect delay respects the server's
/// `retry:` value when present.
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
    // One parser instance shared across reconnects so last_event_id and
    // retry_ms survive disconnections.
    var parser = SseParser{};
    var backoff_ms = opts.initial_backoff_ms;

    while (true) {
        if (subscribe(allocator, url, extra_headers, &parser, callback)) |_| {
            // Clean close -- reset backoff.
            backoff_ms = opts.initial_backoff_ms;
        } else |_| {}

        // Use server-specified retry delay if available, otherwise exponential backoff.
        const delay = parser.retry_ms orelse backoff_ms;
        if (opts.on_reconnect) |cb| cb(delay);
        runtime.sleepMs(delay);

        // Only advance exponential backoff when server hasn't specified retry.
        if (parser.retry_ms == null) {
            // Guard against overflow before clamping.
            backoff_ms = if (backoff_ms > opts.max_backoff_ms / 2)
                opts.max_backoff_ms
            else
                backoff_ms * 2;
        }
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
    try std.testing.expectEqualStrings("perp_price", evt.event.?);
    try std.testing.expectEqualStrings("{\"price\": 100}", evt.data);
    try std.testing.expect(evt.id == null);
}

test "SseParser captures id field" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("id: 42") == null);
    try std.testing.expect(parser.feedLine("event: update") == null);
    try std.testing.expect(parser.feedLine("data: hello") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("42", evt.id.?);
    try std.testing.expectEqualStrings("update", evt.event.?);
    try std.testing.expectEqualStrings("hello", evt.data);
}

test "SseParser persists last_event_id across events" {
    var parser = SseParser{};
    _ = parser.feedLine("id: 7");
    _ = parser.feedLine("data: first");
    _ = parser.feedLine("");
    try std.testing.expectEqualStrings("7", parser.lastEventId().?);

    // Next event without id -- last_event_id should remain "7".
    _ = parser.feedLine("data: second");
    _ = parser.feedLine("");
    try std.testing.expectEqualStrings("7", parser.lastEventId().?);
}

test "SseParser parses retry field" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("retry: 3000") == null);
    try std.testing.expect(parser.retry_ms.? == 3000);
}

test "SseParser ignores malformed retry value" {
    var parser = SseParser{};
    _ = parser.feedLine("retry: not_a_number");
    try std.testing.expect(parser.retry_ms == null);
}

test "SseParser appends multiple data lines with newline" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: test") == null);
    try std.testing.expect(parser.feedLine("data: first") == null);
    try std.testing.expect(parser.feedLine("data: second") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("first\nsecond", evt.data);
}

test "SseParser ignores comments" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine(": this is a comment") == null);
    try std.testing.expect(parser.feedLine("event: test") == null);
    try std.testing.expect(parser.feedLine(": another comment") == null);
    try std.testing.expect(parser.feedLine("data: hello") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("test", evt.event.?);
    try std.testing.expectEqualStrings("hello", evt.data);
}

test "SseParser blank line without prior data emits nothing" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("") == null);
    try std.testing.expect(parser.feedLine("") == null);
}

test "SseParser dispatches event with empty data: line" {
    // Per spec: a bare `data:` (empty value) counts as a data: line and
    // must trigger dispatch with an empty data slice.
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: ping") == null);
    try std.testing.expect(parser.feedLine("data:") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("ping", evt.event.?);
    try std.testing.expectEqualStrings("", evt.data);
}

test "SseParser handles event with no data" {
    // Per spec §9.2.6: if the data buffer is empty, no event is dispatched.
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: heartbeat") == null);
    try std.testing.expect(parser.feedLine("") == null);
}

test "SseParser handles data with no event type" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("data: orphan") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expect(evt.event == null);
    try std.testing.expectEqualStrings("orphan", evt.data);
}

test "SseParser resets per-event state but not last_event_id" {
    var parser = SseParser{};
    _ = parser.feedLine("id: 99");
    _ = parser.feedLine("event: test");
    parser.reset();
    // Per-event fields cleared.
    try std.testing.expect(parser.feedLine("") == null);
    // last_event_id is NOT cleared by reset.
    // (It's updated on dispatch, not on reset, so still 0 here.)
    try std.testing.expect(parser.lastEventId() == null);
}

test "SseParser handles carriage return in line" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event: test\r") == null);
    try std.testing.expect(parser.feedLine("data: value\r") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("test", evt.event.?);
    try std.testing.expectEqualStrings("value", evt.data);
}

test "SseParser colon without space" {
    var parser = SseParser{};
    try std.testing.expect(parser.feedLine("event:no_space") == null);
    try std.testing.expect(parser.feedLine("data:also_no_space") == null);
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("no_space", evt.event.?);
    try std.testing.expectEqualStrings("also_no_space", evt.data);
}

test "SseParser multiple events in sequence" {
    var parser = SseParser{};
    _ = parser.feedLine("event: first");
    _ = parser.feedLine("data: 1");
    const ev1 = parser.feedLine("").?;
    try std.testing.expectEqualStrings("first", ev1.event.?);
    _ = parser.feedLine("event: second");
    _ = parser.feedLine("data: 2");
    const ev2 = parser.feedLine("").?;
    try std.testing.expectEqualStrings("second", ev2.event.?);
    try std.testing.expectEqualStrings("2", ev2.data);
}

test "SseParser ignores unknown fields" {
    var parser = SseParser{};
    _ = parser.feedLine("event: perp_price");
    _ = parser.feedLine("data: test_data");
    const evt = parser.feedLine("").?;
    try std.testing.expectEqualStrings("perp_price", evt.event.?);
    try std.testing.expectEqualStrings("test_data", evt.data);
}
