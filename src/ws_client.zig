const std = @import("std");
const runtime = @import("runtime.zig");
const ws_transport = @import("ws_transport.zig");
const subscription = @import("subscription.zig");
const json_rpc = @import("json_rpc.zig");

const WsTransport = ws_transport.WsTransport;
const Opcode = ws_transport.Opcode;
const SubscriptionParams = subscription.SubscriptionParams;
const SubscriptionType = subscription.SubscriptionType;
const LogSubscriptionParams = subscription.LogSubscriptionParams;

/// Resilient WebSocket client for Ethereum JSON-RPC.
///
/// Wraps `WsTransport` with three additions a production bot needs but that
/// the transport-level API does not provide:
///
///   1. Transparent reconnect with exponential backoff + jitter. When the
///      socket drops, `next()` and `request()` automatically rebuild the
///      transport and re-issue every active subscription before returning.
///   2. Multiplexed subscriptions over a single connection. Multiple
///      `Subscription` handles can coexist; notifications are dispatched to
///      the right handle and never silently dropped.
///   3. Application-layer keepalive. If no frames arrive for
///      `ping_interval_ms`, a ping is sent. If no pong arrives within
///      `pong_timeout_ms`, the connection is treated as dead.
///
/// `WsClient` is single-threaded by design. All network I/O happens
/// synchronously inside `next()` / `request()` / `subscribe()` /
/// `unsubscribe()`. There are no background threads, locks, or callbacks.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub const Opts = struct {
    /// Initial backoff in milliseconds before the first reconnect attempt.
    initial_backoff_ms: u64 = 1_000,
    /// Hard cap on backoff.
    max_backoff_ms: u64 = 30_000,
    /// Maximum reconnect attempts before `next()` returns `error.Disconnected`.
    /// 0 means retry forever.
    max_retries: u32 = 0,
    /// Send a ping if no frame has been received for this long. 0 disables.
    ping_interval_ms: u64 = 30_000,
    /// If a pong is not received within this long after the ping, the
    /// connection is treated as dead and reconnect is triggered.
    pong_timeout_ms: u64 = 10_000,
    /// Backoff jitter as a percentage, applied symmetrically. With 20%, a
    /// 1000 ms backoff becomes a uniform random value in [800, 1200] ms.
    jitter_pct: u8 = 20,
    /// Optional callback invoked before each reconnect attempt (after the
    /// backoff sleep, before the connect call).
    on_reconnect: ?*const fn (attempt: u32, backoff_ms: u64) void = null,
};

pub const Event = struct {
    /// The subscription this notification belongs to.
    sub: *Subscription,
    /// Raw JSON notification payload. Caller owns this memory and must free
    /// it with the same allocator passed to `WsClient.connect`.
    payload: []u8,
};

pub const Error = error{
    ConnectionFailed,
    /// `max_retries` exhausted without a successful reconnect.
    Disconnected,
    /// `deinit()` was called while a read was in flight.
    Closed,
    SubscribeFailed,
    UnsubscribeFailed,
    InvalidNotification,
    InvalidResponse,
    /// The request was sent but the connection dropped before a response
    /// arrived. The server may or may not have processed it; the caller
    /// must decide whether to retry.
    RequestInterrupted,
    OutOfMemory,
};

pub const Subscription = struct {
    /// Stable identifier across reconnects. Useful in logs.
    handle: u64,
    /// Caller-owned deep copy of the original params. Replayed on every
    /// reconnect to re-issue `eth_subscribe`.
    params: SubscriptionParams,
    /// Current sub-id from the node. Replaced on every reconnect.
    /// Owned by the registry.
    server_id: []u8,
    /// Back-pointer to the owning client.
    client: *WsClient,
};

pub const WsClient = struct {
    allocator: std.mem.Allocator,
    /// Owned copy of the URL used for reconnects.
    url: []u8,
    transport: ?WsTransport,
    subs: std.ArrayList(*Subscription),
    /// FIFO of notifications that arrived while a `request()` was waiting
    /// for its matching response. `next()` drains these first.
    pending: std.ArrayList(Event),
    next_handle: u64,
    next_id: u64,
    opts: Opts,
    state: State,
    /// `runtime.milliTimestamp()` of the last received frame.
    last_activity_ms: i64,
    /// Sentinel for an in-flight ping.
    pending_pong: bool,
    ping_sent_ms: i64,
    rng: std.Random.DefaultPrng,

    pub const State = enum { connected, reconnecting, closed };

    /// Open a resilient WebSocket client.
    /// `connect()` itself is NOT retried; if the very first connect fails,
    /// the call returns `error.ConnectionFailed`.
    pub fn connect(allocator: std.mem.Allocator, url: []const u8, opts: Opts) !*WsClient {
        const self = try allocator.create(WsClient);
        errdefer allocator.destroy(self);

        const url_copy = try allocator.dupe(u8, url);
        errdefer allocator.free(url_copy);

        const transport = WsTransport.connect(allocator, url) catch return error.ConnectionFailed;

        self.* = .{
            .allocator = allocator,
            .url = url_copy,
            .transport = transport,
            .subs = .empty,
            .pending = .empty,
            .next_handle = 1,
            .next_id = 1,
            .opts = opts,
            .state = .connected,
            .last_activity_ms = runtime.milliTimestamp(),
            .pending_pong = false,
            .ping_sent_ms = 0,
            .rng = std.Random.DefaultPrng.init(@bitCast(runtime.milliTimestamp())),
        };
        return self;
    }

    /// Close the transport (best-effort) and free all resources.
    pub fn deinit(self: *WsClient) void {
        self.state = .closed;
        if (self.transport) |*t| t.close();
        self.transport = null;

        for (self.subs.items) |sub| {
            self.allocator.free(sub.server_id);
            freeOwnedParams(self.allocator, sub.params);
            self.allocator.destroy(sub);
        }
        self.subs.deinit(self.allocator);

        for (self.pending.items) |ev| {
            self.allocator.free(ev.payload);
        }
        self.pending.deinit(self.allocator);

        self.allocator.free(self.url);
        self.allocator.destroy(self);
    }

    /// Subscribe via `eth_subscribe` and register the subscription so it is
    /// re-issued automatically on reconnect.
    pub fn subscribe(self: *WsClient, params: SubscriptionParams) !*Subscription {
        const owned = try cloneParams(self.allocator, params);
        errdefer freeOwnedParams(self.allocator, owned);

        const sub = try self.allocator.create(Subscription);
        errdefer self.allocator.destroy(sub);

        const params_json = try subscription.buildSubscribeParams(self.allocator, owned);
        defer self.allocator.free(params_json);

        // eth_subscribe is idempotent at the protocol level (a duplicate
        // subscribe just creates a second sub on the server, which is
        // harmless if the original was lost to a disconnect), so we use
        // the replay-safe internal request path.
        const response = self.requestReplay(json_rpc.Method.eth_subscribe, params_json) catch
            return error.SubscribeFailed;
        defer self.allocator.free(response);

        const server_id = subscription.extractResultString(self.allocator, response) catch
            return error.InvalidResponse;
        errdefer self.allocator.free(server_id);

        sub.* = .{
            .handle = self.next_handle,
            .params = owned,
            .server_id = server_id,
            .client = self,
        };
        self.next_handle += 1;

        try self.subs.append(self.allocator, sub);
        return sub;
    }

    /// Unsubscribe and free the handle. The `eth_unsubscribe` call is
    /// best-effort; failures do not propagate, since the server will garbage
    /// collect its end on disconnect anyway.
    pub fn unsubscribe(self: *WsClient, sub: *Subscription) !void {
        // Remove from registry first so a mid-call reconnect does not try to
        // resubscribe a sub the user is tearing down.
        var idx_opt: ?usize = null;
        for (self.subs.items, 0..) |s, i| {
            if (s == sub) {
                idx_opt = i;
                break;
            }
        }
        if (idx_opt) |idx| _ = self.subs.orderedRemove(idx);

        // Drop any queued notifications that point at this sub. Without
        // this purge, a subsequent next() would return an Event whose
        // `sub` field is a dangling pointer.
        self.dropPending(sub);

        // Best-effort eth_unsubscribe.
        const params_json = std.fmt.allocPrint(self.allocator, "[\"{s}\"]", .{sub.server_id}) catch {
            self.freeSubscription(sub);
            return;
        };
        defer self.allocator.free(params_json);

        // eth_unsubscribe is idempotent (the server tolerates an unknown
        // sub-id by returning false), so use the replay-safe internal path.
        const response = self.requestReplay(json_rpc.Method.eth_unsubscribe, params_json) catch {
            self.freeSubscription(sub);
            return;
        };
        self.allocator.free(response);
        self.freeSubscription(sub);
    }

    /// Read the next subscription notification, transparently reconnecting
    /// and resubscribing on disconnect.
    pub fn next(self: *WsClient) Error!Event {
        while (true) {
            if (self.state == .closed) return error.Closed;

            // Drain queued notifications first.
            if (self.pending.items.len > 0) {
                return self.pending.orderedRemove(0);
            }

            const frame = self.readFrameWithKeepalive() catch |err| switch (err) {
                error.Disconnected => return error.Disconnected,
                error.Closed => return error.Closed,
                else => {
                    try self.beginReconnect();
                    continue;
                },
            };

            if (self.dispatch(frame)) |maybe_event| {
                if (maybe_event) |ev| return ev;
                // Frame was a response or unrelated; keep reading.
                continue;
            } else |err| {
                return err;
            }
        }
    }

    /// Send a JSON-RPC request and wait for the matching response.
    ///
    /// Sub notifications received while waiting are queued for `next()`.
    ///
    /// **Idempotency:** if the connection drops AFTER the request was sent
    /// but BEFORE the response was read, this method returns
    /// `error.RequestInterrupted` instead of silently re-sending. The server
    /// may have already processed the original request; only the caller
    /// knows whether the method is safe to retry. Pre-send failures (the
    /// transport was already dead) trigger a transparent reconnect and a
    /// single retry, since the request has not yet been observed by any
    /// server.
    pub fn request(self: *WsClient, method: []const u8, params_json: []const u8) ![]u8 {
        return self.requestImpl(method, params_json, .no_replay);
    }

    /// Internal: like `request`, but replays the request on post-send
    /// disconnect. Use only for methods that are safe to issue twice
    /// (eth_subscribe, eth_unsubscribe).
    fn requestReplay(self: *WsClient, method: []const u8, params_json: []const u8) ![]u8 {
        return self.requestImpl(method, params_json, .replay);
    }

    const ReplayPolicy = enum { no_replay, replay };

    fn requestImpl(
        self: *WsClient,
        method: []const u8,
        params_json: []const u8,
        replay: ReplayPolicy,
    ) ![]u8 {
        const id = self.next_id;
        self.next_id += 1;

        const req = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s},\"id\":{d}}}",
            .{ method, params_json, id },
        );
        defer self.allocator.free(req);

        // Pre-send: the request has never been sent on the wire, so
        // reconnecting and retrying the send is always safe.
        try self.sendOrReconnect(req);

        while (true) {
            if (self.state == .closed) return error.Closed;

            const frame = self.readFrameWithKeepalive() catch |err| switch (err) {
                error.Disconnected => return error.Disconnected,
                error.Closed => return error.Closed,
                else => switch (replay) {
                    .no_replay => {
                        // Reconnect for future calls but do NOT replay this
                        // request -- the server may have processed it.
                        self.beginReconnect() catch {};
                        return error.RequestInterrupted;
                    },
                    .replay => {
                        try self.beginReconnect();
                        try self.sendOrReconnect(req);
                        continue;
                    },
                },
            };

            if (subscription.getSubscriptionId(frame)) |_| {
                // Notification; queue for next() and keep reading.
                if (try self.queueNotification(frame)) {
                    continue;
                } else {
                    self.allocator.free(frame);
                    continue;
                }
            }

            if (subscription.extractResponseId(frame)) |response_id| {
                if (response_id == id) return frame;
            }

            // Unrelated frame; discard.
            self.allocator.free(frame);
        }
    }

    // ----------------------------------------------------------------------
    // Internal: I/O helpers
    // ----------------------------------------------------------------------

    fn sendOrReconnect(self: *WsClient, payload: []const u8) !void {
        while (true) {
            if (self.transport) |*t| {
                t.sendText(payload) catch {
                    try self.beginReconnect();
                    continue;
                };
                return;
            }
            try self.beginReconnect();
        }
    }

    /// Read a single data frame, sending pings and triggering reconnect on
    /// pong timeout as needed. Returns the raw payload (caller owns).
    fn readFrameWithKeepalive(self: *WsClient) ![]u8 {
        while (true) {
            if (self.transport == null) try self.beginReconnect();
            const t = &self.transport.?;
            const frames_before = t.frames_received;

            const now = runtime.milliTimestamp();

            // Pong-timeout check.
            if (self.pending_pong and now - self.ping_sent_ms >= @as(i64, @intCast(self.opts.pong_timeout_ms))) {
                return error.PongTimeout;
            }

            // Maybe send a fresh ping.
            if (self.opts.ping_interval_ms != 0 and !self.pending_pong) {
                const elapsed_idle = now - self.last_activity_ms;
                if (elapsed_idle >= @as(i64, @intCast(self.opts.ping_interval_ms))) {
                    var nonce: [8]u8 = undefined;
                    runtime.defaultIo().random(&nonce);
                    t.sendPing(&nonce) catch return error.WriteError;
                    self.ping_sent_ms = now;
                    self.pending_pong = true;
                }
            }

            // Compute deadline for the next read.
            const deadline_ms: i64 = if (self.pending_pong)
                self.ping_sent_ms + @as(i64, @intCast(self.opts.pong_timeout_ms))
            else if (self.opts.ping_interval_ms != 0)
                self.last_activity_ms + @as(i64, @intCast(self.opts.ping_interval_ms))
            else
                std.math.maxInt(i64);

            const maybe_frame = t.readMessageDeadline(deadline_ms) catch return error.ReadError;
            if (maybe_frame) |frame| {
                self.last_activity_ms = runtime.milliTimestamp();
                self.pending_pong = false;
                return frame;
            }
            // Timeout: if the transport saw a control frame (e.g. pong) while
            // we were waiting for a data frame, we are still alive. Otherwise
            // loop, which will either send a ping or trip pong-timeout.
            if (t.frames_received != frames_before) {
                self.last_activity_ms = runtime.milliTimestamp();
                self.pending_pong = false;
            }
        }
    }

    /// Inspect a frame and either dispatch it as a sub notification or
    /// discard it. Returns the dispatched Event if it matched a registered
    /// subscription.
    fn dispatch(self: *WsClient, frame: []u8) !?Event {
        if (subscription.getSubscriptionId(frame)) |sub_id| {
            for (self.subs.items) |s| {
                if (std.mem.eql(u8, s.server_id, sub_id)) {
                    return Event{ .sub = s, .payload = frame };
                }
            }
            // Notification for an unknown sub-id (stale post-reconnect, etc).
            self.allocator.free(frame);
            return null;
        }
        // Not a notification (probably a stray response). Discard.
        self.allocator.free(frame);
        return null;
    }

    /// Like `dispatch`, but for use inside `request()` where notifications
    /// must be queued instead of returned. Returns true if queued.
    fn queueNotification(self: *WsClient, frame: []u8) !bool {
        const sub_id = subscription.getSubscriptionId(frame) orelse return false;
        for (self.subs.items) |s| {
            if (std.mem.eql(u8, s.server_id, sub_id)) {
                try self.pending.append(self.allocator, .{ .sub = s, .payload = frame });
                return true;
            }
        }
        return false;
    }

    // ----------------------------------------------------------------------
    // Internal: reconnect + resubscribe
    // ----------------------------------------------------------------------

    /// Drive the reconnect+resubscribe loop until success or `Disconnected`.
    fn beginReconnect(self: *WsClient) !void {
        if (self.state == .closed) return error.Closed;
        self.state = .reconnecting;

        if (self.transport) |*t| t.close();
        self.transport = null;
        self.pending_pong = false;

        var attempt: u32 = 0;
        while (true) {
            const base = computeBackoffMs(self.opts, attempt);
            const delay = applyJitter(base, self.opts.jitter_pct, self.rng.random());

            if (self.opts.on_reconnect) |cb| cb(attempt, delay);
            runtime.sleepMs(delay);

            const maybe_t = WsTransport.connect(self.allocator, self.url);
            if (maybe_t) |t_val| {
                var t = t_val;
                if (self.resubscribeAll(&t)) |_| {
                    self.transport = t;
                    self.state = .connected;
                    self.last_activity_ms = runtime.milliTimestamp();
                    return;
                } else |_| {
                    t.close();
                }
            } else |_| {}

            attempt += 1;
            if (self.opts.max_retries != 0 and attempt >= self.opts.max_retries) {
                self.state = .closed;
                return error.Disconnected;
            }
        }
    }

    /// Re-issue eth_subscribe for every registered subscription. On any
    /// failure, frees any newly-allocated server_ids and returns an error so
    /// the caller can close the transport and back off.
    fn resubscribeAll(self: *WsClient, t: *WsTransport) !void {
        for (self.subs.items) |sub| {
            const params_json = try subscription.buildSubscribeParams(self.allocator, sub.params);
            defer self.allocator.free(params_json);

            const response = t.request(json_rpc.Method.eth_subscribe, params_json) catch
                return error.SubscribeFailed;
            defer self.allocator.free(response);

            const new_id = subscription.extractResultString(self.allocator, response) catch
                return error.InvalidResponse;

            self.allocator.free(sub.server_id);
            sub.server_id = new_id;
        }
    }

    fn freeSubscription(self: *WsClient, sub: *Subscription) void {
        self.allocator.free(sub.server_id);
        freeOwnedParams(self.allocator, sub.params);
        self.allocator.destroy(sub);
    }

    /// Remove any queued events whose `sub` pointer matches `target`,
    /// freeing their payloads. Called from `unsubscribe` to prevent
    /// dangling pointers in the pending queue.
    fn dropPending(self: *WsClient, target: *Subscription) void {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (self.pending.items[i].sub == target) {
                const ev = self.pending.orderedRemove(i);
                self.allocator.free(ev.payload);
            } else {
                i += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Pure helpers (testable without I/O)
// ---------------------------------------------------------------------------

/// Compute the base backoff in milliseconds for the given attempt number.
/// `attempt` is 0-indexed: attempt 0 returns `initial_backoff_ms`, attempt 1
/// returns 2x that, etc. The result is clamped to `max_backoff_ms`.
pub fn computeBackoffMs(opts: Opts, attempt: u32) u64 {
    if (opts.initial_backoff_ms == 0) return 0;
    // Avoid overflow when shifting: anything past 30 doublings is well
    // beyond max_backoff_ms in any sane configuration.
    const safe_shift: u6 = if (attempt > 30) 30 else @intCast(attempt);
    const doubled = std.math.shl(u64, opts.initial_backoff_ms, safe_shift);
    // shl saturates? No, it traps on overflow. Use a saturating shift:
    const candidate = if (doubled / opts.initial_backoff_ms != @as(u64, 1) << safe_shift)
        std.math.maxInt(u64)
    else
        doubled;
    return @min(candidate, opts.max_backoff_ms);
}

/// Apply symmetric jitter to a backoff. With `pct = 20`, returns a uniform
/// random value in `[base * 0.8, base * 1.2]`.
pub fn applyJitter(base_ms: u64, pct: u8, rng: std.Random) u64 {
    if (pct == 0 or base_ms == 0) return base_ms;
    const span = (base_ms * pct) / 100;
    if (span == 0) return base_ms;
    const offset = rng.uintLessThan(u64, 2 * span + 1);
    // base + offset - span, with underflow guard.
    if (offset >= span) return base_ms + (offset - span);
    return base_ms - (span - offset);
}

// ---------------------------------------------------------------------------
// Param ownership helpers
// ---------------------------------------------------------------------------

fn cloneParams(allocator: std.mem.Allocator, params: SubscriptionParams) !SubscriptionParams {
    return switch (params) {
        .new_heads => SubscriptionParams{ .new_heads = {} },
        .new_pending_transactions => |pp| SubscriptionParams{ .new_pending_transactions = pp },
        .logs => |lp| blk: {
            var owned = LogSubscriptionParams{
                .address = lp.address,
                .topics = null,
            };
            if (lp.topics) |ts| {
                const copy = try allocator.alloc(?[32]u8, ts.len);
                @memcpy(copy, ts);
                owned.topics = copy;
            }
            break :blk SubscriptionParams{ .logs = owned };
        },
    };
}

fn freeOwnedParams(allocator: std.mem.Allocator, params: SubscriptionParams) void {
    switch (params) {
        .new_heads, .new_pending_transactions => {},
        .logs => |lp| if (lp.topics) |ts| allocator.free(ts),
    }
}

// ============================================================================
// Tests
// ============================================================================

test "computeBackoffMs - exponential with cap" {
    const opts = Opts{
        .initial_backoff_ms = 1_000,
        .max_backoff_ms = 30_000,
    };
    try std.testing.expectEqual(@as(u64, 1_000), computeBackoffMs(opts, 0));
    try std.testing.expectEqual(@as(u64, 2_000), computeBackoffMs(opts, 1));
    try std.testing.expectEqual(@as(u64, 4_000), computeBackoffMs(opts, 2));
    try std.testing.expectEqual(@as(u64, 16_000), computeBackoffMs(opts, 4));
    // 32_000 would be next; capped to 30_000.
    try std.testing.expectEqual(@as(u64, 30_000), computeBackoffMs(opts, 5));
    try std.testing.expectEqual(@as(u64, 30_000), computeBackoffMs(opts, 6));
    try std.testing.expectEqual(@as(u64, 30_000), computeBackoffMs(opts, 100));
}

test "computeBackoffMs - zero initial backoff" {
    const opts = Opts{
        .initial_backoff_ms = 0,
        .max_backoff_ms = 30_000,
    };
    try std.testing.expectEqual(@as(u64, 0), computeBackoffMs(opts, 0));
    try std.testing.expectEqual(@as(u64, 0), computeBackoffMs(opts, 5));
}

test "computeBackoffMs - extreme attempt does not panic" {
    const opts = Opts{
        .initial_backoff_ms = 1_000,
        .max_backoff_ms = 30_000,
    };
    // Attempt 1000 must clamp without integer overflow.
    try std.testing.expectEqual(@as(u64, 30_000), computeBackoffMs(opts, 1000));
}

test "applyJitter - within bounds" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const base: u64 = 1_000;
    const pct: u8 = 20;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const v = applyJitter(base, pct, prng.random());
        try std.testing.expect(v >= 800);
        try std.testing.expect(v <= 1200);
    }
}

test "applyJitter - zero pct is identity" {
    var prng = std.Random.DefaultPrng.init(0xCAFEBABE);
    try std.testing.expectEqual(@as(u64, 5_000), applyJitter(5_000, 0, prng.random()));
}

test "applyJitter - zero base is zero" {
    var prng = std.Random.DefaultPrng.init(0x1234);
    try std.testing.expectEqual(@as(u64, 0), applyJitter(0, 50, prng.random()));
}

test "cloneParams + freeOwnedParams - new_heads" {
    const alloc = std.testing.allocator;
    const cloned = try cloneParams(alloc, SubscriptionParams{ .new_heads = {} });
    defer freeOwnedParams(alloc, cloned);
    try std.testing.expectEqual(SubscriptionType.new_heads, cloned.subType());
}

test "cloneParams + freeOwnedParams - logs with topics deep copied" {
    const alloc = std.testing.allocator;
    var local = [_]?[32]u8{ @as([32]u8, @splat(0xAA)), null };
    const params = SubscriptionParams{ .logs = .{
        .address = @as([20]u8, @splat(0xCC)),
        .topics = local[0..],
    } };
    const cloned = try cloneParams(alloc, params);
    defer freeOwnedParams(alloc, cloned);
    // Mutating the original must not change the clone.
    local[0] = null;
    try std.testing.expect(cloned.logs.topics.?[0] != null);
    try std.testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0xAA))), &cloned.logs.topics.?[0].?);
}

test "Opts defaults" {
    const opts = Opts{};
    try std.testing.expectEqual(@as(u64, 1_000), opts.initial_backoff_ms);
    try std.testing.expectEqual(@as(u64, 30_000), opts.max_backoff_ms);
    try std.testing.expectEqual(@as(u32, 0), opts.max_retries);
    try std.testing.expectEqual(@as(u64, 30_000), opts.ping_interval_ms);
    try std.testing.expectEqual(@as(u64, 10_000), opts.pong_timeout_ms);
    try std.testing.expectEqual(@as(u8, 20), opts.jitter_pct);
}

// ---------------------------------------------------------------------------
// Tests for dispatch + pending queue.
//
// These build a WsClient stub on the stack with no transport, then call the
// pure logic methods directly. This avoids needing a fake socket layer for
// the multiplexing tests.
// ---------------------------------------------------------------------------

fn testStubClient(allocator: std.mem.Allocator) WsClient {
    return .{
        .allocator = allocator,
        .url = &.{},
        .transport = null,
        .subs = .empty,
        .pending = .empty,
        .next_handle = 1,
        .next_id = 1,
        .opts = .{},
        .state = .connected,
        .last_activity_ms = 0,
        .pending_pong = false,
        .ping_sent_ms = 0,
        .rng = std.Random.DefaultPrng.init(0),
    };
}

fn registerStubSubscription(self: *WsClient, server_id: []const u8) !*Subscription {
    const sub = try self.allocator.create(Subscription);
    errdefer self.allocator.destroy(sub);
    const id_copy = try self.allocator.dupe(u8, server_id);
    sub.* = .{
        .handle = self.next_handle,
        .params = .{ .new_heads = {} },
        .server_id = id_copy,
        .client = self,
    };
    self.next_handle += 1;
    try self.subs.append(self.allocator, sub);
    return sub;
}

fn freeStubClient(self: *WsClient) void {
    for (self.subs.items) |s| {
        self.allocator.free(s.server_id);
        self.allocator.destroy(s);
    }
    self.subs.deinit(self.allocator);
    for (self.pending.items) |ev| self.allocator.free(ev.payload);
    self.pending.deinit(self.allocator);
}

fn fakeNotification(allocator: std.mem.Allocator, sub_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\",\"params\":{{\"subscription\":\"{s}\",\"result\":{{}}}}}}",
        .{sub_id},
    );
}

test "dispatch - matches subscription by server_id" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    const sub_a = try registerStubSubscription(&client, "0xaaa");
    _ = try registerStubSubscription(&client, "0xbbb");

    const frame = try fakeNotification(alloc, "0xaaa");
    const event_opt = try client.dispatch(frame);
    const event = event_opt orelse return error.TestExpectedSome;
    defer alloc.free(event.payload);
    try std.testing.expect(event.sub == sub_a);
}

test "dispatch - unknown sub_id frees frame and returns null" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    _ = try registerStubSubscription(&client, "0xaaa");

    const frame = try fakeNotification(alloc, "0xstale");
    const event_opt = try client.dispatch(frame);
    try std.testing.expect(event_opt == null);
    // dispatch frees the frame on no-match; if it leaked, the testing
    // allocator would fail this test.
}

test "queueNotification - preserves arrival order" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    const sub_a = try registerStubSubscription(&client, "0xaaa");
    const sub_b = try registerStubSubscription(&client, "0xbbb");

    const f1 = try fakeNotification(alloc, "0xaaa");
    const f2 = try fakeNotification(alloc, "0xbbb");
    const f3 = try fakeNotification(alloc, "0xaaa");

    try std.testing.expect(try client.queueNotification(f1));
    try std.testing.expect(try client.queueNotification(f2));
    try std.testing.expect(try client.queueNotification(f3));

    try std.testing.expectEqual(@as(usize, 3), client.pending.items.len);
    try std.testing.expect(client.pending.items[0].sub == sub_a);
    try std.testing.expect(client.pending.items[1].sub == sub_b);
    try std.testing.expect(client.pending.items[2].sub == sub_a);
}

test "queueNotification - rejects unknown sub_id" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    _ = try registerStubSubscription(&client, "0xaaa");

    const f = try fakeNotification(alloc, "0xunknown");
    defer alloc.free(f);
    try std.testing.expect(!try client.queueNotification(f));
    try std.testing.expectEqual(@as(usize, 0), client.pending.items.len);
}

test "dropPending - removes only matching events" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    const sub_a = try registerStubSubscription(&client, "0xaaa");
    const sub_b = try registerStubSubscription(&client, "0xbbb");

    // Queue: A, B, A. After dropPending(sub_a) we expect just B.
    const f1 = try fakeNotification(alloc, "0xaaa");
    const f2 = try fakeNotification(alloc, "0xbbb");
    const f3 = try fakeNotification(alloc, "0xaaa");
    try std.testing.expect(try client.queueNotification(f1));
    try std.testing.expect(try client.queueNotification(f2));
    try std.testing.expect(try client.queueNotification(f3));

    client.dropPending(sub_a);
    try std.testing.expectEqual(@as(usize, 1), client.pending.items.len);
    try std.testing.expect(client.pending.items[0].sub == sub_b);
}

test "subscription registry - server_id remap preserves handle" {
    const alloc = std.testing.allocator;
    var client = testStubClient(alloc);
    defer freeStubClient(&client);

    const sub = try registerStubSubscription(&client, "0xold");
    const handle_before = sub.handle;

    // Simulate what resubscribeAll does: free the old id, install a new one.
    alloc.free(sub.server_id);
    sub.server_id = try alloc.dupe(u8, "0xnew");

    // Handle and pointer are stable; only the server_id changed.
    try std.testing.expectEqual(handle_before, sub.handle);
    try std.testing.expectEqualStrings("0xnew", sub.server_id);

    // Notifications addressed to the new id now dispatch to the same handle.
    const f = try fakeNotification(alloc, "0xnew");
    const event_opt = try client.dispatch(f);
    const event = event_opt orelse return error.TestExpectedSome;
    defer alloc.free(event.payload);
    try std.testing.expect(event.sub == sub);
}
