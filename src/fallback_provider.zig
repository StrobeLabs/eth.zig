const std = @import("std");
const provider_mod = @import("provider.zig");
const runtime = @import("runtime.zig");
const block_mod = @import("block.zig");
const receipt_mod = @import("receipt.zig");
const json_rpc = @import("json_rpc.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Provider = provider_mod.Provider;

/// Configuration for FallbackProvider.
/// Upper bound on the number of fallback endpoints, so the per-request
/// "already tried" set can live on the stack (allocation-free dispatch). Far
/// more than any realistic fallback configuration.
pub const max_endpoints = 64;

pub const FallbackOpts = struct {
    /// Number of consecutive transport failures before an endpoint is marked
    /// unhealthy and skipped during selection. Default: 3.
    failover_threshold: u32 = 3,
    /// Time (in milliseconds) that must elapse after the most recent failure
    /// before an unhealthy endpoint is probed again (made eligible for
    /// selection). Default: 30_000 (30s).
    recovery_probe_ms: i64 = 30_000,
};

/// Per-endpoint health state.
///
/// Single-threaded by design: a FallbackProvider holds one transport per
/// endpoint and a single shared `std.http.Client` underneath each, neither of
/// which is thread-safe. The health counters are therefore plain integers, not
/// atomics; do not share a FallbackProvider across threads (give each thread
/// its own, exactly as you would a `Provider`).
pub const EndpointHealth = struct {
    /// Consecutive transport/connection failures since the last success.
    consecutive_failures: u32 = 0,
    /// Wall-clock time (ms) of the last successful request, 0 if never.
    last_success_ms: i64 = 0,
    /// Wall-clock time (ms) of the most recent failure, 0 if never.
    last_failure_ms: i64 = 0,

    /// True if the endpoint has tripped the failover threshold and has not yet
    /// been re-probed. Derived from `consecutive_failures` and `threshold`.
    pub fn isUnhealthy(self: EndpointHealth, threshold: u32) bool {
        return self.consecutive_failures >= threshold;
    }

    /// True if an unhealthy endpoint has waited long enough since its last
    /// failure to be probed again.
    pub fn isProbeReady(self: EndpointHealth, now_ms: i64, recovery_probe_ms: i64) bool {
        return (now_ms - self.last_failure_ms) >= recovery_probe_ms;
    }

    /// Record a successful request: clears the failure streak.
    pub fn recordSuccess(self: *EndpointHealth, now_ms: i64) void {
        self.consecutive_failures = 0;
        self.last_success_ms = now_ms;
    }

    /// Record a transport failure: bumps the failure streak.
    pub fn recordFailure(self: *EndpointHealth, now_ms: i64) void {
        self.consecutive_failures +|= 1;
        self.last_failure_ms = now_ms;
    }
};

/// Returns true if the given error should trigger failover to the next
/// endpoint. ONLY transport/connection-level errors trigger failover.
///
/// Critically, `error.RpcError` does NOT trigger failover: the node answered
/// the request (a revert, "method not found", a rate-limit JSON-RPC error,
/// etc.). Re-sending it to a different endpoint would produce the same answer
/// (or, worse, double-submit a transaction). A valid RPC error is a real
/// answer and is propagated to the caller unchanged.
///
/// Likewise, decode/parse errors (`error.InvalidResponse`, `error.NullResult`)
/// and `error.OutOfMemory` are NOT failover-eligible: a different endpoint
/// would not fix a local parsing bug or an allocation failure.
pub fn isFailoverError(err: anyerror) bool {
    return switch (err) {
        // Transport / connection errors surfaced by HttpTransport.request:
        // the request never reached a node, or the HTTP layer rejected it.
        error.ConnectionFailed,
        error.HttpError,
        // Lower-level socket errors, in case a transport surfaces them raw.
        error.ConnectionRefused,
        error.ConnectionTimedOut,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.NetworkUnreachable,
        error.WouldBlock,
        error.UnexpectedEof,
        => true,
        // error.RpcError: the node answered -> NOT failover.
        // Everything else (InvalidResponse, NullResult, OutOfMemory, ...) is a
        // local concern, not an endpoint-health signal -> NOT failover.
        else => false,
    };
}

/// Pure endpoint-selection function. Given the health state of every endpoint
/// and the current time, returns the index of the endpoint to try, preferring
/// the lowest-index healthy endpoint.
///
/// Selection order:
///   1. The first endpoint (lowest index) that is currently healthy
///      (`consecutive_failures < threshold`). Lower-index endpoints are the
///      preferred ones, so a recovered primary is automatically reclaimed.
///   2. Otherwise the first unhealthy endpoint whose recovery probe is due
///      (enough time has elapsed since its last failure) -- a probe attempt.
///   3. Otherwise `null`: every endpoint is unhealthy and none is probe-ready.
///      The caller surfaces the last error rather than hammering a dead pool.
///
/// Factored out as a pure function over (`health`, `now_ms`, `opts`, `tried`)
/// so the failover/recovery state machine is unit-testable with injected
/// timestamps, without any network or Provider.
///
/// `tried[i] == true` excludes endpoint `i` so that, within a single request,
/// a transport failure fails over to a *different* endpoint rather than
/// re-selecting the same not-yet-unhealthy one (consecutive failures alone do
/// not mark an endpoint unhealthy until the threshold is reached). Pass a slice
/// as long as `health` (or shorter / empty to exclude nothing).
pub fn selectEndpoint(
    health: []const EndpointHealth,
    now_ms: i64,
    opts: FallbackOpts,
    tried: []const bool,
) ?usize {
    // 1. Prefer the lowest-index healthy endpoint not already tried.
    for (health, 0..) |h, i| {
        if (i < tried.len and tried[i]) continue;
        if (!h.isUnhealthy(opts.failover_threshold)) return i;
    }
    // 2. No healthy endpoint: probe the first untried unhealthy one that is due.
    for (health, 0..) |h, i| {
        if (i < tried.len and tried[i]) continue;
        if (h.isProbeReady(now_ms, opts.recovery_probe_ms)) return i;
    }
    // 3. Everything is unhealthy/tried and nothing is probe-ready.
    return null;
}

/// Wraps an ordered list of RPC endpoints and fails over between them.
///
/// On a transport/connection failure (see `isFailoverError`) the request is
/// retried against the next healthy endpoint. After `failover_threshold`
/// consecutive failures an endpoint is marked unhealthy and skipped; a periodic
/// probe (`recovery_probe_ms` after its last failure) makes it eligible again,
/// and lower-index endpoints are always preferred so a recovered primary is
/// reclaimed automatically.
///
/// A valid RPC error response (`error.RpcError` -- a revert, an unsupported
/// method, a rate-limit JSON-RPC error) is a real answer and is returned to the
/// caller WITHOUT failover; see `isFailoverError`.
///
/// The public read method surface mirrors `Provider` exactly, so a
/// `FallbackProvider` is a drop-in replacement.
///
/// Single-threaded: like `Provider`, do not share an instance across threads.
///
/// Example:
///   var fb = try FallbackProvider.init(allocator, &.{
///       "https://primary.example.com",
///       "https://backup.example.com",
///   }, eth.runtime.blockingIo(), .{});
///   defer fb.deinit();
///   const block_num = try fb.getBlockNumber();
pub const FallbackProvider = struct {
    allocator: std.mem.Allocator,
    /// One transport per endpoint, parallel to `providers` and `health`.
    transports: []HttpTransport,
    /// One Provider per endpoint, each bound to the matching transport.
    providers: []Provider,
    /// Per-endpoint health, parallel to `providers`.
    health: []EndpointHealth,
    opts: FallbackOpts,
    /// The `std.Io` shared by every endpoint transport; also drives the
    /// health-tracking timestamps.
    io: std.Io,

    /// Initialise a FallbackProvider over an ordered list of endpoint URLs.
    /// The URLs are referenced (not copied); they must outlive the provider,
    /// exactly as `HttpTransport.init` borrows its URL.
    ///
    /// Requires at least one endpoint.
    pub fn init(
        allocator: std.mem.Allocator,
        endpoints: []const []const u8,
        io: std.Io,
        opts: FallbackOpts,
    ) !FallbackProvider {
        if (endpoints.len == 0) return error.NoEndpoints;
        if (endpoints.len > max_endpoints) return error.TooManyEndpoints;

        const transports = try allocator.alloc(HttpTransport, endpoints.len);
        errdefer allocator.free(transports);
        const providers = try allocator.alloc(Provider, endpoints.len);
        errdefer allocator.free(providers);
        const health = try allocator.alloc(EndpointHealth, endpoints.len);
        errdefer allocator.free(health);

        for (endpoints, 0..) |url, i| {
            transports[i] = HttpTransport.init(allocator, url, io);
            health[i] = .{};
        }
        // Bind each provider to its transport. Done in a second pass so the
        // `transports` slice is fully populated and stable before taking
        // pointers into it.
        for (0..endpoints.len) |i| {
            providers[i] = Provider.init(allocator, &transports[i]);
        }

        return .{
            .allocator = allocator,
            .transports = transports,
            .providers = providers,
            .health = health,
            .opts = opts,
            .io = io,
        };
    }

    pub fn deinit(self: *FallbackProvider) void {
        for (self.transports) |*t| t.deinit();
        self.allocator.free(self.transports);
        self.allocator.free(self.providers);
        self.allocator.free(self.health);
    }

    // ========================================================================
    // Chain state
    // ========================================================================

    pub fn getChainId(self: *FallbackProvider) !u64 {
        return self.dispatch(u64, "getChainId", .{});
    }

    pub fn getBlockNumber(self: *FallbackProvider) !u64 {
        return self.dispatch(u64, "getBlockNumber", .{});
    }

    // ========================================================================
    // Account state
    // ========================================================================

    pub fn getBalance(self: *FallbackProvider, address: [20]u8) !u256 {
        return self.dispatch(u256, "getBalance", .{address});
    }

    pub fn getTransactionCount(self: *FallbackProvider, address: [20]u8) !u64 {
        return self.dispatch(u64, "getTransactionCount", .{address});
    }

    pub fn getTransactionCountAt(self: *FallbackProvider, address: [20]u8, tag: json_rpc.BlockTag) !u64 {
        return self.dispatch(u64, "getTransactionCountAt", .{ address, tag });
    }

    pub fn getCode(self: *FallbackProvider, address: [20]u8) ![]u8 {
        return self.dispatch([]u8, "getCode", .{address});
    }

    pub fn getStorageAt(self: *FallbackProvider, address: [20]u8, slot: [32]u8) ![32]u8 {
        return self.dispatch([32]u8, "getStorageAt", .{ address, slot });
    }

    // ========================================================================
    // Gas
    // ========================================================================

    pub fn getGasPrice(self: *FallbackProvider) !u256 {
        return self.dispatch(u256, "getGasPrice", .{});
    }

    pub fn getMaxPriorityFee(self: *FallbackProvider) !u256 {
        return self.dispatch(u256, "getMaxPriorityFee", .{});
    }

    // ========================================================================
    // Transaction execution
    // ========================================================================

    pub fn call(self: *FallbackProvider, to: [20]u8, data: []const u8) ![]u8 {
        return self.dispatch([]u8, "call", .{ to, data });
    }

    pub fn estimateGas(self: *FallbackProvider, to: [20]u8, data: []const u8, from: ?[20]u8) !u64 {
        return self.dispatch(u64, "estimateGas", .{ to, data, from });
    }

    /// Send a signed transaction and return the transaction hash.
    ///
    /// Failover note: a signed Ethereum transaction is nonce-protected, so
    /// resubmitting the same bytes to a different endpoint after a *connection*
    /// failure is safe -- a duplicate is a no-op once mined. Failover only
    /// fires on transport errors (`isFailoverError`); an `error.RpcError` such
    /// as "nonce too low" or "already known" is the node's real answer and is
    /// returned to the caller, not retried on another endpoint.
    pub fn sendRawTransaction(self: *FallbackProvider, signed_tx: []const u8) ![32]u8 {
        return self.dispatch([32]u8, "sendRawTransaction", .{signed_tx});
    }

    // ========================================================================
    // Receipts
    // ========================================================================

    pub fn getTransactionReceipt(self: *FallbackProvider, tx_hash: [32]u8) !?receipt_mod.TransactionReceipt {
        return self.dispatch(?receipt_mod.TransactionReceipt, "getTransactionReceipt", .{tx_hash});
    }

    // ========================================================================
    // Blocks
    // ========================================================================

    pub fn getBlock(self: *FallbackProvider, block_number: u64) !?block_mod.BlockHeader {
        return self.dispatch(?block_mod.BlockHeader, "getBlock", .{block_number});
    }

    // ========================================================================
    // Logs
    // ========================================================================

    pub fn getLogs(self: *FallbackProvider, filter: json_rpc.LogFilter) ![]receipt_mod.Log {
        return self.dispatch([]receipt_mod.Log, "getLogs", .{filter});
    }

    // ========================================================================
    // Dispatch / failover loop
    // ========================================================================

    /// Generic delegate: call `Provider.<method>(args...)` on the selected
    /// endpoint, advancing to the next healthy endpoint on a failover-eligible
    /// transport error and updating per-endpoint health.
    ///
    /// `method` is the Provider method name; `Ret` is its success type (the
    /// payload inside the error union). The failover/recovery decision is made
    /// by the pure `selectEndpoint`, so the loop here is just orchestration.
    fn dispatch(
        self: *FallbackProvider,
        comptime Ret: type,
        comptime method: []const u8,
        args: anytype,
    ) !Ret {
        // Track the last failover-eligible error so we can surface it if every
        // endpoint is exhausted.
        var last_err: anyerror = error.AllEndpointsFailed;
        // Each endpoint is tried at most once per request (a request never
        // loops forever; `selectEndpoint` returning the same probe twice is
        // prevented because a failed probe bumps its failure streak, and we
        // also cap iterations at endpoint count).
        // Endpoints already attempted in THIS request, so a transport failure
        // fails over to a different endpoint instead of re-selecting the same
        // not-yet-unhealthy one. Bounded by `max_endpoints` (checked in init),
        // so this stays allocation-free.
        var tried_buf: [max_endpoints]bool = @splat(false);
        const tried = tried_buf[0..self.providers.len];

        var attempts: usize = 0;
        while (attempts < self.providers.len) : (attempts += 1) {
            const now = runtime.milliTimestamp(self.io);
            const idx = selectEndpoint(self.health, now, self.opts, tried) orelse break;
            tried[idx] = true;

            const result = @call(.auto, @field(Provider, method), .{&self.providers[idx]} ++ args);
            if (result) |ok| {
                self.health[idx].recordSuccess(runtime.milliTimestamp(self.io));
                return ok;
            } else |err| {
                if (!isFailoverError(err)) {
                    // A real answer (RpcError) or a local error: do NOT fail
                    // over, and do NOT count it against endpoint health.
                    return err;
                }
                self.health[idx].recordFailure(runtime.milliTimestamp(self.io));
                last_err = err;
            }
        }
        return last_err;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "isFailoverError - transport errors trigger failover" {
    try testing.expect(isFailoverError(error.ConnectionFailed));
    try testing.expect(isFailoverError(error.HttpError));
    try testing.expect(isFailoverError(error.ConnectionRefused));
    try testing.expect(isFailoverError(error.ConnectionTimedOut));
    try testing.expect(isFailoverError(error.ConnectionResetByPeer));
    try testing.expect(isFailoverError(error.BrokenPipe));
    try testing.expect(isFailoverError(error.UnexpectedEof));
}

test "isFailoverError - RpcError is a real answer and does NOT fail over" {
    // The critical classification: a node that answered must not be retried.
    try testing.expect(!isFailoverError(error.RpcError));
}

test "isFailoverError - local errors do NOT fail over" {
    try testing.expect(!isFailoverError(error.InvalidResponse));
    try testing.expect(!isFailoverError(error.NullResult));
    try testing.expect(!isFailoverError(error.OutOfMemory));
}

test "EndpointHealth - record success clears failure streak" {
    var h = EndpointHealth{};
    h.recordFailure(100);
    h.recordFailure(200);
    try testing.expectEqual(@as(u32, 2), h.consecutive_failures);
    h.recordSuccess(300);
    try testing.expectEqual(@as(u32, 0), h.consecutive_failures);
    try testing.expectEqual(@as(i64, 300), h.last_success_ms);
}

test "EndpointHealth - isUnhealthy at threshold" {
    var h = EndpointHealth{};
    try testing.expect(!h.isUnhealthy(3));
    h.recordFailure(1);
    h.recordFailure(2);
    try testing.expect(!h.isUnhealthy(3)); // 2 < 3
    h.recordFailure(3);
    try testing.expect(h.isUnhealthy(3)); // 3 >= 3
}

test "EndpointHealth - isProbeReady after recovery interval" {
    var h = EndpointHealth{};
    h.recordFailure(1_000);
    try testing.expect(!h.isProbeReady(1_500, 1_000)); // only 500ms elapsed
    try testing.expect(h.isProbeReady(2_000, 1_000)); // exactly 1000ms
    try testing.expect(h.isProbeReady(5_000, 1_000)); // well past
}

test "selectEndpoint - prefers lowest-index healthy endpoint" {
    const opts = FallbackOpts{ .failover_threshold = 3 };
    var health = [_]EndpointHealth{ .{}, .{}, .{} };
    // All healthy: pick endpoint 0.
    try testing.expectEqual(@as(?usize, 0), selectEndpoint(&health, 0, opts, &[_]bool{}));
}

test "selectEndpoint - excludes already-tried endpoints (per-request failover)" {
    const opts = FallbackOpts{ .failover_threshold = 3 };
    // All three endpoints healthy; the failure streak has not hit the
    // threshold, so without the tried set the same endpoint would be reselected.
    var health = [_]EndpointHealth{ .{}, .{}, .{} };
    try testing.expectEqual(@as(?usize, 1), selectEndpoint(&health, 0, opts, &[_]bool{ true, false, false }));
    try testing.expectEqual(@as(?usize, 2), selectEndpoint(&health, 0, opts, &[_]bool{ true, true, false }));
    // Every endpoint tried this request -> dead for this attempt.
    try testing.expectEqual(@as(?usize, null), selectEndpoint(&health, 0, opts, &[_]bool{ true, true, true }));
}

test "selectEndpoint - advances when preferred endpoint is unhealthy" {
    const opts = FallbackOpts{ .failover_threshold = 2, .recovery_probe_ms = 10_000 };
    var health = [_]EndpointHealth{ .{}, .{}, .{} };
    // Endpoint 0 fails twice -> unhealthy.
    health[0].recordFailure(100);
    health[0].recordFailure(200);
    // now=300, well within probe window, so endpoint 0 is skipped.
    try testing.expectEqual(@as(?usize, 1), selectEndpoint(&health, 300, opts, &[_]bool{}));
}

test "selectEndpoint - recovers preferred endpoint via probe after interval" {
    const opts = FallbackOpts{ .failover_threshold = 2, .recovery_probe_ms = 10_000 };
    var health = [_]EndpointHealth{ .{}, .{} };
    health[0].recordFailure(100);
    health[0].recordFailure(200); // unhealthy, last_failure_ms=200
    health[1].recordFailure(100);
    health[1].recordFailure(150); // unhealthy, last_failure_ms=150

    // Before any probe is due, both unhealthy and none probe-ready -> null.
    try testing.expectEqual(@as(?usize, null), selectEndpoint(&health, 5_000, opts, &[_]bool{}));

    // After 10_000ms past endpoint 1's failure (150) but before endpoint 0's
    // (200): endpoint 1 is probe-ready first by index... but index order means
    // we scan 0 first. At now=10_150, endpoint 0 needs >=10_200, not ready;
    // endpoint 1 needs >=10_150, ready -> pick 1.
    try testing.expectEqual(@as(?usize, 1), selectEndpoint(&health, 10_150, opts, &[_]bool{}));

    // At now=10_200 both are probe-ready; lowest index (0) wins the probe.
    try testing.expectEqual(@as(?usize, 0), selectEndpoint(&health, 10_200, opts, &[_]bool{}));
}

test "selectEndpoint - all unhealthy and none probe-ready returns null" {
    const opts = FallbackOpts{ .failover_threshold = 1, .recovery_probe_ms = 1_000 };
    var health = [_]EndpointHealth{ .{}, .{} };
    health[0].recordFailure(500);
    health[1].recordFailure(500);
    try testing.expectEqual(@as(?usize, null), selectEndpoint(&health, 600, opts, &[_]bool{}));
}

test "selectEndpoint - reclaims primary once its streak clears" {
    const opts = FallbackOpts{ .failover_threshold = 2, .recovery_probe_ms = 10_000 };
    var health = [_]EndpointHealth{ .{}, .{} };
    health[0].recordFailure(100);
    health[0].recordFailure(200); // unhealthy -> traffic goes to endpoint 1
    try testing.expectEqual(@as(?usize, 1), selectEndpoint(&health, 300, opts, &[_]bool{}));

    // A later successful probe clears endpoint 0; it is preferred again.
    health[0].recordSuccess(11_000);
    try testing.expectEqual(@as(?usize, 0), selectEndpoint(&health, 11_100, opts, &[_]bool{}));
}

test "FallbackProvider - init requires at least one endpoint" {
    try testing.expectError(error.NoEndpoints, FallbackProvider.init(testing.allocator, &.{}, runtime.blockingIo(), .{}));
}

test "FallbackProvider - init/deinit wires one provider per endpoint" {
    const endpoints = [_][]const u8{
        "http://localhost:8545",
        "http://localhost:8546",
    };
    var fb = try FallbackProvider.init(testing.allocator, &endpoints, runtime.blockingIo(), .{});
    defer fb.deinit();

    try testing.expectEqual(@as(usize, 2), fb.providers.len);
    try testing.expectEqual(@as(usize, 2), fb.health.len);
    try testing.expectEqual(@as(usize, 2), fb.transports.len);
    // Each provider must point at its own transport (not a dangling/shared one).
    try testing.expectEqual(&fb.transports[0], fb.providers[0].transport);
    try testing.expectEqual(&fb.transports[1], fb.providers[1].transport);
    // Default opts.
    try testing.expectEqual(@as(u32, 3), fb.opts.failover_threshold);
    try testing.expectEqual(@as(i64, 30_000), fb.opts.recovery_probe_ms);
}

test "refAllDecls" {
    testing.refAllDecls(@This());
}
