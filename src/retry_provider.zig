const std = @import("std");
const provider_mod = @import("provider.zig");
const block_mod = @import("block.zig");
const receipt_mod = @import("receipt.zig");
const json_rpc = @import("json_rpc.zig");

const Provider = provider_mod.Provider;

/// Controls which errors trigger a retry attempt.
pub const RetryableErrors = enum {
    /// Only retry on network/transport errors (connection refused, timed out, reset).
    connection_errors,
    /// Also retry on RPC-level errors such as rate limits and server errors.
    all_rpc_errors,
};

/// Configuration for RetryingProvider.
pub const RetryOpts = struct {
    /// Maximum number of attempts (1 = no retry). Default: 3.
    max_attempts: u32 = 3,
    /// Initial backoff delay in milliseconds. Default: 100.
    initial_backoff_ms: u64 = 100,
    /// Backoff multiplier applied after each failed attempt. Default: 2.0 (exponential).
    backoff_multiplier: f64 = 2.0,
    /// Maximum backoff delay in milliseconds. Default: 5_000.
    max_backoff_ms: u64 = 5_000,
    /// Jitter factor 0.0–1.0 added to each backoff to prevent thundering herd. Default: 0.1.
    jitter: f64 = 0.1,
    /// Which errors trigger a retry. Default: connection errors only.
    retryable: RetryableErrors = .connection_errors,
};

/// Wraps a Provider and retries failed calls with exponential backoff.
///
/// Example:
///   var provider = Provider.init(allocator, &transport);
///   var retrying = RetryingProvider.init(&provider, .{});
///   const block_num = try retrying.getBlockNumber();
pub const RetryingProvider = struct {
    inner: *Provider,
    opts: RetryOpts,
    /// PRNG for jitter; mutated on each retry. Not thread-safe — do not share instances across threads.
    prng: std.Random.DefaultPrng,

    /// Initialise a RetryingProvider wrapping the given Provider.
    /// Seeds the PRNG from a cryptographically random value.
    pub fn init(inner: *Provider, opts: RetryOpts) RetryingProvider {
        const seed = std.crypto.random.int(u64);
        return .{
            .inner = inner,
            .opts = opts,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    // ========================================================================
    // Chain state
    // ========================================================================

    pub fn getChainId(self: *RetryingProvider) !u64 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getChainId()) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn getBlockNumber(self: *RetryingProvider) !u64 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getBlockNumber()) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Account state
    // ========================================================================

    pub fn getBalance(self: *RetryingProvider, address: [20]u8) !u256 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getBalance(address)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn getTransactionCount(self: *RetryingProvider, address: [20]u8) !u64 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getTransactionCount(address)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn getCode(self: *RetryingProvider, address: [20]u8) ![]u8 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getCode(address)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn getStorageAt(self: *RetryingProvider, address: [20]u8, slot: [32]u8) ![32]u8 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getStorageAt(address, slot)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Gas
    // ========================================================================

    pub fn getGasPrice(self: *RetryingProvider) !u256 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getGasPrice()) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn getMaxPriorityFee(self: *RetryingProvider) !u256 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getMaxPriorityFee()) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Transaction execution
    // ========================================================================

    pub fn call(self: *RetryingProvider, to: [20]u8, data: []const u8) ![]u8 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.call(to, data)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    pub fn estimateGas(self: *RetryingProvider, to: [20]u8, data: []const u8, from: ?[20]u8) !u64 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.estimateGas(to, data, from)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    /// Send a signed transaction and return the transaction hash.
    ///
    /// Retry semantics: retrying `sendRawTransaction` is generally safe because
    /// signed Ethereum transactions are nonce-protected — a duplicate submission
    /// of the same signed bytes is a no-op on the node once the first is mined.
    /// However, if the first attempt succeeds but the response is lost (network
    /// error after the node accepted the tx), a subsequent retry will fail with
    /// a non-retryable "nonce already used" error. Callers should treat that
    /// error as a signal to check transaction status via `getTransactionReceipt`
    /// rather than as a confirmation of failure.
    ///
    /// See also: `RetryingProvider`, `RetryState`, `RetryOpts`.
    pub fn sendRawTransaction(self: *RetryingProvider, signed_tx: []const u8) ![32]u8 {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.sendRawTransaction(signed_tx)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Receipts
    // ========================================================================

    pub fn getTransactionReceipt(self: *RetryingProvider, tx_hash: [32]u8) !?receipt_mod.TransactionReceipt {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getTransactionReceipt(tx_hash)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Blocks
    // ========================================================================

    pub fn getBlock(self: *RetryingProvider, block_number: u64) !?block_mod.BlockHeader {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getBlock(block_number)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }

    // ========================================================================
    // Logs
    // ========================================================================

    pub fn getLogs(self: *RetryingProvider, filter: json_rpc.LogFilter) ![]receipt_mod.Log {
        var state = RetryState.init(self);
        while (true) {
            if (self.inner.getLogs(filter)) |r| return r else |err| if (!state.next(err)) return err;
        }
    }
};

// ---------------------------------------------------------------------------
// Internal retry state machine
// ---------------------------------------------------------------------------

/// Per-call retry state. Tracks attempt count and current backoff.
const RetryState = struct {
    provider: *RetryingProvider,
    attempt: u32,
    backoff_ms: u64,

    fn init(provider: *RetryingProvider) RetryState {
        return .{
            .provider = provider,
            .attempt = 0,
            .backoff_ms = provider.opts.initial_backoff_ms,
        };
    }

    /// Called on each error. Returns true if the caller should retry, false if it should propagate.
    /// When returning true, sleeps for the appropriate backoff duration.
    fn next(self: *RetryState, err: anyerror) bool {
        self.attempt += 1;
        if (self.attempt >= self.provider.opts.max_attempts) return false;
        if (!isRetryable(err, self.provider.opts)) return false;

        const jitter_ms: u64 = @intFromFloat(@as(f64, @floatFromInt(self.backoff_ms)) * self.provider.opts.jitter);
        const extra = if (jitter_ms > 0) self.provider.prng.random().int(u64) % jitter_ms else 0;
        std.time.sleep((self.backoff_ms + extra) * std.time.ns_per_ms);

        const next_backoff: u64 = @intFromFloat(
            @as(f64, @floatFromInt(self.backoff_ms)) * self.provider.opts.backoff_multiplier,
        );
        self.backoff_ms = @min(next_backoff, self.provider.opts.max_backoff_ms);
        return true;
    }
};

/// Returns true if the given error should trigger a retry under the given options.
fn isRetryable(err: anyerror, opts: RetryOpts) bool {
    return switch (err) {
        // Network / transport errors: always retryable.
        error.ConnectionRefused,
        error.ConnectionTimedOut,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.NetworkUnreachable,
        error.WouldBlock,
        error.UnexpectedEof,
        => true,
        // RPC-level errors: only retryable in .all_rpc_errors mode.
        error.RpcError => opts.retryable == .all_rpc_errors,
        // Parsing, invalid input, etc.: never retryable.
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "RetryOpts - defaults" {
    const opts = RetryOpts{};
    try std.testing.expectEqual(@as(u32, 3), opts.max_attempts);
    try std.testing.expectEqual(@as(u64, 100), opts.initial_backoff_ms);
    try std.testing.expectEqual(@as(u64, 5_000), opts.max_backoff_ms);
    try std.testing.expectEqual(RetryableErrors.connection_errors, opts.retryable);
}

test "isRetryable - connection errors" {
    const opts = RetryOpts{ .retryable = .connection_errors };
    try std.testing.expect(isRetryable(error.ConnectionRefused, opts));
    try std.testing.expect(isRetryable(error.ConnectionTimedOut, opts));
    try std.testing.expect(isRetryable(error.ConnectionResetByPeer, opts));
    try std.testing.expect(isRetryable(error.BrokenPipe, opts));
    try std.testing.expect(isRetryable(error.UnexpectedEof, opts));
    try std.testing.expect(!isRetryable(error.RpcError, opts));
    try std.testing.expect(!isRetryable(error.InvalidResponse, opts));
    try std.testing.expect(!isRetryable(error.OutOfMemory, opts));
}

test "isRetryable - all_rpc_errors" {
    const opts = RetryOpts{ .retryable = .all_rpc_errors };
    try std.testing.expect(isRetryable(error.ConnectionRefused, opts));
    try std.testing.expect(isRetryable(error.RpcError, opts));
    try std.testing.expect(!isRetryable(error.InvalidResponse, opts));
}

test "RetryState - exhausts attempts then stops" {
    // Build a RetryingProvider with max_attempts=2 and no sleep (initial_backoff_ms=0).
    // We can't call into a real Provider here; we test RetryState directly.
    const opts = RetryOpts{ .max_attempts = 2, .initial_backoff_ms = 0, .jitter = 0 };
    const seed: u64 = 0;
    var fake_inner: Provider = undefined;
    var rp = RetryingProvider{
        .inner = &fake_inner,
        .opts = opts,
        .prng = std.Random.DefaultPrng.init(seed),
    };

    var state = RetryState.init(&rp);

    // First error: attempt becomes 1, still < max_attempts=2, retryable error → should retry.
    try std.testing.expect(state.next(error.ConnectionRefused));
    // Second error: attempt becomes 2, 2 >= max_attempts=2 → should not retry.
    try std.testing.expect(!state.next(error.ConnectionRefused));
}

test "RetryState - non-retryable error stops immediately" {
    const opts = RetryOpts{ .max_attempts = 5, .initial_backoff_ms = 0, .jitter = 0 };
    var fake_inner: Provider = undefined;
    var rp = RetryingProvider{
        .inner = &fake_inner,
        .opts = opts,
        .prng = std.Random.DefaultPrng.init(0),
    };

    var state = RetryState.init(&rp);
    // InvalidResponse is not retryable: should stop immediately.
    try std.testing.expect(!state.next(error.InvalidResponse));
}

test "RetryState - backoff increases exponentially" {
    const opts = RetryOpts{
        .max_attempts = 10,
        .initial_backoff_ms = 100,
        .backoff_multiplier = 2.0,
        .max_backoff_ms = 1_000,
        .jitter = 0, // no sleep
        .retryable = .connection_errors,
    };
    var fake_inner: Provider = undefined;
    var rp = RetryingProvider{
        .inner = &fake_inner,
        .opts = opts,
        .prng = std.Random.DefaultPrng.init(0),
    };

    var state = RetryState.init(&rp);
    try std.testing.expectEqual(@as(u64, 100), state.backoff_ms);

    _ = state.next(error.ConnectionRefused);
    try std.testing.expectEqual(@as(u64, 200), state.backoff_ms);

    _ = state.next(error.ConnectionRefused);
    try std.testing.expectEqual(@as(u64, 400), state.backoff_ms);

    _ = state.next(error.ConnectionRefused);
    try std.testing.expectEqual(@as(u64, 800), state.backoff_ms);

    // Capped at max_backoff_ms=1000
    _ = state.next(error.ConnectionRefused);
    try std.testing.expectEqual(@as(u64, 1_000), state.backoff_ms);
}
