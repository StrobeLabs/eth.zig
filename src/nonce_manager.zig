//! Atomic nonce manager for concurrent senders (issue #75).
//!
//! Bots that fire transactions from multiple threads race on
//! `eth_getTransactionCount`: two threads read the same on-chain count and
//! build two transactions with the same nonce, so one is rejected as a
//! duplicate. The standard fix -- a local atomic nonce cache seeded once from
//! the chain and incremented locally -- is reimplemented by every consumer;
//! it belongs upstream.
//!
//! `NonceManager` seeds itself lazily (no RPC in `init`) from the `pending`
//! transaction count and then hands out strictly increasing nonces with a
//! single atomic fetch-and-add. The hot path (`next`) makes no RPC call and
//! takes no lock; the only RPC is the one-time seed and explicit `resync`.
//!
//! Gap-on-failure semantics are subtle and documented precisely on
//! `onFailure` below: a handed-out nonce is only safely reusable while it is
//! the highest one issued. Once a higher nonce is in flight, a lower failed
//! nonce becomes a gap that stalls the account until it is filled, and the
//! only safe recovery is `resync`.

const std = @import("std");
const provider_mod = @import("provider.zig");
const runtime = @import("runtime.zig");

/// Sentinel returned by `peek` when the manager has not been seeded yet.
/// `next()` performs the seed; `peek()` never does I/O, so it cannot know the
/// real base before the first `next()`/`resync()`.
pub const UNSEEDED: u64 = std.math.maxInt(u64);

/// Thread-safe local nonce allocator for a single sending address.
///
/// One `NonceManager` tracks one address. Construct it with `init` (no I/O),
/// then call `next()` to obtain each transaction's nonce. The manager does
/// not own the provider and never frees it; it holds no heap allocations and
/// therefore needs no `deinit`.
pub const NonceManager = struct {
    provider: *provider_mod.Provider,
    address: [20]u8,

    /// The next nonce to hand out. Valid only once `seeded` is true.
    next_nonce: std.atomic.Value(u64),
    /// True once `next_nonce` has been seeded from the chain.
    seeded: std.atomic.Value(bool),
    /// Guards the one-time seed and the `resync`/`reset` re-seed so exactly
    /// one thread performs the RPC. The hot path (`next` after seeding) never
    /// takes this lock.
    seed_mutex: std.Io.Mutex,

    /// Construct a manager for `address`. Does NOT perform any RPC; the first
    /// `next()` (or an explicit `resync()`) seeds from the chain's pending
    /// transaction count. The manager borrows `provider`.
    pub fn init(provider: *provider_mod.Provider, address: [20]u8) NonceManager {
        return .{
            .provider = provider,
            .address = address,
            .next_nonce = std.atomic.Value(u64).init(0),
            .seeded = std.atomic.Value(bool).init(false),
            .seed_mutex = .init,
        };
    }

    /// Ensure the manager is seeded, performing the seeding RPC at most once
    /// across all threads.
    ///
    /// Race-safety approach: a fast unsynchronized acquire-load of `seeded`
    /// short-circuits the common already-seeded case with no lock. When unset,
    /// threads contend on `seed_mutex`; the winner re-checks `seeded` under the
    /// lock (double-checked locking), performs the single RPC, stores the base
    /// with a release store, and only then sets `seeded`. Losers block on the
    /// mutex and observe the freshly stored base. Thus exactly one RPC runs and
    /// no thread reads `next_nonce` before it is initialized.
    fn ensureSeeded(self: *NonceManager) !void {
        if (self.seeded.load(.acquire)) return;

        const io = runtime.defaultIo();
        self.seed_mutex.lockUncancelable(io);
        defer self.seed_mutex.unlock(io);

        // Another thread may have seeded while we waited for the lock.
        if (self.seeded.load(.acquire)) return;

        const base = try self.provider.getTransactionCountAt(self.address, .pending);
        self.next_nonce.store(base, .release);
        self.seeded.store(true, .release);
    }

    /// Return the next nonce to use, then advance. Seeds lazily on first call.
    ///
    /// After seeding, this is a single atomic fetch-and-add: two threads
    /// calling `next()` concurrently always receive distinct, contiguous
    /// nonces and never the same value. No RPC and no lock on the seeded hot
    /// path.
    pub fn next(self: *NonceManager) !u64 {
        try self.ensureSeeded();
        return self.next_nonce.fetchAdd(1, .monotonic);
    }

    /// Return the nonce that the next `next()` call would hand out, without
    /// advancing. Returns `UNSEEDED` if the manager has not been seeded yet
    /// (no I/O is performed here -- call `next()` or `resync()` to seed).
    pub fn peek(self: *NonceManager) u64 {
        if (!self.seeded.load(.acquire)) return UNSEEDED;
        return self.next_nonce.load(.monotonic);
    }

    /// Discard all local state and re-seed from the chain's pending count,
    /// returning the new base. Use this to recover after dropped or replaced
    /// transactions have left a gap the manager cannot reason about locally
    /// (the on-chain pending count is authoritative).
    ///
    /// This is a hard reset: any nonces handed out but not yet mined are
    /// abandoned. Call it only when no `next()`-issued transaction is still
    /// expected to land, otherwise an in-flight transaction may collide with
    /// a re-issued nonce.
    pub fn resync(self: *NonceManager) !u64 {
        const io = runtime.defaultIo();
        self.seed_mutex.lockUncancelable(io);
        defer self.seed_mutex.unlock(io);

        const base = try self.provider.getTransactionCountAt(self.address, .pending);
        self.next_nonce.store(base, .release);
        self.seeded.store(true, .release);
        return base;
    }

    /// Alias for `resync` for callers that read "reset" as "forget local
    /// state and re-fetch from chain". Discards local state; see `resync`.
    pub fn reset(self: *NonceManager) !u64 {
        return self.resync();
    }

    /// Return a handed-out nonce to the pool so the next `next()` reuses it.
    ///
    /// This succeeds ONLY when `nonce` is the most recently issued nonce, i.e.
    /// `nonce == peek() - 1`, and is then a no-op-safe CAS that rolls the
    /// counter back by one. It returns `true` when the rollback happened and
    /// `false` otherwise.
    ///
    /// Why only the last one? Nonces must be consumed contiguously on chain.
    /// If you handed out N then N+1 and N failed, you cannot reuse N: N+1 is
    /// already in flight, so reusing N would either duplicate (if N+1 lands)
    /// or, more importantly, N+1 can never confirm until N is filled -- the
    /// account is already committed to a higher nonce. Reinjecting a middle
    /// nonce here would let a later `next()` hand out a value below one already
    /// broadcast, producing a duplicate-nonce collision. So for any nonce that
    /// is not the current high-water mark this is a documented no-op; recover
    /// from such gaps with `resync()` once the in-flight transactions resolve.
    ///
    /// The CAS also guards against a concurrent `next()`: if another thread
    /// advanced the counter between your failure and this call, `nonce` is no
    /// longer `peek()-1`, the CAS fails, and we correctly decline to roll back.
    pub fn onFailure(self: *NonceManager, nonce: u64) bool {
        if (!self.seeded.load(.acquire)) return false;
        // `UNSEEDED` (maxInt(u64)) is never a real issued nonce and would
        // overflow the `nonce + 1` below; reject it explicitly.
        if (nonce == UNSEEDED) return false;
        // Roll the counter from nonce+1 back to nonce, but only if it is still
        // exactly nonce+1 (i.e. `nonce` was the last one we issued and nobody
        // has advanced past it).
        return self.next_nonce.cmpxchgStrong(nonce + 1, nonce, .monotonic, .monotonic) == null;
    }
};

// ============================================================================
// Tests
// ============================================================================

const http_transport_mod = @import("http_transport.zig");
const primitives = @import("primitives.zig");

/// Build a manager pre-seeded to `base` without any RPC, so the pure
/// nonce-sequencing logic can be exercised offline.
fn seededManager(provider: *provider_mod.Provider, base: u64) NonceManager {
    var mgr = NonceManager.init(provider, @splat(0x11));
    mgr.next_nonce.store(base, .release);
    mgr.seeded.store(true, .release);
    return mgr;
}

test "next() returns increasing values from a seeded base" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = seededManager(&provider, 7);
    try std.testing.expectEqual(@as(u64, 7), try mgr.next());
    try std.testing.expectEqual(@as(u64, 8), try mgr.next());
    try std.testing.expectEqual(@as(u64, 9), try mgr.next());
    try std.testing.expectEqual(@as(u64, 10), mgr.peek());
}

test "peek does not advance" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = seededManager(&provider, 3);
    try std.testing.expectEqual(@as(u64, 3), mgr.peek());
    try std.testing.expectEqual(@as(u64, 3), mgr.peek());
    try std.testing.expectEqual(@as(u64, 3), try mgr.next());
    try std.testing.expectEqual(@as(u64, 4), mgr.peek());
}

test "peek returns UNSEEDED before seeding" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = NonceManager.init(&provider, @splat(0x22));
    try std.testing.expectEqual(UNSEEDED, mgr.peek());
}

test "onFailure(next-1) makes the next call reuse that nonce" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = seededManager(&provider, 100);
    const n = try mgr.next(); // 100, peek now 101
    try std.testing.expectEqual(@as(u64, 100), n);

    // The last issued nonce failed: return it.
    try std.testing.expect(mgr.onFailure(n));
    try std.testing.expectEqual(@as(u64, 100), mgr.peek());
    // The next send reuses it.
    try std.testing.expectEqual(@as(u64, 100), try mgr.next());
}

test "onFailure(other) is a no-op" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = seededManager(&provider, 50);
    const a = try mgr.next(); // 50
    const b = try mgr.next(); // 51, peek now 52
    try std.testing.expectEqual(@as(u64, 50), a);
    try std.testing.expectEqual(@as(u64, 51), b);

    // `a` (50) is a middle nonce now that 51 is in flight: cannot reuse.
    try std.testing.expect(!mgr.onFailure(a));
    try std.testing.expectEqual(@as(u64, 52), mgr.peek());

    // A never-issued / future nonce is also declined.
    try std.testing.expect(!mgr.onFailure(999));
    try std.testing.expectEqual(@as(u64, 52), mgr.peek());

    // Only the true high-water mark (51) rolls back.
    try std.testing.expect(mgr.onFailure(b));
    try std.testing.expectEqual(@as(u64, 51), mgr.peek());
}

test "onFailure before seeding is a no-op" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = NonceManager.init(&provider, @splat(0x33));
    try std.testing.expect(!mgr.onFailure(0));
}

test "onFailure(UNSEEDED) does not overflow and is a no-op" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    var mgr = seededManager(&provider, 0);
    // UNSEEDED == maxInt(u64); `nonce + 1` would overflow without the guard.
    try std.testing.expect(!mgr.onFailure(UNSEEDED));
    try std.testing.expectEqual(@as(u64, 0), mgr.peek());
}

test "concurrent next() yields a contiguous, duplicate-free nonce set" {
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);

    const base: u64 = 1000;
    var mgr = seededManager(&provider, base);

    const num_threads = 8;
    const per_thread = 500;
    const total = num_threads * per_thread;

    const results = try std.testing.allocator.alloc(u64, total);
    defer std.testing.allocator.free(results);

    const Worker = struct {
        fn run(m: *NonceManager, out: []u64) void {
            for (out) |*slot| {
                slot.* = m.next() catch unreachable;
            }
        }
    };

    var threads: [num_threads]std.Thread = undefined;
    var spawned: usize = 0;
    for (0..num_threads) |i| {
        threads[i] = std.Thread.spawn(.{}, Worker.run, .{ &mgr, results[i * per_thread .. (i + 1) * per_thread] }) catch {
            // If the harness cannot spawn threads, run the remaining work
            // inline so the assertion below still holds, and stop spawning.
            Worker.run(&mgr, results[i * per_thread ..]);
            break;
        };
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    // Every nonce in [base, base+total) must appear exactly once.
    var seen = try std.testing.allocator.alloc(bool, total);
    defer std.testing.allocator.free(seen);
    @memset(seen, false);

    for (results) |v| {
        try std.testing.expect(v >= base and v < base + total);
        const idx = v - base;
        try std.testing.expect(!seen[idx]); // no duplicates
        seen[idx] = true;
    }
    for (seen) |s| try std.testing.expect(s); // contiguous, no gaps
    try std.testing.expectEqual(base + total, mgr.peek());
}

test "all public declarations compile" {
    // `next`, `resync`, `reset`, and `ensureSeeded` reach `Provider` RPC paths
    // that have no offline unit test; force semantic analysis so lazily
    // compiled API breakage is caught here.
    std.testing.refAllDecls(@This());
}
