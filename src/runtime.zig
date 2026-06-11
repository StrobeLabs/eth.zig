const std = @import("std");

/// A convenient blocking `std.Io` value callers can pass explicitly.
///
/// Zig 0.16 moved networking, HTTP, sleeping, clocks, and randomness behind the
/// `std.Io` interface. This library never reaches for an `Io` implicitly: every
/// network entry point and every operation needing time/randomness takes an
/// `io: std.Io` from the caller. `blockingIo()` exists purely as a convenience
/// so callers who do not run their own event loop can write, for example,
/// `HttpTransport.init(allocator, url, eth.runtime.blockingIo())`.
///
/// The returned `Io` performs every operation synchronously on the calling
/// thread and never allocates, spawns threads, or requires deinit.
pub fn blockingIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Wall-clock time in milliseconds since the Unix epoch, read through `io`.
///
/// Replacement for `std.time.milliTimestamp()`, which was removed in
/// Zig 0.16. Deadline-style APIs in this library (for example
/// `WsTransport.readMessageDeadline`) use this time base.
pub fn milliTimestamp(io: std.Io) i64 {
    return std.Io.Clock.now(.real, io).toMilliseconds();
}

/// Blocking sleep for `ms` milliseconds, driven by `io`.
///
/// Replacement for `std.Thread.sleep(ms * std.time.ns_per_ms)`, which was
/// removed in Zig 0.16.
pub fn sleepMs(io: std.Io, ms: u64) void {
    const capped_ms: i64 = @intCast(@min(ms, std.math.maxInt(i64)));
    io.sleep(.fromMilliseconds(capped_ms), .awake) catch {};
}

test "milliTimestamp returns a plausible value" {
    const ms = milliTimestamp(blockingIo());
    // After 2020-01-01 and before 2100-01-01.
    try std.testing.expect(ms > 1_577_836_800_000);
    try std.testing.expect(ms < 4_102_444_800_000);
}

test "sleepMs zero returns immediately" {
    sleepMs(blockingIo(), 0);
}
