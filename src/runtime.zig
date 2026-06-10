const std = @import("std");

/// Default `std.Io` runtime used by the library.
///
/// Zig 0.16 moved networking, HTTP, sleeping, and clocks behind the `std.Io`
/// interface. To keep the public eth.zig API unchanged (no `Io` parameter on
/// transports), the library constructs a default blocking implementation
/// internally. All operations the library performs through this `Io` are
/// synchronous and run on the calling thread, matching the pre-0.16 behavior
/// of the blocking std.net / std.http APIs.
///
/// Callers that need a custom event loop should drive the library from their
/// own threads; the transports remain blocking by design.
pub fn defaultIo() std.Io {
    // `global_single_threaded` performs every operation synchronously on the
    // calling thread and never allocates, spawns threads, or requires deinit.
    return std.Io.Threaded.global_single_threaded.io();
}

/// Wall-clock time in milliseconds since the Unix epoch.
///
/// Replacement for `std.time.milliTimestamp()`, which was removed in
/// Zig 0.16. Deadline-style APIs in this library (for example
/// `WsTransport.readMessageDeadline`) use this time base.
pub fn milliTimestamp() i64 {
    return std.Io.Clock.now(.real, defaultIo()).toMilliseconds();
}

/// Blocking sleep for `ms` milliseconds.
///
/// Replacement for `std.Thread.sleep(ms * std.time.ns_per_ms)`, which was
/// removed in Zig 0.16.
pub fn sleepMs(ms: u64) void {
    const capped_ms: i64 = @intCast(@min(ms, std.math.maxInt(i64)));
    defaultIo().sleep(.fromMilliseconds(capped_ms), .awake) catch {};
}

test "milliTimestamp returns a plausible value" {
    const ms = milliTimestamp();
    // After 2020-01-01 and before 2100-01-01.
    try std.testing.expect(ms > 1_577_836_800_000);
    try std.testing.expect(ms < 4_102_444_800_000);
}

test "sleepMs zero returns immediately" {
    sleepMs(0);
}
