const std = @import("std");
const eth = @import("eth");

pub fn main() !void {
    var args = std.process.args();
    _ = args.next(); // skip program name

    const size_str = args.next() orelse "32";
    const iters_str = args.next() orelse "1000000";
    const backend_str = args.next() orelse "xkcp";

    const size = try std.fmt.parseInt(usize, size_str, 10);
    const iters = try std.fmt.parseInt(usize, iters_str, 10);

    // Allocate input data
    const allocator = std.heap.page_allocator;
    const data = try allocator.alloc(u8, size);
    defer allocator.free(data);
    @memset(data, 0xAB);

    if (std.mem.eql(u8, backend_str, "xkcp")) {
        // XKCP backend (our new implementation)
        for (0..iters) |_| {
            const result = eth.keccak.hash(data);
            std.mem.doNotOptimizeAway(&result);
        }
    } else if (std.mem.eql(u8, backend_str, "stdlib")) {
        // Zig stdlib backend
        for (0..iters) |_| {
            var result: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(data, &result, .{});
            std.mem.doNotOptimizeAway(&result);
        }
    }
}
