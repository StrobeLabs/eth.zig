const std = @import("std");
const provider_mod = @import("provider.zig");
const http_transport_mod = @import("http_transport.zig");
const abi_encode = @import("abi_encode.zig");
const uint256_mod = @import("uint256.zig");

/// A single call in a Multicall3 batch.
pub const Call3 = struct {
    target: [20]u8,
    allow_failure: bool,
    call_data: []const u8,
};

/// Result of a single call within a Multicall3 batch.
pub const Result = struct {
    success: bool,
    return_data: []const u8,
};

/// Multicall3 aggregate3 function selector: keccak256("aggregate3((address,bool,bytes)[])")
/// = 0x82ad56cb
pub const AGGREGATE3_SELECTOR = [4]u8{ 0x82, 0xad, 0x56, 0xcb };

/// Multicall3 batched call executor. Accumulates individual calls and executes
/// them all in a single eth_call to the Multicall3 contract via aggregate3().
///
/// The Multicall3 contract is deployed at a well-known address on most chains:
/// 0xcA11bde05977b3631167028862bE2a173976CA11
pub const Multicall = struct {
    provider: *provider_mod.Provider,
    multicall_address: [20]u8,
    allocator: std.mem.Allocator,
    calls: std.ArrayList(Call3) = .empty,

    /// Create a new Multicall instance.
    pub fn init(allocator: std.mem.Allocator, provider: *provider_mod.Provider, multicall_address: [20]u8) Multicall {
        return .{
            .provider = provider,
            .multicall_address = multicall_address,
            .allocator = allocator,
        };
    }

    /// Free the internal calls list.
    pub fn deinit(self: *Multicall) void {
        self.calls.deinit(self.allocator);
    }

    /// Add a call to the batch.
    pub fn addCall(self: *Multicall, target: [20]u8, call_data: []const u8, allow_failure: bool) !void {
        try self.calls.append(self.allocator, .{
            .target = target,
            .allow_failure = allow_failure,
            .call_data = call_data,
        });
    }

    /// Execute all pending calls in a single eth_call via Multicall3.aggregate3().
    ///
    /// The aggregate3 function signature is:
    ///   aggregate3((address,bool,bytes)[]) returns ((bool,bytes)[])
    ///
    /// Each Call3 is ABI-encoded as a tuple of (address, bool, bytes).
    /// The entire input is a dynamic array of these tuples.
    ///
    /// Returns a slice of Result structs. Caller owns the returned memory.
    pub fn execute(self: *Multicall) ![]Result {
        const calldata = try self.encodeAggregate3();
        defer self.allocator.free(calldata);

        const raw_result = try self.provider.call(self.multicall_address, calldata);
        defer self.allocator.free(raw_result);

        return try decodeAggregate3Results(self.allocator, raw_result);
    }

    /// Clear all pending calls.
    pub fn reset(self: *Multicall) void {
        self.calls.clearRetainingCapacity();
    }

    /// ABI-encode the aggregate3 call.
    /// Produces: selector(4) + encoded((address,bool,bytes)[])
    ///
    /// The argument is a dynamic array of tuples. In ABI encoding:
    /// - Outer: offset to array data (32 bytes) -> 0x20
    /// - Array length (32 bytes)
    /// - For each element: offset to tuple data (32 bytes each)
    /// - For each tuple:
    ///   - address (32 bytes, left-padded)
    ///   - bool (32 bytes)
    ///   - offset to bytes data (32 bytes) -> 0x60 (3 * 32)
    ///   - bytes length (32 bytes)
    ///   - bytes data (padded to 32)
    pub fn encodeAggregate3(self: *Multicall) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);

        // Function selector
        try buf.appendSlice(self.allocator, &AGGREGATE3_SELECTOR);

        // Offset to array data (relative to start of params)
        try appendWord(self.allocator, &buf, 0x20);

        // Array length
        try appendWord(self.allocator, &buf, self.calls.items.len);

        // Calculate offsets for each tuple element within the array.
        // After the array of offsets (n * 32 bytes), the tuple data starts.
        // Each tuple's offset is relative to the start of the array data
        // (right after the length word).
        //
        // First, encode all offsets. Then encode all tuple bodies.
        // The offsets section is: n * 32 bytes (one offset per tuple).
        // We need to know the size of each encoded tuple to calculate offsets.

        const n = self.calls.items.len;

        // Calculate sizes of each tuple body
        var tuple_sizes = try self.allocator.alloc(usize, n);
        defer self.allocator.free(tuple_sizes);

        for (self.calls.items, 0..) |c, i| {
            // Each tuple body:
            // - address: 32 bytes
            // - bool: 32 bytes
            // - offset to bytes: 32 bytes (always 0x60 = 96)
            // - bytes length: 32 bytes
            // - bytes data: padded to 32-byte boundary
            const data_padded = padTo32(c.call_data.len);
            tuple_sizes[i] = 32 + 32 + 32 + 32 + data_padded;
        }

        // Offsets section: n * 32 bytes
        var current_offset: usize = n * 32;
        for (0..n) |i| {
            try appendWord(self.allocator, &buf, current_offset);
            current_offset += tuple_sizes[i];
        }

        // Tuple bodies
        for (self.calls.items) |c| {
            // address (left-padded to 32 bytes)
            var addr_word: [32]u8 = [_]u8{0} ** 32;
            @memcpy(addr_word[12..32], &c.target);
            try buf.appendSlice(self.allocator, &addr_word);

            // bool
            try appendWord(self.allocator, &buf, if (c.allow_failure) @as(usize, 1) else @as(usize, 0));

            // offset to bytes data within the tuple (always 0x60 = 3 * 32)
            try appendWord(self.allocator, &buf, 0x60);

            // bytes length
            try appendWord(self.allocator, &buf, c.call_data.len);

            // bytes data (padded)
            try buf.appendSlice(self.allocator, c.call_data);
            const padding = padTo32(c.call_data.len) - c.call_data.len;
            try buf.appendNTimes(self.allocator, 0, padding);
        }

        return buf.toOwnedSlice(self.allocator);
    }
};

/// Decode the ABI-encoded result of aggregate3: (bool, bytes)[]
/// Returns a slice of Result structs. Caller owns all returned memory.
pub fn decodeAggregate3Results(allocator: std.mem.Allocator, data: []const u8) ![]Result {
    if (data.len < 64) return error.OutOfMemory;

    // First word: offset to array data (should be 0x20)
    const array_offset = readWord(data[0..32]);
    if (array_offset + 32 > data.len) return error.OutOfMemory;

    // Array length
    const array_len = readWord(data[array_offset .. array_offset + 32]);
    const array_data_start = array_offset + 32;

    var results = try allocator.alloc(Result, array_len);
    errdefer {
        for (results) |r| {
            if (r.return_data.len > 0) allocator.free(r.return_data);
        }
        allocator.free(results);
    }

    // Read offsets for each result tuple
    for (0..array_len) |i| {
        const offset_pos = array_data_start + i * 32;
        if (offset_pos + 32 > data.len) return error.OutOfMemory;
        const tuple_offset = readWord(data[offset_pos .. offset_pos + 32]);
        const tuple_start = array_data_start + tuple_offset;

        // Each tuple: (bool success, bytes returnData)
        // word 0: success (bool)
        // word 1: offset to returnData within the tuple
        // At that offset: length word + data
        if (tuple_start + 64 > data.len) return error.OutOfMemory;

        const success_word = readWord(data[tuple_start .. tuple_start + 32]);
        const return_data_offset = readWord(data[tuple_start + 32 .. tuple_start + 64]);
        const return_data_abs = tuple_start + return_data_offset;

        if (return_data_abs + 32 > data.len) return error.OutOfMemory;
        const return_data_len = readWord(data[return_data_abs .. return_data_abs + 32]);
        const return_data_start = return_data_abs + 32;

        if (return_data_start + return_data_len > data.len) return error.OutOfMemory;

        var return_data: []const u8 = &.{};
        if (return_data_len > 0) {
            const rd = try allocator.alloc(u8, return_data_len);
            @memcpy(rd, data[return_data_start .. return_data_start + return_data_len]);
            return_data = rd;
        }

        results[i] = .{
            .success = success_word != 0,
            .return_data = return_data,
        };
    }

    return results;
}

/// Free a slice of Results returned by execute or decodeAggregate3Results.
pub fn freeResults(allocator: std.mem.Allocator, results: []Result) void {
    for (results) |r| {
        if (r.return_data.len > 0) allocator.free(r.return_data);
    }
    allocator.free(results);
}

// ============================================================================
// Helpers
// ============================================================================

/// Append a usize as a big-endian 32-byte word to the buffer.
fn appendWord(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: usize) !void {
    const val_u256: u256 = @intCast(value);
    const bytes = uint256_mod.toBigEndianBytes(val_u256);
    try buf.appendSlice(allocator, &bytes);
}

/// Calculate the number of bytes needed to pad `len` up to a 32-byte boundary.
fn padTo32(len: usize) usize {
    if (len == 0) return 0;
    return ((len + 31) / 32) * 32;
}

/// Read a 32-byte big-endian word as a usize.
fn readWord(data: []const u8) usize {
    if (data.len < 32) return 0;
    const val = uint256_mod.fromBigEndianBytes(data[0..32].*);
    if (val > std.math.maxInt(usize)) return std.math.maxInt(usize);
    return @intCast(val);
}

// ============================================================================
// Tests
// ============================================================================

test "Multicall.init and deinit" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);
    const multicall_addr = [_]u8{0xca} ** 20;

    var mc = Multicall.init(allocator, &provider, multicall_addr);
    defer mc.deinit();

    try std.testing.expectEqual(@as(usize, 0), mc.calls.items.len);
    try std.testing.expectEqualSlices(u8, &multicall_addr, &mc.multicall_address);
}

test "Multicall.addCall adds calls" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    const target1 = [_]u8{0x11} ** 20;
    const target2 = [_]u8{0x22} ** 20;
    const calldata1 = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb };
    const calldata2 = [_]u8{ 0x70, 0xa0, 0x82, 0x31 };

    try mc.addCall(target1, &calldata1, false);
    try mc.addCall(target2, &calldata2, true);

    try std.testing.expectEqual(@as(usize, 2), mc.calls.items.len);
    try std.testing.expectEqualSlices(u8, &target1, &mc.calls.items[0].target);
    try std.testing.expect(!mc.calls.items[0].allow_failure);
    try std.testing.expectEqualSlices(u8, &target2, &mc.calls.items[1].target);
    try std.testing.expect(mc.calls.items[1].allow_failure);
}

test "Multicall.reset clears calls" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    try mc.addCall([_]u8{0x11} ** 20, &.{0x01}, false);
    try mc.addCall([_]u8{0x22} ** 20, &.{0x02}, true);
    try std.testing.expectEqual(@as(usize, 2), mc.calls.items.len);

    mc.reset();
    try std.testing.expectEqual(@as(usize, 0), mc.calls.items.len);
}

test "Multicall.encodeAggregate3 produces valid ABI encoding" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    const target = [_]u8{0x11} ** 20;
    const calldata = [_]u8{ 0x70, 0xa0, 0x82, 0x31 }; // balanceOf selector

    try mc.addCall(target, &calldata, false);

    const encoded = try mc.encodeAggregate3();
    defer allocator.free(encoded);

    // Check selector
    try std.testing.expectEqualSlices(u8, &AGGREGATE3_SELECTOR, encoded[0..4]);

    // Check outer offset (should be 0x20 = 32)
    try std.testing.expectEqual(@as(u8, 0x20), encoded[4 + 31]);

    // Check array length (should be 1)
    try std.testing.expectEqual(@as(u8, 0x01), encoded[4 + 63]);

    // The encoding should be well-formed: selector(4) + offset(32) + length(32) +
    // offsets(1*32) + tuple(32+32+32+32+32) = 4 + 32 + 32 + 32 + 160 = 260
    try std.testing.expectEqual(@as(usize, 260), encoded.len);
}

test "Multicall.encodeAggregate3 with multiple calls" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    const target1 = [_]u8{0x11} ** 20;
    const target2 = [_]u8{0x22} ** 20;
    const calldata1 = [_]u8{ 0x70, 0xa0, 0x82, 0x31 };
    const calldata2 = [_]u8{ 0xa9, 0x05, 0x9c, 0xbb, 0x00 }; // 5 bytes

    try mc.addCall(target1, &calldata1, false);
    try mc.addCall(target2, &calldata2, true);

    const encoded = try mc.encodeAggregate3();
    defer allocator.free(encoded);

    // Check selector
    try std.testing.expectEqualSlices(u8, &AGGREGATE3_SELECTOR, encoded[0..4]);

    // Array length should be 2
    try std.testing.expectEqual(@as(u8, 0x02), encoded[4 + 63]);

    // Both calls should be encoded
    try std.testing.expect(encoded.len > 260);
}

test "Multicall.encodeAggregate3 with empty calldata" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    try mc.addCall([_]u8{0x11} ** 20, &.{}, true);

    const encoded = try mc.encodeAggregate3();
    defer allocator.free(encoded);

    // selector(4) + offset(32) + length(32) + offsets(32) + tuple(32+32+32+32+0) = 228
    try std.testing.expectEqual(@as(usize, 228), encoded.len);
}

test "decodeAggregate3Results decodes single result" {
    const allocator = std.testing.allocator;

    // Manually build the ABI-encoded output for: [(true, 0x00000064)]
    // Layout:
    //   word 0: offset to array = 0x20
    //   word 1: array length = 1
    //   word 2: offset to tuple[0] = 0x20
    //   word 3: success = 1
    //   word 4: offset to bytes = 0x40
    //   word 5: bytes length = 4
    //   word 6: bytes data (0x00000064 + padding)
    var data: [7 * 32]u8 = [_]u8{0} ** (7 * 32);

    // word 0: offset = 0x20
    data[31] = 0x20;
    // word 1: length = 1
    data[63] = 0x01;
    // word 2: tuple offset = 0x20
    data[95] = 0x20;
    // word 3: success = true
    data[127] = 0x01;
    // word 4: offset to bytes within tuple = 0x40
    data[159] = 0x40;
    // word 5: bytes length = 4
    data[191] = 0x04;
    // word 6: bytes data
    data[192] = 0x00;
    data[193] = 0x00;
    data[194] = 0x00;
    data[195] = 0x64;

    const results = try decodeAggregate3Results(allocator, &data);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expectEqual(@as(usize, 4), results[0].return_data.len);
    try std.testing.expectEqual(@as(u8, 0x64), results[0].return_data[3]);
}

test "decodeAggregate3Results decodes failed result" {
    const allocator = std.testing.allocator;

    // Build output for: [(false, 0x)]
    var data: [6 * 32]u8 = [_]u8{0} ** (6 * 32);

    // word 0: offset = 0x20
    data[31] = 0x20;
    // word 1: length = 1
    data[63] = 0x01;
    // word 2: tuple offset = 0x20
    data[95] = 0x20;
    // word 3: success = false (0)
    // word 4: offset to bytes within tuple = 0x40
    data[159] = 0x40;
    // word 5: bytes length = 0

    const results = try decodeAggregate3Results(allocator, &data);
    defer freeResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expectEqual(@as(usize, 0), results[0].return_data.len);
}

test "padTo32 calculates correct padding" {
    try std.testing.expectEqual(@as(usize, 0), padTo32(0));
    try std.testing.expectEqual(@as(usize, 32), padTo32(1));
    try std.testing.expectEqual(@as(usize, 32), padTo32(4));
    try std.testing.expectEqual(@as(usize, 32), padTo32(31));
    try std.testing.expectEqual(@as(usize, 32), padTo32(32));
    try std.testing.expectEqual(@as(usize, 64), padTo32(33));
    try std.testing.expectEqual(@as(usize, 64), padTo32(64));
    try std.testing.expectEqual(@as(usize, 96), padTo32(65));
}

test "AGGREGATE3_SELECTOR is correct" {
    // Verify the selector matches keccak256("aggregate3((address,bool,bytes)[])")
    const keccak = @import("keccak.zig");
    const computed = keccak.selector("aggregate3((address,bool,bytes)[])");
    try std.testing.expectEqualSlices(u8, &AGGREGATE3_SELECTOR, &computed);
}

test "Multicall.encodeAggregate3 address encoding" {
    const allocator = std.testing.allocator;
    var transport = http_transport_mod.HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();
    var provider = provider_mod.Provider.init(allocator, &transport);

    var mc = Multicall.init(allocator, &provider, [_]u8{0xca} ** 20);
    defer mc.deinit();

    // Use a known address to verify left-padding
    var target: [20]u8 = [_]u8{0} ** 20;
    target[0] = 0xde;
    target[1] = 0xad;
    target[18] = 0xbe;
    target[19] = 0xef;

    try mc.addCall(target, &.{ 0x01, 0x02, 0x03, 0x04 }, false);

    const encoded = try mc.encodeAggregate3();
    defer allocator.free(encoded);

    // The address should be at the tuple start position:
    // selector(4) + offset(32) + length(32) + tuple_offset(32) = 100
    // In the address word (32 bytes): first 12 bytes zero, then 20 bytes of address
    try std.testing.expectEqual(@as(u8, 0), encoded[100]);
    try std.testing.expectEqual(@as(u8, 0), encoded[111]);
    try std.testing.expectEqual(@as(u8, 0xde), encoded[112]);
    try std.testing.expectEqual(@as(u8, 0xad), encoded[113]);
    try std.testing.expectEqual(@as(u8, 0xbe), encoded[130]);
    try std.testing.expectEqual(@as(u8, 0xef), encoded[131]);
}
