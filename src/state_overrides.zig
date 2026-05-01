const std = @import("std");
const primitives = @import("primitives.zig");
const hex_mod = @import("hex.zig");

/// State overrides for `eth_call`. Lets simulators answer "what if?"
/// questions without forking a node: what if this token balance was X?
/// what if this storage slot held Y? what if this address ran this
/// alternative bytecode?
///
/// Maps to the third parameter of `eth_call`:
/// `eth_call(transaction, blockTag, stateOverrideObject)`.
/// See the Geth docs:
/// https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-eth#eth-call
///
/// Usage:
///   var overrides = StateOverrides.init(allocator);
///   defer overrides.deinit();
///   try overrides.setBalance(target, 100 * std.math.pow(u256, 10, 18));
///   try overrides.setStorageAt(pool, slot, new_value);
///   const result = try provider.callWithOverrides(target, calldata, &overrides);
///
/// Memory: `setCode` deep-copies the bytecode, so callers may free their
/// reference immediately after the call. Storage maps are owned by the
/// `Override` value.
pub const StorageMap = std.AutoHashMap([32]u8, [32]u8);

pub const Override = struct {
    balance: ?u256 = null,
    nonce: ?u64 = null,
    /// Heap-owned bytecode bytes.
    code: ?[]u8 = null,
    /// Full state replacement: any slot not listed here is treated as zero.
    /// Mutually exclusive with `state_diff`; if both are set, `state` wins
    /// per the JSON-RPC spec.
    state: ?StorageMap = null,
    /// Partial state overlay: listed slots take these values, others stay
    /// at the chain's current value.
    state_diff: ?StorageMap = null,
};

pub const StateOverrides = struct {
    overrides: std.AutoHashMap([20]u8, Override),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StateOverrides {
        return .{
            .overrides = std.AutoHashMap([20]u8, Override).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StateOverrides) void {
        var it = self.overrides.iterator();
        while (it.next()) |entry| {
            const ov = entry.value_ptr;
            if (ov.code) |c| self.allocator.free(c);
            if (ov.state) |*m| @constCast(m).deinit();
            if (ov.state_diff) |*m| @constCast(m).deinit();
        }
        self.overrides.deinit();
    }

    /// Get-or-create the per-address Override slot.
    fn ensureOverride(self: *StateOverrides, addr: [20]u8) !*Override {
        const result = try self.overrides.getOrPut(addr);
        if (!result.found_existing) {
            result.value_ptr.* = .{};
        }
        return result.value_ptr;
    }

    pub fn setBalance(self: *StateOverrides, addr: [20]u8, value: u256) !void {
        const ov = try self.ensureOverride(addr);
        ov.balance = value;
    }

    pub fn setNonce(self: *StateOverrides, addr: [20]u8, value: u64) !void {
        const ov = try self.ensureOverride(addr);
        ov.nonce = value;
    }

    /// Override the bytecode at `addr`. The bytes are deep-copied; the
    /// caller may free their reference immediately.
    pub fn setCode(self: *StateOverrides, addr: [20]u8, bytecode: []const u8) !void {
        const ov = try self.ensureOverride(addr);
        const copy = try self.allocator.alloc(u8, bytecode.len);
        errdefer self.allocator.free(copy);
        @memcpy(copy, bytecode);
        if (ov.code) |old| self.allocator.free(old);
        ov.code = copy;
    }

    /// Set a single storage slot via the `stateDiff` mechanism (overlay
    /// onto the chain's current storage). Subsequent calls accumulate into
    /// the same map.
    pub fn setStorageAt(self: *StateOverrides, addr: [20]u8, slot: [32]u8, value: [32]u8) !void {
        const ov = try self.ensureOverride(addr);
        if (ov.state_diff == null) {
            ov.state_diff = StorageMap.init(self.allocator);
        }
        try ov.state_diff.?.put(slot, value);
    }

    /// Replace storage at `addr` entirely with the given key/value pair.
    /// Any slot not subsequently `setFullStorage`'d at this address is
    /// treated as zero by the node. Useful for sandboxing a contract.
    pub fn setFullStorage(self: *StateOverrides, addr: [20]u8, slot: [32]u8, value: [32]u8) !void {
        const ov = try self.ensureOverride(addr);
        if (ov.state == null) {
            ov.state = StorageMap.init(self.allocator);
        }
        try ov.state.?.put(slot, value);
    }

    /// True when no overrides have been set; the JSON serializer should
    /// emit nothing rather than an empty object.
    pub fn isEmpty(self: *const StateOverrides) bool {
        return self.overrides.count() == 0;
    }

    /// Serialize the overrides as the JSON object expected by `eth_call`'s
    /// third parameter. Caller owns the returned memory.
    /// Example output:
    ///   {"0xaaa...":{"balance":"0x...","stateDiff":{"0x...":"0x..."}}}
    pub fn serializeJson(self: *const StateOverrides, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.append(allocator, '{');
        var first_addr = true;
        var addr_it = self.overrides.iterator();
        while (addr_it.next()) |addr_entry| {
            if (!first_addr) try buf.append(allocator, ',');
            first_addr = false;

            const addr_hex = primitives.addressToHex(addr_entry.key_ptr);
            try buf.append(allocator, '"');
            try buf.appendSlice(allocator, &addr_hex);
            try buf.appendSlice(allocator, "\":{");
            try writeOverride(allocator, &buf, addr_entry.value_ptr.*);
            try buf.append(allocator, '}');
        }
        try buf.append(allocator, '}');

        return buf.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn writeOverride(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), ov: Override) !void {
    var first_field = true;

    if (ov.balance) |balance| {
        if (!first_field) try buf.append(allocator, ',');
        first_field = false;
        try buf.appendSlice(allocator, "\"balance\":\"");
        try writeHexU256(allocator, buf, balance);
        try buf.append(allocator, '"');
    }

    if (ov.nonce) |nonce| {
        if (!first_field) try buf.append(allocator, ',');
        first_field = false;
        try buf.appendSlice(allocator, "\"nonce\":\"");
        try writeHexU64(allocator, buf, nonce);
        try buf.append(allocator, '"');
    }

    if (ov.code) |code| {
        if (!first_field) try buf.append(allocator, ',');
        first_field = false;
        try buf.appendSlice(allocator, "\"code\":\"");
        const hex = try hex_mod.bytesToHex(allocator, code);
        defer allocator.free(hex);
        try buf.appendSlice(allocator, hex);
        try buf.append(allocator, '"');
    }

    if (ov.state) |state_map| {
        if (!first_field) try buf.append(allocator, ',');
        first_field = false;
        try buf.appendSlice(allocator, "\"state\":");
        try writeStorageMap(allocator, buf, state_map);
    }

    if (ov.state_diff) |diff_map| {
        if (!first_field) try buf.append(allocator, ',');
        first_field = false;
        try buf.appendSlice(allocator, "\"stateDiff\":");
        try writeStorageMap(allocator, buf, diff_map);
    }
}

fn writeStorageMap(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), map: StorageMap) !void {
    try buf.append(allocator, '{');
    var first = true;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (!first) try buf.append(allocator, ',');
        first = false;
        const slot_hex = primitives.hashToHex(entry.key_ptr);
        const value_hex = primitives.hashToHex(entry.value_ptr);
        try buf.append(allocator, '"');
        try buf.appendSlice(allocator, &slot_hex);
        try buf.appendSlice(allocator, "\":\"");
        try buf.appendSlice(allocator, &value_hex);
        try buf.append(allocator, '"');
    }
    try buf.append(allocator, '}');
}

/// Write `0x<minimal-hex>` for a u256 -- no leading zeros except for "0x0".
fn writeHexU256(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: u256) !void {
    var tmp: [66]u8 = undefined;
    const written = std.fmt.bufPrint(&tmp, "0x{x}", .{value}) catch unreachable;
    try buf.appendSlice(allocator, written);
}

fn writeHexU64(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), value: u64) !void {
    var tmp: [20]u8 = undefined;
    const written = std.fmt.bufPrint(&tmp, "0x{x}", .{value}) catch unreachable;
    try buf.appendSlice(allocator, written);
}

// ============================================================================
// Tests
// ============================================================================

test "StateOverrides - empty serializes to {}" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    try std.testing.expect(ov.isEmpty());
    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);
    try std.testing.expectEqualStrings("{}", json);
}

test "StateOverrides - balance only" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xaa} ** 20;
    try ov.setBalance(addr, 0x1234);

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);

    // The address is lowercase hex with 0x prefix, balance is minimal hex.
    try std.testing.expect(std.mem.indexOf(u8, json, "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"balance\":\"0x1234\"") != null);
}

test "StateOverrides - nonce, code, balance combined for one address" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xbb} ** 20;
    try ov.setBalance(addr, 100);
    try ov.setNonce(addr, 7);
    try ov.setCode(addr, &.{ 0x60, 0x80 });

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"balance\":\"0x64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"nonce\":\"0x7\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"code\":\"0x6080\"") != null);
}

test "StateOverrides - stateDiff merges multiple slots" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xcc} ** 20;
    var slot1: [32]u8 = .{0} ** 32;
    slot1[31] = 0x01;
    var slot2: [32]u8 = .{0} ** 32;
    slot2[31] = 0x02;
    var val: [32]u8 = .{0} ** 32;
    val[31] = 0xff;

    try ov.setStorageAt(addr, slot1, val);
    try ov.setStorageAt(addr, slot2, val);

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"stateDiff\":{") != null);
    // Both slots should appear (order is hash-map dependent so we don't
    // pin it).
    try std.testing.expect(std.mem.indexOf(u8, json, "0x0000000000000000000000000000000000000000000000000000000000000001") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0x0000000000000000000000000000000000000000000000000000000000000002") != null);
}

test "StateOverrides - full state replacement uses state not stateDiff" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xdd} ** 20;
    var slot: [32]u8 = .{0} ** 32;
    slot[31] = 0x05;
    var val: [32]u8 = .{0} ** 32;
    val[31] = 0x42;
    try ov.setFullStorage(addr, slot, val);

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"state\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stateDiff\"") == null);
}

test "StateOverrides - setCode replaces previous bytecode without leak" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xee} ** 20;
    try ov.setCode(addr, &.{ 0x01, 0x02 });
    try ov.setCode(addr, &.{ 0xab, 0xcd, 0xef });
    // The testing allocator catches leaks; this asserts that the first
    // bytecode buffer was freed when the second setCode replaced it.

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"code\":\"0xabcdef\"") != null);
}

test "StateOverrides - setBalance is idempotent on the same address" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr = [_]u8{0xff} ** 20;
    try ov.setBalance(addr, 1);
    try ov.setBalance(addr, 2);
    try ov.setBalance(addr, 3);

    try std.testing.expectEqual(@as(usize, 1), ov.overrides.count());
    const ov_entry = ov.overrides.get(addr).?;
    try std.testing.expectEqual(@as(?u256, 3), ov_entry.balance);
}

test "StateOverrides - multiple addresses round-trip" {
    const allocator = std.testing.allocator;
    var ov = StateOverrides.init(allocator);
    defer ov.deinit();

    const addr_a = [_]u8{0x11} ** 20;
    const addr_b = [_]u8{0x22} ** 20;
    try ov.setBalance(addr_a, 5);
    try ov.setBalance(addr_b, 7);

    const json = try ov.serializeJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"0x1111111111111111111111111111111111111111\":{\"balance\":\"0x5\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"0x2222222222222222222222222222222222222222\":{\"balance\":\"0x7\"}") != null);
}

test "writeHexU256 - zero is 0x0 not 0x" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try writeHexU256(allocator, &buf, 0);
    try std.testing.expectEqualStrings("0x0", buf.items);
}

test "writeHexU256 - large value" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try writeHexU256(allocator, &buf, 0xdeadbeef);
    try std.testing.expectEqualStrings("0xdeadbeef", buf.items);
}
