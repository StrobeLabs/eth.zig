//! Typed eth_simulateV1 requests and results. Simulation never broadcasts.
//! See https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-eth.
const std = @import("std");
const json_rpc = @import("json_rpc.zig");
const hex = @import("hex.zig");
const uint256 = @import("uint256.zig");
const state = @import("state_overrides.zig");
const receipt = @import("receipt.zig");
const access = @import("access_list.zig");

/// A simulated transaction. Null fields are omitted so the node applies its
/// defaults. A null destination represents contract creation.
pub const Call = struct {
    from: ?[20]u8 = null,
    to: ?[20]u8 = null,
    gas: ?u64 = null,
    gas_price: ?u256 = null,
    max_fee_per_gas: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    value: ?u256 = null,
    nonce: ?u64 = null,
    chain_id: ?u64 = null,
    data: ?[]const u8 = null,
    access_list: ?[]const access.AccessListItem = null,

    pub fn jsonStringify(self: Call, j: *std.json.Stringify) std.json.Stringify.Error!void {
        try j.beginObject();
        if (self.from) |v| try hexField(j, "from", &v);
        if (self.to) |v| try hexField(j, "to", &v);
        try quantityField(j, "gas", self.gas);
        try quantityField(j, "gasPrice", self.gas_price);
        try quantityField(j, "maxFeePerGas", self.max_fee_per_gas);
        try quantityField(j, "maxPriorityFeePerGas", self.max_priority_fee_per_gas);
        try quantityField(j, "value", self.value);
        try quantityField(j, "nonce", self.nonce);
        try quantityField(j, "chainId", self.chain_id);
        if (self.data) |v| try hexField(j, "input", v);
        if (self.access_list) |items| {
            try j.objectField("accessList");
            try j.beginArray();
            for (items) |item| {
                try j.beginObject();
                try hexField(j, "address", &item.address);
                try j.objectField("storageKeys");
                try j.beginArray();
                for (item.storage_keys) |key| try j.print("\"0x{x}\"", .{&key});
                try j.endArray();
                try j.endObject();
            }
            try j.endArray();
        }
        try j.endObject();
    }
};

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64,

    pub fn jsonStringify(self: Withdrawal, j: *std.json.Stringify) std.json.Stringify.Error!void {
        try j.beginObject();
        try quantityField(j, "index", @as(?u64, self.index));
        try quantityField(j, "validatorIndex", @as(?u64, self.validator_index));
        try hexField(j, "address", &self.address);
        try quantityField(j, "amount", @as(?u64, self.amount));
        try j.endObject();
    }
};

pub const BlockOverrides = struct {
    number: ?u64 = null,
    time: ?u64 = null,
    gas_limit: ?u64 = null,
    base_fee_per_gas: ?u256 = null,
    blob_base_fee: ?u64 = null,
    prev_randao: ?[32]u8 = null,
    fee_recipient: ?[20]u8 = null,
    withdrawals: ?[]const Withdrawal = null,

    pub fn jsonStringify(self: BlockOverrides, j: *std.json.Stringify) std.json.Stringify.Error!void {
        try j.beginObject();
        try quantityField(j, "number", self.number);
        try quantityField(j, "time", self.time);
        try quantityField(j, "gasLimit", self.gas_limit);
        try quantityField(j, "baseFeePerGas", self.base_fee_per_gas);
        try quantityField(j, "blobBaseFee", self.blob_base_fee);
        if (self.prev_randao) |v| try hexField(j, "prevRandao", &v);
        if (self.fee_recipient) |v| try hexField(j, "feeRecipient", &v);
        if (self.withdrawals) |v| {
            try j.objectField("withdrawals");
            try j.write(v);
        }
        try j.endObject();
    }
};

pub const BlockStateCalls = struct {
    calls: []const Call,
    block_overrides: ?BlockOverrides = null,
    /// Borrows the existing state override set. Serialization uses its
    /// canonical JSON representation, including storage and bytecode.
    state_overrides: ?*const state.StateOverrides = null,
};

pub const SimulatePayload = struct {
    block_state_calls: []const BlockStateCalls,
    validation: bool = false,
    trace_transfers: bool = false,
    return_full_transactions: bool = false,
};

/// One arena owns all nested data. Call deinit once; do not individually free
/// borrowed strings, raw JSON, logs, or return data inside value.
pub fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
            self.* = undefined;
        }
    };
}

pub const RpcFailure = struct {
    code: i64,
    message: []const u8,
    /// Preserves the complete error payload, with no provider diagnostic cap.
    data: ?std.json.Value = null,
};

pub const CallResult = struct {
    status: enum { success, failure },
    return_data: []const u8,
    gas_used: u64,
    logs: []const receipt.Log,
    failure: ?RpcFailure,
};

pub const BlockResult = struct {
    number: ?u64,
    hash: ?[32]u8,
    calls: []const CallResult,
    /// The complete block result, including client-specific header fields and
    /// transactions. Simulated block identity varies across client versions.
    raw: std.json.Value,
};

pub const SimulateResult = Owned([]const BlockResult);

/// Encode the two positional eth_simulateV1 parameters. Caller owns the JSON.
pub fn formatParams(allocator: std.mem.Allocator, payload: SimulatePayload, block: json_rpc.BlockParam) ![]u8 {
    if (payload.block_state_calls.len == 0 or payload.block_state_calls.len > 256) return error.InvalidArgument;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp = arena.allocator();
    const WireBlock = struct {
        calls: []const Call,
        blockOverrides: ?BlockOverrides,
        stateOverrides: ?std.json.Value,
    };
    const blocks = try temp.alloc(WireBlock, payload.block_state_calls.len);
    for (blocks, payload.block_state_calls) |*wire, input| {
        wire.* = .{ .calls = input.calls, .blockOverrides = input.block_overrides, .stateOverrides = null };
        if (input.state_overrides) |overrides| {
            const raw = try overrides.serializeJson(temp);
            wire.stateOverrides = try std.json.parseFromSliceLeaky(std.json.Value, temp, raw, .{});
        }
    }
    var block_buf: [20]u8 = undefined;
    return std.json.Stringify.valueAlloc(allocator, .{ .{
        .blockStateCalls = blocks,
        .validation = payload.validation,
        .traceTransfers = payload.trace_transfers,
        .returnFullTransactions = payload.return_full_transactions,
    }, block.toString(&block_buf) }, .{ .emit_null_optional_fields = false });
}

/// Parse an eth_simulateV1 result value (without the JSON-RPC envelope).
pub fn parseResult(allocator: std.mem.Allocator, raw: []const u8) !SimulateResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const root = try parseJson(a, raw);
    const values = try array(root);
    const blocks = try a.alloc(BlockResult, values.len);
    for (blocks, values) |*block, value| {
        const obj = try object(value);
        const calls_json = try array(try field(obj, "calls"));
        const calls = try a.alloc(CallResult, calls_json.len);
        for (calls, calls_json) |*call, call_json| {
            const call_obj = try object(call_json);
            const result_status = try quantity(u8, try field(call_obj, "status"));
            if (result_status > 1) return error.InvalidResponse;
            call.* = .{
                .status = if (result_status == 1) .success else .failure,
                .return_data = try dataBytes(a, try field(call_obj, "returnData")),
                .gas_used = try quantity(u64, try field(call_obj, "gasUsed")),
                .logs = try parseLogs(a, optional(call_obj, "logs")),
                .failure = if (optional(call_obj, "error")) |err| try parseFailure(err) else null,
            };
        }
        block.* = .{
            .number = if (optional(obj, "number")) |v| try quantity(u64, v) else null,
            .hash = if (optional(obj, "hash")) |v| try fixedHex(32, v) else null,
            .calls = calls,
            .raw = value,
        };
    }
    return .{ .arena = arena, .value = blocks };
}

pub fn quantityField(j: *std.json.Stringify, name: []const u8, value: anytype) std.json.Stringify.Error!void {
    if (value) |v| {
        try j.objectField(name);
        try j.print("\"0x{x}\"", .{v});
    }
}

pub fn hexField(j: *std.json.Stringify, name: []const u8, value: []const u8) std.json.Stringify.Error!void {
    try j.objectField(name);
    try j.print("\"0x{x}\"", .{value});
}

pub fn parseJson(allocator: std.mem.Allocator, raw: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, raw, .{ .allocate = .alloc_always }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
}

pub fn object(value: std.json.Value) !std.json.ObjectMap {
    if (value != .object) return error.InvalidResponse;
    return value.object;
}

pub fn array(value: std.json.Value) ![]const std.json.Value {
    if (value != .array) return error.InvalidResponse;
    return value.array.items;
}

pub fn field(obj: std.json.ObjectMap, name: []const u8) !std.json.Value {
    return obj.get(name) orelse error.InvalidResponse;
}

pub fn optional(obj: std.json.ObjectMap, name: []const u8) ?std.json.Value {
    const value = obj.get(name) orelse return null;
    return if (value == .null) null else value;
}

pub fn string(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.InvalidResponse;
    return value.string;
}

pub fn quantity(comptime T: type, value: std.json.Value) !T {
    const s = try string(value);
    if (s.len < 3 or !std.mem.startsWith(u8, s, "0x")) return error.InvalidResponse;
    const n = uint256.fromHex(s) catch return error.InvalidResponse;
    if (n > std.math.maxInt(T)) return error.InvalidResponse;
    return @intCast(n);
}

pub fn fixedHex(comptime size: usize, value: std.json.Value) ![size]u8 {
    const s = try string(value);
    if (s.len != 2 + size * 2 or !std.mem.startsWith(u8, s, "0x")) return error.InvalidResponse;
    return hex.hexToBytesFixed(size, s) catch return error.InvalidResponse;
}

pub fn dataBytes(allocator: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    const s = try string(value);
    if (s.len < 2 or s.len % 2 != 0 or !std.mem.startsWith(u8, s, "0x")) return error.InvalidResponse;
    const out = try allocator.alloc(u8, (s.len - 2) / 2);
    errdefer allocator.free(out);
    return hex.hexToBytes(out, s) catch return error.InvalidResponse;
}

pub fn parseFailure(value: std.json.Value) !RpcFailure {
    const obj = try object(value);
    const code = try field(obj, "code");
    if (code != .integer) return error.InvalidResponse;
    return .{
        .code = code.integer,
        .message = try string(try field(obj, "message")),
        .data = optional(obj, "data"),
    };
}

fn parseLogs(allocator: std.mem.Allocator, value: ?std.json.Value) ![]const receipt.Log {
    const values = try array(value orelse return &.{});
    const logs = try allocator.alloc(receipt.Log, values.len);
    for (logs, values) |*log, v| {
        const obj = try object(v);
        const topics_json = try array(try field(obj, "topics"));
        const topics = try allocator.alloc([32]u8, topics_json.len);
        for (topics, topics_json) |*topic, t| topic.* = try fixedHex(32, t);
        log.* = .{
            .address = try fixedHex(20, try field(obj, "address")),
            .topics = topics,
            .data = try dataBytes(allocator, try field(obj, "data")),
            .block_number = if (optional(obj, "blockNumber")) |n| try quantity(u64, n) else null,
            .transaction_hash = if (optional(obj, "transactionHash")) |h| try fixedHex(32, h) else null,
            .block_hash = if (optional(obj, "blockHash")) |h| try fixedHex(32, h) else null,
            .transaction_index = if (optional(obj, "transactionIndex")) |n| try quantity(u32, n) else null,
            .log_index = if (optional(obj, "logIndex")) |n| try quantity(u32, n) else null,
            .removed = false,
        };
    }
    return logs;
}

test "simulation request reuses state overrides and encodes quantities" {
    const a = std.testing.allocator;
    var overrides = state.StateOverrides.init(a);
    defer overrides.deinit();
    const addr: [20]u8 = @splat(0xab);
    try overrides.setBalance(addr, 100);
    try overrides.setStorageAt(addr, @splat(0), @splat(1));
    const raw = try formatParams(a, .{
        .block_state_calls = &.{.{
            .calls = &.{.{ .from = addr, .to = addr, .value = 0, .data = &.{ 0x12, 0x34 } }},
            .state_overrides = &overrides,
            .block_overrides = .{ .base_fee_per_gas = 9 },
        }},
        .trace_transfers = true,
    }, .{ .number = 15 });
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
    defer parsed.deinit();
    const params = parsed.value.array.items;
    try std.testing.expectEqualStrings("0xf", params[1].string);
    const payload = params[0].object;
    try std.testing.expect(payload.get("traceTransfers").?.bool);
    const block = payload.get("blockStateCalls").?.array.items[0].object;
    try std.testing.expectEqualStrings("0x9", block.get("blockOverrides").?.object.get("baseFeePerGas").?.string);
    const call = block.get("calls").?.array.items[0].object;
    try std.testing.expectEqualStrings("0x1234", call.get("input").?.string);
    try std.testing.expectEqualStrings("0x0", call.get("value").?.string);
    try std.testing.expect(call.get("gas") == null);
    const account = block.get("stateOverrides").?.object.get("0xabababababababababababababababababababab").?.object;
    try std.testing.expectEqualStrings("0x64", account.get("balance").?.string);
    try std.testing.expect(account.get("stateDiff") != null);
}

const fixture =
    \\[{"number":"0x1","calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x1234","logs":[{"address":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","topics":[],"data":"0x01"}]},{"status":"0x0","gasUsed":"0x100","returnData":"0xdeadbeef","error":{"code":3,"message":"execution reverted","data":"0xdeadbeef"}}]},{"number":"0x2","calls":[{"status":"0x1","gasUsed":"0x0","returnData":"0x","logs":[]}]}]
;

fn checkResult(allocator: std.mem.Allocator) !void {
    var result = try parseResult(allocator, fixture);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.value.len);
    try std.testing.expectEqual(@as(u64, 21000), result.value[0].calls[0].gas_used);
    try std.testing.expectEqualSlices(u8, &.{ 0x12, 0x34 }, result.value[0].calls[0].return_data);
    try std.testing.expectEqual(@as(usize, 1), result.value[0].calls[0].logs.len);
    try std.testing.expectEqual(.failure, result.value[0].calls[1].status);
    try std.testing.expectEqual(@as(i64, 3), result.value[0].calls[1].failure.?.code);
    try std.testing.expectEqualStrings("0xdeadbeef", result.value[0].calls[1].failure.?.data.?.string);
}

test "multi-block simulation preserves successful calls and per-call reverts" {
    try checkResult(std.testing.allocator);
}

test "simulation result frees all nested allocations on allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkResult, .{});
}

test "simulation rejects malformed results and invalid request block counts" {
    const a = std.testing.allocator;
    for ([_][]const u8{
        "{}",                                                                             "[{}]",                                                                                           "[{\"calls\":[{}]}]",
        "[{\"calls\":[{\"status\":\"0x2\",\"gasUsed\":\"0x0\",\"returnData\":\"0x\"}]}]", "[{\"calls\":[{\"status\":\"0x1\",\"gasUsed\":\"0x10000000000000000\",\"returnData\":\"0x\"}]}]", "[{\"calls\":[{\"status\":\"0x1\",\"gasUsed\":\"0x0\",\"returnData\":\"0xz0\"}]}]",
    }) |raw| try std.testing.expectError(error.InvalidResponse, parseResult(a, raw));
    try std.testing.expectError(error.InvalidArgument, formatParams(a, .{ .block_state_calls = &.{} }, .{ .tag = .latest }));
}
