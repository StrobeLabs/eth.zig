//! Geth debug tracers and the Erigon/Nethermind trace namespace.
const std = @import("std");
const sim = @import("simulation.zig");
const rpc = @import("json_rpc.zig");
const hex = @import("hex.zig");

pub const Tracer = union(enum) {
    call_tracer: struct { onlyTopCall: bool = false, withLog: bool = false },
    prestate_tracer: struct { diffMode: bool = false, disableCode: bool = false, disableStorage: bool = false },
    /// A built-in tracer name or a custom JavaScript expression. The result
    /// is kept as JSON; config borrows its strings until the request returns.
    raw: struct { name: []const u8, config: ?std.json.Value = null },
};

pub const Options = struct {
    tracer: Tracer = .{ .call_tracer = .{} },
    timeout: ?[]const u8 = null,
    reexec: ?u64 = null,

    pub fn jsonStringify(self: Options, j: *std.json.Stringify) std.json.Stringify.Error!void {
        try j.beginObject();
        try j.objectField("tracer");
        try j.write(switch (self.tracer) {
            .call_tracer => "callTracer",
            .prestate_tracer => "prestateTracer",
            .raw => |v| v.name,
        });
        try j.objectField("tracerConfig");
        switch (self.tracer) {
            .call_tracer => |v| try j.write(v),
            .prestate_tracer => |v| try j.write(v),
            .raw => |v| if (v.config) |config| try j.write(config) else try j.print("{{}}", .{}),
        }
        if (self.timeout) |v| {
            try j.objectField("timeout");
            try j.write(v);
        }
        if (self.reexec) |v| {
            try j.objectField("reexec");
            try j.write(v);
        }
        try j.endObject();
    }
};

pub const TraceLog = struct {
    address: [20]u8,
    topics: []const [32]u8,
    data: []const u8,
    /// Position among the frame's child calls, when supplied by the node.
    position: ?u64,
};

pub const CallFrame = struct {
    type_: []const u8,
    from: [20]u8,
    /// Can be absent for failed contract creation.
    to: ?[20]u8,
    value: ?u256,
    /// SELFDESTRUCT frames may omit gas and input fields.
    gas: ?u64,
    gas_used: ?u64,
    input: []const u8,
    output: []const u8,
    error_message: ?[]const u8,
    revert_reason: ?[]const u8,
    calls: []const CallFrame,
    logs: []const TraceLog,
    raw: std.json.Value,
};

pub const StorageEntry = struct { slot: [32]u8, value: [32]u8 };
pub const Account = struct {
    address: [20]u8,
    // Diff post-state omits unchanged fields; preserve absent vs zero.
    balance: ?u256,
    nonce: ?u64,
    code: ?[]const u8,
    storage: ?[]const StorageEntry,
};
pub const Prestate = union(enum) {
    accounts: []const Account,
    diff: struct { pre: []const Account, post: []const Account },
};
pub const Value = union(enum) { call_tracer: CallFrame, prestate_tracer: Prestate, raw: std.json.Value };
pub const Result = sim.Owned(Value);

/// Encode debug_traceTransaction parameters. Caller owns the JSON.
pub fn transactionParams(a: std.mem.Allocator, hash: [32]u8, options: Options) ![]u8 {
    const hash_text = hex.bytesToHexBuf(32, &hash);
    return std.json.Stringify.valueAlloc(a, .{ &hash_text, options }, .{});
}

/// Encode debug_traceCall parameters. Caller owns the JSON.
pub fn callParams(a: std.mem.Allocator, call: sim.Call, block: rpc.BlockParam, options: Options) ![]u8 {
    var block_buf: [20]u8 = undefined;
    return std.json.Stringify.valueAlloc(a, .{ call, block.toString(&block_buf), options }, .{});
}

pub const TraceType = enum { trace, vmTrace, stateDiff };

/// Encode trace_call parameters for Erigon/Nethermind. Caller owns the JSON.
pub fn parityCallParams(a: std.mem.Allocator, call: sim.Call, block: rpc.BlockParam, types: []const TraceType) ![]u8 {
    var block_buf: [20]u8 = undefined;
    return std.json.Stringify.valueAlloc(a, .{ call, types, block.toString(&block_buf) }, .{});
}

/// Parse a result (without the RPC envelope) according to the selected tracer.
pub fn parseResult(allocator: std.mem.Allocator, raw: []const u8, tracer: Tracer) !Result {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const root = try sim.parseJson(a, raw);
    const value: Value = switch (tracer) {
        .call_tracer => .{ .call_tracer = try parseFrame(a, root, 0) },
        .prestate_tracer => |config| .{ .prestate_tracer = if (config.diffMode) blk: {
            const obj = try sim.object(root);
            break :blk .{ .diff = .{
                .pre = try parseAccounts(a, try sim.field(obj, "pre")),
                .post = try parseAccounts(a, try sim.field(obj, "post")),
            } };
        } else .{ .accounts = try parseAccounts(a, root) } },
        .raw => .{ .raw = root },
    };
    return .{ .arena = arena, .value = value };
}

fn parseFrame(a: std.mem.Allocator, value: std.json.Value, depth: usize) anyerror!CallFrame {
    // Bound parser stack usage for untrusted recursive responses. Applications
    // needing deeper trees can select a raw tracer result instead.
    if (depth >= 128) return error.TraceTooDeep;
    const obj = try sim.object(value);
    const children = if (sim.optional(obj, "calls")) |v| try sim.array(v) else &.{};
    const calls = try a.alloc(CallFrame, children.len);
    for (calls, children) |*call, child| call.* = try parseFrame(a, child, depth + 1);
    const log_values = if (sim.optional(obj, "logs")) |v| try sim.array(v) else &.{};
    const logs = try a.alloc(TraceLog, log_values.len);
    for (logs, log_values) |*log, v| {
        const fields = try sim.object(v);
        const topic_values = try sim.array(try sim.field(fields, "topics"));
        const topics = try a.alloc([32]u8, topic_values.len);
        for (topics, topic_values) |*topic, t| topic.* = try sim.fixedHex(32, t);
        log.* = .{
            .address = try sim.fixedHex(20, try sim.field(fields, "address")),
            .topics = topics,
            .data = try sim.dataBytes(a, try sim.field(fields, "data")),
            .position = if (sim.optional(fields, "position")) |p| try jsonU64(p) else null,
        };
    }
    return .{
        .type_ = try sim.string(try sim.field(obj, "type")),
        .from = try sim.fixedHex(20, try sim.field(obj, "from")),
        .to = if (sim.optional(obj, "to")) |v| try sim.fixedHex(20, v) else null,
        .value = if (sim.optional(obj, "value")) |v| try sim.quantity(u256, v) else null,
        .gas = if (sim.optional(obj, "gas")) |v| try sim.quantity(u64, v) else null,
        .gas_used = if (sim.optional(obj, "gasUsed")) |v| try sim.quantity(u64, v) else null,
        .input = if (sim.optional(obj, "input")) |v| try sim.dataBytes(a, v) else &.{},
        .output = if (sim.optional(obj, "output")) |v| try sim.dataBytes(a, v) else &.{},
        .error_message = if (sim.optional(obj, "error")) |v| try sim.string(v) else null,
        .revert_reason = if (sim.optional(obj, "revertReason")) |v| try sim.string(v) else null,
        .calls = calls,
        .logs = logs,
        .raw = value,
    };
}

fn jsonU64(value: std.json.Value) !u64 {
    return switch (value) {
        .integer => |v| if (v >= 0) @intCast(v) else error.InvalidResponse,
        .number_string => |v| std.fmt.parseInt(u64, v, 10) catch error.InvalidResponse,
        else => error.InvalidResponse,
    };
}

fn parseAccounts(a: std.mem.Allocator, value: std.json.Value) ![]const Account {
    const obj = try sim.object(value);
    const accounts = try a.alloc(Account, obj.count());
    for (accounts, obj.keys(), obj.values()) |*account, address, entry| {
        const fields = try sim.object(entry);
        const storage: ?[]const StorageEntry = if (sim.optional(fields, "storage")) |v| blk: {
            const slots = try sim.object(v);
            const entries = try a.alloc(StorageEntry, slots.count());
            for (entries, slots.keys(), slots.values()) |*slot, key, val| slot.* = .{
                .slot = try sim.fixedHex(32, .{ .string = key }),
                .value = try sim.fixedHex(32, val),
            };
            break :blk entries;
        } else null;
        account.* = .{
            .address = try sim.fixedHex(20, .{ .string = address }),
            .balance = if (sim.optional(fields, "balance")) |v| try sim.quantity(u256, v) else null,
            .nonce = if (sim.optional(fields, "nonce")) |v| try jsonU64(v) else null,
            .code = if (sim.optional(fields, "code")) |v| try sim.dataBytes(a, v) else null,
            .storage = storage,
        };
    }
    return accounts;
}

const call_fixture =
    \\{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","value":"0x0","gas":"0xffff","gasUsed":"0x1234","input":"0xabcdef","calls":[{"type":"DELEGATECALL","from":"0x2222222222222222222222222222222222222222","calls":[{"type":"CREATE2","from":"0x2222222222222222222222222222222222222222","error":"execution reverted","revertReason":"denied","output":"0xdeadbeef"}]}],"logs":[{"address":"0x2222222222222222222222222222222222222222","topics":["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"data":"0x0102","position":0}]}
;

fn checkCall(a: std.mem.Allocator) !void {
    var result = try parseResult(a, call_fixture, .{ .call_tracer = .{} });
    defer result.deinit();
    const root = result.value.call_tracer;
    try std.testing.expectEqual(@as(?u64, 0x1234), root.gas_used);
    const nested = root.calls[0].calls[0];
    try std.testing.expectEqualStrings("CREATE2", nested.type_);
    try std.testing.expectEqualStrings("denied", nested.revert_reason.?);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, nested.output);
    try std.testing.expect(nested.to == null);
    try std.testing.expectEqual(@as(usize, 1), root.logs[0].topics.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, root.logs[0].data);
}

test "callTracer preserves three nested frames, revert data and logs with allocation failures" {
    try checkCall(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkCall, .{});
}

const prestate_fixture =
    \\{"pre":{"0x1111111111111111111111111111111111111111":{"balance":"0x1","nonce":18446744073709551615,"code":"0x00","storage":{"0x0000000000000000000000000000000000000000000000000000000000000000":"0x0000000000000000000000000000000000000000000000000000000000000001"}}},"post":{"0x1111111111111111111111111111111111111111":{"balance":"0x0"}}}
;

fn checkPrestate(a: std.mem.Allocator) !void {
    var result = try parseResult(a, prestate_fixture, .{ .prestate_tracer = .{ .diffMode = true } });
    defer result.deinit();
    const diff = result.value.prestate_tracer.diff;
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), diff.pre[0].nonce);
    try std.testing.expectEqual(@as(u8, 1), diff.pre[0].storage.?[0].value[31]);
    try std.testing.expectEqual(@as(?u256, 0), diff.post[0].balance);
    try std.testing.expect(diff.post[0].code == null and diff.post[0].nonce == null and diff.post[0].storage == null);
}

test "prestateTracer diff preserves omitted fields and frees nested allocations" {
    try checkPrestate(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkPrestate, .{});
    var result = try parseResult(std.testing.allocator, "{}", .{ .prestate_tracer = .{} });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.value.prestate_tracer.accounts.len);
}

test "tracer requests encode native fields and custom JavaScript safely" {
    const a = std.testing.allocator;
    const raw = try transactionParams(a, @splat(0xab), .{ .tracer = .{ .call_tracer = .{ .withLog = true } }, .timeout = "3s", .reexec = 42 });
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
    defer parsed.deinit();
    const params = parsed.value.array.items;
    try std.testing.expectEqualStrings("0xabababababababababababababababababababababababababababababababab", params[0].string);
    const config = params[1].object;
    try std.testing.expectEqualStrings("callTracer", config.get("tracer").?.string);
    try std.testing.expect(config.get("tracerConfig").?.object.get("withLog").?.bool);
    try std.testing.expectEqual(@as(i64, 42), config.get("reexec").?.integer);
    const js = "{result: function() { return \"hello\"; }}";
    const call = try callParams(a, .{ .value = 1 }, .{ .number = 15 }, .{ .tracer = .{ .raw = .{ .name = js } } });
    defer a.free(call);
    const parsed_call = try std.json.parseFromSlice(std.json.Value, a, call, .{});
    defer parsed_call.deinit();
    const call_params = parsed_call.value.array.items;
    try std.testing.expectEqualStrings("0x1", call_params[0].object.get("value").?.string);
    try std.testing.expectEqualStrings("0xf", call_params[1].string);
    try std.testing.expectEqualStrings(js, call_params[2].object.get("tracer").?.string);
    const parity = try parityCallParams(a, .{ .gas = 21000 }, .{ .tag = .latest }, &.{ .trace, .stateDiff });
    defer a.free(parity);
    try std.testing.expectEqualStrings("[{\"gas\":\"0x5208\"},[\"trace\",\"stateDiff\"],\"latest\"]", parity);
}

test "tracers reject malformed results while custom tracer JSON stays arbitrary" {
    const a = std.testing.allocator;
    for ([_][]const u8{ "null", "{}", "{\"type\":1}", "{\"type\":\"CALL\",\"from\":\"0xzz\"}" }) |raw|
        try std.testing.expectError(error.InvalidResponse, parseResult(a, raw, .{ .call_tracer = .{} }));
    try std.testing.expectError(error.InvalidResponse, parseResult(a, "{}", .{ .prestate_tracer = .{ .diffMode = true } }));
    var raw_result = try parseResult(a, "[1,{\"answer\":true}]", .{ .raw = .{ .name = "custom" } });
    defer raw_result.deinit();
    try std.testing.expect(raw_result.value.raw.array.items[1].object.get("answer").?.bool);
}

test "callTracer bounds recursion on deeply nested untrusted responses" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    for (0..128) |_| try out.writer.writeAll("{\"type\":\"CALL\",\"from\":\"0x1111111111111111111111111111111111111111\",\"calls\":[");
    try out.writer.writeAll("{}");
    for (0..128) |_| try out.writer.writeAll("]}");
    try std.testing.expectError(error.TraceTooDeep, parseResult(std.testing.allocator, out.written(), .{ .call_tracer = .{} }));
}
