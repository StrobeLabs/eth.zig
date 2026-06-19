const std = @import("std");
const json_rpc = @import("json_rpc.zig");
const hex_mod = @import("hex.zig");
const uint256_mod = @import("uint256.zig");
const primitives = @import("primitives.zig");
const receipt_mod = @import("receipt.zig");
const block_mod = @import("block.zig");
const state_overrides_mod = @import("state_overrides.zig");
const rpc_transaction_mod = @import("rpc_transaction.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const runtime = @import("runtime.zig");

/// Read-only Ethereum JSON-RPC provider.
///
/// Wraps an HttpTransport to make typed Ethereum RPC calls.
/// All hex-encoded responses are parsed into native Zig types.
pub const Provider = struct {
    transport: *HttpTransport,
    allocator: std.mem.Allocator,
    /// Monotonic JSON-RPC request id. Atomic so a Provider shared across threads
    /// cannot hand out duplicate ids (note the underlying HttpTransport is still
    /// single-threaded -- sharing a Provider is only id-safe, not call-safe).
    next_id: std.atomic.Value(u64),
    /// Diagnostics for the most recent JSON-RPC `error` response. See lastError().
    last_error: ?ErrorInfo = null,
    /// Inline backing storage for `last_error.message` (truncated to fit). Inline
    /// so the Provider holds no heap diagnostics state and needs no deinit.
    last_error_storage: [256]u8 = undefined,

    /// Structured diagnostics for a failed JSON-RPC call.
    pub const ErrorInfo = struct {
        /// JSON-RPC error code, e.g. 3 = execution reverted, -32000 = server error.
        code: i64,
        /// Error message (may be empty; truncated to 256 bytes). Borrows
        /// provider-owned storage; valid until the next call on this provider.
        message: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, transport: *HttpTransport) Provider {
        return .{
            .transport = transport,
            .allocator = allocator,
            .next_id = .init(1),
        };
    }

    /// The `std.Io` this provider runs on, inherited from its transport.
    pub fn io(self: *const Provider) std.Io {
        return self.transport.io;
    }

    /// Diagnostics for the most recent JSON-RPC `error` response, or null if the
    /// last call did not fail with `error.RpcError`. Lets callers tell an
    /// on-chain revert (code 3) apart from a transport-level failure. The
    /// message is valid until the next call on this provider.
    pub fn lastError(self: *const Provider) ?ErrorInfo {
        return self.last_error;
    }

    // ========================================================================
    // Chain state
    // ========================================================================

    /// Returns the chain ID of the connected network.
    pub fn getChainId(self: *Provider) !u64 {
        const raw = try self.rpcCall(json_rpc.Method.eth_chainId, "[]");
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU64(result_str);
    }

    /// Returns the number of the most recent block.
    pub fn getBlockNumber(self: *Provider) !u64 {
        const raw = try self.rpcCall(json_rpc.Method.eth_blockNumber, "[]");
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU64(result_str);
    }

    // ========================================================================
    // Account state
    // ========================================================================

    /// Returns the balance (in wei) of the given address at the latest block.
    pub fn getBalance(self: *Provider, address: [20]u8) !u256 {
        const params = try self.formatAddressAndBlock(address, "latest");
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getBalance, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU256(result_str);
    }

    /// Returns the number of transactions sent from the given address (nonce)
    /// at the latest block.
    pub fn getTransactionCount(self: *Provider, address: [20]u8) !u64 {
        return self.getTransactionCountAt(address, .latest);
    }

    /// Returns the transaction count (nonce) for an address at a specific
    /// block tag. Use `.pending` to include transactions still in the mempool
    /// -- this is what nonce managers seed from so they do not reuse a nonce
    /// that is already queued but not yet mined.
    pub fn getTransactionCountAt(self: *Provider, address: [20]u8, tag: json_rpc.BlockTag) !u64 {
        const params = try self.formatAddressAndBlock(address, tag.toString());
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getTransactionCount, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU64(result_str);
    }

    /// Returns the bytecode of the contract at the given address.
    /// Caller owns the returned memory.
    pub fn getCode(self: *Provider, address: [20]u8) ![]u8 {
        const params = try self.formatAddressAndBlock(address, "latest");
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getCode, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexBytes(self.allocator, result_str);
    }

    /// Returns the value from a storage slot at a given address.
    pub fn getStorageAt(self: *Provider, address: [20]u8, slot: [32]u8) ![32]u8 {
        const addr_hex = primitives.addressToHex(&address);
        const slot_hex = primitives.hashToHex(&slot);

        var params_buf: std.ArrayList(u8) = .empty;
        defer params_buf.deinit(self.allocator);
        try params_buf.appendSlice(self.allocator, "[\"");
        try params_buf.appendSlice(self.allocator, &addr_hex);
        try params_buf.appendSlice(self.allocator, "\",\"");
        try params_buf.appendSlice(self.allocator, &slot_hex);
        try params_buf.appendSlice(self.allocator, "\",\"latest\"]");

        const params = try params_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getStorageAt, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return hex_mod.hexToBytesFixed(32, result_str) catch return error.InvalidResponse;
    }

    // ========================================================================
    // Gas
    // ========================================================================

    /// Returns the current gas price in wei.
    pub fn getGasPrice(self: *Provider) !u256 {
        const raw = try self.rpcCall(json_rpc.Method.eth_gasPrice, "[]");
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU256(result_str);
    }

    /// Returns the current max priority fee per gas (EIP-1559 tip).
    pub fn getMaxPriorityFee(self: *Provider) !u256 {
        const raw = try self.rpcCall(json_rpc.Method.eth_maxPriorityFeePerGas, "[]");
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU256(result_str);
    }

    // ========================================================================
    // Transaction execution
    // ========================================================================

    /// Executes a message call (eth_call) against the latest block.
    /// Caller owns the returned memory.
    pub fn call(self: *Provider, to: [20]u8, data: []const u8) ![]u8 {
        const params = try self.formatCallParams(to, data, null);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_call, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexBytes(self.allocator, result_str);
    }

    /// Executes a message call (eth_call) against the latest block with
    /// state overrides applied. Lets simulators answer "what if?" questions
    /// (modified balances, code, storage) without forking a node.
    ///
    /// Maps to the third parameter of the geth-style eth_call:
    /// `eth_call(transaction, blockTag, stateOverrideObject)`.
    /// Most production providers (Alchemy, Infura, QuickNode, Anvil)
    /// accept this third argument.
    ///
    /// Caller owns the returned memory.
    pub fn callWithOverrides(
        self: *Provider,
        to: [20]u8,
        data: []const u8,
        overrides: *const state_overrides_mod.StateOverrides,
    ) ![]u8 {
        const params = try self.formatCallParamsWithOverrides(to, data, null, overrides);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_call, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexBytes(self.allocator, result_str);
    }

    /// Estimates the gas needed to execute the given transaction.
    pub fn estimateGas(self: *Provider, to: [20]u8, data: []const u8, from: ?[20]u8) !u64 {
        const params = try self.formatCallParams(to, data, from);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_estimateGas, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return parseHexU64(result_str);
    }

    /// Sends a signed transaction and returns the transaction hash.
    pub fn sendRawTransaction(self: *Provider, signed_tx: []const u8) ![32]u8 {
        const tx_hex = try hex_mod.bytesToHex(self.allocator, signed_tx);
        defer self.allocator.free(tx_hex);

        var params_buf: std.ArrayList(u8) = .empty;
        defer params_buf.deinit(self.allocator);
        try params_buf.appendSlice(self.allocator, "[\"");
        try params_buf.appendSlice(self.allocator, tx_hex);
        try params_buf.appendSlice(self.allocator, "\"]");

        const params = try params_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_sendRawTransaction, params);
        defer self.allocator.free(raw);

        const result_str = try self.extractResult(raw);
        defer self.allocator.free(result_str);
        return primitives.hashFromHex(result_str) catch return error.InvalidResponse;
    }

    // ========================================================================
    // Receipts
    // ========================================================================

    /// Returns the receipt for a mined transaction, or null if not yet mined.
    pub fn getTransactionReceipt(self: *Provider, tx_hash: [32]u8) !?receipt_mod.TransactionReceipt {
        const hash_hex = primitives.hashToHex(&tx_hash);

        var params_buf: std.ArrayList(u8) = .empty;
        defer params_buf.deinit(self.allocator);
        try params_buf.appendSlice(self.allocator, "[\"");
        try params_buf.appendSlice(self.allocator, &hash_hex);
        try params_buf.appendSlice(self.allocator, "\"]");

        const params = try params_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getTransactionReceipt, params);
        defer self.allocator.free(raw);

        return parseTransactionReceipt(self.allocator, raw) catch |err| {
            if (err == error.RpcError) self.captureRpcError(raw);
            return err;
        };
    }

    // ========================================================================
    // Blocks
    // ========================================================================

    /// Returns a block header by number, or null if the block does not exist.
    pub fn getBlock(self: *Provider, block_number: u64) !?block_mod.BlockHeader {
        var num_buf: [20]u8 = undefined;
        const block_param = json_rpc.BlockParam{ .number = block_number };
        const block_str = block_param.toString(&num_buf);

        var params_buf: std.ArrayList(u8) = .empty;
        defer params_buf.deinit(self.allocator);
        try params_buf.appendSlice(self.allocator, "[\"");
        try params_buf.appendSlice(self.allocator, block_str);
        try params_buf.appendSlice(self.allocator, "\",false]");

        const params = try params_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getBlockByNumber, params);
        defer self.allocator.free(raw);

        return parseBlockHeader(self.allocator, raw) catch |err| {
            if (err == error.RpcError) self.captureRpcError(raw);
            return err;
        };
    }

    // ========================================================================
    // Logs
    // ========================================================================

    /// Returns logs matching the given filter.
    /// Caller owns the returned memory.
    pub fn getLogs(self: *Provider, filter: json_rpc.LogFilter) ![]receipt_mod.Log {
        const params = try formatLogFilter(self.allocator, filter);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getLogs, params);
        defer self.allocator.free(raw);

        return parseLogsResponse(self.allocator, raw) catch |err| {
            if (err == error.RpcError) self.captureRpcError(raw);
            return err;
        };
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn rpcCall(self: *Provider, method: []const u8, params: []const u8) ![]u8 {
        // Reset diagnostics at the single choke point every call flows through;
        // the parse step records details if the response carries an RPC error.
        self.last_error = null;
        const id = self.next_id.fetchAdd(1, .monotonic);
        return self.transport.request(method, params, id);
    }

    /// `extractResultString`, but capturing RPC error diagnostics into the
    /// provider on `error.RpcError` so callers can inspect `lastError()`.
    fn extractResult(self: *Provider, raw: []const u8) ![]u8 {
        return extractResultString(self.allocator, raw) catch |err| {
            if (err == error.RpcError) self.captureRpcError(raw);
            return err;
        };
    }

    /// Best-effort: parse `raw` for a JSON-RPC `error` object and record its
    /// code and (truncated) message into `last_error`. Runs only on the error
    /// path, so the extra parse never touches the success hot path.
    fn captureRpcError(self: *Provider, raw: []const u8) void {
        var code: i64 = 0;
        var message: []const u8 = "";
        if (std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{})) |parsed| {
            defer parsed.deinit();
            if (parsed.value == .object) {
                if (parsed.value.object.get("error")) |ev| {
                    if (ev == .object) {
                        if (ev.object.get("code")) |c| {
                            if (c == .integer) code = c.integer;
                        }
                        if (ev.object.get("message")) |m| {
                            if (m == .string) message = m.string;
                        }
                    }
                }
            }
            const n = @min(message.len, self.last_error_storage.len);
            @memcpy(self.last_error_storage[0..n], message[0..n]);
            self.last_error = .{ .code = code, .message = self.last_error_storage[0..n] };
        } else |_| {
            self.last_error = .{ .code = 0, .message = "" };
        }
    }

    fn formatAddressAndBlock(self: *Provider, address: [20]u8, block_tag: []const u8) ![]u8 {
        const addr_hex = primitives.addressToHex(&address);

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, "[\"");
        try buf.appendSlice(self.allocator, &addr_hex);
        try buf.appendSlice(self.allocator, "\",\"");
        try buf.appendSlice(self.allocator, block_tag);
        try buf.appendSlice(self.allocator, "\"]");

        return buf.toOwnedSlice(self.allocator);
    }

    pub fn formatCallParams(self: *Provider, to: [20]u8, data: []const u8, from: ?[20]u8) ![]u8 {
        const to_hex = primitives.addressToHex(&to);
        const data_hex = try hex_mod.bytesToHex(self.allocator, data);
        defer self.allocator.free(data_hex);

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, "[{");

        if (from) |f| {
            const from_hex = primitives.addressToHex(&f);
            try buf.appendSlice(self.allocator, "\"from\":\"");
            try buf.appendSlice(self.allocator, &from_hex);
            try buf.appendSlice(self.allocator, "\",");
        }

        try buf.appendSlice(self.allocator, "\"to\":\"");
        try buf.appendSlice(self.allocator, &to_hex);
        try buf.appendSlice(self.allocator, "\",\"data\":\"");
        try buf.appendSlice(self.allocator, data_hex);
        try buf.appendSlice(self.allocator, "\"},\"latest\"]");

        return buf.toOwnedSlice(self.allocator);
    }

    /// Like `formatCallParams`, but emits the third state-override
    /// argument so eth_call can be invoked with simulated state.
    pub fn formatCallParamsWithOverrides(
        self: *Provider,
        to: [20]u8,
        data: []const u8,
        from: ?[20]u8,
        overrides: *const state_overrides_mod.StateOverrides,
    ) ![]u8 {
        const to_hex = primitives.addressToHex(&to);
        const data_hex = try hex_mod.bytesToHex(self.allocator, data);
        defer self.allocator.free(data_hex);

        const overrides_json = try overrides.serializeJson(self.allocator);
        defer self.allocator.free(overrides_json);

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, "[{");

        if (from) |f| {
            const from_hex = primitives.addressToHex(&f);
            try buf.appendSlice(self.allocator, "\"from\":\"");
            try buf.appendSlice(self.allocator, &from_hex);
            try buf.appendSlice(self.allocator, "\",");
        }

        try buf.appendSlice(self.allocator, "\"to\":\"");
        try buf.appendSlice(self.allocator, &to_hex);
        try buf.appendSlice(self.allocator, "\",\"data\":\"");
        try buf.appendSlice(self.allocator, data_hex);
        try buf.appendSlice(self.allocator, "\"},\"latest\",");
        try buf.appendSlice(self.allocator, overrides_json);
        try buf.append(self.allocator, ']');

        return buf.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Batch eth_call support
// ============================================================================

pub const BatchCallResult = union(enum) {
    success: []u8,
    rpc_error: RpcErrorData,

    pub const RpcErrorData = struct {
        code: i64,
        message: ?[]u8,
    };
};

pub const BatchCaller = struct {
    provider: *Provider,
    allocator: std.mem.Allocator,
    targets: std.ArrayList([20]u8),
    calldata: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, prov: *Provider) BatchCaller {
        return .{
            .provider = prov,
            .allocator = allocator,
            .targets = .empty,
            .calldata = .empty,
        };
    }

    pub fn deinit(self: *BatchCaller) void {
        self.targets.deinit(self.allocator);
        self.calldata.deinit(self.allocator);
    }

    /// Add an eth_call to the batch. Returns the index for result retrieval.
    /// `data` is borrowed (not copied) -- caller must keep it valid until `execute()` returns.
    pub fn addCall(self: *BatchCaller, to: [20]u8, data: []const u8) !usize {
        const index = self.targets.items.len;
        try self.targets.append(self.allocator, to);
        try self.calldata.append(self.allocator, data);
        return index;
    }

    pub fn reset(self: *BatchCaller) void {
        self.targets.clearRetainingCapacity();
        self.calldata.clearRetainingCapacity();
    }

    pub fn execute(self: *BatchCaller) ![]BatchCallResult {
        const n = self.targets.items.len;
        if (n == 0) return try self.allocator.alloc(BatchCallResult, 0);

        // Build individual request bodies
        const bodies = try self.allocator.alloc([]u8, n);
        @memset(bodies, &.{});
        defer {
            for (bodies) |b| if (b.len > 0) self.allocator.free(b);
            self.allocator.free(bodies);
        }

        const ids = try self.allocator.alloc(u64, n);
        defer self.allocator.free(ids);

        const base_id = self.provider.next_id.fetchAdd(n, .monotonic);

        for (0..n) |i| {
            ids[i] = base_id + i;
            const params = try self.provider.formatCallParams(self.targets.items[i], self.calldata.items[i], null);
            defer self.allocator.free(params);
            bodies[i] = try HttpTransport.buildRequestBody(self.allocator, json_rpc.Method.eth_call, params, ids[i]);
        }

        // Build const slice for requestBatch
        const const_bodies = try self.allocator.alloc([]const u8, n);
        defer self.allocator.free(const_bodies);
        for (bodies, 0..) |b, i| {
            const_bodies[i] = b;
        }

        const raw = try self.provider.transport.requestBatch(const_bodies);
        defer self.allocator.free(raw);

        return try parseBatchResponse(self.allocator, raw, ids);
    }
};

/// Parse a JSON-RPC batch response, matching results to request IDs.
/// Unmatched IDs are left as sentinel values: `.rpc_error = .{ .code = -1, .message = null }`.
/// Callers can detect missing responses by checking for `code == -1` and `message == null`.
fn parseBatchResponse(allocator: std.mem.Allocator, raw: []const u8, ids: []const u64) ![]BatchCallResult {
    const n = ids.len;
    var results = try allocator.alloc(BatchCallResult, n);
    for (results) |*r| r.* = .{ .rpc_error = .{ .code = -1, .message = null } };
    errdefer freeBatchResults(allocator, results);

    // Parse JSON array
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.InvalidResponse,
    };

    // Match each response to its request by id
    for (arr.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        // Get id
        const id_val = obj.get("id") orelse continue;
        const id: u64 = switch (id_val) {
            .integer => |i| if (i >= 0) @as(u64, @intCast(i)) else continue,
            else => continue,
        };

        // Find index for this id
        var idx: ?usize = null;
        for (ids, 0..) |expected_id, i| {
            if (expected_id == id) {
                idx = i;
                break;
            }
        }
        const index = idx orelse continue;

        // Check for error
        if (obj.get("error")) |err_val| {
            if (err_val == .object) {
                const code = if (err_val.object.get("code")) |c| switch (c) {
                    .integer => |ci| @as(i64, @intCast(ci)),
                    else => @as(i64, 0),
                } else 0;
                const message = if (err_val.object.get("message")) |m| switch (m) {
                    .string => |s| s,
                    else => "unknown error",
                } else "unknown error";
                // Dupe message since parsed JSON will be freed
                const msg_copy: []u8 = try allocator.dupe(u8, message);
                results[index] = .{ .rpc_error = .{ .code = code, .message = msg_copy } };
                continue;
            }
        }

        // Get result
        const result_val = obj.get("result") orelse continue;
        switch (result_val) {
            .string => |s| {
                const decoded = try parseHexBytes(allocator, s);
                results[index] = .{ .success = decoded };
            },
            else => {},
        }
    }

    return results;
}

pub fn freeBatchResults(allocator: std.mem.Allocator, results: []BatchCallResult) void {
    for (results) |r| {
        switch (r) {
            .success => |data| allocator.free(data),
            .rpc_error => |e| if (e.message) |msg| allocator.free(msg),
        }
    }
    allocator.free(results);
}

// ============================================================================
// JSON response parsing
// ============================================================================

/// Extract the "result" string value from a JSON-RPC response.
/// Handles both quoted string results and null.
/// Caller owns the returned memory.
fn extractResultString(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    // Check for RPC error
    if (root.object.get("error")) |err_val| {
        if (err_val == .object) {
            return error.RpcError;
        }
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;

    return switch (result_val) {
        .string => |s| allocator.dupe(u8, s) catch return error.InvalidResponse,
        .null => error.NullResult,
        else => error.InvalidResponse,
    };
}

fn parseHexU64(hex_str: []const u8) !u64 {
    const val = uint256_mod.fromHex(hex_str) catch return error.InvalidResponse;
    if (val > std.math.maxInt(u64)) return error.InvalidResponse;
    return @intCast(val);
}

fn parseHexU256(hex_str: []const u8) !u256 {
    return uint256_mod.fromHex(hex_str) catch return error.InvalidResponse;
}

fn parseHexU32(hex_str: []const u8) !u32 {
    const val = uint256_mod.fromHex(hex_str) catch return error.InvalidResponse;
    if (val > std.math.maxInt(u32)) return error.InvalidResponse;
    return @intCast(val);
}

fn parseHexU8(hex_str: []const u8) !u8 {
    const val = uint256_mod.fromHex(hex_str) catch return error.InvalidResponse;
    if (val > std.math.maxInt(u8)) return error.InvalidResponse;
    return @intCast(val);
}

/// Decode a hex string (with 0x prefix) into an allocated byte slice.
fn parseHexBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const src = if (hex_str.len >= 2 and hex_str[0] == '0' and (hex_str[1] == 'x' or hex_str[1] == 'X'))
        hex_str[2..]
    else
        hex_str;

    if (src.len == 0) {
        return allocator.alloc(u8, 0);
    }

    // Handle odd-length hex by left-padding with zero
    const padded_len = if (src.len % 2 != 0) src.len + 1 else src.len;
    const byte_len = padded_len / 2;
    const dest = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(dest);

    if (src.len % 2 != 0) {
        // Odd length: first nibble is the low nibble of the first byte
        dest[0] = hex_mod.charToNibble(src[0]) catch {
            allocator.free(dest);
            return error.InvalidResponse;
        };
        var i: usize = 1;
        while (i < byte_len) : (i += 1) {
            const hi = hex_mod.charToNibble(src[i * 2 - 1]) catch {
                allocator.free(dest);
                return error.InvalidResponse;
            };
            const lo = hex_mod.charToNibble(src[i * 2]) catch {
                allocator.free(dest);
                return error.InvalidResponse;
            };
            dest[i] = (@as(u8, hi) << 4) | @as(u8, lo);
        }
    } else {
        _ = hex_mod.hexToBytes(dest, hex_str) catch {
            allocator.free(dest);
            return error.InvalidResponse;
        };
    }

    return dest;
}

/// Parse a [20]u8 address from a hex string, returning null if the input is null.
fn parseOptionalAddress(hex_str: ?[]const u8) !?[20]u8 {
    const s = hex_str orelse return null;
    if (s.len == 0) return null;
    return primitives.addressFromHex(s) catch return error.InvalidResponse;
}

/// Parse a [32]u8 hash from a hex string.
fn parseHash(hex_str: []const u8) ![32]u8 {
    return primitives.hashFromHex(hex_str) catch return error.InvalidResponse;
}

/// Parse optional hash.
fn parseOptionalHash(hex_str: ?[]const u8) !?[32]u8 {
    const s = hex_str orelse return null;
    if (s.len == 0) return null;
    const val = try parseHash(s);
    return val;
}

/// Parse an optional hex u64 value.
fn parseOptionalHexU64(hex_str: ?[]const u8) !?u64 {
    const s = hex_str orelse return null;
    const val = try parseHexU64(s);
    return val;
}

/// Get a string value from a JSON object, returning null if not present or null.
fn jsonGetString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// Get a boolean from a JSON object.
fn jsonGetBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .bool => |b| b,
        else => null,
    };
}

/// Parse a transaction receipt from a raw JSON-RPC response.
fn parseTransactionReceipt(allocator: std.mem.Allocator, raw: []const u8) !?receipt_mod.TransactionReceipt {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    // Check for RPC error
    if (root.object.get("error")) |err_val| {
        if (err_val == .object) {
            return error.RpcError;
        }
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return null;
    if (result_val != .object) return error.InvalidResponse;

    const obj = result_val.object;

    // Parse logs array
    const logs = try parseLogsArray(allocator, obj);
    errdefer {
        for (logs) |log| {
            allocator.free(log.data);
            if (log.topics.len > 0) allocator.free(log.topics);
        }
        if (logs.len > 0) allocator.free(logs);
    }

    // Parse required fields
    const tx_hash = try parseHash(jsonGetString(obj, "transactionHash") orelse return error.InvalidResponse);
    const block_hash = try parseHash(jsonGetString(obj, "blockHash") orelse return error.InvalidResponse);
    const block_number = try parseHexU64(jsonGetString(obj, "blockNumber") orelse return error.InvalidResponse);
    const tx_index = try parseHexU32(jsonGetString(obj, "transactionIndex") orelse return error.InvalidResponse);
    const from_addr = (try parseOptionalAddress(jsonGetString(obj, "from"))) orelse return error.InvalidResponse;
    const to_addr = try parseOptionalAddress(jsonGetString(obj, "to"));
    const gas_used = try parseHexU256(jsonGetString(obj, "gasUsed") orelse return error.InvalidResponse);
    const cumulative = try parseHexU256(jsonGetString(obj, "cumulativeGasUsed") orelse return error.InvalidResponse);
    const effective_price = try parseHexU256(jsonGetString(obj, "effectiveGasPrice") orelse "0x0");
    const status = try parseHexU8(jsonGetString(obj, "status") orelse return error.InvalidResponse);
    const contract_addr = try parseOptionalAddress(jsonGetString(obj, "contractAddress"));
    const type_val = parseHexU8(jsonGetString(obj, "type") orelse "0x0") catch 0;

    return receipt_mod.TransactionReceipt{
        .transaction_hash = tx_hash,
        .block_hash = block_hash,
        .block_number = block_number,
        .transaction_index = tx_index,
        .from = from_addr,
        .to = to_addr,
        .gas_used = gas_used,
        .cumulative_gas_used = cumulative,
        .effective_gas_price = effective_price,
        .status = status,
        .logs = logs,
        .contract_address = contract_addr,
        .type_ = type_val,
    };
}

/// Parse the "logs" array from a receipt JSON object.
fn parseLogsArray(allocator: std.mem.Allocator, obj: std.json.ObjectMap) ![]const receipt_mod.Log {
    const logs_val = obj.get("logs") orelse return &.{};
    if (logs_val != .array) return &.{};

    const arr = logs_val.array;
    if (arr.items.len == 0) return &.{};

    const logs = try allocator.alloc(receipt_mod.Log, arr.items.len);
    var parsed_count: usize = 0;
    errdefer {
        for (logs[0..parsed_count]) |log| {
            allocator.free(log.data);
            if (log.topics.len > 0) allocator.free(log.topics);
        }
        allocator.free(logs);
    }

    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        logs[i] = try parseSingleLog(allocator, item.object);
        parsed_count += 1;
    }

    return logs;
}

/// Parse a single Log from a JSON object.
pub fn parseSingleLog(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !receipt_mod.Log {
    const address = (try parseOptionalAddress(jsonGetString(obj, "address"))) orelse return error.InvalidResponse;
    const data_str = jsonGetString(obj, "data") orelse "0x";
    const data = try parseHexBytes(allocator, data_str);
    errdefer allocator.free(data);

    // Parse topics array
    const topics = try parseTopics(allocator, obj);
    errdefer if (topics.len > 0) allocator.free(topics);

    const block_number = try parseOptionalHexU64(jsonGetString(obj, "blockNumber"));
    const tx_hash = try parseOptionalHash(jsonGetString(obj, "transactionHash"));
    const tx_index: ?u32 = if (jsonGetString(obj, "transactionIndex")) |s|
        parseHexU32(s) catch null
    else
        null;
    const log_index: ?u32 = if (jsonGetString(obj, "logIndex")) |s|
        parseHexU32(s) catch null
    else
        null;
    const block_hash = try parseOptionalHash(jsonGetString(obj, "blockHash"));
    const removed = jsonGetBool(obj, "removed") orelse false;

    return receipt_mod.Log{
        .address = address,
        .topics = topics,
        .data = data,
        .block_number = block_number,
        .transaction_hash = tx_hash,
        .transaction_index = tx_index,
        .log_index = log_index,
        .block_hash = block_hash,
        .removed = removed,
    };
}

/// Parse topics from a log JSON object.
fn parseTopics(allocator: std.mem.Allocator, obj: std.json.ObjectMap) ![]const [32]u8 {
    const topics_val = obj.get("topics") orelse return &.{};
    if (topics_val != .array) return &.{};

    const arr = topics_val.array;
    if (arr.items.len == 0) return &.{};

    const topics = try allocator.alloc([32]u8, arr.items.len);
    errdefer allocator.free(topics);

    for (arr.items, 0..) |item, i| {
        if (item != .string) return error.InvalidResponse;
        topics[i] = primitives.hashFromHex(item.string) catch return error.InvalidResponse;
    }

    return topics;
}

/// Parse a single RpcTransaction from a JSON object as returned by
/// `eth_getTransactionByHash`, full-tx pending subscriptions, etc.
///
/// Caller owns the returned transaction's `input` slice; use
/// `rpc_transaction.freeRpcTransaction` to release it.
pub fn parseSingleTransaction(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !rpc_transaction_mod.RpcTransaction {
    const hash = try parseHash(jsonGetString(obj, "hash") orelse return error.InvalidResponse);
    const nonce = try parseHexU64(jsonGetString(obj, "nonce") orelse return error.InvalidResponse);
    const block_hash = try parseOptionalHash(jsonGetString(obj, "blockHash"));
    const block_number = try parseOptionalHexU64(jsonGetString(obj, "blockNumber"));
    const tx_index: ?u32 = if (jsonGetString(obj, "transactionIndex")) |s|
        try parseHexU32(s)
    else
        null;

    const from_addr = (try parseOptionalAddress(jsonGetString(obj, "from"))) orelse return error.InvalidResponse;
    const to_addr = try parseOptionalAddress(jsonGetString(obj, "to"));
    const value = try parseHexU256(jsonGetString(obj, "value") orelse "0x0");

    const gas = try parseHexU64(jsonGetString(obj, "gas") orelse return error.InvalidResponse);
    const gas_price: ?u256 = if (jsonGetString(obj, "gasPrice")) |s| try parseHexU256(s) else null;
    const max_fee: ?u256 = if (jsonGetString(obj, "maxFeePerGas")) |s| try parseHexU256(s) else null;
    const max_priority: ?u256 = if (jsonGetString(obj, "maxPriorityFeePerGas")) |s| try parseHexU256(s) else null;
    const max_blob_fee: ?u256 = if (jsonGetString(obj, "maxFeePerBlobGas")) |s| try parseHexU256(s) else null;

    // `input` and `data` are aliases; geth uses `input`, parity used `data`.
    const input_str = jsonGetString(obj, "input") orelse jsonGetString(obj, "data") orelse "0x";
    const input = try parseHexBytes(allocator, input_str);
    errdefer allocator.free(input);

    // Typed transactions may report only `yParity`; `v` is a legacy alias.
    const v_str = jsonGetString(obj, "v") orelse jsonGetString(obj, "yParity") orelse return error.InvalidResponse;
    const v = try parseHexU256(v_str);
    const r = try parseHash(jsonGetString(obj, "r") orelse return error.InvalidResponse);
    const s = try parseHash(jsonGetString(obj, "s") orelse return error.InvalidResponse);

    const type_val: u8 = if (jsonGetString(obj, "type")) |t| try parseHexU8(t) else 0;
    const chain_id = try parseOptionalHexU64(jsonGetString(obj, "chainId"));

    // EIP-7702 authorization list (best-effort: parse if the field is present
    // and is an array). Present only on type-0x04 transactions.
    const authorization_list = try parseAuthorizationList(allocator, obj);
    errdefer if (authorization_list) |list| allocator.free(list);

    return rpc_transaction_mod.RpcTransaction{
        .hash = hash,
        .nonce = nonce,
        .block_hash = block_hash,
        .block_number = block_number,
        .transaction_index = tx_index,
        .from = from_addr,
        .to = to_addr,
        .value = value,
        .gas = gas,
        .gas_price = gas_price,
        .max_fee_per_gas = max_fee,
        .max_priority_fee_per_gas = max_priority,
        .max_fee_per_blob_gas = max_blob_fee,
        .input = input,
        .v = v,
        .r = r,
        .s = s,
        .type_ = type_val,
        .chain_id = chain_id,
        .authorization_list = authorization_list,
    };
}

/// Parse an EIP-7702 `authorizationList` from an RPC transaction object.
/// Returns null if the field is absent or not an array. Each element is an
/// object with `chainId`, `address`, `nonce`, `yParity`, `r`, `s`.
/// The returned slice is heap-owned; free with `freeRpcTransaction`.
fn parseAuthorizationList(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
) !?[]const rpc_transaction_mod.RpcAuthorization {
    const val = obj.get("authorizationList") orelse return null;
    if (val != .array) return null;
    const items = val.array.items;
    if (items.len == 0) {
        return try allocator.alloc(rpc_transaction_mod.RpcAuthorization, 0);
    }

    const out = try allocator.alloc(rpc_transaction_mod.RpcAuthorization, items.len);
    errdefer allocator.free(out);

    for (items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        const ao = item.object;
        const chain_id = try parseHexU256(jsonGetString(ao, "chainId") orelse return error.InvalidResponse);
        const address = (try parseOptionalAddress(jsonGetString(ao, "address"))) orelse return error.InvalidResponse;
        const nonce = try parseHexU64(jsonGetString(ao, "nonce") orelse return error.InvalidResponse);
        // yParity is the canonical key; tolerate `v` as an alias.
        const yp_str = jsonGetString(ao, "yParity") orelse jsonGetString(ao, "v") orelse return error.InvalidResponse;
        const y_parity = try parseHexU8(yp_str);
        if (y_parity > 1) return error.InvalidResponse; // EIP-7702 y_parity is 0 or 1
        const r = try parseHash(jsonGetString(ao, "r") orelse return error.InvalidResponse);
        const s = try parseHash(jsonGetString(ao, "s") orelse return error.InvalidResponse);
        out[i] = .{
            .chain_id = chain_id,
            .address = address,
            .nonce = nonce,
            .y_parity = y_parity,
            .r = r,
            .s = s,
        };
    }

    return out;
}

/// Parse the logs response from eth_getLogs.
fn parseLogsResponse(allocator: std.mem.Allocator, raw: []const u8) ![]receipt_mod.Log {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    // Check for RPC error
    if (root.object.get("error")) |err_val| {
        if (err_val == .object) {
            return error.RpcError;
        }
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val != .array) return error.InvalidResponse;

    const arr = result_val.array;
    if (arr.items.len == 0) {
        return allocator.alloc(receipt_mod.Log, 0);
    }

    const logs = try allocator.alloc(receipt_mod.Log, arr.items.len);
    var parsed_count: usize = 0;
    errdefer {
        for (logs[0..parsed_count]) |log| {
            allocator.free(log.data);
            if (log.topics.len > 0) allocator.free(log.topics);
        }
        allocator.free(logs);
    }

    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        logs[i] = try parseSingleLog(allocator, item.object);
        parsed_count += 1;
    }

    return logs;
}

/// Parse a block header from a raw JSON-RPC response.
pub fn parseBlockHeader(allocator: std.mem.Allocator, raw: []const u8) !?block_mod.BlockHeader {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    // Check for RPC error
    if (root.object.get("error")) |err_val| {
        if (err_val == .object) {
            return error.RpcError;
        }
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return null;
    if (result_val != .object) return error.InvalidResponse;

    return try parseBlockHeaderObject(allocator, result_val.object);
}

/// Parse a BlockHeader from a bare JSON object, as found in the `result`
/// of eth_getBlockByNumber or a newHeads subscription notification.
pub fn parseBlockHeaderObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !block_mod.BlockHeader {
    // Parse required fields
    const number = try parseHexU64(jsonGetString(obj, "number") orelse return error.InvalidResponse);
    const hash = try parseHash(jsonGetString(obj, "hash") orelse return error.InvalidResponse);
    const parent_hash = try parseHash(jsonGetString(obj, "parentHash") orelse return error.InvalidResponse);
    const nonce = try parseOptionalHexU64(jsonGetString(obj, "nonce"));
    const sha3_uncles = try parseHash(jsonGetString(obj, "sha3Uncles") orelse return error.InvalidResponse);
    const miner_str = jsonGetString(obj, "miner") orelse return error.InvalidResponse;
    const miner = primitives.addressFromHex(miner_str) catch return error.InvalidResponse;
    const state_root = try parseHash(jsonGetString(obj, "stateRoot") orelse return error.InvalidResponse);
    const tx_root = try parseHash(jsonGetString(obj, "transactionsRoot") orelse return error.InvalidResponse);
    const receipts_root = try parseHash(jsonGetString(obj, "receiptsRoot") orelse return error.InvalidResponse);

    // Parse logsBloom (256 bytes = 512 hex chars)
    const bloom_str = jsonGetString(obj, "logsBloom") orelse return error.InvalidResponse;
    const logs_bloom = hex_mod.hexToBytesFixed(256, bloom_str) catch return error.InvalidResponse;

    const difficulty = try parseHexU256(jsonGetString(obj, "difficulty") orelse "0x0");
    const gas_limit = try parseHexU64(jsonGetString(obj, "gasLimit") orelse return error.InvalidResponse);
    const gas_used = try parseHexU64(jsonGetString(obj, "gasUsed") orelse return error.InvalidResponse);
    const timestamp = try parseHexU64(jsonGetString(obj, "timestamp") orelse return error.InvalidResponse);
    const mix_hash = try parseHash(jsonGetString(obj, "mixHash") orelse "0x" ++ @as([64]u8, @splat('0')));

    // Parse extraData
    const extra_data_str = jsonGetString(obj, "extraData") orelse "0x";
    const extra_data = try parseHexBytes(allocator, extra_data_str);
    errdefer allocator.free(extra_data);

    // Optional EIP-1559 / EIP-4844 fields
    const base_fee: ?u256 = if (jsonGetString(obj, "baseFeePerGas")) |s|
        parseHexU256(s) catch null
    else
        null;

    const blob_gas_used: ?u64 = if (jsonGetString(obj, "blobGasUsed")) |s|
        parseHexU64(s) catch null
    else
        null;

    const excess_blob_gas: ?u64 = if (jsonGetString(obj, "excessBlobGas")) |s|
        parseHexU64(s) catch null
    else
        null;

    return block_mod.BlockHeader{
        .number = number,
        .hash = hash,
        .parent_hash = parent_hash,
        .nonce = nonce,
        .sha3_uncles = sha3_uncles,
        .miner = miner,
        .state_root = state_root,
        .transactions_root = tx_root,
        .receipts_root = receipts_root,
        .logs_bloom = logs_bloom,
        .difficulty = difficulty,
        .gas_limit = gas_limit,
        .gas_used = gas_used,
        .timestamp = timestamp,
        .extra_data = extra_data,
        .mix_hash = mix_hash,
        .base_fee_per_gas = base_fee,
        .blob_gas_used = blob_gas_used,
        .excess_blob_gas = excess_blob_gas,
    };
}

/// Serialize a LogFilter into a JSON params array string.
fn formatLogFilter(allocator: std.mem.Allocator, filter: json_rpc.LogFilter) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{");
    var first = true;

    if (filter.fromBlock) |fb| {
        try appendJsonField(allocator, &buf, "fromBlock", fb, first);
        first = false;
    }
    if (filter.toBlock) |tb| {
        try appendJsonField(allocator, &buf, "toBlock", tb, first);
        first = false;
    }
    if (filter.address) |addr| {
        try appendJsonField(allocator, &buf, "address", addr, first);
        first = false;
    }
    if (filter.blockHash) |bh| {
        try appendJsonField(allocator, &buf, "blockHash", bh, first);
        first = false;
    }
    if (filter.topics) |topics| {
        if (!first) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "\"topics\":[");
        for (topics, 0..) |topic, i| {
            if (i > 0) try buf.append(allocator, ',');
            if (topic) |t| {
                try buf.append(allocator, '"');
                try buf.appendSlice(allocator, t);
                try buf.append(allocator, '"');
            } else {
                try buf.appendSlice(allocator, "null");
            }
        }
        try buf.append(allocator, ']');
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

fn appendJsonField(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), key: []const u8, value: []const u8, first: bool) !void {
    if (!first) try buf.append(allocator, ',');
    try buf.append(allocator, '"');
    try buf.appendSlice(allocator, key);
    try buf.appendSlice(allocator, "\":\"");
    try buf.appendSlice(allocator, value);
    try buf.append(allocator, '"');
}

// ============================================================================
// Tests
// ============================================================================

test "extractResultString - string result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":"0xff"}
    ;
    const result = try extractResultString(allocator, raw);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0xff", result);
}

test "extractResultString - null result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;
    try std.testing.expectError(error.NullResult, extractResultString(allocator, raw));
}

test "extractResultString - rpc error" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}
    ;
    try std.testing.expectError(error.RpcError, extractResultString(allocator, raw));
}

test "Provider.lastError - null before any error" {
    var transport = HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = Provider.init(std.testing.allocator, &transport);
    try std.testing.expect(provider.lastError() == null);
}

test "Provider.captureRpcError - records code and message" {
    var transport = HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = Provider.init(std.testing.allocator, &transport);

    provider.captureRpcError(
        \\{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}
    );

    const info = provider.lastError() orelse return error.TestExpectedDiagnostic;
    try std.testing.expectEqual(@as(i64, 3), info.code);
    try std.testing.expectEqualStrings("execution reverted", info.message);
}

test "Provider.next_id - atomic, starts at 1 and increments" {
    var transport = HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = Provider.init(std.testing.allocator, &transport);
    try std.testing.expectEqual(@as(u64, 1), provider.next_id.fetchAdd(1, .monotonic));
    try std.testing.expectEqual(@as(u64, 2), provider.next_id.load(.monotonic));
}

test "parseHexU64 - basic values" {
    try std.testing.expectEqual(@as(u64, 1), try parseHexU64("0x1"));
    try std.testing.expectEqual(@as(u64, 255), try parseHexU64("0xff"));
    try std.testing.expectEqual(@as(u64, 0), try parseHexU64("0x0"));
    try std.testing.expectEqual(@as(u64, 17000000), try parseHexU64("0x1036640"));
}

test "parseHexU256 - large value" {
    const val = try parseHexU256("0xde0b6b3a7640000");
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), val);
}

test "parseHexBytes - basic" {
    const allocator = std.testing.allocator;
    const bytes = try parseHexBytes(allocator, "0xdeadbeef");
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, bytes);
}

test "parseHexBytes - empty" {
    const allocator = std.testing.allocator;
    const bytes = try parseHexBytes(allocator, "0x");
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), bytes.len);
}

test "parseHexBytes - odd length" {
    const allocator = std.testing.allocator;
    const bytes = try parseHexBytes(allocator, "0xf");
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{0x0f}, bytes);
}

test "formatLogFilter - empty filter" {
    const allocator = std.testing.allocator;
    const filter = json_rpc.LogFilter{};
    const result = try formatLogFilter(allocator, filter);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("[{}]", result);
}

test "formatLogFilter - with address and blocks" {
    const allocator = std.testing.allocator;
    const filter = json_rpc.LogFilter{
        .fromBlock = "0x1",
        .toBlock = "0x100",
        .address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    };
    const result = try formatLogFilter(allocator, filter);
    defer allocator.free(result);

    // Verify the result contains the expected fields
    try std.testing.expect(std.mem.indexOf(u8, result, "\"fromBlock\":\"0x1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"toBlock\":\"0x100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"address\"") != null);
}

test "formatLogFilter - with topics" {
    const allocator = std.testing.allocator;
    const topics = [_]?[]const u8{
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        null,
    };
    const filter = json_rpc.LogFilter{
        .topics = &topics,
    };
    const result = try formatLogFilter(allocator, filter);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"topics\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "null") != null);
}

test "Provider.formatAddressAndBlock" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    var provider = Provider.init(allocator, &transport);
    const addr = try primitives.addressFromHex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const params = try provider.formatAddressAndBlock(addr, "latest");
    defer allocator.free(params);

    try std.testing.expectEqualStrings(
        "[\"0xd8da6bf26964af9d7eed9e03e53415d37aa96045\",\"latest\"]",
        params,
    );
}

test "Provider.formatCallParams - without from" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    var provider = Provider.init(allocator, &transport);
    const to = try primitives.addressFromHex("0xdead000000000000000000000000000000000000");
    const data = &[_]u8{ 0xab, 0xcd };

    const params = try provider.formatCallParams(to, data, null);
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"to\":\"0xdead000000000000000000000000000000000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"data\":\"0xabcd\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"from\"") == null);
}

test "Provider.formatCallParams - with from" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    var provider = Provider.init(allocator, &transport);
    const to = try primitives.addressFromHex("0xdead000000000000000000000000000000000000");
    const from = try primitives.addressFromHex("0xbeef000000000000000000000000000000000000");
    const data = &[_]u8{};

    const params = try provider.formatCallParams(to, data, from);
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"from\":\"0xbeef000000000000000000000000000000000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"to\":\"0xdead000000000000000000000000000000000000\"") != null);
}

test "Provider.formatCallParamsWithOverrides - balance override" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    var provider = Provider.init(allocator, &transport);
    const to = try primitives.addressFromHex("0xdead000000000000000000000000000000000000");
    const data = &[_]u8{ 0x12, 0x34 };

    var overrides = state_overrides_mod.StateOverrides.init(allocator);
    defer overrides.deinit();
    const target = try primitives.addressFromHex("0xcafe000000000000000000000000000000000000");
    try overrides.setBalance(target, 0xdeadbeef);

    const params = try provider.formatCallParamsWithOverrides(to, data, null, &overrides);
    defer allocator.free(params);

    // Shape: [{...},"latest",{...overrides...}]
    try std.testing.expect(std.mem.indexOf(u8, params, "\"to\":\"0xdead000000000000000000000000000000000000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"data\":\"0x1234\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, ",\"latest\",{") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"0xcafe000000000000000000000000000000000000\":{\"balance\":\"0xdeadbeef\"}") != null);
    try std.testing.expect(std.mem.endsWith(u8, params, "}}]"));
}

test "Provider.formatCallParamsWithOverrides - empty overrides emits {}" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    var provider = Provider.init(allocator, &transport);
    const to = try primitives.addressFromHex("0xdead000000000000000000000000000000000000");
    const data = &[_]u8{};

    var overrides = state_overrides_mod.StateOverrides.init(allocator);
    defer overrides.deinit();

    const params = try provider.formatCallParamsWithOverrides(to, data, null, &overrides);
    defer allocator.free(params);

    // Even with no overrides, the third positional argument is present.
    try std.testing.expect(std.mem.endsWith(u8, params, "\"latest\",{}]"));
}

test "parseTransactionReceipt - successful receipt" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":{
        \\"transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\"blockHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\"blockNumber":"0xbc614e",
        \\"transactionIndex":"0x2a",
        \\"from":"0x1111111111111111111111111111111111111111",
        \\"to":"0x2222222222222222222222222222222222222222",
        \\"gasUsed":"0x5208",
        \\"cumulativeGasUsed":"0x7a120",
        \\"effectiveGasPrice":"0x4a817c800",
        \\"status":"0x1",
        \\"type":"0x2",
        \\"contractAddress":null,
        \\"logs":[]
        \\}}
    ;

    const receipt = (try parseTransactionReceipt(allocator, raw)) orelse return error.InvalidResponse;

    try std.testing.expectEqual(@as(u64, 12345678), receipt.block_number);
    try std.testing.expectEqual(@as(u32, 42), receipt.transaction_index);
    try std.testing.expectEqual(@as(u8, 1), receipt.status);
    try std.testing.expectEqual(@as(u8, 2), receipt.type_);
    try std.testing.expectEqual(@as(u256, 21000), receipt.gas_used);
    try std.testing.expect(receipt.contract_address == null);
    try std.testing.expectEqual(@as(usize, 0), receipt.logs.len);
}

test "parseTransactionReceipt - null result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;

    const receipt = try parseTransactionReceipt(allocator, raw);
    try std.testing.expect(receipt == null);
}

test "parseSingleTransaction - pending EIP-1559" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x5",
        \\ "blockHash":null,
        \\ "blockNumber":null,
        \\ "transactionIndex":null,
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0xde0b6b3a7640000",
        \\ "gas":"0x5208",
        \\ "maxFeePerGas":"0x4a817c800",
        \\ "maxPriorityFeePerGas":"0x77359400",
        \\ "input":"0xdeadbeef",
        \\ "v":"0x1",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x2",
        \\ "chainId":"0x1"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqual(@as(u64, 5), tx.nonce);
    try std.testing.expect(tx.block_hash == null);
    try std.testing.expectEqual(@as(u8, 2), tx.type_);
    try std.testing.expect(tx.gas_price == null);
    try std.testing.expectEqual(@as(?u256, 20_000_000_000), tx.max_fee_per_gas);
    try std.testing.expectEqual(@as(?u256, 2_000_000_000), tx.max_priority_fee_per_gas);
    try std.testing.expectEqual(@as(?u64, 1), tx.chain_id);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, tx.input);
    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), tx.value);
}

test "parseSingleTransaction - EIP-7702 with authorizationList" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x7",
        \\ "blockHash":null,
        \\ "blockNumber":null,
        \\ "transactionIndex":null,
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0x0",
        \\ "gas":"0x186a0",
        \\ "maxFeePerGas":"0x4a817c800",
        \\ "maxPriorityFeePerGas":"0x77359400",
        \\ "input":"0x",
        \\ "v":"0x1",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x4",
        \\ "chainId":"0x1",
        \\ "authorizationList":[
        \\   {"chainId":"0x1",
        \\    "address":"0x3333333333333333333333333333333333333333",
        \\    "nonce":"0x2a",
        \\    "yParity":"0x1",
        \\    "r":"0x1111111111111111111111111111111111111111111111111111111111111111",
        \\    "s":"0x2222222222222222222222222222222222222222222222222222222222222222"}
        \\ ]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqual(@as(u8, 4), tx.type_);
    try std.testing.expect(tx.authorization_list != null);
    const list = tx.authorization_list.?;
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqual(@as(u256, 1), list[0].chain_id);
    try std.testing.expectEqual(@as(u64, 0x2a), list[0].nonce);
    try std.testing.expectEqual(@as(u8, 1), list[0].y_parity);
    try std.testing.expectEqual(@as(u8, 0x33), list[0].address[0]);
    try std.testing.expectEqual(@as(u8, 0x11), list[0].r[0]);
    try std.testing.expectEqual(@as(u8, 0x22), list[0].s[0]);
}

test "parseSingleTransaction - no authorizationList yields null" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x5",
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0x0",
        \\ "gas":"0x5208",
        \\ "gasPrice":"0x4a817c800",
        \\ "input":"0x",
        \\ "v":"0x25",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x0"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expect(tx.authorization_list == null);
}

test "parseSingleTransaction - mined legacy" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x10",
        \\ "blockHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\ "blockNumber":"0xbc614e",
        \\ "transactionIndex":"0x2a",
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0x0",
        \\ "gas":"0x5208",
        \\ "gasPrice":"0x4a817c800",
        \\ "input":"0x",
        \\ "v":"0x25",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x0",
        \\ "chainId":"0x1"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqual(@as(u8, 0), tx.type_);
    try std.testing.expectEqual(@as(?u64, 12345678), tx.block_number);
    try std.testing.expectEqual(@as(?u32, 42), tx.transaction_index);
    try std.testing.expectEqual(@as(?u256, 20_000_000_000), tx.gas_price);
    try std.testing.expect(tx.max_fee_per_gas == null);
    try std.testing.expectEqual(@as(usize, 0), tx.input.len);
    try std.testing.expectEqual(@as(u256, 0x25), tx.v);
}

test "parseSingleTransaction - contract creation has null to" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x0",
        \\ "blockHash":null,
        \\ "blockNumber":null,
        \\ "transactionIndex":null,
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":null,
        \\ "value":"0x0",
        \\ "gas":"0x5208",
        \\ "gasPrice":"0x4a817c800",
        \\ "input":"0x6080",
        \\ "v":"0x1c",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x0"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expect(tx.to == null);
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x80 }, tx.input);
}

test "parseSingleTransaction - data alias falls back when input missing" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x0",
        \\ "blockHash":null,
        \\ "blockNumber":null,
        \\ "transactionIndex":null,
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0x0",
        \\ "gas":"0x5208",
        \\ "gasPrice":"0x1",
        \\ "data":"0xfeed",
        \\ "v":"0x1",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x0"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xed }, tx.input);
}

test "parseSingleTransaction - yParity accepted when v missing" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "nonce":"0x0",
        \\ "from":"0x1111111111111111111111111111111111111111",
        \\ "to":"0x2222222222222222222222222222222222222222",
        \\ "value":"0x0",
        \\ "gas":"0x5208",
        \\ "maxFeePerGas":"0x1",
        \\ "maxPriorityFeePerGas":"0x1",
        \\ "input":"0x",
        \\ "yParity":"0x1",
        \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\ "type":"0x2"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const tx = try parseSingleTransaction(allocator, parsed.value.object);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqual(@as(u256, 1), tx.v);
}

test "parseSingleTransaction - malformed fields are rejected" {
    const allocator = std.testing.allocator;
    // Base object is valid; each case corrupts or removes one field.
    const cases = [_]struct { field: []const u8, value: ?[]const u8 }{
        .{ .field = "transactionIndex", .value = "\"not-hex\"" },
        .{ .field = "type", .value = "\"zz\"" },
        .{ .field = "v", .value = null }, // removed entirely (no yParity either)
    };
    for (cases) |case| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try buf.appendSlice(allocator,
            \\{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            \\ "nonce":"0x0",
            \\ "from":"0x1111111111111111111111111111111111111111",
            \\ "value":"0x0",
            \\ "gas":"0x5208",
            \\ "input":"0x",
            \\ "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            \\ "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        if (!std.mem.eql(u8, case.field, "v")) {
            try buf.appendSlice(allocator, ",\"v\":\"0x1\"");
        }
        if (case.value) |val| {
            try buf.appendSlice(allocator, ",\"");
            try buf.appendSlice(allocator, case.field);
            try buf.appendSlice(allocator, "\":");
            try buf.appendSlice(allocator, val);
        }
        try buf.appendSlice(allocator, "}");

        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, buf.items, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidResponse, parseSingleTransaction(allocator, parsed.value.object));
    }
}

test "parseTransactionFromNotification - end-to-end pending tx" {
    // Verify the subscription.zig wrapper round-trips: build a fake
    // notification envelope wrapping a tx object and parse it.
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","method":"eth_subscription","params":{
        \\ "subscription":"0xfeedface",
        \\ "result":{
        \\   "hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\   "nonce":"0x1",
        \\   "blockHash":null,
        \\   "blockNumber":null,
        \\   "transactionIndex":null,
        \\   "from":"0x1111111111111111111111111111111111111111",
        \\   "to":"0x2222222222222222222222222222222222222222",
        \\   "value":"0x0",
        \\   "gas":"0x5208",
        \\   "maxFeePerGas":"0x4a817c800",
        \\   "maxPriorityFeePerGas":"0x77359400",
        \\   "input":"0x",
        \\   "v":"0x1",
        \\   "r":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\   "s":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        \\   "type":"0x2",
        \\   "chainId":"0x1"}}}
    ;
    const subscription = @import("subscription.zig");
    const tx = try subscription.parseTransactionFromNotification(allocator, raw);
    defer rpc_transaction_mod.freeRpcTransaction(allocator, tx);

    try std.testing.expectEqual(@as(u8, 2), tx.type_);
    try std.testing.expectEqual(@as(u64, 1), tx.nonce);
}

test "parseBlockHeader - basic block" {
    const allocator = std.testing.allocator;

    // Build a bloom of 256 zero bytes = "0x" + 512 '0' chars
    const bloom_hex = "0x" ++ @as([512]u8, @splat('0'));

    const raw = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{" ++
        "\"number\":\"0x1036640\"," ++
        "\"hash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"," ++
        "\"parentHash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"," ++
        "\"nonce\":\"0x0\"," ++
        "\"sha3Uncles\":\"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"," ++
        "\"miner\":\"0x1111111111111111111111111111111111111111\"," ++
        "\"stateRoot\":\"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"," ++
        "\"transactionsRoot\":\"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"," ++
        "\"receiptsRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"," ++
        "\"logsBloom\":\"" ++ bloom_hex ++ "\"," ++
        "\"difficulty\":\"0x0\"," ++
        "\"gasLimit\":\"0x1c9c380\"," ++
        "\"gasUsed\":\"0xe4e1c0\"," ++
        "\"timestamp\":\"0x64325a80\"," ++
        "\"extraData\":\"0x\"," ++
        "\"mixHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"," ++
        "\"baseFeePerGas\":\"0x4a817c800\"" ++
        "}}";

    const header = (try parseBlockHeader(allocator, raw)) orelse return error.InvalidResponse;
    defer allocator.free(header.extra_data);

    try std.testing.expectEqual(@as(u64, 17000000), header.number);
    try std.testing.expectEqual(@as(u64, 30000000), header.gas_limit);
    try std.testing.expectEqual(@as(u64, 15000000), header.gas_used);
    try std.testing.expectEqual(@as(?u256, 20_000_000_000), header.base_fee_per_gas);
    try std.testing.expect(header.blob_gas_used == null);
}

test "parseBlockHeader - null result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;

    const header = try parseBlockHeader(allocator, raw);
    try std.testing.expect(header == null);
}

test "parseLogsResponse - empty array" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":[]}
    ;

    const logs = try parseLogsResponse(allocator, raw);
    defer allocator.free(logs);
    try std.testing.expectEqual(@as(usize, 0), logs.len);
}

test "parseLogsResponse - single log" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":[{
        \\"address":"0x1111111111111111111111111111111111111111",
        \\"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
        \\"data":"0x00000000000000000000000000000000000000000000000000000000000003e8",
        \\"blockNumber":"0x100",
        \\"transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\"transactionIndex":"0x0",
        \\"logIndex":"0x0",
        \\"blockHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\"removed":false
        \\}]}
    ;

    const logs = try parseLogsResponse(allocator, raw);
    defer {
        for (logs) |log| {
            allocator.free(log.topics);
            allocator.free(log.data);
        }
        allocator.free(logs);
    }

    try std.testing.expectEqual(@as(usize, 1), logs.len);
    try std.testing.expectEqual(@as(usize, 1), logs[0].topics.len);
    try std.testing.expectEqual(@as(?u64, 256), logs[0].block_number);
    try std.testing.expect(!logs[0].removed);
}

test "Provider.init" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();

    const provider = Provider.init(allocator, &transport);
    try std.testing.expectEqual(@as(u64, 1), provider.next_id.load(.monotonic));
}

test "BatchCaller.init and deinit" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var prov = Provider.init(allocator, &transport);
    var batch = BatchCaller.init(allocator, &prov);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 0), batch.targets.items.len);
}

test "BatchCaller.addCall accumulates" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var prov = Provider.init(allocator, &transport);
    var batch = BatchCaller.init(allocator, &prov);
    defer batch.deinit();

    const idx0 = try batch.addCall(@as([20]u8, @splat(0x11)), &.{ 0x01, 0x02 });
    const idx1 = try batch.addCall(@as([20]u8, @splat(0x22)), &.{ 0x03, 0x04 });

    try std.testing.expectEqual(@as(usize, 0), idx0);
    try std.testing.expectEqual(@as(usize, 1), idx1);
    try std.testing.expectEqual(@as(usize, 2), batch.targets.items.len);
}

test "BatchCaller.reset clears" {
    const allocator = std.testing.allocator;
    var transport = HttpTransport.init(allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var prov = Provider.init(allocator, &transport);
    var batch = BatchCaller.init(allocator, &prov);
    defer batch.deinit();

    _ = try batch.addCall(@as([20]u8, @splat(0x11)), &.{0x01});
    try std.testing.expectEqual(@as(usize, 1), batch.targets.items.len);
    batch.reset();
    try std.testing.expectEqual(@as(usize, 0), batch.targets.items.len);
}

test "parseBatchResponse in order" {
    const allocator = std.testing.allocator;
    const raw = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xdead\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0xbeef\"}]";
    const ids = [_]u64{ 1, 2 };
    const results = try parseBatchResponse(allocator, raw, &ids);
    defer freeBatchResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    switch (results[0]) {
        .success => |data| try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, data),
        else => return error.TestUnexpectedResult,
    }
    switch (results[1]) {
        .success => |data| try std.testing.expectEqualSlices(u8, &.{ 0xbe, 0xef }, data),
        else => return error.TestUnexpectedResult,
    }
}

test "parseBatchResponse out of order" {
    const allocator = std.testing.allocator;
    const raw = "[{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0xbeef\"},{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xdead\"}]";
    const ids = [_]u64{ 1, 2 };
    const results = try parseBatchResponse(allocator, raw, &ids);
    defer freeBatchResults(allocator, results);

    // Results should be in original order (by id), not response order
    switch (results[0]) {
        .success => |data| try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, data),
        else => return error.TestUnexpectedResult,
    }
    switch (results[1]) {
        .success => |data| try std.testing.expectEqualSlices(u8, &.{ 0xbe, 0xef }, data),
        else => return error.TestUnexpectedResult,
    }
}

test "parseBatchResponse partial failure" {
    const allocator = std.testing.allocator;
    const raw = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xdead\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":3,\"message\":\"execution reverted\"}}]";
    const ids = [_]u64{ 1, 2 };
    const results = try parseBatchResponse(allocator, raw, &ids);
    defer freeBatchResults(allocator, results);

    switch (results[0]) {
        .success => |data| try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, data),
        else => return error.TestUnexpectedResult,
    }
    switch (results[1]) {
        .rpc_error => |e| {
            try std.testing.expectEqual(@as(i64, 3), e.code);
        },
        else => return error.TestUnexpectedResult,
    }
}
