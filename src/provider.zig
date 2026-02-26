const std = @import("std");
const json_rpc = @import("json_rpc.zig");
const hex_mod = @import("hex.zig");
const uint256_mod = @import("uint256.zig");
const primitives = @import("primitives.zig");
const receipt_mod = @import("receipt.zig");
const block_mod = @import("block.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;

/// Read-only Ethereum JSON-RPC provider.
///
/// Wraps an HttpTransport to make typed Ethereum RPC calls.
/// All hex-encoded responses are parsed into native Zig types.
pub const Provider = struct {
    transport: *HttpTransport,
    allocator: std.mem.Allocator,
    next_id: u64,

    pub fn init(allocator: std.mem.Allocator, transport: *HttpTransport) Provider {
        return .{
            .transport = transport,
            .allocator = allocator,
            .next_id = 1,
        };
    }

    // ========================================================================
    // Chain state
    // ========================================================================

    /// Returns the chain ID of the connected network.
    pub fn getChainId(self: *Provider) !u64 {
        const raw = try self.rpcCall(json_rpc.Method.eth_chainId, "[]");
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
        return parseHexU64(result_str);
    }

    /// Returns the number of the most recent block.
    pub fn getBlockNumber(self: *Provider) !u64 {
        const raw = try self.rpcCall(json_rpc.Method.eth_blockNumber, "[]");
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
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

        const result_str = try extractResultString(raw);
        return parseHexU256(result_str);
    }

    /// Returns the number of transactions sent from the given address (nonce).
    pub fn getTransactionCount(self: *Provider, address: [20]u8) !u64 {
        const params = try self.formatAddressAndBlock(address, "latest");
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getTransactionCount, params);
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
        return parseHexU64(result_str);
    }

    /// Returns the bytecode of the contract at the given address.
    /// Caller owns the returned memory.
    pub fn getCode(self: *Provider, address: [20]u8) ![]u8 {
        const params = try self.formatAddressAndBlock(address, "latest");
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_getCode, params);
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
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

        const result_str = try extractResultString(raw);
        return hex_mod.hexToBytesFixed(32, result_str) catch return error.InvalidResponse;
    }

    // ========================================================================
    // Gas
    // ========================================================================

    /// Returns the current gas price in wei.
    pub fn getGasPrice(self: *Provider) !u256 {
        const raw = try self.rpcCall(json_rpc.Method.eth_gasPrice, "[]");
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
        return parseHexU256(result_str);
    }

    /// Returns the current max priority fee per gas (EIP-1559 tip).
    pub fn getMaxPriorityFee(self: *Provider) !u256 {
        const raw = try self.rpcCall(json_rpc.Method.eth_maxPriorityFeePerGas, "[]");
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
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

        const result_str = try extractResultString(raw);
        return parseHexBytes(self.allocator, result_str);
    }

    /// Estimates the gas needed to execute the given transaction.
    pub fn estimateGas(self: *Provider, to: [20]u8, data: []const u8, from: ?[20]u8) !u64 {
        const params = try self.formatCallParams(to, data, from);
        defer self.allocator.free(params);

        const raw = try self.rpcCall(json_rpc.Method.eth_estimateGas, params);
        defer self.allocator.free(raw);

        const result_str = try extractResultString(raw);
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

        const result_str = try extractResultString(raw);
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

        return parseTransactionReceipt(self.allocator, raw);
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

        return parseBlockHeader(self.allocator, raw);
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

        return parseLogsResponse(self.allocator, raw);
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn rpcCall(self: *Provider, method: []const u8, params: []const u8) ![]u8 {
        const id = self.next_id;
        self.next_id += 1;
        return self.transport.request(method, params, id);
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

    fn formatCallParams(self: *Provider, to: [20]u8, data: []const u8, from: ?[20]u8) ![]u8 {
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
};

// ============================================================================
// JSON response parsing
// ============================================================================

/// Extract the "result" string value from a JSON-RPC response.
/// Handles both quoted string results and null.
fn extractResultString(raw: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, raw, .{}) catch {
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
        .string => |s| s,
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
    return parseHash(s);
}

/// Parse an optional hex u64 value.
fn parseOptionalHexU64(hex_str: ?[]const u8) !?u64 {
    const s = hex_str orelse return null;
    return parseHexU64(s);
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
    errdefer allocator.free(logs);

    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        logs[i] = try parseSingleLog(allocator, item.object);
    }

    return logs;
}

/// Parse a single Log from a JSON object.
fn parseSingleLog(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !receipt_mod.Log {
    const address = (try parseOptionalAddress(jsonGetString(obj, "address"))) orelse return error.InvalidResponse;
    const data_str = jsonGetString(obj, "data") orelse "0x";
    const data = try parseHexBytes(allocator, data_str);

    // Parse topics array
    const topics = try parseTopics(allocator, obj);

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
    errdefer allocator.free(logs);

    for (arr.items, 0..) |item, i| {
        if (item != .object) return error.InvalidResponse;
        logs[i] = try parseSingleLog(allocator, item.object);
    }

    return logs;
}

/// Parse a block header from a raw JSON-RPC response.
fn parseBlockHeader(allocator: std.mem.Allocator, raw: []const u8) !?block_mod.BlockHeader {
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
    const mix_hash = try parseHash(jsonGetString(obj, "mixHash") orelse "0x" ++ "00" ** 32);

    // Parse extraData
    const extra_data_str = jsonGetString(obj, "extraData") orelse "0x";
    const extra_data = try parseHexBytes(allocator, extra_data_str);

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
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":"0xff"}
    ;
    const result = try extractResultString(raw);
    try std.testing.expectEqualStrings("0xff", result);
}

test "extractResultString - null result" {
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;
    try std.testing.expectError(error.NullResult, extractResultString(raw));
}

test "extractResultString - rpc error" {
    const raw =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}
    ;
    try std.testing.expectError(error.RpcError, extractResultString(raw));
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
    var transport = HttpTransport.init(allocator, "http://localhost:8545");
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
    var transport = HttpTransport.init(allocator, "http://localhost:8545");
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
    var transport = HttpTransport.init(allocator, "http://localhost:8545");
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

test "parseBlockHeader - basic block" {
    const allocator = std.testing.allocator;

    // Build a bloom of 256 zero bytes = "0x" + 512 '0' chars
    const bloom_hex = "0x" ++ "00" ** 256;

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
    var transport = HttpTransport.init(allocator, "http://localhost:8545");
    defer transport.deinit();

    const provider = Provider.init(allocator, &transport);
    try std.testing.expectEqual(@as(u64, 1), provider.next_id);
}
