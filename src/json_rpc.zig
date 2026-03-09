const std = @import("std");

/// JSON-RPC 2.0 request and response types for Ethereum communication.
/// JSON-RPC request.
pub fn Request(comptime Params: type) type {
    return struct {
        jsonrpc: []const u8 = "2.0",
        method: []const u8,
        params: Params,
        id: u64,
    };
}

/// JSON-RPC success response.
pub fn Response(comptime Result: type) type {
    return struct {
        jsonrpc: []const u8,
        id: ?u64,
        result: ?Result = null,
        @"error": ?RpcError = null,

        pub fn isError(self: @This()) bool {
            return self.@"error" != null;
        }

        pub fn getResult(self: @This()) !Result {
            if (self.@"error") |err| {
                _ = err;
                return error.RpcError;
            }
            return self.result orelse error.NullResult;
        }
    };
}

/// JSON-RPC error object.
pub const RpcError = struct {
    code: i64,
    message: []const u8,
    data: ?[]const u8 = null,
};

/// Common Ethereum JSON-RPC methods.
pub const Method = struct {
    // Chain state
    pub const eth_chainId = "eth_chainId";
    pub const eth_blockNumber = "eth_blockNumber";
    pub const eth_gasPrice = "eth_gasPrice";
    pub const eth_maxPriorityFeePerGas = "eth_maxPriorityFeePerGas";
    pub const eth_feeHistory = "eth_feeHistory";

    // Account state
    pub const eth_getBalance = "eth_getBalance";
    pub const eth_getTransactionCount = "eth_getTransactionCount";
    pub const eth_getCode = "eth_getCode";
    pub const eth_getStorageAt = "eth_getStorageAt";

    // Transactions
    pub const eth_call = "eth_call";
    pub const eth_estimateGas = "eth_estimateGas";
    pub const eth_sendRawTransaction = "eth_sendRawTransaction";
    pub const eth_getTransactionByHash = "eth_getTransactionByHash";
    pub const eth_getTransactionReceipt = "eth_getTransactionReceipt";

    // Blocks
    pub const eth_getBlockByNumber = "eth_getBlockByNumber";
    pub const eth_getBlockByHash = "eth_getBlockByHash";

    // Logs
    pub const eth_getLogs = "eth_getLogs";
    pub const eth_newFilter = "eth_newFilter";
    pub const eth_getFilterChanges = "eth_getFilterChanges";
    pub const eth_uninstallFilter = "eth_uninstallFilter";

    // Subscriptions (WebSocket)
    pub const eth_subscribe = "eth_subscribe";
    pub const eth_unsubscribe = "eth_unsubscribe";

    // Net
    pub const net_version = "net_version";
    pub const net_listening = "net_listening";
    pub const net_peerCount = "net_peerCount";

    // Web3
    pub const web3_clientVersion = "web3_clientVersion";

    // Flashbots / MEV
    pub const eth_sendBundle = "eth_sendBundle";
    pub const eth_callBundle = "eth_callBundle";
    pub const eth_cancelBundle = "eth_cancelBundle";
    pub const mev_sendBundle = "mev_sendBundle";
};

/// Standard JSON-RPC error codes.
pub const ErrorCode = struct {
    pub const parse_error: i64 = -32700;
    pub const invalid_request: i64 = -32600;
    pub const method_not_found: i64 = -32601;
    pub const invalid_params: i64 = -32602;
    pub const internal_error: i64 = -32603;

    // Ethereum-specific
    pub const execution_reverted: i64 = 3;
    pub const transaction_rejected: i64 = -32003;
    pub const resource_not_found: i64 = -32001;
    pub const resource_unavailable: i64 = -32002;
    pub const limit_exceeded: i64 = -32005;
};

/// Ethereum call object for eth_call / eth_estimateGas.
pub const CallObject = struct {
    from: ?[]const u8 = null,
    to: []const u8,
    gas: ?[]const u8 = null,
    gasPrice: ?[]const u8 = null,
    maxFeePerGas: ?[]const u8 = null,
    maxPriorityFeePerGas: ?[]const u8 = null,
    value: ?[]const u8 = null,
    data: ?[]const u8 = null,
};

/// Block parameter (number or tag).
pub const BlockParam = union(enum) {
    number: u64,
    tag: BlockTag,

    pub fn toString(self: BlockParam, buf: *[20]u8) []const u8 {
        switch (self) {
            .tag => |t| return t.toString(),
            .number => |n| {
                // Format as hex with 0x prefix
                var hex_buf: [18]u8 = undefined; // "0x" + max 16 hex digits
                hex_buf[0] = '0';
                hex_buf[1] = 'x';
                const hex_chars = "0123456789abcdef";
                if (n == 0) {
                    buf[0] = '0';
                    buf[1] = 'x';
                    buf[2] = '0';
                    return buf[0..3];
                }
                var val = n;
                var len: usize = 0;
                while (val > 0) : (val >>= 4) {
                    len += 1;
                }
                val = n;
                var i: usize = len;
                while (i > 0) {
                    i -= 1;
                    buf[2 + i] = hex_chars[@intCast(val & 0xf)];
                    val >>= 4;
                }
                buf[0] = '0';
                buf[1] = 'x';
                return buf[0 .. 2 + len];
            },
        }
    }
};

pub const BlockTag = enum {
    latest,
    earliest,
    pending,
    safe,
    finalized,

    pub fn toString(self: BlockTag) []const u8 {
        return switch (self) {
            .latest => "latest",
            .earliest => "earliest",
            .pending => "pending",
            .safe => "safe",
            .finalized => "finalized",
        };
    }
};

/// Log filter for eth_getLogs.
pub const LogFilter = struct {
    fromBlock: ?[]const u8 = null,
    toBlock: ?[]const u8 = null,
    address: ?[]const u8 = null,
    topics: ?[]const ?[]const u8 = null,
    blockHash: ?[]const u8 = null,
};

// Tests
test "Request serialization" {
    const req = Request(struct { []const u8, []const u8 }){
        .method = Method.eth_getBalance,
        .params = .{ "0xdead", "latest" },
        .id = 1,
    };

    try std.testing.expectEqualStrings("2.0", req.jsonrpc);
    try std.testing.expectEqualStrings("eth_getBalance", req.method);
    try std.testing.expectEqual(@as(u64, 1), req.id);
}

test "BlockTag toString" {
    try std.testing.expectEqualStrings("latest", BlockTag.latest.toString());
    try std.testing.expectEqualStrings("finalized", BlockTag.finalized.toString());
}

test "BlockParam number toString" {
    var buf: [20]u8 = undefined;
    const result = (BlockParam{ .number = 255 }).toString(&buf);
    try std.testing.expectEqualStrings("0xff", result);
}

test "BlockParam zero toString" {
    var buf: [20]u8 = undefined;
    const result = (BlockParam{ .number = 0 }).toString(&buf);
    try std.testing.expectEqualStrings("0x0", result);
}

test "BlockParam tag toString" {
    var buf: [20]u8 = undefined;
    const result = (BlockParam{ .tag = .latest }).toString(&buf);
    try std.testing.expectEqualStrings("latest", result);
}

test "Method constants" {
    try std.testing.expectEqualStrings("eth_chainId", Method.eth_chainId);
    try std.testing.expectEqualStrings("eth_sendRawTransaction", Method.eth_sendRawTransaction);
}

test "ErrorCode values" {
    try std.testing.expectEqual(@as(i64, -32700), ErrorCode.parse_error);
    try std.testing.expectEqual(@as(i64, 3), ErrorCode.execution_reverted);
}
