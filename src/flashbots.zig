const std = @import("std");
const keccak = @import("keccak.zig");
const hex_mod = @import("hex.zig");
const signer_mod = @import("signer.zig");
const secp256k1 = @import("secp256k1.zig");
const primitives = @import("primitives.zig");
const uint256_mod = @import("uint256.zig");
const json_rpc = @import("json_rpc.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const runtime = @import("runtime.zig");

// ============================================================================
// Types
// ============================================================================

/// Options for eth_sendBundle (Flashbots v1).
pub const SendBundleOpts = struct {
    /// Raw signed transaction bytes.
    transactions: []const []const u8,
    /// Target block number for inclusion.
    block_number: u64,
    /// Minimum timestamp for bundle validity.
    min_timestamp: ?u64 = null,
    /// Maximum timestamp for bundle validity.
    max_timestamp: ?u64 = null,
    /// Transaction hashes allowed to revert without invalidating the bundle.
    reverting_tx_hashes: ?[]const [32]u8 = null,
    /// UUID for bundle replacement (use with eth_cancelBundle).
    replacement_uuid: ?[]const u8 = null,
};

/// Result from eth_sendBundle.
pub const SendBundleResult = struct {
    bundle_hash: [32]u8,
};

/// Options for eth_callBundle (bundle simulation).
pub const CallBundleOpts = struct {
    /// Raw signed transaction bytes.
    transactions: []const []const u8,
    /// Block number to simulate at.
    block_number: u64,
    /// State block number or tag (e.g. "latest"). Defaults to block_number if null.
    state_block_number: ?json_rpc.BlockParam = null,
    /// Timestamp to use for simulation.
    timestamp: ?u64 = null,
};

/// Result from eth_callBundle.
pub const CallBundleResult = struct {
    bundle_hash: [32]u8,
    bundle_gas_price: u256,
    coinbase_diff: u256,
    eth_sent_to_coinbase: u256,
    gas_fees: u256,
    total_gas_used: u64,
};

/// Options for eth_cancelBundle.
pub const CancelBundleOpts = struct {
    replacement_uuid: []const u8,
};

/// A single body element in a mev_sendBundle request.
pub const MevBundleBody = union(enum) {
    tx: MevTx,
    hash: [32]u8,

    pub const MevTx = struct {
        data: []const u8,
        can_revert: bool = false,
    };
};

/// Options for mev_sendBundle (MEV-Share).
pub const MevSendBundleOpts = struct {
    body: []const MevBundleBody,
    inclusion: Inclusion,
    validity: ?Validity = null,
    privacy: ?Privacy = null,

    pub const Inclusion = struct {
        block: u64,
        max_block: ?u64 = null,
    };

    pub const Validity = struct {
        refund: ?[]const Refund = null,
        refund_config: ?[]const RefundConfig = null,

        pub const Refund = struct { body_idx: u32, percent: u32 };
        pub const RefundConfig = struct { address: [20]u8, percent: u32 };
    };

    pub const Privacy = struct {
        hints: ?[]const []const u8 = null,
        builders: ?[]const []const u8 = null,
    };
};

/// Result from mev_sendBundle.
pub const MevSendBundleResult = struct {
    bundle_hash: [32]u8,
};

/// Options for eth_sendPrivateTransaction (MEV-Share).
///
/// Submits a single private transaction with configurable hints about what
/// information to share with searchers -- the primary method for getting MEV
/// protection while still allowing backruns.
pub const SendPrivateTxOpts = struct {
    /// Raw signed transaction bytes (not hex).
    tx: []const u8,
    /// Maximum block number for inclusion. Null lets the relay default
    /// (current block + 25).
    max_block_number: ?u64 = null,
    /// MEV-Share hint preferences -- what to reveal to searchers.
    /// Null sends no preferences object (relay defaults apply).
    preferences: ?TxPreferences = null,

    pub const TxPreferences = struct {
        /// Request fast-mode inclusion (shared with all registered builders,
        /// validity-period refund rules relaxed).
        fast: bool = false,
        /// Reveal calldata to searchers.
        calldata: bool = false,
        /// Reveal contract address to searchers.
        contract_address: bool = false,
        /// Reveal event logs to searchers.
        logs: bool = false,
        /// Reveal the 4-byte function selector to searchers.
        function_selector: bool = false,
        /// Which builders to share with. Null = all Flashbots builders.
        builders: ?[]const []const u8 = null,
    };
};

/// Result from eth_sendPrivateTransaction.
pub const SendPrivateTxResult = struct {
    tx_hash: [32]u8,
};

// ============================================================================
// Bundle builder
// ============================================================================

/// Convenience builder for collecting signed transactions into a bundle.
/// Stores borrowed slices -- callers must keep transaction data alive
/// for the lifetime of the Bundle.
pub const Bundle = struct {
    txs: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Bundle {
        return .{
            .txs = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Bundle) void {
        self.txs.deinit(self.allocator);
    }

    /// Add a raw signed transaction (bytes, not hex).
    /// The slice is borrowed, not copied -- caller retains ownership.
    pub fn addTransaction(self: *Bundle, signed_tx: []const u8) !void {
        try self.txs.append(self.allocator, signed_tx);
    }

    /// Return the collected transactions as borrowed slices.
    pub fn transactions(self: *const Bundle) []const []const u8 {
        return self.txs.items;
    }
};

// ============================================================================
// Flashbots auth signing
// ============================================================================

pub const FlashbotsError = error{
    InvalidPrivateKey,
    SigningFailed,
    HttpError,
    ConnectionFailed,
    InvalidResponse,
    RpcError,
    NullResult,
};

/// Compute the X-Flashbots-Signature header value.
/// Matches the ethers.js reference: wallet.signMessage(id(body))
/// where id(body) = keccak256(toUtf8Bytes(body)) as hex string.
///
/// Returns allocator-owned string: "0x<address>:0x<signature>"
fn computeAuthHeader(allocator: std.mem.Allocator, auth_signer: signer_mod.LocalSigner, body: []const u8) ![]u8 {
    // 1. Hash the request body: keccak256(body) -> 32 bytes
    const body_hash = keccak.hash(body);

    // 2. Convert to hex string: "0x" + 64 hex chars = 66 bytes
    //    This matches ethers.utils.id(body) output format
    const body_hash_hex = hex_mod.bytesToHexBuf(32, &body_hash);

    // 3. EIP-191 prefix hash of the hex string (as 66-byte UTF-8 message)
    //    = keccak256("\x19Ethereum Signed Message:\n66" + body_hash_hex)
    const prefixed_hash = signer_mod.LocalSigner.hashPersonalMessage(&body_hash_hex);

    // 4. Sign the prefixed hash
    const sig = auth_signer.signHash(prefixed_hash) catch return error.SigningFailed;

    // 5. Get the signer address
    const addr = auth_signer.address() catch return error.InvalidPrivateKey;

    // 6. Format: "0x<address>:0x<signature>"
    //    address hex = 42 chars, colon = 1, signature hex = 132 chars = 175 total
    const addr_hex = primitives.addressToHex(&addr);
    const sig_bytes = sig.toBytes();
    const sig_hex = hex_mod.bytesToHexBuf(65, &sig_bytes);

    var result = try allocator.alloc(u8, 42 + 1 + 132);
    @memcpy(result[0..42], &addr_hex);
    result[42] = ':';
    @memcpy(result[43..175], &sig_hex);

    return result;
}

// ============================================================================
// Relay client
// ============================================================================

/// Client for submitting MEV bundles to Flashbots-compatible relays.
///
/// Handles JSON-RPC request construction, Flashbots auth signing
/// (X-Flashbots-Signature header), and response parsing.
pub const Relay = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    auth_signer: signer_mod.LocalSigner,
    client: std.http.Client,
    next_id: u64,

    /// Create a new Relay client.
    /// auth_key is the private key used for Flashbots authentication
    /// (separate from the transaction signing key).
    pub fn init(allocator: std.mem.Allocator, url: []const u8, auth_key: [32]u8, io: std.Io) Relay {
        return .{
            .allocator = allocator,
            .url = url,
            .auth_signer = signer_mod.LocalSigner.init(auth_key),
            .client = .{ .allocator = allocator, .io = io },
            .next_id = 1,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.auth_signer.deinit();
        self.client.deinit();
    }

    /// Submit a bundle via eth_sendBundle (Flashbots v1).
    pub fn sendBundle(self: *Relay, opts: SendBundleOpts) !SendBundleResult {
        const params = try buildSendBundleParams(self.allocator, opts);
        defer self.allocator.free(params);

        const raw = try self.authenticatedRequest("eth_sendBundle", params);
        defer self.allocator.free(raw);

        return parseBundleHashResult(self.allocator, raw);
    }

    /// Simulate a bundle via eth_callBundle.
    pub fn callBundle(self: *Relay, opts: CallBundleOpts) !CallBundleResult {
        const params = try buildCallBundleParams(self.allocator, opts);
        defer self.allocator.free(params);

        const raw = try self.authenticatedRequest("eth_callBundle", params);
        defer self.allocator.free(raw);

        return parseCallBundleResult(self.allocator, raw);
    }

    /// Submit a bundle via mev_sendBundle (MEV-Share).
    pub fn mevSendBundle(self: *Relay, opts: MevSendBundleOpts) !MevSendBundleResult {
        const params = try buildMevSendBundleParams(self.allocator, opts);
        defer self.allocator.free(params);

        const raw = try self.authenticatedRequest("mev_sendBundle", params);
        defer self.allocator.free(raw);

        const result = try parseBundleHashResult(self.allocator, raw);
        return MevSendBundleResult{ .bundle_hash = result.bundle_hash };
    }

    /// Submit a single private transaction via eth_sendPrivateTransaction
    /// (MEV-Share).
    pub fn sendPrivateTransaction(self: *Relay, opts: SendPrivateTxOpts) !SendPrivateTxResult {
        const params = try buildSendPrivateTxParams(self.allocator, opts);
        defer self.allocator.free(params);

        const raw = try self.authenticatedRequest("eth_sendPrivateTransaction", params);
        defer self.allocator.free(raw);

        return parseTxHashResult(self.allocator, raw);
    }

    /// Cancel a bundle via eth_cancelBundle.
    pub fn cancelBundle(self: *Relay, opts: CancelBundleOpts) !void {
        const params = try buildCancelBundleParams(self.allocator, opts);
        defer self.allocator.free(params);

        const raw = try self.authenticatedRequest("eth_cancelBundle", params);
        defer self.allocator.free(raw);

        // Just verify no RPC error in response
        try checkRpcError(self.allocator, raw);
    }

    /// Return the Ethereum address of the auth signer.
    pub fn authAddress(self: *const Relay) !primitives.Address {
        return self.auth_signer.address() catch return error.InvalidPrivateKey;
    }

    // -- Internal --

    /// Send a signed JSON-RPC request to the relay and return the raw
    /// response body. Exposed for sibling modules (e.g. mev_share) that
    /// implement additional Flashbots RPC methods on top of Relay.
    /// Caller owns the returned slice.
    pub fn authenticatedRequest(self: *Relay, method: []const u8, params_json: []const u8) ![]u8 {
        const id = self.next_id;
        self.next_id += 1;

        // Build JSON-RPC body (reuse HttpTransport utility)
        const body = try HttpTransport.buildRequestBody(self.allocator, method, params_json, id);
        defer self.allocator.free(body);

        // Compute Flashbots auth header
        const auth_header = try computeAuthHeader(self.allocator, self.auth_signer, body);
        defer self.allocator.free(auth_header);

        // Send HTTP POST with custom headers
        var response_body: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer response_body.deinit();

        const result = self.client.fetch(.{
            .location = .{ .url = self.url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "X-Flashbots-Signature", .value = auth_header },
            },
            .response_writer = &response_body.writer,
        });

        if (result) |res| {
            if (res.status != .ok) {
                response_body.deinit();
                return error.HttpError;
            }
            return response_body.toOwnedSlice();
        } else |_| {
            response_body.deinit();
            return error.ConnectionFailed;
        }
    }
};

// ============================================================================
// JSON params builders
// ============================================================================

/// Append a JSON-escaped string to buf (without surrounding quotes).
/// Escapes quotes, backslashes, and control characters per RFC 8259.
fn appendJsonEscaped(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => if (c < 0x20) {
                // Control character: \u00XX
                const hex_chars = "0123456789abcdef";
                try buf.appendSlice(allocator, "\\u00");
                try buf.append(allocator, hex_chars[c >> 4]);
                try buf.append(allocator, hex_chars[c & 0xf]);
            } else {
                try buf.append(allocator, c);
            },
        }
    }
}

fn formatHexU64(buf: *[18]u8, value: u64) []const u8 {
    buf[0] = '0';
    buf[1] = 'x';
    const hex_chars = "0123456789abcdef";
    if (value == 0) {
        buf[2] = '0';
        return buf[0..3];
    }
    var val = value;
    var len: usize = 0;
    while (val > 0) : (val >>= 4) {
        len += 1;
    }
    val = value;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        buf[2 + i] = hex_chars[@intCast(val & 0xf)];
        val >>= 4;
    }
    return buf[0 .. 2 + len];
}

fn buildSendBundleParams(allocator: std.mem.Allocator, opts: SendBundleOpts) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{\"txs\":[");

    // Hex-encode each transaction
    for (opts.transactions, 0..) |tx, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.append(allocator, '"');
        const tx_hex = try hex_mod.bytesToHex(allocator, tx);
        defer allocator.free(tx_hex);
        try buf.appendSlice(allocator, tx_hex);
        try buf.append(allocator, '"');
    }

    try buf.appendSlice(allocator, "],\"blockNumber\":\"");
    var hex_buf: [18]u8 = undefined;
    try buf.appendSlice(allocator, formatHexU64(&hex_buf, opts.block_number));
    try buf.append(allocator, '"');

    if (opts.min_timestamp) |ts| {
        try buf.appendSlice(allocator, ",\"minTimestamp\":");
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{ts}) catch unreachable;
        try buf.appendSlice(allocator, ts_str);
    }

    if (opts.max_timestamp) |ts| {
        try buf.appendSlice(allocator, ",\"maxTimestamp\":");
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{ts}) catch unreachable;
        try buf.appendSlice(allocator, ts_str);
    }

    if (opts.reverting_tx_hashes) |hashes| {
        try buf.appendSlice(allocator, ",\"revertingTxHashes\":[");
        for (hashes, 0..) |hash, i| {
            if (i > 0) try buf.append(allocator, ',');
            try buf.append(allocator, '"');
            const hash_hex = primitives.hashToHex(&hash);
            try buf.appendSlice(allocator, &hash_hex);
            try buf.append(allocator, '"');
        }
        try buf.append(allocator, ']');
    }

    if (opts.replacement_uuid) |uuid| {
        try buf.appendSlice(allocator, ",\"replacementUuid\":\"");
        try appendJsonEscaped(allocator, &buf, uuid);
        try buf.append(allocator, '"');
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

fn buildCallBundleParams(allocator: std.mem.Allocator, opts: CallBundleOpts) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{\"txs\":[");

    for (opts.transactions, 0..) |tx, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.append(allocator, '"');
        const tx_hex = try hex_mod.bytesToHex(allocator, tx);
        defer allocator.free(tx_hex);
        try buf.appendSlice(allocator, tx_hex);
        try buf.append(allocator, '"');
    }

    try buf.appendSlice(allocator, "],\"blockNumber\":\"");
    var hex_buf: [18]u8 = undefined;
    try buf.appendSlice(allocator, formatHexU64(&hex_buf, opts.block_number));
    try buf.append(allocator, '"');

    try buf.appendSlice(allocator, ",\"stateBlockNumber\":\"");
    if (opts.state_block_number) |sbp| {
        var sbp_buf: [20]u8 = undefined;
        try buf.appendSlice(allocator, sbp.toString(&sbp_buf));
    } else {
        try buf.appendSlice(allocator, formatHexU64(&hex_buf, opts.block_number));
    }
    try buf.append(allocator, '"');

    if (opts.timestamp) |ts| {
        try buf.appendSlice(allocator, ",\"timestamp\":");
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{ts}) catch unreachable;
        try buf.appendSlice(allocator, ts_str);
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

/// Build the params array for mev_sendBundle: `[{bundle}]`.
/// Also reused by mev_share.simulateBundle, which splices simulation
/// options into the array. Caller owns the returned slice.
pub fn buildMevSendBundleParams(allocator: std.mem.Allocator, opts: MevSendBundleOpts) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{\"version\":\"v0.1\",\"inclusion\":{\"block\":\"");
    var hex_buf: [18]u8 = undefined;
    try buf.appendSlice(allocator, formatHexU64(&hex_buf, opts.inclusion.block));
    try buf.append(allocator, '"');

    if (opts.inclusion.max_block) |mb| {
        try buf.appendSlice(allocator, ",\"maxBlock\":\"");
        try buf.appendSlice(allocator, formatHexU64(&hex_buf, mb));
        try buf.append(allocator, '"');
    }

    try buf.appendSlice(allocator, "},\"body\":[");

    for (opts.body, 0..) |item, i| {
        if (i > 0) try buf.append(allocator, ',');
        switch (item) {
            .tx => |tx| {
                try buf.appendSlice(allocator, "{\"tx\":\"");
                const tx_hex = try hex_mod.bytesToHex(allocator, tx.data);
                defer allocator.free(tx_hex);
                try buf.appendSlice(allocator, tx_hex);
                try buf.append(allocator, '"');
                if (tx.can_revert) {
                    try buf.appendSlice(allocator, ",\"canRevert\":true");
                }
                try buf.append(allocator, '}');
            },
            .hash => |hash| {
                try buf.appendSlice(allocator, "{\"hash\":\"");
                const hash_hex = primitives.hashToHex(&hash);
                try buf.appendSlice(allocator, &hash_hex);
                try buf.appendSlice(allocator, "\"}");
            },
        }
    }

    try buf.append(allocator, ']');

    if (opts.validity) |validity| {
        try buf.appendSlice(allocator, ",\"validity\":{");
        var first = true;

        if (validity.refund) |refunds| {
            try buf.appendSlice(allocator, "\"refund\":[");
            for (refunds, 0..) |r, i| {
                if (i > 0) try buf.append(allocator, ',');
                try buf.appendSlice(allocator, "{\"bodyIdx\":");
                var num_buf: [20]u8 = undefined;
                const idx_str = std.fmt.bufPrint(&num_buf, "{d}", .{r.body_idx}) catch unreachable;
                try buf.appendSlice(allocator, idx_str);
                try buf.appendSlice(allocator, ",\"percent\":");
                const pct_str = std.fmt.bufPrint(&num_buf, "{d}", .{r.percent}) catch unreachable;
                try buf.appendSlice(allocator, pct_str);
                try buf.append(allocator, '}');
            }
            try buf.append(allocator, ']');
            first = false;
        }

        if (validity.refund_config) |configs| {
            if (!first) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "\"refundConfig\":[");
            for (configs, 0..) |c, i| {
                if (i > 0) try buf.append(allocator, ',');
                try buf.appendSlice(allocator, "{\"address\":\"");
                const addr_hex = primitives.addressToHex(&c.address);
                try buf.appendSlice(allocator, &addr_hex);
                try buf.appendSlice(allocator, "\",\"percent\":");
                var num_buf: [20]u8 = undefined;
                const pct_str = std.fmt.bufPrint(&num_buf, "{d}", .{c.percent}) catch unreachable;
                try buf.appendSlice(allocator, pct_str);
                try buf.append(allocator, '}');
            }
            try buf.append(allocator, ']');
        }

        try buf.append(allocator, '}');
    }

    if (opts.privacy) |privacy| {
        try buf.appendSlice(allocator, ",\"privacy\":{");
        var first = true;

        if (privacy.hints) |hints| {
            try buf.appendSlice(allocator, "\"hints\":[");
            for (hints, 0..) |h, i| {
                if (i > 0) try buf.append(allocator, ',');
                try buf.append(allocator, '"');
                try appendJsonEscaped(allocator, &buf, h);
                try buf.append(allocator, '"');
            }
            try buf.append(allocator, ']');
            first = false;
        }

        if (privacy.builders) |builders| {
            if (!first) try buf.append(allocator, ',');
            try buf.appendSlice(allocator, "\"builders\":[");
            for (builders, 0..) |b, i| {
                if (i > 0) try buf.append(allocator, ',');
                try buf.append(allocator, '"');
                try appendJsonEscaped(allocator, &buf, b);
                try buf.append(allocator, '"');
            }
            try buf.append(allocator, ']');
        }

        try buf.append(allocator, '}');
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

fn buildSendPrivateTxParams(allocator: std.mem.Allocator, opts: SendPrivateTxOpts) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{\"tx\":\"");
    const tx_hex = try hex_mod.bytesToHex(allocator, opts.tx);
    defer allocator.free(tx_hex);
    try buf.appendSlice(allocator, tx_hex);
    try buf.append(allocator, '"');

    if (opts.max_block_number) |mbn| {
        try buf.appendSlice(allocator, ",\"maxBlockNumber\":\"");
        var hex_buf: [18]u8 = undefined;
        try buf.appendSlice(allocator, formatHexU64(&hex_buf, mbn));
        try buf.append(allocator, '"');
    }

    if (opts.preferences) |prefs| {
        try buf.appendSlice(allocator, ",\"preferences\":{\"fast\":");
        try buf.appendSlice(allocator, if (prefs.fast) "true" else "false");

        const any_hint = prefs.calldata or prefs.contract_address or
            prefs.logs or prefs.function_selector;
        if (any_hint or prefs.builders != null) {
            try buf.appendSlice(allocator, ",\"privacy\":{");
            var first = true;

            if (any_hint) {
                try buf.appendSlice(allocator, "\"hints\":[");
                var first_hint = true;
                const hint_flags = [_]struct { on: bool, name: []const u8 }{
                    .{ .on = prefs.calldata, .name = "calldata" },
                    .{ .on = prefs.contract_address, .name = "contract_address" },
                    .{ .on = prefs.logs, .name = "logs" },
                    .{ .on = prefs.function_selector, .name = "function_selector" },
                };
                for (hint_flags) |hf| {
                    if (!hf.on) continue;
                    if (!first_hint) try buf.append(allocator, ',');
                    try buf.append(allocator, '"');
                    try buf.appendSlice(allocator, hf.name);
                    try buf.append(allocator, '"');
                    first_hint = false;
                }
                try buf.append(allocator, ']');
                first = false;
            }

            if (prefs.builders) |builders| {
                if (!first) try buf.append(allocator, ',');
                try buf.appendSlice(allocator, "\"builders\":[");
                for (builders, 0..) |b, i| {
                    if (i > 0) try buf.append(allocator, ',');
                    try buf.append(allocator, '"');
                    try appendJsonEscaped(allocator, &buf, b);
                    try buf.append(allocator, '"');
                }
                try buf.append(allocator, ']');
            }

            try buf.append(allocator, '}');
        }

        try buf.append(allocator, '}');
    }

    try buf.appendSlice(allocator, "}]");
    return buf.toOwnedSlice(allocator);
}

fn buildCancelBundleParams(allocator: std.mem.Allocator, opts: CancelBundleOpts) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "[{\"replacementUuid\":\"");
    try appendJsonEscaped(allocator, &buf, opts.replacement_uuid);
    try buf.appendSlice(allocator, "\"}]");

    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// Response parsing
// ============================================================================

fn checkRpcError(allocator: std.mem.Allocator, raw: []const u8) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    if (root.object.get("error")) |err_val| {
        if (err_val == .object) return error.RpcError;
    }
}

fn parseBundleHashResult(allocator: std.mem.Allocator, raw: []const u8) !SendBundleResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    if (root.object.get("error")) |err_val| {
        if (err_val == .object) return error.RpcError;
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return error.NullResult;
    if (result_val != .object) return error.InvalidResponse;

    const obj = result_val.object;
    const hash_str = switch (obj.get("bundleHash") orelse return error.InvalidResponse) {
        .string => |s| s,
        else => return error.InvalidResponse,
    };

    const bundle_hash = primitives.hashFromHex(hash_str) catch return error.InvalidResponse;
    return SendBundleResult{ .bundle_hash = bundle_hash };
}

/// Parse a response whose `result` is a bare transaction-hash string,
/// as returned by eth_sendPrivateTransaction.
fn parseTxHashResult(allocator: std.mem.Allocator, raw: []const u8) !SendPrivateTxResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    if (root.object.get("error")) |err_val| {
        if (err_val == .object) return error.RpcError;
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return error.NullResult;
    if (result_val != .string) return error.InvalidResponse;

    const tx_hash = primitives.hashFromHex(result_val.string) catch return error.InvalidResponse;
    return SendPrivateTxResult{ .tx_hash = tx_hash };
}

fn parseCallBundleResult(allocator: std.mem.Allocator, raw: []const u8) !CallBundleResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        return error.InvalidResponse;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidResponse;

    if (root.object.get("error")) |err_val| {
        if (err_val == .object) return error.RpcError;
    }

    const result_val = root.object.get("result") orelse return error.InvalidResponse;
    if (result_val == .null) return error.NullResult;
    if (result_val != .object) return error.InvalidResponse;

    const obj = result_val.object;

    const bundle_hash = primitives.hashFromHex(
        jsonGetString(obj, "bundleHash") orelse return error.InvalidResponse,
    ) catch return error.InvalidResponse;

    const bundle_gas_price = parseHexOrIntU256(obj, "bundleGasPrice") catch return error.InvalidResponse;
    const coinbase_diff = parseHexOrIntU256(obj, "coinbaseDiff") catch return error.InvalidResponse;
    const eth_sent = parseHexOrIntU256(obj, "ethSentToCoinbase") catch return error.InvalidResponse;
    const gas_fees = parseHexOrIntU256(obj, "gasFees") catch return error.InvalidResponse;
    const total_gas = parseHexOrIntU64(obj, "totalGasUsed") catch return error.InvalidResponse;

    return CallBundleResult{
        .bundle_hash = bundle_hash,
        .bundle_gas_price = bundle_gas_price,
        .coinbase_diff = coinbase_diff,
        .eth_sent_to_coinbase = eth_sent,
        .gas_fees = gas_fees,
        .total_gas_used = total_gas,
    };
}

fn jsonGetString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// Parse a decimal string into u256.
fn parseDecimalU256(s: []const u8) !u256 {
    if (s.len == 0) return error.InvalidResponse;
    const max_div_10 = std.math.maxInt(u256) / 10;
    const max_rem: u8 = @intCast(std.math.maxInt(u256) % 10);
    var result: u256 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidResponse;
        const digit: u8 = c - '0';
        if (result > max_div_10 or (result == max_div_10 and digit > max_rem))
            return error.InvalidResponse;
        result = result * 10 + digit;
    }
    return result;
}

/// Parse a value that may be a hex string, decimal string, or integer.
/// Flashbots returns decimal strings for bundleGasPrice, coinbaseDiff, etc.
fn parseHexOrIntU256(obj: std.json.ObjectMap, key: []const u8) !u256 {
    const val = obj.get(key) orelse return error.InvalidResponse;
    return switch (val) {
        .string => |s| if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X'))
            uint256_mod.fromHex(s) catch return error.InvalidResponse
        else
            parseDecimalU256(s) catch return error.InvalidResponse,
        .integer => |i| if (i < 0) error.InvalidResponse else @intCast(@as(u128, @intCast(i))),
        else => error.InvalidResponse,
    };
}

fn parseHexOrIntU64(obj: std.json.ObjectMap, key: []const u8) !u64 {
    const val = obj.get(key) orelse return error.InvalidResponse;
    return switch (val) {
        .string => |s| blk: {
            const v = if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X'))
                uint256_mod.fromHex(s) catch return error.InvalidResponse
            else
                parseDecimalU256(s) catch return error.InvalidResponse;
            if (v > std.math.maxInt(u64)) return error.InvalidResponse;
            break :blk @intCast(v);
        },
        .integer => |i| if (i < 0) error.InvalidResponse else @intCast(@as(u128, @intCast(i))),
        else => error.InvalidResponse,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "computeAuthHeader format and recovery" {
    const private_key = try hex_mod.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex_mod.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const auth_signer = signer_mod.LocalSigner.init(private_key);
    const body = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendBundle\",\"params\":[{}],\"id\":1}";

    const header = try computeAuthHeader(std.testing.allocator, auth_signer, body);
    defer std.testing.allocator.free(header);

    // Verify format: "0x<40 hex>:0x<130 hex>" = 175 chars
    try std.testing.expectEqual(@as(usize, 175), header.len);
    try std.testing.expectEqual(@as(u8, ':'), header[42]);
    try std.testing.expectEqualStrings("0x", header[0..2]);
    try std.testing.expectEqualStrings("0x", header[43..45]);

    // Verify the address portion matches expected
    const addr_hex = primitives.addressToHex(&expected_address);
    try std.testing.expectEqualStrings(&addr_hex, header[0..42]);

    // Verify signature is recoverable to the auth address
    const sig_bytes = try hex_mod.hexToBytesFixed(65, header[45..175]);
    const sig = @import("signature.zig").Signature.fromBytes(sig_bytes);

    // Reconstruct the hash that was signed
    const body_hash = keccak.hash(body);
    const body_hash_hex = hex_mod.bytesToHexBuf(32, &body_hash);
    const prefixed_hash = signer_mod.LocalSigner.hashPersonalMessage(&body_hash_hex);

    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Bundle init, add, deinit" {
    var bundle = Bundle.init(std.testing.allocator);
    defer bundle.deinit();

    const tx1 = &[_]u8{ 0x02, 0xf8, 0x50 };
    const tx2 = &[_]u8{ 0x02, 0xf8, 0x60 };

    try bundle.addTransaction(tx1);
    try bundle.addTransaction(tx2);

    const txs = bundle.transactions();
    try std.testing.expectEqual(@as(usize, 2), txs.len);
    try std.testing.expectEqualSlices(u8, tx1, txs[0]);
    try std.testing.expectEqualSlices(u8, tx2, txs[1]);
}

test "buildSendBundleParams - basic" {
    const allocator = std.testing.allocator;
    const tx1 = &[_]u8{ 0xde, 0xad };
    const tx2 = &[_]u8{ 0xbe, 0xef };
    const txs = [_][]const u8{ tx1, tx2 };

    const params = try buildSendBundleParams(allocator, .{
        .transactions = &txs,
        .block_number = 0x100,
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"txs\":[\"0xdead\",\"0xbeef\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"blockNumber\":\"0x100\"") != null);
    // No optional fields
    try std.testing.expect(std.mem.indexOf(u8, params, "minTimestamp") == null);
    try std.testing.expect(std.mem.indexOf(u8, params, "maxTimestamp") == null);
}

test "buildSendBundleParams - with optional fields" {
    const allocator = std.testing.allocator;
    const tx = &[_]u8{0xff};
    const txs = [_][]const u8{tx};
    const hash = @as([32]u8, @splat(0xaa));
    const hashes = [_][32]u8{hash};

    const params = try buildSendBundleParams(allocator, .{
        .transactions = &txs,
        .block_number = 42,
        .min_timestamp = 1000,
        .max_timestamp = 2000,
        .reverting_tx_hashes = &hashes,
        .replacement_uuid = "test-uuid-123",
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"minTimestamp\":1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"maxTimestamp\":2000") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"revertingTxHashes\":[\"0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"replacementUuid\":\"test-uuid-123\"") != null);
}

test "buildCallBundleParams - basic" {
    const allocator = std.testing.allocator;
    const tx = &[_]u8{ 0xab, 0xcd };
    const txs = [_][]const u8{tx};

    const params = try buildCallBundleParams(allocator, .{
        .transactions = &txs,
        .block_number = 0xff,
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"txs\":[\"0xabcd\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"blockNumber\":\"0xff\"") != null);
    // state_block_number defaults to block_number
    try std.testing.expect(std.mem.indexOf(u8, params, "\"stateBlockNumber\":\"0xff\"") != null);
}

test "buildCallBundleParams - with latest tag" {
    const allocator = std.testing.allocator;
    const tx = &[_]u8{ 0xab, 0xcd };
    const txs = [_][]const u8{tx};

    const params = try buildCallBundleParams(allocator, .{
        .transactions = &txs,
        .block_number = 0xff,
        .state_block_number = .{ .tag = .latest },
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"stateBlockNumber\":\"latest\"") != null);
}

test "buildMevSendBundleParams - basic" {
    const allocator = std.testing.allocator;
    const tx_data = &[_]u8{ 0xde, 0xad };
    const body = [_]MevBundleBody{
        .{ .tx = .{ .data = tx_data } },
    };

    const params = try buildMevSendBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 100 },
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"version\":\"v0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"inclusion\":{\"block\":\"0x64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"body\":[{\"tx\":\"0xdead\"}]") != null);
}

test "buildMevSendBundleParams - with hash body and privacy" {
    const allocator = std.testing.allocator;
    const hash = @as([32]u8, @splat(0xbb));
    const body = [_]MevBundleBody{
        .{ .hash = hash },
    };
    const hints = [_][]const u8{ "hash", "logs" };

    const params = try buildMevSendBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 50, .max_block = 55 },
        .privacy = .{ .hints = &hints },
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"hash\":\"0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"maxBlock\":\"0x37\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"privacy\":{\"hints\":[\"hash\",\"logs\"]}") != null);
}

test "buildMevSendBundleParams - with canRevert" {
    const allocator = std.testing.allocator;
    const tx_data = &[_]u8{0xff};
    const body = [_]MevBundleBody{
        .{ .tx = .{ .data = tx_data, .can_revert = true } },
    };

    const params = try buildMevSendBundleParams(allocator, .{
        .body = &body,
        .inclusion = .{ .block = 1 },
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"canRevert\":true") != null);
}

test "buildCancelBundleParams" {
    const allocator = std.testing.allocator;
    const params = try buildCancelBundleParams(allocator, .{
        .replacement_uuid = "550e8400-e29b-41d4-a716-446655440000",
    });
    defer allocator.free(params);

    try std.testing.expectEqualStrings(
        "[{\"replacementUuid\":\"550e8400-e29b-41d4-a716-446655440000\"}]",
        params,
    );
}

test "parseBundleHashResult - success" {
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":{"bundleHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
    ;

    const result = try parseBundleHashResult(std.testing.allocator, raw);
    const expected = @as([32]u8, @splat(0xaa));
    try std.testing.expectEqualSlices(u8, &expected, &result.bundle_hash);
}

test "parseBundleHashResult - rpc error" {
    const raw =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"bundle failed"}}
    ;
    try std.testing.expectError(error.RpcError, parseBundleHashResult(std.testing.allocator, raw));
}

test "parseCallBundleResult - success with decimal strings" {
    // Flashbots returns decimal strings for gas/value fields
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":{
        \\"bundleHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\"bundleGasPrice":"476190476193",
        \\"coinbaseDiff":"20000000000126000",
        \\"ethSentToCoinbase":"20000000000000000",
        \\"gasFees":"126000",
        \\"totalGasUsed":42000
        \\}}
    ;

    const result = try parseCallBundleResult(std.testing.allocator, raw);
    const expected_hash = @as([32]u8, @splat(0xbb));
    try std.testing.expectEqualSlices(u8, &expected_hash, &result.bundle_hash);
    try std.testing.expectEqual(@as(u256, 476190476193), result.bundle_gas_price);
    try std.testing.expectEqual(@as(u256, 20000000000126000), result.coinbase_diff);
    try std.testing.expectEqual(@as(u256, 20000000000000000), result.eth_sent_to_coinbase);
    try std.testing.expectEqual(@as(u256, 126000), result.gas_fees);
    try std.testing.expectEqual(@as(u64, 42000), result.total_gas_used);
}

test "Relay.init sets fields correctly" {
    const auth_key = try hex_mod.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    var relay = Relay.init(std.testing.allocator, "https://relay.flashbots.net", auth_key, runtime.blockingIo());
    defer relay.deinit();

    try std.testing.expectEqualStrings("https://relay.flashbots.net", relay.url);
    try std.testing.expectEqual(@as(u64, 1), relay.next_id);

    const expected_address = try hex_mod.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const addr = try relay.authAddress();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "formatHexU64 - various values" {
    var buf: [18]u8 = undefined;

    try std.testing.expectEqualStrings("0x0", formatHexU64(&buf, 0));
    try std.testing.expectEqualStrings("0x1", formatHexU64(&buf, 1));
    try std.testing.expectEqualStrings("0xff", formatHexU64(&buf, 255));
    try std.testing.expectEqualStrings("0x100", formatHexU64(&buf, 256));
    try std.testing.expectEqualStrings("0x1036640", formatHexU64(&buf, 17000000));
}

test "parseDecimalU256 - basic values" {
    try std.testing.expectEqual(@as(u256, 0), try parseDecimalU256("0"));
    try std.testing.expectEqual(@as(u256, 42000), try parseDecimalU256("42000"));
    try std.testing.expectEqual(@as(u256, 476190476193), try parseDecimalU256("476190476193"));
    try std.testing.expectEqual(@as(u256, 20000000000126000), try parseDecimalU256("20000000000126000"));
    try std.testing.expectError(error.InvalidResponse, parseDecimalU256(""));
    try std.testing.expectError(error.InvalidResponse, parseDecimalU256("0xabc"));
    // max u256 should parse ok
    try std.testing.expectEqual(std.math.maxInt(u256), try parseDecimalU256("115792089237316195423570985008687907853269984665640564039457584007913129639935"));
    // max u256 + 1 should overflow
    try std.testing.expectError(error.InvalidResponse, parseDecimalU256("115792089237316195423570985008687907853269984665640564039457584007913129639936"));
}

test "appendJsonEscaped - special characters" {
    const allocator = std.testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try appendJsonEscaped(allocator, &buf, "hello\"world\\test\nnewline");
    try std.testing.expectEqualStrings("hello\\\"world\\\\test\\nnewline", buf.items);
}

test "buildSendBundleParams - replacement_uuid with special chars" {
    const allocator = std.testing.allocator;
    const tx = &[_]u8{0xff};
    const txs = [_][]const u8{tx};

    const params = try buildSendBundleParams(allocator, .{
        .transactions = &txs,
        .block_number = 1,
        .replacement_uuid = "uuid\"with\\quotes",
    });
    defer allocator.free(params);

    // Verify the JSON is valid - special chars are escaped
    try std.testing.expect(std.mem.indexOf(u8, params, "\"replacementUuid\":\"uuid\\\"with\\\\quotes\"") != null);
}

test "SendBundleOpts defaults" {
    const tx = &[_]u8{0x00};
    const txs = [_][]const u8{tx};
    const opts = SendBundleOpts{
        .transactions = &txs,
        .block_number = 1,
    };

    try std.testing.expect(opts.min_timestamp == null);
    try std.testing.expect(opts.max_timestamp == null);
    try std.testing.expect(opts.reverting_tx_hashes == null);
    try std.testing.expect(opts.replacement_uuid == null);
}

test "MevSendBundleOpts defaults" {
    const body = [_]MevBundleBody{};
    const opts = MevSendBundleOpts{
        .body = &body,
        .inclusion = .{ .block = 1 },
    };

    try std.testing.expect(opts.validity == null);
    try std.testing.expect(opts.privacy == null);
    try std.testing.expect(opts.inclusion.max_block == null);
}

test "buildSendPrivateTxParams - minimal" {
    const allocator = std.testing.allocator;
    const params = try buildSendPrivateTxParams(allocator, .{
        .tx = &[_]u8{ 0x02, 0xab, 0xcd },
    });
    defer allocator.free(params);

    try std.testing.expectEqualStrings("[{\"tx\":\"0x02abcd\"}]", params);
}

test "buildSendPrivateTxParams - max block and full preferences" {
    const allocator = std.testing.allocator;
    const builders = [_][]const u8{ "flashbots", "beaverbuild" };
    const params = try buildSendPrivateTxParams(allocator, .{
        .tx = &[_]u8{0xff},
        .max_block_number = 0x112a880,
        .preferences = .{
            .fast = true,
            .calldata = true,
            .logs = true,
            .builders = &builders,
        },
    });
    defer allocator.free(params);

    try std.testing.expect(std.mem.indexOf(u8, params, "\"tx\":\"0xff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"maxBlockNumber\":\"0x112a880\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "\"preferences\":{\"fast\":true,\"privacy\":{\"hints\":[\"calldata\",\"logs\"],\"builders\":[\"flashbots\",\"beaverbuild\"]}}") != null);
}

test "buildSendPrivateTxParams - fast only emits no privacy object" {
    const allocator = std.testing.allocator;
    const params = try buildSendPrivateTxParams(allocator, .{
        .tx = &[_]u8{0x01},
        .preferences = .{ .fast = true },
    });
    defer allocator.free(params);

    try std.testing.expectEqualStrings("[{\"tx\":\"0x01\",\"preferences\":{\"fast\":true}}]", params);
}

test "parseTxHashResult - success" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    ;
    const result = try parseTxHashResult(allocator, raw);
    try std.testing.expectEqual(@as(u8, 0xaa), result.tx_hash[0]);
    try std.testing.expectEqual(@as(u8, 0xaa), result.tx_hash[31]);
}

test "parseTxHashResult - rpc error" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid"}}
    ;
    try std.testing.expectError(error.RpcError, parseTxHashResult(allocator, raw));
}

test "parseTxHashResult - null result" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;
    try std.testing.expectError(error.NullResult, parseTxHashResult(allocator, raw));
}
