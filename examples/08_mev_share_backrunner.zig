// Example 08: MEV-Share backrunner bot (issue #38)
//
// The canonical MEV-Share developer journey is: read the Flashbots docs,
// clone mev-share-client-ts, write a backrunner. This example is that
// backrunner, in Zig, showcasing four eth.zig features along the way:
//
//   1. Comptime function selectors -- the Uniswap swap selectors below are
//      keccak-hashed by the compiler; matching an incoming hint against them
//      is a zero-cost 4-byte compare.
//   2. The MEV-Share SSE event stream -- MevShareClient.on() subscribes to
//      pending-transaction hints broadcast by the Flashbots matchmaker.
//   3. Bundle composition -- a backrun bundle is [user tx hash, our signed
//      tx]; flashbots.MevSendBundleOpts models the mev_sendBundle wire shape.
//   4. EIP-1559 transaction construction and signing -- the backrun payload
//      is built with eth.transaction and signed with eth.signer, no provider
//      required.
//
// Configuration is read from environment variables (all optional):
//
//   AUTH_KEY             Flashbots reputation/auth key (hex, 32 bytes).
//                        Identity only -- never holds funds. Defaults to the
//                        well-known Anvil test key #0.
//   SIGNER_KEY           Key that signs the backrun transaction. Defaults to
//                        Anvil test key #1.
//   RPC_URL              JSON-RPC endpoint, used only in live mode to fetch
//                        nonce/fees/target block. Default: public Sepolia.
//   MEV_SHARE_STREAM_URL SSE event stream. Default: Sepolia matchmaker.
//   RELAY_URL            Bundle relay. Default: Sepolia Flashbots relay.
//   DRY_RUN              "1" (default) prints the mev_sendBundle params it
//                        WOULD submit. Set to "0" to actually submit.
//   MAX_EVENTS           Stop after N stream events (0 = run forever).
//
// Safe by default: with no environment set, this connects to the Sepolia
// event stream, logs hints, and prints would-be bundles without submitting
// anything anywhere.

const std = @import("std");
const eth = @import("eth");

// ============================================================================
// Step 1: comptime swap selectors
// ============================================================================
// eth.keccak.selector() runs at compile time when invoked with `comptime`:
// the compiler hashes the signature string and bakes the 4 bytes into the
// binary. At runtime, classifying a hint is just a few integer compares.

const WatchedSwap = struct {
    name: []const u8,
    selector: [4]u8,
};

const watched_swaps = [_]WatchedSwap{
    // Uniswap V2 router
    .{
        .name = "UniswapV2 swapExactTokensForTokens",
        .selector = eth.keccak.selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
    },
    .{
        .name = "UniswapV2 swapExactETHForTokens",
        .selector = eth.keccak.selector("swapExactETHForTokens(uint256,address[],address,uint256)"),
    },
    .{
        .name = "UniswapV2 swapExactTokensForETH",
        .selector = eth.keccak.selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
    },
    // Uniswap V3 SwapRouter (struct includes a deadline field)
    .{
        .name = "UniswapV3 exactInputSingle (SwapRouter)",
        .selector = eth.keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"),
    },
    .{
        .name = "UniswapV3 exactInput (SwapRouter)",
        .selector = eth.keccak.selector("exactInput((bytes,address,uint256,uint256,uint256))"),
    },
    // Uniswap V3 SwapRouter02 (no deadline field)
    .{
        .name = "UniswapV3 exactInputSingle (SwapRouter02)",
        .selector = eth.keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"),
    },
};

/// Return the human-readable name of a watched swap, or null if the
/// selector is not one we care about.
fn matchSwap(sel: [4]u8) ?[]const u8 {
    for (watched_swaps) |w| {
        if (std.mem.eql(u8, &w.selector, &sel)) return w.name;
    }
    return null;
}

// ============================================================================
// Bot state
// ============================================================================
// MevShareClient.on() takes a plain `fn (PendingEvent) void` callback with no
// context parameter, so the bot's state lives in a file-scope global that the
// callback reaches for. main() initializes it before subscribing.

const Bot = struct {
    allocator: std.mem.Allocator,
    out: *std.Io.Writer,
    /// Signs the backrun transaction (NOT the auth key).
    signer: eth.signer.Signer,
    signer_address: [20]u8,
    client: *eth.mev_share.MevShareClient,
    /// Provider for nonce/fees/block number; only connected in live mode.
    provider: ?*eth.provider.Provider,
    chain_id: u64,
    dry_run: bool,
    max_events: u64,
    events_seen: u64 = 0,
    matches: u64 = 0,
};

var bot: Bot = undefined;

// ============================================================================
// Step 2: the event stream callback
// ============================================================================

/// Invoked by MevShareClient.on() for every hint on the SSE stream. The
/// event is freed by the client after this returns, so anything that must
/// outlive the callback (nothing here) would need to be copied.
fn onEvent(event: eth.mev_share.PendingEvent) void {
    handleEvent(event) catch |err| {
        bot.out.print("error handling event: {}\n", .{err}) catch {};
    };
    bot.out.flush() catch {};

    bot.events_seen += 1;
    if (bot.max_events > 0 and bot.events_seen >= bot.max_events) {
        bot.out.print(
            "\nReached MAX_EVENTS={d} ({d} matched); exiting.\n",
            .{ bot.max_events, bot.matches },
        ) catch {};
        bot.out.flush() catch {};
        // The stream loop only returns when the server closes the
        // connection, so a demo-friendly event cap exits here instead.
        std.process.exit(0);
    }
}

fn handleEvent(event: eth.mev_share.PendingEvent) !void {
    const out = bot.out;

    const tx = switch (event) {
        .transaction => |tx| tx,
        .bundle => |b| {
            // Multi-tx hints (another searcher's bundle seeking a backrun).
            // Backrunning these works the same way -- target the event hash
            // -- but this example keeps the strategy single-tx only.
            try out.print("[bundle]      {d} txs, skipping\n", .{b.txs.len});
            return;
        },
    };

    const hash_hex = eth.primitives.hashToHex(&tx.hash);

    // Every field except `hash` is a hint the transaction originator chose
    // to reveal. A hash-only event gives us nothing to match on: a real
    // searcher would speculatively simulate against it; we log and skip.
    const sel = tx.function_selector orelse {
        try out.print("[hash-only]   {s} (no selector hint, skipping)\n", .{hash_hex});
        return;
    };

    // Zero-cost dispatch: compare the revealed selector against our
    // comptime-computed table.
    const swap_name = matchSwap(sel) orelse {
        try out.print(
            "[no match]    {s} selector 0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n",
            .{ hash_hex, sel[0], sel[1], sel[2], sel[3] },
        );
        return;
    };

    bot.matches += 1;
    try out.print("[MATCH]       {s}\n              {s}\n", .{ hash_hex, swap_name });
    if (tx.to) |to| {
        const to_hex = eth.primitives.addressToHex(&to);
        try out.print("              to: {s}\n", .{to_hex});
    }

    try submitBackrun(tx.hash);
}

// ============================================================================
// Steps 3 + 4: build, sign, and submit the backrun bundle
// ============================================================================

fn submitBackrun(user_tx_hash: [32]u8) !void {
    const allocator = bot.allocator;
    const out = bot.out;

    // -- Fill in nonce / fees / target block ---------------------------------
    // Live mode fetches real values from the RPC. Dry-run mode stays fully
    // offline and uses placeholders so the example runs with zero
    // infrastructure.
    var nonce: u64 = 0;
    var max_priority_fee: u256 = 1_000_000_000; // 1 gwei placeholder
    var max_fee: u256 = 30_000_000_000; // 30 gwei placeholder
    var target_block: u64 = 0; // placeholder; relay would reject this
    if (bot.provider) |provider| {
        nonce = try provider.getTransactionCount(bot.signer_address);
        max_priority_fee = try provider.getMaxPriorityFee();
        max_fee = try provider.getGasPrice() + max_priority_fee;
        target_block = try provider.getBlockNumber() + 1;
    }

    // -- Construct the backrun transaction (EIP-1559) ------------------------
    //
    // >>> REAL STRATEGY GOES HERE <<<
    //
    // A real backrunner would, e.g., decode the swap from the calldata/logs
    // hints, compute the pool price after the user's swap (eth.dex_v2 /
    // eth.dex_v3 have the math), and arbitrage the displacement against
    // another venue -- encoding that swap with eth.abi_encode as `data` and
    // pointing `to` at the router. This example sends a 0-value transfer to
    // ourselves so the bundle is structurally complete but economically
    // inert.
    const backrun_tx = eth.transaction.Eip1559Transaction{
        .chain_id = bot.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = max_priority_fee,
        .max_fee_per_gas = max_fee,
        .gas_limit = 21_000,
        .to = bot.signer_address, // self-transfer placeholder
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    };

    // Sign it: hash the typed-transaction payload, ECDSA-sign the hash, and
    // RLP-serialize with the signature appended. For type-2 transactions the
    // signature's v is the raw y-parity (0 or 1).
    const wrapped = eth.transaction.Transaction{ .eip1559 = backrun_tx };
    const sighash = try eth.transaction.hashForSigning(allocator, wrapped);
    const sig = try bot.signer.signHash(sighash);
    const signed_tx = try eth.transaction.serializeSigned(allocator, wrapped, sig.r, sig.s, sig.v);
    defer allocator.free(signed_tx);

    // -- Compose the bundle ---------------------------------------------------
    // A backrun bundle references the user's pending transaction by the hash
    // from the event stream (body item 1), followed by our signed raw
    // transaction (body item 2). The matchmaker substitutes the real
    // transaction for the hash at building time; order within the body is
    // execution order.
    const body = [_]eth.flashbots.MevBundleBody{
        .{ .hash = user_tx_hash },
        .{ .tx = .{ .data = signed_tx, .can_revert = false } },
    };
    const bundle = eth.flashbots.MevSendBundleOpts{
        .body = &body,
        // Eligible for inclusion across a 3-block window (target_block ..
        // target_block + 2), giving builders more attempts than a single block.
        .inclusion = .{ .block = target_block, .max_block = target_block + 2 },
    };

    // -- Submit (or print) ----------------------------------------------------
    if (bot.dry_run) {
        // buildMevSendBundleParams renders the exact JSON-RPC params array
        // that mev_sendBundle would receive -- ideal for inspection.
        const params = try eth.flashbots.buildMevSendBundleParams(allocator, bundle);
        defer allocator.free(params);
        try out.print("[dry-run]     would submit mev_sendBundle params:\n              {s}\n", .{params});
        return;
    }

    // Live submission goes through the authenticated relay (the request body
    // is signed with AUTH_KEY into the X-Flashbots-Signature header).
    const result = try bot.client.relay.mevSendBundle(bundle);
    const bundle_hash_hex = eth.primitives.hashToHex(&result.bundle_hash);
    try out.print("[submitted]   bundle hash {s}\n", .{bundle_hash_hex});
}

// ============================================================================
// Configuration and startup
// ============================================================================

/// Parse a 32-byte private key from hex, tolerating an optional 0x prefix.
fn parseKey(s: []const u8) ![32]u8 {
    const stripped = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    return eth.hex.hexToBytesFixed(32, stripped);
}

// Zig 0.16: declaring main with a std.process.Init parameter hands us the
// environment map (and a general-purpose allocator) without any global
// teardown bookkeeping.
pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const env = init.environ_map;
    const io = init.io;

    var buf: [4096]u8 = undefined;
    var stdout_impl = std.Io.File.stdout().writerStreaming(io, &buf);
    const stdout = &stdout_impl.interface;

    // -- Read configuration ---------------------------------------------------
    // Defaults target Sepolia, where the subscription flow can be tested with
    // no mainnet funds. The default keys are the well-known Anvil test keys:
    // the auth key is reputation-only and never holds funds, and dry-run mode
    // never broadcasts anything signed by the signer key.
    const auth_key_hex = env.get("AUTH_KEY") orelse
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const signer_key_hex = env.get("SIGNER_KEY") orelse
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const rpc_url = env.get("RPC_URL") orelse
        "https://ethereum-sepolia-rpc.publicnode.com";
    const stream_url = env.get("MEV_SHARE_STREAM_URL") orelse
        eth.mev_share.sepolia_stream_url;
    const relay_url = env.get("RELAY_URL") orelse
        "https://relay-sepolia.flashbots.net";
    const dry_run = !std.mem.eql(u8, env.get("DRY_RUN") orelse "1", "0");
    const max_events = std.fmt.parseInt(u64, env.get("MAX_EVENTS") orelse "0", 10) catch 0;

    const auth_key = try parseKey(auth_key_hex);
    const signer_key = try parseKey(signer_key_hex);

    const backrun_signer = eth.signer.Signer.init(signer_key);
    const signer_address = try backrun_signer.address();

    // MevShareClient bundles the authenticated relay (mev_sendBundle) with
    // the public SSE stream endpoint.
    var client = eth.mev_share.MevShareClient.init(allocator, relay_url, stream_url, auth_key, io);
    defer client.deinit();
    const auth_address = try client.relay.authAddress();

    // -- Live mode needs an RPC for nonce / fees / target block --------------
    var transport = eth.http_transport.HttpTransport.init(allocator, rpc_url, io);
    defer transport.deinit();
    var provider = eth.provider.Provider.init(allocator, &transport);

    var chain_id: u64 = 11_155_111; // Sepolia; dry-run placeholder
    var live_provider: ?*eth.provider.Provider = null;
    if (!dry_run) {
        chain_id = provider.getChainId() catch |err| {
            try stdout.print("Failed to reach RPC_URL ({s}): {}\n", .{ rpc_url, err });
            try stdout.print("Live mode needs a working RPC. Set RPC_URL or use DRY_RUN=1.\n", .{});
            try stdout.flush();
            return;
        };
        live_provider = &provider;
    }

    // -- Banner ----------------------------------------------------------------
    const auth_checksum = eth.primitives.addressToChecksum(&auth_address);
    const signer_checksum = eth.primitives.addressToChecksum(&signer_address);
    try stdout.print("MEV-Share backrunner (example 08)\n", .{});
    try stdout.print("  stream:   {s}\n", .{stream_url});
    try stdout.print("  relay:    {s}\n", .{relay_url});
    try stdout.print("  rpc:      {s}{s}\n", .{ rpc_url, if (dry_run) " (unused in dry-run)" else "" });
    try stdout.print("  auth:     {s}\n", .{auth_checksum});
    try stdout.print("  signer:   {s}\n", .{signer_checksum});
    try stdout.print("  chain id: {d}\n", .{chain_id});
    try stdout.print("  mode:     {s}\n", .{if (dry_run) "DRY RUN (printing bundles, not submitting)" else "LIVE (submitting bundles)"});
    try stdout.print("\nWatching for swap selectors (computed at comptime):\n", .{});
    for (watched_swaps) |w| {
        const s = w.selector;
        try stdout.print("  0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}  {s}\n", .{ s[0], s[1], s[2], s[3], w.name });
    }
    try stdout.print("\nConnecting to event stream...\n\n", .{});
    try stdout.flush();

    bot = .{
        .allocator = allocator,
        .out = stdout,
        .signer = backrun_signer,
        .signer_address = signer_address,
        .client = &client,
        .provider = live_provider,
        .chain_id = chain_id,
        .dry_run = dry_run,
        .max_events = max_events,
    };

    // -- Subscribe -------------------------------------------------------------
    // on() blocks, parsing SSE frames and invoking the callback per hint.
    // It returns normally when the server closes the connection; production
    // bots wrap it in a reconnect loop.
    client.on(&onEvent) catch |err| {
        try stdout.print("Could not stream from {s}: {}\n", .{ stream_url, err });
        try stdout.print("Check network connectivity or override MEV_SHARE_STREAM_URL.\n", .{});
        try stdout.flush();
        return;
    };

    try stdout.print(
        "\nStream closed by server after {d} events ({d} matched). Wrap client.on() in a loop to reconnect.\n",
        .{ bot.events_seen, bot.matches },
    );
    try stdout.flush();
}
