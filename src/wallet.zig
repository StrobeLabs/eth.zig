const std = @import("std");
const signer_mod = @import("signer.zig");
const runtime = @import("runtime.zig");
const provider_mod = @import("provider.zig");
const http_transport_mod = @import("http_transport.zig");
const transaction_mod = @import("transaction.zig");
const receipt_mod = @import("receipt.zig");
const keccak = @import("keccak.zig");
const nonce_manager_mod = @import("nonce_manager.zig");

/// Options for sending a transaction. Fields left as null will be auto-filled
/// from the provider (nonce, gas, fees).
pub const SendTransactionOpts = struct {
    to: ?[20]u8 = null,
    value: u256 = 0,
    data: []const u8 = &.{},
    gas_limit: ?u64 = null,
    max_fee_per_gas: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    nonce: ?u64 = null,
};

pub const WalletError = error{
    ChainIdNotSet,
    SigningFailed,
    ReceiptNotFound,
};

/// A signing wallet that wraps a Signer and a Provider to handle the full
/// transaction lifecycle: fill nonce/gas from the provider, construct an
/// EIP-1559 transaction, sign it, serialize it, and broadcast it.
pub const Wallet = struct {
    /// The account signer (local key or KMS). Owned inline (value semantics).
    signer: signer_mod.Signer,
    provider: *provider_mod.Provider,
    allocator: std.mem.Allocator,
    chain_id: ?u64,
    /// Optional atomic nonce source. When set, `sendTransaction` draws the
    /// nonce from it (collision-free across threads) instead of making a
    /// per-send `eth_getTransactionCount` call. Defaults to null, preserving
    /// the original per-send-RPC behavior. The wallet borrows it and never
    /// frees it. See `nonce_manager.NonceManager`.
    nonce_manager: ?*nonce_manager_mod.NonceManager = null,

    /// Create a new Wallet from a `Signer` (local key or KMS) and a provider.
    /// The chain_id is initially null and will be fetched from the provider
    /// on the first transaction if not set manually.
    pub fn init(allocator: std.mem.Allocator, signer: signer_mod.Signer, provider: *provider_mod.Provider) Wallet {
        return .{
            .signer = signer,
            .provider = provider,
            .allocator = allocator,
            .chain_id = null,
            .nonce_manager = null,
        };
    }

    /// Convenience: create a Wallet from a raw local private key (wraps a
    /// `LocalSigner`). For a KMS-backed key, build a `signer.KmsSigner` and pass
    /// `signer.Signer.fromKms(&kms_signer)` to `init`.
    pub fn initLocal(allocator: std.mem.Allocator, private_key: [32]u8, provider: *provider_mod.Provider) Wallet {
        return init(allocator, signer_mod.Signer.fromPrivateKey(private_key), provider);
    }

    /// Release signer resources owned by this wallet (zeroes a local key). A
    /// KMS signer is borrowed - its owner calls `KmsSigner.deinit` separately.
    /// Call when the Wallet is no longer needed.
    pub fn deinit(self: *Wallet) void {
        self.signer.deinit();
    }

    /// Return the Ethereum address of this wallet's signer.
    pub fn address(self: *const Wallet) ![20]u8 {
        return try self.signer.address();
    }

    /// Ensure chain_id is populated by fetching it from the provider if needed.
    fn ensureChainId(self: *Wallet) !u64 {
        if (self.chain_id) |cid| return cid;
        const cid = try self.provider.getChainId();
        self.chain_id = cid;
        return cid;
    }

    /// Send a transaction: auto-fill nonce, gas, chain_id; sign; broadcast; return tx hash.
    ///
    /// 1. Fetch chain_id from provider if not cached.
    /// 2. Fetch nonce from provider if not specified.
    /// 3. Fetch gas estimates from provider if not specified.
    /// 4. Build an EIP-1559 transaction.
    /// 5. Sign the transaction.
    /// 6. Serialize the signed transaction.
    /// 7. Broadcast via sendRawTransaction.
    /// 8. Return the transaction hash.
    pub fn sendTransaction(self: *Wallet, tx: SendTransactionOpts) ![32]u8 {
        const chain_id = try self.ensureChainId();

        // Auto-fill nonce: an explicit nonce wins; otherwise draw from the
        // nonce manager if one is attached (collision-free across threads),
        // falling back to a per-send pending-count RPC.
        //
        // When the nonce comes from the manager, return it on any later
        // failure (gas estimation, signing, broadcast) so a transaction that
        // never reaches the mempool does not burn a nonce and stall the
        // account. `onFailure` only rolls back if this is still the last nonce
        // issued, so a concurrent `next()` is handled safely.
        var managed_nonce: ?u64 = null;
        const nonce = if (tx.nonce) |n|
            n
        else if (self.nonce_manager) |nm| blk: {
            const n = try nm.next();
            managed_nonce = n;
            break :blk n;
        } else blk: {
            const addr = try self.address();
            break :blk try self.provider.getTransactionCount(addr);
        };
        errdefer if (managed_nonce) |n| {
            _ = self.nonce_manager.?.onFailure(n);
        };

        // Auto-fill gas fees
        const max_priority_fee = if (tx.max_priority_fee_per_gas) |f| f else try self.provider.getMaxPriorityFee();
        const max_fee = if (tx.max_fee_per_gas) |f| f else blk: {
            const gas_price = try self.provider.getGasPrice();
            // max_fee = gas_price + max_priority_fee (a common heuristic)
            break :blk gas_price + max_priority_fee;
        };

        // Auto-fill gas limit
        const gas_limit = if (tx.gas_limit) |g| g else blk: {
            const addr = try self.address();
            if (tx.to) |to_addr| {
                break :blk try self.provider.estimateGas(to_addr, tx.data, addr);
            } else {
                // Contract deployment: estimate with zero address as placeholder
                break :blk try self.provider.estimateGas(@as([20]u8, @splat(0)), tx.data, addr);
            }
        };

        // Build EIP-1559 transaction
        const eip1559_tx = transaction_mod.Eip1559Transaction{
            .chain_id = chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = max_priority_fee,
            .max_fee_per_gas = max_fee,
            .gas_limit = gas_limit,
            .to = tx.to,
            .value = tx.value,
            .data = tx.data,
            .access_list = &.{},
        };

        // Sign and serialize
        const signed_bytes = try self.signTransaction(eip1559_tx);
        defer self.allocator.free(signed_bytes);

        // Broadcast
        return try self.provider.sendRawTransaction(signed_bytes);
    }

    /// Sign and send a transaction, then wait for the receipt by polling.
    /// max_attempts controls how many times to poll for the receipt.
    pub fn sendTransactionAndWait(self: *Wallet, tx: SendTransactionOpts, max_attempts: u32) !receipt_mod.TransactionReceipt {
        const tx_hash = try self.sendTransaction(tx);
        const maybe_receipt = try self.waitForReceipt(tx_hash, max_attempts);
        return maybe_receipt orelse return error.ReceiptNotFound;
    }

    /// Wait for a transaction receipt by polling the provider.
    /// Returns null if the receipt is not found within max_attempts polls.
    /// Each poll sleeps for 1 second between attempts.
    pub fn waitForReceipt(self: *Wallet, tx_hash: [32]u8, max_attempts: u32) !?receipt_mod.TransactionReceipt {
        var attempt: u32 = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            if (try self.provider.getTransactionReceipt(tx_hash)) |receipt| {
                return receipt;
            }
            runtime.sleepMs(self.provider.io(), 1_000); // 1 second
        }
        return null;
    }

    /// Sign an EIP-1559 transaction and return the serialized signed bytes.
    /// Caller owns the returned slice.
    pub fn signTransaction(self: *Wallet, tx: transaction_mod.Eip1559Transaction) ![]u8 {
        const wrapped = transaction_mod.Transaction{ .eip1559 = tx };

        // Hash the transaction for signing
        const msg_hash = try transaction_mod.hashForSigning(self.allocator, wrapped);

        // Sign the hash
        const sig = self.signer.signHash(msg_hash) catch return error.SigningFailed;

        // For EIP-1559 (type 2) transactions, v is the raw recovery id (0 or 1)
        return try transaction_mod.serializeSigned(self.allocator, wrapped, sig.r, sig.s, sig.v);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Wallet.init sets fields correctly" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);
    var wallet = Wallet.initLocal(std.testing.allocator, private_key, &provider);

    try std.testing.expect(wallet.chain_id == null);
    try std.testing.expect(wallet.provider == &provider);
    // Nonce manager is opt-in; default preserves per-send RPC behavior.
    try std.testing.expect(wallet.nonce_manager == null);

    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const addr = try wallet.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Wallet accepts an optional nonce manager without breaking init" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);
    var wallet = Wallet.initLocal(std.testing.allocator, private_key, &provider);

    var nonces = nonce_manager_mod.NonceManager.init(&provider, try wallet.address());
    wallet.nonce_manager = &nonces;
    try std.testing.expect(wallet.nonce_manager.? == &nonces);
}

test "Wallet.signTransaction produces valid signed bytes" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);
    var wallet = Wallet.initLocal(std.testing.allocator, private_key, &provider);
    wallet.chain_id = 1;

    const tx = transaction_mod.Eip1559Transaction{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_500_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .access_list = &.{},
    };

    const signed = try wallet.signTransaction(tx);
    defer std.testing.allocator.free(signed);

    // Must start with type prefix 0x02 for EIP-1559
    try std.testing.expectEqual(@as(u8, 0x02), signed[0]);
    // Signed transaction should be longer than unsigned
    try std.testing.expect(signed.len > 50);
}

test "Wallet.signTransaction is deterministic" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);
    var wallet = Wallet.initLocal(std.testing.allocator, private_key, &provider);
    wallet.chain_id = 1;

    const tx = transaction_mod.Eip1559Transaction{
        .chain_id = 1,
        .nonce = 5,
        .max_priority_fee_per_gas = 2_000_000_000,
        .max_fee_per_gas = 50_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 0,
        .data = &.{ 0xa9, 0x05, 0x9c, 0xbb },
        .access_list = &.{},
    };

    const signed1 = try wallet.signTransaction(tx);
    defer std.testing.allocator.free(signed1);

    const signed2 = try wallet.signTransaction(tx);
    defer std.testing.allocator.free(signed2);

    try std.testing.expectEqualSlices(u8, signed1, signed2);
}

test "SendTransactionOpts defaults" {
    const opts = SendTransactionOpts{
        .to = @as([20]u8, @splat(0xbb)),
    };

    try std.testing.expectEqual(@as(u256, 0), opts.value);
    try std.testing.expectEqual(@as(usize, 0), opts.data.len);
    try std.testing.expect(opts.gas_limit == null);
    try std.testing.expect(opts.max_fee_per_gas == null);
    try std.testing.expect(opts.max_priority_fee_per_gas == null);
    try std.testing.expect(opts.nonce == null);
}

test "SendTransactionOpts supports null to for deployment" {
    const opts = SendTransactionOpts{
        .data = &.{ 0x60, 0x80 },
    };

    try std.testing.expect(opts.to == null);
    try std.testing.expectEqual(@as(usize, 2), opts.data.len);
}

test "SendTransactionOpts with all fields" {
    const opts = SendTransactionOpts{
        .to = @as([20]u8, @splat(0xcc)),
        .value = 1_000_000_000_000_000_000,
        .data = &.{ 0x01, 0x02, 0x03 },
        .gas_limit = 21000,
        .max_fee_per_gas = 30_000_000_000,
        .max_priority_fee_per_gas = 1_500_000_000,
        .nonce = 42,
    };

    try std.testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), opts.value);
    try std.testing.expectEqual(@as(usize, 3), opts.data.len);
    try std.testing.expectEqual(@as(?u64, 21000), opts.gas_limit);
    try std.testing.expectEqual(@as(?u64, 42), opts.nonce);
}
