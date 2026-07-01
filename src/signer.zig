const std = @import("std");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const secp256k1 = @import("secp256k1.zig");
const rlp = @import("rlp.zig");
const kms = @import("kms.zig");
const Signature = @import("signature.zig").Signature;
const Authorization = @import("transaction.zig").Authorization;

/// The error set surfaced by the `Signer` interface. It is the union of every
/// implementation's failure modes so the interface's methods have a stable error
/// set across `LocalSigner` (secp256k1) and `KmsSigner` (AWS KMS over the network).
pub const SignerError =
    secp256k1.SignError ||
    secp256k1.RecoverError ||
    kms.KmsError ||
    error{AddressMismatch};

/// EIP-7702 authorization signing magic byte.
/// The authorization hash is `keccak256(MAGIC || rlp([chain_id, address, nonce]))`.
pub const EIP7702_MAGIC: u8 = 0x05;

/// An Ethereum account signer backed by an in-memory secp256k1 private key.
/// Provides message signing with EIP-191 personal message prefix support.
///
/// This is the local-key implementation of the `Signer` interface (the union
/// below). For a key that is generated in and never leaves AWS KMS, use
/// `KmsSigner`.
pub const LocalSigner = struct {
    private_key: [32]u8,

    const secureZero = @import("utils/constants.zig").secureZero;

    /// Create a new LocalSigner from a 32-byte private key.
    pub fn init(private_key: [32]u8) LocalSigner {
        return .{ .private_key = private_key };
    }

    /// Securely zero the private key. Call when the LocalSigner is no longer needed.
    pub fn deinit(self: *LocalSigner) void {
        secureZero(&self.private_key);
    }

    /// Derive the Ethereum address corresponding to this signer's private key.
    /// pubkey -> keccak256(pubkey_xy) -> last 20 bytes
    pub fn address(self: LocalSigner) secp256k1.SignError!primitives.Address {
        const pubkey = try secp256k1.derivePublicKey(self.private_key);
        return secp256k1.pubkeyToAddress(pubkey);
    }

    /// Sign a 32-byte message hash directly (raw ECDSA sign).
    /// The hash is typically keccak256 of some data.
    pub fn signHash(self: LocalSigner, message_hash: [32]u8) secp256k1.SignError!Signature {
        return secp256k1.sign(self.private_key, message_hash);
    }

    /// Sign a message with the EIP-191 personal message prefix:
    /// keccak256("\x19Ethereum Signed Message:\n" ++ len_str ++ message)
    ///
    /// This is the standard used by eth_sign, personal_sign, etc.
    pub fn signMessage(self: LocalSigner, message: []const u8) secp256k1.SignError!Signature {
        const prefixed_hash = hashPersonalMessage(message);
        return self.signHash(prefixed_hash);
    }

    /// Sign an EIP-7702 authorization tuple.
    ///
    /// Computes the authorization signing hash
    /// `keccak256(0x05 || rlp([chain_id, address, nonce]))` and signs it with
    /// this signer's key. The recovered signer of the returned signature is the
    /// `authority` whose code the authorization delegates.
    ///
    /// A `chain_id` of 0 makes the authorization valid on any chain.
    pub fn signAuthorization(
        self: LocalSigner,
        allocator: std.mem.Allocator,
        chain_id: u256,
        delegate: [20]u8,
        nonce: u64,
    ) (std.mem.Allocator.Error || rlp.RlpError || secp256k1.SignError)!Authorization {
        const msg_hash = try hashAuthorization(allocator, chain_id, delegate, nonce);
        const sig = try self.signHash(msg_hash);
        return .{
            .chain_id = chain_id,
            .address = delegate,
            .nonce = nonce,
            .y_parity = sig.v,
            .r = sig.r,
            .s = sig.s,
        };
    }

    /// Compute the EIP-191 prefixed hash for a personal message.
    /// hash = keccak256("\x19Ethereum Signed Message:\n" ++ decimal_length ++ message)
    pub fn hashPersonalMessage(message: []const u8) [32]u8 {
        const prefix = "\x19Ethereum Signed Message:\n";
        const len_str = formatDecimal(message.len);
        const slices: []const []const u8 = &.{
            prefix,
            len_str.slice(),
            message,
        };
        return keccak.hashConcat(slices);
    }
};

/// secp256k1 curve order N and its half, used for EIP-2 low-s normalization.
const SECP256K1_N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
const SECP256K1_HALF_N: u256 = SECP256K1_N / 2;

/// An Ethereum account signer whose secp256k1 private key lives in AWS KMS and
/// never leaves it. Signing calls `kms:Sign`; the address is derived once at
/// construction via `kms:GetPublicKey` and cached.
///
/// The caller owns the `KmsSigner` and must keep it (and the `region` / `key_id`
/// slices it borrows) alive for its lifetime; wrap it into a `Signer` with
/// `Signer.fromKms(&kms_signer)`.
pub const KmsSigner = struct {
    client: kms.Client,
    /// KMS key identifier: key id, key ARN, or alias (e.g. "alias/perpcity/...").
    /// Borrowed; caller keeps it alive.
    key_id: []const u8,
    cached_address: primitives.Address,

    /// Create a KmsSigner, deriving and caching the Ethereum address via
    /// `kms:GetPublicKey`. `io` backs the HTTP client used for KMS calls.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        region: []const u8,
        key_id: []const u8,
    ) SignerError!KmsSigner {
        // Derive the address through a short-lived client so the client we keep
        // starts with an empty connection pool (safe to return by value).
        var probe = kms.Client.init(allocator, io, region);
        const pubkey = probe.getPublicKey(key_id) catch |e| {
            probe.deinit();
            return e;
        };
        probe.deinit();

        return .{
            .client = kms.Client.init(allocator, io, region),
            .key_id = key_id,
            .cached_address = secp256k1.pubkeyToAddress(pubkey),
        };
    }

    pub fn deinit(self: *KmsSigner) void {
        self.client.deinit();
    }

    /// The cached Ethereum address (derived at construction).
    pub fn address(self: *const KmsSigner) primitives.Address {
        return self.cached_address;
    }

    /// Sign a 32-byte hash via `kms:Sign`, then apply EIP-2 low-s normalization
    /// and recover the parity `v` by matching against the cached address.
    pub fn signHash(self: *KmsSigner, message_hash: [32]u8) SignerError!Signature {
        var rs = try self.client.sign(self.key_id, message_hash);

        const s_val = std.mem.readInt(u256, rs[32..64], .big);
        if (s_val > SECP256K1_HALF_N) {
            std.mem.writeInt(u256, rs[32..64], SECP256K1_N - s_val, .big);
        }

        var v: u8 = 0;
        while (v < 2) : (v += 1) {
            const sig = Signature{ .r = rs[0..32].*, .s = rs[32..64].*, .v = v };
            const recovered = secp256k1.recoverAddress(sig, message_hash) catch continue;
            if (std.mem.eql(u8, &recovered, &self.cached_address)) return sig;
        }
        return SignerError.AddressMismatch;
    }

    /// Sign a message with the EIP-191 personal-message prefix.
    pub fn signMessage(self: *KmsSigner, message: []const u8) SignerError!Signature {
        return self.signHash(LocalSigner.hashPersonalMessage(message));
    }
};

/// The signer interface used by `Wallet` and other consumers. A tagged union so
/// it can be owned inline (value semantics) with no allocation or lifetime
/// fix-ups: `local` is stored inline; `kms` borrows a caller-owned `KmsSigner`.
/// The method surface mirrors alloy's `Signer` trait (`address`, `signHash`,
/// `signMessage`).
pub const Signer = union(enum) {
    local: LocalSigner,
    kms: *KmsSigner,

    /// Wrap a local private key.
    pub fn fromPrivateKey(private_key: [32]u8) Signer {
        return .{ .local = LocalSigner.init(private_key) };
    }

    /// Wrap an existing LocalSigner.
    pub fn fromLocal(local_signer: LocalSigner) Signer {
        return .{ .local = local_signer };
    }

    /// Wrap a caller-owned KmsSigner (must outlive this Signer).
    pub fn fromKms(kms_signer: *KmsSigner) Signer {
        return .{ .kms = kms_signer };
    }

    /// The signer's Ethereum address.
    pub fn address(self: *const Signer) SignerError!primitives.Address {
        return switch (self.*) {
            .local => |s| try s.address(),
            .kms => |k| k.address(),
        };
    }

    /// Sign a 32-byte hash (raw ECDSA), returning a recoverable signature.
    pub fn signHash(self: *const Signer, message_hash: [32]u8) SignerError!Signature {
        return switch (self.*) {
            .local => |s| try s.signHash(message_hash),
            .kms => |k| try k.signHash(message_hash),
        };
    }

    /// Sign a message with the EIP-191 personal-message prefix.
    pub fn signMessage(self: *const Signer, message: []const u8) SignerError!Signature {
        return switch (self.*) {
            .local => |s| try s.signMessage(message),
            .kms => |k| try k.signMessage(message),
        };
    }

    /// Release any resources held by the underlying signer.
    pub fn deinit(self: *Signer) void {
        switch (self.*) {
            .local => |*s| s.deinit(),
            .kms => |k| k.deinit(),
        }
    }
};

/// Compute the EIP-7702 authorization signing hash:
/// `keccak256(0x05 || rlp([chain_id, address, nonce]))`.
///
/// This is the hash signed to produce the y_parity/r/s of an `Authorization`.
pub fn hashAuthorization(
    allocator: std.mem.Allocator,
    chain_id: u256,
    delegate: [20]u8,
    nonce: u64,
) (std.mem.Allocator.Error || rlp.RlpError)![32]u8 {
    // RLP-encode the list [chain_id, address, nonce].
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    const payload_len =
        rlp.encodedLength(chain_id) +
        rlp.encodedLength(delegate) +
        rlp.encodedLength(nonce);

    try list.ensureTotalCapacity(allocator, 1 + rlp.lengthPrefixSize(payload_len) + payload_len);
    if (payload_len < 56) {
        list.appendAssumeCapacity(0xc0 + @as(u8, @intCast(payload_len)));
    } else {
        var len_bytes: usize = 0;
        var temp = payload_len;
        while (temp > 0) : (temp >>= 8) len_bytes += 1;
        list.appendAssumeCapacity(0xc0 + 55 + @as(u8, @intCast(len_bytes)));
        var i: usize = len_bytes;
        while (i > 0) {
            i -= 1;
            list.appendAssumeCapacity(@intCast((payload_len >> @intCast(i * 8)) & 0xff));
        }
    }
    try rlp.encodeInto(allocator, &list, chain_id);
    try rlp.encodeInto(allocator, &list, delegate);
    try rlp.encodeInto(allocator, &list, nonce);

    // hash = keccak256(MAGIC || rlp_list)
    const magic = [_]u8{EIP7702_MAGIC};
    const slices: []const []const u8 = &.{ &magic, list.items };
    return keccak.hashConcat(slices);
}

/// Format a usize as a decimal string in a stack buffer.
/// Returns a wrapper with a slice() method for the valid portion.
fn formatDecimal(value: usize) DecimalBuf {
    var buf: [20]u8 = undefined; // max usize decimal digits
    var len: usize = 0;

    if (value == 0) {
        buf[0] = '0';
        return .{ .buf = buf, .len = 1 };
    }

    var v = value;
    while (v > 0) : (v /= 10) {
        len += 1;
    }

    var i = len;
    v = value;
    while (v > 0) : (v /= 10) {
        i -= 1;
        buf[i] = @intCast((v % 10) + '0');
    }

    return .{ .buf = buf, .len = len };
}

const DecimalBuf = struct {
    buf: [20]u8,
    len: usize,

    pub fn slice(self: *const DecimalBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Signer.address returns correct address for Hardhat #0" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = LocalSigner.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer.signHash and recover" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = LocalSigner.init(private_key);
    const message_hash = keccak.hash("test hash signing");
    const sig = try signer.signHash(message_hash);

    // Recover the address
    const recovered = try secp256k1.recoverAddress(sig, message_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Signer.signMessage with known message" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = LocalSigner.init(private_key);
    const sig = try signer.signMessage("Hello, Ethereum!");

    // To verify: recover from the EIP-191 prefixed hash
    const prefixed_hash = LocalSigner.hashPersonalMessage("Hello, Ethereum!");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Signer.signMessage empty message" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = LocalSigner.init(private_key);
    const sig = try signer.signMessage("");

    const prefixed_hash = LocalSigner.hashPersonalMessage("");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "hashPersonalMessage produces correct hash" {
    // The prefix for "hello" (5 bytes) should be:
    // keccak256("\x19Ethereum Signed Message:\n5hello")
    const hash = LocalSigner.hashPersonalMessage("hello");

    // Compute expected manually
    const expected = keccak.hash("\x19Ethereum Signed Message:\n5hello");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "hashPersonalMessage with longer message" {
    // 13 bytes: "Hello, World!"
    const hash = LocalSigner.hashPersonalMessage("Hello, World!");
    const expected = keccak.hash("\x19Ethereum Signed Message:\n13Hello, World!");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "hashPersonalMessage with empty message" {
    const hash = LocalSigner.hashPersonalMessage("");
    const expected = keccak.hash("\x19Ethereum Signed Message:\n0");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "formatDecimal basic values" {
    const zero = formatDecimal(0);
    try std.testing.expectEqualStrings("0", zero.slice());

    const one = formatDecimal(1);
    try std.testing.expectEqualStrings("1", one.slice());

    const ten = formatDecimal(10);
    try std.testing.expectEqualStrings("10", ten.slice());

    const hundred = formatDecimal(100);
    try std.testing.expectEqualStrings("100", hundred.slice());

    const large = formatDecimal(123456);
    try std.testing.expectEqualStrings("123456", large.slice());
}

test "Signer with Hardhat account #1" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
    const expected_address = try hex.hexToBytesFixed(20, "70997970C51812dc3A010C7d01b50e0d17dc79C8");

    const signer = LocalSigner.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);

    const sig = try signer.signMessage("test from account 1");
    const prefixed_hash = LocalSigner.hashPersonalMessage("test from account 1");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Signer deterministic signatures" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const signer = LocalSigner.init(private_key);
    const sig1 = try signer.signMessage("deterministic");
    const sig2 = try signer.signMessage("deterministic");

    try std.testing.expect(sig1.eql(sig2));
}

test "Signer with Hardhat account #2" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
    const expected_address = try hex.hexToBytesFixed(20, "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");

    const signer = LocalSigner.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer with Hardhat account #3" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");
    const expected_address = try hex.hexToBytesFixed(20, "90F79bf6EB2c4f870365E785982E1f101E93b906");

    const signer = LocalSigner.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer with Hardhat account #4" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a");
    const expected_address = try hex.hexToBytesFixed(20, "15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

    const signer = LocalSigner.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "hashAuthorization matches independent keccak(0x05 || rlp([chain_id,address,nonce]))" {
    const allocator = std.testing.allocator;

    const chain_id: u256 = 1;
    const delegate = @as([20]u8, @splat(0xab));
    const nonce: u64 = 5;

    const got = try hashAuthorization(allocator, chain_id, delegate, nonce);

    // Independently RLP-encode [chain_id, address, nonce] and prepend 0x05.
    const rlp_list = try rlp.encode(allocator, struct {
        chain_id: u256,
        address: [20]u8,
        nonce: u64,
    }{ .chain_id = chain_id, .address = delegate, .nonce = nonce });
    defer allocator.free(rlp_list);

    const magic = [_]u8{0x05};
    const expected = keccak.hashConcat(&.{ &magic, rlp_list });

    try std.testing.expectEqualSlices(u8, &expected, &got);

    // Sanity-check the literal RLP shape: chainId=1 -> 0x01, address -> 0x94+20,
    // nonce=5 -> 0x05. Payload = 1 + 21 + 1 = 23 bytes; header = 0xc0+23 = 0xd7.
    try std.testing.expectEqual(@as(u8, 0xd7), rlp_list[0]);
    try std.testing.expectEqual(@as(u8, 0x01), rlp_list[1]);
    try std.testing.expectEqual(@as(u8, 0x94), rlp_list[2]);
    try std.testing.expectEqual(@as(u8, 0x05), rlp_list[rlp_list.len - 1]);
}

test "signAuthorization round-trips: recovered signer equals authority" {
    const hex = @import("hex.zig");
    const allocator = std.testing.allocator;

    // Hardhat account #0.
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = LocalSigner.init(private_key);
    const delegate = @as([20]u8, @splat(0xde));
    const auth = try signer.signAuthorization(allocator, 1, delegate, 42);

    // Fields preserved.
    try std.testing.expectEqual(@as(u256, 1), auth.chain_id);
    try std.testing.expectEqualSlices(u8, &delegate, &auth.address);
    try std.testing.expectEqual(@as(u64, 42), auth.nonce);
    try std.testing.expect(auth.y_parity == 0 or auth.y_parity == 1);

    // Recover the authority from y_parity/r/s and the signing hash.
    const msg_hash = try hashAuthorization(allocator, 1, delegate, 42);
    const sig = Signature{ .r = auth.r, .s = auth.s, .v = auth.y_parity };
    const recovered = try secp256k1.recoverAddress(sig, msg_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "signAuthorization chain_id=0 (any-chain) round-trips" {
    const hex = @import("hex.zig");
    const allocator = std.testing.allocator;

    const private_key = try hex.hexToBytesFixed(32, "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
    const expected_address = try hex.hexToBytesFixed(20, "70997970C51812dc3A010C7d01b50e0d17dc79C8");

    const signer = LocalSigner.init(private_key);
    const delegate = @as([20]u8, @splat(0x01));
    const auth = try signer.signAuthorization(allocator, 0, delegate, 0);

    const msg_hash = try hashAuthorization(allocator, 0, delegate, 0);
    const sig = Signature{ .r = auth.r, .s = auth.s, .v = auth.y_parity };
    const recovered = try secp256k1.recoverAddress(sig, msg_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "hashPersonalMessage with 100-byte message" {
    const message: [100]u8 = @as([100]u8, @splat('A'));
    const hash = LocalSigner.hashPersonalMessage(&message);

    // The prefix for a 100-byte message includes "100" (3 chars)
    const prefix = "\x19Ethereum Signed Message:\n";
    const len_str = "100";
    const slices: []const []const u8 = &.{ prefix, len_str, &message };
    const expected = keccak.hashConcat(slices);
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}
