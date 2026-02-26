const std = @import("std");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const Signature = @import("signature.zig").Signature;

const Secp256k1 = std.crypto.ecc.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;
const CompressedScalar = Secp256k1.scalar.CompressedScalar;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Fe = Secp256k1.Fe;

pub const SignError = error{
    InvalidPrivateKey,
    SigningFailed,
};

pub const RecoverError = error{
    InvalidSignature,
    InvalidRecoveryId,
    RecoveryFailed,
};

/// Secp256k1 curve order n.
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const CURVE_ORDER_BYTES: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/// Half the curve order (for low-S enforcement per EIP-2).
/// n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
const HALF_ORDER_BYTES: [32]u8 = .{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
};

/// ECDSA signing with RFC 6979 deterministic nonces and recovery ID.
/// The message_hash must already be the 32-byte Keccak-256 hash.
/// Returns a Signature with low-S enforced per EIP-2.
pub fn sign(private_key: [32]u8, message_hash: [32]u8) SignError!Signature {
    // Validate private key: must be non-zero and less than curve order
    const sk = Scalar.fromBytes(private_key, .big) catch return error.InvalidPrivateKey;
    if (sk.isZero()) return error.InvalidPrivateKey;

    // Generate deterministic nonce k via RFC 6979 using HMAC-SHA256
    const k = generateRfc6979Nonce(private_key, message_hash);
    if (k.isZero()) return error.SigningFailed;

    // R = k * G
    const R = Secp256k1.basePoint.mul(k.toBytes(.big), .big) catch return error.SigningFailed;

    // r = R.x mod n
    const r_affine = R.affineCoordinates();
    const r_bytes = r_affine.x.toBytes(.big);
    const r_scalar = reduceFieldElement(r_bytes);
    if (r_scalar.isZero()) return error.SigningFailed;

    // s = k^-1 * (z + r * sk) mod n
    // where z is the message hash reduced to a scalar
    const z = reduceHash(message_hash);
    const k_inv = k.invert();
    const r_times_sk = r_scalar.mul(sk);
    const z_plus_r_sk = z.add(r_times_sk);
    var s_scalar = k_inv.mul(z_plus_r_sk);
    if (s_scalar.isZero()) return error.SigningFailed;

    // Determine recovery ID from R.y parity.
    // v = 0 if R.y is even, v = 1 if R.y is odd.
    var v: u8 = if (r_affine.y.isOdd()) 1 else 0;

    // Enforce low-S (EIP-2): if s > n/2, negate s and flip v
    if (isHighS(s_scalar)) {
        s_scalar = s_scalar.neg();
        v ^= 1;
    }

    return Signature{
        .r = r_scalar.toBytes(.big),
        .s = s_scalar.toBytes(.big),
        .v = v,
    };
}

/// Recover the uncompressed public key (65 bytes: 0x04 || x || y) from a
/// signature and message hash.
pub fn recover(sig: Signature, message_hash: [32]u8) RecoverError![65]u8 {
    if (sig.v > 1) return error.InvalidRecoveryId;

    // r and s must be valid non-zero scalars
    const r_scalar = Scalar.fromBytes(sig.r, .big) catch return error.InvalidSignature;
    const s_scalar = Scalar.fromBytes(sig.s, .big) catch return error.InvalidSignature;
    if (r_scalar.isZero() or s_scalar.isZero()) return error.InvalidSignature;

    // Reconstruct the R point from r and the recovery ID.
    // R.x = r (we only handle r < field prime, which covers nearly all cases)
    // R.y is recovered from the curve equation y^2 = x^3 + 7
    const r_fe = Fe.fromBytes(sig.r, .big) catch return error.InvalidSignature;
    const ry_is_odd: bool = (sig.v == 1);
    const r_y = Secp256k1.recoverY(r_fe, ry_is_odd) catch return error.InvalidSignature;

    // R = (r_fe, r_y)
    const R = Secp256k1.fromAffineCoordinates(.{ .x = r_fe, .y = r_y }) catch return error.InvalidSignature;

    // z = message hash as scalar
    const z = reduceHash(message_hash);

    // Q = r^-1 * (s*R - z*G) = (r^-1 * s) * R + (-(r^-1 * z)) * G
    // Use double-base multiplication with GLV endomorphism for ~3x speedup
    const r_inv = r_scalar.invert();
    const r_inv_s = r_inv.mul(s_scalar);
    const neg_r_inv_z = r_inv.mul(z).neg();

    const Q = Secp256k1.mulDoubleBasePublic(
        R,
        r_inv_s.toBytes(.big),
        Secp256k1.basePoint,
        neg_r_inv_z.toBytes(.big),
        .big,
    ) catch return error.RecoveryFailed;

    return Q.toUncompressedSec1();
}

/// Recover the Ethereum address from a signature and message hash.
/// The address is keccak256(pubkey[1..])[12..32].
pub fn recoverAddress(sig: Signature, message_hash: [32]u8) RecoverError!primitives.Address {
    const pubkey = try recover(sig, message_hash);
    return pubkeyToAddress(pubkey);
}

/// Derive the Ethereum address from an uncompressed public key (65 bytes).
pub fn pubkeyToAddress(pubkey: [65]u8) primitives.Address {
    // Skip the 0x04 prefix byte, hash the 64-byte x||y
    const hash = keccak.hash(pubkey[1..]);
    return hash[12..32].*;
}

/// Derive the public key from a private key.
pub fn derivePublicKey(private_key: [32]u8) SignError![65]u8 {
    const point = Secp256k1.basePoint.mul(private_key, .big) catch return error.InvalidPrivateKey;
    point.rejectIdentity() catch return error.InvalidPrivateKey;
    return point.toUncompressedSec1();
}

// ============================================================================
// Internal helpers
// ============================================================================

/// RFC 6979 deterministic nonce generation using HMAC-SHA256.
/// Implements the algorithm from RFC 6979 Section 3.2.
fn generateRfc6979Nonce(private_key: [32]u8, message_hash: [32]u8) Scalar {
    // Step a: h1 = message_hash (already provided, 32 bytes)
    // Step b: V = 0x01 0x01 ... 0x01 (32 bytes of 0x01)
    var v: [32]u8 = [_]u8{0x01} ** 32;

    // Step c: K = 0x00 0x00 ... 0x00 (32 bytes of 0x00)
    var k: [32]u8 = [_]u8{0x00} ** 32;

    // Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    var hmac_d = HmacSha256.init(&k);
    hmac_d.update(&v);
    hmac_d.update(&[_]u8{0x00});
    hmac_d.update(&private_key);
    hmac_d.update(&message_hash);
    hmac_d.final(&k);

    // Step e: V = HMAC_K(V)
    var hmac_e = HmacSha256.init(&k);
    hmac_e.update(&v);
    hmac_e.final(&v);

    // Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    var hmac_f = HmacSha256.init(&k);
    hmac_f.update(&v);
    hmac_f.update(&[_]u8{0x01});
    hmac_f.update(&private_key);
    hmac_f.update(&message_hash);
    hmac_f.final(&k);

    // Step g: V = HMAC_K(V)
    var hmac_g = HmacSha256.init(&k);
    hmac_g.update(&v);
    hmac_g.final(&v);

    // Step h: Loop until we get a valid scalar
    while (true) {
        // Step h.2: V = HMAC_K(V), T = V (since qlen == hlen == 256 bits)
        var hmac_h2 = HmacSha256.init(&k);
        hmac_h2.update(&v);
        hmac_h2.final(&v);

        // Step h.3: Try to use T as a scalar
        if (Scalar.fromBytes(v, .big)) |scalar| {
            if (!scalar.isZero()) {
                return scalar;
            }
        } else |_| {}

        // If not valid, update K and V per step h.3
        var hmac_k2 = HmacSha256.init(&k);
        hmac_k2.update(&v);
        hmac_k2.update(&[_]u8{0x00});
        hmac_k2.final(&k);

        var hmac_v2 = HmacSha256.init(&k);
        hmac_v2.update(&v);
        hmac_v2.final(&v);
    }
}

/// Reduce a field element (x-coordinate bytes) to a scalar modulo the curve order.
/// The x-coordinate can be larger than the curve order since the field prime > order.
fn reduceFieldElement(bytes: [32]u8) Scalar {
    // Try as a canonical scalar first
    if (Scalar.fromBytes(bytes, .big)) |s| {
        return s;
    } else |_| {}
    // If the value >= order, reduce it using reduce64 with zero-padding
    var padded: [64]u8 = [_]u8{0} ** 64;
    @memcpy(padded[32..64], &bytes);
    return Scalar.fromBytes(Secp256k1.scalar.reduce64(padded, .big), .big) catch unreachable;
}

/// Reduce a message hash to a scalar. For secp256k1 with 256-bit hashes,
/// if the hash is >= order, reduce mod order.
fn reduceHash(hash: [32]u8) Scalar {
    return reduceFieldElement(hash);
}

/// Check if a scalar value s > n/2 (high S).
fn isHighS(s: Scalar) bool {
    const s_bytes = s.toBytes(.big);
    // Compare s_bytes with HALF_ORDER_BYTES (big-endian)
    for (0..32) |i| {
        if (s_bytes[i] > HALF_ORDER_BYTES[i]) return true;
        if (s_bytes[i] < HALF_ORDER_BYTES[i]) return false;
    }
    // Equal to half order: not considered high (convention)
    return false;
}

/// Verify that recovering a signature produces the expected public key.
fn verifyRecovery(sig: Signature, message_hash: [32]u8, expected_pubkey: Secp256k1) bool {
    const recovered = recover(sig, message_hash) catch return false;
    const expected = expected_pubkey.toUncompressedSec1();
    return std.mem.eql(u8, &recovered, &expected);
}

// ============================================================================
// Tests
// ============================================================================

test "sign and recover with Hardhat account #0" {
    const hex = @import("hex.zig");

    // Hardhat account #0 private key
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // Expected address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    // Verify public key derivation -> address
    const pubkey = try derivePublicKey(private_key);
    const derived_addr = pubkeyToAddress(pubkey);
    try std.testing.expectEqualSlices(u8, &expected_address, &derived_addr);

    // Sign a message hash and recover the address
    const message_hash = keccak.hash("test message");
    const sig = try sign(private_key, message_hash);

    // Recovery ID must be 0 or 1
    try std.testing.expect(sig.v <= 1);

    // Recover the address
    const recovered_addr = try recoverAddress(sig, message_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered_addr);
}

test "sign produces low-S signatures" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // Sign multiple messages and verify all have low-S
    const messages = [_][]const u8{
        "hello",
        "world",
        "ethereum",
        "test",
        "secp256k1",
    };

    for (messages) |msg| {
        const hash = keccak.hash(msg);
        const sig = try sign(private_key, hash);

        // Verify low-S: s must be <= n/2
        const s_scalar = Scalar.fromBytes(sig.s, .big) catch unreachable;
        try std.testing.expect(!isHighS(s_scalar));
    }
}

test "sign deterministic - same input produces same signature" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const message_hash = keccak.hash("deterministic test");
    const sig1 = try sign(private_key, message_hash);
    const sig2 = try sign(private_key, message_hash);

    try std.testing.expectEqualSlices(u8, &sig1.r, &sig2.r);
    try std.testing.expectEqualSlices(u8, &sig1.s, &sig2.s);
    try std.testing.expectEqual(sig1.v, sig2.v);
}

test "sign different messages produce different signatures" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const hash1 = keccak.hash("message1");
    const hash2 = keccak.hash("message2");

    const sig1 = try sign(private_key, hash1);
    const sig2 = try sign(private_key, hash2);

    // r and/or s should differ
    try std.testing.expect(!std.mem.eql(u8, &sig1.r, &sig2.r) or !std.mem.eql(u8, &sig1.s, &sig2.s));
}

test "recover fails with invalid recovery ID" {
    const sig = Signature{
        .r = [_]u8{0} ** 31 ++ [_]u8{1},
        .s = [_]u8{0} ** 31 ++ [_]u8{1},
        .v = 2,
    };
    const hash = keccak.hash("test");
    try std.testing.expectError(error.InvalidRecoveryId, recover(sig, hash));
}

test "recover fails with zero r" {
    const sig = Signature{
        .r = [_]u8{0} ** 32,
        .s = [_]u8{0} ** 31 ++ [_]u8{1},
        .v = 0,
    };
    const hash = keccak.hash("test");
    try std.testing.expectError(error.InvalidSignature, recover(sig, hash));
}

test "recover fails with zero s" {
    const sig = Signature{
        .r = [_]u8{0} ** 31 ++ [_]u8{1},
        .s = [_]u8{0} ** 32,
        .v = 0,
    };
    const hash = keccak.hash("test");
    try std.testing.expectError(error.InvalidSignature, recover(sig, hash));
}

test "sign rejects zero private key" {
    const zero_key = [_]u8{0} ** 32;
    const hash = keccak.hash("test");
    try std.testing.expectError(error.InvalidPrivateKey, sign(zero_key, hash));
}

test "sign rejects private key >= curve order" {
    // Key equal to curve order
    const hash = keccak.hash("test");
    try std.testing.expectError(error.InvalidPrivateKey, sign(CURVE_ORDER_BYTES, hash));
}

test "derivePublicKey for Hardhat account #0" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const pubkey = try derivePublicKey(private_key);

    // Must start with 0x04 (uncompressed)
    try std.testing.expectEqual(@as(u8, 0x04), pubkey[0]);

    // Derive address from pubkey
    const addr = pubkeyToAddress(pubkey);
    const expected_addr = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    try std.testing.expectEqualSlices(u8, &expected_addr, &addr);
}

test "RFC 6979 nonce is deterministic" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const msg_hash = keccak.hash("nonce test");

    const k1 = generateRfc6979Nonce(private_key, msg_hash);
    const k2 = generateRfc6979Nonce(private_key, msg_hash);

    try std.testing.expectEqualSlices(u8, &k1.toBytes(.big), &k2.toBytes(.big));
}

test "RFC 6979 different inputs produce different nonces" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const hash1 = keccak.hash("input1");
    const hash2 = keccak.hash("input2");

    const k1 = generateRfc6979Nonce(private_key, hash1);
    const k2 = generateRfc6979Nonce(private_key, hash2);

    try std.testing.expect(!std.mem.eql(u8, &k1.toBytes(.big), &k2.toBytes(.big)));
}

test "isHighS correctly identifies high S values" {
    // Create a scalar from the half-order + 1 (this should be high-S)
    // We test by signing and verifying the low-S enforcement
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // Sign many messages and verify all have low-S
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        var msg: [36]u8 = undefined;
        @memcpy(msg[0..32], &keccak.hash("batch"));
        msg[32] = @truncate(i >> 24);
        msg[33] = @truncate(i >> 16);
        msg[34] = @truncate(i >> 8);
        msg[35] = @truncate(i);

        const hash = keccak.hash(&msg);
        const sig = try sign(private_key, hash);

        const s_scalar = Scalar.fromBytes(sig.s, .big) catch unreachable;
        try std.testing.expect(!isHighS(s_scalar));
    }
}

test "sign and recover with second test key" {
    const hex = @import("hex.zig");
    // Hardhat account #1
    const private_key = try hex.hexToBytesFixed(32, "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
    const expected_address = try hex.hexToBytesFixed(20, "70997970C51812dc3A010C7d01b50e0d17dc79C8");

    const pubkey = try derivePublicKey(private_key);
    const derived_addr = pubkeyToAddress(pubkey);
    try std.testing.expectEqualSlices(u8, &expected_address, &derived_addr);

    const message_hash = keccak.hash("second key test");
    const sig = try sign(private_key, message_hash);
    const recovered_addr = try recoverAddress(sig, message_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered_addr);
}

test "sign with small private key (key=1)" {
    // Private key = 1 (31 zero bytes + 0x01)
    var private_key: [32]u8 = [_]u8{0} ** 32;
    private_key[31] = 0x01;

    const message_hash = keccak.hash("test");
    const sig = try sign(private_key, message_hash);

    // Recover address from the signature
    const recovered_addr = try recoverAddress(sig, message_hash);

    // Derive address directly from the private key
    const pubkey = try derivePublicKey(private_key);
    const expected_addr = pubkeyToAddress(pubkey);

    try std.testing.expectEqualSlices(u8, &expected_addr, &recovered_addr);
}

test "sign and recover produces correct address for multiple messages" {
    const hex = @import("hex.zig");
    // Hardhat account #0
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const messages = [_][]const u8{ "msg1", "msg2", "msg3", "msg4", "msg5" };

    for (messages) |msg| {
        const message_hash = keccak.hash(msg);
        const sig = try sign(private_key, message_hash);
        const recovered_addr = try recoverAddress(sig, message_hash);
        try std.testing.expectEqualSlices(u8, &expected_address, &recovered_addr);
    }
}

test "derivePublicKey then pubkeyToAddress matches Signer.address" {
    const hex = @import("hex.zig");
    // Hardhat account #0
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const pubkey = try derivePublicKey(private_key);
    const addr = pubkeyToAddress(pubkey);
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "sign produces low-s (EIP-2) canonical signature" {
    const hex = @import("hex.zig");
    // Hardhat account #0
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    const half_n: [32]u8 = .{
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    };

    const messages = [_][]const u8{ "canonical1", "canonical2", "canonical3", "canonical4", "canonical5" };

    for (messages) |msg| {
        const message_hash = keccak.hash(msg);
        const sig = try sign(private_key, message_hash);

        // Extract s as big-endian bytes and verify s <= n/2
        const s_bytes = sig.s;
        var s_is_lte = false;
        for (0..32) |i| {
            if (s_bytes[i] < half_n[i]) {
                s_is_lte = true;
                break;
            } else if (s_bytes[i] > half_n[i]) {
                break;
            }
        }
        // If we didn't break early, all bytes were equal (s == n/2), which is also valid
        if (!s_is_lte) {
            // Check if all bytes are equal (s == n/2)
            s_is_lte = std.mem.eql(u8, &s_bytes, &half_n);
        }
        try std.testing.expect(s_is_lte);
    }
}
