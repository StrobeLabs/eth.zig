const std = @import("std");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const secp256k1 = @import("secp256k1.zig");
const Signature = @import("signature.zig").Signature;

/// An Ethereum account signer backed by a secp256k1 private key.
/// Provides message signing with EIP-191 personal message prefix support.
pub const Signer = struct {
    private_key: [32]u8,

    /// Create a new Signer from a 32-byte private key.
    pub fn init(private_key: [32]u8) Signer {
        return .{ .private_key = private_key };
    }

    /// Derive the Ethereum address corresponding to this signer's private key.
    /// pubkey -> keccak256(pubkey_xy) -> last 20 bytes
    pub fn address(self: Signer) secp256k1.SignError!primitives.Address {
        const pubkey = try secp256k1.derivePublicKey(self.private_key);
        return secp256k1.pubkeyToAddress(pubkey);
    }

    /// Sign a 32-byte message hash directly (raw ECDSA sign).
    /// The hash is typically keccak256 of some data.
    pub fn signHash(self: Signer, message_hash: [32]u8) secp256k1.SignError!Signature {
        return secp256k1.sign(self.private_key, message_hash);
    }

    /// Sign a message with the EIP-191 personal message prefix:
    /// keccak256("\x19Ethereum Signed Message:\n" ++ len_str ++ message)
    ///
    /// This is the standard used by eth_sign, personal_sign, etc.
    pub fn signMessage(self: Signer, message: []const u8) secp256k1.SignError!Signature {
        const prefixed_hash = hashPersonalMessage(message);
        return self.signHash(prefixed_hash);
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

    const signer = Signer.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer.signHash and recover" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = Signer.init(private_key);
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

    const signer = Signer.init(private_key);
    const sig = try signer.signMessage("Hello, Ethereum!");

    // To verify: recover from the EIP-191 prefixed hash
    const prefixed_hash = Signer.hashPersonalMessage("Hello, Ethereum!");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Signer.signMessage empty message" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const expected_address = try hex.hexToBytesFixed(20, "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    const signer = Signer.init(private_key);
    const sig = try signer.signMessage("");

    const prefixed_hash = Signer.hashPersonalMessage("");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "hashPersonalMessage produces correct hash" {
    // The prefix for "hello" (5 bytes) should be:
    // keccak256("\x19Ethereum Signed Message:\n5hello")
    const hash = Signer.hashPersonalMessage("hello");

    // Compute expected manually
    const expected = keccak.hash("\x19Ethereum Signed Message:\n5hello");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "hashPersonalMessage with longer message" {
    // 13 bytes: "Hello, World!"
    const hash = Signer.hashPersonalMessage("Hello, World!");
    const expected = keccak.hash("\x19Ethereum Signed Message:\n13Hello, World!");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "hashPersonalMessage with empty message" {
    const hash = Signer.hashPersonalMessage("");
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

    const signer = Signer.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);

    const sig = try signer.signMessage("test from account 1");
    const prefixed_hash = Signer.hashPersonalMessage("test from account 1");
    const recovered = try secp256k1.recoverAddress(sig, prefixed_hash);
    try std.testing.expectEqualSlices(u8, &expected_address, &recovered);
}

test "Signer deterministic signatures" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    const signer = Signer.init(private_key);
    const sig1 = try signer.signMessage("deterministic");
    const sig2 = try signer.signMessage("deterministic");

    try std.testing.expect(sig1.eql(sig2));
}

test "Signer with Hardhat account #2" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
    const expected_address = try hex.hexToBytesFixed(20, "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");

    const signer = Signer.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer with Hardhat account #3" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");
    const expected_address = try hex.hexToBytesFixed(20, "90F79bf6EB2c4f870365E785982E1f101E93b906");

    const signer = Signer.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "Signer with Hardhat account #4" {
    const hex = @import("hex.zig");
    const private_key = try hex.hexToBytesFixed(32, "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a");
    const expected_address = try hex.hexToBytesFixed(20, "15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

    const signer = Signer.init(private_key);
    const addr = try signer.address();
    try std.testing.expectEqualSlices(u8, &expected_address, &addr);
}

test "hashPersonalMessage with 100-byte message" {
    const message: [100]u8 = [_]u8{'A'} ** 100;
    const hash = Signer.hashPersonalMessage(&message);

    // The prefix for a 100-byte message includes "100" (3 chars)
    const prefix = "\x19Ethereum Signed Message:\n";
    const len_str = "100";
    const slices: []const []const u8 = &.{ prefix, len_str, &message };
    const expected = keccak.hashConcat(slices);
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}
