//! Byte-for-byte interop tests against the official c-kzg-4844 test vectors.
//!
//! The YAML files under src/crypto/c-kzg/test_vectors/ are vendored verbatim
//! from the ethereum/c-kzg-4844 v2.1.1 test suite (see that directory's
//! ATTRIBUTION.md). They live inside the package so `@embedFile` can reach them.
//! These tests parse the official blob/commitment/proof inputs and assert that
//! our bindings over the vendored c-kzg + blst reproduce the official outputs
//! exactly. This proves real interop, not just internal round-trip consistency.

const std = @import("std");
const kzg = @import("kzg.zig");
const blob_mod = @import("blob.zig");

const BLOB_SIZE = blob_mod.BLOB_SIZE;

// Official vectors, embedded at compile time. They live under the package root
// (src/) so `@embedFile` can reach them.
const VEC_B2C = @embedFile("crypto/c-kzg/test_vectors/blob_to_kzg_commitment_19b3f3f8c98ea31e.yaml");
const VEC_CBP = @embedFile("crypto/c-kzg/test_vectors/compute_blob_kzg_proof_19b3f3f8c98ea31e.yaml");
const VEC_VERIFY_OK = @embedFile("crypto/c-kzg/test_vectors/verify_blob_kzg_proof_correct_19b3f3f8c98ea31e.yaml");
const VEC_VERIFY_BAD = @embedFile("crypto/c-kzg/test_vectors/verify_blob_kzg_proof_incorrect_19b3f3f8c98ea31e.yaml");

/// Extract the quoted hex value for a `<key>:` line of the form
/// `  key: '0x...'`. Returns the bytes between the surrounding single quotes,
/// including the leading "0x". Searches for "\n<key>:" or a leading "<key>:".
fn findField(yaml: []const u8, key: []const u8) ![]const u8 {
    // Build the search needle "key:".
    var needle_buf: [64]u8 = undefined;
    if (key.len + 1 > needle_buf.len) return error.KeyTooLong;
    @memcpy(needle_buf[0..key.len], key);
    needle_buf[key.len] = ':';
    const needle = needle_buf[0 .. key.len + 1];

    const idx = std.mem.indexOf(u8, yaml, needle) orelse return error.KeyNotFound;
    var i = idx + needle.len;
    // Find opening single quote on this line.
    const q1 = std.mem.indexOfScalarPos(u8, yaml, i, '\'') orelse return error.NoOpenQuote;
    i = q1 + 1;
    const q2 = std.mem.indexOfScalarPos(u8, yaml, i, '\'') orelse return error.NoCloseQuote;
    return yaml[i..q2];
}

/// Decode a "0x"-prefixed hex string of known byte length into `out`.
fn hexToFixed(comptime n: usize, hex: []const u8) ![n]u8 {
    if (hex.len < 2 or hex[0] != '0' or hex[1] != 'x') return error.NotHex;
    const body = hex[2..];
    if (body.len != n * 2) return error.WrongLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, body);
    return out;
}

/// Decode the blob field (allocated; 128 KiB is too big for the stack).
fn decodeBlob(allocator: std.mem.Allocator, yaml: []const u8) !*[BLOB_SIZE]u8 {
    const hex = try findField(yaml, "blob");
    if (hex.len != 2 + BLOB_SIZE * 2) return error.WrongBlobLength;
    const buf = try allocator.create([BLOB_SIZE]u8);
    errdefer allocator.destroy(buf);
    _ = try std.fmt.hexToBytes(buf, hex[2..]);
    return buf;
}

test "official vector: blob_to_kzg_commitment matches byte-for-byte" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_B2C);
    defer allocator.destroy(blob);

    const expected = try hexToFixed(48, try findField(VEC_B2C, "output"));
    const got = try kzg.blobToKzgCommitment(blob);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "official vector: compute_blob_kzg_proof matches byte-for-byte" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_CBP);
    defer allocator.destroy(blob);

    const commitment = try hexToFixed(48, try findField(VEC_CBP, "commitment"));
    const expected = try hexToFixed(48, try findField(VEC_CBP, "output"));
    const got = try kzg.computeBlobKzgProof(blob, commitment);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "official vector: verify_blob_kzg_proof correct proof returns true" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_VERIFY_OK);
    defer allocator.destroy(blob);

    const commitment = try hexToFixed(48, try findField(VEC_VERIFY_OK, "commitment"));
    const proof = try hexToFixed(48, try findField(VEC_VERIFY_OK, "proof"));

    const ok = try kzg.verifyBlobKzgProof(blob, commitment, proof);
    try std.testing.expect(ok);
}

test "official vector: verify_blob_kzg_proof incorrect proof returns false" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_VERIFY_BAD);
    defer allocator.destroy(blob);

    const commitment = try hexToFixed(48, try findField(VEC_VERIFY_BAD, "commitment"));
    const proof = try hexToFixed(48, try findField(VEC_VERIFY_BAD, "proof"));

    // The incorrect-proof vector's expected output is `false`.
    const ok = kzg.verifyBlobKzgProof(blob, commitment, proof) catch false;
    try std.testing.expect(!ok);
}

test "official vector: derived commitment yields versioned hash" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_B2C);
    defer allocator.destroy(blob);

    const commitment = try kzg.blobToKzgCommitment(blob);
    const vh = blob_mod.computeVersionedHash(commitment);
    try std.testing.expectEqual(@as(u8, blob_mod.VERSIONED_HASH_VERSION_KZG), vh[0]);
    try std.testing.expect(blob_mod.verifyVersionedHash(vh, commitment));
}

test "buildSidecar produces verifiable sidecar from official blob" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blob = try decodeBlob(allocator, VEC_B2C);
    defer allocator.destroy(blob);

    const sidecar = try blob_mod.buildSidecar(allocator, blob.*);

    // The sidecar commitment must match the official commitment vector.
    const expected = try hexToFixed(48, try findField(VEC_B2C, "output"));
    try std.testing.expectEqualSlices(u8, &expected, &sidecar.commitment);

    // And the sidecar proof must verify against its own commitment.
    try std.testing.expect(try kzg.verifyBlobKzgProof(&sidecar.blob, sidecar.commitment, sidecar.proof));
}
