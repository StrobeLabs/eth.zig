const std = @import("std");
const keccak = @import("keccak.zig");

/// Size of a single blob in bytes (128 KiB).
pub const BLOB_SIZE: usize = 131072;

/// A single EIP-4844 blob (128 KiB of data).
pub const Blob = [BLOB_SIZE]u8;

/// A KZG commitment (48 bytes, BLS12-381 G1 point).
pub const KzgCommitment = [48]u8;

/// A KZG proof (48 bytes, BLS12-381 G1 point).
pub const KzgProof = [48]u8;

/// Version byte for KZG versioned hashes (EIP-4844).
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// A blob sidecar: the blob itself along with its KZG commitment and proof.
pub const BlobSidecar = struct {
    blob: Blob,
    commitment: KzgCommitment,
    proof: KzgProof,
};

/// Build a blob sidecar from raw blob data, computing the KZG commitment and
/// proof via the vendored c-kzg-4844 backend.
///
/// The caller must have initialized the KZG trusted setup with `kzg.init`
/// beforehand (and is responsible for `kzg.deinit`). The `allocator` is
/// accepted for API symmetry; this routine performs no heap allocation itself
/// (a `BlobSidecar` is returned by value).
pub fn buildSidecar(allocator: std.mem.Allocator, raw_blob: Blob) !BlobSidecar {
    _ = allocator;
    // Lazy import avoids a hard import cycle (kzg.zig imports blob.zig).
    const kzg = @import("kzg.zig");
    const commitment = try kzg.blobToKzgCommitment(&raw_blob);
    const proof = try kzg.computeBlobKzgProof(&raw_blob, commitment);
    return BlobSidecar{
        .blob = raw_blob,
        .commitment = commitment,
        .proof = proof,
    };
}

/// Compute the versioned hash from a KZG commitment.
///
/// The versioned hash is keccak256(commitment) with the first byte
/// replaced by the version byte (0x01 for KZG).
pub fn computeVersionedHash(commitment: KzgCommitment) [32]u8 {
    var h = keccak.hash(&commitment);
    h[0] = VERSIONED_HASH_VERSION_KZG;
    return h;
}

/// Validate that a versioned hash has the correct version byte.
pub fn isValidVersionedHash(h: [32]u8) bool {
    return h[0] == VERSIONED_HASH_VERSION_KZG;
}

/// Verify that a versioned hash matches a given KZG commitment.
pub fn verifyVersionedHash(h: [32]u8, commitment: KzgCommitment) bool {
    const expected = computeVersionedHash(commitment);
    return std.mem.eql(u8, &h, &expected);
}

// ============================================================================
// Tests
// ============================================================================

test "BLOB_SIZE is 128 KiB" {
    try std.testing.expectEqual(@as(usize, 128 * 1024), BLOB_SIZE);
}

test "computeVersionedHash sets version byte" {
    const commitment = @as([48]u8, @splat(0xaa));
    const versioned = computeVersionedHash(commitment);

    // First byte must be 0x01 (KZG version)
    try std.testing.expectEqual(@as(u8, 0x01), versioned[0]);

    // Remaining 31 bytes should match keccak256(commitment)[1..32]
    const full_hash = keccak.hash(&commitment);
    try std.testing.expectEqualSlices(u8, full_hash[1..32], versioned[1..32]);
}

test "computeVersionedHash deterministic" {
    const commitment = @as([48]u8, @splat(0x42));
    const h1 = computeVersionedHash(commitment);
    const h2 = computeVersionedHash(commitment);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computeVersionedHash different commitments produce different hashes" {
    const c1 = @as([48]u8, @splat(0x01));
    const c2 = @as([48]u8, @splat(0x02));
    const h1 = computeVersionedHash(c1);
    const h2 = computeVersionedHash(c2);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "isValidVersionedHash" {
    const commitment = @as([48]u8, @splat(0xbb));
    const valid = computeVersionedHash(commitment);
    try std.testing.expect(isValidVersionedHash(valid));

    // Invalid version byte
    var invalid = valid;
    invalid[0] = 0x00;
    try std.testing.expect(!isValidVersionedHash(invalid));
}

test "verifyVersionedHash" {
    const commitment = @as([48]u8, @splat(0xcc));
    const h = computeVersionedHash(commitment);

    try std.testing.expect(verifyVersionedHash(h, commitment));

    // Wrong commitment
    const wrong_commitment = @as([48]u8, @splat(0xdd));
    try std.testing.expect(!verifyVersionedHash(h, wrong_commitment));
}

test "BlobSidecar struct layout" {
    // Verify the struct can be instantiated (mostly a compile-time check).
    // Use a small stack check - don't actually allocate a full blob on the stack in release.
    const commitment = @as([48]u8, @splat(0x11));
    const proof = @as([48]u8, @splat(0x22));

    _ = BlobSidecar{
        .blob = @as([BLOB_SIZE]u8, @splat(0)),
        .commitment = commitment,
        .proof = proof,
    };
}

test "KzgCommitment and KzgProof are 48 bytes" {
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(KzgCommitment));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(KzgProof));
}
