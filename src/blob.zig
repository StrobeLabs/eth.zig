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

/// Cell proofs per blob in a version-1 (EIP-7594, Fusaka) sidecar: one per
/// cell of the extended blob. Equals `kzg.CELLS_PER_EXT_BLOB`.
pub const CELL_PROOFS_PER_BLOB: usize = 128;

/// The wrapper version byte a version-1 sidecar carries on the wire
/// (`rlp([tx_payload_body, 1, blobs, commitments, cell_proofs])`).
pub const SIDECAR_VERSION_V1: u8 = 0x01;

/// A pre-Fusaka (version 0) blob sidecar: the blob itself along with its KZG
/// commitment and blob proof.
pub const BlobSidecar = struct {
    blob: Blob,
    commitment: KzgCommitment,
    proof: KzgProof,
};

/// Errors from sidecar shape validation and the network wrapper.
pub const SidecarError = error{
    /// The blobs, commitments and proofs slices disagree in length, a
    /// version-1 sidecar does not carry exactly 128 cell proofs per blob, or
    /// there are no blobs at all (a type-3 transaction needs at least one).
    SidecarShapeMismatch,
};

/// A Fusaka (EIP-7594) blob sidecar, network wrapper version 1: the blobs,
/// their KZG commitments and `CELL_PROOFS_PER_BLOB` cell proofs per blob.
///
/// `cell_proofs` is blob-major: the proofs of blob `i` are
/// `cell_proofs[i * 128 ..][0..128]`, proof `j` attesting cell `j` of the
/// extended blob. Built by `buildSidecarV1` (which owns `commitments` and
/// `cell_proofs`; free them with `deinit`) or assembled from slices you own.
pub const BlobSidecarV1 = struct {
    blobs: []const Blob,
    commitments: []const KzgCommitment,
    cell_proofs: []const KzgProof,

    /// The 128 cell proofs of blob `blob_index`.
    pub fn cellProofsOf(self: BlobSidecarV1, blob_index: usize) []const KzgProof {
        return self.cell_proofs[blob_index * CELL_PROOFS_PER_BLOB ..][0..CELL_PROOFS_PER_BLOB];
    }

    /// Check that the slices describe a well-formed sidecar: at least one
    /// blob, one commitment per blob, 128 cell proofs per blob.
    pub fn validateShape(self: BlobSidecarV1) SidecarError!void {
        if (self.blobs.len == 0) return error.SidecarShapeMismatch;
        if (self.commitments.len != self.blobs.len) return error.SidecarShapeMismatch;
        if (self.cell_proofs.len != self.blobs.len * CELL_PROOFS_PER_BLOB) return error.SidecarShapeMismatch;
    }

    /// Verify every cell proof against its commitment: recompute the cells
    /// of each blob and run one `kzg.verifyCellKzgProofBatch` over all of
    /// them, the check a node performs before accepting the transaction.
    /// Returns `false` for a proof or commitment that does not match the
    /// blob; malformed inputs surface as `KzgError`. The caller must have
    /// initialized `kzg`. Scratch memory (256 KiB of cells per blob plus the
    /// commitment/index arrays) comes from `allocator`.
    pub fn verify(self: BlobSidecarV1, allocator: std.mem.Allocator) !bool {
        const kzg = @import("kzg.zig");
        try self.validateShape();
        const n = self.blobs.len * CELL_PROOFS_PER_BLOB;
        const cells = try allocator.alloc(kzg.Cell, n);
        defer allocator.free(cells);
        const commitments = try allocator.alloc(KzgCommitment, n);
        defer allocator.free(commitments);
        const indices = try allocator.alloc(u64, n);
        defer allocator.free(indices);
        for (self.blobs, 0..) |*blob, i| {
            const base = i * CELL_PROOFS_PER_BLOB;
            try kzg.computeCells(blob, cells[base..][0..CELL_PROOFS_PER_BLOB]);
            for (0..CELL_PROOFS_PER_BLOB) |j| {
                commitments[base + j] = self.commitments[i];
                indices[base + j] = @intCast(j);
            }
        }
        return kzg.verifyCellKzgProofBatch(commitments, indices, cells, self.cell_proofs);
    }

    /// Free the `commitments` and `cell_proofs` slices of a sidecar produced
    /// by `buildSidecarV1`. The blobs are borrowed and untouched.
    pub fn deinit(self: *BlobSidecarV1, allocator: std.mem.Allocator) void {
        allocator.free(self.commitments);
        allocator.free(self.cell_proofs);
        self.* = undefined;
    }
};

/// The sidecar that accompanies a signed type-3 transaction on the wire, in
/// either wrapper version. See `transaction.wrapBlobTransaction`.
pub const NetworkSidecar = union(enum) {
    /// Pre-Fusaka: `rlp([tx_payload_body, blobs, commitments, proofs])` with
    /// one blob proof per blob.
    v0: struct {
        blobs: []const Blob,
        commitments: []const KzgCommitment,
        proofs: []const KzgProof,
    },
    /// Fusaka (EIP-7594): `rlp([tx_payload_body, 1, blobs, commitments,
    /// cell_proofs])` with 128 cell proofs per blob.
    v1: BlobSidecarV1,

    /// The blobs of either version.
    pub fn blobs(self: NetworkSidecar) []const Blob {
        return switch (self) {
            .v0 => |v| v.blobs,
            .v1 => |v| v.blobs,
        };
    }

    /// The commitments of either version.
    pub fn commitments(self: NetworkSidecar) []const KzgCommitment {
        return switch (self) {
            .v0 => |v| v.commitments,
            .v1 => |v| v.commitments,
        };
    }

    /// The proofs of either version (one per blob for v0, 128 per blob for v1).
    pub fn proofs(self: NetworkSidecar) []const KzgProof {
        return switch (self) {
            .v0 => |v| v.proofs,
            .v1 => |v| v.cell_proofs,
        };
    }

    /// Check slice lengths for the version: at least one blob, one
    /// commitment per blob, one (v0) or 128 (v1) proofs per blob.
    pub fn validateShape(self: NetworkSidecar) SidecarError!void {
        switch (self) {
            .v0 => |v| {
                if (v.blobs.len == 0) return error.SidecarShapeMismatch;
                if (v.commitments.len != v.blobs.len or v.proofs.len != v.blobs.len) return error.SidecarShapeMismatch;
            },
            .v1 => |v| try v.validateShape(),
        }
    }

    /// Verify the proofs against the blobs and commitments: the blob-proof
    /// batch check for v0, the cell-proof batch check for v1. The caller
    /// must have initialized `kzg`.
    pub fn verify(self: NetworkSidecar, allocator: std.mem.Allocator) !bool {
        const kzg = @import("kzg.zig");
        try self.validateShape();
        return switch (self) {
            .v0 => |v| kzg.verifyBlobKzgProofBatch(v.blobs, v.commitments, v.proofs),
            .v1 => |v| v.verify(allocator),
        };
    }
};

/// Build a version-1 (Fusaka) sidecar from raw blobs: computes each blob's
/// commitment and its 128 cell proofs via the vendored c-kzg-4844 backend.
/// The returned sidecar borrows `blobs` and owns the `commitments` and
/// `cell_proofs` slices (allocated from `allocator`; release them with
/// `BlobSidecarV1.deinit`). The caller must have initialized `kzg`. A blob
/// containing a non-canonical field element fails with `error.BadArgs`; at
/// least one blob is required.
pub fn buildSidecarV1(allocator: std.mem.Allocator, blobs: []const Blob) !BlobSidecarV1 {
    const kzg = @import("kzg.zig");
    if (blobs.len == 0) return error.SidecarShapeMismatch;
    const commitments = try allocator.alloc(KzgCommitment, blobs.len);
    errdefer allocator.free(commitments);
    const cell_proofs = try allocator.alloc(KzgProof, blobs.len * CELL_PROOFS_PER_BLOB);
    errdefer allocator.free(cell_proofs);
    // Cells are recomputed per blob into one scratch buffer; only the proofs
    // are kept, which is what the sidecar carries.
    const cells = try allocator.create([CELL_PROOFS_PER_BLOB]kzg.Cell);
    defer allocator.destroy(cells);
    for (blobs, 0..) |*blob, i| {
        commitments[i] = try kzg.blobToKzgCommitment(blob);
        try kzg.computeCellsAndKzgProofs(blob, cells, cell_proofs[i * CELL_PROOFS_PER_BLOB ..][0..CELL_PROOFS_PER_BLOB]);
    }
    return .{ .blobs = blobs, .commitments = commitments, .cell_proofs = cell_proofs };
}

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

/// Compute the EIP-4844 versioned hash from a KZG commitment.
///
/// Per EIP-4844 this is `sha256(commitment)` with the first byte replaced by
/// the version byte (0x01 for KZG) -- sha256, not keccak256, because the
/// execution layer recomputes it that way when it checks a type-3
/// transaction's `blob_versioned_hashes` against the sidecar commitments
/// (and the point-evaluation precompile does the same).
pub fn computeVersionedHash(commitment: KzgCommitment) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &h, .{});
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

test "computeVersionedHash sets version byte over sha256" {
    const commitment = @as([48]u8, @splat(0xaa));
    const versioned = computeVersionedHash(commitment);

    // First byte must be 0x01 (KZG version)
    try std.testing.expectEqual(@as(u8, 0x01), versioned[0]);

    // Remaining 31 bytes are sha256(commitment)[1..32], as EIP-4844 defines
    // the versioned hash. keccak256 would be a consensus mismatch: the
    // execution layer rejects a blob transaction whose versioned hashes do
    // not equal sha256 of the sidecar commitments.
    var full_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&commitment, &full_hash, .{});
    try std.testing.expectEqualSlices(u8, full_hash[1..32], versioned[1..32]);
    try std.testing.expect(!std.mem.eql(u8, keccak.hash(&commitment)[1..32], versioned[1..32]));
}

test "computeVersionedHash matches the EIP-4844 reference value" {
    // sha256 of a 48-byte all-zero commitment, version byte applied. The
    // digest is the well-known sha256 of 48 zero bytes.
    const expected = [32]u8{
        0x01, 0xb0, 0x76, 0x1f, 0x87, 0xb0, 0x81, 0xd5, 0xcf, 0x10, 0x75, 0x7c, 0xcc, 0x89, 0xf1, 0x2b,
        0xe3, 0x55, 0xc7, 0x0e, 0x2e, 0x29, 0xdf, 0x28, 0x8b, 0x65, 0xb3, 0x07, 0x10, 0xdc, 0xbc, 0xd1,
    };
    const got = computeVersionedHash(@splat(0));
    try std.testing.expectEqualSlices(u8, &expected, &got);
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

test "CELL_PROOFS_PER_BLOB matches the KZG cell count" {
    const kzg = @import("kzg.zig");
    try std.testing.expectEqual(kzg.CELLS_PER_EXT_BLOB, CELL_PROOFS_PER_BLOB);
}

test "BlobSidecarV1 shape validation" {
    const blobs = [_]Blob{@splat(0)};
    const commitments = [_]KzgCommitment{@splat(0)};
    const cell_proofs: [CELL_PROOFS_PER_BLOB]KzgProof = @splat(@splat(0));
    const ok = BlobSidecarV1{ .blobs = &blobs, .commitments = &commitments, .cell_proofs = &cell_proofs };
    try ok.validateShape();
    try std.testing.expectEqual(@as(usize, CELL_PROOFS_PER_BLOB), ok.cellProofsOf(0).len);

    const no_blobs = BlobSidecarV1{ .blobs = &.{}, .commitments = &.{}, .cell_proofs = &.{} };
    try std.testing.expectError(error.SidecarShapeMismatch, no_blobs.validateShape());
    const short = BlobSidecarV1{ .blobs = &blobs, .commitments = &commitments, .cell_proofs = cell_proofs[0..127] };
    try std.testing.expectError(error.SidecarShapeMismatch, short.validateShape());
    const no_commitment = BlobSidecarV1{ .blobs = &blobs, .commitments = &.{}, .cell_proofs = &cell_proofs };
    try std.testing.expectError(error.SidecarShapeMismatch, no_commitment.validateShape());

    const v0_bad = NetworkSidecar{ .v0 = .{ .blobs = &blobs, .commitments = &commitments, .proofs = &.{} } };
    try std.testing.expectError(error.SidecarShapeMismatch, v0_bad.validateShape());
    try std.testing.expectError(error.SidecarShapeMismatch, buildSidecarV1(std.testing.allocator, &.{}));
}

test "buildSidecarV1 produces a verifiable sidecar and rejects tampering" {
    const kzg = @import("kzg.zig");
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blobs = try allocator.alloc(Blob, 2);
    defer allocator.free(blobs);
    for (blobs, 0..) |*b, i| {
        @memset(b, 0);
        b[31] = @intCast(i + 1);
        b[BLOB_SIZE - 1] = 0x5a;
    }

    var sidecar = try buildSidecarV1(allocator, blobs);
    defer sidecar.deinit(allocator);
    try sidecar.validateShape();
    try std.testing.expectEqual(@as(usize, 2 * CELL_PROOFS_PER_BLOB), sidecar.cell_proofs.len);
    try std.testing.expectEqualSlices(u8, &try kzg.blobToKzgCommitment(&blobs[1]), &sidecar.commitments[1]);
    try std.testing.expect(try sidecar.verify(allocator));
    try std.testing.expect(try (NetworkSidecar{ .v1 = sidecar }).verify(allocator));

    // Swapping the two blobs' proofs must fail verification (not error).
    const swapped = try allocator.dupe(KzgProof, sidecar.cell_proofs);
    defer allocator.free(swapped);
    @memcpy(swapped[0..CELL_PROOFS_PER_BLOB], sidecar.cellProofsOf(1));
    @memcpy(swapped[CELL_PROOFS_PER_BLOB..], sidecar.cellProofsOf(0));
    const tampered = BlobSidecarV1{ .blobs = blobs, .commitments = sidecar.commitments, .cell_proofs = swapped };
    try std.testing.expect(!try tampered.verify(allocator));

    // The v0 path verifies blob proofs the same way.
    const proofs = [_]KzgProof{
        try kzg.computeBlobKzgProof(&blobs[0], sidecar.commitments[0]),
        try kzg.computeBlobKzgProof(&blobs[1], sidecar.commitments[1]),
    };
    const v0 = NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = sidecar.commitments, .proofs = &proofs } };
    try std.testing.expect(try v0.verify(allocator));
    const v0_swapped = [_]KzgProof{ proofs[1], proofs[0] };
    const v0_bad = NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = sidecar.commitments, .proofs = &v0_swapped } };
    try std.testing.expect(!try v0_bad.verify(allocator));
}
