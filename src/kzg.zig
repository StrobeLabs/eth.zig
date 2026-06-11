//! Real EIP-4844 KZG support, backed by the vendored c-kzg-4844 + blst C code.
//!
//! This module exposes a small Zig API over c-kzg-4844 for building blob
//! transaction sidecars: computing KZG commitments and proofs from raw blob
//! data and verifying them. The mainnet trusted setup (the KZG ceremony
//! output) is embedded via `@embedFile` and loaded once, so consumers need no
//! external setup file.
//!
//! Usage:
//! ```zig
//! try kzg.init(allocator);
//! defer kzg.deinit();
//! const commitment = try kzg.blobToKzgCommitment(&blob);
//! const proof = try kzg.computeBlobKzgProof(&blob, commitment);
//! const ok = try kzg.verifyBlobKzgProof(&blob, commitment, proof);
//! ```
//!
//! `init` is idempotent and guarded by an atomic once-flag, so it is safe to
//! call from multiple threads; only the first call loads the setup. The
//! verification/commitment functions themselves only read the shared setting,
//! matching c-kzg's thread-safety model. Vendored versions and the
//! portable-C blst build rationale are documented in
//! src/crypto/c-kzg/VENDOR.md.

const std = @import("std");
const blob_mod = @import("blob.zig");

const Blob = blob_mod.Blob;
const KzgCommitment = blob_mod.KzgCommitment;
const KzgProof = blob_mod.KzgProof;
const BLOB_SIZE = blob_mod.BLOB_SIZE;

/// The mainnet trusted setup (KZG ceremony output), embedded so consumers need
/// no external file. Vendored from c-kzg-4844 v2.1.1 (see VENDOR.md).
const TRUSTED_SETUP_TXT = @embedFile("crypto/c-kzg/src/trusted_setup.txt");

// ============================================================================
// c-kzg-4844 / C FFI declarations
// ============================================================================

/// Matches c-kzg's `C_KZG_RET` enum (common/ret.h).
const C_KZG_RET = c_uint;
const C_KZG_OK: C_KZG_RET = 0;
const C_KZG_BADARGS: C_KZG_RET = 1;
const C_KZG_ERROR: C_KZG_RET = 2;
const C_KZG_MALLOC: C_KZG_RET = 3;

/// Mirror of c-kzg's `Blob` struct (eip4844/blob.h): a single 128 KiB buffer.
const CBlob = extern struct {
    bytes: [BLOB_SIZE]u8,
};

/// Mirror of c-kzg's `Bytes48` (common/bytes.h). KZGCommitment and KZGProof are
/// both typedefs of Bytes48.
const CBytes48 = extern struct {
    bytes: [48]u8,
};

/// Mirror of c-kzg's `KZGSettings` struct (setup/settings.h). All members are
/// pointers or size_t, so this is a fixed-size, target-portable layout. We only
/// ever pass a pointer to it across the FFI boundary; the C code owns the
/// pointed-to allocations (freed by `free_trusted_setup`).
const KZGSettings = extern struct {
    roots_of_unity: ?*anyopaque,
    brp_roots_of_unity: ?*anyopaque,
    reverse_roots_of_unity: ?*anyopaque,
    g1_values_monomial: ?*anyopaque,
    g1_values_lagrange_brp: ?*anyopaque,
    g2_values_monomial: ?*anyopaque,
    x_ext_fft_columns: ?*anyopaque,
    tables: ?*anyopaque,
    wbits: usize,
    scratch_size: usize,
};

const FILE = opaque {};

extern fn blob_to_kzg_commitment(out: *CBytes48, blob: *const CBlob, s: *const KZGSettings) C_KZG_RET;

extern fn compute_blob_kzg_proof(
    out: *CBytes48,
    blob: *const CBlob,
    commitment_bytes: *const CBytes48,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn verify_blob_kzg_proof(
    ok: *bool,
    blob: *const CBlob,
    commitment_bytes: *const CBytes48,
    proof_bytes: *const CBytes48,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn verify_blob_kzg_proof_batch(
    ok: *bool,
    blobs: [*]const CBlob,
    commitments_bytes: [*]const CBytes48,
    proofs_bytes: [*]const CBytes48,
    n: u64,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn load_trusted_setup_file(out: *KZGSettings, in: *FILE, precompute: u64) C_KZG_RET;
extern fn free_trusted_setup(s: *KZGSettings) void;

// In-memory FILE* over the embedded setup bytes, so we never touch the disk.
extern fn fmemopen(buf: ?*const anyopaque, size: usize, mode: [*:0]const u8) ?*FILE;
extern fn fclose(stream: *FILE) c_int;

// ============================================================================
// Errors
// ============================================================================

/// Errors surfaced from c-kzg's `C_KZG_RET` plus our own lifecycle errors.
pub const KzgError = error{
    /// The supplied data is invalid in some way (c-kzg C_KZG_BADARGS).
    BadArgs,
    /// Internal c-kzg error - should never occur (C_KZG_ERROR).
    Internal,
    /// c-kzg could not allocate memory (C_KZG_MALLOC).
    OutOfMemory,
    /// The trusted setup has not been loaded; call `kzg.init` first.
    NotInitialized,
    /// Loading the embedded trusted setup failed.
    SetupLoadFailed,
};

fn mapRet(ret: C_KZG_RET) KzgError!void {
    return switch (ret) {
        C_KZG_OK => {},
        C_KZG_BADARGS => error.BadArgs,
        C_KZG_MALLOC => error.OutOfMemory,
        else => error.Internal,
    };
}

// ============================================================================
// Trusted-setup lifecycle (process-global, init-once)
// ============================================================================

// States for the once-flag: 0 = uninitialized, 1 = initializing, 2 = ready.
const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;

var init_state: u8 = STATE_UNINIT;
var settings: KZGSettings = undefined;

/// The recommended `precompute` value (0 = no fixed-base MSM tables). 0 keeps
/// init fast and memory modest; sidecar construction does not need the larger
/// precomputed tables. c-kzg accepts any value 0..15.
const PRECOMPUTE: u64 = 0;

/// Load and initialize the embedded trusted setup. Idempotent and thread-safe:
/// only the first caller performs the load; concurrent callers spin until it is
/// ready. Must be called (and succeed) before any commitment/proof/verify call.
///
/// The `allocator` argument is accepted for API symmetry with the rest of the
/// library; the underlying setup allocations are owned and managed by the C
/// code (freed in `deinit`).
pub fn init(allocator: std.mem.Allocator) KzgError!void {
    _ = allocator;

    // Fast path: already ready.
    if (@atomicLoad(u8, &init_state, .acquire) == STATE_READY) return;

    // Try to claim the initialization slot.
    if (@cmpxchgStrong(u8, &init_state, STATE_UNINIT, STATE_INITIALIZING, .acquire, .acquire)) |current| {
        // Lost the race (or already initializing/ready). Spin until ready.
        var seen = current;
        while (seen != STATE_READY) {
            std.atomic.spinLoopHint();
            seen = @atomicLoad(u8, &init_state, .acquire);
        }
        return;
    }

    // We own initialization. On any error, roll the state back to UNINIT so a
    // later caller can retry.
    errdefer @atomicStore(u8, &init_state, STATE_UNINIT, .release);

    const stream = fmemopen(
        TRUSTED_SETUP_TXT.ptr,
        TRUSTED_SETUP_TXT.len,
        "r",
    ) orelse return error.SetupLoadFailed;
    defer _ = fclose(stream);

    try mapRet(load_trusted_setup_file(&settings, stream, PRECOMPUTE));

    @atomicStore(u8, &init_state, STATE_READY, .release);
}

/// Free the trusted setup. After this, `init` may be called again to reload.
/// Not safe to call concurrently with commitment/proof/verify operations.
pub fn deinit() void {
    if (@atomicLoad(u8, &init_state, .acquire) != STATE_READY) return;
    free_trusted_setup(&settings);
    @atomicStore(u8, &init_state, STATE_UNINIT, .release);
}

fn requireReady() KzgError!*const KZGSettings {
    if (@atomicLoad(u8, &init_state, .acquire) != STATE_READY) return error.NotInitialized;
    return &settings;
}

// ============================================================================
// Public KZG API
// ============================================================================

/// Compute the KZG commitment for a blob. Wraps c-kzg `blob_to_kzg_commitment`.
pub fn blobToKzgCommitment(blob: *const [BLOB_SIZE]u8) KzgError!KzgCommitment {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    var out: CBytes48 = undefined;
    try mapRet(blob_to_kzg_commitment(&out, cblob, s));
    return out.bytes;
}

/// Compute the KZG proof for a blob given its commitment. Wraps c-kzg
/// `compute_blob_kzg_proof`.
pub fn computeBlobKzgProof(blob: *const [BLOB_SIZE]u8, commitment: KzgCommitment) KzgError!KzgProof {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    const ccommit = CBytes48{ .bytes = commitment };
    var out: CBytes48 = undefined;
    try mapRet(compute_blob_kzg_proof(&out, cblob, &ccommit, s));
    return out.bytes;
}

/// Verify a blob KZG proof against its commitment. Wraps c-kzg
/// `verify_blob_kzg_proof`. Returns whether the proof is valid; only returns an
/// error for malformed inputs / internal failures.
pub fn verifyBlobKzgProof(
    blob: *const [BLOB_SIZE]u8,
    commitment: KzgCommitment,
    proof: KzgProof,
) KzgError!bool {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    const ccommit = CBytes48{ .bytes = commitment };
    const cproof = CBytes48{ .bytes = proof };
    var ok: bool = false;
    try mapRet(verify_blob_kzg_proof(&ok, cblob, &ccommit, &cproof, s));
    return ok;
}

/// Verify a batch of blob KZG proofs. All slices must have equal length. Wraps
/// c-kzg `verify_blob_kzg_proof_batch`. Returns whether every proof is valid.
pub fn verifyBlobKzgProofBatch(
    blobs: []const Blob,
    commitments: []const KzgCommitment,
    proofs: []const KzgProof,
) KzgError!bool {
    const s = try requireReady();
    if (blobs.len != commitments.len or blobs.len != proofs.len) return error.BadArgs;
    if (blobs.len == 0) return true;

    // Blob, KzgCommitment and KzgProof are fixed-size byte arrays with the same
    // layout as the c-kzg structs, so the slices can be reinterpreted directly.
    const cblobs: [*]const CBlob = @ptrCast(blobs.ptr);
    const ccommits: [*]const CBytes48 = @ptrCast(commitments.ptr);
    const cproofs: [*]const CBytes48 = @ptrCast(proofs.ptr);
    var ok: bool = false;
    try mapRet(verify_blob_kzg_proof_batch(&ok, cblobs, ccommits, cproofs, @intCast(blobs.len), s));
    return ok;
}

/// Derive the EIP-4844 versioned hash from a commitment. Convenience re-export
/// of `blob.computeVersionedHash`.
pub fn commitmentToVersionedHash(commitment: KzgCommitment) [32]u8 {
    return blob_mod.computeVersionedHash(commitment);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

// Byte-for-byte assertions against the official c-kzg-4844 vectors live in
// src/kzg_vectors_test.zig (which embeds the vendored vector YAML files). The
// in-file tests below exercise the lifecycle and a deterministic round trip.

test "kzg init/deinit lifecycle" {
    try init(testing.allocator);
    defer deinit();
    // Idempotent second init is a no-op.
    try init(testing.allocator);
}

test "kzg round trip: commitment -> proof -> verify" {
    try init(testing.allocator);
    defer deinit();

    // Build a valid blob: each 32-byte field element must be a canonical BLS
    // field element (< modulus). Setting the high byte to 0 guarantees this.
    var blob: Blob = @splat(0);
    var i: usize = 0;
    while (i < BLOB_SIZE) : (i += 32) {
        // Put a small varying value in the low bytes; leave the top byte zero.
        blob[i + 31] = @intCast(i / 32 % 251);
        blob[i + 30] = @intCast((i / 32 / 251) % 251);
    }

    const commitment = try blobToKzgCommitment(&blob);
    const proof = try computeBlobKzgProof(&blob, commitment);

    try testing.expect(try verifyBlobKzgProof(&blob, commitment, proof));

    // Tampered proof must not verify.
    var bad_proof = proof;
    bad_proof[0] ^= 0x01;
    // A flipped byte may make the proof an invalid point (error) or simply not
    // verify; either way it must not report success.
    const tampered = verifyBlobKzgProof(&blob, commitment, bad_proof) catch false;
    try testing.expect(!tampered);

    // Tampered commitment: flipping a byte typically yields an invalid G1
    // encoding (BadArgs) or a non-verifying proof.
    var bad_commit = commitment;
    bad_commit[5] ^= 0x01;
    const tampered2 = verifyBlobKzgProof(&blob, bad_commit, proof) catch false;
    try testing.expect(!tampered2);
}

test "kzg versioned hash matches blob.computeVersionedHash" {
    try init(testing.allocator);
    defer deinit();

    var blob: Blob = @splat(0);
    blob[31] = 0x2a;
    const commitment = try blobToKzgCommitment(&blob);

    const vh1 = commitmentToVersionedHash(commitment);
    const vh2 = blob_mod.computeVersionedHash(commitment);
    try testing.expectEqualSlices(u8, &vh1, &vh2);
    try testing.expectEqual(@as(u8, blob_mod.VERSIONED_HASH_VERSION_KZG), vh1[0]);
}

test "kzg verify rejects when not initialized" {
    // Ensure clean state for this test.
    deinit();
    var blob: Blob = @splat(0);
    try testing.expectError(error.NotInitialized, blobToKzgCommitment(&blob));
    // Restore for any subsequent ordering-independent tests.
}

test "kzg batch verify round trip" {
    try init(testing.allocator);
    defer deinit();

    var blob: Blob = @splat(0);
    blob[31] = 0x07;
    const commitment = try blobToKzgCommitment(&blob);
    const proof = try computeBlobKzgProof(&blob, commitment);

    const blobs = [_]Blob{blob};
    const commits = [_]KzgCommitment{commitment};
    const proofs = [_]KzgProof{proof};

    try testing.expect(try verifyBlobKzgProofBatch(&blobs, &commits, &proofs));

    var bad_proofs = proofs;
    bad_proofs[0][0] ^= 0x01;
    const ok = verifyBlobKzgProofBatch(&blobs, &commits, &bad_proofs) catch false;
    try testing.expect(!ok);
}
