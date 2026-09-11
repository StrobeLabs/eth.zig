//! Real EIP-4844 KZG support, backed by the vendored c-kzg-4844 + blst C code.
//!
//! This module exposes a Zig API over c-kzg-4844: the EIP-4844 blob
//! commitment/proof functions used to build blob-transaction sidecars, the
//! point-evaluation pair (`computeKzgProof`/`verifyKzgProof`) behind the
//! EIP-4844 precompile, and the EIP-7594 (PeerDAS) cell functions that
//! produce and verify the per-cell proofs carried by Fusaka blob sidecars.
//! The mainnet trusted setup (the KZG ceremony output) is embedded via
//! `@embedFile` and loaded once, so consumers need no external setup file.
//!
//! Usage:
//! ```zig
//! try kzg.init(allocator);
//! defer kzg.deinit();
//! const commitment = try kzg.blobToKzgCommitment(&blob);
//! const proof = try kzg.computeBlobKzgProof(&blob, commitment);
//! const ok = try kzg.verifyBlobKzgProof(&blob, commitment, proof);
//!
//! // EIP-7594 cells (Fusaka): 128 cells and 128 proofs per blob.
//! var cells: [kzg.CELLS_PER_EXT_BLOB]kzg.Cell = undefined;
//! var cell_proofs: [kzg.CELLS_PER_EXT_BLOB]kzg.KzgProof = undefined;
//! try kzg.computeCellsAndKzgProofs(&blob, &cells, &cell_proofs);
//! ```
//!
//! `init` is idempotent and guarded by an atomic state machine, so it is safe
//! to call from multiple threads; only one call loads the setup and the others
//! wait for it. If that load fails, the waiting callers observe the failure
//! and retry the load themselves rather than spinning forever. The
//! verification/commitment functions themselves only read the shared setting,
//! matching c-kzg's thread-safety model. Vendored versions and the blst build
//! mode (assembly on x86_64/aarch64, portable C elsewhere) are documented in
//! src/crypto/c-kzg/VENDOR.md.

const std = @import("std");
const builtin = @import("builtin");
const blob_mod = @import("blob.zig");

pub const Blob = blob_mod.Blob;
pub const KzgCommitment = blob_mod.KzgCommitment;
pub const KzgProof = blob_mod.KzgProof;
const BLOB_SIZE = blob_mod.BLOB_SIZE;

/// Size of one field element (a BLS12-381 scalar) in bytes.
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
/// Field elements in a blob (4096 x 32 bytes = 128 KiB).
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
/// Field elements in an extended blob: the blob's polynomial evaluated over
/// twice as many points (Reed-Solomon rate 1/2), which is what cells cover.
pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;
/// Field elements in one cell.
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;
/// Size of one cell in bytes (64 x 32).
pub const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
/// Cells per extended blob (128). A Fusaka blob sidecar carries this many
/// cell proofs per blob, and any 64 of the 128 cells recover the blob.
pub const CELLS_PER_EXT_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
/// Largest `precompute` value c-kzg accepts (blst's window-size limit).
pub const MAX_PRECOMPUTE: u64 = 15;

/// One EIP-7594 cell: 64 consecutive field elements of the extended blob.
pub const Cell = [BYTES_PER_CELL]u8;
/// A 32-byte field element (evaluation point `z` or claimed value `y`).
pub const Bytes32 = [BYTES_PER_FIELD_ELEMENT]u8;
/// Result of `computeKzgProof`: the opening proof and the polynomial's value
/// at the requested point.
pub const ProofAndEvaluation = struct {
    proof: KzgProof,
    y: Bytes32,
};

/// The mainnet trusted setup (KZG ceremony output), embedded so consumers need
/// no external file. Vendored from c-kzg-4844 v2.1.8 (see VENDOR.md).
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

/// Mirror of c-kzg's `Bytes32` (common/bytes.h).
const CBytes32 = extern struct {
    bytes: [32]u8,
};

/// Mirror of c-kzg's `Cell` (eip7594/cell.h): 2048 bytes.
const CCell = extern struct {
    bytes: [BYTES_PER_CELL]u8,
};

/// c-kzg's `KZGSettings` (setup/settings.h), deliberately opaque. Its layout is
/// never mirrored here: `init` sizes the backing storage at run time from the
/// `ethzig_kzg_settings_size`/`_align` shim (src/crypto/c-kzg/ckzg_shim.c),
/// which is compiled against the vendored header, so an upstream field
/// addition can never silently corrupt memory. Only pointers to it cross the
/// FFI boundary; the C code owns the pointed-to allocations (freed by
/// `free_trusted_setup`).
const KZGSettings = opaque {};

extern fn ethzig_kzg_settings_size() usize;
extern fn ethzig_kzg_settings_align() usize;

// The vendored C's own view of the sizes that determine how large the buffers
// handed to it must be. Asserted against the Zig constants above in a test, so
// a vendored-header change cannot silently make a caller-provided array too
// small for what the C writes into it.
extern fn ethzig_kzg_cells_per_ext_blob() usize;
extern fn ethzig_kzg_bytes_per_cell() usize;
extern fn ethzig_kzg_field_elements_per_cell() usize;
extern fn ethzig_kzg_field_elements_per_blob() usize;
extern fn ethzig_kzg_bytes_per_blob() usize;
extern fn ethzig_kzg_bytes_per_commitment() usize;
extern fn ethzig_kzg_bytes_per_proof() usize;
extern fn ethzig_kzg_bytes_per_field_element() usize;

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

extern fn compute_kzg_proof(
    proof_out: *CBytes48,
    y_out: *CBytes32,
    blob: *const CBlob,
    z_bytes: *const CBytes32,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn verify_kzg_proof(
    ok: *bool,
    commitment_bytes: *const CBytes48,
    z_bytes: *const CBytes32,
    y_bytes: *const CBytes32,
    proof_bytes: *const CBytes48,
    s: *const KZGSettings,
) C_KZG_RET;

// EIP-7594. `cells`/`proofs` outputs may be NULL to skip that output.
extern fn compute_cells_and_kzg_proofs(
    cells: ?[*]CCell,
    proofs: ?[*]CBytes48,
    blob: *const CBlob,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn recover_cells_and_kzg_proofs(
    recovered_cells: [*]CCell,
    recovered_proofs: ?[*]CBytes48,
    cell_indices: [*]const u64,
    cells: [*]const CCell,
    num_cells: u64,
    s: *const KZGSettings,
) C_KZG_RET;

extern fn verify_cell_kzg_proof_batch(
    ok: *bool,
    commitments_bytes: [*]const CBytes48,
    cell_indices: [*]const u64,
    cells: [*]const CCell,
    proofs_bytes: [*]const CBytes48,
    num_cells: u64,
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

// States for the init state machine. Transitions:
//   UNINIT -> INITIALIZING (the caller that wins the cmpxchg loads the setup)
//   INITIALIZING -> READY (load succeeded) | UNINIT (load failed)
//   READY -> DEINITIALIZING -> UNINIT (deinit)
// Callers that observe INITIALIZING or DEINITIALIZING wait and re-observe, so
// a failed load never strands them: they see UNINIT and race to retry.
const STATE_UNINIT: u8 = 0;
const STATE_INITIALIZING: u8 = 1;
const STATE_READY: u8 = 2;
const STATE_DEINITIALIZING: u8 = 3;

var init_state: u8 = STATE_UNINIT;

/// Alignment of the opaque `KZGSettings` storage. Generous for a struct of
/// pointers and `size_t`s; `init` checks the C shim's `alignof` against it.
const SETTINGS_ALIGN: std.mem.Alignment = .@"16";

/// Opaque storage for the C `KZGSettings`, allocated by `init` with exactly
/// `ethzig_kzg_settings_size()` bytes and released by `deinit`. Only valid
/// while `init_state == STATE_READY`; published by the release store of that
/// state and read after the matching acquire load.
var settings_storage: []align(SETTINGS_ALIGN.toByteUnits()) u8 = &.{};
var settings_allocator: std.mem.Allocator = undefined;

/// Options for `initWithOptions`.
pub const InitOptions = struct {
    /// Window size of the fixed-base multi-scalar-multiplication tables c-kzg
    /// builds for the FK20 cell-proof prover (0..15; 0 disables them and uses
    /// Pippenger's algorithm). It only affects `computeCellsAndKzgProofs` and
    /// `recoverCellsAndKzgProofs`; commitments, blob proofs and every verify
    /// function are unaffected. The default of 0 keeps init fast and adds no
    /// memory, which is right for occasional sidecar construction. Upstream
    /// recommends 8 or 9 for applications that compute cell proofs often:
    /// on an Apple M1 they cut compute_cells_and_kzg_proofs from ~311 ms to
    /// ~181 ms / ~170 ms at the cost of ~96 MiB / ~192 MiB of tables and
    /// ~0.6 s / ~1.1 s of extra load time (each further step doubles the
    /// memory). Values above `MAX_PRECOMPUTE` are rejected with `BadArgs`.
    precompute: u64 = 0,
};

/// Test-only failure injection: when set, the caller that owns initialization
/// invokes it right after claiming the INITIALIZING state and before loading
/// the setup; an error it returns is reported exactly like a failed load.
/// Never referenced outside test builds.
var test_init_hook: ?*const fn () KzgError!void = null;

/// Load and initialize the embedded trusted setup. Idempotent and thread-safe:
/// one caller performs the load while concurrent callers wait for it; if the
/// load fails, its caller receives the error and the waiters retry the load
/// (each receiving its own error if it keeps failing). Must be called (and
/// succeed) before any commitment/proof/verify call.
///
/// The `allocator` backs the opaque `KZGSettings` storage (a few dozen bytes;
/// the setup tables themselves are allocated by the C code) and must outlive
/// the matching `deinit`, which frees through it. When several threads race,
/// the allocator of the thread whose load succeeds is the one kept.
pub fn init(allocator: std.mem.Allocator) KzgError!void {
    return initWithOptions(allocator, .{});
}

/// `init` with explicit options (see `InitOptions`). The options of the call
/// that performs the load are the ones in effect; once the setup is loaded,
/// further calls with different options are no-ops until `deinit`.
pub fn initWithOptions(allocator: std.mem.Allocator, options: InitOptions) KzgError!void {
    if (options.precompute > MAX_PRECOMPUTE) return error.BadArgs;
    while (true) {
        switch (@atomicLoad(u8, &init_state, .acquire)) {
            STATE_READY => return,
            STATE_INITIALIZING, STATE_DEINITIALIZING => {
                // Another caller is loading or tearing down; wait for it to
                // reach a terminal state, then re-observe.
                std.atomic.spinLoopHint();
                std.Thread.yield() catch {};
                continue;
            },
            else => {},
        }

        // Observed UNINIT: try to claim the load. Losing the race just means
        // the state changed under us, so re-observe.
        if (@cmpxchgWeak(u8, &init_state, STATE_UNINIT, STATE_INITIALIZING, .acquire, .acquire) != null) continue;

        // We own initialization. On any error, roll the state back to UNINIT
        // so a waiter (or a later caller) can retry.
        loadSetup(allocator, options) catch |err| {
            @atomicStore(u8, &init_state, STATE_UNINIT, .release);
            return err;
        };
        @atomicStore(u8, &init_state, STATE_READY, .release);
        return;
    }
}

/// Body of a claimed initialization: allocate the opaque settings storage and
/// load the embedded setup into it. Leaves no allocation behind on error.
fn loadSetup(allocator: std.mem.Allocator, options: InitOptions) KzgError!void {
    if (builtin.is_test) {
        if (test_init_hook) |hook| try hook();
    }

    const size = ethzig_kzg_settings_size();
    if (size == 0 or ethzig_kzg_settings_align() > SETTINGS_ALIGN.toByteUnits()) return error.SetupLoadFailed;
    const storage = allocator.alignedAlloc(u8, SETTINGS_ALIGN, size) catch return error.OutOfMemory;
    errdefer allocator.free(storage);
    @memset(storage, 0);

    const stream = fmemopen(
        TRUSTED_SETUP_TXT.ptr,
        TRUSTED_SETUP_TXT.len,
        "r",
    ) orelse return error.SetupLoadFailed;
    defer _ = fclose(stream);

    try mapRet(load_trusted_setup_file(@ptrCast(storage.ptr), stream, options.precompute));

    settings_storage = storage;
    settings_allocator = allocator;
}

/// Free the trusted setup. After this, `init` may be called again to reload.
/// Not safe to call concurrently with commitment/proof/verify operations;
/// concurrent `init`/`deinit` calls are serialized by the state machine.
pub fn deinit() void {
    // Only the caller that flips READY -> DEINITIALIZING frees the setup, so
    // concurrent `deinit` calls cannot double-free, and an `init` racing with
    // the teardown waits until the storage has been released.
    if (@cmpxchgStrong(u8, &init_state, STATE_READY, STATE_DEINITIALIZING, .acq_rel, .acquire) != null) return;
    free_trusted_setup(@ptrCast(settings_storage.ptr));
    settings_allocator.free(settings_storage);
    settings_storage = &.{};
    @atomicStore(u8, &init_state, STATE_UNINIT, .release);
}

fn requireReady() KzgError!*const KZGSettings {
    if (@atomicLoad(u8, &init_state, .acquire) != STATE_READY) return error.NotInitialized;
    return @ptrCast(settings_storage.ptr);
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

/// Compute the KZG opening proof of a blob's polynomial at the point `z` and
/// return it together with the evaluation `y = p(z)`. This is the prover side
/// of the EIP-4844 point-evaluation precompile. `z` must be a canonical field
/// element (big-endian, below the BLS12-381 scalar modulus) or `BadArgs` is
/// returned. Wraps c-kzg `compute_kzg_proof`.
pub fn computeKzgProof(blob: *const Blob, z: Bytes32) KzgError!ProofAndEvaluation {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    const cz = CBytes32{ .bytes = z };
    var proof: CBytes48 = undefined;
    var y: CBytes32 = undefined;
    try mapRet(compute_kzg_proof(&proof, &y, cblob, &cz, s));
    return .{ .proof = proof.bytes, .y = y.bytes };
}

/// Verify a KZG opening proof: that the polynomial committed to by
/// `commitment` evaluates to `y` at `z`. This is the check performed by the
/// EIP-4844 point-evaluation precompile. Returns whether the proof is valid;
/// malformed points or non-canonical `z`/`y` return `BadArgs`. Wraps c-kzg
/// `verify_kzg_proof`.
pub fn verifyKzgProof(commitment: KzgCommitment, z: Bytes32, y: Bytes32, proof: KzgProof) KzgError!bool {
    const s = try requireReady();
    const ccommit = CBytes48{ .bytes = commitment };
    const cz = CBytes32{ .bytes = z };
    const cy = CBytes32{ .bytes = y };
    const cproof = CBytes48{ .bytes = proof };
    var ok: bool = false;
    try mapRet(verify_kzg_proof(&ok, &ccommit, &cz, &cy, &cproof, s));
    return ok;
}

/// Compute the 128 EIP-7594 cells of a blob (the extended blob split into
/// 64-element cells) without proofs. Cheaper than `computeCellsAndKzgProofs`
/// when only the data is needed. The blob must consist of canonical field
/// elements or `BadArgs` is returned. Wraps c-kzg
/// `compute_cells_and_kzg_proofs` with the proofs output disabled.
pub fn computeCells(blob: *const Blob, cells_out: *[CELLS_PER_EXT_BLOB]Cell) KzgError!void {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    const ccells: [*]CCell = @ptrCast(cells_out);
    try mapRet(compute_cells_and_kzg_proofs(ccells, null, cblob, s));
}

/// Compute the 128 EIP-7594 cells of a blob and the KZG proof of each cell.
/// These are the `cell_proofs` a Fusaka (version 1) blob sidecar carries per
/// blob. Cost is dominated by the FK20 prover; see `InitOptions.precompute`
/// to trade memory for speed when calling this often. Wraps c-kzg
/// `compute_cells_and_kzg_proofs`.
pub fn computeCellsAndKzgProofs(
    blob: *const Blob,
    cells_out: *[CELLS_PER_EXT_BLOB]Cell,
    proofs_out: *[CELLS_PER_EXT_BLOB]KzgProof,
) KzgError!void {
    const s = try requireReady();
    const cblob: *const CBlob = @ptrCast(blob);
    const ccells: [*]CCell = @ptrCast(cells_out);
    const cproofs: [*]CBytes48 = @ptrCast(proofs_out);
    try mapRet(compute_cells_and_kzg_proofs(ccells, cproofs, cblob, s));
}

/// Recover all 128 cells (and, when `proofs_out` is given, their proofs) of
/// an extended blob from any subset of at least 64 of its cells. `cells[i]`
/// is the cell at extended-blob position `cell_indices[i]`. Per the Fulu
/// spec (c-kzg #594) the indices must be strictly increasing: unsorted or
/// duplicated indices, indices at or above `CELLS_PER_EXT_BLOB`, fewer than
/// 64 cells, more than 128 cells, mismatched slice lengths and non-canonical
/// cell contents all return `BadArgs`. Wraps c-kzg
/// `recover_cells_and_kzg_proofs`.
pub fn recoverCellsAndKzgProofs(
    cell_indices: []const u64,
    cells: []const Cell,
    cells_out: *[CELLS_PER_EXT_BLOB]Cell,
    proofs_out: ?*[CELLS_PER_EXT_BLOB]KzgProof,
) KzgError!void {
    const s = try requireReady();
    if (cell_indices.len != cells.len) return error.BadArgs;
    if (cells.len == 0 or cells.len > CELLS_PER_EXT_BLOB) return error.BadArgs;
    const cout: [*]CCell = @ptrCast(cells_out);
    const pout: ?[*]CBytes48 = if (proofs_out) |p| @ptrCast(p) else null;
    const ccells: [*]const CCell = @ptrCast(cells.ptr);
    try mapRet(recover_cells_and_kzg_proofs(cout, pout, cell_indices.ptr, ccells, @intCast(cells.len), s));
}

/// Verify a batch of EIP-7594 cell proofs: for each `i`, that `cells[i]` is
/// the cell at position `cell_indices[i]` of the blob committed to by
/// `commitments[i]`, as attested by `proofs[i]`. Cells from different blobs
/// may be mixed, the same cell may appear more than once, and indices need
/// not be sorted. All four slices must have equal length or `BadArgs` is
/// returned; an empty batch verifies. Malformed points, non-canonical cells
/// and indices at or above `CELLS_PER_EXT_BLOB` return `BadArgs`; a proof
/// that simply does not check out returns `false`. This is the check a
/// sender runs on a Fusaka sidecar before broadcasting it (and the check
/// consensus clients run on data-column sidecars). Wraps c-kzg
/// `verify_cell_kzg_proof_batch`.
pub fn verifyCellKzgProofBatch(
    commitments: []const KzgCommitment,
    cell_indices: []const u64,
    cells: []const Cell,
    proofs: []const KzgProof,
) KzgError!bool {
    const s = try requireReady();
    if (commitments.len != cell_indices.len or commitments.len != cells.len or commitments.len != proofs.len) {
        return error.BadArgs;
    }
    if (cells.len == 0) return true;
    const ccommits: [*]const CBytes48 = @ptrCast(commitments.ptr);
    const ccells: [*]const CCell = @ptrCast(cells.ptr);
    const cproofs: [*]const CBytes48 = @ptrCast(proofs.ptr);
    var ok: bool = false;
    try mapRet(verify_cell_kzg_proof_batch(&ok, ccommits, cell_indices.ptr, ccells, cproofs, @intCast(cells.len), s));
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

test "kzg constants match the vendored C headers" {
    // Every one of these sizes a buffer the C code writes into, or the length
    // of a byte array crossing the FFI boundary. They are hand-written in Zig
    // (Zig cannot read C macros without @cImport), so the shim reports the C
    // side's values and they are compared here rather than trusted.
    try testing.expectEqual(CELLS_PER_EXT_BLOB, ethzig_kzg_cells_per_ext_blob());
    try testing.expectEqual(BYTES_PER_CELL, ethzig_kzg_bytes_per_cell());
    try testing.expectEqual(FIELD_ELEMENTS_PER_CELL, ethzig_kzg_field_elements_per_cell());
    try testing.expectEqual(FIELD_ELEMENTS_PER_BLOB, ethzig_kzg_field_elements_per_blob());
    try testing.expectEqual(BLOB_SIZE, ethzig_kzg_bytes_per_blob());
    try testing.expectEqual(BYTES_PER_FIELD_ELEMENT, ethzig_kzg_bytes_per_field_element());
    try testing.expectEqual(@sizeOf(KzgCommitment), ethzig_kzg_bytes_per_commitment());
    try testing.expectEqual(@sizeOf(KzgProof), ethzig_kzg_bytes_per_proof());
    // The Zig types must be exactly the size the C writes.
    try testing.expectEqual(BYTES_PER_CELL, @sizeOf(Cell));
    try testing.expectEqual(BYTES_PER_CELL, FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT);
    try testing.expectEqual(FIELD_ELEMENTS_PER_EXT_BLOB, CELLS_PER_EXT_BLOB * FIELD_ELEMENTS_PER_CELL);
}

test "kzg settings storage is sized by the C shim" {
    // The layout is opaque on the Zig side; only sanity-check what the shim
    // reports. v2.1.8's KZGSettings holds ten pointer/size_t members, so any
    // future upstream layout can only grow from there.
    const size = ethzig_kzg_settings_size();
    const alignment = ethzig_kzg_settings_align();
    try testing.expect(size >= 10 * @sizeOf(usize));
    try testing.expect(alignment >= 1 and alignment <= SETTINGS_ALIGN.toByteUnits());
    try testing.expectEqual(@as(usize, 0), size % alignment);
}

fn failingInitHook() KzgError!void {
    return error.SetupLoadFailed;
}

test "kzg init reports a failed load and can be retried" {
    deinit();
    test_init_hook = failingInitHook;
    defer test_init_hook = null;

    try testing.expectError(error.SetupLoadFailed, init(testing.allocator));
    // The failed attempt must leave the module uninitialized, not stuck in
    // INITIALIZING, and must not leak its storage (checked by the testing
    // allocator at the end of the test).
    try testing.expectEqual(STATE_UNINIT, @atomicLoad(u8, &init_state, .acquire));
    var blob: Blob = @splat(0);
    try testing.expectError(error.NotInitialized, blobToKzgCommitment(&blob));

    // Once the failure cause is gone, the same caller can retry successfully.
    test_init_hook = null;
    try init(testing.allocator);
    defer deinit();
    _ = try blobToKzgCommitment(&blob);
}

/// Shared state for the concurrent-init test.
const ConcurrentInit = struct {
    const num_threads = 8;

    /// Threads that have called (or are about to call) `init`.
    var entered = std.atomic.Value(u32).init(0);
    /// Number of times the hook has run, i.e. of claimed init attempts.
    var attempts = std.atomic.Value(u32).init(0);
    var results: [num_threads]KzgError!void = undefined;

    /// Fails exactly the first claimed attempt, but only once every thread
    /// has entered `init`, so the other threads are guaranteed to be waiting
    /// on the INITIALIZING state when the failure is published. Without the
    /// retry-on-UNINIT logic those waiters would spin forever.
    fn hook() KzgError!void {
        if (attempts.fetchAdd(1, .acq_rel) != 0) return;
        while (entered.load(.acquire) < num_threads) {
            std.atomic.spinLoopHint();
            std.Thread.yield() catch {};
        }
        return error.SetupLoadFailed;
    }

    fn worker(slot: usize) void {
        _ = entered.fetchAdd(1, .acq_rel);
        results[slot] = init(testing.allocator);
    }
};

test "kzg concurrent init survives a failed first attempt" {
    deinit();
    ConcurrentInit.entered.store(0, .release);
    ConcurrentInit.attempts.store(0, .release);
    test_init_hook = ConcurrentInit.hook;
    defer test_init_hook = null;

    var threads: [ConcurrentInit.num_threads]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, ConcurrentInit.worker, .{i});
    }
    for (threads) |t| t.join();
    defer deinit();

    // Exactly one caller owned the failed attempt and received its error;
    // every other caller either retried the load itself or observed the
    // successful retry, and none of them hung.
    var failures: usize = 0;
    for (ConcurrentInit.results) |r| {
        if (r) |_| {} else |err| {
            try testing.expectEqual(error.SetupLoadFailed, err);
            failures += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), failures);
    try testing.expectEqual(@as(u32, 2), ConcurrentInit.attempts.load(.acquire));
    try testing.expectEqual(STATE_READY, @atomicLoad(u8, &init_state, .acquire));
    var blob: Blob = @splat(0);
    _ = try blobToKzgCommitment(&blob);
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

/// Deterministic blob with full-width canonical field elements for the cell
/// round-trip tests (the top byte of every element is masked below the
/// modulus's top byte, 0x73).
fn testBlob(allocator: std.mem.Allocator, seed: u64) !*Blob {
    const blob = try allocator.create(Blob);
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(blob);
    var i: usize = 0;
    while (i < BLOB_SIZE) : (i += BYTES_PER_FIELD_ELEMENT) blob[i] &= 0x3f;
    return blob;
}

test "kzg point evaluation round trip: computeKzgProof -> verifyKzgProof" {
    const allocator = testing.allocator;
    try init(allocator);
    defer deinit();
    const blob = try testBlob(allocator, 1);
    defer allocator.destroy(blob);

    const commitment = try blobToKzgCommitment(blob);
    var z: Bytes32 = @splat(0);
    z[31] = 0x2a;
    const opening = try computeKzgProof(blob, z);
    try testing.expect(try verifyKzgProof(commitment, z, opening.y, opening.proof));

    // A different claimed value must not verify.
    var wrong_y = opening.y;
    wrong_y[31] ^= 0x01;
    try testing.expect(!try verifyKzgProof(commitment, z, wrong_y, opening.proof));

    // A non-canonical z (the modulus itself) is rejected, not evaluated.
    const modulus = [_]u8{
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
        0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    };
    try testing.expectError(error.BadArgs, computeKzgProof(blob, modulus));
    try testing.expectError(error.BadArgs, verifyKzgProof(commitment, modulus, opening.y, opening.proof));
}

test "kzg cells round trip: compute -> verify batch -> recover" {
    const allocator = testing.allocator;
    try init(allocator);
    defer deinit();
    const blob = try testBlob(allocator, 2);
    defer allocator.destroy(blob);

    const commitment = try blobToKzgCommitment(blob);
    const cells = try allocator.create([CELLS_PER_EXT_BLOB]Cell);
    defer allocator.destroy(cells);
    const proofs = try allocator.create([CELLS_PER_EXT_BLOB]KzgProof);
    defer allocator.destroy(proofs);
    try computeCellsAndKzgProofs(blob, cells, proofs);

    // computeCells yields the same cells without proofs.
    const cells_only = try allocator.create([CELLS_PER_EXT_BLOB]Cell);
    defer allocator.destroy(cells_only);
    try computeCells(blob, cells_only);
    try testing.expectEqualSlices(u8, std.mem.asBytes(cells), std.mem.asBytes(cells_only));

    // The first 64 cells are the blob itself (systematic code).
    try testing.expectEqualSlices(u8, blob, std.mem.asBytes(cells[0 .. CELLS_PER_EXT_BLOB / 2]));

    // Every cell proof verifies against the commitment, in any order.
    var commitments: [CELLS_PER_EXT_BLOB]KzgCommitment = undefined;
    var indices: [CELLS_PER_EXT_BLOB]u64 = undefined;
    for (0..CELLS_PER_EXT_BLOB) |i| {
        commitments[i] = commitment;
        indices[i] = @intCast(CELLS_PER_EXT_BLOB - 1 - i);
    }
    var shuffled_cells: [CELLS_PER_EXT_BLOB]Cell = undefined;
    var shuffled_proofs: [CELLS_PER_EXT_BLOB]KzgProof = undefined;
    for (0..CELLS_PER_EXT_BLOB) |i| {
        shuffled_cells[i] = cells[indices[i]];
        shuffled_proofs[i] = proofs[indices[i]];
    }
    try testing.expect(try verifyCellKzgProofBatch(&commitments, &indices, &shuffled_cells, &shuffled_proofs));
    try testing.expect(try verifyCellKzgProofBatch(&.{}, &.{}, &.{}, &.{}));

    // A cell attributed to the wrong index fails verification; mismatched
    // slice lengths and out-of-range indices are argument errors.
    var bad_index = [_]u64{1};
    try testing.expect(!try verifyCellKzgProofBatch(commitments[0..1], &bad_index, cells[0..1], proofs[0..1]));
    try testing.expectError(error.BadArgs, verifyCellKzgProofBatch(commitments[0..1], indices[0..2], cells[0..2], proofs[0..2]));
    bad_index[0] = CELLS_PER_EXT_BLOB;
    try testing.expectError(error.BadArgs, verifyCellKzgProofBatch(commitments[0..1], &bad_index, cells[0..1], proofs[0..1]));

    // Recovery from every other cell reproduces all cells and proofs.
    var half_indices: [CELLS_PER_EXT_BLOB / 2]u64 = undefined;
    var half_cells: [CELLS_PER_EXT_BLOB / 2]Cell = undefined;
    for (0..CELLS_PER_EXT_BLOB / 2) |i| {
        half_indices[i] = @intCast(2 * i);
        half_cells[i] = cells[2 * i];
    }
    const recovered = try allocator.create([CELLS_PER_EXT_BLOB]Cell);
    defer allocator.destroy(recovered);
    const recovered_proofs = try allocator.create([CELLS_PER_EXT_BLOB]KzgProof);
    defer allocator.destroy(recovered_proofs);
    try recoverCellsAndKzgProofs(&half_indices, &half_cells, recovered, recovered_proofs);
    try testing.expectEqualSlices(u8, std.mem.asBytes(cells), std.mem.asBytes(recovered));
    try testing.expectEqualSlices(u8, std.mem.asBytes(proofs), std.mem.asBytes(recovered_proofs));

    // Proofs are optional on recovery.
    try recoverCellsAndKzgProofs(&half_indices, &half_cells, recovered, null);
    try testing.expectEqualSlices(u8, std.mem.asBytes(cells), std.mem.asBytes(recovered));

    // Unsorted indices, too few cells and length mismatches are rejected.
    var unsorted_indices = half_indices;
    std.mem.swap(u64, &unsorted_indices[0], &unsorted_indices[1]);
    var unsorted_cells = half_cells;
    std.mem.swap(Cell, &unsorted_cells[0], &unsorted_cells[1]);
    try testing.expectError(error.BadArgs, recoverCellsAndKzgProofs(&unsorted_indices, &unsorted_cells, recovered, null));
    try testing.expectError(error.BadArgs, recoverCellsAndKzgProofs(half_indices[0..63], half_cells[0..63], recovered, null));
    try testing.expectError(error.BadArgs, recoverCellsAndKzgProofs(half_indices[0..64], half_cells[0..63], recovered, null));
    try testing.expectError(error.BadArgs, recoverCellsAndKzgProofs(&.{}, &.{}, recovered, null));
}

test "kzg precompute option yields identical cells and proofs" {
    const allocator = testing.allocator;
    try testing.expectError(error.BadArgs, initWithOptions(allocator, .{ .precompute = MAX_PRECOMPUTE + 1 }));

    const blob = try testBlob(allocator, 3);
    defer allocator.destroy(blob);
    const cells_a = try allocator.create([CELLS_PER_EXT_BLOB]Cell);
    defer allocator.destroy(cells_a);
    const proofs_a = try allocator.create([CELLS_PER_EXT_BLOB]KzgProof);
    defer allocator.destroy(proofs_a);
    const cells_b = try allocator.create([CELLS_PER_EXT_BLOB]Cell);
    defer allocator.destroy(cells_b);
    const proofs_b = try allocator.create([CELLS_PER_EXT_BLOB]KzgProof);
    defer allocator.destroy(proofs_b);

    try init(allocator);
    try computeCellsAndKzgProofs(blob, cells_a, proofs_a);
    deinit();

    // A small window keeps the test fast (tables double per step); the
    // fixed-base prover must produce byte-identical output to Pippenger.
    try initWithOptions(allocator, .{ .precompute = 2 });
    defer deinit();
    try computeCellsAndKzgProofs(blob, cells_b, proofs_b);
    try testing.expectEqualSlices(u8, std.mem.asBytes(cells_a), std.mem.asBytes(cells_b));
    try testing.expectEqualSlices(u8, std.mem.asBytes(proofs_a), std.mem.asBytes(proofs_b));
}
