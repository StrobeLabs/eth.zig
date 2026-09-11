//! Byte-for-byte conformance tests for `eth.kzg` against the official
//! ethereum/c-kzg-4844 v2.1.8 reference vectors vendored under
//! tests/vectors/kzg/ (see the README there for the selection).
//!
//! Every exposed function beyond the four EIP-4844 blob functions (which are
//! covered by the unit tests in src/kzg_vectors_test.zig) is checked here:
//! the point-evaluation pair and the EIP-7594 cell functions, with valid and
//! invalid cases. Outputs are compared byte for byte; the accept/reject
//! verdict (`true`/`false`/`null`) must match exactly, where a `null` vector
//! (upstream rejects the input) must map to a `KzgError` or, for inputs of
//! the wrong byte length, to the inability to even construct the fixed-size
//! Zig value.
//!
//! Run: zig build vector-test

const std = @import("std");
const eth = @import("eth");

const kzg = eth.kzg;
const Cell = kzg.Cell;
const KzgProof = kzg.KzgProof;
const KzgCommitment = kzg.KzgCommitment;
const CELLS = kzg.CELLS_PER_EXT_BLOB;

const V = "vectors/kzg/";

// ============================================================================
// Minimal YAML access for the upstream vector format
// ============================================================================

/// True for a `name:` line body (letters, digits, underscores, then a colon).
fn isKeyLine(body: []const u8) bool {
    for (body, 0..) |c, i| {
        if (c == ':') return i > 0;
        if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '_')) return false;
    }
    return false;
}

/// The raw text of `key`'s value: everything after `key:` up to the next line
/// at the key's indentation (or less) that starts another key, or EOF. Block
/// list items (`- ...`), nested lists and multi-line flow lists are included.
fn section(yaml: []const u8, key: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < yaml.len) {
        const nl = std.mem.indexOfScalarPos(u8, yaml, pos, '\n') orelse yaml.len;
        const line = yaml[pos..nl];
        const indent = line.len - std.mem.trimStart(u8, line, " ").len;
        const body = line[indent..];
        if (body.len > key.len and std.mem.startsWith(u8, body, key) and body[key.len] == ':') {
            const start = pos + indent + key.len + 1;
            var end = nl;
            var p = if (nl < yaml.len) nl + 1 else yaml.len;
            while (p < yaml.len) {
                const nl2 = std.mem.indexOfScalarPos(u8, yaml, p, '\n') orelse yaml.len;
                const l2 = yaml[p..nl2];
                const ind2 = l2.len - std.mem.trimStart(u8, l2, " ").len;
                if (ind2 <= indent and isKeyLine(l2[ind2..])) break;
                end = nl2;
                p = if (nl2 < yaml.len) nl2 + 1 else yaml.len;
            }
            return yaml[start..end];
        }
        pos = if (nl < yaml.len) nl + 1 else yaml.len;
    }
    return null;
}

/// Iterates the single-quoted strings of a section in document order (the
/// `- '0x...'` items of flat and nested block lists).
const QuotedIter = struct {
    text: []const u8,
    pos: usize = 0,

    fn next(self: *QuotedIter) ?[]const u8 {
        const q1 = std.mem.indexOfScalarPos(u8, self.text, self.pos, '\'') orelse return null;
        const q2 = std.mem.indexOfScalarPos(u8, self.text, q1 + 1, '\'') orelse return null;
        self.pos = q2 + 1;
        return self.text[q1 + 1 .. q2];
    }
};

/// The kind of the `output:` value: `true` (accept), `false`/`null` (reject
/// with a boolean result / reject with an error), or a list of values.
fn outputKind(yaml: []const u8) !union(enum) { bool: bool, null, list: []const u8 } {
    const text = section(yaml, "output") orelse return error.MissingOutput;
    const trimmed = std.mem.trim(u8, text, " \r\n");
    if (std.mem.eql(u8, trimmed, "true")) return .{ .bool = true };
    if (std.mem.eql(u8, trimmed, "false")) return .{ .bool = false };
    if (std.mem.eql(u8, trimmed, "null")) return .null;
    return .{ .list = text };
}

const DecodeError = error{ NotHex, WrongLength, InvalidCharacter, InvalidLength, NoSpaceLeft };

/// Decode a `0x`-prefixed hex string of exactly `n` bytes.
fn hexToFixed(comptime n: usize, hex: []const u8) DecodeError![n]u8 {
    if (hex.len < 2 or hex[0] != '0' or hex[1] != 'x') return error.NotHex;
    if (hex.len != 2 + 2 * n) return error.WrongLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex[2..]);
    return out;
}

/// Decode the single quoted value of `key` into a fixed-size array.
fn fixedField(comptime n: usize, yaml: []const u8, key: []const u8) ![n]u8 {
    const text = section(yaml, key) orelse return error.MissingKey;
    var it = QuotedIter{ .text = text };
    const hex = it.next() orelse return error.MissingValue;
    return hexToFixed(n, hex);
}

/// Decode every quoted value of a section into a heap-allocated slice of
/// fixed-size arrays. Fails with `WrongLength` if any element has the wrong
/// byte length (the vector's way of expressing malformed inputs).
fn fixedList(comptime n: usize, allocator: std.mem.Allocator, text: []const u8) ![][n]u8 {
    var list: std.ArrayList([n]u8) = .empty;
    errdefer list.deinit(allocator);
    var it = QuotedIter{ .text = text };
    while (it.next()) |hex| try list.append(allocator, try hexToFixed(n, hex));
    return list.toOwnedSlice(allocator);
}

/// Decode the integers of a flow list such as `[0, 1, 2]` (possibly wrapped
/// over several lines).
fn indexList(allocator: std.mem.Allocator, text: []const u8) ![]u64 {
    var list: std.ArrayList(u64) = .empty;
    errdefer list.deinit(allocator);
    var i: usize = 0;
    while (i < text.len) {
        if (std.ascii.isDigit(text[i])) {
            var j = i;
            while (j < text.len and std.ascii.isDigit(text[j])) j += 1;
            try list.append(allocator, try std.fmt.parseUnsigned(u64, text[i..j], 10));
            i = j;
        } else i += 1;
    }
    return list.toOwnedSlice(allocator);
}

fn decodeBlob(allocator: std.mem.Allocator, yaml: []const u8) !*kzg.Blob {
    const text = section(yaml, "blob") orelse return error.MissingKey;
    var it = QuotedIter{ .text = text };
    const hex = it.next() orelse return error.MissingValue;
    if (hex.len != 2 + 2 * eth.blob.BLOB_SIZE) return error.WrongLength;
    const blob = try allocator.create(kzg.Blob);
    errdefer allocator.destroy(blob);
    _ = try std.fmt.hexToBytes(blob, hex[2..]);
    return blob;
}

fn fail(name: []const u8, comptime what: []const u8, args: anytype) error{VectorMismatch} {
    std.debug.print("kzg vector {s}: " ++ what ++ "\n", .{name} ++ args);
    return error.VectorMismatch;
}

/// Reject-with-error outcomes must correspond to `output: null`.
fn expectRejected(name: []const u8, yaml: []const u8, err: anyerror) !void {
    switch (try outputKind(yaml)) {
        .null => {},
        else => return fail(name, "rejected with {s} but the vector expects a result", .{@errorName(err)}),
    }
}

// ============================================================================
// Case lists (upstream case names, minus the `<function>_case_` prefix)
// ============================================================================

const verify_kzg_proof_cases: []const []const u8 = blk: {
    var names: []const []const u8 = &.{};
    for (0..7) |i| {
        for (0..6) |j| names = names ++ &[_][]const u8{std.fmt.comptimePrint("correct_proof_{d}_{d}", .{ i, j })};
    }
    for (0..6) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("correct_proof_point_at_infinity_for_twos_poly_{d}", .{k})};
    for (0..6) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("correct_proof_point_at_infinity_for_zero_poly_{d}", .{k})};
    for (0..7) |i| {
        for (0..6) |j| names = names ++ &[_][]const u8{std.fmt.comptimePrint("incorrect_proof_{d}_{d}", .{ i, j })};
    }
    for (0..6) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("incorrect_proof_point_at_infinity_{d}", .{k})};
    for (0..4) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("invalid_commitment_{d}", .{k})};
    for (0..4) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("invalid_proof_{d}", .{k})};
    for (0..6) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("invalid_y_{d}", .{k})};
    for (0..6) |k| names = names ++ &[_][]const u8{std.fmt.comptimePrint("invalid_z_{d}", .{k})};
    break :blk names;
};

const compute_kzg_proof_cases = [_][]const u8{
    "valid_blob_0_0",
    "valid_blob_1_3",
    "invalid_blob_0",
    "invalid_z_0",
};

const compute_cells_and_kzg_proofs_cases = [_][]const u8{
    "valid_0",
    "valid_1",
    "invalid_blob_0",
    "invalid_blob_1",
};

const recover_cells_and_kzg_proofs_cases = [_][]const u8{
    "valid_half_missing_every_other_cell",
    "valid_half_missing_first_half",
    "invalid_all_cells_are_missing",
    "invalid_cell_0",
    "invalid_cell_index",
    "invalid_duplicate_cell_index",
    "invalid_more_cell_indices_than_cells",
    "invalid_more_than_half_missing",
    "invalid_shuffled_half_missing",
};

const verify_cell_kzg_proof_batch_cases = [_][]const u8{
    "valid_0",
    "valid_1",
    "valid_multiple_blobs",
    "valid_not_sorted",
    "valid_regression1",
    "valid_same_cell_multiple_times",
    "valid_zero_cells",
    "incorrect_cell",
    "incorrect_commitment",
    "incorrect_proof",
    "invalid_cell_0",
    "invalid_cell_1",
    "invalid_cell_2",
    "invalid_cell_3",
    "invalid_cell_index",
    "invalid_commitment_0",
    "invalid_commitment_1",
    "invalid_commitment_2",
    "invalid_commitment_3",
    "invalid_missing_cell",
    "invalid_missing_cell_index",
    "invalid_missing_commitment",
    "invalid_missing_proof",
    "invalid_proof_0",
    "invalid_proof_1",
    "invalid_proof_2",
    "invalid_proof_3",
};

// ============================================================================
// Per-function checks
// ============================================================================

fn checkVerifyKzgProof(name: []const u8, yaml: []const u8) !void {
    const commitment = fixedField(48, yaml, "commitment") catch |e| return expectRejected(name, yaml, e);
    const z = fixedField(32, yaml, "z") catch |e| return expectRejected(name, yaml, e);
    const y = fixedField(32, yaml, "y") catch |e| return expectRejected(name, yaml, e);
    const proof = fixedField(48, yaml, "proof") catch |e| return expectRejected(name, yaml, e);
    const got = kzg.verifyKzgProof(commitment, z, y, proof) catch |e| return expectRejected(name, yaml, e);
    switch (try outputKind(yaml)) {
        .bool => |want| if (got != want) return fail(name, "verify_kzg_proof returned {} but the vector expects {}", .{ got, want }),
        else => return fail(name, "verify_kzg_proof returned {} but the vector expects rejection", .{got}),
    }
}

fn checkComputeKzgProof(allocator: std.mem.Allocator, name: []const u8, yaml: []const u8) !void {
    const blob = decodeBlob(allocator, yaml) catch |e| return expectRejected(name, yaml, e);
    defer allocator.destroy(blob);
    const z = fixedField(32, yaml, "z") catch |e| return expectRejected(name, yaml, e);
    const got = kzg.computeKzgProof(blob, z) catch |e| return expectRejected(name, yaml, e);
    const out = switch (try outputKind(yaml)) {
        .list => |text| text,
        else => return fail(name, "compute_kzg_proof produced a proof but the vector expects rejection", .{}),
    };
    var it = QuotedIter{ .text = out };
    const want_proof = try hexToFixed(48, it.next() orelse return error.MissingValue);
    const want_y = try hexToFixed(32, it.next() orelse return error.MissingValue);
    if (!std.mem.eql(u8, &got.proof, &want_proof)) return fail(name, "proof mismatch", .{});
    if (!std.mem.eql(u8, &got.y, &want_y)) return fail(name, "evaluation mismatch", .{});
}

/// Compare 128 cells and 128 proofs against a nested `[[cells], [proofs]]`
/// output list (the quoted values appear in that order).
fn expectCellsAndProofs(name: []const u8, out: []const u8, cells: *const [CELLS]Cell, proofs: *const [CELLS]KzgProof) !void {
    var it = QuotedIter{ .text = out };
    var i: usize = 0;
    while (it.next()) |hex| : (i += 1) {
        if (i < CELLS) {
            const want = try hexToFixed(kzg.BYTES_PER_CELL, hex);
            if (!std.mem.eql(u8, &cells[i], &want)) return fail(name, "cell {d} mismatch", .{i});
        } else {
            const want = try hexToFixed(48, hex);
            if (!std.mem.eql(u8, &proofs[i - CELLS], &want)) return fail(name, "proof {d} mismatch", .{i - CELLS});
        }
    }
    if (i != 2 * CELLS) return fail(name, "expected 256 output values, found {d}", .{i});
}

fn checkComputeCellsAndKzgProofs(allocator: std.mem.Allocator, name: []const u8, yaml: []const u8) !void {
    const blob = decodeBlob(allocator, yaml) catch |e| return expectRejected(name, yaml, e);
    defer allocator.destroy(blob);
    const cells = try allocator.create([CELLS]Cell);
    defer allocator.destroy(cells);
    const proofs = try allocator.create([CELLS]KzgProof);
    defer allocator.destroy(proofs);
    kzg.computeCellsAndKzgProofs(blob, cells, proofs) catch |e| {
        // computeCells must agree on the verdict.
        try std.testing.expectError(e, kzg.computeCells(blob, cells));
        return expectRejected(name, yaml, e);
    };
    const out = switch (try outputKind(yaml)) {
        .list => |text| text,
        else => return fail(name, "compute_cells_and_kzg_proofs produced cells but the vector expects rejection", .{}),
    };
    try expectCellsAndProofs(name, out, cells, proofs);

    // The cell half of the same vector also pins computeCells (upstream's
    // compute_cells vectors use the same blobs; see the vectors README).
    const cells_only = try allocator.create([CELLS]Cell);
    defer allocator.destroy(cells_only);
    try kzg.computeCells(blob, cells_only);
    if (!std.mem.eql(u8, std.mem.asBytes(cells), std.mem.asBytes(cells_only))) return fail(name, "computeCells disagrees with computeCellsAndKzgProofs", .{});
}

fn checkRecoverCellsAndKzgProofs(allocator: std.mem.Allocator, name: []const u8, yaml: []const u8) !void {
    const idx_text = section(yaml, "cell_indices") orelse return error.MissingKey;
    const cells_text = section(yaml, "cells") orelse return error.MissingKey;
    const indices = try indexList(allocator, idx_text);
    defer allocator.free(indices);
    const cells = fixedList(kzg.BYTES_PER_CELL, allocator, cells_text) catch |e| return expectRejected(name, yaml, e);
    defer allocator.free(cells);

    const recovered = try allocator.create([CELLS]Cell);
    defer allocator.destroy(recovered);
    const recovered_proofs = try allocator.create([CELLS]KzgProof);
    defer allocator.destroy(recovered_proofs);
    kzg.recoverCellsAndKzgProofs(indices, cells, recovered, recovered_proofs) catch |e| return expectRejected(name, yaml, e);
    const out = switch (try outputKind(yaml)) {
        .list => |text| text,
        else => return fail(name, "recover_cells_and_kzg_proofs recovered cells but the vector expects rejection", .{}),
    };
    try expectCellsAndProofs(name, out, recovered, recovered_proofs);
}

fn checkVerifyCellKzgProofBatch(allocator: std.mem.Allocator, name: []const u8, yaml: []const u8) !void {
    const commitments = fixedList(48, allocator, section(yaml, "commitments") orelse return error.MissingKey) catch |e| return expectRejected(name, yaml, e);
    defer allocator.free(commitments);
    const indices = try indexList(allocator, section(yaml, "cell_indices") orelse return error.MissingKey);
    defer allocator.free(indices);
    const cells = fixedList(kzg.BYTES_PER_CELL, allocator, section(yaml, "cells") orelse return error.MissingKey) catch |e| return expectRejected(name, yaml, e);
    defer allocator.free(cells);
    const proofs = fixedList(48, allocator, section(yaml, "proofs") orelse return error.MissingKey) catch |e| return expectRejected(name, yaml, e);
    defer allocator.free(proofs);

    const got = kzg.verifyCellKzgProofBatch(commitments, indices, cells, proofs) catch |e| return expectRejected(name, yaml, e);
    switch (try outputKind(yaml)) {
        .bool => |want| if (got != want) return fail(name, "verify_cell_kzg_proof_batch returned {} but the vector expects {}", .{ got, want }),
        else => return fail(name, "verify_cell_kzg_proof_batch returned {} but the vector expects rejection", .{got}),
    }
}

// ============================================================================
// Tests
// ============================================================================

test "c-kzg-4844 vectors: verify_kzg_proof (122 cases)" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();
    var n: usize = 0;
    inline for (verify_kzg_proof_cases) |name| {
        try checkVerifyKzgProof(name, @embedFile(V ++ "verify_kzg_proof/verify_kzg_proof_case_" ++ name ++ ".yaml"));
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 122), n);
}

test "c-kzg-4844 vectors: compute_kzg_proof" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();
    inline for (compute_kzg_proof_cases) |name| {
        try checkComputeKzgProof(allocator, name, @embedFile(V ++ "compute_kzg_proof/compute_kzg_proof_case_" ++ name ++ ".yaml"));
    }
}

test "c-kzg-4844 vectors: compute_cells_and_kzg_proofs (and compute_cells)" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();
    inline for (compute_cells_and_kzg_proofs_cases) |name| {
        try checkComputeCellsAndKzgProofs(allocator, name, @embedFile(V ++ "compute_cells_and_kzg_proofs/compute_cells_and_kzg_proofs_case_" ++ name ++ ".yaml"));
    }
}

test "c-kzg-4844 vectors: recover_cells_and_kzg_proofs" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();
    inline for (recover_cells_and_kzg_proofs_cases) |name| {
        try checkRecoverCellsAndKzgProofs(allocator, name, @embedFile(V ++ "recover_cells_and_kzg_proofs/recover_cells_and_kzg_proofs_case_" ++ name ++ ".yaml"));
    }
}

test "c-kzg-4844 vectors: verify_cell_kzg_proof_batch" {
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();
    inline for (verify_cell_kzg_proof_batch_cases) |name| {
        try checkVerifyCellKzgProofBatch(allocator, name, @embedFile(V ++ "verify_cell_kzg_proof_batch/verify_cell_kzg_proof_batch_case_" ++ name ++ ".yaml"));
    }
}

test "vector parser: sections, quoted lists and flow-list integers" {
    const yaml =
        \\input:
        \\  commitments:
        \\  - '0xaa'
        \\  cell_indices: [3, 41,
        \\      128]
        \\  cells: []
        \\output: null
        \\
    ;
    try std.testing.expectEqualStrings("\n  - '0xaa'", section(yaml, "commitments").?);
    try std.testing.expect(section(yaml, "cell") == null);
    const idx = try indexList(std.testing.allocator, section(yaml, "cell_indices").?);
    defer std.testing.allocator.free(idx);
    try std.testing.expectEqualSlices(u64, &.{ 3, 41, 128 }, idx);
    try std.testing.expectEqualStrings(" []", section(yaml, "cells").?);
    try std.testing.expect((try outputKind(yaml)) == .null);
    var it = QuotedIter{ .text = section(yaml, "commitments").? };
    try std.testing.expectEqualStrings("0xaa", it.next().?);
    try std.testing.expect(it.next() == null);
    try std.testing.expectError(error.WrongLength, hexToFixed(2, "0xaa"));
}
