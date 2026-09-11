//! Known-answer test for the blob transaction network encodings against
//! go-ethereum v1.16.8 (`types.BlobTxSidecar`, KZG backend go-eth-kzg, which
//! is independent of c-kzg-4844). The vector under
//! tests/vectors/kzg/go-ethereum/ fixes one transaction, one deterministic
//! blob and Anvil account 0; this test rebuilds all of it with eth.zig and
//! compares the commitment, blob proof, 128 cell proofs, signature, signed
//! transaction, version-0 wrapper and EIP-7594 version-1 wrapper byte for
//! byte (the three encodings via length + keccak256, so the vector stays
//! small). See the README there for how the vector was generated.
//!
//! Run: zig build vector-test

const std = @import("std");
const eth = @import("eth");

const kzg = eth.kzg;
const blob_mod = eth.blob;
const transaction = eth.transaction;

const VECTOR_JSON = @embedFile("vectors/kzg/go-ethereum/blobtx_sidecar_vector.json");

fn hexField(comptime n: usize, obj: std.json.ObjectMap, key: []const u8) ![n]u8 {
    const hex = obj.get(key).?.string;
    if (hex.len != 2 + 2 * n or hex[0] != '0' or hex[1] != 'x') return error.WrongLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex[2..]);
    return out;
}

fn expectHash(obj: std.json.ObjectMap, key: []const u8, bytes: []const u8) !void {
    const want = try hexField(32, obj, key);
    const got = eth.keccak.hash(bytes);
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "go-ethereum blob tx sidecar vector: v0 and v1 network encodings" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, VECTOR_JSON, .{});
    defer parsed.deinit();
    const v = parsed.value.object;

    // Blob from the recipe recorded in the vector; pinned by sha256.
    const blobs = try allocator.alloc(blob_mod.Blob, 1);
    defer allocator.free(blobs);
    @memset(&blobs[0], 0);
    var fe: usize = 0;
    while (fe < kzg.FIELD_ELEMENTS_PER_BLOB) : (fe += 1) {
        blobs[0][32 * fe + 31] = @intCast(fe % 251);
        blobs[0][32 * fe + 30] = @intCast((fe / 251) % 251);
    }
    var blob_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&blobs[0], &blob_sha, .{});
    try std.testing.expectEqualSlices(u8, &try hexField(32, v, "blob_sha256"), &blob_sha);

    try kzg.init(allocator);
    defer kzg.deinit();

    // Commitment, versioned hash, blob proof (v0) and cell proofs (v1).
    var sidecar = try blob_mod.buildSidecarV1(allocator, blobs);
    defer sidecar.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &try hexField(48, v, "commitment"), &sidecar.commitments[0]);
    const versioned_hash = blob_mod.computeVersionedHash(sidecar.commitments[0]);
    try std.testing.expectEqualSlices(u8, &try hexField(32, v, "versioned_hash"), &versioned_hash);
    const blob_proof = try kzg.computeBlobKzgProof(&blobs[0], sidecar.commitments[0]);
    try std.testing.expectEqualSlices(u8, &try hexField(48, v, "blob_proof"), &blob_proof);
    const want_cell_proofs = v.get("cell_proofs").?.array.items;
    try std.testing.expectEqual(@as(usize, blob_mod.CELL_PROOFS_PER_BLOB), want_cell_proofs.len);
    for (want_cell_proofs, 0..) |item, i| {
        var want: [48]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, item.string[2..]);
        try std.testing.expectEqualSlices(u8, &want, &sidecar.cell_proofs[i]);
    }

    // The transaction body, signed with the vector's key (RFC 6979 makes the
    // signature deterministic, so r, s and y_parity must match go-ethereum).
    const tx = transaction.Transaction{ .eip4844 = .{
        .chain_id = @intCast(v.get("chain_id").?.integer),
        .nonce = @intCast(v.get("nonce").?.integer),
        .max_priority_fee_per_gas = @intCast(v.get("max_priority_fee_per_gas").?.integer),
        .max_fee_per_gas = @intCast(v.get("max_fee_per_gas").?.integer),
        .gas_limit = @intCast(v.get("gas_limit").?.integer),
        .to = try hexField(20, v, "to"),
        .value = @intCast(v.get("value").?.integer),
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = @intCast(v.get("max_fee_per_blob_gas").?.integer),
        .blob_versioned_hashes = &.{versioned_hash},
    } };
    try std.testing.expectEqualStrings("0x", v.get("data").?.string);
    const signer = eth.signer.LocalSigner.init(try hexField(32, v, "private_key"));
    const sender = try signer.address();
    const want_sender = try hexField(20, v, "sender");
    try std.testing.expectEqualSlices(u8, &want_sender, &sender);
    const sig = try signer.signHash(try transaction.hashForSigning(allocator, tx));
    try std.testing.expectEqualSlices(u8, &try hexField(32, v, "r"), &sig.r);
    try std.testing.expectEqualSlices(u8, &try hexField(32, v, "s"), &sig.s);
    try std.testing.expectEqual(@as(u8, @intCast(v.get("y_parity").?.integer)), sig.v);

    const signed = try transaction.serializeSigned(allocator, tx, sig.r, sig.s, sig.v);
    defer allocator.free(signed);
    try std.testing.expectEqual(@as(usize, @intCast(v.get("signed_tx_len").?.integer)), signed.len);
    try expectHash(v, "signed_tx_keccak256", signed);
    try expectHash(v, "tx_hash", signed);

    // Version-0 wrapper: rlp([tx_payload_body, blobs, commitments, proofs]).
    const raw_v0 = try transaction.wrapBlobTransaction(allocator, signed, .{ .v0 = .{
        .blobs = blobs,
        .commitments = sidecar.commitments,
        .proofs = &.{blob_proof},
    } }, .{});
    defer allocator.free(raw_v0);
    try std.testing.expectEqual(@as(usize, @intCast(v.get("network_v0_len").?.integer)), raw_v0.len);
    try expectHash(v, "network_v0_keccak256", raw_v0);

    // Version-1 wrapper: rlp([tx_payload_body, 1, blobs, commitments, cell_proofs]).
    const raw_v1 = try transaction.wrapBlobTransaction(allocator, signed, .{ .v1 = sidecar }, .{});
    defer allocator.free(raw_v1);
    try std.testing.expectEqual(@as(usize, @intCast(v.get("network_v1_len").?.integer)), raw_v1.len);
    try expectHash(v, "network_v1_keccak256", raw_v1);
}
