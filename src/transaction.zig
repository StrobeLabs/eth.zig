const std = @import("std");
const rlp = @import("rlp.zig");
const keccak = @import("keccak.zig");
const access_list_mod = @import("access_list.zig");
const blob_mod = @import("blob.zig");

pub const AccessListItem = access_list_mod.AccessListItem;
pub const AccessList = access_list_mod.AccessList;

// ============================================================================
// Transaction Types
// ============================================================================

/// EIP-155 legacy transaction (type 0).
pub const LegacyTransaction = struct {
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?[20]u8, // null for contract creation
    value: u256,
    data: []const u8,
    chain_id: ?u64, // for EIP-155; null for pre-EIP-155
};

/// EIP-2930 typed transaction (type 1).
pub const Eip2930Transaction = struct {
    chain_id: u64,
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?[20]u8,
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
};

/// EIP-1559 typed transaction (type 2).
pub const Eip1559Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: ?[20]u8,
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
};

/// EIP-4844 blob transaction (type 3).
pub const Eip4844Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: [20]u8, // blob txs always have a destination
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
    max_fee_per_blob_gas: u256,
    blob_versioned_hashes: []const [32]u8,
};

/// A signed EIP-7702 authorization tuple: `[chain_id, address, nonce, y_parity, r, s]`.
///
/// Authorizes setting the code of `authority` (the signer, recovered from the
/// signature) to a delegation pointing at `address`. The signature is computed
/// over `keccak256(0x05 || rlp([chain_id, address, nonce]))`.
///
/// - `chain_id` of 0 means the authorization is valid on any chain.
/// - `address` is the 20-byte delegation target.
/// - `nonce` is the authority account's nonce at the time of authorization.
pub const Authorization = struct {
    chain_id: u256,
    address: [20]u8,
    nonce: u64,
    y_parity: u8,
    r: [32]u8,
    s: [32]u8,
};

/// EIP-7702 set-code transaction (type 4).
///
/// Note: `to` is NOT nullable — EIP-7702 transactions cannot create contracts.
pub const Eip7702Transaction = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u256,
    max_fee_per_gas: u256,
    gas_limit: u64,
    to: [20]u8, // EIP-7702 has no contract creation; destination is required
    value: u256,
    data: []const u8,
    access_list: []const AccessListItem,
    authorization_list: []const Authorization,
};

/// Tagged union of all transaction types.
pub const Transaction = union(enum) {
    legacy: LegacyTransaction,
    eip2930: Eip2930Transaction,
    eip1559: Eip1559Transaction,
    eip4844: Eip4844Transaction,
    eip7702: Eip7702Transaction,
};

// ============================================================================
// Serialization
// ============================================================================

/// Serialize a transaction for signing (the payload that gets hashed to produce the sighash).
///
/// - Legacy (EIP-155): RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
/// - Legacy (pre-155): RLP([nonce, gasPrice, gasLimit, to, value, data])
/// - EIP-2930: 0x01 ++ RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList])
/// - EIP-1559: 0x02 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
/// - EIP-4844: 0x03 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes])
/// - EIP-7702: 0x04 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, authorizationList])
///
/// Caller owns the returned slice.
pub fn serializeForSigning(allocator: std.mem.Allocator, tx: Transaction) ![]u8 {
    switch (tx) {
        .legacy => |legacy| return serializeLegacyForSigning(allocator, legacy),
        .eip2930 => |eip2930| return serializeTypedForSigning(allocator, 0x01, eip2930),
        .eip1559 => |eip1559| return serializeTypedForSigning(allocator, 0x02, eip1559),
        .eip4844 => |eip4844| return serializeTypedForSigning(allocator, 0x03, eip4844),
        .eip7702 => |eip7702| return serializeTypedForSigning(allocator, 0x04, eip7702),
    }
}

/// Keccak-256 hash of the signing payload.
pub fn hashForSigning(allocator: std.mem.Allocator, tx: Transaction) ![32]u8 {
    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);
    return keccak.hash(payload);
}

/// Serialize a signed transaction (ready for broadcast).
///
/// - Legacy: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
/// - EIP-2930: 0x01 ++ RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s])
/// - EIP-1559: 0x02 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])
/// - EIP-4844: 0x03 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, v, r, s])
/// - EIP-7702: 0x04 ++ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, authorizationList, v, r, s])
///
/// Caller owns the returned slice.
pub fn serializeSigned(allocator: std.mem.Allocator, tx: Transaction, r: [32]u8, s: [32]u8, v: u256) ![]u8 {
    switch (tx) {
        .legacy => |legacy| return serializeLegacySigned(allocator, legacy, r, s, v),
        .eip2930 => |eip2930| return serializeTypedSigned(allocator, 0x01, eip2930, r, s, v),
        .eip1559 => |eip1559| return serializeTypedSigned(allocator, 0x02, eip1559, r, s, v),
        .eip4844 => |eip4844| return serializeTypedSigned(allocator, 0x03, eip4844, r, s, v),
        .eip7702 => |eip7702| return serializeTypedSigned(allocator, 0x04, eip7702, r, s, v),
    }
}

// ============================================================================
// Blob transaction network wrapper (EIP-4844 v0 / EIP-7594 v1)
// ============================================================================

/// Type byte of an EIP-4844 blob transaction.
pub const BLOB_TX_TYPE: u8 = 0x03;

/// Index of `blob_versioned_hashes` in a signed type-3 transaction's RLP list
/// (`[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value,
/// data, accessList, maxFeePerBlobGas, blobVersionedHashes, y_parity, r, s]`).
const BLOB_VERSIONED_HASHES_INDEX: usize = 10;

/// Errors from `wrapBlobTransaction` beyond allocation and KZG errors.
pub const BlobWrapError = error{
    /// `signed_tx` is not `0x03 || rlp([...])` with the field layout of a
    /// signed blob transaction (wrong type byte, not a single RLP list,
    /// trailing bytes, too few fields, or a malformed
    /// `blob_versioned_hashes` list).
    NotABlobTransaction,
    /// The sidecar does not match the transaction body: a different number of
    /// blobs than `blob_versioned_hashes`, or a commitment whose versioned
    /// hash is not the one the body commits to.
    VersionedHashMismatch,
    /// The sidecar's proofs do not verify against its blobs and commitments.
    SidecarVerificationFailed,
} || blob_mod.SidecarError;

/// Options for `wrapBlobTransaction`.
pub const WrapBlobOptions = struct {
    /// Verify every proof in the sidecar against its blob and commitment
    /// before encoding (`kzg.verifyBlobKzgProofBatch` for v0,
    /// `kzg.verifyCellKzgProofBatch` over the recomputed cells for v1). This
    /// is EIP-7594's fourth validity condition and the expensive one: a few
    /// milliseconds per blob, and it requires `kzg.init`. Disable it only
    /// when the sidecar was verified already. The cheap structural checks
    /// (slice shapes and the versioned-hash binding) always run.
    verify_proofs: bool = true,
};

/// Produce the network encoding of a signed EIP-4844 transaction for
/// `eth_sendRawTransaction`: the wrapper list that carries the blobs and
/// proofs alongside the signed transaction body.
///
/// `signed_tx` is the output of `serializeSigned` for a type-3 transaction,
/// `0x03 || rlp([chainId, ..., blobVersionedHashes, y_parity, r, s])`. The
/// result is
///
/// - version 0 (pre-Fusaka), `sidecar = .v0`:
///   `0x03 || rlp([tx_payload_body, blobs, commitments, proofs])`
/// - version 1 (Fusaka, EIP-7594), `sidecar = .v1`:
///   `0x03 || rlp([tx_payload_body, 1, blobs, commitments, cell_proofs])`
///
/// where `tx_payload_body` is the signed transaction's own RLP list embedded
/// as a list item, and each of the trailing lists holds fixed-size byte
/// strings (131072-byte blobs, 48-byte commitments and proofs; 128 cell
/// proofs per blob in version 1, blob-major).
///
/// The sidecar is checked against the transaction body before anything is
/// encoded, so a wrapper this function returns cannot fail a receiving node's
/// sidecar validation (EIP-7594, "the node MUST validate `tx_payload_body`"):
///
/// 1. `signed_tx` must be a single type-3 RLP list with at least the 11
///    fields up to `blob_versioned_hashes` (`NotABlobTransaction`).
/// 2. The sidecar's own slice lengths must agree -- one commitment per blob
///    and one (v0) or 128 (v1) proofs per blob (`SidecarShapeMismatch`).
/// 3. The body must carry exactly one versioned hash per blob, and
///    `computeVersionedHash(commitments[i])` must equal
///    `blob_versioned_hashes[i]` for every `i` (`VersionedHashMismatch`).
/// 4. Unless `options.verify_proofs` is false, every proof must verify
///    against its blob and commitment (`SidecarVerificationFailed`).
///
/// Checks 1 to 3 are cheap and unconditional; only 4 is optional. What is
/// *not* checked here is everything outside the sidecar's relationship to the
/// body: the signature, nonce, fees and gas limit are the caller's business.
///
/// Caller owns the returned slice. Nothing on the wire identifies which
/// version a network expects: use `.v1` on and after Fusaka, `.v0` before.
pub fn wrapBlobTransaction(
    allocator: std.mem.Allocator,
    signed_tx: []const u8,
    sidecar: blob_mod.NetworkSidecar,
    options: WrapBlobOptions,
) ![]u8 {
    if (signed_tx.len < 2 or signed_tx[0] != BLOB_TX_TYPE) return error.NotABlobTransaction;
    const body = rlp.decodeItem(signed_tx[1..]) catch return error.NotABlobTransaction;
    if (body.kind != .list or body.rest.len != 0) return error.NotABlobTransaction;
    try sidecar.validateShape();

    const blobs = sidecar.blobs();
    const commitments = sidecar.commitments();
    const proofs = sidecar.proofs();

    try checkVersionedHashes(body.payload, commitments);
    if (options.verify_proofs) {
        if (!try sidecar.verify(allocator)) return error.SidecarVerificationFailed;
    }
    const version_len: usize = switch (sidecar) {
        .v0 => 0,
        .v1 => 1, // the byte 0x01 encodes as itself
    };
    const blobs_payload = blobs.len * fixedItemLen(blob_mod.BLOB_SIZE);
    const commitments_payload = commitments.len * fixedItemLen(48);
    const proofs_payload = proofs.len * fixedItemLen(48);
    const payload_len = (signed_tx.len - 1) + version_len +
        rlp.lengthPrefixSize(blobs_payload) + blobs_payload +
        rlp.lengthPrefixSize(commitments_payload) + commitments_payload +
        rlp.lengthPrefixSize(proofs_payload) + proofs_payload;
    const total = 1 + rlp.lengthPrefixSize(payload_len) + payload_len;

    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);
    var pos: usize = 0;
    out[pos] = BLOB_TX_TYPE;
    pos += 1;
    pos += rlp.writeLengthDirect(out[pos..], payload_len, 0xc0);
    @memcpy(out[pos..][0 .. signed_tx.len - 1], signed_tx[1..]);
    pos += signed_tx.len - 1;
    if (sidecar == .v1) {
        out[pos] = blob_mod.SIDECAR_VERSION_V1;
        pos += 1;
    }
    pos += rlp.writeLengthDirect(out[pos..], blobs_payload, 0xc0);
    for (blobs) |*b| pos += writeFixedItem(out[pos..], b);
    pos += rlp.writeLengthDirect(out[pos..], commitments_payload, 0xc0);
    for (commitments) |*c| pos += writeFixedItem(out[pos..], c);
    pos += rlp.writeLengthDirect(out[pos..], proofs_payload, 0xc0);
    for (proofs) |*p| pos += writeFixedItem(out[pos..], p);
    std.debug.assert(pos == total);
    return out;
}

/// Bind a sidecar's commitments to a signed transaction body: walk `body` (the
/// payload of the signed transaction's RLP list) to `blob_versioned_hashes`
/// and require one 32-byte hash per commitment, each equal to that
/// commitment's versioned hash. This is EIP-7594's first and third validity
/// condition; without it a caller can broadcast a wrapper whose sidecar has
/// nothing to do with the transaction, which every node rejects.
fn checkVersionedHashes(body: []const u8, commitments: []const blob_mod.KzgCommitment) BlobWrapError!void {
    var rest = body;
    for (0..BLOB_VERSIONED_HASHES_INDEX) |_| {
        const item = rlp.decodeItem(rest) catch return error.NotABlobTransaction;
        rest = item.rest;
    }
    const hashes = rlp.decodeItem(rest) catch return error.NotABlobTransaction;
    if (hashes.kind != .list) return error.NotABlobTransaction;

    var payload = hashes.payload;
    for (commitments) |commitment| {
        if (payload.len == 0) return error.VersionedHashMismatch;
        const item = rlp.decodeItem(payload) catch return error.NotABlobTransaction;
        if (item.kind != .string or item.payload.len != 32) return error.NotABlobTransaction;
        const expected = blob_mod.computeVersionedHash(commitment);
        if (!std.mem.eql(u8, item.payload, &expected)) return error.VersionedHashMismatch;
        payload = item.rest;
    }
    // More hashes than blobs is just as invalid as fewer.
    if (payload.len != 0) return error.VersionedHashMismatch;
}

/// Encoded size of an RLP string of `n` bytes (n >= 2, so never the
/// single-byte short form).
fn fixedItemLen(n: usize) usize {
    return rlp.lengthPrefixSize(n) + n;
}

/// Write `bytes` as an RLP string without copying it through a temporary.
fn writeFixedItem(buf: []u8, bytes: []const u8) usize {
    const n = rlp.writeLengthDirect(buf, bytes.len, 0x80);
    @memcpy(buf[n..][0..bytes.len], bytes);
    return n + bytes.len;
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Encode the common base fields for a legacy transaction (nonce through data).
fn encodeLegacyBaseFields(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), legacy: LegacyTransaction) !void {
    try rlp.encodeInto(allocator, buf, legacy.nonce);
    try rlp.encodeInto(allocator, buf, legacy.gas_price);
    try rlp.encodeInto(allocator, buf, legacy.gas_limit);
    try rlp.encodeInto(allocator, buf, legacy.to);
    try rlp.encodeInto(allocator, buf, legacy.value);
    try rlp.encodeInto(allocator, buf, legacy.data);
}

/// Calculate the payload length of legacy transaction fields.
fn calculateLegacyFieldsLength(legacy: LegacyTransaction) usize {
    var payload_len: usize = 0;
    payload_len += rlp.encodedLength(legacy.nonce);
    payload_len += rlp.encodedLength(legacy.gas_price);
    payload_len += rlp.encodedLength(legacy.gas_limit);
    payload_len += rlp.encodedLength(legacy.to);
    payload_len += rlp.encodedLength(legacy.value);
    payload_len += rlp.encodedLength(legacy.data);
    if (legacy.chain_id) |chain_id| {
        payload_len += rlp.encodedLength(chain_id);
        payload_len += rlp.encodedLength(@as(u64, 0));
        payload_len += rlp.encodedLength(@as(u64, 0));
    }
    return payload_len;
}

/// Serialize a legacy transaction for signing.
fn serializeLegacyForSigning(allocator: std.mem.Allocator, legacy: LegacyTransaction) ![]u8 {
    const payload_len = calculateLegacyFieldsLength(legacy);
    const total = rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    // Write list header + fields directly
    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeLegacyBaseFields(allocator, &result, legacy);

    if (legacy.chain_id) |chain_id| {
        try rlp.encodeInto(allocator, &result, chain_id);
        try rlp.encodeInto(allocator, &result, @as(u64, 0));
        try rlp.encodeInto(allocator, &result, @as(u64, 0));
    }

    return result.toOwnedSlice(allocator);
}

/// Encode the fields of a typed (non-legacy) transaction for signing into an ArrayList.
/// This encodes all the fields specific to each transaction type.
fn encodeTypedFields(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), tx: anytype) !void {
    const T = @TypeOf(tx);

    // All typed transactions start with chain_id
    try rlp.encodeInto(allocator, buf, tx.chain_id);
    try rlp.encodeInto(allocator, buf, tx.nonce);

    // EIP-1559 and EIP-4844 have priority fee + max fee; EIP-2930 has gas_price
    if (@hasField(T, "max_priority_fee_per_gas")) {
        try rlp.encodeInto(allocator, buf, tx.max_priority_fee_per_gas);
        try rlp.encodeInto(allocator, buf, tx.max_fee_per_gas);
    } else {
        try rlp.encodeInto(allocator, buf, tx.gas_price);
    }

    try rlp.encodeInto(allocator, buf, tx.gas_limit);

    // `to` field: EIP-4844 always has a destination (non-optional), others have optional
    if (@hasField(T, "to")) {
        const to_field = tx.to;
        const ToFieldType = @TypeOf(to_field);
        if (ToFieldType == ?[20]u8) {
            try rlp.encodeInto(allocator, buf, to_field);
        } else {
            // Non-optional [20]u8
            try rlp.encodeInto(allocator, buf, to_field);
        }
    }

    try rlp.encodeInto(allocator, buf, tx.value);
    try rlp.encodeInto(allocator, buf, tx.data);

    // Access list
    try access_list_mod.encodeAccessList(allocator, buf, tx.access_list);

    // EIP-4844 extra fields
    if (@hasField(T, "max_fee_per_blob_gas")) {
        try rlp.encodeInto(allocator, buf, tx.max_fee_per_blob_gas);
        // blob_versioned_hashes: list of [32]u8
        try encodeBlobHashes(allocator, buf, tx.blob_versioned_hashes);
    }

    // EIP-7702 extra field
    if (@hasField(T, "authorization_list")) {
        try encodeAuthorizationList(allocator, buf, tx.authorization_list);
    }
}

/// Calculate the RLP-encoded length of a single authorization tuple
/// `[chain_id, address, nonce, y_parity, r, s]`.
fn authorizationItemLength(auth: Authorization) usize {
    var payload_len: usize = 0;
    payload_len += rlp.encodedLength(auth.chain_id);
    payload_len += rlp.encodedLength(auth.address);
    payload_len += rlp.encodedLength(auth.nonce);
    payload_len += rlp.encodedLength(auth.y_parity);
    payload_len += encodedU256BytesLength(&auth.r);
    payload_len += encodedU256BytesLength(&auth.s);
    return rlp.lengthPrefixSize(payload_len) + payload_len;
}

/// Calculate the total RLP-encoded length of an authorization list.
fn authorizationListEncodedLength(list: []const Authorization) usize {
    var outer_payload_len: usize = 0;
    for (list) |auth| {
        outer_payload_len += authorizationItemLength(auth);
    }
    return rlp.lengthPrefixSize(outer_payload_len) + outer_payload_len;
}

/// RLP-encode an EIP-7702 authorization list into the given ArrayList.
/// Each item is encoded as `[chain_id, address, nonce, y_parity, r, s]`.
fn encodeAuthorizationList(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), list: []const Authorization) !void {
    var outer_payload_len: usize = 0;
    for (list) |auth| {
        outer_payload_len += authorizationItemLength(auth);
    }

    try buf.ensureTotalCapacity(allocator, buf.items.len + rlp.lengthPrefixSize(outer_payload_len) + outer_payload_len);
    encodeLengthAssumeCapacity(buf, outer_payload_len, 0xc0);

    for (list) |auth| {
        var item_payload_len: usize = 0;
        item_payload_len += rlp.encodedLength(auth.chain_id);
        item_payload_len += rlp.encodedLength(auth.address);
        item_payload_len += rlp.encodedLength(auth.nonce);
        item_payload_len += rlp.encodedLength(auth.y_parity);
        item_payload_len += encodedU256BytesLength(&auth.r);
        item_payload_len += encodedU256BytesLength(&auth.s);

        encodeLengthAssumeCapacity(buf, item_payload_len, 0xc0);
        try rlp.encodeInto(allocator, buf, auth.chain_id);
        try rlp.encodeInto(allocator, buf, auth.address);
        try rlp.encodeInto(allocator, buf, auth.nonce);
        try rlp.encodeInto(allocator, buf, auth.y_parity);
        try encodeU256Bytes(allocator, buf, &auth.r);
        try encodeU256Bytes(allocator, buf, &auth.s);
    }
}

/// Write an EIP-7702 authorization list directly to buffer. Returns bytes written.
fn writeAuthorizationListDirect(buf: []u8, list: []const Authorization) usize {
    var outer_payload_len: usize = 0;
    for (list) |auth| {
        outer_payload_len += authorizationItemLength(auth);
    }

    var pos = rlp.writeLengthDirect(buf, outer_payload_len, 0xc0);

    for (list) |auth| {
        var item_payload_len: usize = 0;
        item_payload_len += rlp.encodedLength(auth.chain_id);
        item_payload_len += rlp.encodedLength(auth.address);
        item_payload_len += rlp.encodedLength(auth.nonce);
        item_payload_len += rlp.encodedLength(auth.y_parity);
        item_payload_len += encodedU256BytesLength(&auth.r);
        item_payload_len += encodedU256BytesLength(&auth.s);

        pos += rlp.writeLengthDirect(buf[pos..], item_payload_len, 0xc0);
        pos += rlp.writeDirect(buf[pos..], auth.chain_id);
        pos += rlp.writeDirect(buf[pos..], auth.address);
        pos += rlp.writeDirect(buf[pos..], auth.nonce);
        pos += rlp.writeDirect(buf[pos..], auth.y_parity);
        pos += writeU256BytesDirect(buf[pos..], &auth.r);
        pos += writeU256BytesDirect(buf[pos..], &auth.s);
    }

    return pos;
}

/// Write a 32-byte big-endian value as an RLP integer (stripping leading zeros)
/// directly to buffer. Returns bytes written.
fn writeU256BytesDirect(buf: []u8, bytes: *const [32]u8) usize {
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}
    if (start == 32) {
        buf[0] = 0x80;
        return 1;
    }
    return rlp.writeDirect(buf, bytes[start..]);
}

/// Encode a list of 32-byte blob versioned hashes.
fn encodeBlobHashes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), hashes: []const [32]u8) !void {
    // Pre-calculate payload length
    var payload_len: usize = 0;
    for (hashes) |h| {
        payload_len += rlp.encodedLength(h);
    }
    try list.ensureTotalCapacity(allocator, list.items.len + rlp.lengthPrefixSize(payload_len) + payload_len);
    encodeLengthAssumeCapacity(list, payload_len, 0xc0);
    for (hashes) |h| {
        try rlp.encodeInto(allocator, list, h);
    }
}

/// Write typed transaction fields directly to buffer. Returns bytes written.
fn writeTypedFieldsDirect(buf: []u8, tx: anytype) usize {
    const T = @TypeOf(tx);
    var pos: usize = 0;

    pos += rlp.writeDirect(buf[pos..], tx.chain_id);
    pos += rlp.writeDirect(buf[pos..], tx.nonce);

    if (@hasField(T, "max_priority_fee_per_gas")) {
        pos += rlp.writeDirect(buf[pos..], tx.max_priority_fee_per_gas);
        pos += rlp.writeDirect(buf[pos..], tx.max_fee_per_gas);
    } else {
        pos += rlp.writeDirect(buf[pos..], tx.gas_price);
    }

    pos += rlp.writeDirect(buf[pos..], tx.gas_limit);

    if (@hasField(T, "to")) {
        pos += rlp.writeDirect(buf[pos..], tx.to);
    }

    pos += rlp.writeDirect(buf[pos..], tx.value);
    pos += rlp.writeDirect(buf[pos..], tx.data);

    // Access list
    pos += writeAccessListDirect(buf[pos..], tx.access_list);

    if (@hasField(T, "max_fee_per_blob_gas")) {
        pos += rlp.writeDirect(buf[pos..], tx.max_fee_per_blob_gas);
        // blob_versioned_hashes
        var hashes_payload: usize = 0;
        for (tx.blob_versioned_hashes) |h| {
            hashes_payload += rlp.encodedLength(h);
        }
        pos += rlp.writeLengthDirect(buf[pos..], hashes_payload, 0xc0);
        for (tx.blob_versioned_hashes) |h| {
            pos += rlp.writeDirect(buf[pos..], h);
        }
    }

    if (@hasField(T, "authorization_list")) {
        pos += writeAuthorizationListDirect(buf[pos..], tx.authorization_list);
    }

    return pos;
}

/// Write access list directly to buffer. Returns bytes written.
fn writeAccessListDirect(buf: []u8, access_list: access_list_mod.AccessList) usize {
    var outer_payload_len: usize = 0;
    for (access_list) |item| {
        const addr_len = rlp.encodedLength(item.address);
        var keys_payload_len: usize = 0;
        for (item.storage_keys) |key| {
            keys_payload_len += rlp.encodedLength(key);
        }
        const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;
        const item_payload_len = addr_len + keys_list_len;
        outer_payload_len += rlp.lengthPrefixSize(item_payload_len) + item_payload_len;
    }

    var pos = rlp.writeLengthDirect(buf, outer_payload_len, 0xc0);

    for (access_list) |item| {
        const addr_len = rlp.encodedLength(item.address);
        var keys_payload_len: usize = 0;
        for (item.storage_keys) |key| {
            keys_payload_len += rlp.encodedLength(key);
        }
        const keys_list_len = rlp.lengthPrefixSize(keys_payload_len) + keys_payload_len;
        const item_payload_len = addr_len + keys_list_len;

        pos += rlp.writeLengthDirect(buf[pos..], item_payload_len, 0xc0);
        pos += rlp.writeDirect(buf[pos..], item.address);
        pos += rlp.writeLengthDirect(buf[pos..], keys_payload_len, 0xc0);
        for (item.storage_keys) |key| {
            pos += rlp.writeDirect(buf[pos..], key);
        }
    }

    return pos;
}

/// Calculate the total payload length of typed transaction fields for RLP list.
fn calculateTypedFieldsLength(tx: anytype) usize {
    const T = @TypeOf(tx);
    var payload_len: usize = 0;

    payload_len += rlp.encodedLength(tx.chain_id);
    payload_len += rlp.encodedLength(tx.nonce);

    if (@hasField(T, "max_priority_fee_per_gas")) {
        payload_len += rlp.encodedLength(tx.max_priority_fee_per_gas);
        payload_len += rlp.encodedLength(tx.max_fee_per_gas);
    } else {
        payload_len += rlp.encodedLength(tx.gas_price);
    }

    payload_len += rlp.encodedLength(tx.gas_limit);

    if (@hasField(T, "to")) {
        const to_field = tx.to;
        payload_len += rlp.encodedLength(to_field);
    }

    payload_len += rlp.encodedLength(tx.value);
    payload_len += rlp.encodedLength(tx.data);

    payload_len += access_list_mod.accessListEncodedLength(tx.access_list);

    if (@hasField(T, "max_fee_per_blob_gas")) {
        payload_len += rlp.encodedLength(tx.max_fee_per_blob_gas);
        // blob_versioned_hashes list
        var hashes_payload: usize = 0;
        for (tx.blob_versioned_hashes) |h| {
            hashes_payload += rlp.encodedLength(h);
        }
        payload_len += rlp.lengthPrefixSize(hashes_payload) + hashes_payload;
    }

    if (@hasField(T, "authorization_list")) {
        payload_len += authorizationListEncodedLength(tx.authorization_list);
    }

    return payload_len;
}

/// Serialize a typed transaction (EIP-2930/1559/4844) for signing.
/// Returns: type_byte ++ RLP([fields...])
fn serializeTypedForSigning(allocator: std.mem.Allocator, type_byte: u8, tx: anytype) ![]u8 {
    // Calculate exact payload length, then write directly into final buffer.
    const payload_len = calculateTypedFieldsLength(tx);
    const total = 1 + rlp.lengthPrefixSize(payload_len) + payload_len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    buf[0] = type_byte;
    var pos: usize = 1;
    pos += rlp.writeLengthDirect(buf[pos..], payload_len, 0xc0);
    _ = writeTypedFieldsDirect(buf[pos..], tx);

    return buf[0..total];
}

/// Encode a length prefix without allocation (capacity must be pre-ensured).
fn encodeLengthAssumeCapacity(list: *std.ArrayList(u8), len: usize, offset: u8) void {
    if (len < 56) {
        list.appendAssumeCapacity(offset + @as(u8, @intCast(len)));
    } else {
        var len_bytes: usize = 0;
        var temp = len;
        while (temp > 0) : (temp >>= 8) {
            len_bytes += 1;
        }
        list.appendAssumeCapacity(offset + 55 + @as(u8, @intCast(len_bytes)));
        var i: usize = len_bytes;
        while (i > 0) {
            i -= 1;
            list.appendAssumeCapacity(@intCast((len >> @intCast(i * 8)) & 0xff));
        }
    }
}

/// Serialize a signed legacy transaction.
fn serializeLegacySigned(allocator: std.mem.Allocator, legacy: LegacyTransaction, r: [32]u8, s: [32]u8, v: u256) ![]u8 {
    // Calculate payload length
    var payload_len: usize = 0;
    payload_len += rlp.encodedLength(legacy.nonce);
    payload_len += rlp.encodedLength(legacy.gas_price);
    payload_len += rlp.encodedLength(legacy.gas_limit);
    payload_len += rlp.encodedLength(legacy.to);
    payload_len += rlp.encodedLength(legacy.value);
    payload_len += rlp.encodedLength(legacy.data);
    payload_len += rlp.encodedLength(v);
    payload_len += encodedU256BytesLength(&r);
    payload_len += encodedU256BytesLength(&s);

    const total = rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeLegacyBaseFields(allocator, &result, legacy);
    try rlp.encodeInto(allocator, &result, v);
    try encodeU256Bytes(allocator, &result, &r);
    try encodeU256Bytes(allocator, &result, &s);

    return result.toOwnedSlice(allocator);
}

/// Serialize a signed typed transaction.
fn serializeTypedSigned(allocator: std.mem.Allocator, type_byte: u8, tx: anytype, r: [32]u8, s: [32]u8, v: u256) ![]u8 {
    // Pre-calculate total size
    var payload_len = calculateTypedFieldsLength(tx);
    payload_len += rlp.encodedLength(v);
    payload_len += encodedU256BytesLength(&r);
    payload_len += encodedU256BytesLength(&s);

    const total = 1 + rlp.lengthPrefixSize(payload_len) + payload_len;

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, total);

    result.appendAssumeCapacity(type_byte);
    encodeLengthAssumeCapacity(&result, payload_len, 0xc0);
    try encodeTypedFields(allocator, &result, tx);
    try rlp.encodeInto(allocator, &result, v);
    try encodeU256Bytes(allocator, &result, &r);
    try encodeU256Bytes(allocator, &result, &s);

    return result.toOwnedSlice(allocator);
}

/// Calculate the encoded length of a 32-byte big-endian value as RLP integer.
fn encodedU256BytesLength(bytes: *const [32]u8) usize {
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}
    if (start == 32) return rlp.encodedLength(@as(u64, 0));
    return rlp.encodedLength(bytes[start..]);
}

/// Encode a 32-byte big-endian value as an RLP integer (stripping leading zeros).
/// This is used for r and s signature values, which are 256-bit unsigned integers
/// stored as fixed 32-byte arrays.
fn encodeU256Bytes(allocator: std.mem.Allocator, list: *std.ArrayList(u8), bytes: *const [32]u8) !void {
    // Find first non-zero byte
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) : (start += 1) {}

    if (start == 32) {
        // All zeros => encode as 0
        try rlp.encodeInto(allocator, list, @as(u64, 0));
    } else {
        // Encode the significant bytes as a byte string
        try rlp.encodeInto(allocator, list, bytes[start..]);
    }
}

// ============================================================================
// Tests
// ============================================================================

const hex_mod = @import("hex.zig");

test "legacy tx serialization for signing (EIP-155, chain_id=1)" {
    const allocator = std.testing.allocator;

    // A well-known test case: simple ETH transfer on mainnet.
    // nonce=9, gasPrice=20 gwei, gasLimit=21000, to=0x3535...3535, value=1 ether, data=empty, chainId=1
    const tx = Transaction{
        .legacy = .{
            .nonce = 9,
            .gas_price = 20_000_000_000, // 20 gwei
            .gas_limit = 21000,
            .to = @as([20]u8, @splat(0x35)),
            .value = 1_000_000_000_000_000_000, // 1 ETH in wei
            .data = &.{},
            .chain_id = 1,
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Verify it starts with an RLP list prefix
    try std.testing.expect(payload[0] >= 0xc0);

    // Hash it to check determinism
    const hash1 = try hashForSigning(allocator, tx);
    const hash2 = try hashForSigning(allocator, tx);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);

    // Verify the payload is valid RLP by checking the list length
    try std.testing.expect(payload.len > 10);
}

test "legacy tx serialization without chain_id (pre-EIP-155)" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 0,
        .data = &.{},
        .chain_id = null,
    } };

    const with_chain = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const payload_no_chain = try serializeForSigning(allocator, tx);
    defer allocator.free(payload_no_chain);

    const payload_with_chain = try serializeForSigning(allocator, with_chain);
    defer allocator.free(payload_with_chain);

    // Pre-EIP-155 should be shorter (no chainId, 0, 0)
    try std.testing.expect(payload_no_chain.len < payload_with_chain.len);
}

test "legacy tx contract creation (to=null)" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .legacy = .{
            .nonce = 0,
            .gas_price = 1_000_000_000,
            .gas_limit = 100_000,
            .to = null,
            .value = 0,
            .data = &.{ 0x60, 0x00 }, // minimal bytecode
            .chain_id = 1,
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Should encode successfully
    try std.testing.expect(payload.len > 0);
}

test "eip2930 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip2930 = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xbb)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x01
    try std.testing.expectEqual(@as(u8, 0x01), payload[0]);
    // Followed by RLP list
    try std.testing.expect(payload[1] >= 0xc0);
}

test "eip1559 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 0,
            .max_priority_fee_per_gas = 1_500_000_000, // 1.5 gwei
            .max_fee_per_gas = 30_000_000_000, // 30 gwei
            .gas_limit = 21000,
            .to = @as([20]u8, @splat(0xcc)),
            .value = 1_000_000_000_000_000_000,
            .data = &.{},
            .access_list = &.{},
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x02
    try std.testing.expectEqual(@as(u8, 0x02), payload[0]);
}

test "eip4844 tx serialization for signing" {
    const allocator = std.testing.allocator;

    const hash1 = [_]u8{0x01} ++ @as([31]u8, @splat(0xaa));

    const hashes = [_][32]u8{hash1};
    const tx = Transaction{ .eip4844 = .{
        .chain_id = 1,
        .nonce = 5,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 50_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xdd)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 1_000_000_000,
        .blob_versioned_hashes = &hashes,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x03
    try std.testing.expectEqual(@as(u8, 0x03), payload[0]);
}

test "signed legacy tx serialization" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 9,
        .gas_price = 20_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0x35)),
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .chain_id = 1,
    } };

    const r = @as([32]u8, @splat(0x01));
    const s = @as([32]u8, @splat(0x02));
    const v: u8 = 37; // chain_id=1 => v = 1*2 + 35 + 0 = 37

    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Should be RLP-encoded (no type prefix for legacy)
    try std.testing.expect(signed[0] >= 0xc0);
    try std.testing.expect(signed.len > 60);
}

test "signed eip1559 tx serialization" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_500_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const r = @as([32]u8, @splat(0xab));
    const s = @as([32]u8, @splat(0xcd));
    const v: u8 = 1;

    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Typed transaction: starts with 0x02
    try std.testing.expectEqual(@as(u8, 0x02), signed[0]);
}

test "eip1559 known test vector" {
    // Test vector from EIP-1559 reference:
    // Verify the signing payload structure is correct.
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // 0x02 ++ RLP([1, 0, 0, 0, 0, 0x80, 0, 0x80, 0xc0])
    // chainId=1 -> 0x01
    // nonce=0 -> 0x80
    // maxPriorityFeePerGas=0 -> 0x80
    // maxFeePerGas=0 -> 0x80
    // gasLimit=0 -> 0x80
    // to=null -> 0x80
    // value=0 -> 0x80
    // data=empty -> 0x80
    // accessList=empty -> 0xc0
    // List payload = [0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0] = 9 bytes
    // RLP list header: 0xc9 (0xc0 + 9)
    // Total: 0x02, 0xc9, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0

    const expected = [_]u8{ 0x02, 0xc9, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0 };
    try std.testing.expectEqualSlices(u8, &expected, payload);
}

test "legacy tx known encoding (EIP-155)" {
    // Verify the structure for a legacy EIP-155 signing payload with all-zero values.
    const allocator = std.testing.allocator;

    const tx = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // RLP([0, 0, 0, null, 0, empty, 1, 0, 0])
    // nonce=0 -> 0x80
    // gasPrice=0 -> 0x80
    // gasLimit=0 -> 0x80
    // to=null -> 0x80
    // value=0 -> 0x80
    // data=empty -> 0x80
    // chainId=1 -> 0x01
    // 0 -> 0x80
    // 0 -> 0x80
    // List payload = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x80, 0x80] = 9 bytes
    // RLP header: 0xc9

    const expected = [_]u8{ 0xc9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x80, 0x80 };
    try std.testing.expectEqualSlices(u8, &expected, payload);
}

test "eip2930 with access list" {
    const allocator = std.testing.allocator;

    const addr = @as([20]u8, @splat(0x11));
    const key = @as([32]u8, @splat(0x22));

    const keys = [_][32]u8{key};
    const items = [_]AccessListItem{.{
        .address = addr,
        .storage_keys = &keys,
    }};

    const tx = Transaction{ .eip2930 = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 0,
        .gas_limit = 0,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &items,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Starts with 0x01
    try std.testing.expectEqual(@as(u8, 0x01), payload[0]);
    // Should be non-trivially long due to access list
    try std.testing.expect(payload.len > 50);
}

test "encodeU256Bytes strips leading zeros" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    // Value with many leading zeros
    var val = @as([32]u8, @splat(0));
    val[31] = 0x42;

    try encodeU256Bytes(allocator, &list, &val);

    // Should encode as a single byte 0x42 (< 0x80, so single byte encoding)
    try std.testing.expectEqualSlices(u8, &.{0x42}, list.items);
}

test "encodeU256Bytes all zeros" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    const val = @as([32]u8, @splat(0));
    try encodeU256Bytes(allocator, &list, &val);

    // Should encode as RLP 0 = 0x80
    try std.testing.expectEqualSlices(u8, &.{0x80}, list.items);
}

test "hashForSigning produces different hashes for different txs" {
    const allocator = std.testing.allocator;

    const tx1 = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const tx2 = Transaction{ .legacy = .{
        .nonce = 1,
        .gas_price = 1_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 0,
        .data = &.{},
        .chain_id = 1,
    } };

    const h1 = try hashForSigning(allocator, tx1);
    const h2 = try hashForSigning(allocator, tx2);

    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "legacy tx alloy.rs test vector" {
    const allocator = std.testing.allocator;

    const to_addr = try hex_mod.hexToBytesFixed(20, "F0109fC8DF283027b6285cc889F5aA624EaC1F55");

    const tx = Transaction{
        .legacy = .{
            .nonce = 0,
            .gas_price = 21_000_000_000, // 21 gwei
            .gas_limit = 2_000_000,
            .to = to_addr,
            .value = 1_000_000_000, // 1 gwei
            .data = &.{},
            .chain_id = 1,
        },
    };

    // Hash twice and verify determinism
    const hash1 = try hashForSigning(allocator, tx);
    const hash2 = try hashForSigning(allocator, tx);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);

    // Verify the payload starts with RLP list prefix and has reasonable length
    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);
    try std.testing.expect(payload[0] >= 0xc0);
    try std.testing.expect(payload.len > 40);
}

test "eip1559 with specific parameters" {
    const allocator = std.testing.allocator;

    const to_addr = try hex_mod.hexToBytesFixed(20, "6069a6c32cf691f5982febae4faf8a6f3ab2f0f6");

    const data_hex = "a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000";
    var data_buf: [68]u8 = undefined;
    _ = try hex_mod.hexToBytes(&data_buf, data_hex);

    const tx = Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 0x42,
            .max_priority_fee_per_gas = 1_000_000_000, // 1 gwei
            .max_fee_per_gas = 20_000_000_000, // 20 gwei
            .gas_limit = 44386,
            .to = to_addr,
            .value = 0,
            .data = &data_buf,
            .access_list = &.{},
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x02
    try std.testing.expectEqual(@as(u8, 0x02), payload[0]);
    // Should have reasonable length (includes 68 bytes of data)
    try std.testing.expect(payload.len > 68);

    // Hash is deterministic
    const hash1 = try hashForSigning(allocator, tx);
    const hash2 = try hashForSigning(allocator, tx);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "transaction with 256-byte data" {
    const allocator = std.testing.allocator;

    const data = @as([256]u8, @splat(0x42));

    const tx = Transaction{ .legacy = .{
        .nonce = 1,
        .gas_price = 30_000_000_000,
        .gas_limit = 500_000,
        .to = @as([20]u8, @splat(0xAA)),
        .value = 0,
        .data = &data,
        .chain_id = 1,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Payload must be longer than 256 bytes since it includes the data
    try std.testing.expect(payload.len > 256);
}

test "access list with multiple entries" {
    const allocator = std.testing.allocator;

    const key_aa = @as([32]u8, @splat(0xAA));
    const key_bb = @as([32]u8, @splat(0xBB));
    const key_cc = @as([32]u8, @splat(0xCC));

    const keys_1 = [_][32]u8{ key_aa, key_bb };
    const keys_2 = [_][32]u8{key_cc};

    const items = [_]AccessListItem{
        .{ .address = @as([20]u8, @splat(0x11)), .storage_keys = &keys_1 },
        .{ .address = @as([20]u8, @splat(0x22)), .storage_keys = &keys_2 },
        .{ .address = @as([20]u8, @splat(0x33)), .storage_keys = &.{} },
    };

    const tx = Transaction{ .eip2930 = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 1_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xFF)),
        .value = 0,
        .data = &.{},
        .access_list = &items,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Must start with type prefix 0x01
    try std.testing.expectEqual(@as(u8, 0x01), payload[0]);
    // Must include all access list data: 3 addresses + 3 storage keys
    try std.testing.expect(payload.len > 100);
}

test "eip1559 with large fees" {
    const allocator = std.testing.allocator;

    const tx = Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 0,
            .max_priority_fee_per_gas = 100_000_000_000, // 100 gwei
            .max_fee_per_gas = 500_000_000_000, // 500 gwei
            .gas_limit = 21000,
            .to = @as([20]u8, @splat(0xBB)),
            .value = 1_000_000_000_000_000_000, // 1 ETH
            .data = &.{},
            .access_list = &.{},
        },
    };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Hash is deterministic
    const hash1 = try hashForSigning(allocator, tx);
    const hash2 = try hashForSigning(allocator, tx);
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);

    // Payload should be larger than a simple tx due to large fee values
    const simple_tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xBB)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const simple_payload = try serializeForSigning(allocator, simple_tx);
    defer allocator.free(simple_payload);

    try std.testing.expect(payload.len > simple_payload.len);
}

test "eip4844 with three blob hashes" {
    const allocator = std.testing.allocator;

    const hash1 = [_]u8{0x01} ++ @as([31]u8, @splat(0xAA));
    const hash2 = [_]u8{0x01} ++ @as([31]u8, @splat(0xBB));
    const hash3 = [_]u8{0x01} ++ @as([31]u8, @splat(0xCC));

    const three_hashes = [_][32]u8{ hash1, hash2, hash3 };
    const one_hash = [_][32]u8{hash1};

    const tx_three = Transaction{
        .eip4844 = .{
            .chain_id = 1,
            .nonce = 10,
            .max_priority_fee_per_gas = 1_000_000_000, // 1 gwei
            .max_fee_per_gas = 50_000_000_000, // 50 gwei
            .gas_limit = 100_000,
            .to = @as([20]u8, @splat(0xDD)),
            .value = 0,
            .data = &.{},
            .access_list = &.{},
            .max_fee_per_blob_gas = 1_000_000_000, // 1 gwei
            .blob_versioned_hashes = &three_hashes,
        },
    };

    const tx_one = Transaction{ .eip4844 = .{
        .chain_id = 1,
        .nonce = 10,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 50_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xDD)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 1_000_000_000,
        .blob_versioned_hashes = &one_hash,
    } };

    const payload_three = try serializeForSigning(allocator, tx_three);
    defer allocator.free(payload_three);

    const payload_one = try serializeForSigning(allocator, tx_one);
    defer allocator.free(payload_one);

    // Must start with type prefix 0x03
    try std.testing.expectEqual(@as(u8, 0x03), payload_three[0]);
    // Three hashes should be larger than one hash
    try std.testing.expect(payload_three.len > payload_one.len);
}

test "signed eip1559 tx structure" {
    const allocator = std.testing.allocator;

    const tx = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_500_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };

    const r = @as([32]u8, @splat(0x11));
    const s = @as([32]u8, @splat(0x22));
    const v: u8 = 0;

    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Signed tx starts with 0x02
    try std.testing.expectEqual(@as(u8, 0x02), signed[0]);
    // Followed by RLP list
    try std.testing.expect(signed[1] >= 0xc0);

    // Signed version must be longer than unsigned version
    const unsigned = try serializeForSigning(allocator, tx);
    defer allocator.free(unsigned);
    try std.testing.expect(signed.len > unsigned.len);
}

test "eip7702 tx serialization for signing starts with 0x04" {
    const allocator = std.testing.allocator;

    const auth = Authorization{
        .chain_id = 1,
        .address = @as([20]u8, @splat(0xab)),
        .nonce = 0,
        .y_parity = 0,
        .r = @as([32]u8, @splat(0x11)),
        .s = @as([32]u8, @splat(0x22)),
    };
    const auths = [_]Authorization{auth};

    const tx = Transaction{ .eip7702 = .{
        .chain_id = 1,
        .nonce = 7,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .authorization_list = &auths,
    } };

    const payload = try serializeForSigning(allocator, tx);
    defer allocator.free(payload);

    // Type prefix 0x04 followed by an RLP list.
    try std.testing.expectEqual(@as(u8, 0x04), payload[0]);
    try std.testing.expect(payload[1] >= 0xc0);
}

test "eip7702 empty authorization_list encodes as empty list" {
    const allocator = std.testing.allocator;

    const tx_empty = Transaction{ .eip7702 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .gas_limit = 0,
        .to = @as([20]u8, @splat(0)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .authorization_list = &.{},
    } };

    const payload = try serializeForSigning(allocator, tx_empty);
    defer allocator.free(payload);

    // 0x04 ++ RLP([1, 0, 0, 0, 0, addr(20 zeros), 0, 0x80, accessList=0xc0, authList=0xc0])
    // chainId=1 -> 0x01
    // nonce=0 -> 0x80
    // maxPriorityFeePerGas=0 -> 0x80
    // maxFeePerGas=0 -> 0x80
    // gasLimit=0 -> 0x80
    // to=20 zero bytes -> 0x94 ++ 20*0x00 (21 bytes)
    // value=0 -> 0x80
    // data=empty -> 0x80
    // accessList=empty -> 0xc0
    // authorizationList=empty -> 0xc0
    // The last two bytes of the payload must be 0xc0 0xc0.
    try std.testing.expectEqual(@as(u8, 0x04), payload[0]);
    try std.testing.expectEqual(@as(u8, 0xc0), payload[payload.len - 1]); // authList
    try std.testing.expectEqual(@as(u8, 0xc0), payload[payload.len - 2]); // accessList

    // Compare shared 1559-style fields against an equivalent EIP-1559 tx.
    // The 1559 payload after its list header should match the 7702 payload's
    // leading shared fields (chainId..data) since they encode identically.
    const tx_1559 = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 0,
        .max_fee_per_gas = 0,
        .gas_limit = 0,
        .to = @as([20]u8, @splat(0)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };
    const payload_1559 = try serializeForSigning(allocator, tx_1559);
    defer allocator.free(payload_1559);

    // Both start with type byte + list header. Skip type byte + list-header byte
    // (single-byte header for both since payloads < 56 bytes), then the first
    // 8 field encodings (chainId..data = 0x01,0x80,0x80,0x80,0x80,0x94+20*0,0x80,0x80)
    // must be byte-identical.
    const shared_len: usize = 1 + 1 + 1 + 1 + 1 + 21 + 1 + 1; // chainId..data
    try std.testing.expectEqualSlices(
        u8,
        payload_1559[2 .. 2 + shared_len],
        payload[2 .. 2 + shared_len],
    );
}

test "eip7702 signed serialization appends y_parity/r/s" {
    const allocator = std.testing.allocator;

    const auth = Authorization{
        .chain_id = 1,
        .address = @as([20]u8, @splat(0xab)),
        .nonce = 3,
        .y_parity = 1,
        .r = @as([32]u8, @splat(0x33)),
        .s = @as([32]u8, @splat(0x44)),
    };
    const auths = [_]Authorization{auth};

    const tx = Transaction{ .eip7702 = .{
        .chain_id = 1,
        .nonce = 7,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .authorization_list = &auths,
    } };

    const unsigned = try serializeForSigning(allocator, tx);
    defer allocator.free(unsigned);

    const r = @as([32]u8, @splat(0xaa));
    const s = @as([32]u8, @splat(0xbb));
    const v: u8 = 1;
    const signed = try serializeSigned(allocator, tx, r, s, v);
    defer allocator.free(signed);

    // Signed starts with 0x04 and is longer than the unsigned payload.
    try std.testing.expectEqual(@as(u8, 0x04), signed[0]);
    try std.testing.expect(signed.len > unsigned.len);
    // r and s are each 32 non-zero bytes => 33 bytes each encoded, plus v=1 (1 byte).
    // Difference should be at least 3 + 33 + 33 - (header growth) bytes.
    try std.testing.expect(signed.len >= unsigned.len + 60);
}

test "eip7702 one-item vs empty authorization list length" {
    const allocator = std.testing.allocator;

    const auth = Authorization{
        .chain_id = 1,
        .address = @as([20]u8, @splat(0xab)),
        .nonce = 0,
        .y_parity = 0,
        .r = @as([32]u8, @splat(0x11)),
        .s = @as([32]u8, @splat(0x22)),
    };
    const one = [_]Authorization{auth};

    const base = Eip7702Transaction{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 100_000,
        .to = @as([20]u8, @splat(0xcc)),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .authorization_list = &.{},
    };

    var with_one = base;
    with_one.authorization_list = &one;

    const payload_empty = try serializeForSigning(allocator, .{ .eip7702 = base });
    defer allocator.free(payload_empty);
    const payload_one = try serializeForSigning(allocator, .{ .eip7702 = with_one });
    defer allocator.free(payload_one);

    try std.testing.expect(payload_one.len > payload_empty.len);
}

test "encodeAuthorizationList shape for a single item" {
    const allocator = std.testing.allocator;

    // chain_id=1 -> 0x01 (1 byte)
    // address (20 bytes) -> 0x94 ++ 20 bytes (21 bytes)
    // nonce=0 -> 0x80 (1 byte)
    // y_parity=0 -> 0x80 (1 byte)
    // r=1 (after strip) -> 0x01 (1 byte)
    // s=2 (after strip) -> 0x02 (1 byte)
    // item payload = 1 + 21 + 1 + 1 + 1 + 1 = 26 bytes
    // item header = 0xc0 + 26 = 0xda
    // outer payload = 1 + 26 = 27 bytes
    // outer header = 0xc0 + 27 = 0xdb
    var r = @as([32]u8, @splat(0));
    r[31] = 1;
    var s = @as([32]u8, @splat(0));
    s[31] = 2;

    const auth = Authorization{
        .chain_id = 1,
        .address = @as([20]u8, @splat(0xcd)),
        .nonce = 0,
        .y_parity = 0,
        .r = r,
        .s = s,
    };
    const auths = [_]Authorization{auth};

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try encodeAuthorizationList(allocator, &list, &auths);

    try std.testing.expectEqual(@as(u8, 0xdb), list.items[0]); // outer list header
    try std.testing.expectEqual(@as(u8, 0xda), list.items[1]); // item list header
    try std.testing.expectEqual(@as(u8, 0x01), list.items[2]); // chain_id=1
    try std.testing.expectEqual(@as(u8, 0x94), list.items[3]); // address prefix
    // Tail: nonce(0x80), y_parity(0x80), r(0x01), s(0x02)
    const n = list.items.len;
    try std.testing.expectEqual(@as(u8, 0x02), list.items[n - 1]); // s
    try std.testing.expectEqual(@as(u8, 0x01), list.items[n - 2]); // r
    try std.testing.expectEqual(@as(u8, 0x80), list.items[n - 3]); // y_parity
    try std.testing.expectEqual(@as(u8, 0x80), list.items[n - 4]); // nonce
    try std.testing.expectEqual(@as(usize, 28), n); // outer_hdr(1) + item_hdr(1) + 26 payload
}

test "hashForSigning different chain IDs produce different hashes" {
    const allocator = std.testing.allocator;

    const tx_chain1 = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 20_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .chain_id = 1,
    } };

    const tx_chain5 = Transaction{ .legacy = .{
        .nonce = 0,
        .gas_price = 20_000_000_000,
        .gas_limit = 21000,
        .to = @as([20]u8, @splat(0xaa)),
        .value = 1_000_000_000_000_000_000,
        .data = &.{},
        .chain_id = 5,
    } };

    const h1 = try hashForSigning(allocator, tx_chain1);
    const h5 = try hashForSigning(allocator, tx_chain5);

    try std.testing.expect(!std.mem.eql(u8, &h1, &h5));
}

// ============================================================================
// Blob transaction network wrapper tests
// ============================================================================

/// Split an RLP list payload into its items, asserting the expected kinds.
fn expectItems(payload: []const u8, comptime n: usize) ![n]rlp.Item {
    var items: [n]rlp.Item = undefined;
    var rest = payload;
    for (&items) |*it| {
        it.* = try rlp.decodeItem(rest);
        rest = it.rest;
    }
    try std.testing.expectEqual(@as(usize, 0), rest.len);
    return items;
}

/// Decode a list of fixed-size strings and compare to the expected values.
fn expectFixedList(comptime n: usize, list: rlp.Item, expected: []const [n]u8) !void {
    try std.testing.expectEqual(rlp.ItemKind.list, list.kind);
    var rest = list.payload;
    for (expected) |*want| {
        const it = try rlp.decodeItem(rest);
        try std.testing.expectEqual(rlp.ItemKind.string, it.kind);
        try std.testing.expectEqualSlices(u8, want, it.payload);
        rest = it.rest;
    }
    try std.testing.expectEqual(@as(usize, 0), rest.len);
}

/// A signed type-3 transaction over the given versioned hashes (structural
/// tests only; the signature values are arbitrary).
fn signedBlobTx(allocator: std.mem.Allocator, hashes: []const [32]u8) ![]u8 {
    const tx = Transaction{ .eip4844 = .{
        .chain_id = 1,
        .nonce = 7,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 30_000_000_000,
        .gas_limit = 21_000,
        .to = @splat(0x11),
        .value = 0,
        .data = &.{},
        .access_list = &.{},
        .max_fee_per_blob_gas = 1_000_000_000,
        .blob_versioned_hashes = hashes,
    } };
    return serializeSigned(allocator, tx, @splat(0x22), @splat(0x33), 1);
}

test "wrapBlobTransaction v1 round-trips through the RLP decoder" {
    const allocator = std.testing.allocator;
    const blobs = try allocator.alloc(blob_mod.Blob, 2);
    defer allocator.free(blobs);
    for (blobs, 0..) |*b, i| {
        @memset(b, 0);
        b[31] = @intCast(i + 1);
    }
    const commitments = [_]blob_mod.KzgCommitment{ @splat(0xc1), @splat(0xc2) };
    const cell_proofs = try allocator.alloc(blob_mod.KzgProof, 2 * blob_mod.CELL_PROOFS_PER_BLOB);
    defer allocator.free(cell_proofs);
    for (cell_proofs, 0..) |*p, i| p.* = @splat(@intCast(i % 251));
    const hashes = [_][32]u8{ blob_mod.computeVersionedHash(commitments[0]), blob_mod.computeVersionedHash(commitments[1]) };
    const signed = try signedBlobTx(allocator, &hashes);
    defer allocator.free(signed);

    const sidecar = blob_mod.NetworkSidecar{ .v1 = .{ .blobs = blobs, .commitments = &commitments, .cell_proofs = cell_proofs } };
    // Structural test: proofs are synthetic, so skip KZG verification.
    const raw = try wrapBlobTransaction(allocator, signed, sidecar, .{ .verify_proofs = false });
    defer allocator.free(raw);

    try std.testing.expectEqual(BLOB_TX_TYPE, raw[0]);
    const outer = try rlp.decodeItem(raw[1..]);
    try std.testing.expectEqual(rlp.ItemKind.list, outer.kind);
    try std.testing.expectEqual(@as(usize, 0), outer.rest.len);
    const items = try expectItems(outer.payload, 5);

    // Item 0 is the signed transaction's own list, byte for byte.
    try std.testing.expectEqual(rlp.ItemKind.list, items[0].kind);
    const body = try rlp.decodeItem(signed[1..]);
    try std.testing.expectEqualSlices(u8, body.payload, items[0].payload);
    // Item 1 is the version byte 0x01 (a single byte, encoded as itself).
    try std.testing.expectEqual(rlp.ItemKind.string, items[1].kind);
    try std.testing.expectEqualSlices(u8, &.{blob_mod.SIDECAR_VERSION_V1}, items[1].payload);
    try expectFixedList(blob_mod.BLOB_SIZE, items[2], blobs);
    try expectFixedList(48, items[3], &commitments);
    try expectFixedList(48, items[4], cell_proofs);

    // The wrapper is exactly the sum of its parts (no padding, no copies).
    const per_blob = rlp.lengthPrefixSize(blob_mod.BLOB_SIZE) + blob_mod.BLOB_SIZE;
    const per_48 = rlp.lengthPrefixSize(48) + 48;
    const blobs_payload = 2 * per_blob;
    const commitments_payload = 2 * per_48;
    const proofs_payload = 2 * blob_mod.CELL_PROOFS_PER_BLOB * per_48;
    const payload = (signed.len - 1) + 1 +
        rlp.lengthPrefixSize(blobs_payload) + blobs_payload +
        rlp.lengthPrefixSize(commitments_payload) + commitments_payload +
        rlp.lengthPrefixSize(proofs_payload) + proofs_payload;
    try std.testing.expectEqual(1 + rlp.lengthPrefixSize(payload) + payload, raw.len);
}

test "wrapBlobTransaction v0 round-trips through the RLP decoder" {
    const allocator = std.testing.allocator;
    const blobs = try allocator.alloc(blob_mod.Blob, 1);
    defer allocator.free(blobs);
    @memset(&blobs[0], 0);
    const commitments = [_]blob_mod.KzgCommitment{@splat(0xc1)};
    const proofs = [_]blob_mod.KzgProof{@splat(0xd1)};
    const hashes = [_][32]u8{blob_mod.computeVersionedHash(commitments[0])};
    const signed = try signedBlobTx(allocator, &hashes);
    defer allocator.free(signed);

    const sidecar = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = &commitments, .proofs = &proofs } };
    const raw = try wrapBlobTransaction(allocator, signed, sidecar, .{ .verify_proofs = false });
    defer allocator.free(raw);

    try std.testing.expectEqual(BLOB_TX_TYPE, raw[0]);
    const outer = try rlp.decodeItem(raw[1..]);
    try std.testing.expectEqual(@as(usize, 0), outer.rest.len);
    const items = try expectItems(outer.payload, 4);
    const body = try rlp.decodeItem(signed[1..]);
    try std.testing.expectEqualSlices(u8, body.payload, items[0].payload);
    try expectFixedList(blob_mod.BLOB_SIZE, items[1], blobs);
    try expectFixedList(48, items[2], &commitments);
    try expectFixedList(48, items[3], &proofs);
}

test "wrapBlobTransaction rejects non-blob transactions and bad shapes" {
    const allocator = std.testing.allocator;
    const blobs = try allocator.alloc(blob_mod.Blob, 1);
    defer allocator.free(blobs);
    @memset(&blobs[0], 0);
    const commitments = [_]blob_mod.KzgCommitment{@splat(0xc1)};
    const proofs = [_]blob_mod.KzgProof{@splat(0xd1)};
    const sidecar = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = &commitments, .proofs = &proofs } };
    const no_verify = WrapBlobOptions{ .verify_proofs = false };

    // An EIP-1559 transaction is not wrappable.
    const eip1559 = Transaction{ .eip1559 = .{
        .chain_id = 1,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 2,
        .gas_limit = 21_000,
        .to = null,
        .value = 0,
        .data = &.{},
        .access_list = &.{},
    } };
    const signed_1559 = try serializeSigned(allocator, eip1559, @splat(0x22), @splat(0x33), 0);
    defer allocator.free(signed_1559);
    try std.testing.expectError(error.NotABlobTransaction, wrapBlobTransaction(allocator, signed_1559, sidecar, no_verify));

    // Truncated or padded type-3 bytes are rejected.
    const hashes = [_][32]u8{blob_mod.computeVersionedHash(commitments[0])};
    const signed = try signedBlobTx(allocator, &hashes);
    defer allocator.free(signed);
    try std.testing.expectError(error.NotABlobTransaction, wrapBlobTransaction(allocator, signed[0 .. signed.len - 1], sidecar, no_verify));
    const padded = try std.mem.concat(allocator, u8, &.{ signed, &.{0x00} });
    defer allocator.free(padded);
    try std.testing.expectError(error.NotABlobTransaction, wrapBlobTransaction(allocator, padded, sidecar, no_verify));
    try std.testing.expectError(error.NotABlobTransaction, wrapBlobTransaction(allocator, &.{}, sidecar, no_verify));

    // Sidecar shape errors are reported before any encoding happens.
    const short_v1 = blob_mod.NetworkSidecar{ .v1 = .{ .blobs = blobs, .commitments = &commitments, .cell_proofs = &proofs } };
    try std.testing.expectError(error.SidecarShapeMismatch, wrapBlobTransaction(allocator, signed, short_v1, no_verify));
    const no_blobs = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = &.{}, .commitments = &.{}, .proofs = &.{} } };
    try std.testing.expectError(error.SidecarShapeMismatch, wrapBlobTransaction(allocator, signed, no_blobs, no_verify));
}

test "wrapBlobTransaction binds the sidecar to blob_versioned_hashes" {
    const kzg = @import("kzg.zig");
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blobs = try allocator.alloc(blob_mod.Blob, 2);
    defer allocator.free(blobs);
    for (blobs, 0..) |*b, i| {
        @memset(b, 0);
        b[31] = @intCast(i + 1);
    }
    var sidecar = try blob_mod.buildSidecarV1(allocator, blobs);
    defer sidecar.deinit(allocator);
    const good = [_][32]u8{
        blob_mod.computeVersionedHash(sidecar.commitments[0]),
        blob_mod.computeVersionedHash(sidecar.commitments[1]),
    };

    // The matching body is accepted (and the wrapper round-trips).
    const signed_ok = try signedBlobTx(allocator, &good);
    defer allocator.free(signed_ok);
    const raw = try wrapBlobTransaction(allocator, signed_ok, .{ .v1 = sidecar }, .{});
    defer allocator.free(raw);

    // (a) Versioned hashes that do not correspond to the sidecar commitments.
    // Every node would reject this wrapper; the caller must learn locally.
    const bogus = [_][32]u8{ @splat(0xab), @splat(0xcd) };
    const signed_bogus = try signedBlobTx(allocator, &bogus);
    defer allocator.free(signed_bogus);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_bogus, .{ .v1 = sidecar }, .{}),
    );

    // (b) One versioned hash in the body, two blobs in the sidecar.
    const signed_one = try signedBlobTx(allocator, good[0..1]);
    defer allocator.free(signed_one);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_one, .{ .v1 = sidecar }, .{}),
    );

    // (c) No versioned hashes at all.
    const signed_none = try signedBlobTx(allocator, &.{});
    defer allocator.free(signed_none);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_none, .{ .v1 = sidecar }, .{}),
    );

    // (d) More versioned hashes than blobs.
    const three = [_][32]u8{ good[0], good[1], @splat(0xef) };
    const signed_three = try signedBlobTx(allocator, &three);
    defer allocator.free(signed_three);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_three, .{ .v1 = sidecar }, .{}),
    );

    // (e) Right count, but the two hashes are swapped: position matters.
    const swapped = [_][32]u8{ good[1], good[0] };
    const signed_swapped = try signedBlobTx(allocator, &swapped);
    defer allocator.free(signed_swapped);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_swapped, .{ .v1 = sidecar }, .{}),
    );

    // The binding is checked before the expensive proof verification, so it
    // also fires with verification disabled.
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_bogus, .{ .v1 = sidecar }, .{ .verify_proofs = false }),
    );

    // The v0 path is bound the same way.
    const blob_proof = try kzg.computeBlobKzgProof(&blobs[0], sidecar.commitments[0]);
    const v0 = blob_mod.NetworkSidecar{ .v0 = .{
        .blobs = blobs[0..1],
        .commitments = sidecar.commitments[0..1],
        .proofs = &.{blob_proof},
    } };
    const raw_v0 = try wrapBlobTransaction(allocator, signed_one, v0, .{});
    defer allocator.free(raw_v0);
    try std.testing.expectError(
        error.VersionedHashMismatch,
        wrapBlobTransaction(allocator, signed_bogus, v0, .{ .verify_proofs = false }),
    );
}

test "wrapBlobTransaction rejects a body that is too short to carry blob hashes" {
    const allocator = std.testing.allocator;
    const blobs = try allocator.alloc(blob_mod.Blob, 1);
    defer allocator.free(blobs);
    @memset(&blobs[0], 0);
    const commitments = [_]blob_mod.KzgCommitment{@splat(0xc1)};
    const proofs = [_]blob_mod.KzgProof{@splat(0xd1)};
    const sidecar = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = &commitments, .proofs = &proofs } };

    // A type-3 byte in front of a short list: structurally an RLP list, but it
    // has no blob_versioned_hashes field to bind against.
    const stub = [_]u8{ BLOB_TX_TYPE, 0xc3, 0x01, 0x02, 0x03 };
    try std.testing.expectError(
        error.NotABlobTransaction,
        wrapBlobTransaction(allocator, &stub, sidecar, .{ .verify_proofs = false }),
    );

    // Eleven fields, but the eleventh is a string rather than a list.
    var buf: [16]u8 = undefined;
    buf[0] = BLOB_TX_TYPE;
    buf[1] = 0xc0 + 11;
    for (0..11) |i| buf[2 + i] = @intCast(i + 1);
    try std.testing.expectError(
        error.NotABlobTransaction,
        wrapBlobTransaction(allocator, buf[0..13], sidecar, .{ .verify_proofs = false }),
    );
}

test "wrapBlobTransaction verifies real proofs by default" {
    const kzg = @import("kzg.zig");
    const allocator = std.testing.allocator;
    try kzg.init(allocator);
    defer kzg.deinit();

    const blobs = try allocator.alloc(blob_mod.Blob, 1);
    defer allocator.free(blobs);
    @memset(&blobs[0], 0);
    blobs[0][31] = 0x2a;
    var sidecar = try blob_mod.buildSidecarV1(allocator, blobs);
    defer sidecar.deinit(allocator);
    const hashes = [_][32]u8{blob_mod.computeVersionedHash(sidecar.commitments[0])};
    const signed = try signedBlobTx(allocator, &hashes);
    defer allocator.free(signed);

    const raw = try wrapBlobTransaction(allocator, signed, .{ .v1 = sidecar }, .{});
    defer allocator.free(raw);
    try std.testing.expectEqual(BLOB_TX_TYPE, raw[0]);

    // A corrupted cell proof is caught before broadcast.
    const bad_proofs = try allocator.dupe(blob_mod.KzgProof, sidecar.cell_proofs);
    defer allocator.free(bad_proofs);
    bad_proofs[5] = bad_proofs[6];
    const bad = blob_mod.NetworkSidecar{ .v1 = .{ .blobs = blobs, .commitments = sidecar.commitments, .cell_proofs = bad_proofs } };
    try std.testing.expectError(error.SidecarVerificationFailed, wrapBlobTransaction(allocator, signed, bad, .{}));

    // The v0 wrapper verifies the blob proof the same way.
    const proof = try kzg.computeBlobKzgProof(&blobs[0], sidecar.commitments[0]);
    const v0 = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = sidecar.commitments, .proofs = &.{proof} } };
    const raw_v0 = try wrapBlobTransaction(allocator, signed, v0, .{});
    defer allocator.free(raw_v0);
    var wrong = proof;
    wrong[1] ^= 0x01;
    const v0_bad = blob_mod.NetworkSidecar{ .v0 = .{ .blobs = blobs, .commitments = sidecar.commitments, .proofs = &.{wrong} } };
    // A flipped byte is either an invalid point (BadArgs) or a failing proof.
    const res = wrapBlobTransaction(allocator, signed, v0_bad, .{});
    if (res) |bytes| {
        allocator.free(bytes);
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.SidecarVerificationFailed, error.BadArgs => {},
        else => return err,
    }
}
