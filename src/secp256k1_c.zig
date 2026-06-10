const std = @import("std");
const Signature = @import("signature.zig").Signature;

pub const SignError = error{
    InvalidPrivateKey,
    SigningFailed,
};

pub const RecoverError = error{
    InvalidSignature,
    InvalidRecoveryId,
    RecoveryFailed,
};

// ============================================================================
// libsecp256k1 C FFI declarations
// ============================================================================

const secp256k1_context = opaque {};

const secp256k1_pubkey = extern struct {
    data: [64]u8,
};

const secp256k1_ecdsa_recoverable_signature = extern struct {
    data: [65]u8,
};

const SECP256K1_CONTEXT_NONE: c_uint = 1;
const SECP256K1_EC_UNCOMPRESSED: c_uint = 2;

extern fn secp256k1_context_create(flags: c_uint) ?*secp256k1_context;
extern fn secp256k1_context_destroy(ctx: *secp256k1_context) void;
extern fn secp256k1_context_randomize(ctx: *secp256k1_context, seed32: ?[*]const u8) c_int;

extern fn secp256k1_ecdsa_sign_recoverable(
    ctx: *const secp256k1_context,
    sig: *secp256k1_ecdsa_recoverable_signature,
    msghash32: [*]const u8,
    seckey: [*]const u8,
    noncefp: ?*const anyopaque,
    ndata: ?*const anyopaque,
) c_int;

extern fn secp256k1_ecdsa_recoverable_signature_serialize_compact(
    ctx: *const secp256k1_context,
    output64: [*]u8,
    recid: *c_int,
    sig: *const secp256k1_ecdsa_recoverable_signature,
) c_int;

extern fn secp256k1_ecdsa_recoverable_signature_parse_compact(
    ctx: *const secp256k1_context,
    sig: *secp256k1_ecdsa_recoverable_signature,
    input64: [*]const u8,
    recid: c_int,
) c_int;

extern fn secp256k1_ecdsa_recover(
    ctx: *const secp256k1_context,
    pubkey: *secp256k1_pubkey,
    sig: *const secp256k1_ecdsa_recoverable_signature,
    msghash32: [*]const u8,
) c_int;

extern fn secp256k1_ec_pubkey_create(
    ctx: *const secp256k1_context,
    pubkey: *secp256k1_pubkey,
    seckey: [*]const u8,
) c_int;

extern fn secp256k1_ec_pubkey_serialize(
    ctx: *const secp256k1_context,
    output: [*]u8,
    outputlen: *usize,
    pubkey: *const secp256k1_pubkey,
    flags: c_uint,
) c_int;

extern fn secp256k1_ec_seckey_verify(
    ctx: *const secp256k1_context,
    seckey: [*]const u8,
) c_int;

// ============================================================================
// Context management
// ============================================================================

var global_ctx: ?*secp256k1_context = null;

fn getContext() *secp256k1_context {
    if (@atomicLoad(?*secp256k1_context, &global_ctx, .acquire)) |ctx| return ctx;
    const ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE) orelse
        @panic("secp256k1_context_create failed");
    // Use cmpxchg to avoid TOCTOU race: if another thread won, use their context
    if (@cmpxchgStrong(?*secp256k1_context, &global_ctx, null, ctx, .release, .acquire)) |_| {
        // Another thread already initialized; destroy our redundant context.
        secp256k1_context_destroy(ctx);
    }
    return @atomicLoad(?*secp256k1_context, &global_ctx, .acquire).?;
}

// ============================================================================
// Public API (matches secp256k1.zig signatures)
// ============================================================================

/// ECDSA signing with recoverable signature via libsecp256k1.
/// Uses RFC 6979 deterministic nonces. Low-S is enforced by the library.
pub fn sign(private_key: [32]u8, message_hash: [32]u8) SignError!Signature {
    const ctx = getContext();

    // Validate private key: must be non-zero and less than curve order
    if (secp256k1_ec_seckey_verify(ctx, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }

    var raw_sig: secp256k1_ecdsa_recoverable_signature = undefined;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &raw_sig, &message_hash, &private_key, null, null) != 1) {
        return error.SigningFailed;
    }

    var compact: [64]u8 = undefined;
    var recid: c_int = undefined;
    _ = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &compact, &recid, &raw_sig);

    return Signature{
        .r = compact[0..32].*,
        .s = compact[32..64].*,
        .v = @intCast(recid),
    };
}

/// Recover the uncompressed public key (65 bytes: 0x04 || x || y) from a
/// signature and message hash.
pub fn recover(sig: Signature, message_hash: [32]u8) RecoverError![65]u8 {
    if (sig.v > 1) return error.InvalidRecoveryId;

    // Validate r and s are non-zero
    const zero = @as([32]u8, @splat(0));
    if (std.mem.eql(u8, &sig.r, &zero) or std.mem.eql(u8, &sig.s, &zero)) {
        return error.InvalidSignature;
    }

    const ctx = getContext();

    var compact: [64]u8 = undefined;
    @memcpy(compact[0..32], &sig.r);
    @memcpy(compact[32..64], &sig.s);

    var raw_sig: secp256k1_ecdsa_recoverable_signature = undefined;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &raw_sig, &compact, @intCast(sig.v)) != 1) {
        return error.InvalidSignature;
    }

    var pubkey: secp256k1_pubkey = undefined;
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &raw_sig, &message_hash) != 1) {
        return error.RecoveryFailed;
    }

    var output: [65]u8 = undefined;
    var outputlen: usize = 65;
    _ = secp256k1_ec_pubkey_serialize(ctx, &output, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return output;
}

/// Derive the public key from a private key.
pub fn derivePublicKey(private_key: [32]u8) SignError![65]u8 {
    const ctx = getContext();

    var pubkey: secp256k1_pubkey = undefined;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, &private_key) != 1) {
        return error.InvalidPrivateKey;
    }

    var output: [65]u8 = undefined;
    var outputlen: usize = 65;
    _ = secp256k1_ec_pubkey_serialize(ctx, &output, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return output;
}
