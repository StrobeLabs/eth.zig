//! Offline verification of Noir UltraHonk proofs through Barretenberg's C ABI.
//!
//! Opt-in: build with `-Dnoir=true`. That flag makes build.zig fetch the pinned
//! Barretenberg v5.2.0 `libbb-external.a` for the host target as a lazy
//! package dependency and link it together with libc++. Without the flag this
//! file is still part of the module, but every entry point that touches the
//! library fails to compile with a clear message when referenced, and nothing
//! here is linked or tested. Supported targets: arm64 and x86_64 macOS,
//! x86_64 Linux and arm64 Linux (the release assets that exist for those
//! hosts).
//!
//! What is verified: UltraHonk proofs written by `bb prove` (bb 5.2.0 paired
//! with nargo 1.0.0-beta.25) in the poseidon2 (`noir-recursive`, the CLI
//! default) and keccak (`evm`) oracle-hash flavors, with or without ZK.
//! IPA-accumulating rollup proofs (`bb --verifier_target noir-rollup`) are
//! NOT supported: they additionally need a 32768-point Grumpkin CRS that
//! `init` does not install (see `Settings.ipa_accumulation`). Proving,
//! verification-key computation and Solidity verifier generation are also not
//! part of this module.
//!
//! Usage:
//! ```zig
//! try noir.init();
//! const proof = try noir.fieldsFromBytes(proof_file_bytes);           // bb `proof`
//! const inputs = try noir.fieldsFromBytes(public_inputs_file_bytes);  // bb `public_inputs`
//! const ok = try noir.verify(allocator, vk_file_bytes, inputs, proof, .fromVerifierTarget(.evm));
//! ```
//!
//! Wire protocol: `bbapi` takes one msgpack-encoded command and returns one
//! msgpack-encoded response (see noir/msgpack.zig). Requests are
//! `[[name, {field: value}]]`; responses `[name, {field: value}]`. The library
//! requires every struct field to be present and decodes requests outside its
//! exception guard, so the request encoders below emit exactly the canonical
//! bytes the library was confirmed to accept. The response decoder rejects
//! anything whose shape does not match the pinned v5.2.0 schema -- wrong
//! envelope, unknown response name, wrong field name or count, trailing bytes
//! -- as `error.UnexpectedResponse`, while accepting any msgpack encoding of
//! that shape (see noir/msgpack.zig on canonical form).
//!
//! CRS: verification needs only two trusted-setup elements, the BN254 G1
//! generator and the G2 element `[x]_2`, both embedded below as constants
//! (192 bytes, taken from barretenberg's `srs/factories/bn254_crs_data.hpp`).
//! No CRS file is read and no network is used. Barretenberg's global CRS
//! factory is first-writer-wins for the lifetime of the process: the one-point
//! G1 CRS that `init` installs can never be replaced or enlarged afterwards,
//! so a future proving milestone must size the CRS in `init` rather than add a
//! second initializer.
//!
//! Concurrency: the library keeps unsynchronized per-process request state,
//! so every `bbapi` call is serialized behind one mutex. `init` is guarded by
//! an atomic once-flag and may be called from any number of threads.

const std = @import("std");
const build_options = @import("build_options");
const msgpack = @import("noir/msgpack.zig");
const runtime = @import("runtime.zig");

/// True when the build links Barretenberg (`-Dnoir=true`).
pub const enabled: bool = build_options.noir;

/// Barretenberg release this module is pinned to. The msgpack schema used
/// below is validated against exactly this release; see
/// src/crypto/barretenberg/VENDOR.md for the update procedure.
pub const BARRETENBERG_VERSION = "v5.2.0";

// ============================================================================
// Embedded CRS constants
// ============================================================================

/// BN254 G1 generator (x = 1, y = 2) in barretenberg's affine serialization:
/// `x || y`, each a 32-byte big-endian field element. This is the first G1
/// element of the Aztec CRS and the only G1 point verification needs.
pub const BN254_G1_GENERATOR: [64]u8 = ([_]u8{0} ** 31) ++ [_]u8{1} ++ ([_]u8{0} ** 31) ++ [_]u8{2};

/// The BN254 trusted-setup G2 element `[x]_2` (128 bytes), verbatim from
/// barretenberg `srs/factories/bn254_crs_data.hpp` (`BN254_G2_ELEMENT_BYTES`).
pub const BN254_G2_ELEMENT: [128]u8 = .{
    0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e,
    0x9f, 0x59, 0x44, 0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0,
    0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6, 0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8,
    0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e, 0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1,
    0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42, 0x14, 0xe5, 0x61, 0x5e,
    0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e, 0x55,
    0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85,
    0x9c, 0xf2, 0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4,
};

/// SHA-256 of `BN254_G2_ELEMENT`, pinned upstream as `BN254_G2_ELEMENT_SHA256`
/// in the same header. Checked by a unit test so a transcription error in the
/// constant above cannot go unnoticed.
pub const BN254_G2_ELEMENT_SHA256: [32]u8 = .{
    0x01, 0x79, 0x7b, 0xfc, 0x4d, 0xe5, 0xa9, 0x6f, 0x0e, 0x51, 0x6a, 0x9e, 0xa4, 0x53, 0x7d, 0x18,
    0x78, 0x6d, 0xc3, 0x0c, 0xb9, 0x91, 0xac, 0xa4, 0x27, 0x4c, 0x95, 0x82, 0x2b, 0x69, 0xc3, 0x2f,
};

// ============================================================================
// C ABI (libbb-external.a)
// ============================================================================

/// The single native entrypoint. `output_out`/`output_len_out` are in-out: on
/// entry they describe an optional caller-provided scratch buffer (we always
/// pass null/0), on return they describe the response, which the library
/// allocated and which must be released with `bbfree`.
extern fn bbapi(input_in: [*]const u8, input_len_in: usize, output_out: *?[*]u8, output_len_out: *usize) void;
extern fn bbfree(ptr: ?*anyopaque) void;

// ============================================================================
// Public types
// ============================================================================

pub const NoirError = error{
    /// `init` has not completed successfully in this process.
    NotInitialized,
    /// Barretenberg rejected the inputs before or during deserialization and
    /// answered `CircuitVerify` with an `ErrorResponse`: a non-canonical field
    /// element, a proof element that is not a curve point, a public-input
    /// count that disagrees with the verification key, or a verification key
    /// that does not deserialize. The message is available through
    /// `verifyDiag`. Like `false`, this means "not verified"; it says the
    /// library never got as far as a verdict, not that the proof was
    /// well-formed.
    ProofRejected,
    /// Barretenberg answered `SrsInitSrs` with an `ErrorResponse`.
    SrsInitFailed,
    /// The response bytes do not match the pinned v5.2.0 schema (wrong
    /// envelope, unknown response name, missing or extra fields, trailing
    /// bytes). Indicates a library/binding version mismatch.
    UnexpectedResponse,
    /// `bbapi` returned no output buffer at all.
    NoResponse,
    OutOfMemory,
    /// A request component exceeds the msgpack 32-bit length limit.
    TooLong,
};

/// Oracle hash used by the prover's Fiat-Shamir transcript. Must match the
/// flavor the proof was generated with. Barretenberg also knows `starknet`,
/// but it is compiled out of the release static libraries.
pub const OracleHash = enum {
    poseidon2,
    keccak,
};

/// Mirror of Barretenberg's `ProofSystemSettings`; the field names and order
/// are the wire schema. Defaults match `bb` with no `--verifier_target`.
pub const Settings = struct {
    /// Proof carries an IPA accumulator (rollup circuits). Part of the wire
    /// struct, but `verify` cannot honor it: an IPA proof is checked against a
    /// 32768-point Grumpkin CRS that `init` does not install, so Barretenberg
    /// answers such a request with `error.ProofRejected` ("You need to
    /// initialize the global CRS with a call to init_grumpkin_crs_factory").
    /// No `VerifierTarget` sets it; see src/crypto/barretenberg/VENDOR.md for
    /// what supporting it would cost.
    ipa_accumulation: bool = false,
    oracle_hash_type: OracleHash = .poseidon2,
    /// The proof was generated without blinding (`*-no-zk` targets).
    disable_zk: bool = false,
    /// Barretenberg's experimental Solidity-verifier layout; not used by any
    /// `--verifier_target`, kept so the wire struct is complete.
    optimized_solidity_verifier: bool = false,

    /// The `bb --verifier_target` values this module can verify. `default` is
    /// what `bb` uses when the flag is absent (poseidon2, ZK, no IPA), which
    /// is identical to `noir_recursive`.
    ///
    /// bb also accepts `noir-rollup`/`noir-rollup-no-zk` (IPA accumulation)
    /// and `starknet`/`starknet-no-zk`. They are deliberately absent: the
    /// rollup targets need a Grumpkin CRS `init` does not install (see
    /// `ipa_accumulation`), and the starknet flavors are compiled out of the
    /// release static libraries.
    pub const VerifierTarget = enum {
        default,
        evm,
        evm_no_zk,
        noir_recursive,
        noir_recursive_no_zk,
    };

    /// Same mapping as `bb`'s CLI applies to `--verifier_target`.
    pub fn fromVerifierTarget(target: VerifierTarget) Settings {
        return switch (target) {
            .default, .noir_recursive => .{},
            .noir_recursive_no_zk => .{ .disable_zk = true },
            .evm => .{ .oracle_hash_type = .keccak },
            .evm_no_zk => .{ .oracle_hash_type = .keccak, .disable_zk = true },
        };
    }
};

/// Receives Barretenberg's error message when `verifyDiag` fails with
/// `error.ProofRejected`. Fixed-size so no allocator is involved.
pub const Diagnostics = struct {
    pub const max_message_len = 256;

    buf: [max_message_len]u8 = undefined,
    len: usize = 0,

    /// The last `ErrorResponse` message (possibly truncated), or empty.
    pub fn message(self: *const Diagnostics) []const u8 {
        return self.buf[0..self.len];
    }

    fn set(self: *Diagnostics, msg: []const u8) void {
        const n = @min(msg.len, max_message_len);
        @memcpy(self.buf[0..n], msg[0..n]);
        self.len = n;
    }
};

// ============================================================================
// Lifecycle (process-global, init-once)
// ============================================================================

const State = enum(u8) { uninit, initializing, ready };

var init_state: std.atomic.Value(u8) = .init(@intFromEnum(State.uninit));

/// Serializes every `bbapi` call (the library's request state is a process
/// global with no lock of its own). The mutex only needs an `Io` for futex
/// waits on contention, so the library's blocking `Io` is used here; nothing
/// else about the call touches I/O.
var api_mutex: std.Io.Mutex = .init;

fn loadState() State {
    return @enumFromInt(init_state.load(.acquire));
}

/// Install the verification CRS (G1 generator + pinned G2) into Barretenberg.
/// Idempotent and thread-safe: the first caller performs the `SrsInitSrs`
/// call, concurrent callers wait for it, later callers return immediately. If
/// the winner fails, the state is rolled back so a later call can retry.
///
/// Must complete before `verify`. The installed CRS holds a single G1 point,
/// which is sufficient for verification only (see the module docs on the
/// first-writer-wins constraint).
pub fn init() NoirError!void {
    if (comptime !enabled) @compileError("eth.noir requires building with -Dnoir=true (links Barretenberg " ++ BARRETENBERG_VERSION ++ ")");

    while (true) {
        switch (loadState()) {
            .ready => return,
            .initializing => std.atomic.spinLoopHint(),
            .uninit => {
                if (init_state.cmpxchgStrong(
                    @intFromEnum(State.uninit),
                    @intFromEnum(State.initializing),
                    .acquire,
                    .acquire,
                ) == null) break;
            },
        }
    }

    // We own initialization. Roll back on failure so another caller can retry.
    errdefer init_state.store(@intFromEnum(State.uninit), .release);

    // The request is 242 bytes; encode it on the stack.
    var stack: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack);
    const request = try encodeSrsInitSrsRequest(fba.allocator(), &BN254_G1_GENERATOR, 1, &BN254_G2_ELEMENT);

    const response = try call(request);
    defer response.deinit();
    try parseSrsInitResponse(response.bytes(), null);

    init_state.store(@intFromEnum(State.ready), .release);
}

/// Whether `init` has completed successfully in this process.
pub fn isInitialized() bool {
    return loadState() == .ready;
}

// ============================================================================
// Verification
// ============================================================================

/// Verify an UltraHonk proof against its verification key.
///
/// - `vk`: the raw bytes of bb's `vk` output.
/// - `public_inputs` / `proof`: 32-byte big-endian field elements, exactly as
///   bb writes them; use `fieldsFromBytes` to view the raw files this way.
/// - `settings`: must match the flavor used at proving time
///   (`Settings.fromVerifierTarget`).
///
/// Only `true` means verified. Both failure shapes mean "not verified", and
/// which one you get depends on how far Barretenberg got:
///
/// - `false`: Barretenberg answered `verified=false` (a proof that does not
///   satisfy the circuit, a wrong public-input *value*, a wrong proof or VK
///   size, a flavor mismatch).
/// - `error.ProofRejected`: Barretenberg rejected the inputs before or during
///   deserialization (a non-canonical field element, a point that is not on
///   the curve, a public-input *count* that disagrees with the VK, a VK that
///   does not deserialize). `verifyDiag` exposes the library's message.
///
/// Callers deciding whether to accept a proof must treat the error as a
/// rejection, not as an internal fault: which of the two an invalid input
/// produces is not a stable property of the input.
///
/// `allocator` is used for one transient request buffer that is freed before
/// returning.
pub fn verify(
    allocator: std.mem.Allocator,
    vk: []const u8,
    public_inputs: []const [32]u8,
    proof: []const [32]u8,
    settings: Settings,
) NoirError!bool {
    return verifyDiag(allocator, vk, public_inputs, proof, settings, null);
}

/// `verify` with an optional sink for Barretenberg's error message.
pub fn verifyDiag(
    allocator: std.mem.Allocator,
    vk: []const u8,
    public_inputs: []const [32]u8,
    proof: []const [32]u8,
    settings: Settings,
    diag: ?*Diagnostics,
) NoirError!bool {
    if (comptime !enabled) @compileError("eth.noir requires building with -Dnoir=true (links Barretenberg " ++ BARRETENBERG_VERSION ++ ")");

    if (diag) |d| d.len = 0;
    // Guard in Zig: calling the library before the CRS is installed makes it
    // throw internally, and we do not want to rely on how it reports that.
    if (loadState() != .ready) return error.NotInitialized;

    const request = try encodeCircuitVerifyRequest(allocator, vk, public_inputs, proof, settings);
    defer allocator.free(request);

    const response = try call(request);
    defer response.deinit();
    return parseVerifyResponse(response.bytes(), diag);
}

/// View a concatenation of 32-byte field elements (bb's `proof` and
/// `public_inputs` files) as a slice of fields, without copying.
pub fn fieldsFromBytes(bytes: []const u8) error{InvalidLength}![]const [32]u8 {
    if (bytes.len % 32 != 0) return error.InvalidLength;
    if (bytes.len == 0) return &[0][32]u8{};
    const fields: [*]const [32]u8 = @ptrCast(bytes.ptr);
    return fields[0 .. bytes.len / 32];
}

// ============================================================================
// Wire encoding (exposed for byte-for-byte tests against bb reference requests)
// ============================================================================

/// Encode `SrsInitSrs{points_buf, num_points, g2_point}` wrapped in the
/// single-argument tuple `bbapi` expects. Caller owns the result.
pub fn encodeSrsInitSrsRequest(
    allocator: std.mem.Allocator,
    points_buf: []const u8,
    num_points: u32,
    g2_point: *const [128]u8,
) msgpack.EncodeError![]u8 {
    var enc = msgpack.Encoder.init(allocator);
    errdefer enc.deinit();
    try enc.writeArrayHeader(1); // std::tuple<Command>
    try enc.writeArrayHeader(2); // NamedUnion: [name, fields]
    try enc.writeStr("SrsInitSrs");
    try enc.writeMapHeader(3);
    try enc.writeStr("points_buf");
    try enc.writeBin(points_buf);
    try enc.writeStr("num_points");
    try enc.writeUint(num_points);
    try enc.writeStr("g2_point");
    try enc.writeBin(g2_point);
    return enc.toOwnedSlice();
}

/// Encode `CircuitVerify{verification_key, public_inputs, proof, settings}`
/// wrapped in the single-argument tuple `bbapi` expects. Caller owns the result.
pub fn encodeCircuitVerifyRequest(
    allocator: std.mem.Allocator,
    vk: []const u8,
    public_inputs: []const [32]u8,
    proof: []const [32]u8,
    settings: Settings,
) msgpack.EncodeError![]u8 {
    var enc = msgpack.Encoder.init(allocator);
    errdefer enc.deinit();
    try enc.writeArrayHeader(1);
    try enc.writeArrayHeader(2);
    try enc.writeStr("CircuitVerify");
    try enc.writeMapHeader(4);
    try enc.writeStr("verification_key");
    try enc.writeBin(vk);
    try enc.writeStr("public_inputs");
    try writeFields(&enc, public_inputs);
    try enc.writeStr("proof");
    try writeFields(&enc, proof);
    try enc.writeStr("settings");
    try enc.writeMapHeader(4);
    try enc.writeStr("ipa_accumulation");
    try enc.writeBool(settings.ipa_accumulation);
    try enc.writeStr("oracle_hash_type");
    try enc.writeStr(@tagName(settings.oracle_hash_type));
    try enc.writeStr("disable_zk");
    try enc.writeBool(settings.disable_zk);
    try enc.writeStr("optimized_solidity_verifier");
    try enc.writeBool(settings.optimized_solidity_verifier);
    return enc.toOwnedSlice();
}

/// `std::vector<uint256_t>` encodes as an array of 32-byte bin values.
fn writeFields(enc: *msgpack.Encoder, fields: []const [32]u8) msgpack.EncodeError!void {
    try enc.writeArrayHeader(fields.len);
    for (fields) |*field| try enc.writeBin(field);
}

// ============================================================================
// Calling the library and decoding responses
// ============================================================================

/// A response buffer owned by Barretenberg.
const Response = struct {
    ptr: [*]u8,
    len: usize,

    fn bytes(self: Response) []const u8 {
        return self.ptr[0..self.len];
    }

    fn deinit(self: Response) void {
        bbfree(@ptrCast(self.ptr));
    }
};

fn call(request: []const u8) NoirError!Response {
    const io = runtime.blockingIo();
    api_mutex.lockUncancelable(io);
    defer api_mutex.unlock(io);

    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    bbapi(request.ptr, request.len, &out, &out_len);
    const ptr = out orelse return error.NoResponse;
    return .{ .ptr = ptr, .len = out_len };
}

const Envelope = struct {
    name: []const u8,
    field_count: usize,
};

/// Read the `[name, {...}]` response envelope up to the map header.
fn readEnvelope(dec: *msgpack.Decoder) NoirError!Envelope {
    const outer = dec.readArrayHeader() catch return error.UnexpectedResponse;
    if (outer != 2) return error.UnexpectedResponse;
    const name = dec.readStr() catch return error.UnexpectedResponse;
    const field_count = dec.readMapHeader() catch return error.UnexpectedResponse;
    return .{ .name = name, .field_count = field_count };
}

/// Read the single `message` field of an `ErrorResponse`, record it, and
/// return `err`.
fn readErrorResponse(dec: *msgpack.Decoder, envelope: Envelope, diag: ?*Diagnostics, err: NoirError) NoirError {
    if (envelope.field_count != 1) return error.UnexpectedResponse;
    const key = dec.readStr() catch return error.UnexpectedResponse;
    if (!std.mem.eql(u8, key, "message")) return error.UnexpectedResponse;
    const message = dec.readStr() catch return error.UnexpectedResponse;
    if (!dec.finished()) return error.UnexpectedResponse;
    if (diag) |d| d.set(message);
    return err;
}

/// Decode `["CircuitVerifyResponse", {"verified": bool}]` or an `ErrorResponse`.
fn parseVerifyResponse(bytes: []const u8, diag: ?*Diagnostics) NoirError!bool {
    var dec = msgpack.Decoder.init(bytes);
    const envelope = try readEnvelope(&dec);
    if (std.mem.eql(u8, envelope.name, "ErrorResponse")) {
        return readErrorResponse(&dec, envelope, diag, error.ProofRejected);
    }
    if (!std.mem.eql(u8, envelope.name, "CircuitVerifyResponse")) return error.UnexpectedResponse;
    if (envelope.field_count != 1) return error.UnexpectedResponse;
    const key = dec.readStr() catch return error.UnexpectedResponse;
    if (!std.mem.eql(u8, key, "verified")) return error.UnexpectedResponse;
    const verified = dec.readBool() catch return error.UnexpectedResponse;
    if (!dec.finished()) return error.UnexpectedResponse;
    return verified;
}

/// Decode `["SrsInitSrsResponse", {"points_buf": bin}]` or an `ErrorResponse`.
fn parseSrsInitResponse(bytes: []const u8, diag: ?*Diagnostics) NoirError!void {
    var dec = msgpack.Decoder.init(bytes);
    const envelope = try readEnvelope(&dec);
    if (std.mem.eql(u8, envelope.name, "ErrorResponse")) {
        return readErrorResponse(&dec, envelope, diag, error.SrsInitFailed);
    }
    if (!std.mem.eql(u8, envelope.name, "SrsInitSrsResponse")) return error.UnexpectedResponse;
    if (envelope.field_count != 1) return error.UnexpectedResponse;
    const key = dec.readStr() catch return error.UnexpectedResponse;
    if (!std.mem.eql(u8, key, "points_buf")) return error.UnexpectedResponse;
    _ = dec.readBin() catch return error.UnexpectedResponse;
    if (!dec.finished()) return error.UnexpectedResponse;
}

// ============================================================================
// Tests
// ============================================================================
//
// The proof vectors and the byte-for-byte request comparisons live in
// tests/noir_vectors_test.zig (a separate test binary that embeds
// tests/vectors/noir/). The tests here cover the lifecycle guard, the
// once-flag under contention, the settings mapping, the embedded constants
// and the response decoder. They only run when the build links Barretenberg
// (root.zig gates the import on the `noir` build option).

const testing = std.testing;

// Must stay the first test in this file: it relies on no earlier test in this
// process having initialized the library, and the CRS cannot be uninstalled.
test "noir: verify before init returns NotInitialized without touching the library" {
    try testing.expect(!isInitialized());
    try testing.expectError(error.NotInitialized, verify(testing.allocator, "", &.{}, &.{}, .{}));
}

test "noir: init is idempotent under concurrent callers" {
    const thread_count = 8;
    const Worker = struct {
        fn run(ok: *bool) void {
            init() catch return;
            ok.* = true;
        }
    };
    var ok: [thread_count]bool = @splat(false);
    var threads: [thread_count]std.Thread = undefined;
    var spawned: usize = 0;
    for (0..thread_count) |i| {
        threads[i] = std.Thread.spawn(.{}, Worker.run, .{&ok[i]}) catch break;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();
    for (ok[0..spawned]) |flag| try testing.expect(flag);
    try testing.expect(isInitialized());
    // A later call is a no-op that still succeeds.
    try init();
    try testing.expect(isInitialized());
}

test "noir: empty inputs after init are answered, not crashed on" {
    try init();
    var diag: Diagnostics = .{};
    const result = verifyDiag(testing.allocator, "", &.{}, &.{}, .{}, &diag) catch |err| switch (err) {
        error.ProofRejected => false,
        else => return err,
    };
    try testing.expect(!result);
}

test "noir: Settings.fromVerifierTarget mirrors bb --verifier_target" {
    const S = Settings;
    try testing.expectEqual(S{}, S.fromVerifierTarget(.default));
    try testing.expectEqual(S{}, S.fromVerifierTarget(.noir_recursive));
    try testing.expectEqual(S{ .disable_zk = true }, S.fromVerifierTarget(.noir_recursive_no_zk));
    try testing.expectEqual(S{ .oracle_hash_type = .keccak }, S.fromVerifierTarget(.evm));
    try testing.expectEqual(S{ .oracle_hash_type = .keccak, .disable_zk = true }, S.fromVerifierTarget(.evm_no_zk));
    // Every target leaves the experimental Solidity layout off.
    try testing.expect(!S.fromVerifierTarget(.evm).optimized_solidity_verifier);
}

test "noir: no VerifierTarget requests IPA accumulation" {
    // `init` installs a BN254 verification CRS only. An IPA proof is checked
    // against a 32768-point Grumpkin CRS, which Barretenberg has no way to
    // obtain here, so offering a rollup target would promise a mode that
    // always fails. This pins that the gap cannot silently reopen: adding a
    // rollup variant to `VerifierTarget` must fail this test (and come with a
    // Grumpkin CRS in `init`).
    inline for (@typeInfo(Settings.VerifierTarget).@"enum".fields) |field| {
        const settings = Settings.fromVerifierTarget(@field(Settings.VerifierTarget, field.name));
        try testing.expect(!settings.ipa_accumulation);
        try testing.expect(std.mem.indexOf(u8, field.name, "rollup") == null);
    }
    // The wire field itself stays, because it is part of the pinned schema.
    try testing.expect(@hasField(Settings, "ipa_accumulation"));
}

test "noir: embedded G2 element matches the upstream SHA-256 pin" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&BN254_G2_ELEMENT, &digest, .{});
    try testing.expectEqualSlices(u8, &BN254_G2_ELEMENT_SHA256, &digest);
}

test "noir: embedded G1 generator is (1, 2)" {
    try testing.expectEqual(@as(u8, 1), BN254_G1_GENERATOR[31]);
    try testing.expectEqual(@as(u8, 2), BN254_G1_GENERATOR[63]);
    var nonzero: usize = 0;
    for (BN254_G1_GENERATOR) |b| nonzero += @intFromBool(b != 0);
    try testing.expectEqual(@as(usize, 2), nonzero);
}

test "noir: SrsInitSrs request has the documented shape and leaks nothing" {
    const request = try encodeSrsInitSrsRequest(testing.allocator, &BN254_G1_GENERATOR, 1, &BN254_G2_ELEMENT);
    defer testing.allocator.free(request);
    try testing.expectEqual(@as(usize, 242), request.len);
    // [[ "SrsInitSrs", { "points_buf": bin8(64) ...
    const prefix = "\x91\x92\xaaSrsInitSrs\x83\xaapoints_buf\xc4\x40";
    try testing.expectEqualSlices(u8, prefix, request[0..prefix.len]);
    // ... "num_points": 1, "g2_point": bin8(128) <128 bytes> ]]
    const tail_key = "\xaanum_points\x01\xa8g2_point\xc4\x80";
    const tail_start = prefix.len + 64;
    try testing.expectEqualSlices(u8, tail_key, request[tail_start .. tail_start + tail_key.len]);
    try testing.expectEqualSlices(u8, &BN254_G2_ELEMENT, request[request.len - 128 ..]);
}

test "noir: CircuitVerify request encodes settings by name and fields as bin32" {
    const vk = [_]u8{0xab} ** 3;
    const fields = [_][32]u8{ [_]u8{0x11} ** 32, [_]u8{0x22} ** 32 };
    const request = try encodeCircuitVerifyRequest(testing.allocator, &vk, fields[0..1], &fields, .fromVerifierTarget(.evm_no_zk));
    defer testing.allocator.free(request);
    const expected = "\x91\x92\xadCircuitVerify\x84" ++
        "\xb0verification_key\xc4\x03\xab\xab\xab" ++
        "\xadpublic_inputs\x91\xc4\x20" ++ ("\x11" ** 32) ++
        "\xa5proof\x92\xc4\x20" ++ ("\x11" ** 32) ++ "\xc4\x20" ++ ("\x22" ** 32) ++
        "\xa8settings\x84" ++
        "\xb0ipa_accumulation\xc2" ++
        "\xb0oracle_hash_type\xa6keccak" ++
        "\xaadisable_zk\xc3" ++
        "\xbboptimized_solidity_verifier\xc2";
    try testing.expectEqualSlices(u8, expected, request);
}

test "noir: fieldsFromBytes splits on 32-byte boundaries" {
    const raw = [_]u8{7} ** 96;
    const fields = try fieldsFromBytes(&raw);
    try testing.expectEqual(@as(usize, 3), fields.len);
    try testing.expectEqualSlices(u8, raw[32..64], &fields[1]);
    try testing.expectEqual(@as(usize, 0), (try fieldsFromBytes("")).len);
    try testing.expectError(error.InvalidLength, fieldsFromBytes(raw[0..33]));
}

test "noir: response decoder accepts the pinned CircuitVerifyResponse shape" {
    const yes = "\x92\xb5CircuitVerifyResponse\x81\xa8verified\xc3";
    try testing.expectEqual(@as(usize, 34), yes.len);
    try testing.expect(try parseVerifyResponse(yes, null));
    const no = "\x92\xb5CircuitVerifyResponse\x81\xa8verified\xc2";
    try testing.expect(!try parseVerifyResponse(no, null));
}

test "noir: response decoder maps ErrorResponse to ProofRejected with the message" {
    const err = "\x92\xadErrorResponse\x81\xa7message\xb3point not on curve!";
    var diag: Diagnostics = .{};
    try testing.expectError(error.ProofRejected, parseVerifyResponse(err, &diag));
    try testing.expectEqualStrings("point not on curve!", diag.message());
    // SrsInitSrs errors get their own tag.
    try testing.expectError(error.SrsInitFailed, parseSrsInitResponse(err, null));
}

test "noir: response decoder rejects schema drift instead of guessing" {
    var diag: Diagnostics = .{};
    // Unknown response name.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xa9Something\x80", &diag));
    // Right name, extra field.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xb5CircuitVerifyResponse\x82\xa8verified\xc3\xa5extra\xc0", &diag));
    // Right name, renamed field.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xb5CircuitVerifyResponse\x81\xa2ok\xc3", &diag));
    // Right name, wrong value type.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xb5CircuitVerifyResponse\x81\xa8verified\x01", &diag));
    // Trailing bytes.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xb5CircuitVerifyResponse\x81\xa8verified\xc3\xc0", &diag));
    // Truncated and empty.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x92\xb5CircuitVerifyResponse\x81\xa8verif", &diag));
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("", &diag));
    // Envelope of the wrong arity.
    try testing.expectError(error.UnexpectedResponse, parseVerifyResponse("\x91\xb5CircuitVerifyResponse", &diag));
    // SrsInitSrsResponse with a non-bin payload.
    try testing.expectError(error.UnexpectedResponse, parseSrsInitResponse("\x92\xb2SrsInitSrsResponse\x81\xaapoints_buf\xa0", &diag));
    // A well-formed SrsInitSrsResponse.
    try parseSrsInitResponse("\x92\xb2SrsInitSrsResponse\x81\xaapoints_buf\xc4\x00", &diag);
}
