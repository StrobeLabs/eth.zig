// Barretenberg v5.2.0 interop vectors for eth.noir.
//
// Verifies real UltraHonk proofs written by the bb CLI (bb 5.2.0, nargo
// 1.0.0-beta.25) for the hello circuit under tests/vectors/noir/, in both the
// poseidon2 (default) and keccak ("evm") flavors, and pins the exact request
// bytes eth.noir sends to the library against reference requests produced by
// an independent encoder and confirmed against the library at runtime.
//
// Only built and run when the build links Barretenberg:
//   zig build test -Dnoir=true

const std = @import("std");
const eth = @import("eth");
const noir = eth.noir;

const testing = std.testing;

const p2_vk = @embedFile("vectors/noir/poseidon2/vk");
const p2_proof = @embedFile("vectors/noir/poseidon2/proof");
const p2_public_inputs = @embedFile("vectors/noir/poseidon2/public_inputs");

const kc_vk = @embedFile("vectors/noir/keccak/vk");
const kc_proof = @embedFile("vectors/noir/keccak/proof");
const kc_public_inputs = @embedFile("vectors/noir/keccak/public_inputs");

const req_srs_g1only = @embedFile("vectors/noir/requests/req_srs_g1only.bin");
const req_verify_default = @embedFile("vectors/noir/requests/req_verify_default.bin");
const req_verify_evm = @embedFile("vectors/noir/requests/req_verify_evm.bin");

test "noir vectors: bb artifacts have the documented sizes" {
    // poseidon2 proofs are padded to CONST_PROOF_SIZE_LOG_N; keccak (evm) proofs are not.
    try testing.expectEqual(@as(usize, 458), (try noir.fieldsFromBytes(p2_proof)).len);
    try testing.expectEqual(@as(usize, 3680), p2_vk.len);
    try testing.expectEqual(@as(usize, 142), (try noir.fieldsFromBytes(kc_proof)).len);
    try testing.expectEqual(@as(usize, 1888), kc_vk.len);
    // The circuit has one public input, y = 2.
    const inputs = try noir.fieldsFromBytes(p2_public_inputs);
    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(u8, 2), inputs[0][31]);
    try testing.expectEqualSlices(u8, p2_public_inputs, kc_public_inputs);
}

test "noir vectors: poseidon2 ZK proof verifies" {
    try noir.init();
    const ok = try noir.verify(
        testing.allocator,
        p2_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        try noir.fieldsFromBytes(p2_proof),
        .fromVerifierTarget(.default),
    );
    try testing.expect(ok);
}

test "noir vectors: keccak ZK (evm) proof verifies" {
    try noir.init();
    const ok = try noir.verify(
        testing.allocator,
        kc_vk,
        try noir.fieldsFromBytes(kc_public_inputs),
        try noir.fieldsFromBytes(kc_proof),
        .fromVerifierTarget(.evm),
    );
    try testing.expect(ok);
}

test "noir vectors: tampered proof element is rejected with an error and a message" {
    try noir.init();
    var tampered: [p2_proof.len]u8 = p2_proof.*;
    // Flip the low bit of the last field (the y coordinate of the KZG opening
    // point): the point is no longer on the curve, so deserialization fails.
    tampered[tampered.len - 1] ^= 0x01;
    var diag: noir.Diagnostics = .{};
    try testing.expectError(error.ProofRejected, noir.verifyDiag(
        testing.allocator,
        p2_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        try noir.fieldsFromBytes(&tampered),
        .fromVerifierTarget(.default),
        &diag,
    ));
    try testing.expect(diag.message().len > 0);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "curve") != null);
}

test "noir vectors: short proof returns false" {
    try noir.init();
    const full = try noir.fieldsFromBytes(p2_proof);
    const ok = try noir.verify(
        testing.allocator,
        p2_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        full[0 .. full.len - 1],
        .fromVerifierTarget(.default),
    );
    try testing.expect(!ok);
}

test "noir vectors: wrong public input returns false" {
    try noir.init();
    const zero_input = [_][32]u8{[_]u8{0} ** 32};
    const ok = try noir.verify(
        testing.allocator,
        p2_vk,
        &zero_input,
        try noir.fieldsFromBytes(p2_proof),
        .fromVerifierTarget(.default),
    );
    try testing.expect(!ok);
}

test "noir vectors: wrong public input count is rejected with an error" {
    try noir.init();
    // The value-mismatch case above returns false, but a count that disagrees
    // with the verification key is rejected before a verdict is reached. Both
    // mean "not verified"; the distinction is what the docs promise.
    const two_inputs = [_][32]u8{ (try noir.fieldsFromBytes(p2_public_inputs))[0], [_]u8{0} ** 32 };
    for ([_][]const [32]u8{ &.{}, &two_inputs }) |inputs| {
        var diag: noir.Diagnostics = .{};
        try testing.expectError(error.ProofRejected, noir.verifyDiag(
            testing.allocator,
            p2_vk,
            inputs,
            try noir.fieldsFromBytes(p2_proof),
            .fromVerifierTarget(.default),
            &diag,
        ));
        try testing.expect(diag.message().len > 0);
    }
}

test "noir vectors: right-size verification key that does not deserialize is rejected with an error" {
    try noir.init();
    // Same length as the real poseidon2 VK, so the size gate passes and the
    // failure comes from deserialization rather than a verdict.
    const zero_vk = [_]u8{0} ** p2_vk.len;
    var diag: noir.Diagnostics = .{};
    try testing.expectError(error.ProofRejected, noir.verifyDiag(
        testing.allocator,
        &zero_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        try noir.fieldsFromBytes(p2_proof),
        .fromVerifierTarget(.default),
        &diag,
    ));
    try testing.expect(diag.message().len > 0);
}

test "noir vectors: non-canonical field element is rejected with an error" {
    try noir.init();
    var bad: [p2_proof.len]u8 = p2_proof.*;
    // 0xff..ff is >= the BN254 scalar field modulus.
    @memset(bad[0..32], 0xff);
    var diag: noir.Diagnostics = .{};
    try testing.expectError(error.ProofRejected, noir.verifyDiag(
        testing.allocator,
        p2_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        try noir.fieldsFromBytes(&bad),
        .fromVerifierTarget(.default),
        &diag,
    ));
    try testing.expect(diag.message().len > 0);
}

test "noir vectors: flavor mismatch returns false" {
    try noir.init();
    // A keccak proof and VK checked with the poseidon2 settings.
    const ok = try noir.verify(
        testing.allocator,
        kc_vk,
        try noir.fieldsFromBytes(kc_public_inputs),
        try noir.fieldsFromBytes(kc_proof),
        .fromVerifierTarget(.default),
    );
    try testing.expect(!ok);
}

test "noir vectors: concurrent verification across threads" {
    try noir.init();
    // Barretenberg keeps per-process request state with no lock of its own, so
    // eth.noir serializes every bbapi call behind one mutex. This is what would
    // catch that mutex being dropped in a later refactor: without it the
    // threads race on the library's global request object.
    const thread_count = 8;
    const rounds = 5;
    const Worker = struct {
        fn run(index: usize, ok: *bool) void {
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                // Alternate flavors so the threads do not all walk the same path.
                const use_keccak = (index + round) % 2 == 1;
                const verified = if (use_keccak) noir.verify(
                    std.testing.allocator,
                    kc_vk,
                    noir.fieldsFromBytes(kc_public_inputs) catch return,
                    noir.fieldsFromBytes(kc_proof) catch return,
                    .fromVerifierTarget(.evm),
                ) catch return else noir.verify(
                    std.testing.allocator,
                    p2_vk,
                    noir.fieldsFromBytes(p2_public_inputs) catch return,
                    noir.fieldsFromBytes(p2_proof) catch return,
                    .fromVerifierTarget(.default),
                ) catch return;
                if (!verified) return;
            }
            ok.* = true;
        }
    };
    var ok: [thread_count]bool = @splat(false);
    var threads: [thread_count]std.Thread = undefined;
    var spawned: usize = 0;
    for (0..thread_count) |i| {
        threads[i] = std.Thread.spawn(.{}, Worker.run, .{ i, &ok[i] }) catch break;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();
    try testing.expect(spawned > 0);
    for (ok[0..spawned]) |flag| try testing.expect(flag);
}

test "noir vectors: SrsInitSrs request bytes match the reference" {
    const request = try noir.encodeSrsInitSrsRequest(testing.allocator, &noir.BN254_G1_GENERATOR, 1, &noir.BN254_G2_ELEMENT);
    defer testing.allocator.free(request);
    try testing.expectEqualSlices(u8, req_srs_g1only, request);
}

test "noir vectors: CircuitVerify request bytes match the poseidon2 reference" {
    const request = try noir.encodeCircuitVerifyRequest(
        testing.allocator,
        p2_vk,
        try noir.fieldsFromBytes(p2_public_inputs),
        try noir.fieldsFromBytes(p2_proof),
        .fromVerifierTarget(.default),
    );
    defer testing.allocator.free(request);
    try testing.expectEqualSlices(u8, req_verify_default, request);
}

test "noir vectors: CircuitVerify request bytes match the keccak reference" {
    const request = try noir.encodeCircuitVerifyRequest(
        testing.allocator,
        kc_vk,
        try noir.fieldsFromBytes(kc_public_inputs),
        try noir.fieldsFromBytes(kc_proof),
        .fromVerifierTarget(.evm),
    );
    defer testing.allocator.free(request);
    try testing.expectEqualSlices(u8, req_verify_evm, request);
}
