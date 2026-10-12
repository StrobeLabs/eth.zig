// Small, CI-friendly conformance suite backed by upstream Ethereum and Trezor
// vectors. Run with: zig build conformance-test

const std = @import("std");
const eth = @import("eth");

const rlp_vectors = @embedFile("vectors/rlp.json");
const transaction_vectors = @embedFile("vectors/transactions.json");
const bip39_vectors = @embedFile("vectors/bip39_english.json");

test "official RLP vectors" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, rlp_vectors, .{});
    defer parsed.deinit();

    for (parsed.value.object.get("valid").?.array.items) |case| {
        const encoded = try decodeHex(allocator, case.object.get("encoded").?.string);
        defer allocator.free(encoded);
        try eth.rlp.validate(encoded);
    }

    for (parsed.value.object.get("invalid").?.array.items) |case| {
        const encoded = try decodeHex(allocator, case.object.get("encoded").?.string);
        defer allocator.free(encoded);
        if (eth.rlp.validate(encoded)) |_| {
            return error.InvalidVectorAccepted;
        } else |_| {}
    }
}

test "official transaction envelope vectors" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, transaction_vectors, .{});
    defer parsed.deinit();

    for (parsed.value.array.items) |case| {
        const obj = case.object;
        const tx = try decodeHex(allocator, obj.get("txbytes").?.string);
        defer allocator.free(tx);
        const tx_type: u8 = @intCast(obj.get("type").?.integer);

        if (tx_type == 0) {
            try eth.rlp.validate(tx);
        } else {
            try std.testing.expect(tx.len > 1);
            try std.testing.expectEqual(tx_type, tx[0]);
            try eth.rlp.validate(tx[1..]);
        }

        if (obj.get("hash")) |hash_value| {
            const expected = try eth.hex.hexToBytesFixed(32, hash_value.string);
            const actual = eth.keccak.hash(tx);
            try std.testing.expectEqualSlices(u8, &expected, &actual);
        }
    }
}

test "Trezor BIP-39 English vectors" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bip39_vectors, .{});
    defer parsed.deinit();

    for (parsed.value.array.items) |case| {
        const obj = case.object;
        const words = try splitWords(allocator, obj.get("mnemonic").?.string);
        defer allocator.free(words);

        try eth.mnemonic.validate(words);
        const seed = try eth.mnemonic.toSeed(words, "TREZOR");
        var expected_seed: [64]u8 = undefined;
        _ = try eth.hex.hexToBytes(&expected_seed, obj.get("seed").?.string);
        try std.testing.expectEqualSlices(u8, &expected_seed, &seed);

        const entropy = try decodeHex(allocator, obj.get("entropy").?.string);
        defer allocator.free(entropy);
        try expectGeneratedMnemonic(entropy, words);
    }
}

fn decodeHex(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const source = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    const result = try allocator.alloc(u8, source.len / 2);
    errdefer allocator.free(result);
    _ = try eth.hex.hexToBytes(result, source);
    return result;
}

fn splitWords(allocator: std.mem.Allocator, phrase: []const u8) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    errdefer words.deinit(allocator);
    var split = std.mem.splitScalar(u8, phrase, ' ');
    while (split.next()) |word| try words.append(allocator, word);
    return words.toOwnedSlice(allocator);
}

fn expectGeneratedMnemonic(entropy: []const u8, expected: []const []const u8) !void {
    switch (entropy.len) {
        16 => try expectGeneratedMnemonicFor(.@"128", entropy, expected),
        20 => try expectGeneratedMnemonicFor(.@"160", entropy, expected),
        24 => try expectGeneratedMnemonicFor(.@"192", entropy, expected),
        28 => try expectGeneratedMnemonicFor(.@"224", entropy, expected),
        32 => try expectGeneratedMnemonicFor(.@"256", entropy, expected),
        else => return error.InvalidEntropyLength,
    }
}

fn expectGeneratedMnemonicFor(comptime size: eth.mnemonic.ValidEntropySize, bytes: []const u8, expected: []const []const u8) !void {
    var entropy: [@backingInt(size)]u8 = undefined;
    @memcpy(&entropy, bytes);
    const generated = eth.mnemonic.entropyToMnemonic(size, &entropy);
    try std.testing.expectEqual(generated.len, expected.len);
    for (generated, expected) |actual, want| {
        try std.testing.expectEqualStrings(want, actual);
    }
}

