const std = @import("std");
const keccak = @import("../keccak.zig");

/// Compute the namehash of an ENS name according to EIP-137.
///
/// The namehash algorithm recursively hashes labels from right to left:
///   namehash("") = 0x00...00 (32 zero bytes)
///   namehash("eth") = keccak256(namehash("") ++ keccak256("eth"))
///   namehash("foo.eth") = keccak256(namehash("eth") ++ keccak256("foo"))
pub fn namehash(name: []const u8) [32]u8 {
    if (name.len == 0) return [_]u8{0} ** 32;

    var node: [32]u8 = [_]u8{0} ** 32;

    // We need to process labels right-to-left. First, find all label boundaries.
    // Walk backwards through the name to find dot positions.
    var end: usize = name.len;
    var i: usize = name.len;
    while (i > 0) {
        i -= 1;
        if (name[i] == '.') {
            const label = name[i + 1 .. end];
            if (label.len > 0) {
                const label_hash = keccak.hash(label);
                node = keccak.hashConcat(&.{ &node, &label_hash });
            }
            end = i;
        }
    }
    // Process the leftmost label (no leading dot)
    const label = name[0..end];
    if (label.len > 0) {
        const label_hash = keccak.hash(label);
        node = keccak.hashConcat(&.{ &node, &label_hash });
    }

    return node;
}

/// Compute the labelhash (keccak256 of a single label).
/// This is used for registering second-level domains.
/// e.g., labelhash("eth") = keccak256("eth")
pub fn labelhash(label: []const u8) [32]u8 {
    return keccak.hash(label);
}

// ============================================================================
// Tests
// ============================================================================

const hex = @import("../hex.zig");

test "namehash empty string" {
    const result = namehash("");
    const expected = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash eth" {
    const result = namehash("eth");
    const expected = try hex.hexToBytesFixed(32, "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash foo.eth" {
    const result = namehash("foo.eth");
    const expected = try hex.hexToBytesFixed(32, "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash alice.eth" {
    const result = namehash("alice.eth");
    const expected = try hex.hexToBytesFixed(32, "787192fc5378cc32aa956ddfdedbf26b24e8d78e40109add0eea2c1a012c3dec");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash subdomain" {
    // sub.foo.eth should be: keccak256(namehash("foo.eth") ++ keccak256("sub"))
    const foo_eth = namehash("foo.eth");
    const sub_label = keccak.hash("sub");
    const expected = keccak.hashConcat(&.{ &foo_eth, &sub_label });
    const result = namehash("sub.foo.eth");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash deep subdomain" {
    // a.b.c.eth should process right-to-left: eth -> c -> b -> a
    const result = namehash("a.b.c.eth");
    // Verify it manually step by step
    var node: [32]u8 = [_]u8{0} ** 32;
    // eth
    const eth_label = keccak.hash("eth");
    node = keccak.hashConcat(&.{ &node, &eth_label });
    // c
    const c_label = keccak.hash("c");
    node = keccak.hashConcat(&.{ &node, &c_label });
    // b
    const b_label = keccak.hash("b");
    node = keccak.hashConcat(&.{ &node, &b_label });
    // a
    const a_label = keccak.hash("a");
    node = keccak.hashConcat(&.{ &node, &a_label });

    try std.testing.expectEqualSlices(u8, &node, &result);
}

test "labelhash eth" {
    const result = labelhash("eth");
    const expected = keccak.hash("eth");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "labelhash is just keccak256 of the label" {
    const result = labelhash("vitalik");
    const expected = keccak.hash("vitalik");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash single label (no dots)" {
    // A single label like "eth" should produce: keccak256(0x00..00 ++ keccak256("eth"))
    const result = namehash("eth");
    var node: [32]u8 = [_]u8{0} ** 32;
    const eth_hash = keccak.hash("eth");
    node = keccak.hashConcat(&.{ &node, &eth_hash });
    try std.testing.expectEqualSlices(u8, &node, &result);
}

test "namehash consistency - foo.eth decomposed" {
    // namehash("foo.eth") should equal:
    // keccak256(namehash("eth") ++ keccak256("foo"))
    const eth_node = namehash("eth");
    const foo_label = keccak.hash("foo");
    const expected = keccak.hashConcat(&.{ &eth_node, &foo_label });
    const result = namehash("foo.eth");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash vitalik.eth official" {
    const result = namehash("vitalik.eth");
    const expected = try hex.hexToBytesFixed(32, "ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "namehash resolver.eth" {
    // Manually compute: node starts as zeros, then hash "eth", then hash "resolver"
    var node: [32]u8 = [_]u8{0} ** 32;
    const eth_label = keccak.hash("eth");
    node = keccak.hashConcat(&.{ &node, &eth_label });
    const resolver_label = keccak.hash("resolver");
    node = keccak.hashConcat(&.{ &node, &resolver_label });

    const result = namehash("resolver.eth");
    try std.testing.expectEqualSlices(u8, &node, &result);
}

test "namehash trailing dot handling" {
    // A trailing dot produces an empty label at the end which gets skipped
    // by the `if (label.len > 0)` check, so "foo.eth." should equal "foo.eth"
    const with_dot = namehash("foo.eth.");
    const without_dot = namehash("foo.eth");
    try std.testing.expectEqualSlices(u8, &without_dot, &with_dot);
}
