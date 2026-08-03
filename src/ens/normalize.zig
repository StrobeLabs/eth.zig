//! ENSIP-15 ENS name normalization -- public API.
//!
//! Port of adraffy/go-ens-normalize's `ensip15` package. The heavy lifting
//! (table decode, tokenization, script-group and whole-script-confusable
//! validation, emoji sequence matching) lives in `normalize/ensip15.zig`;
//! this file is the thin public surface re-exported from `root.zig` as
//! `ens_normalize`.

const std = @import("std");
const ensip15 = @import("normalize/ensip15.zig");

/// Error set returned by `normalize`. Go's `fmt.Errorf`-wrapped diagnostic
/// chains collapse to these flat variants (see `ensip15.zig` for the mapping).
pub const NormalizeError = ensip15.NormalizeError;

/// ENSIP-15 normalize. Caller owns the returned memory.
///
/// The first call performs a one-time decode of the embedded `spec.bin` /
/// `nf.bin` tables (allocated once with `std.heap.page_allocator` for the
/// process lifetime, guarded by a lock-free atomic once).
pub const normalize = ensip15.normalize;

/// Re-export of the NF (NFC/NFD) implementation so Task 5's vector suite can
/// run Unicode normalization conformance tests directly against it.
pub const testing_nf = @import("normalize/nf.zig");

test "normalize case folds" {
    const allocator = std.testing.allocator;
    const out = try normalize(allocator, "Nick.ETH");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("nick.eth", out);
}

test "normalize is identity on already-normal ascii" {
    const allocator = std.testing.allocator;
    const out = try normalize(allocator, "vitalik.eth");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("vitalik.eth", out);
}

test "normalize rejects empty label" {
    try std.testing.expectError(error.EmptyLabel, normalize(std.testing.allocator, ".eth"));
}

test "normalize rejects underscore not at start" {
    try std.testing.expectError(error.LeadingUnderscore, normalize(std.testing.allocator, "a_b.eth"));
}

test "normalize rejects label extension" {
    try std.testing.expectError(error.InvalidLabelExtension, normalize(std.testing.allocator, "xn--a.eth"));
}

test "normalize handles emoji" {
    const allocator = std.testing.allocator;
    // U+1F4A9 with FE0F -> FE0F is stripped in normalized form
    const out = try normalize(allocator, "\u{1F4A9}\u{FE0F}.eth");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("\u{1F4A9}.eth", out);
}

test "normalize accepts empty string" {
    const allocator = std.testing.allocator;
    const out = try normalize(allocator, "");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}
