//! ABI word readers and zero-copy views shared by the router calldata
//! decoders (`calldata.zig`, `v4.zig`, `routers.zig`). Every function returns
//! null or a value and never panics on any input.

const std = @import("std");
const uint256 = @import("../uint256.zig");

// ============================================================================
// Views
// ============================================================================

/// An ABI `address[]`, borrowed from calldata. Every element's 12 padding
/// bytes were checked to be zero by `decode`, and `decode` guarantees
/// `len() >= 2` (every swap path has a source and a destination token), so
/// `first()` and `last()` are always valid.
pub const AddressPath = struct {
    /// `len() * 32` bytes: the array's elements, one ABI word each.
    words: []const u8,

    pub fn len(self: AddressPath) usize {
        return self.words.len / 32;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: AddressPath, i: usize) [20]u8 {
        std.debug.assert(i < self.len());
        const word = self.words[i * 32 ..][0..32].*;
        return word[12..32].*;
    }

    /// First element. Asserts `len() > 0`.
    pub fn first(self: AddressPath) [20]u8 {
        std.debug.assert(self.len() > 0);
        return self.get(0);
    }

    /// Last element. Asserts `len() > 0`.
    pub fn last(self: AddressPath) [20]u8 {
        const n = self.len();
        std.debug.assert(n > 0);
        return self.get(n - 1);
    }
};

/// A Uniswap V3 packed path `token(20) fee(3) token(20) [fee(3) token(20)]...`,
/// borrowed from calldata. `decode` checked that its length is `20 + 23 * k`
/// with `k >= 1`.
///
/// Exact-output paths are encoded in reverse: `first()` is the token out and
/// `last()` is the token in.
pub const V3Path = struct {
    bytes: []const u8,

    pub const Hop = struct {
        token_a: [20]u8,
        /// The pool's fee tier. On Aerodrome/Velodrome Slipstream paths the same
        /// 3 bytes hold the pool's `int24` tick spacing; see `tickSpacing`.
        fee: u24,
        token_b: [20]u8,

        /// The 3-byte pool field read as a Slipstream `int24` tick spacing.
        pub fn tickSpacing(self: Hop) i24 {
            return @bitCast(self.fee);
        }
    };

    /// Number of pools traversed (`k`). Always at least 1.
    pub fn hops(self: V3Path) usize {
        return (self.bytes.len - 20) / 23;
    }

    /// Hop `i`. Asserts `i < hops()`.
    pub fn hop(self: V3Path, i: usize) Hop {
        std.debug.assert(i < self.hops());
        const off = i * 23;
        return .{
            .token_a = self.bytes[off..][0..20].*,
            .fee = std.mem.readInt(u24, self.bytes[off + 20 ..][0..3], .big),
            .token_b = self.bytes[off + 23 ..][0..20].*,
        };
    }

    pub fn first(self: V3Path) [20]u8 {
        return self.bytes[0..20].*;
    }

    pub fn last(self: V3Path) [20]u8 {
        return self.bytes[self.bytes.len - 20 ..][0..20].*;
    }
};

/// An Algebra (Camelot V3) packed path `token(20) token(20) [token(20)]...`,
/// with no fee bytes, borrowed from calldata. `decodeFor` checked that its
/// length is `20 * n` with `n >= 2`. Exact-output paths are reversed.
pub const AlgebraPath = struct {
    bytes: []const u8,

    /// Number of tokens (hops + 1). Always at least 2.
    pub fn len(self: AlgebraPath) usize {
        return self.bytes.len / 20;
    }

    /// Token `i`. Asserts `i < len()`.
    pub fn get(self: AlgebraPath, i: usize) [20]u8 {
        std.debug.assert(i < self.len());
        return self.bytes[i * 20 ..][0..20].*;
    }

    pub fn first(self: AlgebraPath) [20]u8 {
        return self.get(0);
    }

    pub fn last(self: AlgebraPath) [20]u8 {
        return self.get(self.len() - 1);
    }
};

/// An ABI `uint256[]`, borrowed from calldata.
pub const U256Array = struct {
    /// `len() * 32` bytes.
    words: []const u8,

    pub fn len(self: U256Array) usize {
        return self.words.len / 32;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: U256Array, i: usize) u256 {
        std.debug.assert(i < self.len());
        return uint256.fromBigEndianBytes(self.words[i * 32 ..][0..32].*);
    }
};

/// An ABI `bytes[]`, borrowed from calldata. `decode` checked every element's
/// offset and length, and that the array is canonical: element `i`'s offset
/// is at or past element `i - 1`'s data end, rounded up to a 32-byte word.
/// This rejects aliased or overlapping elements and keeps validation linear
/// in `data.len`.
pub const BytesArray = struct {
    /// The array's tail: starts at the first element's offset word, i.e.
    /// immediately after the length word. Element offsets are relative to it.
    head: []const u8,
    count: usize,

    pub fn len(self: BytesArray) usize {
        return self.count;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: BytesArray, i: usize) []const u8 {
        std.debug.assert(i < self.count);
        return bytesAt(self.head, 0, i * 32) orelse unreachable;
    }
};

// ============================================================================
// Decoding: safe arithmetic and word-level readers
// ============================================================================
//
// Every helper below either returns null or a value; none can panic. Offsets
// and lengths taken from calldata are always u256 words, range-checked into
// usize before any arithmetic touches them, and every byte range is bounds
// checked against `data.len` before it is sliced.

pub fn addChecked(a: usize, b: usize) ?usize {
    return std.math.add(usize, a, b) catch null;
}

pub fn mulChecked(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

/// Round `n` up to the next 32-byte word boundary, checked against overflow.
pub fn roundUpWord(n: usize) ?usize {
    const padded = addChecked(n, 31) orelse return null;
    return padded & ~@as(usize, 31);
}

pub fn wordToUsize(w: u256) ?usize {
    if (w > std.math.maxInt(usize)) return null;
    return @intCast(w);
}

pub fn isZeroSlice(s: []const u8) bool {
    for (s) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Read the 32-byte word at `offset`, or null if it runs past `data`.
pub fn readWord(data: []const u8, offset: usize) ?[32]u8 {
    const end = addChecked(offset, 32) orelse return null;
    if (end > data.len) return null;
    return data[offset..][0..32].*;
}

pub fn readU256At(data: []const u8, offset: usize) ?u256 {
    const w = readWord(data, offset) orelse return null;
    return uint256.fromBigEndianBytes(w);
}

/// Read a word meant to be used as an offset or length, range-checked into
/// `usize` before any arithmetic can touch it.
pub fn readOffset(data: []const u8, word_pos: usize) ?usize {
    const w = readU256At(data, word_pos) orelse return null;
    return wordToUsize(w);
}

/// A clean ABI address word: 12 zero high bytes, address in the low 20.
pub fn readAddressAt(data: []const u8, pos: usize) ?[20]u8 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..12])) return null;
    return w[12..32].*;
}

/// A clean ABI bool word: all zero except the last byte, which is 0 or 1.
pub fn readBoolAt(data: []const u8, pos: usize) ?bool {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..31])) return null;
    if (w[31] > 1) return null;
    return w[31] == 1;
}

/// A clean ABI uint24 word: only the low 3 bytes may be set.
pub fn readFeeAt(data: []const u8, pos: usize) ?u24 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..29])) return null;
    return std.mem.readInt(u24, w[29..32], .big);
}

/// A clean ABI `uintN` word (N a multiple of 8): the high bytes must be zero.
pub fn readUintAt(comptime T: type, data: []const u8, pos: usize) ?T {
    const bytes = @divExact(@typeInfo(T).int.bits, 8);
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0 .. 32 - bytes])) return null;
    return std.mem.readInt(T, w[32 - bytes ..][0..bytes], .big);
}

/// A clean ABI `intN` word (N a multiple of 8): the high bytes must be the
/// sign extension of the value.
pub fn readIntAt(comptime T: type, data: []const u8, pos: usize) ?T {
    const bytes = @divExact(@typeInfo(T).int.bits, 8);
    const w = readWord(data, pos) orelse return null;
    const v = std.mem.readInt(T, w[32 - bytes ..][0..bytes], .big);
    const fill: u8 = if (v < 0) 0xff else 0x00;
    for (w[0 .. 32 - bytes]) |b| if (b != fill) return null;
    return v;
}

/// A clean ABI uint160 word: only the low 20 bytes may be set.
pub fn readU160At(data: []const u8, pos: usize) ?u160 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..12])) return null;
    return std.mem.readInt(u160, w[12..32], .big);
}

/// The 4-byte selector as a big-endian u32, or null if `data` is shorter.
pub fn readSelectorU32(data: []const u8) ?u32 {
    if (data.len < 4) return null;
    return std.mem.readInt(u32, data[0..4], .big);
}

pub fn selU32(s: [4]u8) u32 {
    return std.mem.readInt(u32, &s, .big);
}

// ============================================================================
// Decoding: dynamic value locators
// ============================================================================
//
// `base` is the start of the enclosing tuple or argument block; `offset_word_pos`
// is the absolute position of the word holding the offset, relative to `base`.

/// Locate a dynamic `bytes` value's content.
pub fn bytesAt(data: []const u8, base: usize, offset_word_pos: usize) ?[]const u8 {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const start = addChecked(base, off) orelse return null;
    const len = wordToUsize(readU256At(data, start) orelse return null) orelse return null;
    const content_start = addChecked(start, 32) orelse return null;
    const content_end = addChecked(content_start, len) orelse return null;
    if (content_end > data.len) return null;
    return data[content_start..content_end];
}

pub const ArrayHead = struct {
    /// First element's byte position (right after the length word).
    start: usize,
    /// End of the head words region (`start + count * 32`).
    end: usize,
    count: usize,
};

/// Locate a dynamic array's length and head-words region, bounds checked.
pub fn arrayHeadAt(data: []const u8, base: usize, offset_word_pos: usize) ?ArrayHead {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const arr_start = addChecked(base, off) orelse return null;
    const count = wordToUsize(readU256At(data, arr_start) orelse return null) orelse return null;
    const head_start = addChecked(arr_start, 32) orelse return null;
    const head_len = mulChecked(count, 32) orelse return null;
    const head_end = addChecked(head_start, head_len) orelse return null;
    if (head_end > data.len) return null;
    return .{ .start = head_start, .end = head_end, .count = count };
}

/// An `address[]` swap path, validating every element's padding eagerly and
/// requiring at least 2 elements (a swap path always has a source and a
/// destination token; see UniswapV2Library.sol:63,74 and UR
/// V2SwapRouter.sol:75,112).
pub fn addressArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?AddressPath {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    if (h.count < 2) return null;
    const words = data[h.start..h.end];
    var i: usize = 0;
    while (i < h.count) : (i += 1) {
        if (!isZeroSlice(words[i * 32 ..][0..12])) return null;
    }
    return .{ .words = words };
}

/// A `uint256[]`; every 32-byte word is a valid element.
pub fn u256ArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?U256Array {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    return .{ .words = data[h.start..h.end] };
}

/// A `bytes[]` array's location, requiring a canonical layout: element `i`'s
/// offset must be at or past element `i - 1`'s data end, rounded up to a
/// 32-byte word. This rejects aliased or overlapping elements and keeps
/// validation linear in `data.len`. Used for both multicall calls and UR
/// inputs, which share this requirement.
pub fn bytesArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?BytesArray {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    const head = data[h.start..];
    var prev_end: usize = 0;
    var i: usize = 0;
    while (i < h.count) : (i += 1) {
        const off = readOffset(head, i * 32) orelse return null;
        if (i > 0 and off < prev_end) return null;
        const elem_len = wordToUsize(readU256At(head, off) orelse return null) orelse return null;
        const content_start = addChecked(off, 32) orelse return null;
        const content_end = addChecked(content_start, elem_len) orelse return null;
        if (content_end > head.len) return null;
        prev_end = roundUpWord(content_end) orelse return null;
    }
    return .{ .head = head, .count = h.count };
}

/// `k` for a V3 packed path of this byte length, or null if it isn't
/// `20 + 23 * k` with `k >= 1`.
pub fn v3PathHops(len: usize) ?usize {
    if (len < 43) return null;
    const rem = len - 20;
    if (rem % 23 != 0) return null;
    return rem / 23;
}
