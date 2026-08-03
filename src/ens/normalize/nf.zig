const std = @import("std");
const Decoder = @import("decoder.zig").Decoder;
const RuneSet = @import("rune_set.zig").RuneSet;

const nf_bin = @embedFile("data/nf.bin");

/// Packed decomposition-buffer entries carry the canonical combining class
/// in the high 8 bits and the codepoint in the low 24 bits. Mirrors
/// go-ens-normalize's `nf.go` SHIFT/MASK, where a packed entry is a Go
/// `rune` (int32) holding `cc<<24 | cp`. Unlike Go, `composePair` and the
/// decomposition stack return `?u21`/optional codepoints instead of a `-1`
/// (`NONE`) sentinel value.
const SHIFT: u5 = 24;
const MASK: u32 = (1 << SHIFT) - 1;

const S0: u21 = 0xAC00;
const L0: u21 = 0x1100;
const V0: u21 = 0x1161;
const T0: u21 = 0x11A7;
const L_COUNT: u21 = 19;
const V_COUNT: u21 = 21;
const T_COUNT: u21 = 28;
const N_COUNT: u21 = V_COUNT * T_COUNT;
const S_COUNT: u21 = L_COUNT * N_COUNT;
const S1: u21 = S0 + S_COUNT;
const L1: u21 = L0 + L_COUNT;
const V1: u21 = V0 + V_COUNT;
const T1: u21 = T0 + T_COUNT;

fn isHangul(cp: u21) bool {
    return cp >= S0 and cp < S1;
}

fn unpackCC(pk: u32) u8 {
    return @intCast(pk >> SHIFT);
}

fn unpackCP(pk: u32) u21 {
    return @intCast(pk & MASK);
}

fn pack(cc: u8, cp: u21) u32 {
    return (@as(u32, cc) << SHIFT) | @as(u32, cp);
}

/// Takes ownership of `v` (freeing it), returning a freshly allocated `[]u21`
/// with the same values. The decoder returns codepoint sets as `[]u32`;
/// `RuneSet` and the NF tables below store `u21` codepoints.
fn intoU21Owned(allocator: std.mem.Allocator, v: []u32) ![]u21 {
    defer allocator.free(v);
    const out = try allocator.alloc(u21, v.len);
    for (v, 0..) |x, i| out[i] = @intCast(x);
    return out;
}

fn freeDecomps(allocator: std.mem.Allocator, decomps: *std.AutoHashMapUnmanaged(u21, []const u21)) void {
    var it = decomps.valueIterator();
    while (it.next()) |slice| allocator.free(slice.*);
    decomps.deinit(allocator);
}

fn freeRecomps(allocator: std.mem.Allocator, recomps: *std.AutoHashMapUnmanaged(u21, std.AutoHashMapUnmanaged(u21, u21))) void {
    var it = recomps.valueIterator();
    while (it.next()) |inner| inner.deinit(allocator);
    recomps.deinit(allocator);
}

/// Accumulates a packed decomposition buffer during `decomposed`. Port of
/// `nf.go`'s `Packer`. `check` tracks whether any packed entry carries a
/// nonzero combining class, so `fixOrder` can skip its stabilization pass
/// entirely for runs that never needed reordering (matching the Go
/// reference's early-return).
const Packer = struct {
    nf: *const NF,
    buf: std.ArrayList(u32),
    check: bool,

    fn add(self: *Packer, allocator: std.mem.Allocator, cp: u21) !void {
        var packed_val: u32 = cp;
        if (self.nf.ranks.get(cp)) |cc| {
            self.check = true;
            packed_val = pack(cc, cp);
        }
        try self.buf.append(allocator, packed_val);
    }

    /// Stable-ish insertion sort that bubbles a combining mark left past any
    /// immediately preceding entries with a strictly higher combining class,
    /// stopping at the first entry with combining class 0 (a "starter",
    /// which never moves and always blocks further leftward movement).
    fn fixOrder(self: *Packer) void {
        if (!self.check) return;
        const v = self.buf.items;
        if (v.len == 0) return;
        var prev = unpackCC(v[0]);
        var i: usize = 1;
        while (i < v.len) : (i += 1) {
            const cc = unpackCC(v[i]);
            if (cc == 0 or prev <= cc) {
                prev = cc;
                continue;
            }
            var j = i - 1;
            while (true) {
                const tmp = v[j + 1];
                v[j + 1] = v[j];
                v[j] = tmp;
                if (j == 0) break;
                j -= 1;
                prev = unpackCC(v[j]);
                if (prev <= cc) break;
            }
            prev = unpackCC(v[i]);
        }
    }
};

/// Unicode Normalization Form C/D (NFC/NFD) tables, decoded once from the
/// embedded `data/nf.bin` blob. Port of go-ens-normalize's `nf/nf.go`.
pub const NF = struct {
    allocator: std.mem.Allocator,
    exclusions: RuneSet,
    quick_check: RuneSet,
    decomps: std.AutoHashMapUnmanaged(u21, []const u21),
    recomps: std.AutoHashMapUnmanaged(u21, std.AutoHashMapUnmanaged(u21, u21)),
    ranks: std.AutoHashMapUnmanaged(u21, u8),

    /// Decodes `data/nf.bin` into the NFC/NFD lookup tables. Port of
    /// go-ens-normalize's `nf.New()`. The table decode order below matches
    /// the Go reference exactly -- the bit stream is order-sensitive.
    /// Tables are allocated with `allocator` and owned by the returned `NF`;
    /// call `deinit` to free them.
    pub fn init(allocator: std.mem.Allocator) !NF {
        var d = try Decoder.init(allocator, nf_bin);
        defer d.deinit();

        // Unicode version string: decoded only to preserve stream order.
        // Not part of this port's public surface (unused by nfc/nfd), so
        // discard it immediately rather than storing it as a field.
        const unicode_version = try d.readString(allocator);
        allocator.free(unicode_version);

        const exclusions = try RuneSet.fromOwnedUnsorted(allocator, try intoU21Owned(allocator, try d.readUnique(allocator)));
        errdefer allocator.free(@constCast(exclusions.sorted));

        const quick_check = try RuneSet.fromOwnedUnsorted(allocator, try intoU21Owned(allocator, try d.readUnique(allocator)));
        errdefer allocator.free(@constCast(quick_check.sorted));

        var decomps: std.AutoHashMapUnmanaged(u21, []const u21) = .empty;
        errdefer freeDecomps(allocator, &decomps);

        var recomps: std.AutoHashMapUnmanaged(u21, std.AutoHashMapUnmanaged(u21, u21)) = .empty;
        errdefer freeRecomps(allocator, &recomps);

        var ranks: std.AutoHashMapUnmanaged(u21, u8) = .empty;
        errdefer ranks.deinit(allocator);

        // Single-codepoint decompositions: decomps[cp] = [x].
        {
            const decomp1 = try d.readSortedUnique(allocator);
            defer allocator.free(decomp1);
            const decomp1a = try d.readUnsortedDeltas(allocator, decomp1.len);
            defer allocator.free(decomp1a);
            for (decomp1, 0..) |cp_raw, i| {
                const one = try allocator.alloc(u21, 1);
                one[0] = @intCast(decomp1a[i]);
                try decomps.put(allocator, @intCast(cp_raw), one);
            }
        }

        // Two-codepoint decompositions: decomps[cp] = [cpB, cpA] (note the
        // reversed storage order -- see `decomposed`'s stack-pop comment).
        // recomps[cpA][cpB] = cp unless cp is a composition exclusion.
        {
            const decomp2 = try d.readSortedUnique(allocator);
            defer allocator.free(decomp2);
            const decomp2a = try d.readUnsortedDeltas(allocator, decomp2.len);
            defer allocator.free(decomp2a);
            const decomp2b = try d.readUnsortedDeltas(allocator, decomp2.len);
            defer allocator.free(decomp2b);
            for (decomp2, 0..) |cp_raw, i| {
                const cp: u21 = @intCast(cp_raw);
                const cp_a: u21 = @intCast(decomp2a[i]);
                const cp_b: u21 = @intCast(decomp2b[i]);
                const pair = try allocator.alloc(u21, 2);
                pair[0] = cp_b;
                pair[1] = cp_a;
                try decomps.put(allocator, cp, pair);
                if (!exclusions.contains(cp)) {
                    const gop = try recomps.getOrPut(allocator, cp_a);
                    if (!gop.found_existing) gop.value_ptr.* = .empty;
                    try gop.value_ptr.put(allocator, cp_b, cp);
                }
            }
        }

        // Combining-class ranks: successive ReadUnique groups, rank = 1-based
        // group index, terminated by an empty group.
        {
            var i: u32 = 1;
            while (true) : (i += 1) {
                const v = try d.readUnique(allocator);
                defer allocator.free(v);
                if (v.len == 0) break;
                const rank: u8 = @intCast(i);
                for (v) |cp_raw| try ranks.put(allocator, @intCast(cp_raw), rank);
            }
        }

        d.assertEof();

        return NF{
            .allocator = allocator,
            .exclusions = exclusions,
            .quick_check = quick_check,
            .decomps = decomps,
            .recomps = recomps,
            .ranks = ranks,
        };
    }

    /// Frees all tables allocated by `init`. Production use (Task 4)
    /// initializes once with `page_allocator` for the process lifetime and
    /// never calls this; it exists so tests can run under
    /// `std.testing.allocator`'s leak checker.
    pub fn deinit(self: *NF) void {
        self.allocator.free(@constCast(self.exclusions.sorted));
        self.allocator.free(@constCast(self.quick_check.sorted));
        freeDecomps(self.allocator, &self.decomps);
        freeRecomps(self.allocator, &self.recomps);
        self.ranks.deinit(self.allocator);
    }

    fn composePair(self: *const NF, a: u21, b: u21) ?u21 {
        if (a >= L0 and a < L1 and b >= V0 and b < V1) {
            return S0 + (a - L0) * N_COUNT + (b - V0) * T_COUNT;
        } else if (isHangul(a) and b > T0 and b < T1 and (a - S0) % T_COUNT == 0) {
            return a + (b - T0);
        } else {
            if (self.recomps.get(a)) |inner| {
                if (inner.get(b)) |cp| return cp;
            }
            return null;
        }
    }

    /// Port of `nf.go`'s `decomposed`: fully decomposes `cps` (including
    /// algorithmic Hangul decomposition) into a packed (cc<<24|cp) buffer,
    /// then stabilizes combining-mark order via `Packer.fixOrder`.
    ///
    /// Each input codepoint's multi-codepoint decomposition is processed via
    /// a shared work stack. `decomps[cp]` is stored as `[cpB, cpA]`, so
    /// pushing it and popping from the end yields `cpA` (the base/starter)
    /// before `cpB` (the combining mark) -- matching canonical decomposition
    /// order (base, then mark) once both are recursively fully decomposed.
    fn decomposedPacked(self: *const NF, allocator: std.mem.Allocator, cps: []const u21) ![]u32 {
        var packer = Packer{ .nf = self, .buf = .empty, .check = false };
        errdefer packer.buf.deinit(allocator);

        var stack: std.ArrayList(u21) = .empty;
        defer stack.deinit(allocator);

        for (cps) |cp0| {
            var cp = cp0;
            while (true) {
                if (cp < 0x80) {
                    try packer.buf.append(allocator, cp);
                } else if (isHangul(cp)) {
                    const s_index = cp - S0;
                    const l_index = s_index / N_COUNT;
                    const v_index = (s_index % N_COUNT) / T_COUNT;
                    const t_index = s_index % T_COUNT;
                    try packer.add(allocator, L0 + l_index);
                    try packer.add(allocator, V0 + v_index);
                    if (t_index > 0) try packer.add(allocator, T0 + t_index);
                } else {
                    if (self.decomps.get(cp)) |decomp| {
                        try stack.appendSlice(allocator, decomp);
                    } else {
                        try packer.add(allocator, cp);
                    }
                }
                if (stack.items.len == 0) break;
                const last = stack.items.len - 1;
                cp = stack.items[last];
                stack.shrinkRetainingCapacity(last);
            }
        }

        packer.fixOrder();
        return packer.buf.toOwnedSlice(allocator);
    }

    /// Port of `nf.go`'s `composedFromPacked`: greedily recomposes a packed
    /// decomposition buffer (as produced by `decomposedPacked`) into NFC.
    fn composedFromPacked(self: *const NF, allocator: std.mem.Allocator, entries: []const u32) ![]u21 {
        var cps: std.ArrayList(u21) = .empty;
        errdefer cps.deinit(allocator);
        var stack: std.ArrayList(u21) = .empty;
        defer stack.deinit(allocator);

        var prev_cp: ?u21 = null;
        var prev_cc: u8 = 0;

        for (entries) |p| {
            const cc = unpackCC(p);
            const cp = unpackCP(p);
            if (prev_cp == null) {
                if (cc == 0) {
                    prev_cp = cp;
                } else {
                    try cps.append(allocator, cp);
                }
            } else if (prev_cc > 0 and prev_cc >= cc) {
                if (cc == 0) {
                    try cps.append(allocator, prev_cp.?);
                    try cps.appendSlice(allocator, stack.items);
                    stack.clearRetainingCapacity();
                    prev_cp = cp;
                } else {
                    try stack.append(allocator, cp);
                }
                prev_cc = cc;
            } else {
                const composed = self.composePair(prev_cp.?, cp);
                if (composed) |c| {
                    prev_cp = c;
                } else if (prev_cc == 0 and cc == 0) {
                    try cps.append(allocator, prev_cp.?);
                    prev_cp = cp;
                } else {
                    try stack.append(allocator, cp);
                    prev_cc = cc;
                }
            }
        }
        if (prev_cp) |final_cp| {
            try cps.append(allocator, final_cp);
            try cps.appendSlice(allocator, stack.items);
        }
        return cps.toOwnedSlice(allocator);
    }

    /// Returns the Unicode Normalization Form D (fully decomposed, canonical
    /// order) of `cps`. Caller owns the returned slice.
    pub fn nfd(self: *const NF, allocator: std.mem.Allocator, cps: []const u21) ![]u21 {
        const entries = try self.decomposedPacked(allocator, cps);
        defer allocator.free(entries);
        const out = try allocator.alloc(u21, entries.len);
        errdefer allocator.free(out);
        for (entries, 0..) |x, i| out[i] = unpackCP(x);
        return out;
    }

    /// Returns the Unicode Normalization Form C (decomposed then greedily
    /// recomposed) of `cps`. Caller owns the returned slice.
    pub fn nfc(self: *const NF, allocator: std.mem.Allocator, cps: []const u21) ![]u21 {
        const entries = try self.decomposedPacked(allocator, cps);
        defer allocator.free(entries);
        return self.composedFromPacked(allocator, entries);
    }
};

test "nfc composes e + combining acute" {
    const allocator = std.testing.allocator;
    var nf_tables = try NF.init(allocator);
    defer nf_tables.deinit();
    const out = try nf_tables.nfc(allocator, &.{ 0x65, 0x301 });
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u21, &.{0xE9}, out);
}

test "nfd decomposes e-acute" {
    const allocator = std.testing.allocator;
    var nf_tables = try NF.init(allocator);
    defer nf_tables.deinit();
    const out = try nf_tables.nfd(allocator, &.{0xE9});
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u21, &.{ 0x65, 0x301 }, out);
}

test "nfc composes Hangul jamo" {
    const allocator = std.testing.allocator;
    var nf_tables = try NF.init(allocator);
    defer nf_tables.deinit();
    const out = try nf_tables.nfc(allocator, &.{ 0x1100, 0x1161 });
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u21, &.{0xAC00}, out);
}
