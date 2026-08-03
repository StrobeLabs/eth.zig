//! ENSIP-15 name normalization core.
//!
//! Port of adraffy/go-ens-normalize's `ensip15/` package (pinned at 165fa80):
//! `shared.go`, `getters.go`, `utils.go`, `emojis.go`, `groups.go`,
//! `wholes.go`, `output.go`, `errors.go`, `ensip15.go`. Section comments below
//! mirror the Go file layout.
//!
//! Only the `Normalize` transform is ported here; `Beautify` and
//! `NormalizeFragment` (and the diagnostic `SafeCodepoint`/`SafeImplode`
//! message-building helpers) are deliberately omitted -- Go's wrapped
//! `fmt.Errorf` chains collapse to the flat `NormalizeError` set, so the
//! per-error diagnostic text is not reconstructed. Those are a follow-up PR.
//!
//! Memory model: the vendored `spec.bin`/`nf.bin` tables are decoded exactly
//! once, into a process-lifetime `Ensip15` allocated with
//! `std.heap.page_allocator` (guarded by a lock-free atomic once). Each
//! `normalize` call runs entirely inside an `ArenaAllocator` layered over the
//! caller's allocator; only the final normalized bytes are duped out with the
//! caller's allocator before the arena is torn down.

const std = @import("std");
const Decoder = @import("decoder.zig").Decoder;
const RuneSet = @import("rune_set.zig").RuneSet;
const NF = @import("nf.zig").NF;

/// The vendored ENSIP-15 spec table (script groups, emojis, whole-script
/// confusables, mapped/ignored/fenced sets). Decoded once by `Ensip15.init`.
const compressed = @embedFile("data/spec.bin");

// ============================================================================
// errors.go
//
// Go's package-level `ErrX` sentinels are wrapped with `fmt.Errorf("%w: ...")`
// to attach human-readable context. This port drops the context and exposes a
// flat error set. Mapping: ErrLeadingUnderscore -> LeadingUnderscore,
// ErrCMLeading -> CombiningMarkLeading, ErrCMAfterEmoji -> CombiningMarkAfterEmoji,
// ErrNSMDuplicate -> NsmDuplicate, ErrNSMExcessive -> NsmExcessive; all others
// map 1:1 by name.
// ============================================================================

/// Every way ENSIP-15 normalization can reject a name (plus `OutOfMemory` from
/// the per-call arena and `InvalidUtf8` from decoding the input bytes).
pub const NormalizeError = error{
    InvalidUtf8,
    EmptyLabel,
    DisallowedCharacter,
    IllegalMixture,
    WholeConfusable,
    /// Underscore is only allowed as a run at the very start of a label.
    LeadingUnderscore,
    /// Characters 3 and 4 are both hyphens (the `xn--` label-extension rule).
    InvalidLabelExtension,
    FencedLeading,
    FencedAdjacent,
    FencedTrailing,
    CombiningMarkLeading,
    CombiningMarkAfterEmoji,
    /// Duplicate non-spacing marks within a combining sequence.
    NsmDuplicate,
    /// More than the allowed number of non-spacing marks in a sequence.
    NsmExcessive,
    OutOfMemory,
};

// ============================================================================
// emojis.go
// ============================================================================

const FE0F: u21 = 0xFE0F;
const ZWJ: u21 = 0x200D;

/// A recognized emoji: `normalized` is `beautified` with every FE0F stripped
/// (or the same backing slice when there is no FE0F to strip).
const EmojiSequence = struct {
    normalized: []const u21,
    beautified: []const u21,
};

/// Recursive decode of the emoji trie payload. `prev` is the codepoint path
/// accumulated so far (owned by the caller/scratch); each decoded sequence's
/// `normalized`/`beautified` slices are allocated with `persist`.
fn decodeEmojis(
    persist: std.mem.Allocator,
    scratch: std.mem.Allocator,
    d: *Decoder,
    prev: []const u21,
    out: *std.ArrayList(EmojiSequence),
) !void {
    {
        const n = d.readUnsigned();
        const leaves = try d.readSortedAscending(scratch, n);
        for (leaves) |cp_raw| {
            const cp: u21 = @intCast(cp_raw);
            const beautified = try persist.alloc(u21, prev.len + 1);
            @memcpy(beautified[0..prev.len], prev);
            beautified[prev.len] = cp;
            var cnt: usize = 0;
            for (beautified) |x| {
                if (x != FE0F) cnt += 1;
            }
            const normalized = if (cnt == beautified.len) beautified else blk: {
                const nz = try persist.alloc(u21, cnt);
                var k: usize = 0;
                for (beautified) |x| {
                    if (x != FE0F) {
                        nz[k] = x;
                        k += 1;
                    }
                }
                break :blk nz;
            };
            try out.append(persist, .{ .normalized = normalized, .beautified = beautified });
        }
    }
    {
        const n = d.readUnsigned();
        const branches = try d.readSortedAscending(scratch, n);
        for (branches) |cp_raw| {
            const cp: u21 = @intCast(cp_raw);
            const prev2 = try scratch.alloc(u21, prev.len + 1);
            @memcpy(prev2[0..prev.len], prev);
            prev2[prev.len] = cp;
            try decodeEmojis(persist, scratch, d, prev2, out);
        }
    }
}

/// A node in the emoji-matching trie. `children` is keyed by codepoint; FE0F
/// edges are optional (both the FE0F-consumed and FE0F-skipped branches point
/// at the same terminal `emoji`).
const EmojiNode = struct {
    emoji: ?*const EmojiSequence,
    children: std.AutoHashMapUnmanaged(u21, *EmojiNode),

    fn child(node: *EmojiNode, persist: std.mem.Allocator, cp: u21) !*EmojiNode {
        const gop = try node.children.getOrPut(persist, cp);
        if (!gop.found_existing) {
            const n = try persist.create(EmojiNode);
            n.* = .{ .emoji = null, .children = .empty };
            gop.value_ptr.* = n;
        }
        return gop.value_ptr.*;
    }
};

/// Builds the emoji trie from the (already normalized-sorted) `emojis` slice.
/// The stored `node.emoji` pointers alias elements of `emojis`, so that slice
/// must not move after this call. FE0F edges are made optional exactly as in
/// go-ens-normalize's `makeEmojiTree` (append children while keeping the
/// FE0F-skipped nodes in the working set).
fn makeEmojiTree(
    persist: std.mem.Allocator,
    scratch: std.mem.Allocator,
    emojis: []EmojiSequence,
) !*EmojiNode {
    const root = try persist.create(EmojiNode);
    root.* = .{ .emoji = null, .children = .empty };
    var v: std.ArrayList(*EmojiNode) = .empty;
    defer v.deinit(scratch);
    for (emojis) |*emoji| {
        v.clearRetainingCapacity();
        try v.append(scratch, root);
        for (emoji.beautified) |cp| {
            if (cp == FE0F) {
                const len = v.items.len;
                for (0..len) |k| {
                    const node = v.items[k];
                    const c = try node.child(persist, cp);
                    try v.append(scratch, c);
                }
            } else {
                for (v.items) |*slot| {
                    slot.* = try slot.*.child(persist, cp);
                }
            }
        }
        for (v.items) |node| node.emoji = emoji;
    }
    return root;
}

const ParseResult = struct { emoji: ?*const EmojiSequence, end: ?usize };

// ============================================================================
// groups.go
// ============================================================================

/// A script group (Latin, Greek, ...). `index` is its position in
/// `Ensip15.groups`; the synthetic ASCII/EMOJI groups in Go used index -1 but
/// are not reconstructed here (normalize discards the resolved group).
const Group = struct {
    index: i32,
    name: []const u8,
    restricted: bool,
    cm_whitelisted: bool,
    primary: RuneSet,
    secondary: RuneSet,

    fn contains(self: *const Group, cp: u21) bool {
        return self.primary.contains(cp) or self.secondary.contains(cp);
    }
};

fn decodeGroups(persist: std.mem.Allocator, scratch: std.mem.Allocator, d: *Decoder) ![]Group {
    var list: std.ArrayList(Group) = .empty;
    while (true) {
        const name_cps = try d.readString(scratch);
        if (name_cps.len == 0) break;
        const bits = d.readUnsigned();
        const name = try persist.alloc(u8, name_cps.len);
        for (name_cps, 0..) |c, i| name[i] = @intCast(c);
        const primary = try decodeRuneSet(persist, scratch, d);
        const secondary = try decodeRuneSet(persist, scratch, d);
        try list.append(persist, Group{
            .index = @intCast(list.items.len),
            .name = name,
            .restricted = (bits & 1) != 0,
            .cm_whitelisted = (bits & 2) != 0,
            .primary = primary,
            .secondary = secondary,
        });
    }
    return list.toOwnedSlice(persist);
}

// ============================================================================
// wholes.go
// ============================================================================

/// Decodes the whole-script-confusable section into `confusables`, mapping each
/// confused codepoint to its sorted list of "complement" group indices (the
/// groups NOT covered by the codepoint's own extent). The `Whole`/`valid`
/// structures from Go are transient here -- only the per-codepoint complements
/// survive, which is all `checkWhole` consults.
fn decodeWholes(
    persist: std.mem.Allocator,
    scratch: std.mem.Allocator,
    d: *Decoder,
    groups: []const Group,
    confusables: *std.AutoHashMapUnmanaged(u21, []const i32),
) !void {
    const GroupSet = std.AutoHashMapUnmanaged(usize, void);
    const Extent = struct {
        gs: GroupSet,
        cps: std.ArrayList(u21),
    };
    while (true) {
        const confused = try readSortedCps(scratch, d);
        if (confused.len == 0) break;
        const valid = try readSortedCps(scratch, d);

        // cp -> its shared complements slice (persistent), for this whole only.
        var complements: std.AutoHashMapUnmanaged(u21, []const i32) = .empty;
        var cover: GroupSet = .empty;
        var extents: std.ArrayList(*Extent) = .empty;

        var phase: usize = 0;
        while (phase < 2) : (phase += 1) {
            const arr = if (phase == 0) valid else confused;
            for (arr) |cp| {
                var gs: GroupSet = .empty;
                for (groups, 0..) |*g, gi| {
                    if (g.contains(cp)) try gs.put(scratch, gi, {});
                }
                var ext: ?*Extent = null;
                outer: for (extents.items) |x| {
                    var kit = gs.keyIterator();
                    while (kit.next()) |gp| {
                        if (x.gs.contains(gp.*)) {
                            ext = x;
                            break :outer;
                        }
                    }
                }
                if (ext == null) {
                    const e = try scratch.create(Extent);
                    e.* = .{ .gs = .empty, .cps = .empty };
                    try extents.append(scratch, e);
                    ext = e;
                }
                var kit2 = gs.keyIterator();
                while (kit2.next()) |gp| {
                    try ext.?.gs.put(scratch, gp.*, {});
                    try cover.put(scratch, gp.*, {});
                }
                try ext.?.cps.append(scratch, cp);
            }
        }

        for (extents.items) |x| {
            var comps_list: std.ArrayList(i32) = .empty;
            var cit = cover.keyIterator();
            while (cit.next()) |gp| {
                if (!x.gs.contains(gp.*)) try comps_list.append(scratch, groups[gp.*].index);
            }
            const comps_slice = try persist.alloc(i32, comps_list.items.len);
            @memcpy(comps_slice, comps_list.items);
            std.mem.sort(i32, comps_slice, {}, std.sort.asc(i32));
            for (x.cps.items) |cp| try complements.put(scratch, cp, comps_slice);
        }

        for (confused) |cp| {
            const comps = complements.get(cp) orelse &[_]i32{};
            try confusables.put(persist, cp, comps);
        }
    }
}

fn sortedContainsI32(hay: []const i32, needle: i32) bool {
    return std.sort.binarySearch(i32, hay, needle, struct {
        fn order(ctx: i32, item: i32) std.math.Order {
            return std.math.order(ctx, item);
        }
    }.order) != null;
}

// ============================================================================
// output.go
// ============================================================================

/// A run of output codepoints: either an emoji token (with a resolved
/// `emoji`) or a text token (`emoji == null`). For emoji tokens `codepoints`
/// aliases `emoji.normalized`; for text tokens it is the NFC of a buffered run.
const OutputToken = struct {
    codepoints: []const u21,
    emoji: ?*const EmojiSequence,
};

fn flattenTokens(a: std.mem.Allocator, tokens: []const OutputToken) NormalizeError![]u21 {
    var n: usize = 0;
    for (tokens) |t| n += t.codepoints.len;
    const out = try a.alloc(u21, n);
    var i: usize = 0;
    for (tokens) |t| {
        @memcpy(out[i..][0..t.codepoints.len], t.codepoints);
        i += t.codepoints.len;
    }
    return out;
}

// ============================================================================
// utils.go
// ============================================================================

fn isASCII(cps: []const u21) bool {
    for (cps) |cp| {
        if (cp >= 0x80) return false;
    }
    return true;
}

fn uniqueRunes(a: std.mem.Allocator, cps: []const u21) NormalizeError![]u21 {
    var seen: std.AutoHashMapUnmanaged(u21, void) = .empty;
    defer seen.deinit(a);
    var out: std.ArrayList(u21) = .empty;
    for (cps) |cp| {
        const gop = try seen.getOrPut(a, cp);
        if (!gop.found_existing) try out.append(a, cp);
    }
    return out.toOwnedSlice(a);
}

/// Orders codepoint slices shorter-first, then lexicographically. Mirrors Go's
/// `compareRunes`; used to sort emojis by `normalized` before building the trie.
fn compareRunes(a: []const u21, b: []const u21) i32 {
    const c: i32 = @as(i32, @intCast(a.len)) - @as(i32, @intCast(b.len));
    if (c != 0) return c;
    for (a, 0..) |aa, i| {
        if (aa < b[i]) return -1;
        if (aa > b[i]) return 1;
    }
    return 0;
}

fn emojiLessThan(_: void, x: EmojiSequence, y: EmojiSequence) bool {
    return compareRunes(x.normalized, y.normalized) < 0;
}

// ============================================================================
// shared decode helpers (util.RuneSet / Decoder glue)
// ============================================================================

/// Reads a `ReadUnique` set and stores it as a persistent, sorted `RuneSet`.
/// The intermediate `[]u32` is scratch-allocated; the `[]u21` backing survives.
fn decodeRuneSet(persist: std.mem.Allocator, scratch: std.mem.Allocator, d: *Decoder) !RuneSet {
    const v32 = try d.readUnique(scratch);
    const v21 = try persist.alloc(u21, v32.len);
    for (v32, 0..) |x, i| v21[i] = @intCast(x);
    return RuneSet.fromOwnedUnsorted(persist, v21);
}

/// Reads a `ReadUnique` set into a scratch, ascending-sorted `[]u21` (mirrors
/// Go's `NewRuneSetFromInts(...).ToArray()`, whose iteration order is sorted).
fn readSortedCps(scratch: std.mem.Allocator, d: *Decoder) ![]u21 {
    const v32 = try d.readSortedUnique(scratch);
    const v21 = try scratch.alloc(u21, v32.len);
    for (v32, 0..) |x, i| v21[i] = @intCast(x);
    return v21;
}

/// Reads the named-codepoints section (fenced set) as a `RuneSet` of keys; the
/// per-codepoint display names are read to keep the bit stream aligned, then
/// discarded (they only fed diagnostic messages).
fn decodeFenced(persist: std.mem.Allocator, scratch: std.mem.Allocator, d: *Decoder) !RuneSet {
    const n = d.readUnsigned();
    const keys = try d.readSortedAscending(scratch, n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const name = try d.readString(scratch);
        _ = name;
    }
    const v21 = try persist.alloc(u21, keys.len);
    for (keys, 0..) |x, j| v21[j] = @intCast(x);
    return RuneSet.fromOwnedUnsorted(persist, v21);
}

/// Decodes the mapped-codepoints section into `map` (persistent rows).
fn decodeMapped(
    persist: std.mem.Allocator,
    scratch: std.mem.Allocator,
    d: *Decoder,
    map: *std.AutoHashMapUnmanaged(u21, []const u21),
) !void {
    while (true) {
        const w = d.readUnsigned();
        if (w == 0) break;
        const keys = try d.readSortedUnique(scratch);
        const n = keys.len;
        const rows = try scratch.alloc([]u21, n);
        for (0..n) |i| rows[i] = try persist.alloc(u21, @as(usize, w));
        for (0..@as(usize, w)) |j| {
            const vals = try d.readUnsortedDeltas(scratch, n);
            for (0..n) |i| rows[i][j] = @intCast(vals[i]);
        }
        for (0..n) |i| try map.put(persist, @intCast(keys[i]), rows[i]);
    }
}

fn runeSetFromKeys(
    persist: std.mem.Allocator,
    set: *std.AutoHashMapUnmanaged(u21, void),
) !RuneSet {
    const arr = try persist.alloc(u21, set.count());
    var i: usize = 0;
    var it = set.keyIterator();
    while (it.next()) |cpp| {
        arr[i] = cpp.*;
        i += 1;
    }
    return RuneSet.fromOwnedUnsorted(persist, arr);
}

// ============================================================================
// ensip15.go
// ============================================================================

/// Decoded ENSIP-15 tables plus the derived sets built by `init`. Read-only
/// after construction and shared for the process lifetime.
const Ensip15 = struct {
    nf: NF,
    ignored: RuneSet,
    combining_marks: RuneSet,
    max_non_spacing_marks: usize,
    non_spacing_marks: RuneSet,
    fenced: RuneSet,
    mapped: std.AutoHashMapUnmanaged(u21, []const u21),
    groups: []Group,
    emojis: []EmojiSequence,
    emoji_root: *EmojiNode,
    possibly_valid: RuneSet,
    confusables: std.AutoHashMapUnmanaged(u21, []const i32),
    unique_non_confusables: RuneSet,

    /// Port of go-ens-normalize's `New()`. Decodes `spec.bin` (via `Decoder`)
    /// and `nf.bin` (via `NF.init`), then builds `possibly_valid` (union of all
    /// group codepoints closed under NFD) and `unique_non_confusables` (that
    /// union with multi-group codepoints and confusables removed AFTER the NFD
    /// closure is taken -- the removal order is load-bearing). `persist` must
    /// outlive every returned normalization (page_allocator in production).
    fn init(persist: std.mem.Allocator) !Ensip15 {
        var arena = std.heap.ArenaAllocator.init(persist);
        defer arena.deinit();
        const scratch = arena.allocator();

        var d = try Decoder.init(scratch, compressed);

        const nf = try NF.init(persist);

        // shouldEscape: read to advance the stream; only used by the (omitted)
        // diagnostic message builders.
        _ = try d.readUnique(scratch);
        const ignored = try decodeRuneSet(persist, scratch, &d);
        const combining_marks = try decodeRuneSet(persist, scratch, &d);
        const max_non_spacing_marks: usize = d.readUnsigned();
        const non_spacing_marks = try decodeRuneSet(persist, scratch, &d);
        // nfcCheck: read to advance the stream; unused by the Normalize path.
        _ = try d.readUnique(scratch);
        const fenced = try decodeFenced(persist, scratch, &d);

        var mapped: std.AutoHashMapUnmanaged(u21, []const u21) = .empty;
        try decodeMapped(persist, scratch, &d, &mapped);

        const groups = try decodeGroups(persist, scratch, &d);

        var emoji_list: std.ArrayList(EmojiSequence) = .empty;
        try decodeEmojis(persist, scratch, &d, &.{}, &emoji_list);
        const emojis = try emoji_list.toOwnedSlice(persist);

        var confusables: std.AutoHashMapUnmanaged(u21, []const i32) = .empty;
        try decodeWholes(persist, scratch, &d, groups, &confusables);

        d.assertEof();

        std.mem.sort(EmojiSequence, emojis, {}, emojiLessThan);
        const emoji_root = try makeEmojiTree(persist, scratch, emojis);

        // union / multi over every group's primary+secondary codepoints.
        var union_set: std.AutoHashMapUnmanaged(u21, void) = .empty;
        var multi_set: std.AutoHashMapUnmanaged(u21, void) = .empty;
        for (groups) |*g| {
            for (g.primary.sorted) |cp| try addUnion(scratch, &union_set, &multi_set, cp);
            for (g.secondary.sorted) |cp| try addUnion(scratch, &union_set, &multi_set, cp);
        }

        // possibly_valid = union closed under NFD.
        var pv_set: std.AutoHashMapUnmanaged(u21, void) = .empty;
        {
            var it = union_set.keyIterator();
            while (it.next()) |cpp| {
                const cp = cpp.*;
                try pv_set.put(scratch, cp, {});
                const dec = try nf.nfd(scratch, &[_]u21{cp});
                for (dec) |x| try pv_set.put(scratch, x, {});
            }
        }
        const possibly_valid = try runeSetFromKeys(persist, &pv_set);

        // unique_non_confusables = union minus multi-group cps minus confusables.
        {
            var it = multi_set.keyIterator();
            while (it.next()) |cpp| _ = union_set.remove(cpp.*);
        }
        {
            var it = confusables.keyIterator();
            while (it.next()) |cpp| _ = union_set.remove(cpp.*);
        }
        const unique_non_confusables = try runeSetFromKeys(persist, &union_set);

        return Ensip15{
            .nf = nf,
            .ignored = ignored,
            .combining_marks = combining_marks,
            .max_non_spacing_marks = max_non_spacing_marks,
            .non_spacing_marks = non_spacing_marks,
            .fenced = fenced,
            .mapped = mapped,
            .groups = groups,
            .emojis = emojis,
            .emoji_root = emoji_root,
            .possibly_valid = possibly_valid,
            .confusables = confusables,
            .unique_non_confusables = unique_non_confusables,
        };
    }

    /// Port of `ParseEmojiAt`: greedily walks the trie from `start`, returning
    /// the longest matched emoji and the codepoint index just past it.
    fn parseEmojiAt(self: *const Ensip15, cps: []const u21, start: usize) ParseResult {
        var emoji: ?*const EmojiSequence = null;
        var end: ?usize = null;
        var node = self.emoji_root;
        var pos = start;
        while (pos < cps.len) {
            const next = node.children.get(cps[pos]) orelse break;
            node = next;
            pos += 1;
            if (node.emoji) |e| {
                emoji = e;
                end = pos;
            }
        }
        return .{ .emoji = emoji, .end = end };
    }

    /// Port of `outputTokenize` specialized to Normalize (NFC of text runs,
    /// `emoji.normalized` for emoji runs).
    fn outputTokenize(self: *const Ensip15, a: std.mem.Allocator, cps: []const u21) NormalizeError![]OutputToken {
        var tokens: std.ArrayList(OutputToken) = .empty;
        var buf: std.ArrayList(u21) = .empty;
        var i: usize = 0;
        while (i < cps.len) {
            const r = self.parseEmojiAt(cps, i);
            if (r.emoji) |emoji| {
                if (buf.items.len > 0) {
                    const nfced = try self.nf.nfc(a, buf.items);
                    try tokens.append(a, .{ .codepoints = nfced, .emoji = null });
                    buf.clearRetainingCapacity();
                }
                try tokens.append(a, .{ .codepoints = emoji.normalized, .emoji = emoji });
                i = r.end.?;
            } else {
                const cp = cps[i];
                if (self.possibly_valid.contains(cp)) {
                    try buf.append(a, cp);
                } else if (self.mapped.get(cp)) |m| {
                    try buf.appendSlice(a, m);
                } else if (!self.ignored.contains(cp)) {
                    return error.DisallowedCharacter;
                }
                i += 1;
            }
        }
        if (buf.items.len > 0) {
            const nfced = try self.nf.nfc(a, buf.items);
            try tokens.append(a, .{ .codepoints = nfced, .emoji = null });
        }
        return tokens.toOwnedSlice(a);
    }

    fn checkCombiningMarks(self: *const Ensip15, tokens: []const OutputToken) NormalizeError!void {
        for (tokens, 0..) |t, i| {
            if (t.emoji == null) {
                const cp = t.codepoints[0];
                if (self.combining_marks.contains(cp)) {
                    if (i == 0) return error.CombiningMarkLeading;
                    return error.CombiningMarkAfterEmoji;
                }
            }
        }
    }

    fn checkFenced(self: *const Ensip15, cps: []const u21) NormalizeError!void {
        if (self.fenced.contains(cps[0])) return error.FencedLeading;
        const n = cps.len;
        var last_pos: ?usize = null;
        var i: usize = 1;
        while (i < n) : (i += 1) {
            if (self.fenced.contains(cps[i])) {
                if (last_pos) |lp| {
                    if (lp == i) return error.FencedAdjacent;
                }
                last_pos = i + 1;
            }
        }
        if (last_pos) |lp| {
            if (lp == n) return error.FencedTrailing;
        }
    }

    /// Port of `determineGroup`: intersects the candidate group set across the
    /// unique codepoints, replicating Go's in-place compaction of the cloned
    /// group slice (including the full-slice scan on an empty intersection that
    /// decides mixture-vs-disallowed).
    fn determineGroup(self: *const Ensip15, a: std.mem.Allocator, unique: []const u21) NormalizeError!*const Group {
        const gs = try a.alloc(*const Group, self.groups.len);
        for (self.groups, 0..) |*g, i| gs[i] = g;
        var prev: usize = gs.len;
        for (unique) |cp| {
            var next: usize = 0;
            var i: usize = 0;
            while (i < prev) : (i += 1) {
                if (gs[i].contains(cp)) {
                    gs[next] = gs[i];
                    next += 1;
                }
            }
            if (next == 0) {
                for (gs) |g| {
                    if (g.contains(cp)) return error.IllegalMixture;
                }
                return error.DisallowedCharacter;
            }
            prev = next;
            if (prev == 1) break;
        }
        return gs[0];
    }

    /// Port of `checkGroup`: every codepoint must belong to `group`, and (unless
    /// the group is CM-whitelisted) the NFD of the run must satisfy the
    /// non-spacing-mark duplicate/excessive rules.
    fn checkGroup(self: *const Ensip15, a: std.mem.Allocator, group: *const Group, cps: []const u21) NormalizeError!void {
        for (cps) |cp| {
            if (!group.contains(cp)) return error.IllegalMixture;
        }
        if (!group.cm_whitelisted) {
            const decomposed = try self.nf.nfd(a, cps);
            const e = decomposed.len;
            var i: usize = 1;
            while (i < e) : (i += 1) {
                if (self.non_spacing_marks.contains(decomposed[i])) {
                    var j: usize = i + 1;
                    while (j < e) : (j += 1) {
                        const cp = decomposed[j];
                        if (!self.non_spacing_marks.contains(cp)) break;
                        var k: usize = i;
                        while (k < j) : (k += 1) {
                            if (decomposed[k] == cp) return error.NsmDuplicate;
                        }
                    }
                    const cnt = j - i;
                    if (cnt > self.max_non_spacing_marks) return error.NsmExcessive;
                    i = j;
                }
            }
        }
    }

    /// Port of `checkWhole`: rejects labels whose confusable codepoints are all
    /// simultaneously coverable by some other single group.
    fn checkWhole(self: *const Ensip15, a: std.mem.Allocator, group: *const Group, cps: []const u21) NormalizeError!void {
        _ = group;
        var shared: std.ArrayList(u21) = .empty;
        var universe: []i32 = &.{};
        var prev: usize = 0;
        for (cps) |cp| {
            if (self.confusables.get(cp)) |comp| {
                if (prev == 0) {
                    prev = comp.len;
                    universe = try a.dupe(i32, comp);
                } else {
                    var next: usize = 0;
                    var i: usize = 0;
                    while (i < prev) : (i += 1) {
                        if (sortedContainsI32(comp, universe[i])) {
                            universe[next] = universe[i];
                            next += 1;
                        }
                    }
                    prev = next;
                }
                if (prev == 0) return;
            } else if (self.unique_non_confusables.contains(cp)) {
                return;
            } else {
                try shared.append(a, cp);
            }
        }
        if (prev > 0) {
            for (0..prev) |i| {
                const other = &self.groups[@intCast(universe[i])];
                var all = true;
                for (shared.items) |cp| {
                    if (!other.contains(cp)) {
                        all = false;
                        break;
                    }
                }
                if (all) return error.WholeConfusable;
            }
        }
    }

    /// Port of `checkValidLabel`. The resolved group is validated but not
    /// returned (Normalize, unlike Beautify, does not need it).
    fn checkValidLabel(self: *const Ensip15, a: std.mem.Allocator, cps: []const u21, tokens: []const OutputToken) NormalizeError!void {
        if (cps.len == 0) return error.EmptyLabel;
        try checkLeadingUnderscore(cps);
        const has_emoji = tokens.len > 1 or tokens[0].emoji != null;
        if (!has_emoji and isASCII(cps)) {
            try checkLabelExtension(cps);
            return;
        }
        var chars: std.ArrayList(u21) = .empty;
        for (tokens) |t| {
            if (t.emoji == null) try chars.appendSlice(a, t.codepoints);
        }
        if (has_emoji and chars.items.len == 0) return;
        try self.checkCombiningMarks(tokens);
        try self.checkFenced(cps);
        const unique = try uniqueRunes(a, chars.items);
        const group = try self.determineGroup(a, unique);
        try self.checkGroup(a, group, chars.items);
        try self.checkWhole(a, group, unique);
    }

    /// Normalizes one label into `out` (its normalized UTF-8 bytes). All working
    /// memory comes from `a` (the per-call arena).
    fn processLabel(self: *const Ensip15, a: std.mem.Allocator, label: []const u8, out: *std.ArrayList(u8)) NormalizeError!void {
        const cps = try utf8ToCps(a, label);
        const tokens = try self.outputTokenize(a, cps);
        const flat = try flattenTokens(a, tokens);
        try self.checkValidLabel(a, flat, tokens);
        for (flat) |cp| {
            var buf: [4]u8 = undefined;
            // Normalized output is always well-formed Unicode scalar data
            // (from the mapped/emoji tables and NFC), so encoding cannot fail.
            const n = std.unicode.utf8Encode(cp, &buf) catch unreachable;
            try out.appendSlice(a, buf[0..n]);
        }
    }

    /// Port of `transform` + `Normalize`: split on '.', normalize each label,
    /// re-join with '.'. The final bytes are duped with the caller's allocator
    /// so they survive the per-call arena teardown.
    fn normalizeImpl(self: *const Ensip15, allocator: std.mem.Allocator, name: []const u8) NormalizeError![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var out: std.ArrayList(u8) = .empty;
        // Go's Split returns nil for the empty name (empty-name allowance), so
        // an empty input yields an empty output with no label processing.
        if (name.len != 0) {
            var it = std.mem.splitScalar(u8, name, '.');
            var first = true;
            while (it.next()) |label| {
                if (!first) try out.append(a, '.');
                first = false;
                try self.processLabel(a, label, &out);
            }
        }
        return allocator.dupe(u8, out.items);
    }
};

fn addUnion(
    scratch: std.mem.Allocator,
    union_set: *std.AutoHashMapUnmanaged(u21, void),
    multi_set: *std.AutoHashMapUnmanaged(u21, void),
    cp: u21,
) !void {
    const gop = try union_set.getOrPut(scratch, cp);
    if (gop.found_existing) {
        try multi_set.put(scratch, cp, {});
    } else {
        gop.value_ptr.* = {};
    }
}

fn checkLeadingUnderscore(cps: []const u21) NormalizeError!void {
    const UNDERSCORE: u21 = 0x5F;
    var allowed = true;
    for (cps) |cp| {
        if (allowed) {
            if (cp != UNDERSCORE) allowed = false;
        } else {
            if (cp == UNDERSCORE) return error.LeadingUnderscore;
        }
    }
}

fn checkLabelExtension(cps: []const u21) NormalizeError!void {
    const HYPHEN: u21 = 0x2D;
    if (cps.len >= 4 and cps[2] == HYPHEN and cps[3] == HYPHEN) return error.InvalidLabelExtension;
}

fn utf8ToCps(a: std.mem.Allocator, s: []const u8) NormalizeError![]u21 {
    const view = std.unicode.Utf8View.init(s) catch return error.InvalidUtf8;
    var list: std.ArrayList(u21) = .empty;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| try list.append(a, cp);
    return list.toOwnedSlice(a);
}

// ============================================================================
// public API + one-time table init (shared.go)
// ============================================================================

const State = enum(u8) { uninit = 0, initializing = 1, ready = 2 };
var tables_state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(State.uninit));
var tables: Ensip15 = undefined;

/// Lock-free one-time init (std.once was removed in Zig 0.16 and
/// std.Io.Mutex now requires an Io context, so this replaces the brief's
/// std.once with an equivalent atomic guard). The winner of the CAS decodes
/// the vendored blob with page_allocator; a decode failure there is a bug in
/// the vendored data, hence `catch unreachable`. Late arrivals spin until
/// `ready`.
fn getTables() *const Ensip15 {
    if (tables_state.load(.acquire) == @intFromEnum(State.ready)) return &tables;
    if (tables_state.cmpxchgStrong(
        @intFromEnum(State.uninit),
        @intFromEnum(State.initializing),
        .acquire,
        .acquire,
    ) == null) {
        tables = Ensip15.init(std.heap.page_allocator) catch unreachable;
        tables_state.store(@intFromEnum(State.ready), .release);
        return &tables;
    }
    while (tables_state.load(.acquire) != @intFromEnum(State.ready)) std.atomic.spinLoopHint();
    return &tables;
}

/// ENSIP-15 normalize. Caller owns the returned memory. See `NormalizeError`
/// for the rejection reasons. The first call decodes the embedded tables once.
pub fn normalize(allocator: std.mem.Allocator, name: []const u8) NormalizeError![]u8 {
    return getTables().normalizeImpl(allocator, name);
}

test "internal: normalize resolves emoji and ascii" {
    const allocator = std.testing.allocator;
    const out = try normalize(allocator, "abc");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("abc", out);
}
