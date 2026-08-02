const std = @import("std");

/// Zigzag-decode a signed value packed by go-ens-normalize's encoder:
/// even values map to `i >> 1`, odd values map to `~i >> 1` (i.e. negative).
/// Mirrors `util/decoder.go`'s `asSigned`.
fn asSigned(i: i64) i64 {
    if ((i & 1) != 0) {
        return ~i >> 1;
    }
    return i >> 1;
}

/// Bit-level reader for the packed binary format used by the vendored
/// ens-normalize data blobs (`nf.bin`, `spec.bin`). Port of go-ens-normalize's
/// `util/decoder.go`. The blobs are vendored and trusted, so every read here
/// assumes well-formed input: malformed input panics or indexes out of
/// bounds rather than returning an error.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    buf: []const u8,
    pos: usize,
    /// Header table read by `init` (via `readMagic`) before any values are
    /// decoded. Public because `readUnsigned` and tests inspect it directly.
    magic: []u32,
    word: u8,
    bit: u8,

    /// Parses the magic header from `buf` and returns a decoder positioned
    /// right after it, ready for `readUnsigned` and friends.
    pub fn init(allocator: std.mem.Allocator, buf: []const u8) !Decoder {
        var d = Decoder{
            .allocator = allocator,
            .buf = buf,
            .pos = 0,
            .magic = &.{},
            .word = 0,
            .bit = 0,
        };
        d.magic = try d.readMagic();
        return d;
    }

    /// Frees the magic header allocated by `init`.
    pub fn deinit(self: *Decoder) void {
        self.allocator.free(self.magic);
    }

    /// Panics unless every byte of `buf` has been consumed.
    pub fn assertEof(self: *const Decoder) void {
        if (self.pos < self.buf.len) {
            std.debug.panic("expected eof: {d}/{d}", .{ self.pos, self.buf.len });
        }
    }

    fn readMagic(self: *Decoder) ![]u32 {
        var list: std.ArrayList(u32) = .empty;
        errdefer list.deinit(self.allocator);
        var w: u32 = 0;
        while (true) {
            const dw = self.readUnary();
            if (dw == 0) break;
            w += dw;
            try list.append(self.allocator, w);
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn readBit(self: *Decoder) bool {
        if (self.bit == 0) {
            self.word = self.buf[self.pos];
            self.pos += 1;
            self.bit = 1;
        }
        const bit = (self.word & self.bit) != 0;
        self.bit <<= 1;
        return bit;
    }

    fn readUnary(self: *Decoder) u32 {
        var x: u32 = 0;
        while (self.readBit()) x += 1;
        return x;
    }

    fn readBinary(self: *Decoder, w: u32) u32 {
        var x: u32 = 0;
        var b: u32 = @as(u32, 1) << @intCast(w - 1);
        while (b != 0) : (b >>= 1) {
            if (self.readBit()) x |= b;
        }
        return x;
    }

    /// Reads a single variable-width unsigned integer using the decoder's
    /// magic/width table.
    pub fn readUnsigned(self: *Decoder) u32 {
        var a: u32 = 0;
        var w: u32 = 0;
        var i: usize = 0;
        while (true) : (i += 1) {
            w = self.magic[i];
            const n: u32 = @as(u32, 1) << @intCast(w);
            if (i + 1 == self.magic.len or !self.readBit()) break;
            a += n;
        }
        return a + self.readBinary(w);
    }

    fn readArray(self: *Decoder, allocator: std.mem.Allocator, n: usize, comptime combine: fn (prev: i64, x: u32) i64) ![]u32 {
        const v = try allocator.alloc(u32, n);
        errdefer allocator.free(v);
        var prev: i64 = -1;
        for (v) |*slot| {
            const x = self.readUnsigned();
            prev = combine(prev, x);
            slot.* = @intCast(prev);
        }
        return v;
    }

    /// Reads `n` values as ascending deltas: `v[i] = v[i-1] + 1 + x`, with
    /// `v[-1]` treated as `-1`.
    pub fn readSortedAscending(self: *Decoder, allocator: std.mem.Allocator, n: usize) ![]u32 {
        return self.readArray(allocator, n, struct {
            fn f(prev: i64, x: u32) i64 {
                return prev + 1 + @as(i64, x);
            }
        }.f);
    }

    /// Reads `n` values as zigzag-signed deltas: `v[i] = v[i-1] + asSigned(x)`,
    /// with `v[-1]` treated as `-1`. Each individual zigzag-decoded delta
    /// (`asSigned(x)`) may be negative, but for valid upstream blobs the
    /// accumulated `v[i]` values are always non-negative (verified against
    /// the upstream `spec.json` / `nf.json` source data, whose encoded
    /// deltas never drive the running sum below zero). The `i64` accumulator
    /// in `readArray` is retained regardless, since nothing here enforces
    /// that invariant for arbitrary (non-upstream) input.
    pub fn readUnsortedDeltas(self: *Decoder, allocator: std.mem.Allocator, n: usize) ![]u32 {
        return self.readArray(allocator, n, struct {
            fn f(prev: i64, x: u32) i64 {
                return prev + asSigned(@as(i64, x));
            }
        }.f);
    }

    /// Reads a length-prefixed run of unsorted-delta codepoints as a
    /// codepoint slice (not UTF-8).
    pub fn readString(self: *Decoder, allocator: std.mem.Allocator) ![]u21 {
        const n = self.readUnsigned();
        const v = try self.readUnsortedDeltas(allocator, n);
        defer allocator.free(v);
        const cps = try allocator.alloc(u21, v.len);
        errdefer allocator.free(cps);
        for (v, 0..) |x, idx| {
            cps[idx] = @intCast(x);
        }
        return cps;
    }

    /// Reads a set of values encoded as a sorted-ascending prefix plus an
    /// optional run of half-open ranges appended in encounter order.
    pub fn readUnique(self: *Decoder, allocator: std.mem.Allocator) ![]u32 {
        const v = try self.readSortedAscending(allocator, self.readUnsigned());
        errdefer allocator.free(v);
        const n = self.readUnsigned();
        if (n == 0) return v;

        const vx = try self.readSortedAscending(allocator, n);
        defer allocator.free(vx);
        const vs = try self.readUnsortedDeltas(allocator, n);
        defer allocator.free(vs);

        // Build the appended ranges in a separate buffer (rather than growing
        // `v` in place via ArrayList.fromOwnedSlice) so `v`'s errdefer above
        // and this list's cleanup never alias the same allocation.
        var extra: std.ArrayList(u32) = .empty;
        defer extra.deinit(allocator);
        for (0..n) |i| {
            var x = vx[i];
            const e = vx[i] + vs[i];
            while (x < e) : (x += 1) {
                try extra.append(allocator, x);
            }
        }

        const result = try allocator.alloc(u32, v.len + extra.items.len);
        @memcpy(result[0..v.len], v);
        @memcpy(result[v.len..], extra.items);
        allocator.free(v); // safe: nothing after this can fail, so v's errdefer never re-fires
        return result;
    }

    /// Reads a `readUnique` set and sorts it ascending.
    pub fn readSortedUnique(self: *Decoder, allocator: std.mem.Allocator) ![]u32 {
        const v = try self.readUnique(allocator);
        std.mem.sort(u32, v, {}, std.sort.asc(u32));
        return v;
    }
};

test "readBinary reads MSB-first from LSB-first bit stream" {
    // stream bits (in read order): 1,0,1 -> byte 0b00000101
    // preceded by magic terminator: readMagic consumes leading bits.
    // Build buffer manually: first byte encodes magic = [1]:
    //   readUnary -> bits 1,0 (dw=1), readUnary -> bit 0 (stop)
    //   bits consumed: 1,0,0 then readBinary(1) reads next bit.
    // byte0 = bit0:1 bit1:0 bit2:0 bit3:1 -> 0b00001001 = 0x09
    const allocator = std.testing.allocator;
    var d = try Decoder.init(allocator, &.{0x09});
    defer d.deinit();
    try std.testing.expectEqual(@as(usize, 1), d.magic.len);
    try std.testing.expectEqual(@as(u32, 1), d.magic[0]);
    try std.testing.expectEqual(@as(u32, 1), d.readUnsigned()); // magic=[1]: single readBinary(1) -> bit 1
}

test "readSortedAscending applies prev+1+x" {
    // magic=[2] header bits: 1,1,0,0 (unary 2, then stop)
    // then two ReadUnsigned(2-bit) values: 0 -> bits 0,0 ; 1 -> bits 0,1
    // stream: 1,1,0,0, 0,0, 0,1 -> byte0 = bits 1,1,0,0,0,0,0,1 -> 0b10000011 = 0x83
    const allocator = std.testing.allocator;
    var d = try Decoder.init(allocator, &.{0x83});
    defer d.deinit();
    const v = try d.readSortedAscending(allocator, 2);
    defer allocator.free(v);
    // prev=-1: v[0] = -1+1+0 = 0; v[1] = 0+1+1 = 2
    try std.testing.expectEqualSlices(u32, &.{ 0, 2 }, v);
}

test "readUnique appends half-open ranges after the sorted-ascending prefix" {
    // Bypasses init()/readMagic so the body bits can be hand-derived against
    // a fixed magic=[3] table (every ReadUnsigned reads exactly 3 bits).
    // Regression test for a fix to readUnique: the original port grew the
    // sorted-ascending prefix in place via ArrayList.fromOwnedSlice(v), which
    // aliased the errdefer-tracked `v` allocation with the list's own cleanup
    // -- an append failure mid-loop would free that buffer twice. The fix
    // builds appended ranges in a separate buffer and copies once at the end.
    //
    // Call sequence (each ReadUnsigned is 3 bits, x in 0..7).
    // Derivation (prev starts at -1 for each array read):
    //   n0: x=1                  -> n0 = 1
    //   v[0]: x=5                -> v[0] = -1+1+5 = 5          => v = [5]
    //   n: x=1                   -> n = 1
    //   vx[0]: x=3               -> vx[0] = -1+1+3 = 3         => vx = [3]
    //   vs[0]: x=6, asSigned(6)=3-> vs[0] = -1+3 = 2            => vs = [2]
    //   range: [vx[0], vx[0]+vs[0]) = [3, 5) = {3, 4}
    //   readUnique = v ++ extra = [5, 3, 4]
    //   readSortedUnique = [3, 4, 5]
    const allocator = std.testing.allocator;
    var magic_buf = [_]u32{3};
    var body = [_]u8{ 0x2C, 0x3D };
    var d = Decoder{
        .allocator = allocator,
        .buf = &body,
        .pos = 0,
        .magic = &magic_buf,
        .word = 0,
        .bit = 0,
    };
    const v = try d.readUnique(allocator);
    defer allocator.free(v);
    try std.testing.expectEqualSlices(u32, &.{ 5, 3, 4 }, v);

    d.pos = 0;
    d.bit = 0;
    const v2 = try d.readSortedUnique(allocator);
    defer allocator.free(v2);
    try std.testing.expectEqualSlices(u32, &.{ 3, 4, 5 }, v2);
}
