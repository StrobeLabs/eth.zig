const std = @import("std");

/// Sorted, deduplicatable set of codepoints supporting O(log n) membership
/// tests. Port of go-ens-normalize's `util/runeset.go`.
pub const RuneSet = struct {
    sorted: []const u21,

    /// Sorts `v` in place ascending and takes ownership of it as the set's
    /// backing storage.
    pub fn fromOwnedUnsorted(allocator: std.mem.Allocator, v: []u21) !RuneSet {
        _ = allocator;
        std.mem.sort(u21, v, {}, std.sort.asc(u21));
        return RuneSet{ .sorted = v };
    }

    /// Reports whether `cp` is a member of the set, via binary search.
    pub fn contains(self: RuneSet, cp: u21) bool {
        return std.sort.binarySearch(u21, self.sorted, cp, struct {
            fn order(context: u21, item: u21) std.math.Order {
                return std.math.order(context, item);
            }
        }.order) != null;
    }

    /// Returns the number of codepoints in the set.
    pub fn size(self: RuneSet) usize {
        return self.sorted.len;
    }
};

test "RuneSet contains via binary search" {
    const allocator = std.testing.allocator;
    const v = try allocator.dupe(u21, &.{ 5, 1, 3 });
    var set = try RuneSet.fromOwnedUnsorted(allocator, v);
    defer allocator.free(@constCast(set.sorted));
    try std.testing.expect(set.contains(3));
    try std.testing.expect(!set.contains(4));
    try std.testing.expectEqual(@as(usize, 3), set.size());
}
