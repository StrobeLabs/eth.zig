// Official ENSIP-15 + Unicode NF conformance vector suite.
//
// Runs the upstream ens-normalize (1.11.1) and Unicode (17) test vectors
// against eth.zig's ported normalizer and NF (NFD/NFC) tables. This is the
// permanent, CI-wired proof that the ENSIP-15 port matches the reference
// implementation, replacing the ad-hoc one-off run done during development.
//
// Run: zig build vector-test

const std = @import("std");
const eth = @import("eth");

const tests_json = @embedFile("data/ens-normalize/tests.json");
const nf_tests_json = @embedFile("data/ens-normalize/nf-tests.json");

test "ENSIP-15 official vectors" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, tests_json, .{});
    defer parsed.deinit();

    var pass: usize = 0;
    var fail: usize = 0;
    for (parsed.value.array.items) |item| {
        const obj = item.object;
        if (obj.get("version") != null) continue; // metadata entry (first element)
        const name = obj.get("name").?.string;
        const expect_error = if (obj.get("error")) |e| e.bool else false;
        const norm = if (obj.get("norm")) |n| n.string else name;

        const result = eth.ens_normalize.normalize(allocator, name);
        if (expect_error) {
            if (result) |out| {
                allocator.free(out);
                fail += 1;
                std.debug.print("expected error: {s} (comment: {s})\n", .{ name, if (obj.get("comment")) |c| c.string else "" });
            } else |_| pass += 1;
        } else {
            if (result) |out| {
                defer allocator.free(out);
                if (std.mem.eql(u8, out, norm)) {
                    pass += 1;
                } else {
                    fail += 1;
                    std.debug.print("wrong norm for {s}: got {s} want {s}\n", .{ name, out, norm });
                }
            } else |err| {
                fail += 1;
                std.debug.print("unexpected error {any} for: {s}\n", .{ err, name });
            }
        }
    }
    std.debug.print("ENSIP-15 vectors: {d} pass, {d} fail\n", .{ pass, fail });
    try std.testing.expectEqual(@as(usize, 0), fail);
}

test "Unicode NF official vectors" {
    const allocator = std.testing.allocator;
    var nf_tables = try eth.ens_normalize.testing_nf.NF.init(allocator);
    defer nf_tables.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, nf_tests_json, .{});
    defer parsed.deinit();

    var it = parsed.value.object.iterator();
    var pass: usize = 0;
    var fail: usize = 0;
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .array) continue;
        for (entry.value_ptr.array.items) |case| {
            const v = case.array.items;
            const input = try utf8ToCps(allocator, v[0].string);
            defer allocator.free(input);
            const nfd0 = v[1].string;
            const nfc0 = v[2].string;

            const nfd_out = try nf_tables.nfd(allocator, input);
            defer allocator.free(nfd_out);
            const nfc_out = try nf_tables.nfc(allocator, input);
            defer allocator.free(nfc_out);

            const nfd_str = try cpsToUtf8(allocator, nfd_out);
            defer allocator.free(nfd_str);
            const nfc_str = try cpsToUtf8(allocator, nfc_out);
            defer allocator.free(nfc_str);

            if (!std.mem.eql(u8, nfd_str, nfd0)) {
                fail += 1;
                std.debug.print("NFD mismatch for {s}: got {s} want {s}\n", .{ v[0].string, nfd_str, nfd0 });
            } else pass += 1;

            if (!std.mem.eql(u8, nfc_str, nfc0)) {
                fail += 1;
                std.debug.print("NFC mismatch for {s}: got {s} want {s}\n", .{ v[0].string, nfc_str, nfc0 });
            } else pass += 1;
        }
    }
    std.debug.print("Unicode NF vectors: {d} pass, {d} fail\n", .{ pass, fail });
    try std.testing.expectEqual(@as(usize, 0), fail);
}

fn utf8ToCps(allocator: std.mem.Allocator, s: []const u8) ![]u21 {
    var list: std.ArrayList(u21) = .empty;
    errdefer list.deinit(allocator);
    var view = try std.unicode.Utf8View.init(s);
    var iter = view.iterator();
    while (iter.nextCodepoint()) |cp| try list.append(allocator, cp);
    return list.toOwnedSlice(allocator);
}

fn cpsToUtf8(allocator: std.mem.Allocator, cps: []const u21) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var buf: [4]u8 = undefined;
    for (cps) |cp| {
        const n = try std.unicode.utf8Encode(cp, &buf);
        try list.appendSlice(allocator, buf[0..n]);
    }
    return list.toOwnedSlice(allocator);
}
