//! Acceptance tests for spec 0002 (docs/specs/0002-uniswap-complete-and-phase2.md),
//! tests B1, B2, B5: `v4.parsePlan` on Universal Router `V4_SWAP` (command
//! 0x10) command inputs.
//!
//! `parsePlan` takes exactly the bytes of one UR `inputs[i]` entry for the
//! 0x10 command -- not the whole UR transaction, not the whole
//! `execute(bytes,bytes[],...)` calldata. Every fixture and hand-built input
//! below is already that inner slice.
//!
//! B1 fixtures are extracted from real mainnet UR `execute` transactions
//! with an independent Python ABI walker (word-by-word offset/length
//! reader, source kept by the test-writer, not this decoder) that locates
//! command 0x10 in `commands`/`inputs[]` the same way `calldata.zig`'s
//! seam does. Expected field values come from `cast abi-decode --input` on
//! each action's params (`cast --version`: 1.6.0-Homebrew f83bad9), per
//! docs/specs/0002's oracle requirement -- except the two no-tuple-offset
//! txs (F1, F2), whose single-hop swap struct is cross-checked by hand
//! against the hex (see the comment above each): the contract locates the
//! struct at `params + word0` (CalldataDecoder.sol), and in these two txs
//! word0 is 0 (the struct's first field, `currency0`, is itself 0 for
//! native ETH), so there is no separate leading offset word to read with
//! `cast`'s generic tuple signature -- `cast` happens to decode it
//! correctly too, by the same coincidence (jumping to offset 0 is a
//! no-op), which the by-hand walk below confirms independently.
//!
//! B2 round-trips the only accepted struct layout (research/uniswap_rest.md
//! "LIVE layout", spec 0002 section 5 amendment R1): live (deployed
//! routers), no `minHopPriceX36`, single hookData offset 0x120 exactly,
//! multi path offset 0x80 exactly. The `min_hop_price_x36` fields were
//! removed from the V4 structs, because no deployed router reads them; the
//! current v4-periphery main-branch layout (with `minHopPriceX36`, offsets
//! 0x140 / 0xa0) is well-formed ABI but is now rejected outright --
//! `parsePlan` returns null for a plan containing it, rather than decoding
//! it. See the R1 tests below for why: a reviewer fork repro against the
//! deployed Universal Router showed a main-layout-shaped SWAP_EXACT_OUT
//! decoding amount_out as 1e15 while the chain executed 416, because that
//! router reads amounts from different words than the main layout puts
//! them at.
//!
//! B5 hand-crafts null-producing malformed inputs (the crafted-rejection
//! list from the test-writer's brief) and fuzzes every B1 fixture: every
//! prefix length, and 1,000 seeded single-byte mutations, walking every
//! accessor on any non-null result.

const std = @import("std");
const testing = std.testing;
const v4 = @import("v4.zig");
const abi_encode = @import("../abi_encode.zig");
const hex = @import("../hex.zig");

const AV = abi_encode.AbiValue;

// ============================================================================
// Helpers
// ============================================================================

/// Decode a hex literal (with or without "0x") into a 20-byte address.
fn addr(comptime hex_str: []const u8) [20]u8 {
    return hex.hexToBytesFixed(20, hex_str) catch unreachable;
}

/// Decode a "0x..."-prefixed calldata hex literal into a fixed-size byte
/// array sized at comptime from the literal's length.
fn fixtureBytes(comptime hex_str: []const u8) [(hex_str.len - 2) / 2]u8 {
    @setEvalBranchQuota(1_000_000);
    return hex.hexToBytesFixed((hex_str.len - 2) / 2, hex_str) catch unreachable;
}

const ZERO_ADDR: [20]u8 = @splat(0);
const TOKEN_A = addr("1111111111111111111111111111111111111111");
const TOKEN_B = addr("2222222222222222222222222222222222222222");
const TOKEN_C = addr("3333333333333333333333333333333333333333");
const HOOKS_ADDR = addr("4444444444444444444444444444444444444444");
const RECIPIENT = addr("5555555555555555555555555555555555555555");

/// Raw big-endian byte-buffer builder for hand-crafted (possibly malformed)
/// V4_SWAP inputs that `abi_encode`'s clean encoder cannot produce (dirty
/// padding, out-of-range offsets, aliased array elements, ...). Mirrors
/// `calldata_test.zig`'s local `Builder`.
const Builder = struct {
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) Builder {
        return .{ .allocator = allocator };
    }
    fn deinit(self: *Builder) void {
        self.buf.deinit(self.allocator);
    }
    /// A clean, correctly zero-padded uint256 word.
    fn w(self: *Builder, v: u256) !void {
        try self.buf.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u256, v)));
    }
    /// A clean, correctly zero-padded address word.
    fn wAddr(self: *Builder, a: [20]u8) !void {
        var word: [32]u8 = @splat(0);
        @memcpy(word[12..32], &a);
        try self.buf.appendSlice(self.allocator, &word);
    }
    /// An arbitrary 32-byte word, verbatim (for dirty bits/padding attacks).
    fn wRaw(self: *Builder, word: [32]u8) !void {
        try self.buf.appendSlice(self.allocator, &word);
    }
    fn raw(self: *Builder, bytes: []const u8) !void {
        try self.buf.appendSlice(self.allocator, bytes);
    }
    fn padZero(self: *Builder, n: usize) !void {
        try self.buf.appendNTimes(self.allocator, 0, n);
    }
    fn ownedSlice(self: *Builder) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }
};

/// Assemble a clean `abi.encode(bytes actions, bytes[] params)` V4_SWAP
/// input with exactly one action and one already-built (possibly
/// malformed) params blob `param`. Used by the B5 crafted-rejection tests
/// so each test only has to hand-craft the inner piece it means to attack.
fn writeSingleAction(b: *Builder, action: u8, param: []const u8) !void {
    const actions = [_]u8{action};
    try b.w(0x40); // actions offset: right after the 2 head words
    try b.w(0x40 + 64); // params offset: right after the 1-byte actions tail (len word + 1 byte padded to a word = 64)
    try b.w(1); // actions.length = 1
    try b.raw(&actions);
    try b.padZero(31); // pad the 1-byte actions content to a full word
    try b.w(1); // params.length = 1
    try b.w(0x20); // params[0] offset: right after the 1 head word
    try b.w(param.len); // params[0].length
    try b.raw(param);
    const pad = (32 - (param.len % 32)) % 32;
    try b.padZero(pad);
}

fn expectPoolKey(expected: v4.PoolKey, actual: v4.PoolKey) !void {
    try testing.expectEqualSlices(u8, &expected.currency0, &actual.currency0);
    try testing.expectEqualSlices(u8, &expected.currency1, &actual.currency1);
    try testing.expectEqual(expected.fee, actual.fee);
    try testing.expectEqual(expected.tick_spacing, actual.tick_spacing);
    try testing.expectEqualSlices(u8, &expected.hooks, &actual.hooks);
}

fn expectPathKey(expected: v4.PathKey, actual: v4.PathKey) !void {
    try testing.expectEqualSlices(u8, &expected.intermediate_currency, &actual.intermediate_currency);
    try testing.expectEqual(expected.fee, actual.fee);
    try testing.expectEqual(expected.tick_spacing, actual.tick_spacing);
    try testing.expectEqualSlices(u8, &expected.hooks, &actual.hooks);
    try testing.expectEqualSlices(u8, expected.hook_data, actual.hook_data);
}

fn expectCurrencyAmount(expected: v4.CurrencyAmount, actual: v4.CurrencyAmount) !void {
    try testing.expectEqualSlices(u8, &expected.currency, &actual.currency);
    try testing.expectEqual(expected.amount, actual.amount);
}

fn expectCurrencyRecipientAmount(expected: v4.CurrencyRecipientAmount, actual: v4.CurrencyRecipientAmount) !void {
    try testing.expectEqualSlices(u8, &expected.currency, &actual.currency);
    try testing.expectEqualSlices(u8, &expected.recipient, &actual.recipient);
    try testing.expectEqual(expected.amount, actual.amount);
}

// ============================================================================
// Infallibility walkers
// ============================================================================
//
// The contract (v4.zig doc comment): if `parsePlan` returns non-null, every
// accessor and iterator is infallible. These walkers exercise all of them so
// B5's fuzzing actually reaches every code path: the action iterator,
// `PathKeys.get` for every element, and every `hook_data` slice.

fn walkHookData(hd: []const u8) void {
    var acc: u8 = 0;
    for (hd) |byte| acc ^= byte;
    std.mem.doNotOptimizeAway(acc);
}

fn walkPathKeys(pk: v4.PathKeys) void {
    const n = pk.len();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const k = pk.get(i);
        walkHookData(k.hook_data);
    }
}

fn walkAction(a: v4.Action) void {
    switch (a.payload) {
        .swap_exact_in_single => |p| walkHookData(p.hook_data),
        .swap_exact_out_single => |p| walkHookData(p.hook_data),
        .swap_exact_in => |p| walkPathKeys(p.path),
        .swap_exact_out => |p| walkPathKeys(p.path),
        .settle, .settle_all, .take, .take_all, .take_portion, .other => {},
    }
}

fn walkPlan(plan: v4.Plan) void {
    var it = plan.iterator();
    while (it.next()) |a| walkAction(a);
}

// ============================================================================
// B1: live mainnet fixtures
//
// Each fixture is the raw bytes of the UR `inputs[i]` entry for command
// 0x10, extracted from `execute`/`execute(bytes,bytes[],uint256)` calldata
// on real mainnet Universal Router (0x66a9893cc07d91d95644aedd05d03f95e1dba8af)
// transactions. `cast --version`: 1.6.0-Homebrew f83bad9.
// ============================================================================

// tx 0x3019fe262eaa5c1a5a5decfef86cc3ae77d46598dde5057d6e2e028ebb4aba2c block
// 26042048, UR execute(bytes,bytes[],uint256) commands 0a,02,10 -> V4_SWAP
// actions 06 (SWAP_EXACT_IN_SINGLE), 0b (SETTLE), 0f (TAKE_ALL). NO-TUTPLE-OFFSET:
// action 0x06's params word0 = 0 (currency0 = native ETH = 0), so the
// contract's `struct = params + word0` locates the struct's fields starting
// at byte 0 of params, not byte 32 -- there is no separate leading offset
// word in the encoding. Manually walking the hex confirms: bytes[0:32] =
// currency0 = 0 (also, degenerately, the "offset" value itself); bytes[32:64]
// = currency1 = 0x9ebf91b8d6ff68aa05545301a3d0984eaee54a03; bytes[64:96] low 3
// bytes = fee = 0; bytes[96:128] low 3 bytes = tickSpacing = 0x3c = 60;
// bytes[128:160] = hooks = 0xe3c63a9813ac03be0e8618b627cb8170cfa468c4;
// bytes[160:192] = zeroForOne = 0 (false); bytes[192:224] = amountIn =
// 0xaafb4ae0859176b5679 = 50464864394347136374393; bytes[224:256] =
// amountOutMinimum = 0x2fed881a38c482 = 13490492716663938; bytes[256:288] =
// hookData offset (rel. to struct start) = 0x120; the word at struct+0x120 =
// hookData length = 0. `cast abi-decode --input
// "f(((address,address,uint24,int24,address),bool,uint128,uint128,bytes))"`
// on the same params (jumping to offset 0, a no-op) agrees exactly.
const F1_NO_OFFSET_0A0210 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003060b0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009ebf91b8d6ff68aa05545301a3d0984eaee54a030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000e3c63a9813ac03be0e8618b627cb8170cfa468c40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aafb4ae0859176b5679000000000000000000000000000000000000000000000000002fed881a38c4820000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000009ebf91b8d6ff68aa05545301a3d0984eaee54a03000000000000000000000000000000000000000000000aafb4ae0859176b56790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

test "B1: live fixture - SWAP_EXACT_IN_SINGLE + SETTLE + TAKE_ALL, no-tuple-offset (0x3019fe26...)" {
    const plan = v4.parsePlan(&F1_NO_OFFSET_0A0210);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x06, 0x0b, 0x0f }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x06), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_in_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{
        .currency0 = ZERO_ADDR,
        .currency1 = addr("9ebf91b8d6ff68aa05545301a3d0984eaee54a03"),
        .fee = 0,
        .tick_spacing = 60,
        .hooks = addr("e3c63a9813ac03be0e8618b627cb8170cfa468c4"),
    }, s0.pool_key);
    try testing.expectEqual(false, s0.zero_for_one);
    try testing.expectEqual(@as(u128, 50464864394347136374393), s0.amount_in);
    try testing.expectEqual(@as(u128, 13490492716663938), s0.amount_out_minimum);
    try testing.expectEqualSlices(u8, &[_]u8{}, s0.hook_data);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0b), a1.raw);
    const s1 = switch (a1.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("9ebf91b8d6ff68aa05545301a3d0984eaee54a03"), &s1.currency);
    try testing.expectEqual(@as(u256, 50464864394347136374393), s1.amount);
    try testing.expectEqual(false, s1.payer_is_user);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0f), a2.raw);
    const s2 = switch (a2.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = ZERO_ADDR, .amount = 0 }, s2);

    try testing.expect(it.next() == null);
}

// tx 0x2960d43c6e040aa61fd523d99d55e2702de6d35a3cdecf5ec564e1f38ad0e8c4 block
// 26043795, commands 10,06,04 -> V4_SWAP actions 06, 0c (SETTLE_ALL), 0f
// (TAKE_ALL). NO-TUPLE-OFFSET (the second required tx): action 0x06's params
// word0 = 0 again (currency0 = native ETH). By hand: bytes[0:32] = currency0
// = 0; bytes[32:64] = currency1 = 0xdb99b0477574ac0b2d9c8cec56b42277da3fdb82;
// fee = 0; tickSpacing low byte = 0x01 = 1; hooks = 0 (no hook); zeroForOne =
// 1 (true); amountIn = 0x1c6bf52634000 = 500000000000000 (matches the tx's
// own `value` field, 0x1c6bf52634000 -- this V4_SWAP is spending msg.value);
// amountOutMinimum = 0; hookData offset = 0x120, length at struct+0x120 = 0.
// `cast abi-decode --input
// "f(((address,address,uint24,int24,address),bool,uint128,uint128,bytes))"`
// agrees.
const F2_NO_OFFSET_100604 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003060c0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000db99b0477574ac0b2d9c8cec56b42277da3fdb8200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000001c6bf52634000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c6bf526340000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000db99b0477574ac0b2d9c8cec56b42277da3fdb820000000000000000000000000000000000000000000000000000000000000000");

test "B1: live fixture - SWAP_EXACT_IN_SINGLE + SETTLE_ALL + TAKE_ALL, no-tuple-offset (0x2960d43c...)" {
    const plan = v4.parsePlan(&F2_NO_OFFSET_100604);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x06, 0x0c, 0x0f }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x06), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_in_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{
        .currency0 = ZERO_ADDR,
        .currency1 = addr("db99b0477574ac0b2d9c8cec56b42277da3fdb82"),
        .fee = 0,
        .tick_spacing = 1,
        .hooks = ZERO_ADDR,
    }, s0.pool_key);
    try testing.expectEqual(true, s0.zero_for_one);
    try testing.expectEqual(@as(u128, 500000000000000), s0.amount_in);
    try testing.expectEqual(@as(u128, 0), s0.amount_out_minimum);
    try testing.expectEqualSlices(u8, &[_]u8{}, s0.hook_data);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0c), a1.raw);
    const s1 = switch (a1.payload) {
        .settle_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = ZERO_ADDR, .amount = 500000000000000 }, s1);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0f), a2.raw);
    const s2 = switch (a2.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = addr("db99b0477574ac0b2d9c8cec56b42277da3fdb82"), .amount = 0 }, s2);

    try testing.expect(it.next() == null);
}

// tx 0x9ae4af73ed08127e083869f946d0b243af775d167a91b00217cb976c48fec026 block
// 26043693, commands 00,00,10,00,0c -> V4_SWAP actions 0b (SETTLE), 07
// (SWAP_EXACT_IN, multi-hop, 1 hop), 0e (TAKE). Standard layout (params
// word0 = 0x20). Expected values from `cast abi-decode --input
// "f(address,uint256,bool)"` / "f((address,(address,uint24,int24,address,bytes)[],uint128,uint128))"
// / "f(address,address,uint256)".
const F3_000010000C = fixtureBytes("0x0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000030b070e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000e37cdc5c000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000");

test "B1: live fixture - SETTLE + SWAP_EXACT_IN(multi 1-hop) + TAKE (0x9ae4af73...)" {
    const plan = v4.parsePlan(&F3_000010000C);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0b, 0x07, 0x0e }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0b), a0.raw);
    const s0 = switch (a0.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), &s0.currency);
    try testing.expectEqual(@as(u256, 3816610908), s0.amount);
    try testing.expectEqual(true, s0.payer_is_user);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x07), a1.raw);
    const s1 = switch (a1.payload) {
        .swap_exact_in => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), &s1.currency_in);
    try testing.expectEqual(@as(usize, 1), s1.path.len());
    try expectPathKey(.{
        .intermediate_currency = addr("dac17f958d2ee523a2206206994597c13d831ec7"),
        .fee = 10,
        .tick_spacing = 1,
        .hooks = ZERO_ADDR,
        .hook_data = &[_]u8{},
    }, s1.path.get(0));
    try testing.expectEqual(@as(u128, 0), s1.amount_in);
    try testing.expectEqual(@as(u128, 0), s1.amount_out_minimum);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0e), a2.raw);
    const s2 = switch (a2.payload) {
        .take => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{
        .currency = addr("dac17f958d2ee523a2206206994597c13d831ec7"),
        .recipient = addr("0000000000000000000000000000000000000002"),
        .amount = 0,
    }, s2);

    try testing.expect(it.next() == null);
}

// tx 0x3b24c8cd314145eaba6fa30d0b46a89ffc4e22c70b632d76a6d4b2bdd640ed6f block
// 26043254, commands 08,0b,10,04 -> V4_SWAP actions 08 (SWAP_EXACT_OUT_SINGLE),
// 0b (SETTLE), 0f (TAKE_ALL). amount_in_maximum is exactly
// type(uint128).max (340282366920938463463374607431768211455), a real
// mainnet edge-case value worth pinning. Standard layout.
const F4_000C1004 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003080b0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002600000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007cf9a80db3b29ee8efe3710aadb7b95270572d470000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000003c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000007f8f55a000000000000000000000000000000000ffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000007cf9a80db3b29ee8efe3710aadb7b95270572d47000000000000000000000000000000000000000000000000000000007f8f55a0");

test "B1: live fixture - SWAP_EXACT_OUT_SINGLE (amount_in_maximum = uint128 max) + SETTLE + TAKE_ALL (0x3b24c8cd...)" {
    const plan = v4.parsePlan(&F4_000C1004);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x08, 0x0b, 0x0f }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x08), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_out_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{
        .currency0 = ZERO_ADDR,
        .currency1 = addr("7cf9a80db3b29ee8efe3710aadb7b95270572d47"),
        .fee = 3000,
        .tick_spacing = 60,
        .hooks = ZERO_ADDR,
    }, s0.pool_key);
    try testing.expectEqual(true, s0.zero_for_one);
    try testing.expectEqual(@as(u128, 2140100000), s0.amount_out);
    try testing.expectEqual(@as(u128, std.math.maxInt(u128)), s0.amount_in_maximum);
    try testing.expectEqualSlices(u8, &[_]u8{}, s0.hook_data);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0b), a1.raw);
    const s1 = switch (a1.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &ZERO_ADDR, &s1.currency);
    try testing.expectEqual(@as(u256, 0), s1.amount);
    try testing.expectEqual(false, s1.payer_is_user);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0f), a2.raw);
    const s2 = switch (a2.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = addr("7cf9a80db3b29ee8efe3710aadb7b95270572d47"), .amount = 2140100000 }, s2);

    try testing.expect(it.next() == null);
}

// tx 0x0a59d21307e0f3266392308da59170c8dbd8feb2b23fd7dcce80e1b10956701d block
// 26042088, commands 01,01,10 -> V4_SWAP actions 09 (SWAP_EXACT_OUT,
// multi-hop, 2 hops), 0b (SETTLE), 0e (TAKE). Standard layout.
const F5_010110 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003090b0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000020000000000000000000000000aea46a60368a7bd060eec7df8cba43b7ef41ad85000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000c84643a169d9a50000000000000000000000000000000000000000000000000000000000002b5ad85000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000aea46a60368a7bd060eec7df8cba43b7ef41ad8500000000000000000000000054af09561966412ae840aa709f010cd596d64ca70000000000000000000000000000000000000000000000000000000000000000");

test "B1: live fixture - SWAP_EXACT_OUT(multi 2-hop) + SETTLE + TAKE (0x0a59d213...)" {
    const plan = v4.parsePlan(&F5_010110);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x09, 0x0b, 0x0e }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x09), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_out => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("aea46a60368a7bd060eec7df8cba43b7ef41ad85"), &s0.currency_out);
    try testing.expectEqual(@as(usize, 2), s0.path.len());
    try expectPathKey(.{
        .intermediate_currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        .fee = 100,
        .tick_spacing = 1,
        .hooks = ZERO_ADDR,
        .hook_data = &[_]u8{},
    }, s0.path.get(0));
    try expectPathKey(.{
        .intermediate_currency = ZERO_ADDR,
        .fee = 3000,
        .tick_spacing = 60,
        .hooks = ZERO_ADDR,
        .hook_data = &[_]u8{},
    }, s0.path.get(1));
    try testing.expectEqual(@as(u128, 230900742664000000000), s0.amount_out);
    try testing.expectEqual(@as(u128, 45460869), s0.amount_in_maximum);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0b), a1.raw);
    const s1 = switch (a1.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), &s1.currency);
    try testing.expectEqual(@as(u256, 0), s1.amount);
    try testing.expectEqual(true, s1.payer_is_user);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0e), a2.raw);
    const s2 = switch (a2.payload) {
        .take => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{
        .currency = addr("aea46a60368a7bd060eec7df8cba43b7ef41ad85"),
        .recipient = addr("54af09561966412ae840aa709f010cd596d64ca7"),
        .amount = 0,
    }, s2);

    try testing.expect(it.next() == null);
}

// tx 0xc11f1e3d9c5ebce5e23e11e955d1c7a389530d4d4f45c3cda8503ac0a6cfb0e2 block
// 26042985, single UR command 0x10 with 4 V4 actions: 07 (SWAP_EXACT_IN,
// multi-hop, 2 hops, native ETH in), 0c (SETTLE_ALL), 10 (TAKE_PORTION --
// the only fixture with this action), 0f (TAKE_ALL). Standard layout.
const F6_1005 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000004070c100f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003800000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000265e8af39300000000000000000000000000000000000000000000000000000000000001b06b51000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000265e8af39300000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000066a9893cc07d91d95644aedd05d03f95e1dba8af00000000000000000000000000000000000000000000000000000000000000550000000000000000000000000000000000000000000000000000000000000040000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000001b06b51");

test "B1: live fixture - SWAP_EXACT_IN(multi 2-hop, native in) + SETTLE_ALL + TAKE_PORTION + TAKE_ALL (0xc11f1e3d...)" {
    const plan = v4.parsePlan(&F6_1005);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x07, 0x0c, 0x10, 0x0f }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x07), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_in => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &ZERO_ADDR, &s0.currency_in);
    try testing.expectEqual(@as(usize, 2), s0.path.len());
    try expectPathKey(.{
        .intermediate_currency = addr("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        .fee = 500,
        .tick_spacing = 10,
        .hooks = ZERO_ADDR,
        .hook_data = &[_]u8{},
    }, s0.path.get(0));
    try expectPathKey(.{
        .intermediate_currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        .fee = 500,
        .tick_spacing = 10,
        .hooks = ZERO_ADDR,
        .hook_data = &[_]u8{},
    }, s0.path.get(1));
    try testing.expectEqual(@as(u128, 10800000000000000), s0.amount_in);
    try testing.expectEqual(@as(u128, 28339025), s0.amount_out_minimum);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0c), a1.raw);
    const s1 = switch (a1.payload) {
        .settle_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = ZERO_ADDR, .amount = 10800000000000000 }, s1);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x10), a2.raw);
    const s2 = switch (a2.payload) {
        .take_portion => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{
        .currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        .recipient = addr("66a9893cc07d91d95644aedd05d03f95e1dba8af"),
        .amount = 85,
    }, s2);

    const a3 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0f), a3.raw);
    const s3 = switch (a3.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), .amount = 28339025 }, s3);

    try testing.expect(it.next() == null);
}

// tx 0xc667bd6592be64caa2190832f0730dfea2f7607a6b3deed45a96b2706256a857 block
// 26042826, UR selector 0x24856bc3 (execute(bytes,bytes[]), no deadline arg
// -- a different top-level selector than the other 7 fixtures, extra
// diversity for the "one V4_SWAP input, decoded standalone" contract).
// V4_SWAP actions 06, 0f (TAKE_ALL), 0c (SETTLE_ALL). Standard layout.
const F7_24856BC3_10 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003060f0c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000118b70df4f06fa5678e7d543e6066e028c8ea0c0000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000009c400000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000010f0cf064dd5920000000000000000000000000000000000000000000000000000000000000270a5dd8000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000118b70df4f06fa5678e7d543e6066e028c8ea0c000000000000000000000000000000000000000000000010f0cf064dd59200000");

test "B1: live fixture - SWAP_EXACT_IN_SINGLE + TAKE_ALL + SETTLE_ALL, execute(bytes,bytes[]) selector (0xc667bd65...)" {
    const plan = v4.parsePlan(&F7_24856BC3_10);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x06, 0x0f, 0x0c }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x06), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_in_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{
        .currency0 = addr("118b70df4f06fa5678e7d543e6066e028c8ea0c0"),
        .currency1 = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        .fee = 2500,
        .tick_spacing = 25,
        .hooks = ZERO_ADDR,
    }, s0.pool_key);
    try testing.expectEqual(true, s0.zero_for_one);
    try testing.expectEqual(@as(u128, 5000000000000000000000), s0.amount_in);
    try testing.expectEqual(@as(u128, 654990808), s0.amount_out_minimum);
    try testing.expectEqualSlices(u8, &[_]u8{}, s0.hook_data);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0f), a1.raw);
    const s1 = switch (a1.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), .amount = 0 }, s1);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0c), a2.raw);
    const s2 = switch (a2.payload) {
        .settle_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = addr("118b70df4f06fa5678e7d543e6066e028c8ea0c0"), .amount = 5000000000000000000000 }, s2);

    try testing.expect(it.next() == null);
}

// tx 0xb9c86521d2a93a15c2b172f193cc61ebfef909589380fd1d0fc69ab054450e2f block
// 26042476, commands 0a,10,04 -> V4_SWAP actions 07 (SWAP_EXACT_IN, multi-hop,
// 2 hops, both with a non-zero hooks address -- path[1].fee has the
// LPFeeLibrary dynamic-fee-flag bit (0x800000) set, a real edge case within
// u24's range), 0b (SETTLE), 0e (TAKE). Standard layout.
const F8_0A1004 = fixtureBytes("0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003070b0e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000380000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000200000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000006b2c78df8b9b97dd0000000000000000000000000000000000000000000000000000000000759b14d9f000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000958942af77dcd973b815b2a16bd88a5134c4688800000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000113dcf4add69999fad8f20f2b63f979bfcc000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000006b175474e89094c44da98b954eedeac495271d0f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000035036a9cf3834df85462b0f3a70ca8e94fc252590000000000000000000000000000000000000000000000000000000000000000");

test "B1: live fixture - SWAP_EXACT_IN(multi 2-hop, hooked path + dynamic-fee flag) + SETTLE + TAKE (0xb9c86521...)" {
    const plan = v4.parsePlan(&F8_0A1004);
    try testing.expect(plan != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x07, 0x0b, 0x0e }, plan.?.actions);

    var it = plan.?.iterator();

    const a0 = it.next().?;
    try testing.expectEqual(@as(u8, 0x07), a0.raw);
    const s0 = switch (a0.payload) {
        .swap_exact_in => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("6b175474e89094c44da98b954eedeac495271d0f"), &s0.currency_in);
    try testing.expectEqual(@as(usize, 2), s0.path.len());
    try expectPathKey(.{
        .intermediate_currency = addr("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        .fee = 0,
        .tick_spacing = 1,
        .hooks = addr("958942af77dcd973b815b2a16bd88a5134c46888"),
        .hook_data = &[_]u8{},
    }, s0.path.get(0));
    try expectPathKey(.{
        .intermediate_currency = addr("dac17f958d2ee523a2206206994597c13d831ec7"),
        .fee = 8388608, // 0x800000 = LPFeeLibrary.DYNAMIC_FEE_FLAG, within u24's range
        .tick_spacing = 1,
        .hooks = addr("0000113dcf4add69999fad8f20f2b63f979bfcc0"),
        .hook_data = &[_]u8{},
    }, s0.path.get(1));
    try testing.expectEqual(@as(u128, 31632098765000000000000), s0.amount_in);
    try testing.expectEqual(@as(u128, 31569563039), s0.amount_out_minimum);

    const a1 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0b), a1.raw);
    const s1 = switch (a1.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &addr("6b175474e89094c44da98b954eedeac495271d0f"), &s1.currency);
    try testing.expectEqual(@as(u256, 0), s1.amount);
    try testing.expectEqual(true, s1.payer_is_user);

    const a2 = it.next().?;
    try testing.expectEqual(@as(u8, 0x0e), a2.raw);
    const s2 = switch (a2.payload) {
        .take => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{
        .currency = addr("dac17f958d2ee523a2206206994597c13d831ec7"),
        .recipient = addr("35036a9cf3834df85462b0f3a70ca8e94fc25259"),
        .amount = 0,
    }, s2);

    try testing.expect(it.next() == null);
}

/// Every B1 fixture above, for B5's hostile-input sweep (prefix truncation +
/// byte mutation).
const all_fixtures = [_][]const u8{
    &F1_NO_OFFSET_0A0210,
    &F2_NO_OFFSET_100604,
    &F3_000010000C,
    &F4_000C1004,
    &F5_010110,
    &F6_1005,
    &F7_24856BC3_10,
    &F8_0A1004,
};

// ============================================================================
// B2: round trips of the only accepted layout (live) for all 4 swap
// actions, plus settle/settle_all/take/take_all/take_portion, plus an
// unknown action byte.
//
// R1: the "main layout" (current v4-periphery main branch, with
// minHopPriceX36) tests below no longer round-trip -- they now assert
// `parsePlan` returns null for the whole plan. Why: the deployed Universal
// Router (0x66a9893cc07d91d95644aedd05d03f95e1dba8af) reads swap amounts
// from different word offsets than the main-layout struct puts them at
// (it never grew the minHopPriceX36 field). A reviewer fork repro against
// that router showed a main-layout-shaped SWAP_EXACT_OUT input decoding
// amount_out as 1e15 while the chain executed 416 -- a well-formed ABI
// encoding that silently misdecoded live amounts. So a main-layout
// encoding must now fail closed instead of decoding: this is an accept/
// reject decision, not a values-differ decision, hence `null`. The
// `min_hop_price_x36` fields are removed from the V4 structs, since no
// deployed router reads them (see v4.zig).
// ============================================================================

/// Build the full V4_SWAP input `abi.encode(bytes actions, bytes[] params)`
/// from an actions byte string and the already-encoded params blob for each.
fn buildPlanInput(allocator: std.mem.Allocator, actions: []const u8, params: []const []const u8) ![]u8 {
    var params_av_buf: [8]AV = undefined;
    for (params, 0..) |p, i| params_av_buf[i] = .{ .bytes = p };
    const values = [_]AV{
        .{ .bytes = actions },
        .{ .array = params_av_buf[0..params.len] },
    };
    return abi_encode.encodeValues(allocator, &values);
}

/// Build one swap action's params: `abi.encode(StructType)` -- a single
/// dynamic-tuple argument, which always carries a leading offset word. This
/// is exactly the "struct = params + word0" shape `parsePlan` must locate.
fn buildSwapParams(allocator: std.mem.Allocator, fields: []const AV) ![]u8 {
    const values = [_]AV{.{ .tuple = fields }};
    return abi_encode.encodeValues(allocator, &values);
}

/// Build one non-swap action's params: `abi.decode(params, (T1, T2, ...))`
/// with no wrapping struct -- a flat concatenation of static fields, no
/// leading offset word.
fn buildPlainParams(allocator: std.mem.Allocator, fields: []const AV) ![]u8 {
    return abi_encode.encodeValues(allocator, fields);
}

test "B2: round trip - SWAP_EXACT_IN_SINGLE, live layout (no minHopPriceX36)" {
    const allocator = testing.allocator;
    const hook_data = [_]u8{ 0xAB, 0xCD, 0xEF };
    const pool_key_fields = [_]AV{
        .{ .address = TOKEN_A },   .{ .address = TOKEN_B },
        .{ .uint256 = 3000 },      .{ .int256 = 60 },
        .{ .address = ZERO_ADDR },
    };
    const struct_fields = [_]AV{
        .{ .tuple = &pool_key_fields },
        .{ .boolean = true },
        .{ .uint256 = 1_000_000 },
        .{ .uint256 = 900_000 },
        .{ .bytes = &hook_data },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_in_single};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.swap_exact_in_single), a.raw);
    const s = switch (a.payload) {
        .swap_exact_in_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{ .currency0 = TOKEN_A, .currency1 = TOKEN_B, .fee = 3000, .tick_spacing = 60, .hooks = ZERO_ADDR }, s.pool_key);
    try testing.expectEqual(true, s.zero_for_one);
    try testing.expectEqual(@as(u128, 1_000_000), s.amount_in);
    try testing.expectEqual(@as(u128, 900_000), s.amount_out_minimum);
    try testing.expectEqualSlices(u8, &hook_data, s.hook_data);
    try testing.expect(it.next() == null);
}

test "R1: SWAP_EXACT_IN_SINGLE, main layout (minHopPriceX36) -> parsePlan null" {
    const allocator = testing.allocator;
    const hook_data = [_]u8{0x42};
    const pool_key_fields = [_]AV{
        .{ .address = TOKEN_A },    .{ .address = TOKEN_B },
        .{ .uint256 = 500 },        .{ .int256 = -10 },
        .{ .address = HOOKS_ADDR },
    };
    const struct_fields = [_]AV{
        .{ .tuple = &pool_key_fields },
        .{ .boolean = false },
        .{ .uint256 = 2_000_000 },
        .{ .uint256 = 1_800_000 },
        .{ .uint256 = 123456789 }, // minHopPriceX36: no longer accepted, see the R1 comment above
        .{ .bytes = &hook_data },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_in_single};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(input));
}

test "B2: round trip - SWAP_EXACT_OUT_SINGLE, live layout (no minHopPriceX36)" {
    const allocator = testing.allocator;
    const pool_key_fields = [_]AV{
        .{ .address = TOKEN_B },   .{ .address = TOKEN_C },
        .{ .uint256 = 10000 },     .{ .int256 = 200 },
        .{ .address = ZERO_ADDR },
    };
    const struct_fields = [_]AV{
        .{ .tuple = &pool_key_fields },
        .{ .boolean = true },
        .{ .uint256 = 500_000 },
        .{ .uint256 = 520_000 },
        .{ .bytes = &[_]u8{} },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_out_single};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    const s = switch (a.payload) {
        .swap_exact_out_single => |p| p,
        else => return error.WrongVariant,
    };
    try expectPoolKey(.{ .currency0 = TOKEN_B, .currency1 = TOKEN_C, .fee = 10000, .tick_spacing = 200, .hooks = ZERO_ADDR }, s.pool_key);
    try testing.expectEqual(true, s.zero_for_one);
    try testing.expectEqual(@as(u128, 500_000), s.amount_out);
    try testing.expectEqual(@as(u128, 520_000), s.amount_in_maximum);
    try testing.expectEqualSlices(u8, &[_]u8{}, s.hook_data);
    try testing.expect(it.next() == null);
}

test "R1: SWAP_EXACT_OUT_SINGLE, main layout (minHopPriceX36) -> parsePlan null" {
    const allocator = testing.allocator;
    const pool_key_fields = [_]AV{
        .{ .address = TOKEN_B },    .{ .address = TOKEN_C },
        .{ .uint256 = 3000 },       .{ .int256 = -60 },
        .{ .address = HOOKS_ADDR },
    };
    const struct_fields = [_]AV{
        .{ .tuple = &pool_key_fields },
        .{ .boolean = false },
        .{ .uint256 = 700_000 },
        .{ .uint256 = 750_000 },
        .{ .uint256 = 987654321 }, // minHopPriceX36: no longer accepted, see the R1 comment above
        .{ .bytes = &[_]u8{} },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_out_single};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(input));
}

test "B2: round trip - SWAP_EXACT_IN, live layout (2-hop path, no minHopPriceX36[])" {
    const allocator = testing.allocator;
    const hd1 = [_]u8{0x01};
    const pk0_fields = [_]AV{ .{ .address = TOKEN_B }, .{ .uint256 = 500 }, .{ .int256 = 10 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const pk1_fields = [_]AV{ .{ .address = TOKEN_C }, .{ .uint256 = 3000 }, .{ .int256 = 60 }, .{ .address = HOOKS_ADDR }, .{ .bytes = &hd1 } };
    const path_items = [_]AV{ .{ .tuple = &pk0_fields }, .{ .tuple = &pk1_fields } };
    const struct_fields = [_]AV{
        .{ .address = TOKEN_A },
        .{ .array = &path_items },
        .{ .uint256 = 5_000_000 },
        .{ .uint256 = 4_900_000 },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_in};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    const s = switch (a.payload) {
        .swap_exact_in => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &TOKEN_A, &s.currency_in);
    try testing.expectEqual(@as(usize, 2), s.path.len());
    try expectPathKey(.{ .intermediate_currency = TOKEN_B, .fee = 500, .tick_spacing = 10, .hooks = ZERO_ADDR, .hook_data = &[_]u8{} }, s.path.get(0));
    try expectPathKey(.{ .intermediate_currency = TOKEN_C, .fee = 3000, .tick_spacing = 60, .hooks = HOOKS_ADDR, .hook_data = &hd1 }, s.path.get(1));
    try testing.expectEqual(@as(u128, 5_000_000), s.amount_in);
    try testing.expectEqual(@as(u128, 4_900_000), s.amount_out_minimum);
    try testing.expect(it.next() == null);
}

test "R1: SWAP_EXACT_IN, main layout (2-hop path, minHopPriceX36[]) -> parsePlan null" {
    const allocator = testing.allocator;
    const pk0_fields = [_]AV{ .{ .address = TOKEN_B }, .{ .uint256 = 500 }, .{ .int256 = 10 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const pk1_fields = [_]AV{ .{ .address = TOKEN_C }, .{ .uint256 = 3000 }, .{ .int256 = 60 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const path_items = [_]AV{ .{ .tuple = &pk0_fields }, .{ .tuple = &pk1_fields } };
    const min_hop_items = [_]AV{ .{ .uint256 = 111 }, .{ .uint256 = 222 } }; // minHopPriceX36[]: no longer accepted, see the R1 comment above
    const struct_fields = [_]AV{
        .{ .address = TOKEN_A },
        .{ .array = &path_items },
        .{ .array = &min_hop_items },
        .{ .uint256 = 6_000_000 },
        .{ .uint256 = 5_900_000 },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_in};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(input));
}

test "B2: round trip - SWAP_EXACT_OUT, live layout (2-hop path, no minHopPriceX36[])" {
    const allocator = testing.allocator;
    const pk0_fields = [_]AV{ .{ .address = TOKEN_A }, .{ .uint256 = 500 }, .{ .int256 = 10 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const pk1_fields = [_]AV{ .{ .address = TOKEN_B }, .{ .uint256 = 3000 }, .{ .int256 = 60 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const path_items = [_]AV{ .{ .tuple = &pk0_fields }, .{ .tuple = &pk1_fields } };
    const struct_fields = [_]AV{
        .{ .address = TOKEN_C },
        .{ .array = &path_items },
        .{ .uint256 = 3_000_000 },
        .{ .uint256 = 3_100_000 },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_out};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    const s = switch (a.payload) {
        .swap_exact_out => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &TOKEN_C, &s.currency_out);
    try testing.expectEqual(@as(usize, 2), s.path.len());
    try testing.expectEqual(@as(u128, 3_000_000), s.amount_out);
    try testing.expectEqual(@as(u128, 3_100_000), s.amount_in_maximum);
    try testing.expect(it.next() == null);
}

test "R1: SWAP_EXACT_OUT, main layout (2-hop path, minHopPriceX36[]) -> parsePlan null" {
    const allocator = testing.allocator;
    const pk0_fields = [_]AV{ .{ .address = TOKEN_A }, .{ .uint256 = 500 }, .{ .int256 = 10 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const pk1_fields = [_]AV{ .{ .address = TOKEN_B }, .{ .uint256 = 3000 }, .{ .int256 = 60 }, .{ .address = ZERO_ADDR }, .{ .bytes = &[_]u8{} } };
    const path_items = [_]AV{ .{ .tuple = &pk0_fields }, .{ .tuple = &pk1_fields } };
    const min_hop_items = [_]AV{ .{ .uint256 = 333 }, .{ .uint256 = 444 } }; // minHopPriceX36[]: no longer accepted, see the R1 comment above
    const struct_fields = [_]AV{
        .{ .address = TOKEN_C },
        .{ .array = &path_items },
        .{ .array = &min_hop_items },
        .{ .uint256 = 4_000_000 },
        .{ .uint256 = 4_100_000 },
    };
    const params = try buildSwapParams(allocator, &struct_fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.swap_exact_out};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(input));
}

// ============================================================================
// R1/R6: single-hop hookData-offset-word and multi-hop path-offset-word
// probes. Each starts from an otherwise-valid live-layout struct (the same
// shape as the "B2: round trip - SWAP_EXACT_IN_SINGLE, live layout" /
// "... SWAP_EXACT_IN, live layout" fixtures above) and patches only the one
// word that carries the offset value -- everything else, including the
// physical position of the bytes that word points at, is untouched. 0x120
// (single-hop) and 0x80 (multi-hop) are the only values `parsePlan`
// accepts; every other value, including the old main-layout's 0x140 /
// 0xa0, must reject.
// ============================================================================

test "R1/R6: single-hop hookData offset word in {0x00, 0x60, 0x100, 0x140, 0x160} -> parsePlan null" {
    const allocator = testing.allocator;
    const bad_offsets = [_]u256{ 0x00, 0x60, 0x100, 0x140, 0x160 };
    for (bad_offsets) |bad_offset| {
        var pb = Builder.init(allocator);
        defer pb.deinit();
        try pb.w(0x20); // struct offset: standard "struct = params + word0"
        try pb.wAddr(TOKEN_A); // currency0
        try pb.wAddr(TOKEN_B); // currency1
        try pb.w(3000); // fee
        try pb.w(60); // tickSpacing
        try pb.wAddr(ZERO_ADDR); // hooks
        try pb.w(1); // zeroForOne = true
        try pb.w(1_000_000); // amountIn
        try pb.w(900_000); // amountOutMinimum
        try pb.w(bad_offset); // hookData offset word: patched to the value under test
        try pb.w(0); // hookData length = 0, physically right where 0x120 would point -- unread once the offset check rejects
        const param = try pb.ownedSlice();
        defer allocator.free(param);

        var b = Builder.init(allocator);
        defer b.deinit();
        try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
        const data = try b.ownedSlice();
        defer allocator.free(data);
        try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
    }
}

test "R1/R6: multi-hop path offset word set to 0xa0 (old main-layout marker) -> parsePlan null" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20); // struct offset
    try pb.wAddr(TOKEN_A); // currencyIn
    try pb.w(0xa0); // path offset word: patched to the old main-layout's marker value
    try pb.w(1_000_000); // amountIn, at the live-layout's fixed position (unaffected by the offset word's declared value)
    try pb.w(900_000); // amountOutMinimum, likewise fixed
    try pb.w(0); // filler word at struct_base+0x80, so a genuinely valid empty path array sits exactly at the declared 0xa0
    try pb.w(0); // path array: count = 0 -- a real, well-formed PathKeys[] at 0xa0; only the offset *value* must be rejected
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B2: round trip - SETTLE" {
    const allocator = testing.allocator;
    const fields = [_]AV{ .{ .address = TOKEN_A }, .{ .uint256 = 12345 }, .{ .boolean = true } };
    const params = try buildPlainParams(allocator, &fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.settle};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.settle), a.raw);
    const s = switch (a.payload) {
        .settle => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqualSlices(u8, &TOKEN_A, &s.currency);
    try testing.expectEqual(@as(u256, 12345), s.amount);
    try testing.expectEqual(true, s.payer_is_user);
    try testing.expect(it.next() == null);
}

test "B2: round trip - SETTLE_ALL" {
    const allocator = testing.allocator;
    const fields = [_]AV{ .{ .address = TOKEN_B }, .{ .uint256 = 999999 } };
    const params = try buildPlainParams(allocator, &fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.settle_all};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.settle_all), a.raw);
    const s = switch (a.payload) {
        .settle_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = TOKEN_B, .amount = 999999 }, s);
    try testing.expect(it.next() == null);
}

test "B2: round trip - TAKE" {
    const allocator = testing.allocator;
    const fields = [_]AV{ .{ .address = TOKEN_A }, .{ .address = RECIPIENT }, .{ .uint256 = 42424242 } };
    const params = try buildPlainParams(allocator, &fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.take};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.take), a.raw);
    const s = switch (a.payload) {
        .take => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{ .currency = TOKEN_A, .recipient = RECIPIENT, .amount = 42424242 }, s);
    try testing.expect(it.next() == null);
}

test "B2: round trip - TAKE_ALL" {
    const allocator = testing.allocator;
    const fields = [_]AV{ .{ .address = TOKEN_C }, .{ .uint256 = 7 } };
    const params = try buildPlainParams(allocator, &fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.take_all};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.take_all), a.raw);
    const s = switch (a.payload) {
        .take_all => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyAmount(.{ .currency = TOKEN_C, .amount = 7 }, s);
    try testing.expect(it.next() == null);
}

test "B2: round trip - TAKE_PORTION" {
    const allocator = testing.allocator;
    const fields = [_]AV{ .{ .address = TOKEN_B }, .{ .address = RECIPIENT }, .{ .uint256 = 500 } }; // 5.00%
    const params = try buildPlainParams(allocator, &fields);
    defer allocator.free(params);
    const actions = [_]u8{v4.actions.take_portion};
    const params_slices = [_][]const u8{params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, v4.actions.take_portion), a.raw);
    const s = switch (a.payload) {
        .take_portion => |p| p,
        else => return error.WrongVariant,
    };
    try expectCurrencyRecipientAmount(.{ .currency = TOKEN_B, .recipient = RECIPIENT, .amount = 500 }, s);
    try testing.expect(it.next() == null);
}

test "B2: round trip - unknown action byte (0x14) is .other with raw params" {
    const allocator = testing.allocator;
    const raw_params = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    const actions = [_]u8{0x14};
    const params_slices = [_][]const u8{&raw_params};
    const input = try buildPlanInput(allocator, &actions, &params_slices);
    defer allocator.free(input);

    const plan = v4.parsePlan(input);
    try testing.expect(plan != null);
    var it = plan.?.iterator();
    const a = it.next().?;
    try testing.expectEqual(@as(u8, 0x14), a.raw);
    const s = switch (a.payload) {
        .other => |p| p,
        else => return error.WrongVariant,
    };
    try testing.expectEqual(@as(u8, 0x14), s.action);
    try testing.expectEqualSlices(u8, &raw_params, s.params);
    try testing.expect(it.next() == null);
}

// ============================================================================
// B5: crafted rejections -- every one of these must decode to null.
// ============================================================================

test "B5: attack - actions.len != params.len" {
    const allocator = testing.allocator;
    var b = Builder.init(allocator);
    defer b.deinit();
    const actions_content = [_]u8{ v4.actions.settle_all, v4.actions.take_all }; // 2 actions
    try b.w(0x40); // actions offset
    try b.w(0x40 + 64); // params offset: actions tail = 32 (len) + 32 (2 bytes padded to a word) = 64
    try b.w(actions_content.len); // actions.length = 2
    try b.raw(&actions_content);
    try b.padZero(30);
    // params: bytes[] with only ONE element -- mismatch with actions.length = 2.
    try b.w(1); // params.length = 1
    try b.w(0x20); // params[0] offset
    try b.w(64); // params[0].length
    try b.wAddr(TOKEN_A);
    try b.w(999);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - int24 tick_spacing bad sign extension" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20); // struct offset: standard "struct = params + word0"
    try pb.wAddr(TOKEN_A); // currency0
    try pb.wAddr(TOKEN_B); // currency1
    try pb.w(3000); // fee
    try pb.wRaw(blk: {
        var word: [32]u8 = @splat(0);
        word[0] = 0x01; // dirty: nonzero far above int24's sign-extension range
        word[31] = 60; // tickSpacing = 60 (positive) in the low byte
        break :blk word;
    });
    try pb.wAddr(ZERO_ADDR); // hooks
    try pb.w(1); // zeroForOne = true
    try pb.w(1_000_000); // amountIn
    try pb.w(900_000); // amountOutMinimum
    try pb.w(0x120); // hookData offset (rel. to struct start)
    try pb.w(0); // hookData length = 0
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - uint128 amount_in with high bits set" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20);
    try pb.wAddr(TOKEN_A);
    try pb.wAddr(TOKEN_B);
    try pb.w(3000);
    try pb.w(60);
    try pb.wAddr(ZERO_ADDR);
    try pb.w(1);
    try pb.wRaw(blk: {
        // amountIn: uint128 occupies only the low 16 bytes (word[16..32]);
        // set a bit above that boundary.
        var word: [32]u8 = @splat(0);
        word[10] = 0x01;
        word[31] = 0x01;
        break :blk word;
    });
    try pb.w(900_000); // amountOutMinimum
    try pb.w(0x120);
    try pb.w(0);
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - uint24 fee with high bits set" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20);
    try pb.wAddr(TOKEN_A);
    try pb.wAddr(TOKEN_B);
    try pb.wRaw(blk: {
        // fee: uint24 occupies only the low 3 bytes; set a bit above that.
        var word: [32]u8 = @splat(0);
        word[28] = 0x01; // bit 24 set: outside uint24's range
        word[30] = 0x01;
        word[31] = 0xf4; // fee = 500 (0x01f4) in the low 3 bytes
        break :blk word;
    });
    try pb.w(60);
    try pb.wAddr(ZERO_ADDR);
    try pb.w(1);
    try pb.w(1_000_000);
    try pb.w(900_000);
    try pb.w(0x120);
    try pb.w(0);
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - bool word equals 2 (zero_for_one)" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20);
    try pb.wAddr(TOKEN_A);
    try pb.wAddr(TOKEN_B);
    try pb.w(3000);
    try pb.w(60);
    try pb.wAddr(ZERO_ADDR);
    try pb.w(2); // zeroForOne: invalid (must be 0 or 1)
    try pb.w(1_000_000);
    try pb.w(900_000);
    try pb.w(0x120);
    try pb.w(0);
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - dirty address padding in PoolKey (hooks)" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20);
    try pb.wAddr(TOKEN_A);
    try pb.wAddr(TOKEN_B);
    try pb.w(3000);
    try pb.w(60);
    // hooks word: real address in the low 20 bytes, but a nonzero byte in
    // the padding region that real ABI-encoded calldata always zeros.
    try pb.wRaw(blk: {
        var dirty: [32]u8 = @splat(0);
        dirty[0] = 0x01;
        @memcpy(dirty[12..32], &HOOKS_ADDR);
        break :blk dirty;
    });
    try pb.w(1);
    try pb.w(1_000_000);
    try pb.w(900_000);
    try pb.w(0x120);
    try pb.w(0);
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - path offset pointing out of bounds (multi-hop)" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20); // struct offset
    try pb.wAddr(TOKEN_A); // currencyIn
    try pb.w(0xFFFFFFFF); // path offset: far past the end
    try pb.w(1_000_000); // amountIn
    try pb.w(900_000); // amountOutMinimum
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - hookData length runs past the end" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    try pb.w(0x20);
    try pb.wAddr(TOKEN_A);
    try pb.wAddr(TOKEN_B);
    try pb.w(3000);
    try pb.w(60);
    try pb.wAddr(ZERO_ADDR);
    try pb.w(1);
    try pb.w(1_000_000);
    try pb.w(900_000);
    try pb.w(0x120); // hookData offset: correct location
    try pb.w(0xFFFFFFFF); // hookData length: absurdly large, no such bytes exist
    const param = try pb.ownedSlice();
    defer allocator.free(param);

    var b = Builder.init(allocator);
    defer b.deinit();
    try writeSingleAction(&b, v4.actions.swap_exact_in_single, param);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

test "B5: attack - aliased params elements" {
    const allocator = testing.allocator;
    var pb = Builder.init(allocator);
    defer pb.deinit();
    // A 2-element bytes[] array where element 0 is valid (empty, length 0,
    // so its own decode cannot fail) and element 1's offset is identical to
    // element 0's -- aliased, violating the canonical "at or past element
    // i-1's data end" layout `abi_reader.bytesArrayAt` requires.
    try pb.w(2); // params.length = 2
    try pb.w(0x40); // params[0] offset
    try pb.w(0x40); // params[1] offset: ALIASED (equal to params[0])
    try pb.w(0); // params[0].length = 0
    const params_region = try pb.ownedSlice();
    defer allocator.free(params_region);

    var b = Builder.init(allocator);
    defer b.deinit();
    const actions = [_]u8{ v4.actions.settle_all, v4.actions.take_all };
    try b.w(0x40); // actions offset
    try b.w(0x40 + 64); // params offset
    try b.w(actions.len);
    try b.raw(&actions);
    try b.padZero(30);
    try b.raw(params_region);
    const data = try b.ownedSlice();
    defer allocator.free(data);
    try testing.expectEqual(@as(?v4.Plan, null), v4.parsePlan(data));
}

// ============================================================================
// B5: hostile input -- every prefix length, and 1,000 single-byte mutations
// per fixture, must return null or a value and never panic.
// ============================================================================

test "B5: hostile input - every prefix of every B1 fixture" {
    for (all_fixtures) |data| {
        var len: usize = 0;
        while (len <= data.len) : (len += 1) {
            if (v4.parsePlan(data[0..len])) |plan| walkPlan(plan);
        }
    }
}

test "B5: hostile input - 1,000 single-byte mutations per B1 fixture, fixed seed" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_D00D_1234);
    const rnd = prng.random();

    for (all_fixtures) |data| {
        if (data.len == 0) continue;
        const mutated = try allocator.alloc(u8, data.len);
        defer allocator.free(mutated);

        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            @memcpy(mutated, data);
            const idx = rnd.uintLessThan(usize, data.len);
            mutated[idx] = rnd.int(u8);
            if (v4.parsePlan(mutated)) |plan| walkPlan(plan);
        }
    }
}
