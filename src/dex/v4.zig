//! Uniswap V4 swap plans, as carried by the Universal Router `V4_SWAP`
//! command (0x10).
//!
//! The command input is `abi.encode(bytes actions, bytes[] params)`: one
//! action byte per params entry (v4-periphery `BaseActionsRouter`). The
//! V4Router executes only the swap, settle and take actions typed below
//! (V4Router.sol:34-82); every other action byte arrives as `.other`.
//!
//! Swap params are located the way the contract locates them: the struct
//! starts at `params + word0` (CalldataDecoder.sol). Only the layout the
//! deployed Universal Router (0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af)
//! executes is accepted: single-hop `hookData` offset 0x120, multi-hop
//! `path` offset 0x80. v4-periphery main-branch calldata, which carries an
//! extra `minHopPriceX36` field (single-hop hookData offset 0x140,
//! multi-hop path offset 0xa0), is rejected: the deployed router has no
//! `minHopPriceX36` slot, so it reads `amount`/`hookData`/`path` from
//! different words than that layout would put them at.
//!
//! Same guarantees as `calldata.zig`: no allocation, no panics, and a
//! non-null `parsePlan` makes every accessor and iterator infallible.

const std = @import("std");
const reader = @import("abi_reader.zig");

pub const BytesArray = reader.BytesArray;
pub const U256Array = reader.U256Array;

const addChecked = reader.addChecked;
const roundUpWord = reader.roundUpWord;
const wordToUsize = reader.wordToUsize;
const readU256At = reader.readU256At;
const readOffset = reader.readOffset;
const readAddressAt = reader.readAddressAt;
const readBoolAt = reader.readBoolAt;
const readFeeAt = reader.readFeeAt;
const readUintAt = reader.readUintAt;
const readIntAt = reader.readIntAt;
const bytesAt = reader.bytesAt;
const arrayHeadAt = reader.arrayHeadAt;
const bytesArrayAt = reader.bytesArrayAt;

/// v4-periphery Actions.sol values for the actions V4Router executes.
pub const actions = struct {
    pub const swap_exact_in_single: u8 = 0x06;
    pub const swap_exact_in: u8 = 0x07;
    pub const swap_exact_out_single: u8 = 0x08;
    pub const swap_exact_out: u8 = 0x09;
    pub const settle: u8 = 0x0b;
    pub const settle_all: u8 = 0x0c;
    pub const take: u8 = 0x0e;
    pub const take_all: u8 = 0x0f;
    pub const take_portion: u8 = 0x10;
};

/// A V4 pool identifier. `currency0 == 0` is native ETH.
pub const PoolKey = struct {
    currency0: [20]u8,
    currency1: [20]u8,
    fee: u24,
    tick_spacing: i24,
    hooks: [20]u8,
};

/// One hop of a multi-hop V4 path.
pub const PathKey = struct {
    intermediate_currency: [20]u8,
    fee: u24,
    tick_spacing: i24,
    hooks: [20]u8,
    hook_data: []const u8,
};

/// An ABI `PathKey[]`, borrowed from calldata; every element was validated.
pub const PathKeys = struct {
    /// The array's tail: element offset words start here.
    head: []const u8,
    count: usize,

    pub fn len(self: PathKeys) usize {
        return self.count;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: PathKeys, i: usize) PathKey {
        std.debug.assert(i < self.count);
        const off = readOffset(self.head, i * 32) orelse unreachable;
        return readPathKeyAt(self.head, off) orelse unreachable;
    }
};

pub const ExactInputSingle = struct {
    pool_key: PoolKey,
    zero_for_one: bool,
    /// 0 is OPEN_DELTA: the router swaps its full credit of the input currency.
    amount_in: u128,
    amount_out_minimum: u128,
    hook_data: []const u8,
};

pub const ExactOutputSingle = struct {
    pool_key: PoolKey,
    zero_for_one: bool,
    /// 0 is OPEN_DELTA: the router takes its full debt of the output currency.
    amount_out: u128,
    amount_in_maximum: u128,
    hook_data: []const u8,
};

pub const ExactInput = struct {
    currency_in: [20]u8,
    path: PathKeys,
    /// 0 is OPEN_DELTA: the router swaps its full credit of `currency_in`.
    amount_in: u128,
    amount_out_minimum: u128,
};

/// `path` runs from the output currency backwards, as in V4Router.
pub const ExactOutput = struct {
    currency_out: [20]u8,
    path: PathKeys,
    /// 0 is OPEN_DELTA: the router takes its full debt of `currency_out`.
    amount_out: u128,
    amount_in_maximum: u128,
};

pub const CurrencyAmount = struct {
    currency: [20]u8,
    amount: u256,
};

pub const CurrencyRecipientAmount = struct {
    currency: [20]u8,
    /// Raw value: `0x0…01` is msg.sender and `0x0…02` is the router
    /// (ActionConstants MSG_SENDER / ADDRESS_THIS); not resolved here.
    recipient: [20]u8,
    amount: u256,
};

pub const Action = struct {
    /// The raw action byte.
    raw: u8,
    payload: Payload,

    pub const Payload = union(enum) {
        swap_exact_in_single: ExactInputSingle,
        swap_exact_in: ExactInput,
        swap_exact_out_single: ExactOutputSingle,
        swap_exact_out: ExactOutput,
        settle: struct {
            currency: [20]u8,
            /// 0 is OPEN_DELTA (settle the full debt); 1 << 255 is
            /// CONTRACT_BALANCE (pay the router's whole balance).
            amount: u256,
            payer_is_user: bool,
        },
        /// `amount` is the maximum to settle.
        settle_all: CurrencyAmount,
        /// `amount` 0 is OPEN_DELTA: take the full credit.
        take: CurrencyRecipientAmount,
        /// `amount` is the minimum to take.
        take_all: CurrencyAmount,
        /// `amount` is the portion in basis points.
        take_portion: CurrencyRecipientAmount,
        /// Any other action byte, undecoded.
        other: struct {
            action: u8,
            params: []const u8,
        },
    };
};

/// A `V4_SWAP` plan: `actions.len == params.len()`.
pub const Plan = struct {
    actions: []const u8,
    params: BytesArray,

    pub fn iterator(self: Plan) Iterator {
        return .{ .actions = self.actions, .params = self.params };
    }

    pub const Iterator = struct {
        actions: []const u8,
        params: BytesArray,
        index: usize = 0,

        pub fn next(self: *Iterator) ?Action {
            if (self.index >= self.actions.len) return null;
            const raw = self.actions[self.index];
            const param = self.params.get(self.index);
            self.index += 1;
            const payload: Action.Payload = switch (raw) {
                actions.swap_exact_in_single => .{ .swap_exact_in_single = parseExactInputSingle(param) orelse unreachable },
                actions.swap_exact_in => .{ .swap_exact_in = parseExactInput(param) orelse unreachable },
                actions.swap_exact_out_single => .{ .swap_exact_out_single = parseExactOutputSingle(param) orelse unreachable },
                actions.swap_exact_out => .{ .swap_exact_out = parseExactOutput(param) orelse unreachable },
                actions.settle => blk: {
                    const f = parseSettle(param) orelse unreachable;
                    break :blk .{ .settle = .{ .currency = f.currency, .amount = f.amount, .payer_is_user = f.payer_is_user } };
                },
                actions.settle_all => .{ .settle_all = parseSettleAll(param) orelse unreachable },
                actions.take => .{ .take = parseTake(param) orelse unreachable },
                actions.take_all => .{ .take_all = parseTakeAll(param) orelse unreachable },
                actions.take_portion => .{ .take_portion = parseTakePortion(param) orelse unreachable },
                else => .{ .other = .{ .action = raw, .params = param } },
            };
            return .{ .raw = raw, .payload = payload };
        }
    };
};

/// Parse and fully validate a `V4_SWAP` command input. Null for anything
/// malformed; never panics.
pub fn parsePlan(input: []const u8) ?Plan {
    const acts = bytesAt(input, 0, 0) orelse return null;
    const params = bytesArrayAt(input, 0, 32) orelse return null;
    if (acts.len != params.count) return null;

    var i: usize = 0;
    while (i < acts.len) : (i += 1) {
        const param = params.get(i);
        const ok = switch (acts[i]) {
            actions.swap_exact_in_single => parseExactInputSingle(param) != null,
            actions.swap_exact_in => parseExactInput(param) != null,
            actions.swap_exact_out_single => parseExactOutputSingle(param) != null,
            actions.swap_exact_out => parseExactOutput(param) != null,
            actions.settle => parseSettle(param) != null,
            actions.settle_all => parseSettleAll(param) != null,
            actions.take => parseTake(param) != null,
            actions.take_all => parseTakeAll(param) != null,
            actions.take_portion => parseTakePortion(param) != null,
            else => true,
        };
        if (!ok) return null;
    }
    return .{ .actions = acts, .params = params };
}

// ============================================================================
// Decoding: PoolKey / PathKey field readers
// ============================================================================

/// `PoolKey` is a static 5-word tuple, inlined wherever it appears.
fn readPoolKey(data: []const u8, base: usize) ?PoolKey {
    const p_currency1 = addChecked(base, 0x20) orelse return null;
    const p_fee = addChecked(base, 0x40) orelse return null;
    const p_tick = addChecked(base, 0x60) orelse return null;
    const p_hooks = addChecked(base, 0x80) orelse return null;
    const currency0 = readAddressAt(data, base) orelse return null;
    const currency1 = readAddressAt(data, p_currency1) orelse return null;
    const fee = readFeeAt(data, p_fee) orelse return null;
    const tick_spacing = readIntAt(i24, data, p_tick) orelse return null;
    const hooks = readAddressAt(data, p_hooks) orelse return null;
    return .{ .currency0 = currency0, .currency1 = currency1, .fee = fee, .tick_spacing = tick_spacing, .hooks = hooks };
}

/// `PathKey` is a dynamic tuple (4 static words + a trailing `bytes
/// hookData`): `off` is the tuple's start, relative to `data`.
fn readPathKeyAt(data: []const u8, off: usize) ?PathKey {
    const p_fee = addChecked(off, 0x20) orelse return null;
    const p_tick = addChecked(off, 0x40) orelse return null;
    const p_hooks = addChecked(off, 0x60) orelse return null;
    const p_hook_data_off = addChecked(off, 0x80) orelse return null;
    const intermediate_currency = readAddressAt(data, off) orelse return null;
    const fee = readFeeAt(data, p_fee) orelse return null;
    const tick_spacing = readIntAt(i24, data, p_tick) orelse return null;
    const hooks = readAddressAt(data, p_hooks) orelse return null;
    const hook_data = bytesAt(data, off, p_hook_data_off) orelse return null;
    return .{
        .intermediate_currency = intermediate_currency,
        .fee = fee,
        .tick_spacing = tick_spacing,
        .hooks = hooks,
        .hook_data = hook_data,
    };
}

/// A `PathKey[]`, validated the way `bytesArrayAt` validates `bytes[]`:
/// canonical, non-overlapping element order, checked linear in `data.len`.
/// Each element is a dynamic tuple (4 static words, then `bytes hookData`),
/// so an element's data end is the later of its fixed 0xA0-byte head and its
/// `hookData` content end.
fn pathKeysAt(data: []const u8, base: usize, offset_word_pos: usize) ?PathKeys {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    const head = data[h.start..];
    var prev_end: usize = 0;
    var i: usize = 0;
    while (i < h.count) : (i += 1) {
        const off = readOffset(head, i * 32) orelse return null;
        if (i > 0 and off < prev_end) return null;
        if (readPathKeyAt(head, off) == null) return null;

        const p_hook_data_off = addChecked(off, 0x80) orelse return null;
        const hd_off = readOffset(head, p_hook_data_off) orelse return null;
        const hd_start = addChecked(off, hd_off) orelse return null;
        const hd_len = wordToUsize(readU256At(head, hd_start) orelse return null) orelse return null;
        const hd_content_start = addChecked(hd_start, 32) orelse return null;
        const hd_content_end = addChecked(hd_content_start, hd_len) orelse return null;
        if (hd_content_end > head.len) return null;

        const tuple_end = addChecked(off, 0xA0) orelse return null;
        const elem_end = @max(tuple_end, hd_content_end);
        prev_end = roundUpWord(elem_end) orelse return null;
    }
    return .{ .head = head, .count = h.count };
}

// ============================================================================
// Decoding: single-hop / multi-hop struct layout detection
//
// "struct = params + word0" (CalldataDecoder.sol): every swap action's
// params is `abi.encode(StructType)`, a lone dynamic tuple, so word0 of
// params is the struct's own offset (usually 0x20; 0 for the degenerate
// native-ETH case where the struct's first field is itself zero).
// ============================================================================

/// The `hookData` offset word position, right after the two `uint128`
/// amounts. The deployed router puts `hookData`'s offset there, always
/// `0x120`; anything else (including the main-branch layout, which inserts
/// a `minHopPriceX36` word there instead) is rejected.
fn singleHopHookDataOffsetPos(data: []const u8, struct_base: usize) ?usize {
    const pos = addChecked(struct_base, 0x100) orelse return null;
    const word = readU256At(data, pos) orelse return null;
    if (word != 0x120) return null;
    return pos;
}

const MultiHopLayout = struct {
    path_offset_pos: usize,
    amount_a_pos: usize,
    amount_b_pos: usize,
};

/// The `path` offset must be `0x80` (4-word head: currency, path, amountA,
/// amountB), the value the deployed router reads. `0xa0` (5-word head, with
/// a `minHopPriceX36[]` offset inserted after `path`) is the main-branch
/// layout and is rejected, like anything else.
fn multiHopLayout(data: []const u8, struct_base: usize) ?MultiHopLayout {
    const path_offset_pos = addChecked(struct_base, 0x20) orelse return null;
    const path_off = readU256At(data, path_offset_pos) orelse return null;
    if (path_off != 0x80) return null;
    const amount_a_pos = addChecked(struct_base, 0x40) orelse return null;
    const amount_b_pos = addChecked(struct_base, 0x60) orelse return null;
    return .{ .path_offset_pos = path_offset_pos, .amount_a_pos = amount_a_pos, .amount_b_pos = amount_b_pos };
}

// ============================================================================
// Decoding: swap actions
// ============================================================================

fn parseExactInputSingle(param: []const u8) ?ExactInputSingle {
    const struct_base = readOffset(param, 0) orelse return null;
    const pool_key = readPoolKey(param, struct_base) orelse return null;
    const p_zero_for_one = addChecked(struct_base, 0xA0) orelse return null;
    const zero_for_one = readBoolAt(param, p_zero_for_one) orelse return null;
    const p_amount_in = addChecked(struct_base, 0xC0) orelse return null;
    const amount_in = readUintAt(u128, param, p_amount_in) orelse return null;
    const p_amount_out_min = addChecked(struct_base, 0xE0) orelse return null;
    const amount_out_minimum = readUintAt(u128, param, p_amount_out_min) orelse return null;
    const hook_data_offset_pos = singleHopHookDataOffsetPos(param, struct_base) orelse return null;
    const hook_data = bytesAt(param, struct_base, hook_data_offset_pos) orelse return null;
    return .{
        .pool_key = pool_key,
        .zero_for_one = zero_for_one,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
        .hook_data = hook_data,
    };
}

fn parseExactOutputSingle(param: []const u8) ?ExactOutputSingle {
    const struct_base = readOffset(param, 0) orelse return null;
    const pool_key = readPoolKey(param, struct_base) orelse return null;
    const p_zero_for_one = addChecked(struct_base, 0xA0) orelse return null;
    const zero_for_one = readBoolAt(param, p_zero_for_one) orelse return null;
    const p_amount_out = addChecked(struct_base, 0xC0) orelse return null;
    const amount_out = readUintAt(u128, param, p_amount_out) orelse return null;
    const p_amount_in_max = addChecked(struct_base, 0xE0) orelse return null;
    const amount_in_maximum = readUintAt(u128, param, p_amount_in_max) orelse return null;
    const hook_data_offset_pos = singleHopHookDataOffsetPos(param, struct_base) orelse return null;
    const hook_data = bytesAt(param, struct_base, hook_data_offset_pos) orelse return null;
    return .{
        .pool_key = pool_key,
        .zero_for_one = zero_for_one,
        .amount_out = amount_out,
        .amount_in_maximum = amount_in_maximum,
        .hook_data = hook_data,
    };
}

fn parseExactInput(param: []const u8) ?ExactInput {
    const struct_base = readOffset(param, 0) orelse return null;
    const currency_in = readAddressAt(param, struct_base) orelse return null;
    const layout = multiHopLayout(param, struct_base) orelse return null;
    const path = pathKeysAt(param, struct_base, layout.path_offset_pos) orelse return null;
    const amount_in = readUintAt(u128, param, layout.amount_a_pos) orelse return null;
    const amount_out_minimum = readUintAt(u128, param, layout.amount_b_pos) orelse return null;
    return .{
        .currency_in = currency_in,
        .path = path,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
    };
}

fn parseExactOutput(param: []const u8) ?ExactOutput {
    const struct_base = readOffset(param, 0) orelse return null;
    const currency_out = readAddressAt(param, struct_base) orelse return null;
    const layout = multiHopLayout(param, struct_base) orelse return null;
    const path = pathKeysAt(param, struct_base, layout.path_offset_pos) orelse return null;
    const amount_out = readUintAt(u128, param, layout.amount_a_pos) orelse return null;
    const amount_in_maximum = readUintAt(u128, param, layout.amount_b_pos) orelse return null;
    return .{
        .currency_out = currency_out,
        .path = path,
        .amount_out = amount_out,
        .amount_in_maximum = amount_in_maximum,
    };
}

// ============================================================================
// Decoding: settle / take actions
//
// Each params blob is `abi.decode(params, (T1, T2, ...))`: a flat
// concatenation of static fields, with no wrapping struct or leading offset
// word (unlike the swap actions above).
// ============================================================================

const SettleFields = struct {
    currency: [20]u8,
    amount: u256,
    payer_is_user: bool,
};

fn parseSettle(param: []const u8) ?SettleFields {
    const currency = readAddressAt(param, 0) orelse return null;
    const amount = readU256At(param, 0x20) orelse return null;
    const payer_is_user = readBoolAt(param, 0x40) orelse return null;
    return .{ .currency = currency, .amount = amount, .payer_is_user = payer_is_user };
}

fn parseSettleAll(param: []const u8) ?CurrencyAmount {
    const currency = readAddressAt(param, 0) orelse return null;
    const amount = readU256At(param, 0x20) orelse return null;
    return .{ .currency = currency, .amount = amount };
}

fn parseTake(param: []const u8) ?CurrencyRecipientAmount {
    const currency = readAddressAt(param, 0) orelse return null;
    const recipient = readAddressAt(param, 0x20) orelse return null;
    const amount = readU256At(param, 0x40) orelse return null;
    return .{ .currency = currency, .recipient = recipient, .amount = amount };
}

fn parseTakeAll(param: []const u8) ?CurrencyAmount {
    const currency = readAddressAt(param, 0) orelse return null;
    const amount = readU256At(param, 0x20) orelse return null;
    return .{ .currency = currency, .amount = amount };
}

fn parseTakePortion(param: []const u8) ?CurrencyRecipientAmount {
    const currency = readAddressAt(param, 0) orelse return null;
    const recipient = readAddressAt(param, 0x20) orelse return null;
    const amount = readU256At(param, 0x40) orelse return null;
    return .{ .currency = currency, .recipient = recipient, .amount = amount };
}
