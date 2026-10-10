//! Router-aware decoding for issue #15 Phase 2.
//!
//! `decode(data)` assumes today's Uniswap routers. Some routers reuse those
//! selectors with a different meaning, so calldata alone cannot tell them
//! apart:
//! - `exactInput((bytes,address,uint256,uint256,uint256))` (0xc04b8d59) is a
//!   fee path on Uniswap V3, a tick-spacing path on Slipstream, and a
//!   fee-less token path on Camelot V3 (Algebra).
//! - Universal Router command 0x10 is V4_SWAP on Uniswap's current router
//!   and an NFT command on pre-V4 and PancakeSwap routers.
//!
//! `decodeFor(router, data)` reads calldata with the right rules, and
//! `routerAt(chain_id, address)` maps a verified deployment to its `Router`.
//! SushiSwap V2/V3 and PancakeSwap V2/V3 routers share Uniswap's ABIs and map
//! to `.uniswap`, tagged with their `Protocol`.

const std = @import("std");
const reader = @import("abi_reader.zig");
const calldata = @import("calldata.zig");
const hex = @import("../hex.zig");

const AddressPath = reader.AddressPath;
const AlgebraPath = reader.AlgebraPath;
const U256Array = reader.U256Array;
const Decoded = calldata.Decoded;

// ============================================================================
// Selectors
// ============================================================================

const keccak = @import("../keccak.zig");

pub const selectors = struct {
    // Aerodrome (Base) / Velodrome V2 (Optimism) Router, Route = (address from, address to, bool stable, address factory)
    pub const aerodrome_swap_exact_tokens_for_tokens = keccak.selector("swapExactTokensForTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_eth_for_tokens = keccak.selector("swapExactETHForTokens(uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_eth = keccak.selector("swapExactTokensForETH(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_unsafe_swap_exact_tokens_for_tokens = keccak.selector("UNSAFE_swapExactTokensForTokens(uint256[],(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");

    // Slipstream (Aerodrome/Velodrome CL) SwapRouter: int24 tickSpacing instead of uint24 fee
    pub const slipstream_exact_input_single = keccak.selector("exactInputSingle((address,address,int24,address,uint256,uint256,uint256,uint160))");
    pub const slipstream_exact_output_single = keccak.selector("exactOutputSingle((address,address,int24,address,uint256,uint256,uint256,uint160))");
    // exactInput / exactOutput share Uniswap SwapRouter's selectors (0xc04b8d59 / 0xf28c0498).

    // Camelot V2 (Arbitrum): fee-on-transfer only, `referrer` between `to` and `deadline`
    pub const camelot_v2_swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,address,uint256)");
    pub const camelot_v2_swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,address,uint256)");
    pub const camelot_v2_swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,address,uint256)");

    // Camelot V3 (Algebra): no fee field, limitSqrtPrice
    pub const camelot_v3_exact_input_single = keccak.selector("exactInputSingle((address,address,address,uint256,uint256,uint256,uint160))");
    pub const camelot_v3_exact_input_single_fot = keccak.selector("exactInputSingleSupportingFeeOnTransferTokens((address,address,address,uint256,uint256,uint256,uint160))");
    // exactInput / exactOutput share Uniswap SwapRouter's selectors, with a fee-less path.

    // PancakeSwap SmartRouter StableSwapRouter
    pub const pancake_exact_input_stable_swap = keccak.selector("exactInputStableSwap(address[],uint256[],uint256,uint256,address)");
    pub const pancake_exact_output_stable_swap = keccak.selector("exactOutputStableSwap(address[],uint256[],uint256,uint256,address)");
};

// ============================================================================
// Routers and deployments
// ============================================================================

/// Decoding rules. Several protocols share one rule set.
pub const Router = enum {
    /// Uniswap V2Router02 / SwapRouter / SwapRouter02 / Universal Router with
    /// V4, and ABI-identical forks. Same as `decode`.
    uniswap,
    /// Pre-V4 Uniswap Universal Router: like `.uniswap`, but UR commands use
    /// `UrDialect.uniswap_v1`.
    uniswap_ur_v1,
    /// PancakeSwap SmartRouter: SwapRouter02 ABI plus stable swaps.
    pancake_smart_router,
    /// PancakeSwap Universal Router: `UrDialect.pancake`.
    pancake_ur,
    /// Aerodrome Router (Base) and Velodrome V2 Router (Optimism).
    aerodrome,
    /// Aerodrome/Velodrome Slipstream (CL) SwapRouter.
    slipstream,
    /// Camelot V2 Router (Arbitrum).
    camelot_v2,
    /// Camelot V3 (Algebra) SwapRouter (Arbitrum).
    camelot_v3,
};

pub const Protocol = enum { uniswap, sushiswap, pancakeswap, aerodrome, velodrome, camelot };

/// A verified router deployment.
pub const Deployment = struct {
    chain_id: u64,
    address: [20]u8,
    protocol: Protocol,
    router: Router,
};

/// Comptime hex-literal -> address parser for the deployment table below.
fn addr(comptime hex_str: []const u8) [20]u8 {
    @setEvalBranchQuota(10_000);
    return hex.hexToBytesFixed(20, hex_str) catch unreachable;
}

/// Verified deployments (every address checked with `cast code` against the
/// chain's RPC, research/deployments_verified.md). Unknown addresses are not
/// guessed.
pub const deployments = [_]Deployment{
    .{ .chain_id = 1, .address = addr("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"), .protocol = .uniswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("E592427A0AEce92De3Edee1F18E0157C05861564"), .protocol = .uniswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"), .protocol = .uniswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"), .protocol = .uniswap, .router = .uniswap_ur_v1 },
    .{ .chain_id = 1, .address = addr("66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"), .protocol = .uniswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("d9e1cE17f2641f24aE83637ab66a2cca9C378B9F"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 8453, .address = addr("6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 10, .address = addr("2ABf469074dc0b54d793850807E6eb5Faf2625b1"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 42161, .address = addr("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 56, .address = addr("1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("2E6cd2d30aa43f40aa81619ff4b6E0a41479B13F"), .protocol = .sushiswap, .router = .uniswap },
    .{ .chain_id = 56, .address = addr("10ED43C718714eb63d5aA57B78B54704E256024E"), .protocol = .pancakeswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("13f4EA83D0bd40E75C8222255bc855a974568Dd4"), .protocol = .pancakeswap, .router = .pancake_smart_router },
    .{ .chain_id = 56, .address = addr("13f4EA83D0bd40E75C8222255bc855a974568Dd4"), .protocol = .pancakeswap, .router = .pancake_smart_router },
    .{ .chain_id = 1, .address = addr("1b81D678ffb9C0263b24A97847620C99d213eB14"), .protocol = .pancakeswap, .router = .uniswap },
    .{ .chain_id = 56, .address = addr("1b81D678ffb9C0263b24A97847620C99d213eB14"), .protocol = .pancakeswap, .router = .uniswap },
    .{ .chain_id = 1, .address = addr("65b382653f7C31bC0Af67f188122035461ec9C76"), .protocol = .pancakeswap, .router = .pancake_ur },
    .{ .chain_id = 56, .address = addr("d9C500DfF816a1Da21A48A732d3498Bf09dc9AEB"), .protocol = .pancakeswap, .router = .pancake_ur },
    .{ .chain_id = 8453, .address = addr("cF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43"), .protocol = .aerodrome, .router = .aerodrome },
    .{ .chain_id = 8453, .address = addr("BE6D8f0d05cC4be24d5167a3ef062215bE6D18a5"), .protocol = .aerodrome, .router = .slipstream },
    .{ .chain_id = 10, .address = addr("a062aE8A9c5e11aaA026fc2670B0D65cCc8B2858"), .protocol = .velodrome, .router = .aerodrome },
    .{ .chain_id = 10, .address = addr("bA3aEe516399388C779463183d00bB579f5041Ca"), .protocol = .velodrome, .router = .slipstream },
    .{ .chain_id = 42161, .address = addr("c873fEcbd354f5A56E00E710B90EF4201db2448d"), .protocol = .camelot, .router = .camelot_v2 },
    .{ .chain_id = 42161, .address = addr("1F721E2E82F6676FCE4eA07A5958cF098D339e18"), .protocol = .camelot, .router = .camelot_v3 },
};

/// The deployment at `address` on `chain_id`, or null if it is not a known
/// router. Linear scan; the table is small (24 entries).
pub fn routerAt(chain_id: u64, address: [20]u8) ?Deployment {
    for (deployments) |d| {
        if (d.chain_id == chain_id and std.mem.eql(u8, &d.address, &address)) return d;
    }
    return null;
}

// ============================================================================
// Phase 2 decoded calls
// ============================================================================

/// Aerodrome/Velodrome `Route`.
pub const Route = struct {
    from: [20]u8,
    to: [20]u8,
    stable: bool,
    factory: [20]u8,
};

/// An ABI `Route[]` (static tuples, 4 words each), borrowed from calldata.
/// `decodeFor` checked every element and that `len() >= 1`.
pub const RouteArray = struct {
    words: []const u8,

    pub fn len(self: RouteArray) usize {
        return self.words.len / 128;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: RouteArray, i: usize) Route {
        std.debug.assert(i < self.len());
        const w = self.words[i * 128 ..][0..128];
        return .{
            .from = w[12..32].*,
            .to = w[44..64].*,
            .stable = w[95] != 0,
            .factory = w[108..128].*,
        };
    }
};

pub const AerodromeExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

/// The input amount is the tx `value`.
pub const AerodromeEthExactIn = struct {
    amount_out_min: u256,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

/// `UNSAFE_swapExactTokensForTokens`: the caller supplies every hop amount.
pub const AerodromeUnsafe = struct {
    amounts: U256Array,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

pub const SlipstreamExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    tick_spacing: i24,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
    sqrt_price_limit_x96: u160,
};

pub const SlipstreamExactOutputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    tick_spacing: i24,
    recipient: [20]u8,
    deadline: u256,
    amount_out: u256,
    amount_in_maximum: u256,
    sqrt_price_limit_x96: u160,
};

pub const CamelotV2ExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    referrer: [20]u8,
    deadline: u256,
};

/// The input amount is the tx `value`.
pub const CamelotV2EthExactIn = struct {
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    referrer: [20]u8,
    deadline: u256,
};

pub const AlgebraExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
    limit_sqrt_price: u160,
};

pub const AlgebraExactInput = struct {
    path: AlgebraPath,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
};

/// `path` is reversed (token out first).
pub const AlgebraExactOutput = struct {
    path: AlgebraPath,
    recipient: [20]u8,
    deadline: u256,
    amount_out: u256,
    amount_in_maximum: u256,
};

pub const PancakeStableExactIn = struct {
    path: AddressPath,
    /// `flags[i]` selects the stable pool for hop i.
    flags: U256Array,
    amount_in: u256,
    amount_out_min: u256,
    to: [20]u8,
};

pub const PancakeStableExactOut = struct {
    path: AddressPath,
    flags: U256Array,
    amount_out: u256,
    amount_in_max: u256,
    to: [20]u8,
};

// ============================================================================
// Decoding: shared locators
// ============================================================================

/// A `Route[]` array: static 4-word tuples packed right after the length
/// word (no per-element offsets, unlike `bytes[]`). Requires `count >= 1`
/// (a swap always has at least one hop) and validates every element's
/// padding eagerly, same as `abi_reader.addressArrayAt`.
fn routeArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?RouteArray {
    const off = reader.readOffset(data, offset_word_pos) orelse return null;
    const arr_start = reader.addChecked(base, off) orelse return null;
    const count = reader.wordToUsize(reader.readU256At(data, arr_start) orelse return null) orelse return null;
    if (count < 1) return null;
    const head_start = reader.addChecked(arr_start, 32) orelse return null;
    const elem_bytes = reader.mulChecked(count, 128) orelse return null;
    const head_end = reader.addChecked(head_start, elem_bytes) orelse return null;
    if (head_end > data.len) return null;
    const words = data[head_start..head_end];
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const e = i * 128;
        _ = reader.readAddressAt(words, e) orelse return null;
        _ = reader.readAddressAt(words, e + 32) orelse return null;
        _ = reader.readBoolAt(words, e + 64) orelse return null;
        _ = reader.readAddressAt(words, e + 96) orelse return null;
    }
    return .{ .words = words };
}

/// `n` for an Algebra (Camelot V3) packed path of this byte length, or null
/// unless it is `20 * n` with `n >= 2`.
fn algebraPathHops(len: usize) ?usize {
    if (len == 0 or len % 20 != 0) return null;
    const n = len / 20;
    if (n < 2) return null;
    return n;
}

// ============================================================================
// Decoding: Aerodrome / Velodrome Router
// ============================================================================
//
// `swapExactTokensForTokens`/`swapExactTokensForETH`/both FoT-tokens variants
// share one static head: amountIn, amountOutMin, routes offset, to, deadline.
// `swapExactETHForTokens`/its FoT variant drop `amountIn` (the tx `value` is
// the input).

fn parseAerodromeExactIn(data: []const u8, args_base: usize) ?AerodromeExactIn {
    const amount_in = reader.readU256At(data, args_base) orelse return null;
    const amount_out_min = reader.readU256At(data, args_base + 32) orelse return null;
    const routes = routeArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = reader.readAddressAt(data, args_base + 96) orelse return null;
    const deadline = reader.readU256At(data, args_base + 128) orelse return null;
    return .{ .amount_in = amount_in, .amount_out_min = amount_out_min, .routes = routes, .to = to, .deadline = deadline };
}

fn parseAerodromeEthExactIn(data: []const u8, args_base: usize) ?AerodromeEthExactIn {
    const amount_out_min = reader.readU256At(data, args_base) orelse return null;
    const routes = routeArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = reader.readAddressAt(data, args_base + 64) orelse return null;
    const deadline = reader.readU256At(data, args_base + 96) orelse return null;
    return .{ .amount_out_min = amount_out_min, .routes = routes, .to = to, .deadline = deadline };
}

fn parseAerodromeUnsafe(data: []const u8, args_base: usize) ?AerodromeUnsafe {
    const amounts = reader.u256ArrayAt(data, args_base, args_base) orelse return null;
    const routes = routeArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = reader.readAddressAt(data, args_base + 64) orelse return null;
    const deadline = reader.readU256At(data, args_base + 96) orelse return null;
    return .{ .amounts = amounts, .routes = routes, .to = to, .deadline = deadline };
}

// ============================================================================
// Decoding: Slipstream (Aerodrome/Velodrome CL) SwapRouter
// ============================================================================
//
// `exactInputSingle`/`exactOutputSingle` are a static tuple with an `int24
// tickSpacing` where Uniswap V3 has `uint24 fee`, inlined right after the
// selector (same shape as calldata.zig's `parseV3ExactInputSingle`).
// `exactInput`/`exactOutput` share Uniswap's selectors; the tick spacing
// lives inside the packed path, read by `V3Path.Hop.tickSpacing()`.

fn parseSlipstreamExactInputSingle(data: []const u8) ?SlipstreamExactInputSingle {
    const t: usize = 4;
    const token_in = reader.readAddressAt(data, t) orelse return null;
    const token_out = reader.readAddressAt(data, t + 32) orelse return null;
    const tick_spacing = reader.readIntAt(i24, data, t + 64) orelse return null;
    const recipient = reader.readAddressAt(data, t + 96) orelse return null;
    const deadline = reader.readU256At(data, t + 128) orelse return null;
    const amount_in = reader.readU256At(data, t + 160) orelse return null;
    const amount_out_minimum = reader.readU256At(data, t + 192) orelse return null;
    const sqrt_price_limit_x96 = reader.readU160At(data, t + 224) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .tick_spacing = tick_spacing,
        .recipient = recipient,
        .deadline = deadline,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

fn parseSlipstreamExactOutputSingle(data: []const u8) ?SlipstreamExactOutputSingle {
    const t: usize = 4;
    const token_in = reader.readAddressAt(data, t) orelse return null;
    const token_out = reader.readAddressAt(data, t + 32) orelse return null;
    const tick_spacing = reader.readIntAt(i24, data, t + 64) orelse return null;
    const recipient = reader.readAddressAt(data, t + 96) orelse return null;
    const deadline = reader.readU256At(data, t + 128) orelse return null;
    const amount_out = reader.readU256At(data, t + 160) orelse return null;
    const amount_in_maximum = reader.readU256At(data, t + 192) orelse return null;
    const sqrt_price_limit_x96 = reader.readU160At(data, t + 224) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .tick_spacing = tick_spacing,
        .recipient = recipient,
        .deadline = deadline,
        .amount_out = amount_out,
        .amount_in_maximum = amount_in_maximum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

// ============================================================================
// Decoding: Camelot V2 Router
// ============================================================================
//
// Fee-on-transfer-only; `referrer` sits between `to` and `deadline`.

fn parseCamelotV2ExactIn(data: []const u8, args_base: usize) ?CamelotV2ExactIn {
    const amount_in = reader.readU256At(data, args_base) orelse return null;
    const amount_out_min = reader.readU256At(data, args_base + 32) orelse return null;
    const path = reader.addressArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = reader.readAddressAt(data, args_base + 96) orelse return null;
    const referrer = reader.readAddressAt(data, args_base + 128) orelse return null;
    const deadline = reader.readU256At(data, args_base + 160) orelse return null;
    return .{ .amount_in = amount_in, .amount_out_min = amount_out_min, .path = path, .to = to, .referrer = referrer, .deadline = deadline };
}

fn parseCamelotV2EthExactIn(data: []const u8, args_base: usize) ?CamelotV2EthExactIn {
    const amount_out_min = reader.readU256At(data, args_base) orelse return null;
    const path = reader.addressArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = reader.readAddressAt(data, args_base + 64) orelse return null;
    const referrer = reader.readAddressAt(data, args_base + 96) orelse return null;
    const deadline = reader.readU256At(data, args_base + 128) orelse return null;
    return .{ .amount_out_min = amount_out_min, .path = path, .to = to, .referrer = referrer, .deadline = deadline };
}

// ============================================================================
// Decoding: Camelot V3 (Algebra) SwapRouter
// ============================================================================
//
// No fee field (single pool per pair); `limitSqrtPrice` instead of
// `sqrtPriceLimitX96`. Path is `token(20) token(20) ...`, no fee bytes.

fn parseAlgebraExactInputSingle(data: []const u8) ?AlgebraExactInputSingle {
    const t: usize = 4;
    const token_in = reader.readAddressAt(data, t) orelse return null;
    const token_out = reader.readAddressAt(data, t + 32) orelse return null;
    const recipient = reader.readAddressAt(data, t + 64) orelse return null;
    const deadline = reader.readU256At(data, t + 96) orelse return null;
    const amount_in = reader.readU256At(data, t + 128) orelse return null;
    const amount_out_minimum = reader.readU256At(data, t + 160) orelse return null;
    const limit_sqrt_price = reader.readU160At(data, t + 192) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .recipient = recipient,
        .deadline = deadline,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
        .limit_sqrt_price = limit_sqrt_price,
    };
}

fn parseAlgebraExactInput(data: []const u8) ?AlgebraExactInput {
    const args_base: usize = 4;
    const off = reader.readOffset(data, args_base) orelse return null;
    const t = reader.addChecked(args_base, off) orelse return null;
    const path_bytes = reader.bytesAt(data, t, t) orelse return null;
    if (algebraPathHops(path_bytes.len) == null) return null;
    const recipient = reader.readAddressAt(data, t + 32) orelse return null;
    const deadline = reader.readU256At(data, t + 64) orelse return null;
    const amount_in = reader.readU256At(data, t + 96) orelse return null;
    const amount_out_minimum = reader.readU256At(data, t + 128) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_in = amount_in, .amount_out_minimum = amount_out_minimum };
}

fn parseAlgebraExactOutput(data: []const u8) ?AlgebraExactOutput {
    const args_base: usize = 4;
    const off = reader.readOffset(data, args_base) orelse return null;
    const t = reader.addChecked(args_base, off) orelse return null;
    const path_bytes = reader.bytesAt(data, t, t) orelse return null;
    if (algebraPathHops(path_bytes.len) == null) return null;
    const recipient = reader.readAddressAt(data, t + 32) orelse return null;
    const deadline = reader.readU256At(data, t + 64) orelse return null;
    const amount_out = reader.readU256At(data, t + 96) orelse return null;
    const amount_in_maximum = reader.readU256At(data, t + 128) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_out = amount_out, .amount_in_maximum = amount_in_maximum };
}

// ============================================================================
// Decoding: PancakeSwap SmartRouter StableSwapRouter
// ============================================================================

fn parsePancakeStableExactIn(data: []const u8, args_base: usize) ?PancakeStableExactIn {
    const path = reader.addressArrayAt(data, args_base, args_base) orelse return null;
    const flags = reader.u256ArrayAt(data, args_base, args_base + 32) orelse return null;
    const amount_in = reader.readU256At(data, args_base + 64) orelse return null;
    const amount_out_min = reader.readU256At(data, args_base + 96) orelse return null;
    const to = reader.readAddressAt(data, args_base + 128) orelse return null;
    return .{ .path = path, .flags = flags, .amount_in = amount_in, .amount_out_min = amount_out_min, .to = to };
}

fn parsePancakeStableExactOut(data: []const u8, args_base: usize) ?PancakeStableExactOut {
    const path = reader.addressArrayAt(data, args_base, args_base) orelse return null;
    const flags = reader.u256ArrayAt(data, args_base, args_base + 32) orelse return null;
    const amount_out = reader.readU256At(data, args_base + 64) orelse return null;
    const amount_in_max = reader.readU256At(data, args_base + 96) orelse return null;
    const to = reader.readAddressAt(data, args_base + 128) orelse return null;
    return .{ .path = path, .flags = flags, .amount_out = amount_out, .amount_in_max = amount_in_max, .to = to };
}

// ============================================================================
// Decoding: dispatch
// ============================================================================

/// The selector set `calldata.decode` turns into a swap `Decoded` (every
/// case in `decodeDispatch` except the two batch dispatchers). `.uniswap`,
/// `.uniswap_ur_v1` and `.pancake_ur` all decode non-batch calls this way.
fn isUniswapSwapSelector(sel: u32) bool {
    return sel == reader.selU32(calldata.selectors.swap_exact_tokens_for_tokens) or
        sel == reader.selU32(calldata.selectors.swap_tokens_for_exact_tokens) or
        sel == reader.selU32(calldata.selectors.swap_exact_eth_for_tokens) or
        sel == reader.selU32(calldata.selectors.swap_tokens_for_exact_eth) or
        sel == reader.selU32(calldata.selectors.swap_exact_tokens_for_eth) or
        sel == reader.selU32(calldata.selectors.swap_eth_for_exact_tokens) or
        sel == reader.selU32(calldata.selectors.swap_exact_tokens_for_tokens_fot) or
        sel == reader.selU32(calldata.selectors.swap_exact_eth_for_tokens_fot) or
        sel == reader.selU32(calldata.selectors.swap_exact_tokens_for_eth_fot) or
        sel == reader.selU32(calldata.selectors.exact_input_single) or
        sel == reader.selU32(calldata.selectors.exact_input) or
        sel == reader.selU32(calldata.selectors.exact_output_single) or
        sel == reader.selU32(calldata.selectors.exact_output) or
        sel == reader.selU32(calldata.selectors.exact_input_single_02) or
        sel == reader.selU32(calldata.selectors.exact_input_02) or
        sel == reader.selU32(calldata.selectors.exact_output_single_02) or
        sel == reader.selU32(calldata.selectors.exact_output_02) or
        sel == reader.selU32(calldata.selectors.swap_exact_tokens_for_tokens_02) or
        sel == reader.selU32(calldata.selectors.swap_tokens_for_exact_tokens_02);
}

/// True if `selector` is a swap under `router`'s rules, i.e. an inner
/// multicall call that must decode fully (or the whole multicall is null).
pub fn isInnerSwapSelector(router: Router, selector: [4]u8) bool {
    const sel = reader.selU32(selector);
    return switch (router) {
        .uniswap, .uniswap_ur_v1, .pancake_ur => isUniswapSwapSelector(sel),
        .pancake_smart_router => isUniswapSwapSelector(sel) or
            sel == reader.selU32(selectors.pancake_exact_input_stable_swap) or
            sel == reader.selU32(selectors.pancake_exact_output_stable_swap),
        .slipstream => sel == reader.selU32(selectors.slipstream_exact_input_single) or
            sel == reader.selU32(selectors.slipstream_exact_output_single) or
            sel == reader.selU32(calldata.selectors.exact_input) or
            sel == reader.selU32(calldata.selectors.exact_output),
        .camelot_v3 => sel == reader.selU32(selectors.camelot_v3_exact_input_single) or
            sel == reader.selU32(selectors.camelot_v3_exact_input_single_fot) or
            sel == reader.selU32(calldata.selectors.exact_input) or
            sel == reader.selU32(calldata.selectors.exact_output),
        .aerodrome => sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_tokens) or
            sel == reader.selU32(selectors.aerodrome_swap_exact_eth_for_tokens) or
            sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_eth) or
            sel == reader.selU32(selectors.aerodrome_unsafe_swap_exact_tokens_for_tokens) or
            sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_tokens_fot) or
            sel == reader.selU32(selectors.aerodrome_swap_exact_eth_for_tokens_fot) or
            sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_eth_fot),
        .camelot_v2 => sel == reader.selU32(selectors.camelot_v2_swap_exact_tokens_for_tokens_fot) or
            sel == reader.selU32(selectors.camelot_v2_swap_exact_eth_for_tokens_fot) or
            sel == reader.selU32(selectors.camelot_v2_swap_exact_tokens_for_eth_fot),
    };
}

fn decodePancakeSmartInner(data: []const u8, sel: u32) ?Decoded {
    if (sel == reader.selU32(selectors.pancake_exact_input_stable_swap)) {
        return Decoded{ .pancake_exact_input_stable_swap = parsePancakeStableExactIn(data, 4) orelse return null };
    }
    if (sel == reader.selU32(selectors.pancake_exact_output_stable_swap)) {
        return Decoded{ .pancake_exact_output_stable_swap = parsePancakeStableExactOut(data, 4) orelse return null };
    }
    return calldata.decode(data);
}

fn decodeSlipstreamInner(data: []const u8, sel: u32) ?Decoded {
    if (sel == reader.selU32(selectors.slipstream_exact_input_single)) {
        return Decoded{ .slipstream_exact_input_single = parseSlipstreamExactInputSingle(data) orelse return null };
    }
    if (sel == reader.selU32(selectors.slipstream_exact_output_single)) {
        return Decoded{ .slipstream_exact_output_single = parseSlipstreamExactOutputSingle(data) orelse return null };
    }
    if (sel == reader.selU32(calldata.selectors.exact_input)) {
        return Decoded{ .slipstream_exact_input = calldata.parseV3ExactInput(data, true) orelse return null };
    }
    if (sel == reader.selU32(calldata.selectors.exact_output)) {
        return Decoded{ .slipstream_exact_output = calldata.parseV3ExactOutput(data, true) orelse return null };
    }
    return null;
}

fn decodeCamelotV3Inner(data: []const u8, sel: u32) ?Decoded {
    if (sel == reader.selU32(selectors.camelot_v3_exact_input_single)) {
        return Decoded{ .camelot_v3_exact_input_single = parseAlgebraExactInputSingle(data) orelse return null };
    }
    if (sel == reader.selU32(selectors.camelot_v3_exact_input_single_fot)) {
        return Decoded{ .camelot_v3_exact_input_single_fot = parseAlgebraExactInputSingle(data) orelse return null };
    }
    if (sel == reader.selU32(calldata.selectors.exact_input)) {
        return Decoded{ .camelot_v3_exact_input = parseAlgebraExactInput(data) orelse return null };
    }
    if (sel == reader.selU32(calldata.selectors.exact_output)) {
        return Decoded{ .camelot_v3_exact_output = parseAlgebraExactOutput(data) orelse return null };
    }
    return null;
}

fn decodeAerodromeInner(data: []const u8, sel: u32) ?Decoded {
    const args_base: usize = 4;
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_tokens)) {
        return Decoded{ .aerodrome_swap_exact_tokens_for_tokens = parseAerodromeExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_eth_for_tokens)) {
        return Decoded{ .aerodrome_swap_exact_eth_for_tokens = parseAerodromeEthExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_eth)) {
        return Decoded{ .aerodrome_swap_exact_tokens_for_eth = parseAerodromeExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_unsafe_swap_exact_tokens_for_tokens)) {
        return Decoded{ .aerodrome_unsafe_swap_exact_tokens_for_tokens = parseAerodromeUnsafe(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_tokens_fot)) {
        return Decoded{ .aerodrome_swap_exact_tokens_for_tokens_fot = parseAerodromeExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_eth_for_tokens_fot)) {
        return Decoded{ .aerodrome_swap_exact_eth_for_tokens_fot = parseAerodromeEthExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.aerodrome_swap_exact_tokens_for_eth_fot)) {
        return Decoded{ .aerodrome_swap_exact_tokens_for_eth_fot = parseAerodromeExactIn(data, args_base) orelse return null };
    }
    return null;
}

fn decodeCamelotV2Inner(data: []const u8, sel: u32) ?Decoded {
    const args_base: usize = 4;
    if (sel == reader.selU32(selectors.camelot_v2_swap_exact_tokens_for_tokens_fot)) {
        return Decoded{ .camelot_v2_swap_exact_tokens_for_tokens_fot = parseCamelotV2ExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.camelot_v2_swap_exact_eth_for_tokens_fot)) {
        return Decoded{ .camelot_v2_swap_exact_eth_for_tokens_fot = parseCamelotV2EthExactIn(data, args_base) orelse return null };
    }
    if (sel == reader.selU32(selectors.camelot_v2_swap_exact_tokens_for_eth_fot)) {
        return Decoded{ .camelot_v2_swap_exact_tokens_for_eth_fot = parseCamelotV2ExactIn(data, args_base) orelse return null };
    }
    return null;
}

/// Decode one inner multicall call under `router`'s rules. Never decodes a
/// batch (multicall or execute): those return null, so nesting stays one
/// level deep. Never panics: `data.len < 4` and any malformed input just
/// return null.
pub fn decodeInnerCall(router: Router, data: []const u8) ?Decoded {
    const sel = reader.readSelectorU32(data) orelse return null;
    if (calldata.isBatchSelector(sel)) return null;
    return switch (router) {
        .uniswap, .uniswap_ur_v1, .pancake_ur => calldata.decode(data),
        .pancake_smart_router => decodePancakeSmartInner(data, sel),
        .slipstream => decodeSlipstreamInner(data, sel),
        .camelot_v3 => decodeCamelotV3Inner(data, sel),
        .aerodrome => decodeAerodromeInner(data, sel),
        .camelot_v2 => decodeCamelotV2Inner(data, sel),
    };
}

/// Decode calldata sent to a `router`. Null for unknown selectors and any
/// malformed input; never panics and never allocates. For `.uniswap` this is
/// always equal to `calldata.decode(data)`.
pub fn decodeFor(router: Router, data: []const u8) ?Decoded {
    const sel = reader.readSelectorU32(data) orelse return null;
    if (calldata.isBatchSelector(sel)) return calldata.decodeBatchFor(router, data);
    return decodeInnerCall(router, data);
}
