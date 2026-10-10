//! Uniswap router calldata decoding (#15).
//!
//! `decode(tx.data)` recognizes swap calls to UniswapV2Router02, the V3
//! SwapRouter, SwapRouter02 and the Universal Router, and returns a typed view
//! over the calldata, or `null` for anything else.
//!
//! ```zig
//! const eth = @import("eth");
//!
//! const decoded = eth.dex.decode(tx.data) orelse continue;
//! switch (decoded) {
//!     .v2_swap_exact_tokens_for_tokens => |swap| {
//!         // swap.amount_in, swap.amount_out_min, swap.path, swap.to, swap.deadline
//!     },
//!     .v3_exact_input_single => |swap| {
//!         // swap.token_in, swap.token_out, swap.fee, swap.amount_in, ...
//!     },
//!     .universal_router_execute => |ur| {
//!         var it = ur.iterator();
//!         while (it.next()) |cmd| { ... }
//!     },
//!     else => {},
//! }
//! ```
//!
//! ## Guarantees
//! - No allocation. Paths, byte arrays and command inputs are views that
//!   borrow `data`, so they are valid only while `data` is.
//! - No panics on any input. Hostile mempool bytes return `null`.
//! - All validation happens in `decode`. A non-null result means every
//!   accessor and iterator below is infallible.
//! - Selectors are comptime keccak constants; dispatch is a `switch` on the
//!   first four bytes.
//! - Decoding is linear in `data.len`; non-canonical, aliased `bytes[]`
//!   encodings (multicall calls, UR inputs) are rejected.
//!
//! ## Scope
//! `decode` looks at calldata only; checking `tx.to` against a router address
//! is the caller's job. Forks that reuse these ABIs (SushiSwap and PancakeSwap
//! V2 routers) decode the same way.
//!
//! ## Known limits
//! Validation is strict ABI (abicoder v2), so a few inputs that the
//! Universal Router or V2Router02 execute are rejected: dirty address or
//! bool padding bits, V3 paths with trailing bytes, and short static command
//! inputs. One rejected command makes the whole `execute` or `multicall`
//! null. `V4_SWAP` (`0x10`) and the Permit2 commands are typed.
//! `PAY_PORTION_FULL_PRECISION` (`0x07`) is `.other`: the deployed router
//! reverts `InvalidCommandType(7)` before executing it. PancakeSwap
//! Infinity's `0x10`, the UR position-manager commands and other NFT
//! commands are also `.other`. `decode()` assumes the `.uniswap` dialect
//! (0x10 is `V4_SWAP`), so it returns null for a pre-V4 router's calldata
//! carrying an NFT command `0x10`; use
//! `decodeFor(routerAt(chain_id, address).?.router, data)` for those
//! routers.

const std = @import("std");
const keccak = @import("../keccak.zig");
const uint256 = @import("../uint256.zig");
const reader = @import("abi_reader.zig");
const routers = @import("routers.zig");
/// Uniswap V4 swap plans (Universal Router `V4_SWAP`).
pub const v4 = @import("v4.zig");
pub const AddressPath = reader.AddressPath;
pub const AlgebraPath = reader.AlgebraPath;
pub const V3Path = reader.V3Path;
pub const U256Array = reader.U256Array;
pub const BytesArray = reader.BytesArray;
const addChecked = reader.addChecked;
const mulChecked = reader.mulChecked;
const roundUpWord = reader.roundUpWord;
const wordToUsize = reader.wordToUsize;
const isZeroSlice = reader.isZeroSlice;
const readWord = reader.readWord;
const readU256At = reader.readU256At;
const readOffset = reader.readOffset;
const readAddressAt = reader.readAddressAt;
const readBoolAt = reader.readBoolAt;
const readFeeAt = reader.readFeeAt;
const readU160At = reader.readU160At;
const readUintAt = reader.readUintAt;
const readSelectorU32 = reader.readSelectorU32;
const selU32 = reader.selU32;
const bytesAt = reader.bytesAt;
const arrayHeadAt = reader.arrayHeadAt;
const addressArrayAt = reader.addressArrayAt;
const u256ArrayAt = reader.u256ArrayAt;
const bytesArrayAt = reader.bytesArrayAt;
const v3PathHops = reader.v3PathHops;
const ArrayHead = reader.ArrayHead;

// ============================================================================
// Selectors
// ============================================================================

/// Comptime 4-byte selectors for every function `decode` recognizes.
pub const selectors = struct {
    // UniswapV2Router02
    pub const swap_exact_tokens_for_tokens = keccak.selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_tokens_for_exact_tokens = keccak.selector("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_eth_for_tokens = keccak.selector("swapExactETHForTokens(uint256,address[],address,uint256)");
    pub const swap_tokens_for_exact_eth = keccak.selector("swapTokensForExactETH(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_eth = keccak.selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)");
    pub const swap_eth_for_exact_tokens = keccak.selector("swapETHForExactTokens(uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)");

    // V3 SwapRouter (params structs carry a deadline)
    pub const exact_input_single = keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))");
    pub const exact_input = keccak.selector("exactInput((bytes,address,uint256,uint256,uint256))");
    pub const exact_output_single = keccak.selector("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))");
    pub const exact_output = keccak.selector("exactOutput((bytes,address,uint256,uint256,uint256))");

    // SwapRouter02 (V3 params structs without a deadline)
    pub const exact_input_single_02 = keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))");
    pub const exact_input_02 = keccak.selector("exactInput((bytes,address,uint256,uint256))");
    pub const exact_output_single_02 = keccak.selector("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))");
    pub const exact_output_02 = keccak.selector("exactOutput((bytes,address,uint256,uint256))");

    // SwapRouter02 V2-style swaps (no deadline argument)
    pub const swap_exact_tokens_for_tokens_02 = keccak.selector("swapExactTokensForTokens(uint256,uint256,address[],address)");
    pub const swap_tokens_for_exact_tokens_02 = keccak.selector("swapTokensForExactTokens(uint256,uint256,address[],address)");

    // Multicall (SwapRouter and SwapRouter02)
    pub const multicall = keccak.selector("multicall(bytes[])");
    pub const multicall_deadline = keccak.selector("multicall(uint256,bytes[])");
    pub const multicall_blockhash = keccak.selector("multicall(bytes32,bytes[])");

    // Universal Router
    pub const execute = keccak.selector("execute(bytes,bytes[])");
    pub const execute_deadline = keccak.selector("execute(bytes,bytes[],uint256)");
};

// ============================================================================
// Decoded calls
// ============================================================================

/// Exact-input V2 swap. `deadline` is null for SwapRouter02's V2-style call.
pub const V2ExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: ?u256,
};

/// Exact-output V2 swap. `deadline` is null for SwapRouter02's V2-style call.
pub const V2ExactOut = struct {
    amount_out: u256,
    amount_in_max: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: ?u256,
};

/// Exact-input V2 swap paying ETH; the input amount is the tx `value`.
pub const V2EthExactIn = struct {
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: u256,
};

/// Exact-output V2 swap paying ETH; the tx `value` is the maximum input.
pub const V2EthExactOut = struct {
    amount_out: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: u256,
};

/// V3 `exactInputSingle`. `deadline` is null for SwapRouter02.
pub const V3ExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    fee: u24,
    recipient: [20]u8,
    deadline: ?u256,
    amount_in: u256,
    amount_out_minimum: u256,
    sqrt_price_limit_x96: u160,
};

/// V3 `exactOutputSingle`. `deadline` is null for SwapRouter02.
pub const V3ExactOutputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    fee: u24,
    recipient: [20]u8,
    deadline: ?u256,
    amount_out: u256,
    amount_in_maximum: u256,
    sqrt_price_limit_x96: u160,
};

/// V3 `exactInput`. `deadline` is null for SwapRouter02.
pub const V3ExactInput = struct {
    path: V3Path,
    recipient: [20]u8,
    deadline: ?u256,
    amount_in: u256,
    amount_out_minimum: u256,
};

/// V3 `exactOutput`; `path` is reversed (token out first). `deadline` is null
/// for SwapRouter02.
pub const V3ExactOutput = struct {
    path: V3Path,
    recipient: [20]u8,
    deadline: ?u256,
    amount_out: u256,
    amount_in_maximum: u256,
};

pub const Decoded = union(enum) {
    // UniswapV2Router02
    v2_swap_exact_tokens_for_tokens: V2ExactIn,
    v2_swap_tokens_for_exact_tokens: V2ExactOut,
    v2_swap_exact_eth_for_tokens: V2EthExactIn,
    v2_swap_tokens_for_exact_eth: V2ExactOut,
    v2_swap_exact_tokens_for_eth: V2ExactIn,
    v2_swap_eth_for_exact_tokens: V2EthExactOut,
    v2_swap_exact_tokens_for_tokens_fot: V2ExactIn,
    v2_swap_exact_eth_for_tokens_fot: V2EthExactIn,
    v2_swap_exact_tokens_for_eth_fot: V2ExactIn,
    // SwapRouter02 V2-style (deadline null)
    swap_router02_swap_exact_tokens_for_tokens: V2ExactIn,
    swap_router02_swap_tokens_for_exact_tokens: V2ExactOut,
    // V3 SwapRouter and SwapRouter02
    v3_exact_input_single: V3ExactInputSingle,
    v3_exact_input: V3ExactInput,
    v3_exact_output_single: V3ExactOutputSingle,
    v3_exact_output: V3ExactOutput,
    // Batches
    multicall: Multicall,
    universal_router_execute: UniversalRouterExecute,
    // Phase 2 routers: returned only by `decodeFor` with the matching router,
    // never by `decode`. See routers.zig.
    aerodrome_swap_exact_tokens_for_tokens: routers.AerodromeExactIn,
    aerodrome_swap_exact_eth_for_tokens: routers.AerodromeEthExactIn,
    aerodrome_swap_exact_tokens_for_eth: routers.AerodromeExactIn,
    aerodrome_unsafe_swap_exact_tokens_for_tokens: routers.AerodromeUnsafe,
    aerodrome_swap_exact_tokens_for_tokens_fot: routers.AerodromeExactIn,
    aerodrome_swap_exact_eth_for_tokens_fot: routers.AerodromeEthExactIn,
    aerodrome_swap_exact_tokens_for_eth_fot: routers.AerodromeExactIn,
    slipstream_exact_input_single: routers.SlipstreamExactInputSingle,
    slipstream_exact_output_single: routers.SlipstreamExactOutputSingle,
    /// Path hops carry `int24` tick spacing; read it with `Hop.tickSpacing()`.
    slipstream_exact_input: V3ExactInput,
    /// Path hops carry `int24` tick spacing; read it with `Hop.tickSpacing()`.
    slipstream_exact_output: V3ExactOutput,
    camelot_v2_swap_exact_tokens_for_tokens_fot: routers.CamelotV2ExactIn,
    camelot_v2_swap_exact_eth_for_tokens_fot: routers.CamelotV2EthExactIn,
    camelot_v2_swap_exact_tokens_for_eth_fot: routers.CamelotV2ExactIn,
    camelot_v3_exact_input_single: routers.AlgebraExactInputSingle,
    camelot_v3_exact_input_single_fot: routers.AlgebraExactInputSingle,
    camelot_v3_exact_input: routers.AlgebraExactInput,
    camelot_v3_exact_output: routers.AlgebraExactOutput,
    pancake_exact_input_stable_swap: routers.PancakeStableExactIn,
    pancake_exact_output_stable_swap: routers.PancakeStableExactOut,
};

// ============================================================================
// Multicall
// ============================================================================

/// A SwapRouter/SwapRouter02 `multicall`. At most one of `deadline` and
/// `previous_blockhash` is set, matching the overload called.
pub const Multicall = struct {
    deadline: ?u256,
    previous_blockhash: ?[32]u8,
    calls: BytesArray,
    /// The rules inner calls are decoded with: the router the multicall was
    /// sent to (`decodeFor`), `.uniswap` for `decode`.
    router: routers.Router = .uniswap,

    pub fn len(self: Multicall) usize {
        return self.calls.len();
    }

    pub fn iterator(self: Multicall) Iterator {
        return .{ .calls = self.calls, .router = self.router };
    }

    /// One inner call. Inner swaps and the router's payment/permit helpers
    /// are decoded; everything else (including a nested multicall or
    /// Universal Router execute) is `.other`.
    pub const Call = union(enum) {
        swap: Decoded,
        payment: Payment,
        other: struct {
            selector: [4]u8,
            data: []const u8,
        },
    };

    /// SwapRouter/SwapRouter02 helper calls (PeripheryPayments*, SelfPermit).
    /// A null `recipient` means the overload without one (SwapRouter02
    /// extended: pays `msg.sender`).
    pub const Payment = union(enum) {
        /// unwrapWETH9(uint256[,address])
        unwrap_weth9: struct { amount_minimum: u256, recipient: ?[20]u8 },
        /// unwrapWETH9WithFee(uint256,[address,]uint256,address)
        unwrap_weth9_with_fee: struct { amount_minimum: u256, recipient: ?[20]u8, fee_bips: u256, fee_recipient: [20]u8 },
        /// sweepToken(address,uint256[,address])
        sweep_token: struct { token: [20]u8, amount_minimum: u256, recipient: ?[20]u8 },
        /// sweepTokenWithFee(address,uint256,[address,]uint256,address)
        sweep_token_with_fee: struct { token: [20]u8, amount_minimum: u256, recipient: ?[20]u8, fee_bips: u256, fee_recipient: [20]u8 },
        /// refundETH()
        refund_eth,
        /// wrapETH(uint256)
        wrap_eth: struct { value: u256 },
        /// pull(address,uint256)
        pull: struct { token: [20]u8, value: u256 },
        self_permit: SelfPermit,
    };

    /// selfPermit / selfPermitIfNecessary (EIP-2612: `amount` is the value,
    /// `deadline` the deadline) and selfPermitAllowed /
    /// selfPermitAllowedIfNecessary (DAI-style: `amount` is the nonce,
    /// `deadline` the expiry).
    pub const SelfPermit = struct {
        kind: enum { permit, permit_if_necessary, allowed, allowed_if_necessary },
        token: [20]u8,
        amount: u256,
        deadline: u256,
        v: u8,
        r: [32]u8,
        s: [32]u8,
    };

    pub const Iterator = struct {
        calls: BytesArray,
        router: routers.Router = .uniswap,
        index: usize = 0,

        /// `self.router` is public and may have been changed since
        /// construction; if the call no longer re-decodes under it, it
        /// yields `.other` instead of panicking.
        pub fn next(self: *Iterator) ?Call {
            if (self.index >= self.calls.len()) return null;
            const inner = self.calls.get(self.index);
            self.index += 1;
            return decodeMulticallInner(self.router, inner) orelse
                Call{ .other = .{ .selector = inner[0..4].*, .data = inner } };
        }
    };
};

// ============================================================================
// Universal Router
// ============================================================================

/// Universal Router command types, from Commands.sol.
pub const command_types = struct {
    pub const flag_allow_revert: u8 = 0x80;
    /// Every dialect's deployed Universal Router masks the command byte to
    /// 6 bits (0x66a9893c...'s bytecode: `603f8760f81c16`).
    pub const command_type_mask: u8 = 0x3f;

    pub const v3_swap_exact_in: u8 = 0x00;
    pub const v3_swap_exact_out: u8 = 0x01;
    pub const sweep: u8 = 0x04;
    pub const transfer: u8 = 0x05;
    pub const pay_portion: u8 = 0x06;
    pub const v2_swap_exact_in: u8 = 0x08;
    pub const v2_swap_exact_out: u8 = 0x09;
    pub const wrap_eth: u8 = 0x0b;
    pub const unwrap_weth: u8 = 0x0c;
};

/// Command bytes typed by Wave A (spec 0002), kept out of the frozen
/// `command_types` table above.
const ur_cmd = struct {
    const permit2_transfer_from: u8 = 0x02;
    const permit2_permit_batch: u8 = 0x03;
    const permit2_permit: u8 = 0x0a;
    const permit2_transfer_from_batch: u8 = 0x0d;
    const balance_check_erc20: u8 = 0x0e;
    const v4_swap: u8 = 0x10;
    const execute_sub_plan: u8 = 0x21;
    const pancake_stable_swap_exact_in: u8 = 0x22;
    const pancake_stable_swap_exact_out: u8 = 0x23;
};

/// Which command table a Universal Router deployment uses. The same command
/// byte means different things on different deployments.
pub const UrDialect = enum {
    /// Uniswap UR (deployed 0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af
    /// bytecode: type mask 0x3f via `603f8760f81c16`): 0x10 V4_SWAP, 0x21
    /// EXECUTE_SUB_PLAN. What `decode` assumes.
    uniswap,
    /// Pre-V4 Uniswap UR (Commands.sol @ v1.6.0 41183d6, e.g. 0x3fC91A3a…7FAD):
    /// type mask 0x3f, same 0x00-0x0e commands, 0x10-0x20 and 0x22 are NFT and
    /// approval commands (`.other`), 0x21 EXECUTE_SUB_PLAN.
    uniswap_v1,
    /// PancakeSwap UR on BSC: type mask 0x3f, same 0x00-0x0e commands, 0x22 /
    /// 0x23 stable swaps (layout confirmed by BSC tx 0x6cf50c46…c803). 0x10
    /// carries a PancakeSwap Infinity plan with its own pool key and is
    /// `.other`, as is every other command.
    pancake,
};

/// Universal Router `execute`. `deadline` is null for `execute(bytes,bytes[])`
/// and for a sub-plan.
pub const UniversalRouterExecute = struct {
    /// One byte per command.
    commands: []const u8,
    /// One ABI-encoded input per command; `inputs.len() == commands.len`.
    inputs: BytesArray,
    deadline: ?u256,
    dialect: UrDialect = .uniswap,
    /// True for an EXECUTE_SUB_PLAN payload. Sub-plans nest one level: a
    /// sub-plan command inside a sub-plan is `.other`.
    is_sub_plan: bool = false,

    pub fn iterator(self: UniversalRouterExecute) Iterator {
        return .{ .commands = self.commands, .inputs = self.inputs, .dialect = self.dialect, .is_sub_plan = self.is_sub_plan };
    }

    pub const Iterator = struct {
        commands: []const u8,
        inputs: BytesArray,
        dialect: UrDialect = .uniswap,
        is_sub_plan: bool = false,
        index: usize = 0,

        /// `self.dialect`/`self.is_sub_plan` are public and may have been
        /// changed since construction; if the command no longer re-parses
        /// under them, it yields `.other` with its raw input instead of
        /// panicking.
        pub fn next(self: *Iterator) ?Command {
            if (self.index >= self.commands.len) return null;
            const raw = self.commands[self.index];
            const input = self.inputs.get(self.index);
            self.index += 1;
            const command_type = raw & command_types.command_type_mask;
            const payload = parseCommandPayload(self.dialect, self.is_sub_plan, command_type, input) orelse
                Command.Payload{ .other = .{ .command_type = command_type, .input = input } };
            return .{
                .raw = raw,
                .allow_revert = (raw & command_types.flag_allow_revert) != 0,
                .payload = payload,
            };
        }
    };
};

/// One Universal Router command.
///
/// The Dispatcher maps two recipient sentinels before use: `0x0…01` means
/// `msg.sender` and `0x0…02` means the router itself (Dispatcher.sol:332-340).
/// `decode` does not resolve the sentinel; every `recipient` field below
/// carries the raw 20-byte value from calldata.
pub const Command = struct {
    /// The raw command byte.
    raw: u8,
    /// Bit 0x80: a revert in this command does not revert the transaction.
    allow_revert: bool,
    payload: Payload,

    /// V3 swap input. `min_hop_price_x36` is present only in the six-field
    /// layout of newer routers (path offset 0xc0); legacy five-field inputs
    /// (path offset 0xa0) leave it null.
    pub const V3SwapExactIn = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    /// Same layout as `V3SwapExactIn`; `path` is reversed (token out first).
    pub const V3SwapExactOut = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_out: u256,
        amount_in_max: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactIn = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: AddressPath,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactOut = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_out: u256,
        amount_in_max: u256,
        path: AddressPath,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const TokenRecipientAmount = struct {
        token: [20]u8,
        recipient: [20]u8,
        amount: u256,
    };

    pub const RecipientAmount = struct {
        recipient: [20]u8,
        amount: u256,
    };

    /// Permit2 `PermitDetails`.
    pub const PermitDetails = struct {
        token: [20]u8,
        amount: u160,
        expiration: u48,
        nonce: u48,
    };

    /// An ABI `PermitDetails[]` (static tuples, 4 words each), borrowed from
    /// calldata; every element was validated.
    pub const PermitDetailsArray = struct {
        words: []const u8,

        pub fn len(self: PermitDetailsArray) usize {
            return self.words.len / 128;
        }

        pub fn get(self: PermitDetailsArray, i: usize) PermitDetails {
            std.debug.assert(i < self.len());
            const eb = i * 128;
            return .{
                .token = readAddressAt(self.words, eb) orelse unreachable,
                .amount = readUintAt(u160, self.words, eb + 32) orelse unreachable,
                .expiration = readUintAt(u48, self.words, eb + 64) orelse unreachable,
                .nonce = readUintAt(u48, self.words, eb + 96) orelse unreachable,
            };
        }
    };

    /// Permit2 `AllowanceTransferDetails`.
    pub const AllowanceTransfer = struct {
        from: [20]u8,
        to: [20]u8,
        amount: u160,
        token: [20]u8,
    };

    /// An ABI `AllowanceTransferDetails[]` (static tuples, 4 words each).
    pub const AllowanceTransferArray = struct {
        words: []const u8,

        pub fn len(self: AllowanceTransferArray) usize {
            return self.words.len / 128;
        }

        pub fn get(self: AllowanceTransferArray, i: usize) AllowanceTransfer {
            std.debug.assert(i < self.len());
            const eb = i * 128;
            return .{
                .from = readAddressAt(self.words, eb) orelse unreachable,
                .to = readAddressAt(self.words, eb + 32) orelse unreachable,
                .amount = readUintAt(u160, self.words, eb + 64) orelse unreachable,
                .token = readAddressAt(self.words, eb + 96) orelse unreachable,
            };
        }
    };

    /// PERMIT2_PERMIT (0x0a): `(PermitSingle, bytes signature)`.
    pub const Permit2Permit = struct {
        details: PermitDetails,
        spender: [20]u8,
        sig_deadline: u256,
        signature: []const u8,
    };

    /// PERMIT2_PERMIT_BATCH (0x03): `(PermitBatch, bytes signature)`.
    pub const Permit2PermitBatch = struct {
        details: PermitDetailsArray,
        spender: [20]u8,
        sig_deadline: u256,
        signature: []const u8,
    };

    /// PancakeSwap UR stable swap (0x22 exact in / 0x23 exact out).
    /// `amount0`/`amount1` are amountIn/amountOutMin for exact in and
    /// amountOut/amountInMax for exact out. `flags[i]` selects the stable
    /// pool for hop i.
    pub const StableSwap = struct {
        recipient: [20]u8,
        amount0: u256,
        amount1: u256,
        path: AddressPath,
        flags: U256Array,
        payer_is_user: bool,
    };

    pub const Payload = union(enum) {
        v3_swap_exact_in: V3SwapExactIn,
        v3_swap_exact_out: V3SwapExactOut,
        v2_swap_exact_in: V2SwapExactIn,
        v2_swap_exact_out: V2SwapExactOut,
        /// `amount` is the minimum to sweep.
        sweep: TokenRecipientAmount,
        /// `amount` is the value transferred.
        transfer: TokenRecipientAmount,
        /// `amount` is the portion in basis points.
        pay_portion: TokenRecipientAmount,
        /// `amount` is the ETH amount to wrap.
        wrap_eth: RecipientAmount,
        /// `amount` is the minimum WETH to unwrap.
        unwrap_weth: RecipientAmount,
        /// BALANCE_CHECK_ERC20 (0x0e).
        balance_check_erc20: struct { owner: [20]u8, token: [20]u8, min_balance: u256 },
        permit2_permit: Permit2Permit,
        permit2_permit_batch: Permit2PermitBatch,
        /// PERMIT2_TRANSFER_FROM (0x02).
        permit2_transfer_from: struct { token: [20]u8, recipient: [20]u8, amount: u160 },
        /// PERMIT2_TRANSFER_FROM_BATCH (0x0d).
        permit2_transfer_from_batch: AllowanceTransferArray,
        /// V4_SWAP (0x10, `.uniswap` dialect only).
        v4_swap: v4.Plan,
        /// EXECUTE_SUB_PLAN: a nested `execute` with `deadline == null` and
        /// `is_sub_plan == true`.
        execute_sub_plan: UniversalRouterExecute,
        /// PancakeSwap 0x22 (`.pancake` dialect only).
        stable_swap_exact_in: StableSwap,
        /// PancakeSwap 0x23 (`.pancake` dialect only).
        stable_swap_exact_out: StableSwap,
        /// Any other command type (position managers, NFT commands, ...),
        /// undecoded.
        other: struct {
            command_type: u8,
            input: []const u8,
        },
    };
};

// ============================================================================
// Decoding: UniswapV2Router02 / SwapRouter02 V2-style swaps
// ============================================================================
//
// Static head: amount0, amount1, path offset, to, [deadline]. `has_deadline`
// is false only for the SwapRouter02 V2-style overloads (no trailing word).

fn parseV2ExactIn(data: []const u8, args_base: usize, has_deadline: bool) ?V2ExactIn {
    const amount_in = readU256At(data, args_base) orelse return null;
    const amount_out_min = readU256At(data, args_base + 32) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = readAddressAt(data, args_base + 96) orelse return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 128) orelse return null) else null;
    return .{ .amount_in = amount_in, .amount_out_min = amount_out_min, .path = path, .to = to, .deadline = deadline };
}

fn parseV2ExactOut(data: []const u8, args_base: usize, has_deadline: bool) ?V2ExactOut {
    const amount_out = readU256At(data, args_base) orelse return null;
    const amount_in_max = readU256At(data, args_base + 32) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = readAddressAt(data, args_base + 96) orelse return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 128) orelse return null) else null;
    return .{ .amount_out = amount_out, .amount_in_max = amount_in_max, .path = path, .to = to, .deadline = deadline };
}

fn parseV2EthExactIn(data: []const u8, args_base: usize) ?V2EthExactIn {
    const amount_out_min = readU256At(data, args_base) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = readAddressAt(data, args_base + 64) orelse return null;
    const deadline = readU256At(data, args_base + 96) orelse return null;
    return .{ .amount_out_min = amount_out_min, .path = path, .to = to, .deadline = deadline };
}

fn parseV2EthExactOut(data: []const u8, args_base: usize) ?V2EthExactOut {
    const amount_out = readU256At(data, args_base) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = readAddressAt(data, args_base + 64) orelse return null;
    const deadline = readU256At(data, args_base + 96) orelse return null;
    return .{ .amount_out = amount_out, .path = path, .to = to, .deadline = deadline };
}

// ============================================================================
// Decoding: V3 SwapRouter / SwapRouter02
// ============================================================================
//
// The *Single params are a static tuple, inline right after the selector.
// The path-based params contain a dynamic `bytes path`, so the tuple itself
// is dynamic and reached through one outer offset word.

fn parseV3ExactInputSingle(data: []const u8, has_deadline: bool) ?V3ExactInputSingle {
    const t: usize = 4;
    const token_in = readAddressAt(data, t) orelse return null;
    const token_out = readAddressAt(data, t + 32) orelse return null;
    const fee = readFeeAt(data, t + 64) orelse return null;
    const recipient = readAddressAt(data, t + 96) orelse return null;
    var pos = t + 128;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_in = readU256At(data, pos) orelse return null;
    const amount_out_minimum = readU256At(data, pos + 32) orelse return null;
    const sqrt_price_limit_x96 = readU160At(data, pos + 64) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .fee = fee,
        .recipient = recipient,
        .deadline = deadline,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

fn parseV3ExactOutputSingle(data: []const u8, has_deadline: bool) ?V3ExactOutputSingle {
    const t: usize = 4;
    const token_in = readAddressAt(data, t) orelse return null;
    const token_out = readAddressAt(data, t + 32) orelse return null;
    const fee = readFeeAt(data, t + 64) orelse return null;
    const recipient = readAddressAt(data, t + 96) orelse return null;
    var pos = t + 128;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_out = readU256At(data, pos) orelse return null;
    const amount_in_maximum = readU256At(data, pos + 32) orelse return null;
    const sqrt_price_limit_x96 = readU160At(data, pos + 64) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .fee = fee,
        .recipient = recipient,
        .deadline = deadline,
        .amount_out = amount_out,
        .amount_in_maximum = amount_in_maximum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

/// Shared with routers.zig (Slipstream uses the same layout).
pub fn parseV3ExactInput(data: []const u8, has_deadline: bool) ?V3ExactInput {
    const args_base: usize = 4;
    const off = readOffset(data, args_base) orelse return null;
    const t = addChecked(args_base, off) orelse return null;
    const path_bytes = bytesAt(data, t, t) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const recipient = readAddressAt(data, t + 32) orelse return null;
    var pos = t + 64;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_in = readU256At(data, pos) orelse return null;
    const amount_out_minimum = readU256At(data, pos + 32) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_in = amount_in, .amount_out_minimum = amount_out_minimum };
}

/// Shared with routers.zig (Slipstream uses the same layout).
pub fn parseV3ExactOutput(data: []const u8, has_deadline: bool) ?V3ExactOutput {
    const args_base: usize = 4;
    const off = readOffset(data, args_base) orelse return null;
    const t = addChecked(args_base, off) orelse return null;
    const path_bytes = bytesAt(data, t, t) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const recipient = readAddressAt(data, t + 32) orelse return null;
    var pos = t + 64;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_out = readU256At(data, pos) orelse return null;
    const amount_in_maximum = readU256At(data, pos + 32) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_out = amount_out, .amount_in_maximum = amount_in_maximum };
}

// ============================================================================
// Decoding: Universal Router command payloads
// ============================================================================
//
// Each `input` is itself an ABI argument block (no selector). Slots 0-4 are
// recipient/amount/amount/pathOffset/bool; slot 5 (present when the path
// offset is >= 0xc0) is an offset to `minHopPriceX36`, per BytesLib's
// `toLengthOffset` convention (spec section 5).

fn parseV3SwapExactIn(input: []const u8) ?Command.V3SwapExactIn {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_in = readU256At(input, 32) orelse return null;
    const amount_out_min = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path_bytes = bytesAt(input, 0, 96) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_in = amount_in,
        .amount_out_min = amount_out_min,
        .path = .{ .bytes = path_bytes },
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV3SwapExactOut(input: []const u8) ?Command.V3SwapExactOut {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_out = readU256At(input, 32) orelse return null;
    const amount_in_max = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path_bytes = bytesAt(input, 0, 96) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_out = amount_out,
        .amount_in_max = amount_in_max,
        .path = .{ .bytes = path_bytes },
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV2SwapExactIn(input: []const u8) ?Command.V2SwapExactIn {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_in = readU256At(input, 32) orelse return null;
    const amount_out_min = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path = addressArrayAt(input, 0, 96) orelse return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_in = amount_in,
        .amount_out_min = amount_out_min,
        .path = path,
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV2SwapExactOut(input: []const u8) ?Command.V2SwapExactOut {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_out = readU256At(input, 32) orelse return null;
    const amount_in_max = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path = addressArrayAt(input, 0, 96) orelse return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_out = amount_out,
        .amount_in_max = amount_in_max,
        .path = path,
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseTokenRecipientAmount(input: []const u8) ?Command.TokenRecipientAmount {
    const token = readAddressAt(input, 0) orelse return null;
    const recipient = readAddressAt(input, 32) orelse return null;
    const amount = readU256At(input, 64) orelse return null;
    return .{ .token = token, .recipient = recipient, .amount = amount };
}

fn parseRecipientAmount(input: []const u8) ?Command.RecipientAmount {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount = readU256At(input, 32) orelse return null;
    return .{ .recipient = recipient, .amount = amount };
}

/// PERMIT2_PERMIT (0x0a): `PermitSingle` inline (4-word `PermitDetails`,
/// spender, sigDeadline), then `bytes signature` at arg 6.
fn parsePermit2Permit(input: []const u8) ?Command.Permit2Permit {
    const token = readAddressAt(input, 0) orelse return null;
    const amount = readUintAt(u160, input, 32) orelse return null;
    const expiration = readUintAt(u48, input, 64) orelse return null;
    const nonce = readUintAt(u48, input, 96) orelse return null;
    const spender = readAddressAt(input, 128) orelse return null;
    const sig_deadline = readU256At(input, 160) orelse return null;
    const signature = bytesAt(input, 0, 192) orelse return null;
    return .{
        .details = .{ .token = token, .amount = amount, .expiration = expiration, .nonce = nonce },
        .spender = spender,
        .sig_deadline = sig_deadline,
        .signature = signature,
    };
}

/// A `PermitDetails[]` (static 4-word tuples), located and eagerly validated
/// the way `bytesArrayAt` locates a `bytes[]`, but with an inline (offset-less)
/// element layout, so every element sits directly in the array's data.
fn permitDetailsArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?Command.PermitDetailsArray {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const arr_start = addChecked(base, off) orelse return null;
    const count = wordToUsize(readU256At(data, arr_start) orelse return null) orelse return null;
    const head_start = addChecked(arr_start, 32) orelse return null;
    const head_len = mulChecked(count, 128) orelse return null;
    const head_end = addChecked(head_start, head_len) orelse return null;
    if (head_end > data.len) return null;
    const words = data[head_start..head_end];
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const eb = i * 128;
        _ = readAddressAt(words, eb) orelse return null;
        _ = readUintAt(u160, words, eb + 32) orelse return null;
        _ = readUintAt(u48, words, eb + 64) orelse return null;
        _ = readUintAt(u48, words, eb + 96) orelse return null;
    }
    return .{ .words = words };
}

/// An `AllowanceTransferDetails[]` (static 4-word tuples); same shape as
/// `permitDetailsArrayAt` but with `(from, to, amount, token)` fields.
fn allowanceTransferArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?Command.AllowanceTransferArray {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const arr_start = addChecked(base, off) orelse return null;
    const count = wordToUsize(readU256At(data, arr_start) orelse return null) orelse return null;
    const head_start = addChecked(arr_start, 32) orelse return null;
    const head_len = mulChecked(count, 128) orelse return null;
    const head_end = addChecked(head_start, head_len) orelse return null;
    if (head_end > data.len) return null;
    const words = data[head_start..head_end];
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const eb = i * 128;
        _ = readAddressAt(words, eb) orelse return null;
        _ = readAddressAt(words, eb + 32) orelse return null;
        _ = readUintAt(u160, words, eb + 64) orelse return null;
        _ = readAddressAt(words, eb + 96) orelse return null;
    }
    return .{ .words = words };
}

/// PERMIT2_PERMIT_BATCH (0x03): `(PermitBatch{details,spender,sigDeadline}
/// via offset, bytes signature)`.
fn parsePermit2PermitBatch(input: []const u8) ?Command.Permit2PermitBatch {
    const t = readOffset(input, 0) orelse return null;
    const details = permitDetailsArrayAt(input, t, t) orelse return null;
    const spender_pos = addChecked(t, 32) orelse return null;
    const spender = readAddressAt(input, spender_pos) orelse return null;
    const sig_deadline_pos = addChecked(t, 64) orelse return null;
    const sig_deadline = readU256At(input, sig_deadline_pos) orelse return null;
    const signature = bytesAt(input, 0, 32) orelse return null;
    return .{ .details = details, .spender = spender, .sig_deadline = sig_deadline, .signature = signature };
}

/// PancakeSwap UR stable swap (0x22/0x23): `(recipient, amount0, amount1,
/// address[] path, uint256[] flags, bool payerIsUser)`.
fn parseStableSwap(input: []const u8) ?Command.StableSwap {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount0 = readU256At(input, 32) orelse return null;
    const amount1 = readU256At(input, 64) orelse return null;
    const path = addressArrayAt(input, 0, 96) orelse return null;
    const flags = u256ArrayAt(input, 0, 128) orelse return null;
    const payer_is_user = readBoolAt(input, 160) orelse return null;
    return .{ .recipient = recipient, .amount0 = amount0, .amount1 = amount1, .path = path, .flags = flags, .payer_is_user = payer_is_user };
}

/// Dispatch on the masked command type, for `dialect`. `is_sub_plan` forces
/// EXECUTE_SUB_PLAN (0x21) to `.other`: a sub-plan command inside a sub-plan
/// nests no further. Unknown or dialect-inapplicable types always succeed as
/// `.other`; known, applicable types must parse or the whole command is
/// invalid.
fn parseCommandPayload(dialect: UrDialect, is_sub_plan: bool, command_type: u8, input: []const u8) ?Command.Payload {
    return switch (command_type) {
        command_types.v3_swap_exact_in => .{ .v3_swap_exact_in = parseV3SwapExactIn(input) orelse return null },
        command_types.v3_swap_exact_out => .{ .v3_swap_exact_out = parseV3SwapExactOut(input) orelse return null },
        ur_cmd.permit2_transfer_from => blk: {
            const token = readAddressAt(input, 0) orelse return null;
            const recipient = readAddressAt(input, 32) orelse return null;
            const amount = readUintAt(u160, input, 64) orelse return null;
            break :blk .{ .permit2_transfer_from = .{ .token = token, .recipient = recipient, .amount = amount } };
        },
        ur_cmd.permit2_permit_batch => .{ .permit2_permit_batch = parsePermit2PermitBatch(input) orelse return null },
        command_types.sweep => .{ .sweep = parseTokenRecipientAmount(input) orelse return null },
        command_types.transfer => .{ .transfer = parseTokenRecipientAmount(input) orelse return null },
        command_types.pay_portion => .{ .pay_portion = parseTokenRecipientAmount(input) orelse return null },
        command_types.v2_swap_exact_in => .{ .v2_swap_exact_in = parseV2SwapExactIn(input) orelse return null },
        command_types.v2_swap_exact_out => .{ .v2_swap_exact_out = parseV2SwapExactOut(input) orelse return null },
        ur_cmd.permit2_permit => .{ .permit2_permit = parsePermit2Permit(input) orelse return null },
        command_types.wrap_eth => .{ .wrap_eth = parseRecipientAmount(input) orelse return null },
        command_types.unwrap_weth => .{ .unwrap_weth = parseRecipientAmount(input) orelse return null },
        ur_cmd.permit2_transfer_from_batch => blk: {
            const arr = allowanceTransferArrayAt(input, 0, 0) orelse return null;
            break :blk .{ .permit2_transfer_from_batch = arr };
        },
        ur_cmd.balance_check_erc20 => blk: {
            const owner = readAddressAt(input, 0) orelse return null;
            const token = readAddressAt(input, 32) orelse return null;
            const min_balance = readU256At(input, 64) orelse return null;
            break :blk .{ .balance_check_erc20 = .{ .owner = owner, .token = token, .min_balance = min_balance } };
        },
        ur_cmd.v4_swap => if (dialect == .uniswap)
            Command.Payload{ .v4_swap = v4.parsePlan(input) orelse return null }
        else
            Command.Payload{ .other = .{ .command_type = command_type, .input = input } },
        ur_cmd.execute_sub_plan => if (!is_sub_plan and dialect != .pancake)
            Command.Payload{ .execute_sub_plan = parseUniversalRouterExecute(input, 0, false, dialect, true) orelse return null }
        else
            Command.Payload{ .other = .{ .command_type = command_type, .input = input } },
        ur_cmd.pancake_stable_swap_exact_in => if (dialect == .pancake)
            Command.Payload{ .stable_swap_exact_in = parseStableSwap(input) orelse return null }
        else
            Command.Payload{ .other = .{ .command_type = command_type, .input = input } },
        ur_cmd.pancake_stable_swap_exact_out => if (dialect == .pancake)
            Command.Payload{ .stable_swap_exact_out = parseStableSwap(input) orelse return null }
        else
            Command.Payload{ .other = .{ .command_type = command_type, .input = input } },
        else => .{ .other = .{ .command_type = command_type, .input = input } },
    };
}

/// `execute(bytes commands, bytes[] inputs, [uint256 deadline])`. Every
/// command's payload is validated here so the iterator can be infallible.
/// `dialect` picks the command table; `is_sub_plan` is true when `data` is
/// itself an EXECUTE_SUB_PLAN payload (`args_base == 0`, `has_deadline ==
/// false`).
fn parseUniversalRouterExecute(data: []const u8, args_base: usize, has_deadline: bool, dialect: UrDialect, is_sub_plan: bool) ?UniversalRouterExecute {
    const commands = bytesAt(data, args_base, args_base) orelse return null;
    const inputs = bytesArrayAt(data, args_base, args_base + 32) orelse return null;
    if (commands.len != inputs.count) return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 64) orelse return null) else null;

    var i: usize = 0;
    while (i < commands.len) : (i += 1) {
        const input_i = bytesAt(inputs.head, 0, i * 32) orelse return null;
        const command_type = commands[i] & command_types.command_type_mask;
        _ = parseCommandPayload(dialect, is_sub_plan, command_type, input_i) orelse return null;
    }
    return .{ .commands = commands, .inputs = inputs, .deadline = deadline, .dialect = dialect, .is_sub_plan = is_sub_plan };
}

// ============================================================================
// Decoding: Multicall
// ============================================================================

const MulticallKind = enum { plain, with_deadline, with_blockhash };

/// Selectors for the SwapRouter/SwapRouter02 payment and permit helpers
/// (`PeripheryPayments*`, `SelfPermit`) a multicall inner call can carry.
const multicall_payment_selectors = struct {
    const unwrap_weth9 = keccak.selector("unwrapWETH9(uint256)");
    const unwrap_weth9_recipient = keccak.selector("unwrapWETH9(uint256,address)");
    const unwrap_weth9_with_fee = keccak.selector("unwrapWETH9WithFee(uint256,uint256,address)");
    const unwrap_weth9_with_fee_recipient = keccak.selector("unwrapWETH9WithFee(uint256,address,uint256,address)");
    const sweep_token = keccak.selector("sweepToken(address,uint256)");
    const sweep_token_recipient = keccak.selector("sweepToken(address,uint256,address)");
    const sweep_token_with_fee = keccak.selector("sweepTokenWithFee(address,uint256,uint256,address)");
    const sweep_token_with_fee_recipient = keccak.selector("sweepTokenWithFee(address,uint256,address,uint256,address)");
    const refund_eth = keccak.selector("refundETH()");
    const wrap_eth = keccak.selector("wrapETH(uint256)");
    const pull = keccak.selector("pull(address,uint256)");
    const self_permit = keccak.selector("selfPermit(address,uint256,uint256,uint8,bytes32,bytes32)");
    const self_permit_if_necessary = keccak.selector("selfPermitIfNecessary(address,uint256,uint256,uint8,bytes32,bytes32)");
    const self_permit_allowed = keccak.selector("selfPermitAllowed(address,uint256,uint256,uint8,bytes32,bytes32)");
    const self_permit_allowed_if_necessary = keccak.selector("selfPermitAllowedIfNecessary(address,uint256,uint256,uint8,bytes32,bytes32)");
};

fn isMulticallPaymentSelector(sel: u32) bool {
    return switch (sel) {
        selU32(multicall_payment_selectors.unwrap_weth9),
        selU32(multicall_payment_selectors.unwrap_weth9_recipient),
        selU32(multicall_payment_selectors.unwrap_weth9_with_fee),
        selU32(multicall_payment_selectors.unwrap_weth9_with_fee_recipient),
        selU32(multicall_payment_selectors.sweep_token),
        selU32(multicall_payment_selectors.sweep_token_recipient),
        selU32(multicall_payment_selectors.sweep_token_with_fee),
        selU32(multicall_payment_selectors.sweep_token_with_fee_recipient),
        selU32(multicall_payment_selectors.refund_eth),
        selU32(multicall_payment_selectors.wrap_eth),
        selU32(multicall_payment_selectors.pull),
        selU32(multicall_payment_selectors.self_permit),
        selU32(multicall_payment_selectors.self_permit_if_necessary),
        selU32(multicall_payment_selectors.self_permit_allowed),
        selU32(multicall_payment_selectors.self_permit_allowed_if_necessary),
        => true,
        else => false,
    };
}

const SelfPermitFields = struct { token: [20]u8, amount: u256, deadline: u256, v: u8, r: [32]u8, s: [32]u8 };

fn parseSelfPermitFields(data: []const u8, b: usize) ?SelfPermitFields {
    const token = readAddressAt(data, b) orelse return null;
    const amount = readU256At(data, b + 32) orelse return null;
    const deadline = readU256At(data, b + 64) orelse return null;
    const v = readUintAt(u8, data, b + 96) orelse return null;
    const r = readWord(data, b + 128) orelse return null;
    const s = readWord(data, b + 160) orelse return null;
    return .{ .token = token, .amount = amount, .deadline = deadline, .v = v, .r = r, .s = s };
}

/// Decode a payment/permit helper call's arguments (`inner[4..]`). Null for
/// an unrecognized or malformed selector.
fn decodeMulticallPayment(sel: u32, inner: []const u8) ?Multicall.Payment {
    const b: usize = 4;
    return switch (sel) {
        selU32(multicall_payment_selectors.unwrap_weth9) => blk: {
            const amount_minimum = readU256At(inner, b) orelse return null;
            break :blk .{ .unwrap_weth9 = .{ .amount_minimum = amount_minimum, .recipient = null } };
        },
        selU32(multicall_payment_selectors.unwrap_weth9_recipient) => blk: {
            const amount_minimum = readU256At(inner, b) orelse return null;
            const recipient = readAddressAt(inner, b + 32) orelse return null;
            break :blk .{ .unwrap_weth9 = .{ .amount_minimum = amount_minimum, .recipient = recipient } };
        },
        selU32(multicall_payment_selectors.unwrap_weth9_with_fee) => blk: {
            const amount_minimum = readU256At(inner, b) orelse return null;
            const fee_bips = readU256At(inner, b + 32) orelse return null;
            const fee_recipient = readAddressAt(inner, b + 64) orelse return null;
            break :blk .{ .unwrap_weth9_with_fee = .{ .amount_minimum = amount_minimum, .recipient = null, .fee_bips = fee_bips, .fee_recipient = fee_recipient } };
        },
        selU32(multicall_payment_selectors.unwrap_weth9_with_fee_recipient) => blk: {
            const amount_minimum = readU256At(inner, b) orelse return null;
            const recipient = readAddressAt(inner, b + 32) orelse return null;
            const fee_bips = readU256At(inner, b + 64) orelse return null;
            const fee_recipient = readAddressAt(inner, b + 96) orelse return null;
            break :blk .{ .unwrap_weth9_with_fee = .{ .amount_minimum = amount_minimum, .recipient = recipient, .fee_bips = fee_bips, .fee_recipient = fee_recipient } };
        },
        selU32(multicall_payment_selectors.sweep_token) => blk: {
            const token = readAddressAt(inner, b) orelse return null;
            const amount_minimum = readU256At(inner, b + 32) orelse return null;
            break :blk .{ .sweep_token = .{ .token = token, .amount_minimum = amount_minimum, .recipient = null } };
        },
        selU32(multicall_payment_selectors.sweep_token_recipient) => blk: {
            const token = readAddressAt(inner, b) orelse return null;
            const amount_minimum = readU256At(inner, b + 32) orelse return null;
            const recipient = readAddressAt(inner, b + 64) orelse return null;
            break :blk .{ .sweep_token = .{ .token = token, .amount_minimum = amount_minimum, .recipient = recipient } };
        },
        selU32(multicall_payment_selectors.sweep_token_with_fee) => blk: {
            const token = readAddressAt(inner, b) orelse return null;
            const amount_minimum = readU256At(inner, b + 32) orelse return null;
            const fee_bips = readU256At(inner, b + 64) orelse return null;
            const fee_recipient = readAddressAt(inner, b + 96) orelse return null;
            break :blk .{ .sweep_token_with_fee = .{ .token = token, .amount_minimum = amount_minimum, .recipient = null, .fee_bips = fee_bips, .fee_recipient = fee_recipient } };
        },
        selU32(multicall_payment_selectors.sweep_token_with_fee_recipient) => blk: {
            const token = readAddressAt(inner, b) orelse return null;
            const amount_minimum = readU256At(inner, b + 32) orelse return null;
            const recipient = readAddressAt(inner, b + 64) orelse return null;
            const fee_bips = readU256At(inner, b + 96) orelse return null;
            const fee_recipient = readAddressAt(inner, b + 128) orelse return null;
            break :blk .{ .sweep_token_with_fee = .{ .token = token, .amount_minimum = amount_minimum, .recipient = recipient, .fee_bips = fee_bips, .fee_recipient = fee_recipient } };
        },
        selU32(multicall_payment_selectors.refund_eth) => .refund_eth,
        selU32(multicall_payment_selectors.wrap_eth) => blk: {
            const value = readU256At(inner, b) orelse return null;
            break :blk .{ .wrap_eth = .{ .value = value } };
        },
        selU32(multicall_payment_selectors.pull) => blk: {
            const token = readAddressAt(inner, b) orelse return null;
            const value = readU256At(inner, b + 32) orelse return null;
            break :blk .{ .pull = .{ .token = token, .value = value } };
        },
        selU32(multicall_payment_selectors.self_permit) => blk: {
            const f = parseSelfPermitFields(inner, b) orelse return null;
            break :blk .{ .self_permit = .{ .kind = .permit, .token = f.token, .amount = f.amount, .deadline = f.deadline, .v = f.v, .r = f.r, .s = f.s } };
        },
        selU32(multicall_payment_selectors.self_permit_if_necessary) => blk: {
            const f = parseSelfPermitFields(inner, b) orelse return null;
            break :blk .{ .self_permit = .{ .kind = .permit_if_necessary, .token = f.token, .amount = f.amount, .deadline = f.deadline, .v = f.v, .r = f.r, .s = f.s } };
        },
        selU32(multicall_payment_selectors.self_permit_allowed) => blk: {
            const f = parseSelfPermitFields(inner, b) orelse return null;
            break :blk .{ .self_permit = .{ .kind = .allowed, .token = f.token, .amount = f.amount, .deadline = f.deadline, .v = f.v, .r = f.r, .s = f.s } };
        },
        selU32(multicall_payment_selectors.self_permit_allowed_if_necessary) => blk: {
            const f = parseSelfPermitFields(inner, b) orelse return null;
            break :blk .{ .self_permit = .{ .kind = .allowed_if_necessary, .token = f.token, .amount = f.amount, .deadline = f.deadline, .v = f.v, .r = f.r, .s = f.s } };
        },
        else => null,
    };
}

/// Decode one inner multicall call (`inner.len >= 4` already checked by the
/// caller) under `router`'s rules: a swap (via `routers.isInnerSwapSelector`
/// / `decodeInnerCall`), a typed payment/permit helper, or `.other`. Null
/// means the call looked like a swap or payment but failed to parse.
fn decodeMulticallInner(router: routers.Router, inner: []const u8) ?Multicall.Call {
    const sel = readSelectorU32(inner) orelse return null;
    const sel4 = inner[0..4].*;
    if (routers.isInnerSwapSelector(router, sel4)) {
        const decoded = routers.decodeInnerCall(router, inner) orelse return null;
        return .{ .swap = decoded };
    }
    if (isMulticallPaymentSelector(sel)) {
        const payment = decodeMulticallPayment(sel, inner) orelse return null;
        return .{ .payment = payment };
    }
    return .{ .other = .{ .selector = sel4, .data = inner } };
}

/// Every inner call is validated eagerly: too short is fatal, a recognized
/// swap or payment selector must fully decode, and anything else (including
/// a nested multicall or UR execute) is accepted as `.other` without
/// recursing.
fn parseMulticall(data: []const u8, args_base: usize, kind: MulticallKind, router: routers.Router) ?Multicall {
    var deadline: ?u256 = null;
    var previous_blockhash: ?[32]u8 = null;
    var calls_offset_pos = args_base;
    switch (kind) {
        .plain => {},
        .with_deadline => {
            deadline = readU256At(data, args_base) orelse return null;
            calls_offset_pos = args_base + 32;
        },
        .with_blockhash => {
            previous_blockhash = readWord(data, args_base) orelse return null;
            calls_offset_pos = args_base + 32;
        },
    }
    const calls = bytesArrayAt(data, args_base, calls_offset_pos) orelse return null;

    var i: usize = 0;
    while (i < calls.count) : (i += 1) {
        const inner = bytesAt(calls.head, 0, i * 32) orelse return null;
        if (inner.len < 4) return null;
        _ = decodeMulticallInner(router, inner) orelse return null;
    }
    return .{ .deadline = deadline, .previous_blockhash = previous_blockhash, .calls = calls, .router = router };
}

// ============================================================================
// Decoding: top-level dispatch
// ============================================================================

/// Shared dispatch for `decode` and `decodeBatchFor`. `ur_dialect`
/// picks the command table for a Universal Router `execute` call.
fn decodeDispatch(data: []const u8, ur_dialect: UrDialect) ?Decoded {
    const sel = readSelectorU32(data) orelse return null;
    const args_base: usize = 4;

    return switch (sel) {
        selU32(selectors.swap_exact_tokens_for_tokens) => Decoded{ .v2_swap_exact_tokens_for_tokens = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_tokens_for_exact_tokens) => Decoded{ .v2_swap_tokens_for_exact_tokens = parseV2ExactOut(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_eth_for_tokens) => Decoded{ .v2_swap_exact_eth_for_tokens = parseV2EthExactIn(data, args_base) orelse return null },
        selU32(selectors.swap_tokens_for_exact_eth) => Decoded{ .v2_swap_tokens_for_exact_eth = parseV2ExactOut(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_tokens_for_eth) => Decoded{ .v2_swap_exact_tokens_for_eth = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_eth_for_exact_tokens) => Decoded{ .v2_swap_eth_for_exact_tokens = parseV2EthExactOut(data, args_base) orelse return null },
        selU32(selectors.swap_exact_tokens_for_tokens_fot) => Decoded{ .v2_swap_exact_tokens_for_tokens_fot = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_eth_for_tokens_fot) => Decoded{ .v2_swap_exact_eth_for_tokens_fot = parseV2EthExactIn(data, args_base) orelse return null },
        selU32(selectors.swap_exact_tokens_for_eth_fot) => Decoded{ .v2_swap_exact_tokens_for_eth_fot = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_tokens_for_tokens_02) => Decoded{ .swap_router02_swap_exact_tokens_for_tokens = parseV2ExactIn(data, args_base, false) orelse return null },
        selU32(selectors.swap_tokens_for_exact_tokens_02) => Decoded{ .swap_router02_swap_tokens_for_exact_tokens = parseV2ExactOut(data, args_base, false) orelse return null },
        selU32(selectors.exact_input_single) => Decoded{ .v3_exact_input_single = parseV3ExactInputSingle(data, true) orelse return null },
        selU32(selectors.exact_input_single_02) => Decoded{ .v3_exact_input_single = parseV3ExactInputSingle(data, false) orelse return null },
        selU32(selectors.exact_output_single) => Decoded{ .v3_exact_output_single = parseV3ExactOutputSingle(data, true) orelse return null },
        selU32(selectors.exact_output_single_02) => Decoded{ .v3_exact_output_single = parseV3ExactOutputSingle(data, false) orelse return null },
        selU32(selectors.exact_input) => Decoded{ .v3_exact_input = parseV3ExactInput(data, true) orelse return null },
        selU32(selectors.exact_input_02) => Decoded{ .v3_exact_input = parseV3ExactInput(data, false) orelse return null },
        selU32(selectors.exact_output) => Decoded{ .v3_exact_output = parseV3ExactOutput(data, true) orelse return null },
        selU32(selectors.exact_output_02) => Decoded{ .v3_exact_output = parseV3ExactOutput(data, false) orelse return null },
        selU32(selectors.multicall) => Decoded{ .multicall = parseMulticall(data, args_base, .plain, .uniswap) orelse return null },
        selU32(selectors.multicall_deadline) => Decoded{ .multicall = parseMulticall(data, args_base, .with_deadline, .uniswap) orelse return null },
        selU32(selectors.multicall_blockhash) => Decoded{ .multicall = parseMulticall(data, args_base, .with_blockhash, .uniswap) orelse return null },
        selU32(selectors.execute) => Decoded{ .universal_router_execute = parseUniversalRouterExecute(data, args_base, false, ur_dialect, false) orelse return null },
        selU32(selectors.execute_deadline) => Decoded{ .universal_router_execute = parseUniversalRouterExecute(data, args_base, true, ur_dialect, false) orelse return null },
        else => null,
    };
}

/// Shared with routers.zig, which reuses it for `decodeFor`/`decodeInnerCall`.
pub fn isBatchSelector(sel: u32) bool {
    return sel == selU32(selectors.multicall) or
        sel == selU32(selectors.multicall_deadline) or
        sel == selU32(selectors.multicall_blockhash) or
        sel == selU32(selectors.execute) or
        sel == selU32(selectors.execute_deadline);
}

/// Decode a batch call (`multicall` or Universal Router `execute`) sent to
/// `router`: the multicall's `router` field is set so inner calls decode under
/// its rules, and `execute` uses the router's `UrDialect`. Null for any other
/// selector. Used by `decodeFor`.
pub fn decodeBatchFor(router: Router, data: []const u8) ?Decoded {
    const sel = readSelectorU32(data) orelse return null;
    if (!isBatchSelector(sel)) return null;
    const args_base: usize = 4;

    if (sel == selU32(selectors.multicall)) {
        return Decoded{ .multicall = parseMulticall(data, args_base, .plain, router) orelse return null };
    }
    if (sel == selU32(selectors.multicall_deadline)) {
        return Decoded{ .multicall = parseMulticall(data, args_base, .with_deadline, router) orelse return null };
    }
    if (sel == selU32(selectors.multicall_blockhash)) {
        return Decoded{ .multicall = parseMulticall(data, args_base, .with_blockhash, router) orelse return null };
    }
    const dialect: UrDialect = switch (router) {
        .uniswap_ur_v1 => .uniswap_v1,
        .pancake_ur => .pancake,
        else => .uniswap,
    };
    const has_deadline = sel == selU32(selectors.execute_deadline);
    return Decoded{ .universal_router_execute = parseUniversalRouterExecute(data, args_base, has_deadline, dialect, false) orelse return null };
}

/// Router-aware decoding for routers whose selectors collide with Uniswap's
/// but mean something else (Slipstream, Camelot, Pancake, pre-V4 UR).
pub const decodeFor = routers.decodeFor;
pub const Router = routers.Router;
pub const Protocol = routers.Protocol;
pub const Deployment = routers.Deployment;
pub const routerAt = routers.routerAt;

/// Decode router calldata. Returns null for unknown selectors and for any
/// malformed or truncated input; never panics and never allocates.
pub fn decode(data: []const u8) ?Decoded {
    return decodeDispatch(data, .uniswap);
}
