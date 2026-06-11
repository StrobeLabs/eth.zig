//! Comptime contract bindings (abigen).
//!
//! `Bind(@embedFile("weth.json"))` parses a Solidity JSON ABI *at compile time*
//! and returns a contract type whose calls and event decoders are statically
//! typed from the ABI, with selectors and event topics precomputed and zero
//! runtime ABI parsing. This is the headline "why Zig" capability -- Rust needs
//! a proc-macro plus a codegen step to reach the same developer experience;
//! Zig does it in-language.
//!
//! Calls go through a single generic `call(provider, name, args)` rather than a
//! generated `weth.balanceOf(...)` method, because Zig cannot mint a `pub fn`
//! whose name comes from a comptime string. `name` is still comptime, so the
//! argument and return types are resolved from the ABI at compile time:
//! `ArgsOf(name)` / `ReturnOf(name)`. An unknown function name or a wrong
//! argument type is a compile error, exactly like a named method would give.
//!
//! ## Usage
//! ```zig
//! const eth = @import("eth");
//! const Weth = eth.bind(@embedFile("weth.json"));
//!
//! const weth = Weth.at(weth_address);
//! // args/return are typed from the ABI: holder is [20]u8, bal is u256.
//! const bal = try weth.call(&provider, "balanceOf", .{holder});
//!
//! // Typed event decode: returns a struct { from, to, value }.
//! const transfer = try Weth.decodeEvent("Transfer", log);
//! ```
//!
//! ## Scope of this release
//! Typed reads via `call(provider, ...)`, state-changing writes via
//! `send(wallet, ...)` / `sendValue(...)` / `sendAndWait(...)`, and typed event
//! decoders. A write builds the *same* calldata as the matching read and hands
//! it to a `*Wallet`, which fills nonce/gas/chainId, signs, and broadcasts.
//! Calling `send` on a `view`/`pure` function is a compile error (use `call`).
//! See the type-mapping table and the "Limitations" section below for the exact
//! ABI surface that is supported.
//!
//! ## ABI -> Zig type mapping
//! | ABI type            | Zig type        | Notes                                     |
//! |---------------------|-----------------|-------------------------------------------|
//! | `uintN` (8..256)    | `uN`            | Smallest fitting unsigned (`uint8`->`u8`) |
//! | `intN` (8..256)     | `iN`            | Smallest fitting signed (`int128`->`i128`)|
//! | `uint` / `int`      | `u256` / `i256` | Bare alias for the 256-bit form           |
//! | `address`           | `[20]u8`        | Raw 20-byte address                       |
//! | `bool`              | `bool`          |                                           |
//! | `bytesN` (1..32)    | `[N]u8`         | Fixed-size byte array                      |
//! | `bytes`             | `[]const u8`    | Dynamic; decoded values are heap-allocated |
//! | `string`            | `[]const u8`    | Same encoding as `bytes`                   |
//!
//! Integers map to the exact Solidity width (matching zabi's
//! `AbiParameterToPrimative`): `decimals()` returns `u8`, a Uniswap pair's
//! `getReserves()` returns `u112` fields. The mapping is lossless and the
//! encode/decode bridge widens to the engine's `u256`/`i256` at the boundary.
//!
//! ## Limitations (honest scope cuts)
//! - **Tuples and arrays.** Functions whose inputs or outputs contain a `tuple`,
//!   fixed array, or dynamic array are parsed (and their canonical selector is
//!   still computed correctly), but no typed Zig method is generated for them --
//!   mapping arbitrary nested aggregates to ergonomic Zig types is a follow-up.
//!   The same restriction applies to non-indexed event parameters that are
//!   tuples/arrays. Indexed reference-type event params (which are hashed) are
//!   surfaced as their raw 32-byte topic.
//! - **Overloaded functions.** Solidity allows two functions with the same name
//!   but different parameters. Zig struct methods cannot share a name, so the
//!   *first* declaration of a given name wins and later overloads are skipped
//!   (a comptime note is not emitted to keep builds quiet; use the runtime
//!   `abi_json` parser if you need every overload).

const std = @import("std");
const keccak = @import("keccak.zig");
const abi_types = @import("abi_types.zig");
const abi_encode = @import("abi_encode.zig");
const abi_decode = @import("abi_decode.zig");
const uint256_mod = @import("uint256.zig");
const receipt_mod = @import("receipt.zig");
const provider_mod = @import("provider.zig");
const wallet_mod = @import("wallet.zig");

const AbiType = abi_types.AbiType;
const AbiValue = abi_encode.AbiValue;
const Log = receipt_mod.Log;

/// Errors surfaced by generated event decoders.
pub const EventError = error{
    /// The log's topic0 did not match this event's signature hash.
    TopicMismatch,
    /// The log has fewer topics than the event has indexed parameters.
    MissingIndexedTopic,
    /// `log.data` is shorter than the event's non-indexed parameters require.
    TruncatedData,
};

// ============================================================================
// Comptime parsed-ABI representation
//
// These mirror `abi_types` but live entirely in comptime-known memory (built by
// `parseAbi` from the embedded JSON string). We keep them local so the parser
// can accumulate with the `result = result ++ [_]T{...}` idiom without touching
// the runtime allocator-backed `abi_json` types.
// ============================================================================

/// A single function/event parameter parsed from the ABI.
const Param = struct {
    name: []const u8,
    /// The canonical ABI type string, e.g. "uint256", "address", "bytes32".
    type_str: []const u8,
    /// Only meaningful for event parameters.
    indexed: bool = false,
};

/// A parsed ABI function entry.
const Func = struct {
    name: []const u8,
    inputs: []const Param,
    outputs: []const Param,
    /// "view" / "pure" / "nonpayable" / "payable" (defaults to "nonpayable").
    state_mutability: []const u8,
};

/// A parsed ABI event entry.
const Evt = struct {
    name: []const u8,
    inputs: []const Param,
};

/// The full parsed ABI: just the entries we generate bindings for.
const ParsedAbi = struct {
    funcs: []const Func,
    events: []const Evt,
};

// ============================================================================
// Public entry point
// ============================================================================

/// Parse a Solidity JSON ABI at comptime and return a typed contract struct.
///
/// The returned type exposes a *comptime-name-dispatched* typed API. Function
/// names are passed as comptime strings, so the compiler resolves the matching
/// ABI entry at each call site and the argument-tuple and return types are fully
/// typed -- there is no runtime ABI parsing or string lookup in the hot path.
///
/// - `Self`, the contract handle holding an `address: [20]u8`.
/// - `pub fn at(address: [20]u8) Self` constructor.
/// - `pub fn call(self, provider, comptime name, args) !Ret` -- the typed read
///   call for the ABI function `name`. `args` is a tuple typed from the inputs
///   (e.g. `.{ holder }` of type `.{[20]u8}`); `Ret` is the mapped output type
///   (e.g. `u256` for `balanceOf`).
/// - `pub fn send(self, wallet, comptime name, args) ![32]u8` -- the typed
///   state-changing write: builds the same `selector ++ encode(args)` calldata
///   as `call` and broadcasts it via `wallet.sendTransaction`, returning the tx
///   hash. `sendValue(..., value)` is the payable variant; `sendAndWait(...,
///   max_attempts)` waits for the receipt. Naming a `view`/`pure` function is a
///   compile error (use `call`).
/// - `pub fn selectorOf(comptime name) [4]u8` -- the precomputed 4-byte selector.
/// - `pub fn ArgsOf(comptime name) type` / `pub fn ReturnOf(comptime name) type`
///   -- the typed argument-tuple and return types, for callers that want them.
/// - `pub fn decodeEvent(comptime name, log) !EventStruct` -- decode a `Log`
///   into the typed struct for event `name` (indexed params from topics,
///   non-indexed from data), validating `log.topics[0]`.
/// - `pub fn topicOf(comptime name) [32]u8` -- the precomputed event topic0.
/// - `pub fn EventOf(comptime name) type` -- the typed decoded-event struct.
///
/// Comptime name resolution fails the build (`@compileError`) for an unknown or
/// unsupported (tuple/array-typed) name, so typos and unsupported ABI shapes are
/// caught at compile time.
pub fn Bind(comptime abi_json: []const u8) type {
    // Comptime JSON parsing is branch-heavy; give it generous headroom.
    @setEvalBranchQuota(2_000_000);
    const parsed = comptime parseAbi(abi_json);

    return struct {
        const Self = @This();

        /// The deployed contract address this handle points at.
        address: [20]u8,

        /// The parsed ABI, exposed for introspection (comptime-known).
        pub const abi = parsed;

        /// Construct a contract handle bound to `address`.
        pub fn at(address: [20]u8) Self {
            return .{ .address = address };
        }

        /// The typed argument tuple for ABI function `name`,
        /// e.g. `ArgsOf("transfer")` == `struct { [20]u8, u256 }`.
        pub fn ArgsOf(comptime name: []const u8) type {
            return argsTuple(findFunc(parsed.funcs, name).inputs);
        }

        /// The typed return value for ABI function `name`,
        /// e.g. `ReturnOf("balanceOf")` == `u256`.
        pub fn ReturnOf(comptime name: []const u8) type {
            return returnType(findFunc(parsed.funcs, name).outputs);
        }

        /// The precomputed 4-byte selector for ABI function `name`.
        pub fn selectorOf(comptime name: []const u8) [4]u8 {
            const func = comptime findFunc(parsed.funcs, name);
            return comptime keccak.selector(signatureOf(func.name, func.inputs));
        }

        /// Typed read call for ABI function `name`. ABI-encodes
        /// `selector ++ encode(args)`, performs an `eth_call` against
        /// `self.address`, and decodes the response into `ReturnOf(name)`.
        /// Caller owns any heap memory inside the returned value (dynamic
        /// `bytes`/`string` outputs are dupe'd onto `provider.allocator`).
        pub fn call(
            self: Self,
            provider: *provider_mod.Provider,
            comptime name: []const u8,
            args: ArgsOf(name),
        ) anyerror!ReturnOf(name) {
            const func = comptime findFunc(parsed.funcs, name);
            const allocator = provider.allocator;

            // 1. Build calldata = selector ++ encoded args (caller frees).
            const calldata = try encodeCall(allocator, name, args);
            defer allocator.free(calldata);

            // 2. eth_call.
            const ret_data = try provider.call(self.address, calldata);
            defer allocator.free(ret_data);

            // 3. Decode the response into the mapped return type.
            return decodeReturn(ReturnOf(name), func.outputs, ret_data, allocator);
        }

        /// ABI-encode `selector ++ encode(args)` for ABI function `name` onto
        /// `allocator`, returning the heap calldata (the caller owns and frees
        /// it). Shared by `call` (read) and `send` (write) so both produce
        /// byte-identical calldata from the same typed `args`.
        fn encodeCall(
            allocator: std.mem.Allocator,
            comptime name: []const u8,
            args: ArgsOf(name),
        ) anyerror![]u8 {
            const func = comptime findFunc(parsed.funcs, name);
            const selector = comptime keccak.selector(signatureOf(func.name, func.inputs));

            // Lower the typed Zig args to dynamic AbiValues for encoding.
            var values: [func.inputs.len]AbiValue = undefined;
            inline for (func.inputs, 0..) |input, i| {
                values[i] = lowerArg(input.type_str, args[i]);
            }
            return abi_encode.encodeFunctionCall(allocator, selector, &values);
        }

        /// Typed state-changing write for ABI function `name`. Builds the same
        /// `selector ++ encode(args)` calldata as `call` and submits it via
        /// `wallet.sendTransaction(.{ .to = self.address, .data = calldata })`,
        /// returning the broadcast transaction hash. The wallet fills
        /// nonce/gas/chainId, signs, and broadcasts.
        ///
        /// Naming a `view`/`pure` function is a compile error: those make no
        /// state change, so a write to one is almost always a mistake -- use
        /// `call` instead. For payable functions that take ETH, use `sendValue`.
        pub fn send(
            self: Self,
            wallet: *wallet_mod.Wallet,
            comptime name: []const u8,
            args: ArgsOf(name),
        ) anyerror![32]u8 {
            return self.sendValue(wallet, name, args, 0);
        }

        /// Like `send`, but attaches `value` wei to the call for `payable`
        /// functions (e.g. WETH `deposit()`). For non-payable functions pass
        /// `0` (or just use `send`).
        pub fn sendValue(
            self: Self,
            wallet: *wallet_mod.Wallet,
            comptime name: []const u8,
            args: ArgsOf(name),
            value: u256,
        ) anyerror![32]u8 {
            comptime assertWritable(parsed.funcs, name);
            const allocator = wallet.allocator;

            const calldata = try encodeCall(allocator, name, args);
            defer allocator.free(calldata);

            return wallet.sendTransaction(.{
                .to = self.address,
                .value = value,
                .data = calldata,
            });
        }

        /// Convenience over `send` that waits for the transaction receipt,
        /// polling up to `max_attempts` times. Returns `error.ReceiptNotFound`
        /// if the receipt does not land in time.
        pub fn sendAndWait(
            self: Self,
            wallet: *wallet_mod.Wallet,
            comptime name: []const u8,
            args: ArgsOf(name),
            max_attempts: u32,
        ) anyerror!receipt_mod.TransactionReceipt {
            comptime assertWritable(parsed.funcs, name);
            const allocator = wallet.allocator;

            const calldata = try encodeCall(allocator, name, args);
            defer allocator.free(calldata);

            return wallet.sendTransactionAndWait(.{
                .to = self.address,
                .data = calldata,
            }, max_attempts);
        }

        /// The typed decoded-event struct for event `name`.
        pub fn EventOf(comptime name: []const u8) type {
            return eventStruct(findEvent(parsed.events, name));
        }

        /// The precomputed topic0 (signature hash) for event `name`.
        pub fn topicOf(comptime name: []const u8) [32]u8 {
            const evt = comptime findEvent(parsed.events, name);
            return comptime keccak.hash(signatureOf(evt.name, evt.inputs));
        }

        /// Decode `log` into the typed struct for event `name`. Indexed params
        /// are read from `log.topics[1..]`, non-indexed params from `log.data`.
        /// Returns `error.TopicMismatch` when `log.topics[0]` is not the event's
        /// signature hash.
        pub fn decodeEvent(comptime name: []const u8, log: Log) anyerror!EventOf(name) {
            const evt = comptime findEvent(parsed.events, name);
            const topic = comptime keccak.hash(signatureOf(evt.name, evt.inputs));
            const Decoded = EventOf(name);

            if (log.topics.len == 0 or !std.mem.eql(u8, &log.topics[0], &topic)) {
                return EventError.TopicMismatch;
            }

            var result: Decoded = undefined;
            var topic_idx: usize = 1; // topics[0] is the signature hash
            var data_word: usize = 0;
            inline for (evt.inputs, 0..) |input, i| {
                if (input.indexed) {
                    if (topic_idx >= log.topics.len) return EventError.MissingIndexedTopic;
                    const topic_word = log.topics[topic_idx];
                    @field(result, eventFieldName(input.name, i)) =
                        if (comptime !isStaticScalarType(input.type_str))
                            // Reference type: the topic is keccak256(value), so
                            // surface the raw 32-byte hash (its mapped field is [32]u8).
                            topic_word
                        else
                            wordToValue(mapType(input.type_str), input.type_str, topic_word);
                    topic_idx += 1;
                } else {
                    const FieldT = mapType(input.type_str);
                    // Reject truncated data rather than fabricating a
                    // zero-padded word from an under-length RPC payload.
                    if ((data_word + 1) * 32 > log.data.len) return EventError.TruncatedData;
                    const word = readWord(log.data, data_word);
                    @field(result, eventFieldName(input.name, i)) =
                        wordToValue(FieldT, input.type_str, word);
                    data_word += 1;
                }
            }
            return result;
        }
    };
}

// ============================================================================
// ABI lookup (comptime)
// ============================================================================

/// Find the function named `name`, failing the build if it is missing or maps
/// to an unsupported (tuple/array-typed) shape. The *first* declaration of a
/// given name wins (Solidity overloads beyond the first are not addressable by
/// name here -- see the module-level "Limitations").
fn findFunc(comptime funcs: []const Func, comptime name: []const u8) Func {
    for (funcs) |func| {
        if (std.mem.eql(u8, func.name, name)) {
            if (!isGeneratable(func)) {
                @compileError("abigen: function '" ++ name ++
                    "' has tuple/array params or returns, which are not supported yet");
            }
            return func;
        }
    }
    @compileError("abigen: no function named '" ++ name ++ "' in ABI");
}

/// Fail the build when the function `name` in `funcs` is `view`/`pure`. Sending
/// a transaction to a read-only function makes no state change and costs gas for
/// nothing, so it is almost always a user error -- direct them to `call`. Also
/// validates that `name` exists and is generatable (via `findFunc`).
fn assertWritable(comptime funcs: []const Func, comptime name: []const u8) void {
    const func = findFunc(funcs, name);
    if (std.mem.eql(u8, func.state_mutability, "view") or
        std.mem.eql(u8, func.state_mutability, "pure"))
    {
        @compileError("abigen: '" ++ name ++ "' is a " ++ func.state_mutability ++
            " function (read-only); use `call` instead of `send`");
    }
}

/// Find the event named `name`, failing the build if it is missing or has a
/// tuple/array/dynamic parameter that cannot be decoded yet.
fn findEvent(comptime events: []const Evt, comptime name: []const u8) Evt {
    for (events) |evt| {
        if (std.mem.eql(u8, evt.name, name)) {
            if (!isEventGeneratable(evt)) {
                @compileError("abigen: event '" ++ name ++
                    "' has a non-indexed tuple/array/dynamic param, which is not supported yet");
            }
            return evt;
        }
    }
    @compileError("abigen: no event named '" ++ name ++ "' in ABI");
}

/// The Zig argument tuple type for a function's inputs, e.g. `struct { [20]u8, u256 }`.
fn argsTuple(comptime inputs: []const Param) type {
    comptime var types: [inputs.len]type = undefined;
    inline for (inputs, 0..) |input, i| {
        types[i] = mapType(input.type_str);
    }
    return @Tuple(&types);
}

/// The Zig return type for a function's outputs:
/// - no outputs  -> `void`
/// - one output  -> that output's mapped type
/// - many outputs-> an anonymous struct `{ <name0>: T0, <name1>: T1, ... }`
fn returnType(comptime outputs: []const Param) type {
    if (outputs.len == 0) return void;
    if (outputs.len == 1) return mapType(outputs[0].type_str);

    comptime var names: [outputs.len][:0]const u8 = undefined;
    comptime var types: [outputs.len]type = undefined;
    inline for (outputs, 0..) |out, i| {
        names[i] = outputFieldName(out.name, i);
        types[i] = mapType(out.type_str);
    }
    return namedStruct(&names, &types);
}

/// The per-field attribute struct accepted by `@Struct`. Its path moved between
/// Zig versions (`StructField.Attributes` in 0.16, `Struct.FieldAttributes` in
/// 0.17-dev), so resolve it portably here.
const FieldAttr = if (@hasDecl(std.builtin.Type, "StructField"))
    std.builtin.Type.StructField.Attributes // 0.16
else
    std.builtin.Type.Struct.FieldAttributes; // 0.17-dev

/// Build a plain (non-tuple) struct type with the given field `names` and
/// `types`, with default (no) field attributes. Centralizes the `@Struct` call
/// so the version difference in the attribute type stays in one place.
///
/// `@Struct` wants `types`/attrs as pointers to fixed-size arrays, so we
/// materialize the slices into arrays first.
fn namedStruct(comptime names: []const [:0]const u8, comptime types: []const type) type {
    const n = names.len;
    var name_arr: [n][:0]const u8 = undefined;
    var type_arr: [n]type = undefined;
    var attrs: [n]FieldAttr = undefined;
    inline for (0..n) |i| {
        name_arr[i] = names[i];
        type_arr[i] = types[i];
        attrs[i] = .{};
    }
    return @Struct(.auto, null, &name_arr, &type_arr, &attrs);
}

/// Decode `ret_data` (an `eth_call` response) into `Ret`.
fn decodeReturn(comptime Ret: type, comptime outputs: []const Param, ret_data: []const u8, allocator: std.mem.Allocator) anyerror!Ret {
    if (Ret == void) return {};

    comptime var out_types: [outputs.len]AbiType = undefined;
    inline for (outputs, 0..) |out, i| {
        out_types[i] = comptime abiTypeOf(out.type_str);
    }

    const values = try abi_decode.decodeValues(ret_data, &out_types, allocator);
    defer abi_decode.freeValues(values, allocator);

    if (outputs.len == 1) {
        return liftValue(mapType(outputs[0].type_str), outputs[0].type_str, values[0], allocator);
    }

    var result: Ret = undefined;
    inline for (outputs, 0..) |out, i| {
        @field(result, outputFieldName(out.name, i)) =
            try liftValue(mapType(out.type_str), out.type_str, values[i], allocator);
    }
    return result;
}

// ============================================================================
// Event decoding helpers
// ============================================================================

/// The typed Zig struct for a decoded event: one field per input parameter.
fn eventStruct(comptime evt: Evt) type {
    comptime var names: [evt.inputs.len][:0]const u8 = undefined;
    comptime var types: [evt.inputs.len]type = undefined;
    inline for (evt.inputs, 0..) |input, i| {
        names[i] = eventFieldName(input.name, i);
        types[i] = eventFieldType(input);
    }
    return namedStruct(&names, &types);
}

/// The Zig type of a decoded event field. An indexed reference type
/// (string/bytes/array/tuple) is stored in the topic as `keccak256(value)`, not
/// the value itself, so it is surfaced as the raw 32-byte topic. All other
/// params map normally.
fn eventFieldType(comptime input: Param) type {
    if (input.indexed and !isStaticScalarType(input.type_str)) return [32]u8;
    return mapType(input.type_str);
}

/// Read the i-th 32-byte word from `data`. Callers must bounds-check `data`
/// first (see `decodeEvent`, which rejects truncated data); a short tail is
/// zero-padded here only as a defensive fallback.
fn readWord(data: []const u8, i: usize) [32]u8 {
    var word: [32]u8 = @splat(0);
    const start = i * 32;
    if (start >= data.len) return word;
    const n = @min(32, data.len - start);
    @memcpy(word[0..n], data[start..][0..n]);
    return word;
}

// ============================================================================
// ABI type <-> Zig type mapping
// ============================================================================

/// Map an ABI type string to its Zig type. Only the scalar types listed in the
/// module-level table are reachable here; aggregate types are filtered out
/// before generation by `isScalarType`.
///
/// Integers map to the *smallest fitting* Zig integer (`uint112` -> `u112`,
/// `uint8` -> `u8`), matching zabi's `AbiParameterToPrimative`. This is more
/// precise than always widening to u256 -- `decimals()` is `u8`, not `u256` --
/// while remaining lossless.
fn mapType(comptime type_str: []const u8) type {
    if (std.mem.eql(u8, type_str, "address")) return [20]u8;
    if (std.mem.eql(u8, type_str, "bool")) return bool;
    if (std.mem.eql(u8, type_str, "string")) return []const u8;
    if (std.mem.eql(u8, type_str, "bytes")) return []const u8;
    if (std.mem.startsWith(u8, type_str, "uint")) return @Int(.unsigned, intBitsOf(type_str[4..]));
    if (std.mem.startsWith(u8, type_str, "int")) return @Int(.signed, intBitsOf(type_str[3..]));
    if (std.mem.startsWith(u8, type_str, "bytes")) {
        const n = fixedBytesLen(type_str);
        return [n]u8;
    }
    @compileError("abigen: unmappable ABI type '" ++ type_str ++ "'");
}

/// Parse the bit width from the digits after `uint`/`int` (empty -> 256).
/// Validates the Solidity constraint: a multiple of 8 in 8..256.
fn intBitsOf(comptime digits: []const u8) u16 {
    if (digits.len == 0) return 256;
    const bits = std.fmt.parseInt(u16, digits, 10) catch
        @compileError("abigen: invalid integer width '" ++ digits ++ "'");
    if (bits == 0 or bits > 256 or bits % 8 != 0)
        @compileError("abigen: integer width must be a multiple of 8 in 8..256");
    return bits;
}

/// Map an ABI type string to its `abi_types.AbiType` enum (for the existing
/// encode/decode machinery). Mirrors `abi_json.parseType` for scalar types.
fn abiTypeOf(comptime type_str: []const u8) AbiType {
    if (std.mem.eql(u8, type_str, "address")) return .address;
    if (std.mem.eql(u8, type_str, "bool")) return .bool;
    if (std.mem.eql(u8, type_str, "string")) return .string;
    if (std.mem.eql(u8, type_str, "bytes")) return .bytes;
    if (std.mem.startsWith(u8, type_str, "uint")) return .uint256;
    if (std.mem.startsWith(u8, type_str, "int")) return .int256;
    if (std.mem.startsWith(u8, type_str, "bytes")) {
        const n = fixedBytesLen(type_str);
        return @field(AbiType, std.fmt.comptimePrint("bytes{d}", .{n}));
    }
    @compileError("abigen: unmappable ABI type '" ++ type_str ++ "'");
}

/// Number of bytes in a `bytesN` type string (e.g. "bytes32" -> 32).
fn fixedBytesLen(comptime type_str: []const u8) usize {
    return std.fmt.parseInt(usize, type_str[5..], 10) catch
        @compileError("abigen: invalid bytesN type '" ++ type_str ++ "'");
}

/// Lower a typed Zig argument into a dynamic `AbiValue` for encoding.
fn lowerArg(comptime type_str: []const u8, value: mapType(type_str)) AbiValue {
    if (comptime std.mem.eql(u8, type_str, "address")) return .{ .address = value };
    if (comptime std.mem.eql(u8, type_str, "bool")) return .{ .boolean = value };
    if (comptime std.mem.eql(u8, type_str, "string")) return .{ .string = value };
    if (comptime std.mem.eql(u8, type_str, "bytes")) return .{ .bytes = value };
    if (comptime std.mem.startsWith(u8, type_str, "uint")) return .{ .uint256 = @intCast(value) };
    if (comptime std.mem.startsWith(u8, type_str, "int")) return .{ .int256 = @intCast(value) };
    if (comptime std.mem.startsWith(u8, type_str, "bytes")) {
        const n = comptime fixedBytesLen(type_str);
        var fb = AbiValue.FixedBytes{ .len = n };
        @memcpy(fb.data[0..n], &value);
        return .{ .fixed_bytes = fb };
    }
    @compileError("abigen: cannot lower ABI type '" ++ type_str ++ "'");
}

/// Lift a decoded `AbiValue` into the typed Zig return value. For dynamic
/// `bytes`/`string` the underlying buffer is dupe'd so the caller owns it after
/// the decode arena is freed.
fn liftValue(comptime T: type, comptime type_str: []const u8, value: AbiValue, allocator: std.mem.Allocator) anyerror!T {
    if (comptime std.mem.eql(u8, type_str, "address")) return value.address;
    if (comptime std.mem.eql(u8, type_str, "bool")) return value.boolean;
    if (comptime std.mem.eql(u8, type_str, "string")) return allocator.dupe(u8, value.string);
    if (comptime std.mem.eql(u8, type_str, "bytes")) return allocator.dupe(u8, value.bytes);
    if (comptime std.mem.startsWith(u8, type_str, "uint")) return @intCast(value.uint256);
    if (comptime std.mem.startsWith(u8, type_str, "int")) return @intCast(value.int256);
    if (comptime std.mem.startsWith(u8, type_str, "bytes")) {
        const n = comptime fixedBytesLen(type_str);
        var out: [n]u8 = undefined;
        @memcpy(&out, value.fixed_bytes.data[0..n]);
        return out;
    }
    @compileError("abigen: cannot lift ABI type '" ++ type_str ++ "'");
}

/// Convert a raw 32-byte ABI word into a typed scalar value, used for event
/// decoding where words come from the topics or the data section. Only static
/// scalar types reach here (`isEventGeneratable` excludes dynamic and aggregate
/// params), so an `address` word is right-aligned and a `bytesN`/integer word
/// is read directly.
fn wordToValue(comptime T: type, comptime type_str: []const u8, word: [32]u8) T {
    if (comptime std.mem.eql(u8, type_str, "address")) {
        var addr: [20]u8 = undefined;
        @memcpy(&addr, word[12..32]);
        return addr;
    }
    if (comptime std.mem.eql(u8, type_str, "bool")) return word[31] != 0;
    if (comptime std.mem.startsWith(u8, type_str, "uint")) return @intCast(uint256_mod.fromBigEndianBytes(word));
    if (comptime std.mem.startsWith(u8, type_str, "int")) {
        const signed: i256 = @bitCast(uint256_mod.fromBigEndianBytes(word));
        return @intCast(signed);
    }
    if (comptime std.mem.startsWith(u8, type_str, "bytes")) {
        const n = comptime fixedBytesLen(type_str);
        var out: [n]u8 = undefined;
        @memcpy(&out, word[0..n]);
        return out;
    }
    @compileError("abigen: cannot decode word for ABI type '" ++ type_str ++ "'");
}

// ============================================================================
// Generation predicates
// ============================================================================

/// A scalar type is one we can map to a single Zig value and ABI word(s)
/// without aggregate handling: integers, address, bool, bytesN, bytes, string.
fn isScalarType(comptime type_str: []const u8) bool {
    if (std.mem.endsWith(u8, type_str, "]")) return false; // arrays
    if (std.mem.eql(u8, type_str, "tuple")) return false; // tuples
    if (std.mem.eql(u8, type_str, "address")) return true;
    if (std.mem.eql(u8, type_str, "bool")) return true;
    if (std.mem.eql(u8, type_str, "string")) return true;
    if (std.mem.eql(u8, type_str, "bytes")) return true;
    if (std.mem.startsWith(u8, type_str, "uint")) return true;
    if (std.mem.startsWith(u8, type_str, "int")) return true;
    if (std.mem.startsWith(u8, type_str, "bytes")) return true;
    return false;
}

/// A non-indexed event param must be a *static* scalar (so it occupies exactly
/// one 32-byte word in the data section). Dynamic non-indexed params would
/// require offset-following decode; excluded for now.
fn isStaticScalarType(comptime type_str: []const u8) bool {
    if (!isScalarType(type_str)) return false;
    if (std.mem.eql(u8, type_str, "bytes")) return false;
    if (std.mem.eql(u8, type_str, "string")) return false;
    return true;
}

/// True if every input and output of `func` maps to a scalar Zig type.
fn isGeneratable(comptime func: Func) bool {
    for (func.inputs) |p| {
        if (!isScalarType(p.type_str)) return false;
    }
    for (func.outputs) |p| {
        if (!isScalarType(p.type_str)) return false;
    }
    return true;
}

/// True if an event can be decoded. Non-indexed params must be static scalars
/// (one data word). Indexed params may be any type: a static scalar decodes
/// from its topic, and an indexed reference type (string/bytes/array/tuple) is
/// surfaced as its raw 32-byte topic (the `keccak256(value)` Ethereum stores).
/// Only non-indexed dynamic params (which need offset-following decode) are
/// excluded.
fn isEventGeneratable(comptime evt: Evt) bool {
    for (evt.inputs) |p| {
        if (!p.indexed and !isStaticScalarType(p.type_str)) return false;
    }
    return true;
}

// ============================================================================
// Signature + name helpers
// ============================================================================

/// Build the canonical signature `name(type1,type2,...)` used for selectors and
/// event topics. Matches the form `keccak.selector` / `topicFromSignature`
/// expect.
fn signatureOf(comptime name: []const u8, comptime params: []const Param) []const u8 {
    comptime var sig: []const u8 = name ++ "(";
    inline for (params, 0..) |p, i| {
        if (i != 0) sig = sig ++ ",";
        sig = sig ++ p.type_str;
    }
    return sig ++ ")";
}

/// `<name>` as a sentinel-terminated string usable as a generated struct field name.
fn toSentinel(comptime name: []const u8) [:0]const u8 {
    return name ++ "";
}

/// Field name for an output param: its ABI name, or `outN` if anonymous.
fn outputFieldName(comptime name: []const u8, comptime i: usize) [:0]const u8 {
    if (name.len == 0) return std.fmt.comptimePrint("out{d}", .{i});
    return toSentinel(name);
}

/// Field name for an event param: its ABI name, or `argN` if anonymous.
fn eventFieldName(comptime name: []const u8, comptime i: usize) [:0]const u8 {
    if (name.len == 0) return std.fmt.comptimePrint("arg{d}", .{i});
    return toSentinel(name);
}

// ============================================================================
// Comptime JSON ABI parser
//
// A purpose-built tokenizer over the embedded ABI string. We avoid `std.json`
// because its parser needs a runtime allocator and does not run at comptime in
// 0.16. The parser only understands the subset of JSON a Solidity ABI uses:
// an array of objects whose values are strings, booleans, or nested arrays of
// objects (for `inputs`/`outputs`/`components`). It accumulates results with
// the `result = result ++ [_]T{...}` idiom into comptime-known slices.
// ============================================================================

/// Parse the ABI JSON into the function/event entries we bind.
fn parseAbi(comptime json: []const u8) ParsedAbi {
    @setEvalBranchQuota(2_000_000);
    comptime var funcs: []const Func = &.{};
    comptime var events: []const Evt = &.{};

    // Walk the top-level array of entries.
    comptime var i: usize = 0;
    i = skipWs(json, i);
    if (i >= json.len or json[i] != '[') @compileError("abigen: ABI must be a JSON array");
    i += 1;

    while (true) {
        i = skipWs(json, i);
        if (i >= json.len) @compileError("abigen: unterminated ABI array");
        if (json[i] == ']') break;
        if (json[i] == ',') {
            i += 1;
            continue;
        }
        // Parse one `{ ... }` entry.
        const entry = parseEntry(json, i);
        i = entry.end;

        if (std.mem.eql(u8, entry.kind, "function")) {
            funcs = funcs ++ [_]Func{.{
                .name = entry.name,
                .inputs = entry.inputs,
                .outputs = entry.outputs,
                .state_mutability = entry.state_mutability,
            }};
        } else if (std.mem.eql(u8, entry.kind, "event")) {
            events = events ++ [_]Evt{.{
                .name = entry.name,
                .inputs = entry.inputs,
            }};
        }
        // constructor / fallback / receive / error: ignored for bindings.
    }

    return .{ .funcs = funcs, .events = events };
}

/// One parsed top-level ABI entry plus the index just past its closing brace.
const Entry = struct {
    kind: []const u8, // "function" | "event" | "error" | "constructor" | ...
    name: []const u8,
    inputs: []const Param,
    outputs: []const Param,
    state_mutability: []const u8,
    end: usize,
};

/// Parse a single `{ ... }` object starting at `start` (which must be `{`).
fn parseEntry(comptime json: []const u8, comptime start: usize) Entry {
    comptime var i = skipWs(json, start);
    if (json[i] != '{') @compileError("abigen: expected '{' for ABI entry");
    i += 1;

    comptime var kind: []const u8 = "";
    comptime var name: []const u8 = "";
    comptime var inputs: []const Param = &.{};
    comptime var outputs: []const Param = &.{};
    comptime var state_mutability: []const u8 = "nonpayable";

    while (true) {
        i = skipWs(json, i);
        if (json[i] == '}') {
            i += 1;
            break;
        }
        if (json[i] == ',') {
            i += 1;
            continue;
        }
        // key
        const key = parseString(json, i);
        i = skipWs(json, key.end);
        if (json[i] != ':') @compileError("abigen: expected ':' after key");
        i = skipWs(json, i + 1);

        if (std.mem.eql(u8, key.value, "type")) {
            const v = parseString(json, i);
            kind = v.value;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "name")) {
            const v = parseString(json, i);
            name = v.value;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "stateMutability")) {
            const v = parseString(json, i);
            state_mutability = v.value;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "inputs")) {
            const v = parseParams(json, i);
            inputs = v.params;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "outputs")) {
            const v = parseParams(json, i);
            outputs = v.params;
            i = v.end;
        } else {
            // Unknown key (e.g. "anonymous", "constant", "payable"): skip value.
            i = skipValue(json, i);
        }
    }

    return .{
        .kind = kind,
        .name = name,
        .inputs = inputs,
        .outputs = outputs,
        .state_mutability = state_mutability,
        .end = i,
    };
}

/// A parsed `inputs`/`outputs` array plus the index past its `]`.
const Params = struct { params: []const Param, end: usize };

/// Parse a JSON array of parameter objects.
fn parseParams(comptime json: []const u8, comptime start: usize) Params {
    comptime var i = skipWs(json, start);
    if (json[i] != '[') @compileError("abigen: expected '[' for params");
    i += 1;
    comptime var params: []const Param = &.{};

    while (true) {
        i = skipWs(json, i);
        if (json[i] == ']') {
            i += 1;
            break;
        }
        if (json[i] == ',') {
            i += 1;
            continue;
        }
        const p = parseParam(json, i);
        params = params ++ [_]Param{p.param};
        i = p.end;
    }

    return .{ .params = params, .end = i };
}

/// A single parsed parameter plus the index past its `}`.
const ParsedParam = struct { param: Param, end: usize };

/// Parse one parameter object `{ "name": ..., "type": ..., "indexed": ... }`.
fn parseParam(comptime json: []const u8, comptime start: usize) ParsedParam {
    comptime var i = skipWs(json, start);
    if (json[i] != '{') @compileError("abigen: expected '{' for param");
    i += 1;

    comptime var name: []const u8 = "";
    comptime var type_str: []const u8 = "";
    comptime var indexed = false;

    while (true) {
        i = skipWs(json, i);
        if (json[i] == '}') {
            i += 1;
            break;
        }
        if (json[i] == ',') {
            i += 1;
            continue;
        }
        const key = parseString(json, i);
        i = skipWs(json, key.end);
        if (json[i] != ':') @compileError("abigen: expected ':' in param");
        i = skipWs(json, i + 1);

        if (std.mem.eql(u8, key.value, "name")) {
            const v = parseString(json, i);
            name = v.value;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "type")) {
            const v = parseString(json, i);
            type_str = v.value;
            i = v.end;
        } else if (std.mem.eql(u8, key.value, "indexed")) {
            const v = parseBool(json, i);
            indexed = v.value;
            i = v.end;
        } else {
            // "internalType", "components", etc.: skip.
            i = skipValue(json, i);
        }
    }

    return .{ .param = .{ .name = name, .type_str = type_str, .indexed = indexed }, .end = i };
}

// ----------------------------------------------------------------------------
// Low-level token scanners
// ----------------------------------------------------------------------------

/// A parsed string literal value plus the index past its closing quote.
const StringTok = struct { value: []const u8, end: usize };

/// Skip ASCII whitespace starting at `i`.
fn skipWs(comptime json: []const u8, comptime i: usize) usize {
    comptime var j = i;
    while (j < json.len and (json[j] == ' ' or json[j] == '\t' or json[j] == '\n' or json[j] == '\r')) : (j += 1) {}
    return j;
}

/// Parse a `"..."` JSON string (no escape handling -- ABI strings are plain
/// identifiers and type names, which never contain quotes or backslashes).
fn parseString(comptime json: []const u8, comptime start: usize) StringTok {
    comptime var i = skipWs(json, start);
    if (json[i] != '"') @compileError("abigen: expected string");
    i += 1;
    const begin = i;
    while (i < json.len and json[i] != '"') : (i += 1) {}
    if (i >= json.len) @compileError("abigen: unterminated string");
    return .{ .value = json[begin..i], .end = i + 1 };
}

/// A parsed boolean literal plus the index past it.
const BoolTok = struct { value: bool, end: usize };

/// Parse a `true`/`false` JSON literal.
fn parseBool(comptime json: []const u8, comptime start: usize) BoolTok {
    const i = skipWs(json, start);
    if (std.mem.startsWith(u8, json[i..], "true")) return .{ .value = true, .end = i + 4 };
    if (std.mem.startsWith(u8, json[i..], "false")) return .{ .value = false, .end = i + 5 };
    @compileError("abigen: expected boolean");
}

/// Skip an arbitrary JSON value (string, bool, null, number, object, array),
/// returning the index just past it. Used to ignore keys we do not consume.
fn skipValue(comptime json: []const u8, comptime start: usize) usize {
    const i = skipWs(json, start);
    switch (json[i]) {
        '"' => return parseString(json, i).end,
        '{' => return skipBalanced(json, i, '{', '}'),
        '[' => return skipBalanced(json, i, '[', ']'),
        't' => return i + 4, // true
        'f' => return i + 5, // false
        'n' => return i + 4, // null
        else => {
            // number
            comptime var j = i;
            while (j < json.len and json[j] != ',' and json[j] != '}' and json[j] != ']') : (j += 1) {}
            return j;
        },
    }
}

/// Skip a balanced `open`/`close` region (respecting nested strings) and return
/// the index past the matching close.
fn skipBalanced(comptime json: []const u8, comptime start: usize, comptime open: u8, comptime close: u8) usize {
    comptime var i = start + 1;
    comptime var depth: usize = 1;
    while (i < json.len and depth > 0) : (i += 1) {
        const c = json[i];
        if (c == '"') {
            i = parseString(json, i).end - 1; // -1 because loop will += 1
        } else if (c == open) {
            depth += 1;
        } else if (c == close) {
            depth -= 1;
        }
    }
    return i;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const hex_mod = @import("hex.zig");

/// A minimal ERC-20 ABI used across the tests (no file dependency).
const erc20_abi =
    \\[
    \\  {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]},
    \\  {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint8"}]},
    \\  {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint256"}]},
    \\  {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
    \\  {"type":"function","name":"allowance","stateMutability":"view","inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
    \\  {"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
    \\  {"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]},
    \\  {"type":"event","name":"Approval","inputs":[{"name":"owner","type":"address","indexed":true},{"name":"spender","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}
    \\]
;

test "Bind compiles and precomputes known selectors" {
    const Erc20 = Bind(erc20_abi);

    try testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &Erc20.selectorOf("balanceOf"));
    try testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &Erc20.selectorOf("transfer"));
    try testing.expectEqualSlices(u8, &.{ 0x18, 0x16, 0x0d, 0xdd }, &Erc20.selectorOf("totalSupply"));
    try testing.expectEqualSlices(u8, &.{ 0xdd, 0x62, 0xed, 0x3e }, &Erc20.selectorOf("allowance"));
}

test "Bind precomputes known event topic0" {
    const Erc20 = Bind(erc20_abi);
    // keccak256("Transfer(address,address,uint256)")
    const expected = try hex_mod.hexToBytesFixed(32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    try testing.expectEqualSlices(u8, &expected, &Erc20.topicOf("Transfer"));
}

test "at() constructs a handle holding the address" {
    const Erc20 = Bind(erc20_abi);
    var addr: [20]u8 = @splat(0);
    addr[19] = 0xAB;
    const c = Erc20.at(addr);
    try testing.expectEqualSlices(u8, &addr, &c.address);
}

test "type mapping: balanceOf args are .{[20]u8}, returns u256" {
    const Erc20 = Bind(erc20_abi);
    const Args = Erc20.ArgsOf("balanceOf");
    try testing.expectEqual(@as(usize, 1), std.meta.fieldNames(Args).len);
    try testing.expectEqual([20]u8, @FieldType(Args, "0"));
    try testing.expectEqual(u256, Erc20.ReturnOf("balanceOf"));
}

test "type mapping: transfer args are .{[20]u8, u256}" {
    const Erc20 = Bind(erc20_abi);
    const Args = Erc20.ArgsOf("transfer");
    try testing.expectEqual(@as(usize, 2), std.meta.fieldNames(Args).len);
    try testing.expectEqual([20]u8, @FieldType(Args, "0"));
    try testing.expectEqual(u256, @FieldType(Args, "1"));
    try testing.expectEqual(bool, Erc20.ReturnOf("transfer"));
}

test "type mapping: name() returns []const u8, decimals() returns u8" {
    const Erc20 = Bind(erc20_abi);
    try testing.expectEqual([]const u8, Erc20.ReturnOf("name"));
    // uint8 maps to the smallest fitting integer, u8 (not widened to u256).
    try testing.expectEqual(u8, Erc20.ReturnOf("decimals"));
}

test "calldata encoding for balanceOf matches selector ++ padded address" {
    // Exercise the encode path directly (no network): selector ++ encode(addr).
    const Erc20 = Bind(erc20_abi);
    const allocator = testing.allocator;

    var addr: [20]u8 = @splat(0);
    addr[0] = 0xd8;
    addr[1] = 0xdA;
    addr[19] = 0x45;

    const values = [_]AbiValue{.{ .address = addr }};
    const calldata = try abi_encode.encodeFunctionCall(allocator, Erc20.selectorOf("balanceOf"), &values);
    defer allocator.free(calldata);

    // Hand-built expected: 4-byte selector + 12 zero bytes + 20-byte address.
    try testing.expectEqual(@as(usize, 36), calldata.len);
    try testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, calldata[0..4]);
    for (calldata[4..16]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expectEqualSlices(u8, &addr, calldata[16..36]);
}

test "decodeEvent(Transfer) returns typed indexed + data fields" {
    const Erc20 = Bind(erc20_abi);

    var from: [20]u8 = @splat(0);
    from[19] = 0x01;
    var to: [20]u8 = @splat(0);
    to[19] = 0x02;

    // topic1/topic2 are left-padded addresses; data is the uint256 value.
    var from_topic: [32]u8 = @splat(0);
    @memcpy(from_topic[12..32], &from);
    var to_topic: [32]u8 = @splat(0);
    @memcpy(to_topic[12..32], &to);

    const value: u256 = 1_000_000;
    const data = uint256_mod.toBigEndianBytes(value);

    const topics = [_][32]u8{ Erc20.topicOf("Transfer"), from_topic, to_topic };
    const log = Log{
        .address = @splat(0xAA),
        .topics = &topics,
        .data = &data,
        .block_number = 100,
        .transaction_hash = null,
        .transaction_index = null,
        .log_index = null,
        .block_hash = null,
        .removed = false,
    };

    const decoded = try Erc20.decodeEvent("Transfer", log);
    try testing.expectEqualSlices(u8, &from, &decoded.from);
    try testing.expectEqualSlices(u8, &to, &decoded.to);
    try testing.expectEqual(value, decoded.value);
}

test "decodeEvent rejects a mismatched topic0" {
    const Erc20 = Bind(erc20_abi);
    const topics = [_][32]u8{@as([32]u8, @splat(0xFF))};
    const log = Log{
        .address = @splat(0),
        .topics = &topics,
        .data = &.{},
        .block_number = null,
        .transaction_hash = null,
        .transaction_index = null,
        .log_index = null,
        .block_hash = null,
        .removed = false,
    };
    try testing.expectError(EventError.TopicMismatch, Erc20.decodeEvent("Transfer", log));
}

test "EventOf struct has the typed fields" {
    const Erc20 = Bind(erc20_abi);
    const T = Erc20.EventOf("Transfer");
    const names = std.meta.fieldNames(T);
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("from", names[0]);
    try testing.expectEqual([20]u8, @FieldType(T, "from"));
    try testing.expectEqualStrings("value", names[2]);
    try testing.expectEqual(u256, @FieldType(T, "value"));
}

test "multi-output return type is a named struct" {
    // A small ABI with a two-output view function to exercise returnType().
    const abi =
        \\[{"type":"function","name":"slot0","stateMutability":"view","inputs":[],
        \\  "outputs":[{"name":"price","type":"uint256"},{"name":"tick","type":"int256"}]}]
    ;
    const C = Bind(abi);
    const Ret = C.ReturnOf("slot0");
    const names = std.meta.fieldNames(Ret);
    try testing.expectEqual(@as(usize, 2), names.len);
    try testing.expectEqualStrings("price", names[0]);
    try testing.expectEqual(u256, @FieldType(Ret, "price"));
    try testing.expectEqualStrings("tick", names[1]);
    try testing.expectEqual(i256, @FieldType(Ret, "tick"));
}

test "scalar functions alongside an array-param function both parse" {
    // `getReserves()` returns scalars (callable); `swap(uint256[])` has an
    // array input. Both must parse without breaking the build; only the
    // scalar one is addressable (the array one would @compileError if named).
    const abi =
        \\[
        \\  {"type":"function","name":"getReserves","stateMutability":"view","inputs":[],
        \\    "outputs":[{"name":"r0","type":"uint112"},{"name":"r1","type":"uint112"}]},
        \\  {"type":"function","name":"swap","stateMutability":"nonpayable",
        \\    "inputs":[{"name":"amounts","type":"uint256[]"}],"outputs":[]}
        \\]
    ;
    const C = Bind(abi);
    // getReserves resolves to a two-field struct return; uint112 -> u112.
    const Ret = C.ReturnOf("getReserves");
    try testing.expectEqual(@as(usize, 2), std.meta.fieldNames(Ret).len);
    try testing.expectEqual(u112, @FieldType(Ret, "r0"));
    // The ABI still recorded both entries.
    try testing.expectEqual(@as(usize, 2), C.abi.funcs.len);
}

test "bytes32 indexed event param decodes to [32]u8" {
    const abi =
        \\[{"type":"event","name":"Hashed","inputs":[
        \\  {"name":"id","type":"bytes32","indexed":true},
        \\  {"name":"n","type":"uint256","indexed":false}]}]
    ;
    const C = Bind(abi);
    const T = C.EventOf("Hashed");
    try testing.expectEqual([32]u8, @FieldType(T, "id"));

    var id: [32]u8 = @splat(0);
    id[0] = 0xAB;
    const data = uint256_mod.toBigEndianBytes(@as(u256, 7));
    const topics = [_][32]u8{ C.topicOf("Hashed"), id };
    const log = Log{
        .address = @splat(0),
        .topics = &topics,
        .data = &data,
        .block_number = null,
        .transaction_hash = null,
        .transaction_index = null,
        .log_index = null,
        .block_hash = null,
        .removed = false,
    };
    const decoded = try C.decodeEvent("Hashed", log);
    try testing.expectEqualSlices(u8, &id, &decoded.id);
    try testing.expectEqual(@as(u256, 7), decoded.n);
}

test "indexed reference-type (string) event param surfaces as raw [32]u8 topic" {
    const abi =
        \\[{"type":"event","name":"Named","inputs":[
        \\  {"name":"label","type":"string","indexed":true},
        \\  {"name":"value","type":"uint256","indexed":false}]}]
    ;
    const C = Bind(abi);
    const T = C.EventOf("Named");
    // Indexed string is hashed in the topic, so the field is the raw 32 bytes.
    try testing.expectEqual([32]u8, @FieldType(T, "label"));

    var label_topic: [32]u8 = @splat(0);
    label_topic[31] = 0x2a;
    const data = uint256_mod.toBigEndianBytes(@as(u256, 99));
    const topics = [_][32]u8{ C.topicOf("Named"), label_topic };
    const log = Log{
        .address = @splat(0),
        .topics = &topics,
        .data = &data,
        .block_number = null,
        .transaction_hash = null,
        .transaction_index = null,
        .log_index = null,
        .block_hash = null,
        .removed = false,
    };
    const decoded = try C.decodeEvent("Named", log);
    try testing.expectEqualSlices(u8, &label_topic, &decoded.label);
    try testing.expectEqual(@as(u256, 99), decoded.value);
}

test "decodeEvent rejects truncated log.data" {
    const C = Bind(erc20_abi);
    const topics = [_][32]u8{ C.topicOf("Transfer"), @splat(0x11), @splat(0x22) };
    // Transfer's non-indexed `value` needs a full 32-byte word; give it 4 bytes.
    const short_data = [_]u8{ 0, 0, 0, 1 };
    const log = Log{
        .address = @splat(0),
        .topics = &topics,
        .data = &short_data,
        .block_number = null,
        .transaction_hash = null,
        .transaction_index = null,
        .log_index = null,
        .block_hash = null,
        .removed = false,
    };
    try testing.expectError(EventError.TruncatedData, C.decodeEvent("Transfer", log));
}

test "encodeCall(transfer) is selector ++ padded to ++ 32-byte amount" {
    // The shared write/read calldata builder must produce byte-identical
    // calldata to a hand-built transfer call: 0xa9059cbb ++ 32-byte address ++
    // 32-byte amount.
    const Erc20 = Bind(erc20_abi);
    const allocator = testing.allocator;

    var to: [20]u8 = @splat(0);
    to[0] = 0xd8;
    to[1] = 0xdA;
    to[19] = 0x45;
    const amount: u256 = 1_000_000_000_000_000_000;

    const calldata = try Erc20.encodeCall(allocator, "transfer", .{ to, amount });
    defer allocator.free(calldata);

    // 4-byte selector + 32-byte padded address + 32-byte amount.
    try testing.expectEqual(@as(usize, 68), calldata.len);
    try testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, calldata[0..4]);
    // address is right-aligned in its 32-byte word (12 leading zero bytes).
    for (calldata[4..16]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expectEqualSlices(u8, &to, calldata[16..36]);
    // amount is the big-endian 32-byte word.
    const expected_amount = uint256_mod.toBigEndianBytes(amount);
    try testing.expectEqualSlices(u8, &expected_amount, calldata[36..68]);
}

test "encodeCall and the read path build identical calldata" {
    // `call` and `send` must share one encoder: assert encodeCall matches a
    // hand-rolled selector ++ encode(args) for balanceOf.
    const Erc20 = Bind(erc20_abi);
    const allocator = testing.allocator;

    var holder: [20]u8 = @splat(0);
    holder[19] = 0xAB;

    const via_helper = try Erc20.encodeCall(allocator, "balanceOf", .{holder});
    defer allocator.free(via_helper);

    const values = [_]AbiValue{.{ .address = holder }};
    const via_manual = try abi_encode.encodeFunctionCall(allocator, Erc20.selectorOf("balanceOf"), &values);
    defer allocator.free(via_manual);

    try testing.expectEqualSlices(u8, via_manual, via_helper);
}

test "send/sendValue/sendAndWait exist with the expected signatures" {
    const Erc20 = Bind(erc20_abi);

    // The write API is present on the generated handle.
    try testing.expect(@hasDecl(Erc20, "send"));
    try testing.expect(@hasDecl(Erc20, "sendValue"));
    try testing.expect(@hasDecl(Erc20, "sendAndWait"));

    // send/sendValue return the tx hash; sendAndWait returns a receipt.
    const SendRet = @typeInfo(@TypeOf(Erc20.send)).@"fn".return_type.?;
    try testing.expectEqual([32]u8, @typeInfo(SendRet).error_union.payload);
    const SendValueRet = @typeInfo(@TypeOf(Erc20.sendValue)).@"fn".return_type.?;
    try testing.expectEqual([32]u8, @typeInfo(SendValueRet).error_union.payload);
    const WaitRet = @typeInfo(@TypeOf(Erc20.sendAndWait)).@"fn".return_type.?;
    try testing.expectEqual(receipt_mod.TransactionReceipt, @typeInfo(WaitRet).error_union.payload);
}

test "send typechecks against a Wallet built over a (dummy) provider" {
    // Build a real Wallet over an HttpTransport pointed at a dummy URL: no call
    // is made here, we only confirm `send` typechecks end to end against the
    // wallet's `sendTransaction`. (The network round trip is covered by
    // integration tests.)
    const hex = @import("hex.zig");
    const http_transport_mod = @import("http_transport.zig");
    const runtime = @import("runtime.zig");

    const Erc20 = Bind(erc20_abi);
    const private_key = try hex.hexToBytesFixed(32, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    var transport = http_transport_mod.HttpTransport.init(testing.allocator, "http://127.0.0.1:1", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(testing.allocator, &transport);
    var wallet = wallet_mod.Wallet.init(testing.allocator, private_key, &provider);
    defer wallet.deinit();

    const token = Erc20.at(@splat(0xAB));
    var to: [20]u8 = @splat(0);
    to[19] = 0x02;
    const amount: u256 = 5;

    // Typecheck the full write surface against the live wallet without making a
    // network call: a comptime-false branch forces the compiler to resolve each
    // call's argument and return types but never runs them.
    if (comptime false) {
        _ = try token.send(&wallet, "transfer", .{ to, amount });
        _ = try token.sendValue(&wallet, "transfer", .{ to, amount }, 0);
        _ = try token.sendAndWait(&wallet, "transfer", .{ to, amount }, 1);
    }
}

test "refAllDecls" {
    std.testing.refAllDecls(@This());
}
