const std = @import("std");
const eth = @import("eth");

// ============================================================================
// Test data (Anvil account 0 -- well-known test key)
// ============================================================================

const TEST_PRIVKEY: [32]u8 = .{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3,
    0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc,
    0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};

// keccak256("") -- a well-known hash
const TEST_MSG_HASH: [32]u8 = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};

const TEST_ADDR: [20]u8 = .{
    0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6,
    0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf,
    0xfF, 0xb9, 0x22, 0x66,
};

// BIP-39 test seed from "abandon" x11 + "about"
const TEST_SEED: [64]u8 = .{
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
};

const TRANSFER_SELECTOR: [4]u8 = .{ 0xa9, 0x05, 0x9c, 0xbb };

// Pre-encoded data for decode benchmarks (initialized in main)
var precomputed_abi_dynamic: []const u8 = &.{};
var precomputed_rlp_u256: []const u8 = &.{};
var precomputed_pubkey: [65]u8 = undefined;

// ============================================================================
// Benchmark harness -- criterion-style: calibrate batch, measure wall time
// ============================================================================

const WARMUP_NS: u64 = 500_000_000; // 0.5s warmup
const BENCH_NS: u64 = 2_000_000_000; // 2s measurement

/// Minimal replacement for std.time.Timer, which was removed in Zig 0.16.
const Timer = struct {
    start_ns: i96,

    fn now() i96 {
        const io = std.Io.Threaded.global_single_threaded.io();
        return std.Io.Clock.now(.awake, io).nanoseconds;
    }

    fn start() error{}!Timer {
        return .{ .start_ns = now() };
    }

    fn reset(self: *Timer) void {
        self.start_ns = now();
    }

    fn read(self: *Timer) u64 {
        const elapsed = now() - self.start_ns;
        if (elapsed < 0) return 0;
        return @intCast(elapsed);
    }
};

const BenchResult = struct {
    ns_per_op: u64,
    iters: u64,
};

fn runBench(comptime func: fn () void) BenchResult {
    var timer = Timer.start() catch @panic("timer unsupported");

    // Warmup: run until WARMUP_NS elapsed
    timer.reset();
    while (true) {
        inline for (0..64) |_| func();
        if (timer.read() >= WARMUP_NS) break;
    }

    // Calibrate: find iteration count that fills ~100ms
    var batch: u64 = 64;
    while (true) {
        timer.reset();
        for (0..batch) |_| func();
        if (timer.read() >= 100_000_000) break; // 100ms
        batch *= 2;
    }

    // Measure: collect samples over BENCH_NS
    var total_iters: u64 = 0;
    timer.reset();

    while (timer.read() < BENCH_NS) {
        for (0..batch) |_| func();
        total_iters += batch;
    }

    const total_ns = timer.read();
    const ns_per_op = if (total_iters > 0) total_ns / total_iters else 0;
    return .{ .ns_per_op = ns_per_op, .iters = total_iters };
}

fn runAndPrint(comptime name: []const u8, comptime func: fn () void, stdout: anytype) !void {
    const result = runBench(func);
    try stdout.print("{s:<34} {d:>9} ns {d:>14}\n", .{ name, result.ns_per_op, result.iters });
}

// ============================================================================
// Benchmark functions -- Keccak256
// ============================================================================

fn benchKeccakEmpty() void {
    const data: [0]u8 = .{};
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak32() void {
    const data: [32]u8 = TEST_MSG_HASH;
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak256b() void {
    const data: [256]u8 = @splat(0xAB);
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak1k() void {
    const data: [1024]u8 = @splat(0xAB);
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak4k() void {
    const data: [4096]u8 = @splat(0xAB);
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

// ============================================================================
// Benchmark functions -- secp256k1
// ============================================================================

fn benchSecp256k1Sign() void {
    const sig = eth.secp256k1.sign(TEST_PRIVKEY, TEST_MSG_HASH) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

fn benchSecp256k1Recover() void {
    const sig = eth.secp256k1.sign(TEST_PRIVKEY, TEST_MSG_HASH) catch unreachable;
    const pubkey = eth.secp256k1.recover(sig, TEST_MSG_HASH) catch unreachable;
    std.mem.doNotOptimizeAway(&pubkey);
}

// ============================================================================
// Benchmark functions -- Address
// ============================================================================

fn benchAddressDerivation() void {
    const addr = eth.secp256k1.pubkeyToAddress(precomputed_pubkey);
    std.mem.doNotOptimizeAway(&addr);
}

fn benchAddressFromHex() void {
    var hex_str: []const u8 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    std.mem.doNotOptimizeAway(&hex_str);
    const addr = eth.primitives.addressFromHex(hex_str) catch unreachable;
    std.mem.doNotOptimizeAway(&addr);
}

fn benchChecksumAddress() void {
    const addr = TEST_ADDR;
    const checksum = eth.primitives.addressToChecksum(&addr);
    std.mem.doNotOptimizeAway(&checksum);
}

// ============================================================================
// Benchmark functions -- ABI encoding
// ============================================================================

fn benchAbiEncodeTransfer() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = TEST_ADDR },
        .{ .uint256 = 1_000_000_000_000_000_000 },
    };
    const result = eth.abi_encode.encodeFunctionCall(alloc, TRANSFER_SELECTOR, &args) catch unreachable;
    std.mem.doNotOptimizeAway(result.ptr);
}

fn benchAbiEncodeStatic() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = TEST_ADDR },
        .{ .uint256 = 1_000_000_000_000_000_000 },
    };
    const result = eth.abi_encode.encodeValues(alloc, &args) catch unreachable;
    std.mem.doNotOptimizeAway(result.ptr);
}

fn benchAbiEncodeDynamic() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const array_items = [_]eth.abi_encode.AbiValue{
        .{ .uint256 = 1 },
        .{ .uint256 = 2 },
        .{ .uint256 = 3 },
        .{ .uint256 = 4 },
        .{ .uint256 = 5 },
    };
    const args = [_]eth.abi_encode.AbiValue{
        .{ .string = "The quick brown fox jumps over the lazy dog" },
        .{ .bytes = "hello world, this is a dynamic bytes benchmark test payload" },
        .{ .array = &array_items },
    };
    const result = eth.abi_encode.encodeValues(alloc, &args) catch unreachable;
    std.mem.doNotOptimizeAway(result.ptr);
}

// ============================================================================
// Benchmark functions -- ABI decoding
// ============================================================================

fn benchAbiDecodeUint256() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const encoded: [32]u8 = .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
    };
    const types = [_]eth.abi_types.AbiType{.uint256};
    const values = eth.abi_decode.decodeValues(&encoded, &types, alloc) catch unreachable;
    std.mem.doNotOptimizeAway(values.ptr);
}

fn benchAbiDecodeDynamic() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const types = [_]eth.abi_types.AbiType{ .string, .bytes };
    const values = eth.abi_decode.decodeValues(precomputed_abi_dynamic, &types, alloc) catch unreachable;
    std.mem.doNotOptimizeAway(values.ptr);
}

// ============================================================================
// Benchmark functions -- RLP
// ============================================================================

fn benchRlpEncodeTx() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const tx = eth.transaction.Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 42,
            .max_priority_fee_per_gas = 2_000_000_000,
            .max_fee_per_gas = 100_000_000_000,
            .gas_limit = 21000,
            .to = TEST_ADDR,
            .value = 1_000_000_000_000_000_000,
            .data = &.{},
            .access_list = &.{},
        },
    };
    const serialized = eth.transaction.serializeForSigning(alloc, tx) catch unreachable;
    std.mem.doNotOptimizeAway(serialized.ptr);
}

fn benchRlpDecodeU256() void {
    const decoded = eth.rlp.decode(u256, precomputed_rlp_u256) catch unreachable;
    std.mem.doNotOptimizeAway(&decoded.value);
}

// ============================================================================
// Benchmark functions -- u256 arithmetic
// ============================================================================

fn benchU256Add() void {
    var a: u256 = 1_000_000_000_000_000_000;
    var b: u256 = 997_000_000_000_000_000;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = a +% b;
    std.mem.doNotOptimizeAway(&result);
}

fn benchU256Mul() void {
    var a: u256 = 1_000_000_000_000_000_000;
    var b: u256 = 997;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = a *% b;
    std.mem.doNotOptimizeAway(&result);
}

fn benchU256Div() void {
    var a: u256 = 997_000_000_000_000_000_000;
    var b: u256 = 1_000_000_000_000_000_000;
    std.mem.doNotOptimizeAway(&a);
    std.mem.doNotOptimizeAway(&b);
    const result = eth.uint256.fastDiv(a, b);
    std.mem.doNotOptimizeAway(&result);
}

fn benchU256UniswapV2AmountOut() void {
    var amount_in: u256 = 1_000_000_000_000_000_000; // 1 ETH
    var reserve_in: u256 = 100_000_000_000_000_000_000; // 100 ETH
    var reserve_out: u256 = 200_000_000_000; // 200k USDC (6 decimals)
    asm volatile (""
        :
        : [a] "r" (&amount_in),
          [b] "r" (&reserve_in),
          [c] "r" (&reserve_out),
        : .{ .memory = true });

    // Use limb-based compound function that avoids __udivti3
    const amount_out = eth.uint256.getAmountOut(amount_in, reserve_in, reserve_out);
    std.mem.doNotOptimizeAway(&amount_out);
}

fn benchU256MulDiv() void {
    var a: u256 = 1_000_000_000_000_000_000;
    var b: u256 = 79228162514264337593543950336;
    var c: u256 = 1_000_000_000_000_001_000;
    asm volatile (""
        :
        : [a] "r" (&a),
          [b] "r" (&b),
          [c] "r" (&c),
        : .{ .memory = true });
    const result = eth.uint256.mulDiv(a, b, c);
    std.mem.doNotOptimizeAway(&result);
}

fn benchU256UniswapV4Swap() void {
    var liquidity: u256 = 1_000_000_000_000_000_000;
    var sqrt_price: u256 = 79228162514264337593543950336;
    var amount_in: u256 = 1_000_000_000_000_000;
    asm volatile (""
        :
        : [a] "r" (&liquidity),
          [b] "r" (&sqrt_price),
          [c] "r" (&amount_in),
        : .{ .memory = true });

    const product = eth.uint256.fastMul(amount_in, sqrt_price);
    const denominator = liquidity +% product;
    const next_sqrt_price = eth.uint256.mulDiv(liquidity, sqrt_price, denominator);
    std.mem.doNotOptimizeAway(&next_sqrt_price);
}

// ============================================================================
// Benchmark functions -- Hex
// ============================================================================

fn benchHexEncode32() void {
    const data: [32]u8 = TEST_MSG_HASH;
    const result = eth.hex.bytesToHexBuf(32, &data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchHexDecode32() void {
    var hex_str: []const u8 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    std.mem.doNotOptimizeAway(&hex_str);
    var buf: [32]u8 = undefined;
    _ = eth.hex.hexToBytes(&buf, hex_str) catch unreachable;
    std.mem.doNotOptimizeAway(&buf);
}

// ============================================================================
// Benchmark functions -- Transaction
// ============================================================================

fn benchTxHashEip1559() void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();
    const tx = eth.transaction.Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 42,
            .max_priority_fee_per_gas = 2_000_000_000,
            .max_fee_per_gas = 100_000_000_000,
            .gas_limit = 21000,
            .to = TEST_ADDR,
            .value = 1_000_000_000_000_000_000,
            .data = &.{},
            .access_list = &.{},
        },
    };
    const hash = eth.transaction.hashForSigning(alloc, tx) catch unreachable;
    std.mem.doNotOptimizeAway(&hash);
}

// ============================================================================
// Benchmark functions -- HD Wallet
// ============================================================================

fn benchHdWalletDerive10() void {
    const master = eth.hd_wallet.masterKeyFromSeed(TEST_SEED) catch unreachable;
    for (0..10) |i| {
        const child = eth.hd_wallet.deriveChild(master, @intCast(i)) catch unreachable;
        std.mem.doNotOptimizeAway(&child);
    }
}

// ============================================================================
// Benchmark functions -- EIP-712
// ============================================================================

fn benchEip712Hash() void {
    var buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const alloc = fba.allocator();

    const domain = eth.eip712.DomainSeparator{
        .name = "TestDApp",
        .version = "1",
        .chain_id = 1,
        .verifying_contract = TEST_ADDR,
    };

    const transfer_type = eth.eip712.TypeDef{
        .name = "Transfer",
        .fields = &.{
            .{ .name = "to", .type_str = "address" },
            .{ .name = "amount", .type_str = "uint256" },
        },
    };

    const message = eth.eip712.StructValue{
        .type_name = "Transfer",
        .fields = &.{
            .{ .name = "to", .type_str = "address", .value = .{ .address = TEST_ADDR } },
            .{ .name = "amount", .type_str = "uint256", .value = .{ .uint256 = 1_000_000_000_000_000_000 } },
        },
    };

    const result = eth.eip712.hashTypedData(
        alloc,
        domain,
        message,
        &.{transfer_type},
    ) catch unreachable;
    std.mem.doNotOptimizeAway(&result);
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Pre-compute data for decode benchmarks
    const abi_dyn_args = [_]eth.abi_encode.AbiValue{
        .{ .string = "The quick brown fox jumps over the lazy dog" },
        .{ .bytes = "hello world, this is a dynamic bytes benchmark test payload" },
    };
    const abi_dyn_encoded = try eth.abi_encode.encodeValues(allocator, &abi_dyn_args);
    precomputed_abi_dynamic = abi_dyn_encoded;

    const rlp_encoded = try eth.rlp.encode(allocator, @as(u256, 1_000_000_000_000_000_000));
    precomputed_rlp_u256 = rlp_encoded;

    precomputed_pubkey = eth.secp256k1.derivePublicKey(TEST_PRIVKEY) catch unreachable;

    var out_buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(std.Io.Threaded.global_single_threaded.io(), &out_buf);
    const stdout = &w.interface;

    try stdout.print("\n{s:<34} {s:>12} {s:>14}\n", .{ "Benchmark", "ns/op", "iters" });
    try stdout.print("{s}\n", .{"" ++ @as([64]u8, @splat('-'))});

    // Keccak256
    try runAndPrint("keccak256_empty", benchKeccakEmpty, stdout);
    try runAndPrint("keccak256_32b", benchKeccak32, stdout);
    try runAndPrint("keccak256_256b", benchKeccak256b, stdout);
    try runAndPrint("keccak256_1kb", benchKeccak1k, stdout);
    try runAndPrint("keccak256_4kb", benchKeccak4k, stdout);
    // secp256k1
    try runAndPrint("secp256k1_sign", benchSecp256k1Sign, stdout);
    try runAndPrint("secp256k1_sign_recover", benchSecp256k1Recover, stdout);
    // Address
    try runAndPrint("address_derivation", benchAddressDerivation, stdout);
    try runAndPrint("address_from_hex", benchAddressFromHex, stdout);
    try runAndPrint("checksum_address", benchChecksumAddress, stdout);
    // ABI encoding
    try runAndPrint("abi_encode_transfer", benchAbiEncodeTransfer, stdout);
    try runAndPrint("abi_encode_static", benchAbiEncodeStatic, stdout);
    try runAndPrint("abi_encode_dynamic", benchAbiEncodeDynamic, stdout);
    // ABI decoding
    try runAndPrint("abi_decode_uint256", benchAbiDecodeUint256, stdout);
    try runAndPrint("abi_decode_dynamic", benchAbiDecodeDynamic, stdout);
    // RLP
    try runAndPrint("rlp_encode_eip1559_tx", benchRlpEncodeTx, stdout);
    try runAndPrint("rlp_decode_u256", benchRlpDecodeU256, stdout);
    // u256 arithmetic
    try runAndPrint("u256_add", benchU256Add, stdout);
    try runAndPrint("u256_mul", benchU256Mul, stdout);
    try runAndPrint("u256_div", benchU256Div, stdout);
    try runAndPrint("u256_uniswapv2_amount_out", benchU256UniswapV2AmountOut, stdout);
    try runAndPrint("u256_mulDiv", benchU256MulDiv, stdout);
    try runAndPrint("u256_uniswapv4_swap", benchU256UniswapV4Swap, stdout);
    // Hex
    try runAndPrint("hex_encode_32b", benchHexEncode32, stdout);
    try runAndPrint("hex_decode_32b", benchHexDecode32, stdout);
    // Transaction
    try runAndPrint("tx_hash_eip1559", benchTxHashEip1559, stdout);
    // HD Wallet
    try runAndPrint("hd_wallet_derive_10", benchHdWalletDerive10, stdout);
    // EIP-712
    try runAndPrint("eip712_hash_typed_data", benchEip712Hash, stdout);

    try stdout.print("\n", .{});
    try stdout.flush();
}
