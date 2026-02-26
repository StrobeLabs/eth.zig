const std = @import("std");
const eth = @import("eth");

// ============================================================================
// Benchmark harness
// ============================================================================

const BenchResult = struct {
    name: []const u8,
    iterations: u64,
    total_ns: u64,

    fn nsPerOp(self: BenchResult) u64 {
        if (self.total_ns == 0) return 0;
        return self.total_ns / self.iterations;
    }

    fn opsPerSec(self: BenchResult) u64 {
        if (self.total_ns == 0) return 0;
        return self.iterations * 1_000_000_000 / self.total_ns;
    }
};

fn bench(name: []const u8, warmup: u32, iterations: u32, comptime func: fn () void) BenchResult {
    for (0..warmup) |_| {
        func();
    }

    var timer = std.time.Timer.start() catch @panic("timer unavailable");
    for (0..iterations) |_| {
        func();
    }
    const elapsed = timer.read();

    return .{
        .name = name,
        .iterations = iterations,
        .total_ns = elapsed,
    };
}

fn benchAlloc(name: []const u8, warmup: u32, iterations: u32, allocator: std.mem.Allocator, comptime func: fn (std.mem.Allocator) void) BenchResult {
    for (0..warmup) |_| {
        func(allocator);
    }

    var timer = std.time.Timer.start() catch @panic("timer unavailable");
    for (0..iterations) |_| {
        func(allocator);
    }
    const elapsed = timer.read();

    return .{
        .name = name,
        .iterations = iterations,
        .total_ns = elapsed,
    };
}

fn printResults(results: []const BenchResult) void {
    var buf: [16384]u8 = undefined;
    var writer_impl = std.fs.File.stdout().writer(&buf);
    const w = &writer_impl.interface;

    w.print("\neth.zig benchmarks (ReleaseFast)\n", .{}) catch {};
    w.print("{s}\n", .{"=" ** 62}) catch {};
    w.print("{s: <34} {s: >12} {s: >12}\n", .{ "Benchmark", "ops/sec", "ns/op" }) catch {};
    w.print("{s}\n", .{"-" ** 62}) catch {};

    for (results) |r| {
        const ops = r.opsPerSec();
        const ns = r.nsPerOp();

        // Format ops/sec with comma separators
        var ops_buf: [24]u8 = undefined;
        const ops_str = formatWithCommas(ops, &ops_buf);

        w.print("{s: <34} {s: >12} {d: >12}\n", .{ r.name, ops_str, ns }) catch {};
    }

    w.print("{s}\n", .{"=" ** 62}) catch {};

    // Machine-readable JSON output for comparison script
    w.print("\n", .{}) catch {};
    for (results) |r| {
        w.print("BENCH_JSON|{{\"name\":\"{s}\",\"ns_per_op\":{d},\"ops_per_sec\":{d}}}\n", .{
            r.name, r.nsPerOp(), r.opsPerSec(),
        }) catch {};
    }

    w.print("\n", .{}) catch {};
    w.flush() catch {};
}

fn formatWithCommas(value: u64, out_buf: []u8) []const u8 {
    if (value == 0) {
        out_buf[0] = '0';
        return out_buf[0..1];
    }

    // Write digits to a temp buffer (reversed order: least significant first)
    var digits: [20]u8 = undefined;
    var digit_count: usize = 0;
    var v = value;
    while (v > 0) {
        digits[digit_count] = @intCast(v % 10 + '0');
        digit_count += 1;
        v /= 10;
    }

    // Write with commas. We iterate from the least significant digit,
    // inserting a comma every 3 digits, then reverse the whole thing.
    var tmp: [28]u8 = undefined; // 20 digits + up to 6 commas + slack
    var pos: usize = 0;
    for (0..digit_count) |i| {
        if (i > 0 and i % 3 == 0) {
            tmp[pos] = ',';
            pos += 1;
        }
        tmp[pos] = digits[i];
        pos += 1;
    }

    // Reverse into out_buf
    for (0..pos) |i| {
        out_buf[i] = tmp[pos - 1 - i];
    }
    return out_buf[0..pos];
}

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

// Precomputed selector for transfer(address,uint256)
const TRANSFER_SELECTOR: [4]u8 = .{ 0xa9, 0x05, 0x9c, 0xbb };

// Pre-encoded data for decode benchmarks (initialized in main)
var precomputed_abi_dynamic: []const u8 = &.{};
var precomputed_rlp_u256: []const u8 = &.{};
var precomputed_pubkey: [65]u8 = undefined;

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
    const data: [256]u8 = .{0xAB} ** 256;
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak1k() void {
    const data: [1024]u8 = .{0xAB} ** 1024;
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak4k() void {
    const data: [4096]u8 = .{0xAB} ** 4096;
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

fn benchAbiEncodeTransfer(allocator: std.mem.Allocator) void {
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = TEST_ADDR },
        .{ .uint256 = 1_000_000_000_000_000_000 },
    };
    const result = eth.abi_encode.encodeFunctionCall(allocator, TRANSFER_SELECTOR, &args) catch unreachable;
    defer allocator.free(result);
    std.mem.doNotOptimizeAway(result.ptr);
}

fn benchAbiEncodeStatic(allocator: std.mem.Allocator) void {
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = TEST_ADDR },
        .{ .uint256 = 1_000_000_000_000_000_000 },
    };
    const result = eth.abi_encode.encodeValues(allocator, &args) catch unreachable;
    defer allocator.free(result);
    std.mem.doNotOptimizeAway(result.ptr);
}

fn benchAbiEncodeDynamic(allocator: std.mem.Allocator) void {
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
    const result = eth.abi_encode.encodeValues(allocator, &args) catch unreachable;
    defer allocator.free(result);
    std.mem.doNotOptimizeAway(result.ptr);
}

// ============================================================================
// Benchmark functions -- ABI decoding
// ============================================================================

fn benchAbiDecodeUint256(allocator: std.mem.Allocator) void {
    const encoded: [32]u8 = .{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
    };
    const types = [_]eth.abi_types.AbiType{.uint256};
    const values = eth.abi_decode.decodeValues(&encoded, &types, allocator) catch unreachable;
    defer eth.abi_decode.freeValues(values, allocator);
    std.mem.doNotOptimizeAway(values.ptr);
}

fn benchAbiDecodeDynamic(allocator: std.mem.Allocator) void {
    const types = [_]eth.abi_types.AbiType{ .string, .bytes };
    const values = eth.abi_decode.decodeValues(precomputed_abi_dynamic, &types, allocator) catch unreachable;
    defer eth.abi_decode.freeValues(values, allocator);
    std.mem.doNotOptimizeAway(values.ptr);
}

// ============================================================================
// Benchmark functions -- RLP
// ============================================================================

fn benchRlpEncodeTx(allocator: std.mem.Allocator) void {
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
    const serialized = eth.transaction.serializeForSigning(allocator, tx) catch unreachable;
    defer allocator.free(serialized);
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
    // Single barrier covers all inputs (avoids 3 separate memory clobbers)
    asm volatile (""
        :
        : [a] "r" (&amount_in),
          [b] "r" (&reserve_in),
          [c] "r" (&reserve_out),
        : .{ .memory = true });

    const amount_in_with_fee = eth.uint256.fastMul(amount_in, 997);
    const numerator = eth.uint256.fastMul(amount_in_with_fee, reserve_out);
    const denominator = eth.uint256.fastMul(reserve_in, 1000) +% amount_in_with_fee;
    const amount_out = eth.uint256.fastDiv(numerator, denominator);
    std.mem.doNotOptimizeAway(&amount_out);
}

fn benchU256MulDiv() void {
    // FullMath.mulDiv: (a * b) / c with 512-bit intermediate
    // Common pattern in UniswapV3/V4 SqrtPriceMath
    var a: u256 = 1_000_000_000_000_000_000; // 1e18 liquidity
    var b: u256 = 79228162514264337593543950336; // ~1.0 sqrtPriceX96
    var c: u256 = 1_000_000_000_000_001_000; // liquidity + amountIn
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
    // UniswapV4 getNextSqrtPriceFromAmount0RoundingUp:
    // sqrtPriceNext = liquidity * sqrtPriceX96 / (liquidity + amount * sqrtPriceX96)
    var liquidity: u256 = 1_000_000_000_000_000_000; // 1e18
    var sqrt_price: u256 = 79228162514264337593543950336; // ~1.0 in Q96
    var amount_in: u256 = 1_000_000_000_000_000; // 0.001 ETH
    asm volatile (""
        :
        : [a] "r" (&liquidity),
          [b] "r" (&sqrt_price),
          [c] "r" (&amount_in),
        : .{ .memory = true });

    // Step 1: amount * sqrtPrice (may overflow u256 so use mulDiv path)
    const product = eth.uint256.fastMul(amount_in, sqrt_price);
    // Step 2: denominator = liquidity + product
    const denominator = liquidity +% product;
    // Step 3: numerator = liquidity * sqrtPrice / denominator (full precision)
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

fn benchTxHashEip1559(allocator: std.mem.Allocator) void {
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
    const hash = eth.transaction.hashForSigning(allocator, tx) catch unreachable;
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

fn benchEip712Hash(allocator: std.mem.Allocator) void {
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
        allocator,
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
    const allocator = std.heap.c_allocator;

    // Pre-compute data for decode benchmarks
    const abi_dyn_args = [_]eth.abi_encode.AbiValue{
        .{ .string = "The quick brown fox jumps over the lazy dog" },
        .{ .bytes = "hello world, this is a dynamic bytes benchmark test payload" },
    };
    const abi_dyn_encoded = try eth.abi_encode.encodeValues(allocator, &abi_dyn_args);
    precomputed_abi_dynamic = abi_dyn_encoded;

    const rlp_encoded = try eth.rlp.encode(allocator, @as(u256, 1_000_000_000_000_000_000));
    precomputed_rlp_u256 = rlp_encoded;

    // Pre-compute public key for address derivation benchmark
    precomputed_pubkey = eth.secp256k1.derivePublicKey(TEST_PRIVKEY) catch unreachable;

    const WARMUP = 100;
    const ITERS = 10_000;
    const SIGN_ITERS = 1_000;
    const TX_ITERS = 5_000;

    const results = [_]BenchResult{
        // Keccak256
        bench("keccak256_empty", WARMUP, ITERS, benchKeccakEmpty),
        bench("keccak256_32b", WARMUP, ITERS, benchKeccak32),
        bench("keccak256_256b", WARMUP, ITERS, benchKeccak256b),
        bench("keccak256_1kb", WARMUP, ITERS, benchKeccak1k),
        bench("keccak256_4kb", WARMUP, ITERS, benchKeccak4k),
        // secp256k1
        bench("secp256k1_sign", WARMUP, SIGN_ITERS, benchSecp256k1Sign),
        bench("secp256k1_sign_recover", WARMUP, SIGN_ITERS, benchSecp256k1Recover),
        // Address
        bench("address_derivation", WARMUP, SIGN_ITERS, benchAddressDerivation),
        bench("address_from_hex", WARMUP, ITERS, benchAddressFromHex),
        bench("checksum_address", WARMUP, ITERS, benchChecksumAddress),
        // ABI encoding
        benchAlloc("abi_encode_transfer", WARMUP, ITERS, allocator, benchAbiEncodeTransfer),
        benchAlloc("abi_encode_static", WARMUP, ITERS, allocator, benchAbiEncodeStatic),
        benchAlloc("abi_encode_dynamic", WARMUP, ITERS, allocator, benchAbiEncodeDynamic),
        // ABI decoding
        benchAlloc("abi_decode_uint256", WARMUP, ITERS, allocator, benchAbiDecodeUint256),
        benchAlloc("abi_decode_dynamic", WARMUP, ITERS, allocator, benchAbiDecodeDynamic),
        // RLP
        benchAlloc("rlp_encode_eip1559_tx", WARMUP, ITERS, allocator, benchRlpEncodeTx),
        bench("rlp_decode_u256", WARMUP, ITERS, benchRlpDecodeU256),
        // u256 arithmetic
        bench("u256_add", WARMUP, ITERS, benchU256Add),
        bench("u256_mul", WARMUP, ITERS, benchU256Mul),
        bench("u256_div", WARMUP, ITERS, benchU256Div),
        bench("u256_uniswapv2_amount_out", WARMUP, ITERS, benchU256UniswapV2AmountOut),
        bench("u256_mulDiv", WARMUP, ITERS, benchU256MulDiv),
        bench("u256_uniswapv4_swap", WARMUP, ITERS, benchU256UniswapV4Swap),
        // Hex
        bench("hex_encode_32b", WARMUP, ITERS, benchHexEncode32),
        bench("hex_decode_32b", WARMUP, ITERS, benchHexDecode32),
        // Transaction
        benchAlloc("tx_hash_eip1559", WARMUP, TX_ITERS, allocator, benchTxHashEip1559),
        // HD Wallet (eth-zig only)
        bench("hd_wallet_derive_10", WARMUP, SIGN_ITERS, benchHdWalletDerive10),
        // EIP-712 (eth-zig only)
        benchAlloc("eip712_hash_typed_data", WARMUP, ITERS, allocator, benchEip712Hash),
    };

    printResults(&results);
}
