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
    var buf: [8192]u8 = undefined;
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

    w.print("{s}\n\n", .{"=" ** 62}) catch {};
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

// ============================================================================
// Benchmark functions
// ============================================================================

fn benchKeccak32() void {
    const data: [32]u8 = TEST_MSG_HASH;
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchKeccak1k() void {
    const data: [1024]u8 = .{0xAB} ** 1024;
    const result = eth.keccak.hash(&data);
    std.mem.doNotOptimizeAway(&result);
}

fn benchSecp256k1Sign() void {
    const sig = eth.secp256k1.sign(TEST_PRIVKEY, TEST_MSG_HASH) catch unreachable;
    std.mem.doNotOptimizeAway(&sig);
}

fn benchSecp256k1Recover() void {
    const sig = eth.secp256k1.sign(TEST_PRIVKEY, TEST_MSG_HASH) catch unreachable;
    const pubkey = eth.secp256k1.recover(sig, TEST_MSG_HASH) catch unreachable;
    std.mem.doNotOptimizeAway(&pubkey);
}

fn benchAddressDerivation() void {
    const s = eth.signer.Signer.init(TEST_PRIVKEY);
    const addr = s.address() catch unreachable;
    std.mem.doNotOptimizeAway(&addr);
}

fn benchAbiEncodeTransfer(allocator: std.mem.Allocator) void {
    const args = [_]eth.abi_encode.AbiValue{
        .{ .address = TEST_ADDR },
        .{ .uint256 = 1_000_000_000_000_000_000 }, // 1 ETH in wei
    };
    const result = eth.abi_encode.encodeFunctionCall(allocator, TRANSFER_SELECTOR, &args) catch unreachable;
    defer allocator.free(result);
    std.mem.doNotOptimizeAway(result.ptr);
}

fn benchAbiDecodeUint256(allocator: std.mem.Allocator) void {
    // Pre-encoded uint256 value: 1 ETH in wei, left-padded to 32 bytes
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

fn benchRlpEncodeTx(allocator: std.mem.Allocator) void {
    const tx = eth.transaction.Transaction{
        .eip1559 = .{
            .chain_id = 1,
            .nonce = 42,
            .max_priority_fee_per_gas = 2_000_000_000, // 2 gwei
            .max_fee_per_gas = 100_000_000_000, // 100 gwei
            .gas_limit = 21000,
            .to = TEST_ADDR,
            .value = 1_000_000_000_000_000_000, // 1 ETH
            .data = &.{},
            .access_list = &.{},
        },
    };
    const serialized = eth.transaction.serializeForSigning(allocator, tx) catch unreachable;
    defer allocator.free(serialized);
    std.mem.doNotOptimizeAway(serialized.ptr);
}

fn benchHdWalletDerive10() void {
    const master = eth.hd_wallet.masterKeyFromSeed(TEST_SEED) catch unreachable;
    for (0..10) |i| {
        const child = eth.hd_wallet.deriveChild(master, @intCast(i)) catch unreachable;
        std.mem.doNotOptimizeAway(&child);
    }
}

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

fn benchChecksumAddress() void {
    const addr = TEST_ADDR;
    const checksum = eth.primitives.addressToChecksum(&addr);
    std.mem.doNotOptimizeAway(&checksum);
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const WARMUP = 100;
    const ITERS = 10_000;
    // Signing/EC ops are expensive -- use fewer iterations
    const SIGN_ITERS = 1_000;

    const results = [_]BenchResult{
        bench("keccak256_32b", WARMUP, ITERS, benchKeccak32),
        bench("keccak256_1kb", WARMUP, ITERS, benchKeccak1k),
        bench("secp256k1_sign", WARMUP, SIGN_ITERS, benchSecp256k1Sign),
        bench("secp256k1_sign_recover", WARMUP, SIGN_ITERS, benchSecp256k1Recover),
        bench("address_derivation", WARMUP, SIGN_ITERS, benchAddressDerivation),
        benchAlloc("abi_encode_transfer", WARMUP, ITERS, allocator, benchAbiEncodeTransfer),
        benchAlloc("abi_decode_uint256", WARMUP, ITERS, allocator, benchAbiDecodeUint256),
        benchAlloc("rlp_encode_eip1559_tx", WARMUP, ITERS, allocator, benchRlpEncodeTx),
        bench("hd_wallet_derive_10", WARMUP, SIGN_ITERS, benchHdWalletDerive10),
        benchAlloc("eip712_hash_typed_data", WARMUP, ITERS, allocator, benchEip712Hash),
        bench("checksum_address", WARMUP, ITERS, benchChecksumAddress),
    };

    printResults(&results);
}
