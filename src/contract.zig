const std = @import("std");
const provider_mod = @import("provider.zig");
const http_transport_mod = @import("http_transport.zig");
const runtime = @import("runtime.zig");
const wallet_mod = @import("wallet.zig");
const abi_encode = @import("abi_encode.zig");
const abi_decode = @import("abi_decode.zig");
const abi_types = @import("abi_types.zig");
const keccak_mod = @import("keccak.zig");

pub const AbiValue = abi_encode.AbiValue;
pub const AbiType = abi_types.AbiType;

/// Read a contract function: encode calldata, execute eth_call, decode the result.
/// Caller must free the returned values with freeReturnValues().
pub fn contractRead(
    allocator: std.mem.Allocator,
    provider: *provider_mod.Provider,
    to: [20]u8,
    sel: [4]u8,
    args: []const AbiValue,
    output_types: []const AbiType,
) ![]AbiValue {
    const calldata = try abi_encode.encodeFunctionCall(allocator, sel, args);
    defer allocator.free(calldata);
    const response = try provider.call(to, calldata);
    defer allocator.free(response);
    return try abi_decode.decodeValues(response, output_types, allocator);
}

/// Write to a contract: encode calldata, send as a transaction.
/// Returns the transaction hash.
pub fn contractWrite(
    allocator: std.mem.Allocator,
    wallet: *wallet_mod.Wallet,
    to: [20]u8,
    sel: [4]u8,
    args: []const AbiValue,
) ![32]u8 {
    const calldata = try abi_encode.encodeFunctionCall(allocator, sel, args);
    defer allocator.free(calldata);
    return try wallet.sendTransaction(.{
        .to = to,
        .data = calldata,
    });
}

/// Free values returned by contractRead.
pub fn freeReturnValues(values: []AbiValue, allocator: std.mem.Allocator) void {
    abi_decode.freeValues(values, allocator);
}

/// High-level contract interaction for reading and writing to Ethereum smart contracts.
/// Wraps a provider and contract address to simplify ABI-encoded calls.
pub const Contract = struct {
    address: [20]u8,
    provider: *provider_mod.Provider,
    allocator: std.mem.Allocator,

    /// Create a new Contract instance bound to a specific address and provider.
    pub fn init(allocator: std.mem.Allocator, contract_address: [20]u8, provider: *provider_mod.Provider) Contract {
        return .{
            .address = contract_address,
            .provider = provider,
            .allocator = allocator,
        };
    }

    /// Read a contract function using raw calldata (eth_call).
    /// Returns the raw bytes returned by the contract.
    /// Caller owns the returned slice.
    pub fn call(self: *Contract, data: []const u8) ![]u8 {
        return try self.provider.call(self.address, data);
    }

    /// Read a contract function using a 4-byte selector and ABI-encoded parameters.
    /// Encodes the function call, executes eth_call, and returns raw result bytes.
    /// Caller owns the returned slice.
    pub fn readRaw(self: *Contract, selector: [4]u8, values: []const abi_encode.AbiValue) ![]u8 {
        const calldata = try abi_encode.encodeFunctionCall(self.allocator, selector, values);
        defer self.allocator.free(calldata);
        return try self.provider.call(self.address, calldata);
    }

    /// Write to a contract by sending a transaction with raw calldata.
    /// Returns the transaction hash.
    pub fn write(self: *Contract, wallet: *wallet_mod.Wallet, data: []const u8, value: u256) ![32]u8 {
        return try wallet.sendTransaction(.{
            .to = self.address,
            .data = data,
            .value = value,
        });
    }

    /// Write to a contract using a 4-byte selector and ABI-encoded parameters.
    /// Encodes the function call, sends it as a transaction, and returns the tx hash.
    pub fn writeRaw(self: *Contract, wallet: *wallet_mod.Wallet, selector: [4]u8, values: []const abi_encode.AbiValue, value: u256) ![32]u8 {
        const calldata = try abi_encode.encodeFunctionCall(self.allocator, selector, values);
        defer self.allocator.free(calldata);
        return try wallet.sendTransaction(.{
            .to = self.address,
            .data = calldata,
            .value = value,
        });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Contract.init sets fields correctly" {
    const contract_addr = @as([20]u8, @splat(0xaa));
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545", runtime.blockingIo());
    defer transport.deinit();
    var provider = provider_mod.Provider.init(std.testing.allocator, &transport);
    const contract = Contract.init(std.testing.allocator, contract_addr, &provider);

    try std.testing.expectEqualSlices(u8, &contract_addr, &contract.address);
    try std.testing.expect(contract.provider == &provider);
}

test "Contract.readRaw encodes function call correctly" {
    // This test verifies that readRaw properly encodes a function call.
    // Since the provider stub returns ConnectionFailed, we verify encoding
    // by testing the underlying encodeFunctionCall separately.
    const allocator = std.testing.allocator;

    // Simulate what readRaw does internally: encode a balanceOf(address) call
    const keccak = @import("keccak.zig");
    const selector = keccak.selector("balanceOf(address)");
    var addr: [20]u8 = @as([20]u8, @splat(0));
    addr[0] = 0xd8;
    addr[19] = 0x45;

    const values = [_]abi_encode.AbiValue{.{ .address = addr }};
    const calldata = try abi_encode.encodeFunctionCall(allocator, selector, &values);
    defer allocator.free(calldata);

    // 4 bytes selector + 32 bytes address
    try std.testing.expectEqual(@as(usize, 36), calldata.len);
    try std.testing.expectEqualSlices(u8, &selector, calldata[0..4]);
}

test "Contract.writeRaw encodes transfer call correctly" {
    // Verify the encoding that writeRaw would produce for a transfer call.
    const allocator = std.testing.allocator;
    const keccak = @import("keccak.zig");

    const selector = keccak.selector("transfer(address,uint256)");
    var addr: [20]u8 = @as([20]u8, @splat(0));
    addr[19] = 0x01;

    const values = [_]abi_encode.AbiValue{
        .{ .address = addr },
        .{ .uint256 = 1000 },
    };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selector, &values);
    defer allocator.free(calldata);

    // 4 bytes selector + 2 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 68), calldata.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xa9, 0x05, 0x9c, 0xbb }, calldata[0..4]);
}
