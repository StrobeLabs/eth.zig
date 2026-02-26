const std = @import("std");
const contract_mod = @import("contract.zig");
const abi_encode = @import("abi_encode.zig");
const abi_decode = @import("abi_decode.zig");
const abi_types = @import("abi_types.zig");
const abi_comptime = @import("abi_comptime.zig");
const provider_mod = @import("provider.zig");
const wallet_mod = @import("wallet.zig");
const http_transport_mod = @import("http_transport.zig");

const AbiValue = abi_encode.AbiValue;
const AbiType = abi_types.AbiType;
const Contract = contract_mod.Contract;

/// Comptime-computed ERC-20 function selectors.
pub const selectors = struct {
    pub const name = abi_comptime.comptimeSelector("name()");
    pub const symbol = abi_comptime.comptimeSelector("symbol()");
    pub const decimals = abi_comptime.comptimeSelector("decimals()");
    pub const totalSupply = abi_comptime.comptimeSelector("totalSupply()");
    pub const balanceOf = abi_comptime.comptimeSelector("balanceOf(address)");
    pub const allowance = abi_comptime.comptimeSelector("allowance(address,address)");
    pub const transfer = abi_comptime.comptimeSelector("transfer(address,uint256)");
    pub const approve = abi_comptime.comptimeSelector("approve(address,uint256)");
    pub const transferFrom = abi_comptime.comptimeSelector("transferFrom(address,address,uint256)");
};

/// Comptime-computed ERC-20 event topics.
pub const topics = struct {
    pub const Transfer = abi_comptime.comptimeTopic("Transfer(address,address,uint256)");
    pub const Approval = abi_comptime.comptimeTopic("Approval(address,address,uint256)");
};

/// High-level ERC-20 token interface.
/// Wraps a Contract with typed methods for the standard ERC-20 functions.
pub const ERC20 = struct {
    contract: Contract,

    /// Create a new ERC20 instance bound to a token address and provider.
    pub fn init(allocator: std.mem.Allocator, token_address: [20]u8, provider: *provider_mod.Provider) ERC20 {
        return .{
            .contract = Contract.init(allocator, token_address, provider),
        };
    }

    /// Returns the token name.
    /// Caller owns the returned string.
    pub fn name(self: *ERC20) ![]const u8 {
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.name,
            &.{},
            &.{.string},
        );
        defer self.contract.allocator.free(result);
        if (result.len == 0) return error.InvalidResponse;
        const s = result[0].string;
        // Copy the string so we can free the decode result
        const owned = try self.contract.allocator.alloc(u8, s.len);
        @memcpy(owned, s);
        return owned;
    }

    /// Returns the token symbol.
    /// Caller owns the returned string.
    pub fn symbol(self: *ERC20) ![]const u8 {
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.symbol,
            &.{},
            &.{.string},
        );
        defer self.contract.allocator.free(result);
        if (result.len == 0) return error.InvalidResponse;
        const s = result[0].string;
        const owned = try self.contract.allocator.alloc(u8, s.len);
        @memcpy(owned, s);
        return owned;
    }

    /// Returns the number of decimals the token uses.
    pub fn decimals(self: *ERC20) !u8 {
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.decimals,
            &.{},
            &.{.uint8},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return @intCast(result[0].uint256);
    }

    /// Returns the total token supply.
    pub fn totalSupply(self: *ERC20) !u256 {
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.totalSupply,
            &.{},
            &.{.uint256},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].uint256;
    }

    /// Returns the balance of the given account.
    pub fn balanceOf(self: *ERC20, account: [20]u8) !u256 {
        const args = [_]AbiValue{.{ .address = account }};
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.balanceOf,
            &args,
            &.{.uint256},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].uint256;
    }

    /// Returns the remaining number of tokens that spender is allowed to spend on behalf of owner.
    pub fn allowance(self: *ERC20, owner: [20]u8, spender: [20]u8) !u256 {
        const args = [_]AbiValue{ .{ .address = owner }, .{ .address = spender } };
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.allowance,
            &args,
            &.{.uint256},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].uint256;
    }

    /// Transfer tokens to a recipient. Returns the transaction hash.
    pub fn transfer(self: *ERC20, wallet: *wallet_mod.Wallet, to: [20]u8, amount: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = to }, .{ .uint256 = amount } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.transfer,
            &args,
        );
    }

    /// Approve a spender to spend tokens. Returns the transaction hash.
    pub fn approve(self: *ERC20, wallet: *wallet_mod.Wallet, spender: [20]u8, amount: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = spender }, .{ .uint256 = amount } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.approve,
            &args,
        );
    }

    /// Transfer tokens from one address to another (requires prior approval). Returns the transaction hash.
    pub fn transferFrom(self: *ERC20, wallet: *wallet_mod.Wallet, from: [20]u8, to: [20]u8, amount: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = from }, .{ .address = to }, .{ .uint256 = amount } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.transferFrom,
            &args,
        );
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ERC20 selectors match known values" {
    // transfer(address,uint256) = 0xa9059cbb
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, &selectors.transfer);
    // approve(address,uint256) = 0x095ea7b3
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x5e, 0xa7, 0xb3 }, &selectors.approve);
    // balanceOf(address) = 0x70a08231
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &selectors.balanceOf);
    // totalSupply() = 0x18160ddd
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x16, 0x0d, 0xdd }, &selectors.totalSupply);
    // name() = 0x06fdde03
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0xfd, 0xde, 0x03 }, &selectors.name);
    // symbol() = 0x95d89b41
    try std.testing.expectEqualSlices(u8, &.{ 0x95, 0xd8, 0x9b, 0x41 }, &selectors.symbol);
    // decimals() = 0x313ce567
    try std.testing.expectEqualSlices(u8, &.{ 0x31, 0x3c, 0xe5, 0x67 }, &selectors.decimals);
    // transferFrom(address,address,uint256) = 0x23b872dd
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0xb8, 0x72, 0xdd }, &selectors.transferFrom);
    // allowance(address,address) = 0xdd62ed3e
    try std.testing.expectEqualSlices(u8, &.{ 0xdd, 0x62, 0xed, 0x3e }, &selectors.allowance);
}

test "ERC20 Transfer topic matches known value" {
    const hex_mod = @import("hex.zig");
    const expected = try hex_mod.hexToBytesFixed(32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    try std.testing.expectEqualSlices(u8, &expected, &topics.Transfer);
}

test "ERC20 Approval topic matches known value" {
    const hex_mod = @import("hex.zig");
    const expected = try hex_mod.hexToBytesFixed(32, "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");
    try std.testing.expectEqualSlices(u8, &expected, &topics.Approval);
}

test "ERC20.init sets address correctly" {
    const token_addr = [_]u8{0xaa} ** 20;
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var prov = provider_mod.Provider.init(std.testing.allocator, &transport);
    const erc20 = ERC20.init(std.testing.allocator, token_addr, &prov);

    try std.testing.expectEqualSlices(u8, &token_addr, &erc20.contract.address);
}

test "ERC20 transfer encodes correctly" {
    // Verify the encoding that transfer would produce
    const allocator = std.testing.allocator;
    var to_addr: [20]u8 = [_]u8{0} ** 20;
    to_addr[19] = 0x01;

    const args = [_]AbiValue{ .{ .address = to_addr }, .{ .uint256 = 1000 } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.transfer, &args);
    defer allocator.free(calldata);

    // 4 bytes selector + 2 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 68), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xa9, 0x05, 0x9c, 0xbb }, calldata[0..4]);
}

test "ERC20 balanceOf encodes correctly" {
    const allocator = std.testing.allocator;
    var holder: [20]u8 = [_]u8{0} ** 20;
    holder[0] = 0xd8;
    holder[19] = 0x45;

    const args = [_]AbiValue{.{ .address = holder }};
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.balanceOf, &args);
    defer allocator.free(calldata);

    try std.testing.expectEqual(@as(usize, 36), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, calldata[0..4]);
}

test "ERC20 approve encodes correctly" {
    const allocator = std.testing.allocator;
    var spender: [20]u8 = [_]u8{0} ** 20;
    spender[19] = 0x02;

    const args = [_]AbiValue{ .{ .address = spender }, .{ .uint256 = 500 } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.approve, &args);
    defer allocator.free(calldata);

    try std.testing.expectEqual(@as(usize, 68), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x5e, 0xa7, 0xb3 }, calldata[0..4]);
}

test "ERC20 transferFrom encodes correctly" {
    const allocator = std.testing.allocator;
    var from: [20]u8 = [_]u8{0} ** 20;
    from[19] = 0x01;
    var to: [20]u8 = [_]u8{0} ** 20;
    to[19] = 0x02;

    const args = [_]AbiValue{ .{ .address = from }, .{ .address = to }, .{ .uint256 = 100 } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.transferFrom, &args);
    defer allocator.free(calldata);

    // 4 bytes selector + 3 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 100), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0xb8, 0x72, 0xdd }, calldata[0..4]);
}

test "ERC20 allowance encodes correctly" {
    const allocator = std.testing.allocator;
    var owner: [20]u8 = [_]u8{0} ** 20;
    owner[19] = 0x01;
    var spender: [20]u8 = [_]u8{0} ** 20;
    spender[19] = 0x02;

    const args = [_]AbiValue{ .{ .address = owner }, .{ .address = spender } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.allowance, &args);
    defer allocator.free(calldata);

    // 4 bytes selector + 2 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 68), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xdd, 0x62, 0xed, 0x3e }, calldata[0..4]);
}
