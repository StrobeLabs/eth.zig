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

/// Comptime-computed ERC-721 function selectors.
pub const selectors = struct {
    pub const name = abi_comptime.comptimeSelector("name()");
    pub const symbol = abi_comptime.comptimeSelector("symbol()");
    pub const tokenURI = abi_comptime.comptimeSelector("tokenURI(uint256)");
    pub const balanceOf = abi_comptime.comptimeSelector("balanceOf(address)");
    pub const ownerOf = abi_comptime.comptimeSelector("ownerOf(uint256)");
    pub const getApproved = abi_comptime.comptimeSelector("getApproved(uint256)");
    pub const isApprovedForAll = abi_comptime.comptimeSelector("isApprovedForAll(address,address)");
    pub const transferFrom = abi_comptime.comptimeSelector("transferFrom(address,address,uint256)");
    pub const safeTransferFrom = abi_comptime.comptimeSelector("safeTransferFrom(address,address,uint256)");
    pub const approve = abi_comptime.comptimeSelector("approve(address,uint256)");
    pub const setApprovalForAll = abi_comptime.comptimeSelector("setApprovalForAll(address,bool)");
};

/// Comptime-computed ERC-721 event topics.
pub const topics = struct {
    pub const Transfer = abi_comptime.comptimeTopic("Transfer(address,address,uint256)");
    pub const Approval = abi_comptime.comptimeTopic("Approval(address,address,uint256)");
    pub const ApprovalForAll = abi_comptime.comptimeTopic("ApprovalForAll(address,address,bool)");
};

/// High-level ERC-721 NFT interface.
/// Wraps a Contract with typed methods for the standard ERC-721 functions.
pub const ERC721 = struct {
    contract: Contract,

    /// Create a new ERC721 instance bound to a token address and provider.
    pub fn init(allocator: std.mem.Allocator, token_address: [20]u8, provider: *provider_mod.Provider) ERC721 {
        return .{
            .contract = Contract.init(allocator, token_address, provider),
        };
    }

    /// Returns the token collection name.
    /// Caller owns the returned string.
    pub fn name(self: *ERC721) ![]const u8 {
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
        const owned = try self.contract.allocator.alloc(u8, s.len);
        @memcpy(owned, s);
        return owned;
    }

    /// Returns the token collection symbol.
    /// Caller owns the returned string.
    pub fn symbol(self: *ERC721) ![]const u8 {
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

    /// Returns the URI for a given token ID.
    /// Caller owns the returned string.
    pub fn tokenURI(self: *ERC721, token_id: u256) ![]const u8 {
        const args = [_]AbiValue{.{ .uint256 = token_id }};
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.tokenURI,
            &args,
            &.{.string},
        );
        defer self.contract.allocator.free(result);
        if (result.len == 0) return error.InvalidResponse;
        const s = result[0].string;
        const owned = try self.contract.allocator.alloc(u8, s.len);
        @memcpy(owned, s);
        return owned;
    }

    /// Returns the number of tokens owned by the given account.
    pub fn balanceOf(self: *ERC721, owner: [20]u8) !u256 {
        const args = [_]AbiValue{.{ .address = owner }};
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

    /// Returns the owner of a given token ID.
    pub fn ownerOf(self: *ERC721, token_id: u256) ![20]u8 {
        const args = [_]AbiValue{.{ .uint256 = token_id }};
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.ownerOf,
            &args,
            &.{.address},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].address;
    }

    /// Returns the approved address for a token ID, or zero address if none.
    pub fn getApproved(self: *ERC721, token_id: u256) ![20]u8 {
        const args = [_]AbiValue{.{ .uint256 = token_id }};
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.getApproved,
            &args,
            &.{.address},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].address;
    }

    /// Returns true if operator is approved to manage all of owner's tokens.
    pub fn isApprovedForAll(self: *ERC721, owner: [20]u8, operator: [20]u8) !bool {
        const args = [_]AbiValue{ .{ .address = owner }, .{ .address = operator } };
        const result = try contract_mod.contractRead(
            self.contract.allocator,
            self.contract.provider,
            self.contract.address,
            selectors.isApprovedForAll,
            &args,
            &.{.bool},
        );
        defer contract_mod.freeReturnValues(result, self.contract.allocator);
        if (result.len == 0) return error.InvalidResponse;
        return result[0].boolean;
    }

    /// Transfer a token from one address to another. Returns the transaction hash.
    pub fn transferFrom(self: *ERC721, wallet: *wallet_mod.Wallet, from: [20]u8, to: [20]u8, token_id: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = from }, .{ .address = to }, .{ .uint256 = token_id } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.transferFrom,
            &args,
        );
    }

    /// Safely transfer a token from one address to another. Returns the transaction hash.
    pub fn safeTransferFrom(self: *ERC721, wallet: *wallet_mod.Wallet, from: [20]u8, to: [20]u8, token_id: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = from }, .{ .address = to }, .{ .uint256 = token_id } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.safeTransferFrom,
            &args,
        );
    }

    /// Approve an address to transfer a specific token. Returns the transaction hash.
    pub fn approve(self: *ERC721, wallet: *wallet_mod.Wallet, to: [20]u8, token_id: u256) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = to }, .{ .uint256 = token_id } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.approve,
            &args,
        );
    }

    /// Approve or revoke an operator for all tokens. Returns the transaction hash.
    pub fn setApprovalForAll(self: *ERC721, wallet: *wallet_mod.Wallet, operator: [20]u8, approved: bool) ![32]u8 {
        const args = [_]AbiValue{ .{ .address = operator }, .{ .boolean = approved } };
        return try contract_mod.contractWrite(
            self.contract.allocator,
            wallet,
            self.contract.address,
            selectors.setApprovalForAll,
            &args,
        );
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ERC721 selectors match known values" {
    // name() = 0x06fdde03
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0xfd, 0xde, 0x03 }, &selectors.name);
    // symbol() = 0x95d89b41
    try std.testing.expectEqualSlices(u8, &.{ 0x95, 0xd8, 0x9b, 0x41 }, &selectors.symbol);
    // balanceOf(address) = 0x70a08231
    try std.testing.expectEqualSlices(u8, &.{ 0x70, 0xa0, 0x82, 0x31 }, &selectors.balanceOf);
    // ownerOf(uint256) = 0x6352211e
    try std.testing.expectEqualSlices(u8, &.{ 0x63, 0x52, 0x21, 0x1e }, &selectors.ownerOf);
    // transferFrom(address,address,uint256) = 0x23b872dd
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0xb8, 0x72, 0xdd }, &selectors.transferFrom);
    // approve(address,uint256) = 0x095ea7b3
    try std.testing.expectEqualSlices(u8, &.{ 0x09, 0x5e, 0xa7, 0xb3 }, &selectors.approve);
    // setApprovalForAll(address,bool) = 0xa22cb465
    try std.testing.expectEqualSlices(u8, &.{ 0xa2, 0x2c, 0xb4, 0x65 }, &selectors.setApprovalForAll);
    // getApproved(uint256) = 0x081812fc
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x18, 0x12, 0xfc }, &selectors.getApproved);
    // isApprovedForAll(address,address) = 0xe985e9c5
    try std.testing.expectEqualSlices(u8, &.{ 0xe9, 0x85, 0xe9, 0xc5 }, &selectors.isApprovedForAll);
    // tokenURI(uint256) = 0xc87b56dd
    try std.testing.expectEqualSlices(u8, &.{ 0xc8, 0x7b, 0x56, 0xdd }, &selectors.tokenURI);
    // safeTransferFrom(address,address,uint256) = 0x42842e0e
    try std.testing.expectEqualSlices(u8, &.{ 0x42, 0x84, 0x2e, 0x0e }, &selectors.safeTransferFrom);
}

test "ERC721 Transfer topic matches ERC20 Transfer topic" {
    // Both ERC-20 and ERC-721 use the same Transfer(address,address,uint256) signature
    const hex_mod = @import("hex.zig");
    const expected = try hex_mod.hexToBytesFixed(32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    try std.testing.expectEqualSlices(u8, &expected, &topics.Transfer);
}

test "ERC721 ApprovalForAll topic matches known value" {
    const hex_mod = @import("hex.zig");
    const expected = try hex_mod.hexToBytesFixed(32, "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31");
    try std.testing.expectEqualSlices(u8, &expected, &topics.ApprovalForAll);
}

test "ERC721.init sets address correctly" {
    const nft_addr = [_]u8{0xbb} ** 20;
    var transport = http_transport_mod.HttpTransport.init(std.testing.allocator, "http://localhost:8545");
    defer transport.deinit();
    var prov = provider_mod.Provider.init(std.testing.allocator, &transport);
    const erc721 = ERC721.init(std.testing.allocator, nft_addr, &prov);

    try std.testing.expectEqualSlices(u8, &nft_addr, &erc721.contract.address);
}

test "ERC721 transferFrom encodes correctly" {
    const allocator = std.testing.allocator;
    var from: [20]u8 = [_]u8{0} ** 20;
    from[19] = 0x01;
    var to: [20]u8 = [_]u8{0} ** 20;
    to[19] = 0x02;

    const args = [_]AbiValue{ .{ .address = from }, .{ .address = to }, .{ .uint256 = 42 } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.transferFrom, &args);
    defer allocator.free(calldata);

    // 4 bytes selector + 3 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 100), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0xb8, 0x72, 0xdd }, calldata[0..4]);
}

test "ERC721 ownerOf encodes correctly" {
    const allocator = std.testing.allocator;
    const args = [_]AbiValue{.{ .uint256 = 1 }};
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.ownerOf, &args);
    defer allocator.free(calldata);

    try std.testing.expectEqual(@as(usize, 36), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x63, 0x52, 0x21, 0x1e }, calldata[0..4]);
}

test "ERC721 setApprovalForAll encodes correctly" {
    const allocator = std.testing.allocator;
    var operator: [20]u8 = [_]u8{0} ** 20;
    operator[19] = 0x03;

    const args = [_]AbiValue{ .{ .address = operator }, .{ .boolean = true } };
    const calldata = try abi_encode.encodeFunctionCall(allocator, selectors.setApprovalForAll, &args);
    defer allocator.free(calldata);

    // 4 bytes selector + 2 * 32 bytes args
    try std.testing.expectEqual(@as(usize, 68), calldata.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xa2, 0x2c, 0xb4, 0x65 }, calldata[0..4]);
}
