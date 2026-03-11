const primitives = @import("../primitives.zig");

/// Maximum u256 value (2^256 - 1).
pub const MAX_UINT256: u256 = @import("std").math.maxInt(u256);

/// Zero u256.
pub const ZERO_UINT256: u256 = 0;

/// Zero address (0x0000...0000).
pub const ZERO_ADDRESS: primitives.Address = primitives.ZERO_ADDRESS;

/// Zero hash (0x0000...0000).
pub const ZERO_HASH: primitives.Hash = primitives.ZERO_HASH;

/// Securely zero a buffer using volatile writes to prevent compiler elision.
/// Use this to clear sensitive data (private keys, seeds, nonces) from memory.
pub fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const volatile_ptr: *volatile u8 = b;
        volatile_ptr.* = 0;
    }
}
