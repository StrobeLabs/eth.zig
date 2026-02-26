/// Shared test vectors for alloy.rs benchmarks.
/// All values are identical to those used in eth-zig's bench/bench.zig.

use alloy_primitives::{address, Address, B256, U256};

/// Anvil account 0 private key
pub const TEST_PRIVKEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
    0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
    0xff, 0x80,
];

/// keccak256("") -- well-known hash
pub const TEST_MSG_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
    0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
    0xa4, 0x70,
];

/// Derived address from TEST_PRIVKEY
pub const TEST_ADDR: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// 1 ETH in wei
pub const ONE_ETH: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

/// UniswapV2 test reserves
pub const RESERVE_IN: U256 = U256::from_limbs([100_000_000_000_000_000_000u128 as u64, 5, 0, 0]);
pub const RESERVE_OUT: U256 = U256::from_limbs([200_000_000_000u64, 0, 0, 0]);

/// Keccak test inputs
pub const KECCAK_256B: [u8; 256] = [0xAB; 256];
pub const KECCAK_1KB: [u8; 1024] = [0xAB; 1024];
pub const KECCAK_4KB: [u8; 4096] = [0xAB; 4096];

/// Dynamic ABI test data
pub const ABI_DYNAMIC_STRING: &str = "The quick brown fox jumps over the lazy dog";
pub const ABI_DYNAMIC_BYTES: &[u8] =
    b"hello world, this is a dynamic bytes benchmark test payload";

/// Hex test data
pub const HEX_STRING_32B: &str =
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

pub const ADDRESS_HEX: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Helper: B256 from test msg hash
pub fn test_msg_hash_b256() -> B256 {
    B256::from(TEST_MSG_HASH)
}
