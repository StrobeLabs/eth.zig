// eth.zig - Pure Zig Ethereum Client Library
// Maintained by Strobe Labs (https://github.com/strobelabs/eth.zig)

// -- Layer 1: Primitives --
pub const primitives = @import("primitives.zig");
pub const uint256 = @import("uint256.zig");
pub const hex = @import("hex.zig");

// -- Layer 2: Encoding --
pub const rlp = @import("rlp.zig");
pub const keccak = @import("keccak.zig");
pub const abi_types = @import("abi_types.zig");
pub const abi_encode = @import("abi_encode.zig");
pub const abi_decode = @import("abi_decode.zig");
pub const abi_comptime = @import("abi_comptime.zig");

// -- Layer 3: Crypto --
pub const signature = @import("signature.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const signer = @import("signer.zig");
pub const eip155 = @import("eip155.zig");

// -- Layer 4: Types --
pub const access_list = @import("access_list.zig");
pub const transaction = @import("transaction.zig");
pub const receipt = @import("receipt.zig");
pub const block = @import("block.zig");
pub const blob = @import("blob.zig");

// -- Layer 5: Accounts --
pub const mnemonic = @import("mnemonic.zig");
pub const hd_wallet = @import("hd_wallet.zig");

// -- Layer 6: Transport --
pub const json_rpc = @import("json_rpc.zig");
pub const http_transport = @import("http_transport.zig");
pub const ws_transport = @import("ws_transport.zig");
pub const subscription = @import("subscription.zig");
pub const provider = @import("provider.zig");

// -- Layer 7: ENS --
pub const ens_namehash = @import("ens/namehash.zig");
pub const ens_resolver = @import("ens/resolver.zig");
pub const ens_reverse = @import("ens/reverse.zig");

// -- Layer 8: Client --
pub const wallet = @import("wallet.zig");
pub const contract = @import("contract.zig");
pub const multicall = @import("multicall.zig");
pub const event = @import("event.zig");
pub const erc20 = @import("erc20.zig");
pub const erc721 = @import("erc721.zig");

// -- Layer 9: Standards --
pub const eip712 = @import("eip712.zig");
pub const abi_json = @import("abi_json.zig");

// -- Layer 10: Chains --
pub const chains = @import("chains/chain.zig");

// -- Utilities --
pub const units = @import("utils/units.zig");
pub const constants = @import("utils/constants.zig");

// Re-export common types for convenience
pub const Address = primitives.Address;
pub const Hash = primitives.Hash;
pub const Bytes32 = primitives.Bytes32;

// Compile all tests
test {
    // Layer 1
    _ = @import("hex.zig");
    _ = @import("keccak.zig");
    _ = @import("uint256.zig");
    _ = @import("primitives.zig");
    // Layer 2
    _ = @import("rlp.zig");
    _ = @import("abi_types.zig");
    _ = @import("abi_encode.zig");
    _ = @import("abi_decode.zig");
    _ = @import("abi_comptime.zig");
    // Layer 3
    _ = @import("signature.zig");
    _ = @import("secp256k1.zig");
    _ = @import("signer.zig");
    _ = @import("eip155.zig");
    // Layer 4
    _ = @import("access_list.zig");
    _ = @import("transaction.zig");
    _ = @import("receipt.zig");
    _ = @import("block.zig");
    _ = @import("blob.zig");
    // Layer 5
    _ = @import("mnemonic.zig");
    _ = @import("hd_wallet.zig");
    // Layer 6
    _ = @import("json_rpc.zig");
    _ = @import("http_transport.zig");
    _ = @import("ws_transport.zig");
    _ = @import("subscription.zig");
    _ = @import("provider.zig");
    // Layer 7: Client
    _ = @import("wallet.zig");
    _ = @import("contract.zig");
    _ = @import("multicall.zig");
    _ = @import("event.zig");
    _ = @import("erc20.zig");
    _ = @import("erc721.zig");
    // Layer 9
    _ = @import("eip712.zig");
    _ = @import("abi_json.zig");
    // Layer 10
    _ = @import("chains/chain.zig");
    _ = @import("chains/ethereum.zig");
    _ = @import("chains/arbitrum.zig");
    _ = @import("chains/optimism.zig");
    _ = @import("chains/base.zig");
    _ = @import("chains/polygon.zig");
    // ENS
    _ = @import("ens/namehash.zig");
    _ = @import("ens/resolver.zig");
    _ = @import("ens/reverse.zig");
    // Utils
    _ = @import("utils/units.zig");
}
