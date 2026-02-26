const eth = @import("eth");

// Pull in all module tests
test {
    // Layer 1: Primitives
    _ = eth.hex;
    _ = eth.keccak;
    _ = eth.uint256;
    _ = eth.primitives;
    // Layer 2: Encoding
    _ = eth.rlp;
    _ = eth.abi_types;
    _ = eth.abi_encode;
    _ = eth.abi_decode;
    _ = eth.abi_comptime;
    // Layer 3: Crypto
    _ = eth.signature;
    // Layer 4: Types
    _ = eth.access_list;
    _ = eth.transaction;
    _ = eth.receipt;
    _ = eth.block;
    _ = eth.blob;
    // Layer 5: Accounts
    _ = eth.mnemonic;
    _ = eth.hd_wallet;
    // Layer 6: Transport
    _ = eth.json_rpc;
    _ = eth.ws_transport;
    _ = eth.subscription;
    _ = eth.provider;
    // Layer 7: Client
    _ = eth.wallet;
    _ = eth.contract;
    _ = eth.multicall;
    _ = eth.event;
    _ = eth.erc20;
    _ = eth.erc721;
    // Layer 9: Standards
    _ = eth.eip712;
    _ = eth.abi_json;
    // Layer 10: Chains
    _ = eth.chains;
    // Utils
    _ = eth.units;
}
