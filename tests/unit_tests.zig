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
    // Layer 3: Crypto
    _ = eth.signature;
    _ = eth.secp256k1;
    _ = eth.signer;
    _ = eth.eip155;
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
    _ = eth.http_transport;
    _ = eth.ws_transport;
    _ = eth.subscription;
    _ = eth.provider;
    // Layer 7: ENS
    _ = eth.ens_namehash;
    _ = eth.ens_resolver;
    _ = eth.ens_reverse;
    // Layer 8: Client
    _ = eth.wallet;
    _ = eth.flashbots;
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
    // DEX Math
    _ = eth.dex_v2;
    _ = eth.dex_v3;
    _ = eth.dex_router;
    // Utils
    _ = eth.units;
    _ = eth.constants;
    // Middleware
    _ = eth.retry_provider;
}
