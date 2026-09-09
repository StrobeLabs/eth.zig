#include "eth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CHECK remains active in release builds, unlike assert under NDEBUG. */
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); \
} } while (0)

static void unhex(const char *hex, uint8_t *out, size_t len) {
    CHECK(strlen(hex) == len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte = 0;
        CHECK(sscanf(hex + i * 2, "%2x", &byte) == 1);
        out[i] = (uint8_t)byte;
    }
}

static void word(uint8_t out[32], uint64_t n) {
    memset(out, 0, 32);
    for (size_t i = 0; i < 8; ++i) { out[31 - i] = (uint8_t)n; n >>= 8; }
}

static void crypto(void) {
    uint8_t expected[32], hash[32], key[32] = {0}, sig[65], address[20];
    char checksum[43];
    unhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", expected, 32);
    CHECK(eth_keccak256(NULL, 0, hash) == ETH_OK);
    CHECK(memcmp(hash, expected, 32) == 0);
    CHECK(eth_keccak256(NULL, 1, hash) == ETH_ERR_INVALID_ARGUMENT);
    CHECK(eth_keccak256(NULL, 0, NULL) == ETH_ERR_INVALID_ARGUMENT);
    CHECK(eth_sign(key, hash, sig) == ETH_ERR_INVALID_KEY);
    key[31] = 1;
    CHECK(eth_sign(key, hash, sig) == ETH_OK);
    CHECK(sig[64] <= 1);
    CHECK(eth_recover(sig, hash, address) == ETH_OK);
    CHECK(eth_address_checksum(address, checksum) == ETH_OK);
    CHECK(strcmp(checksum, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") == 0);
    sig[64] = 27;
    CHECK(eth_recover(sig, hash, address) == ETH_ERR_INVALID_SIGNATURE);
    uint8_t pubkey[65];
    unhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", pubkey, 65);
    CHECK(eth_address_from_pubkey(pubkey, address) == ETH_OK);
    CHECK(eth_address_checksum(address, checksum) == ETH_OK);
    CHECK(strcmp(checksum, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") == 0);
    memset(pubkey, 0, sizeof(pubkey));
    CHECK(eth_address_from_pubkey(pubkey, address) == ETH_ERR_INVALID_ARGUMENT);
}

static void transaction(void) {
    /* Same independent viem vector as wallet.zig: exact bytes AND tx hash. */
    uint8_t key[32], data[] = {0xa9, 0x05, 0x9c, 0xbb}, expected[115], hash[32], expected_hash[32];
    unhex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", key, 32);
    eth_eip1559_tx tx = {0};
    tx.chain_id = 1; tx.nonce = 5; tx.gas_limit = 100000; tx.has_to = 1;
    memset(tx.to, 0xaa, 20);
    word(tx.max_priority_fee_per_gas, 2000000000ULL);
    word(tx.max_fee_per_gas, 50000000000ULL);
    tx.data = data; tx.data_len = sizeof(data);
    size_t cap = eth_tx_sign_max_len(&tx), written = 99;
    CHECK(cap > 0);
    uint8_t *out = malloc(cap + 1);
    CHECK(out != NULL);
    out[cap] = 0xa5;
    CHECK(eth_tx_sign(&tx, key, out, cap - 1, &written) == ETH_ERR_BUFFER_TOO_SMALL);
    CHECK(written == 0);
    CHECK(eth_tx_sign(&tx, key, out, cap, &written) == ETH_OK);
    unhex("02f87001058477359400850ba43b7400830186a094aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8084a9059cbbc001a096c40667fc8d708d1e2c548918533b952881d0f92aad790fa0e5d5d7fe2e0643a06e7d62e317516b359c31c63dbb0e9fb73d06ecf473f5f013211cdab71db3198c", expected, 115);
    CHECK(written == sizeof(expected));
    CHECK(memcmp(out, expected, written) == 0);
    CHECK(out[cap] == 0xa5);
    CHECK(eth_tx_hash(out, written, hash) == ETH_OK);
    unhex("7a8921f4543662f78b5ff4917258d8a32ce704a3df7dc9789b24000dce29afab", expected_hash, 32);
    CHECK(memcmp(hash, expected_hash, 32) == 0);
    CHECK(eth_tx_sign(NULL, key, out, cap, &written) == ETH_ERR_INVALID_ARGUMENT);
    free(out);

    /* Full access-list translation, dynamic payload, contract creation. */
    uint8_t keys[2][32] = {{0}, {0}};
    keys[0][31] = 1; keys[1][31] = 2;
    eth_access_list_item item = {0};
    memset(item.address, 0xbb, 20);
    item.storage_keys = keys; item.storage_keys_len = 2;
    tx.access_list = &item; tx.access_list_len = 1; tx.has_to = 0;
    uint8_t large[8192]; memset(large, 0xab, sizeof(large));
    tx.data = large; tx.data_len = sizeof(large);
    cap = eth_tx_sign_max_len(&tx);
    CHECK(cap > sizeof(large));
    out = malloc(cap + 1); CHECK(out != NULL); out[cap] = 0xa5;
    CHECK(eth_tx_sign(&tx, key, out, cap, &written) == ETH_OK);
    CHECK(written > sizeof(large)); CHECK(out[cap] == 0xa5);
    free(out);
    tx.has_to = 2;
    CHECK(eth_tx_sign_max_len(&tx) == 0);
    tx.has_to = 0; tx.data_len = SIZE_MAX;
    CHECK(eth_tx_sign_max_len(&tx) == 0);
}

static void abi(void) {
    uint8_t selector[4];
    CHECK(eth_abi_selector("transfer(address,uint256)", selector) == ETH_OK);
    CHECK(memcmp(selector, "\xa9\x05\x9c\xbb", 4) == 0);
    eth_abi_value values[7] = {0}, decoded[7];
    int types[] = {ETH_ABI_UINT256, ETH_ABI_INT256, ETH_ABI_ADDRESS, ETH_ABI_BOOL,
                   ETH_ABI_BYTES32, ETH_ABI_BYTES, ETH_ABI_STRING};
    for (size_t i = 0; i < 7; ++i) values[i].type = types[i];
    word(values[0].word, 123);
    memset(values[1].word, 0xff, 32);
    memset(values[2].word + 12, 0xab, 20);
    word(values[3].word, 1);
    memset(values[4].word, 0xcc, 32);
    values[5].data = (const uint8_t *)"\0\1\2"; values[5].data_len = 3;
    values[6].data = (const uint8_t *)"hello"; values[6].data_len = 5;
    size_t cap = eth_abi_encode_max_len(values, 7), written;
    uint8_t *encoded = malloc(cap + 1); CHECK(encoded != NULL); encoded[cap] = 0xa5;
    CHECK(eth_abi_encode(values, 7, encoded, cap - 1, &written) == ETH_ERR_BUFFER_TOO_SMALL);
    CHECK(written == 0);
    CHECK(eth_abi_encode(values, 7, encoded, cap, &written) == ETH_OK);
    CHECK(written == 352); CHECK(encoded[cap] == 0xa5);
    /* Pin dynamic offsets against the Solidity ABI layout, not just a roundtrip. */
    CHECK(encoded[5 * 32 + 31] == 224);
    CHECK(encoded[6 * 32 + 30] == 1 && encoded[6 * 32 + 31] == 32);
    size_t storage_cap = eth_abi_decode_max_len(written, 7), used;
    uint8_t *storage = malloc(storage_cap + 1); CHECK(storage != NULL); storage[storage_cap] = 0xa5;
    CHECK(eth_abi_decode(encoded, written, types, 7, decoded, storage, 0, &used) == ETH_ERR_BUFFER_TOO_SMALL);
    CHECK(used == 0);
    CHECK(eth_abi_decode(encoded, written, types, 7, decoded, storage, storage_cap, &used) == ETH_OK);
    CHECK(storage[storage_cap] == 0xa5);
    for (size_t i = 0; i < 5; ++i) CHECK(memcmp(decoded[i].word, values[i].word, 32) == 0);
    for (size_t i = 5; i < 7; ++i) {
        CHECK(decoded[i].data_len == values[i].data_len);
        CHECK(memcmp(decoded[i].data, values[i].data, values[i].data_len) == 0);
    }
    memset(encoded + 5 * 32, 0xff, 32);
    CHECK(eth_abi_decode(encoded, written, types, 7, decoded, storage, storage_cap, &used) == ETH_ERR_INVALID_ENCODING);
    CHECK(used == 0);
    free(storage); free(encoded);
    values[0].type = 99;
    CHECK(eth_abi_encode_max_len(values, 1) == 0);
    CHECK(eth_abi_decode_max_len(SIZE_MAX, 2) == 0);
    CHECK(eth_abi_encode_max_len(NULL, 33) == 0);
    CHECK(eth_abi_encode(NULL, 0, NULL, 0, &written) == ETH_OK);
    CHECK(written == 0);
}

static void rlp_roundtrip(void) {
    uint8_t out[128], decoded[128]; size_t written, used, n; int kind;
    CHECK(eth_rlp_encode(ETH_RLP_STRING, (const uint8_t *)"dog", 3, out, sizeof(out), &written) == ETH_OK);
    CHECK(written == 4 && memcmp(out, "\x83" "dog", 4) == 0);
    CHECK(eth_rlp_decode(out, written, &kind, decoded, sizeof(decoded), &n, &used) == ETH_OK);
    CHECK(kind == ETH_RLP_STRING && n == 3 && used == 4 && memcmp(decoded, "dog", 3) == 0);
    const uint8_t list[] = {0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'};
    CHECK(eth_rlp_encode(ETH_RLP_LIST, list, sizeof(list), out, sizeof(out), &written) == ETH_OK);
    CHECK(out[0] == 0xc8 && written == 9);
    CHECK(eth_rlp_decode(out, written, &kind, decoded, sizeof(decoded), &n, &used) == ETH_OK);
    CHECK(kind == ETH_RLP_LIST && n == 8 && memcmp(decoded, list, 8) == 0);
    CHECK(eth_rlp_decode(decoded, n, &kind, out, sizeof(out), &written, &used) == ETH_OK);
    CHECK(used == 4 && written == 3 && memcmp(out, "cat", 3) == 0);
    const uint8_t bad[] = {0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    CHECK(eth_rlp_decode(bad, sizeof(bad), &kind, out, sizeof(out), &written, &used) == ETH_ERR_INVALID_ENCODING);
    CHECK(written == 0 && used == 0);
    CHECK(eth_rlp_decode((const uint8_t *)"\x81\x01", 2, &kind, out, sizeof(out), &written, &used) == ETH_ERR_INVALID_ENCODING);
    CHECK(eth_rlp_encode_max_len(SIZE_MAX) == 0);
}

int main(void) {
    crypto(); transaction(); abi(); rlp_roundtrip();
    puts("C ABI: crypto, transaction vectors, ABI/RLP and error cases passed");
    return 0;
}
