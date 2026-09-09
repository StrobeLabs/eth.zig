#ifndef ETHZIG_H
#define ETHZIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI version 1. Incompatible changes require a shared-library major bump.
 * All integers wider than 64 bits are big-endian byte arrays.
 * No function retains caller pointers. Results and serialization workspace
 * are caller-owned; secp256k1 lazily allocates its shared backend context.
 * Calls may run concurrently with separate output and workspace buffers.
 * Input and output buffers must not overlap. NULL is allowed for a byte
 * buffer only if len=0.
 * On failure, output contents are unspecified and written is zero.
 * max_len helpers include workspace and return 0 on invalid input/overflow.
 */
#define ETH_ABI_VERSION 1
#define ETH_ABI_MAX_VALUES 32

typedef enum {
    ETH_OK = 0,
    ETH_ERR_BUFFER_TOO_SMALL = -1,
    ETH_ERR_INVALID_ARGUMENT = -2,
    ETH_ERR_INVALID_KEY = -3,
    ETH_ERR_INVALID_SIGNATURE = -4,
    ETH_ERR_INVALID_ENCODING = -5,
    ETH_ERR_UNSUPPORTED = -6,
    ETH_ERR_OVERFLOW = -7,
    ETH_ERR_CRYPTO = -8
} eth_error;

int eth_keccak256(const uint8_t *data, size_t len, uint8_t out[32]);
/* Uncompressed SEC1 public key, including the 0x04 prefix. */
int eth_address_from_pubkey(const uint8_t pubkey[65], uint8_t out[20]);
int eth_address_checksum(const uint8_t address[20], char out[43]);
/* Signature layout: r[32] || s[32] || recovery_id[1], where id is 0 or 1. */
int eth_sign(const uint8_t key[32], const uint8_t hash[32], uint8_t out[65]);
int eth_recover(const uint8_t signature[65], const uint8_t hash[32], uint8_t out[20]);

typedef struct {
    uint8_t address[20];
    const uint8_t (*storage_keys)[32];
    size_t storage_keys_len;
} eth_access_list_item;

typedef struct {
    uint64_t chain_id;
    uint64_t nonce;
    uint8_t max_priority_fee_per_gas[32];
    uint8_t max_fee_per_gas[32];
    uint64_t gas_limit;
    uint8_t to[20];
    uint8_t has_to; /* 0 for contract creation, 1 otherwise */
    uint8_t value[32];
    const uint8_t *data;
    size_t data_len;
    const eth_access_list_item *access_list;
    size_t access_list_len;
} eth_eip1559_tx;

size_t eth_tx_sign_max_len(const eth_eip1559_tx *tx);
/* Writes a signed type-2 transaction ready for eth_sendRawTransaction. */
int eth_tx_sign(const eth_eip1559_tx *tx, const uint8_t key[32],
                uint8_t *out, size_t capacity, size_t *written);
/* Hash of serialized signed transaction bytes, not the signing preimage. */
int eth_tx_hash(const uint8_t *signed_tx, size_t len, uint8_t out[32]);

typedef enum {
    ETH_ABI_UINT256 = 0, ETH_ABI_INT256 = 1, ETH_ABI_ADDRESS = 2,
    ETH_ABI_BOOL = 3, ETH_ABI_BYTES32 = 4, ETH_ABI_BYTES = 5,
    ETH_ABI_STRING = 6
} eth_abi_type;

/* A flat tuple of up to ETH_ABI_MAX_VALUES scalar/bytes/string values.
 * word: big-endian integers, right-aligned address/bool, or bytes32.
 * data/data_len: bytes/string only. Arrays and nested tuples are unsupported.
 * Decode writes dynamic payloads into the caller's storage buffer and sets
 * data to that buffer; word values require no additional storage.
 */
typedef struct {
    int type;
    uint8_t word[32];
    const uint8_t *data;
    size_t data_len;
} eth_abi_value;

int eth_abi_selector(const char *signature, uint8_t out[4]);
size_t eth_abi_encode_max_len(const eth_abi_value *values, size_t count);
int eth_abi_encode(const eth_abi_value *values, size_t count,
                   uint8_t *out, size_t capacity, size_t *written);
/* Storage includes temporary Zig values. Input is untrusted ABI bytes. */
size_t eth_abi_decode_max_len(size_t encoded_len, size_t count);
int eth_abi_decode(const uint8_t *encoded, size_t len, const int *types,
                   size_t count, eth_abi_value *out_values,
                   uint8_t *storage, size_t storage_capacity, size_t *written);

typedef enum { ETH_RLP_STRING = 0, ETH_RLP_LIST = 1 } eth_rlp_kind;
/* A list payload is a concatenation of already encoded RLP items. Decode
 * unwraps one item, writes its payload, and reports how much input it used.
 * This permits arbitrary nesting without imposing a C tree representation.
 */
size_t eth_rlp_encode_max_len(size_t payload_len);
int eth_rlp_encode(int kind, const uint8_t *payload, size_t len,
                   uint8_t *out, size_t capacity, size_t *written);
size_t eth_rlp_decode_max_len(size_t encoded_len);
int eth_rlp_decode(const uint8_t *encoded, size_t len, int *kind,
                   uint8_t *out, size_t capacity, size_t *written, size_t *consumed);

#ifdef __cplusplus
}
#endif
#endif
