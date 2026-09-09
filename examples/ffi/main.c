#include "eth.h"
#include <stdio.h>

int main(void) {
    uint8_t hash[32];
    if (eth_keccak256((const uint8_t *)"hello", 5, hash) != ETH_OK) return 1;
    for (size_t i = 0; i < sizeof(hash); ++i) printf("%02x", hash[i]);
    puts("");
    return 0;
}
