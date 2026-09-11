/*
 * eth.zig-owned shim over the vendored c-kzg-4844 sources (not part of the
 * upstream release; see VENDOR.md).
 *
 * src/kzg.zig never mirrors the layout of c-kzg's KZGSettings. It treats the
 * struct as opaque and sizes its storage at run time from these two
 * functions, so an upstream field addition can never silently corrupt memory:
 * the storage is always exactly as large and as aligned as the C code that
 * writes into it expects.
 */

#include <stddef.h>

#include "ckzg.h"

size_t ethzig_kzg_settings_size(void) {
    return sizeof(KZGSettings);
}

size_t ethzig_kzg_settings_align(void) {
    return _Alignof(KZGSettings);
}
