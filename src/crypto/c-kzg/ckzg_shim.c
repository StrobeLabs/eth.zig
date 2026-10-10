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

/*
 * The sizes that determine how large the buffers src/kzg.zig hands to c-kzg
 * must be. The C code writes exactly CELLS_PER_EXT_BLOB cells and proofs into
 * caller-provided arrays, so a mismatch between these macros and the Zig
 * constants is the same class of memory-corruption bug the settings size
 * above exists to rule out. src/kzg.zig asserts each one against its own
 * constant in a test.
 */

size_t ethzig_kzg_cells_per_ext_blob(void) {
    return CELLS_PER_EXT_BLOB;
}

size_t ethzig_kzg_bytes_per_cell(void) {
    return BYTES_PER_CELL;
}

size_t ethzig_kzg_field_elements_per_cell(void) {
    return FIELD_ELEMENTS_PER_CELL;
}

size_t ethzig_kzg_field_elements_per_blob(void) {
    return FIELD_ELEMENTS_PER_BLOB;
}

size_t ethzig_kzg_bytes_per_blob(void) {
    return BYTES_PER_BLOB;
}

size_t ethzig_kzg_bytes_per_commitment(void) {
    return BYTES_PER_COMMITMENT;
}

size_t ethzig_kzg_bytes_per_proof(void) {
    return BYTES_PER_PROOF;
}

size_t ethzig_kzg_bytes_per_field_element(void) {
    return BYTES_PER_FIELD_ELEMENT;
}
