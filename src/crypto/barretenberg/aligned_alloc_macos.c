/*
 * Strong C11 `aligned_alloc` for macOS builds that link Barretenberg.
 *
 * Barretenberg's common/mem.hpp defines its own `aligned_alloc` (a
 * posix_memalign wrapper) as an inline function in the global namespace on
 * Apple targets. Because <stdlib.h> already declares the C11 function, that
 * definition takes C linkage and is emitted into every archive member as a
 * weak, hidden ("weak private external") symbol. Zig's self-hosted Mach-O
 * linker resolves the archive's references to libSystem's exported
 * `aligned_alloc` instead of to the archive's own definition; Apple's ld binds
 * them to the archive copy. libSystem's implementation is strict C11 and
 * returns NULL when `size` is not a multiple of `alignment`, and Barretenberg
 * calls it with sizes such as aligned_alloc(64, 19) when packing msgpack
 * responses, so the first `bbapi` call would dereference NULL.
 *
 * Defining a strong, exported `aligned_alloc` in the executable makes every
 * reference bind here instead. The implementation rounds `size` up to a
 * multiple of `alignment` (so it also satisfies strict C11 callers) and
 * delegates to posix_memalign; the memory is released with free()/bbfree as
 * usual. This file is compiled only for macOS targets and only when the build
 * links Barretenberg (-Dnoir=true); see build.zig.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void *aligned_alloc(size_t alignment, size_t size) {
    /* posix_memalign requires a power of two that is a multiple of sizeof(void *). */
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        errno = EINVAL;
        return NULL;
    }
    if (alignment < sizeof(void *)) {
        alignment = sizeof(void *);
    }
    size_t remainder = size % alignment;
    if (remainder != 0) {
        size_t padding = alignment - remainder;
        if (size > SIZE_MAX - padding) {
            errno = ENOMEM;
            return NULL;
        }
        size += padding;
    }
    if (size == 0) {
        size = alignment;
    }
    void *ptr = NULL;
    int rc = posix_memalign(&ptr, alignment, size);
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    return ptr;
}
