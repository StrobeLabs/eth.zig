# Use eth.zig from C or Python

Build with **Zig 0.16.0**, from the repository root:

```sh
zig build c-lib -Doptimize=ReleaseSafe
zig build c-test
python3 examples/ffi/sign_transaction.py
zig cc examples/ffi/main.c -I zig-out/include zig-out/lib/libethzig.a -o zig-out/ffi-example
./zig-out/ffi-example
```

The Python example uses only `ctypes` from the standard library. It signs an
EIP-1559 transaction offline and checks its hash against an independent vector.
There are no RPC requests, accounts to create, or packages to install.

The artifacts are `zig-out/include/eth.h`, `zig-out/lib/libethzig.a`, and a
versioned shared library (`libethzig.so.1` or `libethzig.1.dylib`). Applications
must deploy the shared library alongside their binding, or link the archive.
Build with `-Dcpu=baseline` for redistribution across machines with the same
architecture. This interface has its own ABI major version, 1; it is separate
from the Zig package's release version. An incompatible header change requires
a shared-library major version change.

## Buffer and type contract

All buffers belong to the caller. No allocation or free crosses the language
boundary, and the library does not retain pointers. Input and output buffers
must not overlap. For each variable-size operation, call its `*_max_len` helper,
allocate that capacity, and pass a `size_t` for the result length. Zero from a
size helper means invalid input or overflow. On errors, the result length is
zero and the buffer contents are unspecified.

Signing and recovery reuse the existing secp256k1 backend, which lazily
allocates a process-wide context on first use. This is not a heap-free crypto
backend; the context is internal and has no caller-visible ownership.

Transaction capacity includes temporary access-list metadata and serialization
workspace. Only `out[0..written]` is the signed transaction. Big integers use
32-byte **big-endian** arrays, not host-endian limbs. Signatures contain `r`,
`s`, and a final recovery byte of **0 or 1**. Transactions support destinations,
contract creation, arbitrary calldata, and access lists.

ABI functions support flat tuples of up to 32 values: uint256, int256, address,
bool, bytes32, bytes, and string. Arrays and nested tuples are not in this first
C interface. Decode writes dynamic payloads into the supplied storage; keep it
alive while using the returned value descriptors. RLP functions wrap/unwrap
one string or list envelope; concatenate encoded children to build a list,
and use `consumed` to walk its payload. Integer-to-minimal-byte conversion is
the caller's responsibility for generic RLP payloads (zero is empty bytes).

The native core performs signing, hashing, and encoding. Use your language's
HTTP client for network requests. Published Python, Node, and Go packages can
build on this header once the interface has been reviewed.
