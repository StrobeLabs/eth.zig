# Conformance vectors

This directory contains a small, reviewed subset of upstream Ethereum
conformance data used by `zig build conformance-test`.

- RLP cases are selected from [`ethereum/tests/RLPTests`](https://github.com/ethereum/tests/tree/develop/RLPTests).
- Transaction envelopes are selected from [`ethereum/tests/TransactionTests`](https://github.com/ethereum/tests/tree/develop/TransactionTests).
- BIP-39 English vectors are selected from [`trezor/python-mnemonic`](https://github.com/trezor/python-mnemonic/blob/master/vectors.json).

The upstream repositories and their licenses remain the authoritative source.
The files here intentionally keep only the fields needed by this project so
CI stays fast and the fixture provenance remains easy to audit.

The transaction fixtures cover legacy, EIP-2930, and EIP-1559 envelopes. The
library's existing transaction tests cover EIP-4844 serialization; a follow-up
can add execution-spec-tests fixtures once a small redistributable subset is
settled on.

