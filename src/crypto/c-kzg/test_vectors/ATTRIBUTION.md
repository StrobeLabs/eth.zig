# KZG test vectors

These YAML files are vendored verbatim from the official c-kzg-4844 test suite:

- Source: https://github.com/ethereum/c-kzg-4844
- Version: v2.1.8 (commit e125905e5e01186e6ccb7a0ced4845bf7eddbcfe)
- Path in upstream: `tests/<function>/kzg-mainnet/<case>/data.yaml`

All four cases exercise the same non-trivial mainnet blob across functions
(upstream numbers its generated cases; this blob is case `6` in each suite).
The file contents are byte-identical to the v2.1.1 cases that carried the id
`19b3f3f8c98ea31e` before upstream renamed its generated vectors.

| File | Upstream case |
| --- | --- |
| `blob_to_kzg_commitment_valid_blob_6.yaml` | `blob_to_kzg_commitment/kzg-mainnet/blob_to_kzg_commitment_case_valid_blob_6` |
| `compute_blob_kzg_proof_valid_blob_6.yaml` | `compute_blob_kzg_proof/kzg-mainnet/compute_blob_kzg_proof_case_valid_blob_6` |
| `verify_blob_kzg_proof_correct_proof_6.yaml` | `verify_blob_kzg_proof/kzg-mainnet/verify_blob_kzg_proof_case_correct_proof_6` |
| `verify_blob_kzg_proof_incorrect_proof_6.yaml` | `verify_blob_kzg_proof/kzg-mainnet/verify_blob_kzg_proof_case_incorrect_proof_6` |

These files live inside the package (under `src/`) so `@embedFile` can reach
them. The `src/kzg_vectors_test.zig` test parses the
`blob`/`commitment`/`proof`/`output` fields out of these files and asserts our
c-kzg-4844 + blst bindings reproduce the official commitment and proof bytes
byte-for-byte, and that the verify cases return the official true/false result.
