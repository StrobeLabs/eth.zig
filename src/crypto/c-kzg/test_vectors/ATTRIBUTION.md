# KZG test vectors

These YAML files are vendored verbatim from the official c-kzg-4844 test suite:

- Source: https://github.com/ethereum/c-kzg-4844
- Version: v2.1.1 (commit 28743bc8a2d89d737e63e8d9ca63fe23fdccdd80)
- Path in upstream: `tests/<function>/kzg-mainnet/<case>/data.yaml`

All four cases share the case id `19b3f3f8c98ea31e` so they exercise the same
non-trivial mainnet blob across functions:

| File | Upstream case |
| --- | --- |
| `blob_to_kzg_commitment_19b3f3f8c98ea31e.yaml` | `blob_to_kzg_commitment/kzg-mainnet/blob_to_kzg_commitment_case_valid_blob_19b3f3f8c98ea31e` |
| `compute_blob_kzg_proof_19b3f3f8c98ea31e.yaml` | `compute_blob_kzg_proof/kzg-mainnet/compute_blob_kzg_proof_case_valid_blob_19b3f3f8c98ea31e` |
| `verify_blob_kzg_proof_correct_19b3f3f8c98ea31e.yaml` | `verify_blob_kzg_proof/kzg-mainnet/verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e` |
| `verify_blob_kzg_proof_incorrect_19b3f3f8c98ea31e.yaml` | `verify_blob_kzg_proof/kzg-mainnet/verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e` |

These files live inside the package (under `src/`) so `@embedFile` can reach
them. The `src/kzg_vectors_test.zig` test parses the
`blob`/`commitment`/`proof`/`output` fields out of these files and asserts our
c-kzg-4844 + blst bindings reproduce the official commitment and proof bytes
byte-for-byte, and that the verify cases return the official true/false result.
