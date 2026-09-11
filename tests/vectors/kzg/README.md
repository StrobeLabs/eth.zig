# KZG reference vectors (EIP-4844 point evaluation and EIP-7594 cells)

Vendored verbatim from the official ethereum/c-kzg-4844 test suite:

- Source: https://github.com/ethereum/c-kzg-4844
- Tag: **v2.1.8** (commit `e125905e5e01186e6ccb7a0ced4845bf7eddbcfe`)
- Upstream path: `tests/<function>/kzg-mainnet/<case>/data.yaml`, stored here
  as `<function>/<case>.yaml` with the file contents unchanged.

They are consumed by `tests/kzg_vectors_test.zig` (run by `zig build
vector-test`, part of `make ci`), which asserts byte-for-byte agreement of
`eth.kzg` with the reference outputs and the exact accept/reject verdicts.
The EIP-4844 blob vectors used by the unit tests live under
`src/crypto/c-kzg/test_vectors/` (they must sit inside the package for
`@embedFile`); see the `ATTRIBUTION.md` there.

## Selection

The upstream suite is 76 MB; this directory keeps the cases the tests use
(7.3 MiB, 166 files). Every function exposed by `eth.kzg` beyond the four
EIP-4844 blob functions is covered with valid and invalid cases:

| Function | Cases | Size | Notes |
| --- | --- | --- | --- |
| `verify_cell_kzg_proof_batch` | 27 of 32 | 1.2 MiB | All `incorrect_*`, `invalid_*`, `valid_multiple_blobs`, `valid_not_sorted`, `valid_regression1` (a point-at-infinity commitment), `valid_same_cell_multiple_times` (duplicated cells), `valid_zero_cells` (empty batch), plus `valid_0` (zero blob, infinity commitment and proofs) and `valid_1` (random blob). `valid_2`..`valid_6` are further random blobs of the same shape and are omitted (544 KiB each). |
| `recover_cells_and_kzg_proofs` | 9 of 18 | 3.0 MiB | Two valid shapes (`half_missing_every_other_cell`, `half_missing_first_half`), unsorted indices (`invalid_shuffled_half_missing`, the #594 rule), duplicated index, out-of-range index (128), more than half missing, all missing, a non-canonical cell, and an index/cell count mismatch. |
| `compute_cells_and_kzg_proofs` | 4 of 11 | 2.0 MiB | `valid_0` (zero blob), `valid_1` (random blob), `invalid_blob_0` (all `0xff`), `invalid_blob_1` (a field element equal to the modulus). `invalid_blob_2`/`_3` are wrong-length blobs, which the fixed-size `Blob` type cannot express. |
| `compute_cells` | (shares the above) | - | Upstream's `compute_cells` cases use the same blobs as `compute_cells_and_kzg_proofs` (`valid_0`/`valid_1` are byte-identical), so `computeCells` is checked against the cell half of those outputs. |
| `compute_kzg_proof` | 4 of 52 | 1.0 MiB | `valid_blob_0_0` (zero blob, z = 0), `valid_blob_1_3`, `invalid_blob_0`, `invalid_z_0` (z equal to the modulus). |
| `verify_kzg_proof` | 122 of 122 | 47 KiB | The whole suite (each case is under 1 KiB): correct proofs including the point-at-infinity families, incorrect proofs, and invalid commitment / proof / y / z encodings. |

Cases whose inputs have the wrong byte length (`invalid_cell_2`/`_3`,
`invalid_commitment_0`/`_1`, `invalid_proof_0`/`_1`, ...) cannot be
constructed with eth.zig's fixed-size types; the test treats a construction
failure as a rejection and requires the vector's expected output to be
`null`, so the verdict is still checked.
