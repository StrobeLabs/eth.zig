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
EIP-4844 blob functions is covered with valid and invalid cases.

Many of upstream's generated `valid_*` cases use constant blobs, whose 128
cells and 128 proofs are all identical; such a case cannot detect a
permutation of the outputs, so where one was the only positive case the
selection prefers a full-entropy one (see the notes below):

| Function | Cases | Size | Notes |
| --- | --- | --- | --- |
| `verify_cell_kzg_proof_batch` | 27 of 32 | 1.2 MiB | All `incorrect_*`, `invalid_*`, `valid_multiple_blobs`, `valid_not_sorted` (4 cells, 3 commitments, unsorted indices), `valid_regression1` (10 cells, a point-at-infinity commitment), `valid_same_cell_multiple_times` (duplicated cells), `valid_zero_cells` (empty batch), plus `valid_0` (the zero blob: 128 cells but only one distinct cell, proof and commitment) and `valid_2` (a full-entropy blob: 128 distinct cells and proofs, so the cell-to-index pairing is pinned). `valid_1` duplicates `valid_0`'s degenerate shape and is omitted; `valid_3`..`valid_6` are further full-entropy blobs of the same shape as `valid_2` (544 KiB each). |
| `recover_cells_and_kzg_proofs` | 9 of 18 | 3.0 MiB | Two valid shapes (`half_missing_every_other_cell`, `half_missing_first_half`), unsorted indices (`invalid_shuffled_half_missing`, the #594 rule), duplicated index, out-of-range index (128), more than half missing, all missing, a non-canonical cell, and an index/cell count mismatch. |
| `compute_cells_and_kzg_proofs` | 4 of 11 | 2.0 MiB | `valid_0` (the zero blob: all 128 cells equal, all 128 proofs the point at infinity), `valid_2` (a full-entropy blob: 128 distinct cells and 128 distinct proofs, so per-index content and ordering are pinned), `invalid_blob_0` (all `0xff`), `invalid_blob_1` (a field element equal to the modulus). Upstream's `valid_1` is a second *constant* blob (every field element 2) whose outputs are again one distinct cell and one distinct proof, so it cannot detect a permutation of the 128 outputs; it is deliberately not vendored. `invalid_blob_2`/`_3` are wrong-length blobs, which the fixed-size `Blob` type cannot express. |
| `compute_cells` | (shares the above) | - | Upstream's `compute_cells` cases use the same blobs as `compute_cells_and_kzg_proofs` (verified byte-identical for `valid_0` and `valid_2`), so `computeCells` is checked against the cell half of those outputs. |
| `compute_kzg_proof` | 4 of 52 | 1.0 MiB | `valid_blob_0_0` (zero blob, z = 0), `valid_blob_1_3`, `invalid_blob_0`, `invalid_z_0` (z equal to the modulus). |
| `verify_kzg_proof` | 122 of 122 | 47 KiB | The whole suite (each case is under 1 KiB): correct proofs including the point-at-infinity families, incorrect proofs, and invalid commitment / proof / y / z encodings. |

Cases whose inputs have the wrong byte length (`invalid_cell_2`/`_3`,
`invalid_commitment_0`/`_1`, `invalid_proof_0`/`_1`, ...) cannot be
constructed with eth.zig's fixed-size types; the test treats a construction
failure as a rejection and requires the vector's expected output to be
`null`, so the verdict is still checked.

## go-ethereum blob transaction cross-check (`go-ethereum/`)

`blobtx_sidecar_vector.json` is a known-answer vector for the blob
transaction network encodings, generated independently of c-kzg-4844 by the
Go program next to it (`main.go`, pinned to go-ethereum v1.16.8, whose
`crypto/kzg4844` is backed by crate-crypto/go-eth-kzg). For one fixed
transaction (Anvil account 0, chain id 1, nonce 7, **two distinct**
deterministic blobs built from the recipes in the file) it records the two
commitments, versioned hashes and blob proofs, the 2 x 128 cell proofs, the
signature, and the length and keccak256 of the signed transaction, of the
pre-Fusaka version-0 wrapper
`0x03 || rlp([tx_payload_body, blobs, commitments, proofs])` and of the
EIP-7594 version-1 wrapper
`0x03 || rlp([tx_payload_body, 1, blobs, commitments, cell_proofs])`, exactly
as `types.Transaction.MarshalBinary` emits them with a `BlobTxSidecar` of the
matching version (go-ethereum also round-trips both encodings through its
decoder, and self-checks the cell proofs with `kzg4844.VerifyCellProofs`,
before they are written). `tests/blob_sidecar_vectors_test.zig` rebuilds the
same transaction and sidecar with eth.zig and compares all of it byte for
byte (the full encodings via their keccak256 and length, which keeps the
vector at 30 KiB instead of 1 MiB).

Two blobs rather than one is deliberate: with a single blob the blob-major
and cell-major `cell_proofs` layouts produce identical bytes, so a one-blob
vector cannot pin the layout EIP-7594 specifies. With two distinct blobs all
256 proofs are distinct and the two 128-proof blocks differ, so a transposed
or swapped layout changes the wrapper's keccak256.

Regenerate with `cd go-ethereum && go run .` (network access is needed the
first time to fetch the pinned modules). The run also drops the full
encodings next to the vector as `*.hex` for debugging; those are gitignored.
