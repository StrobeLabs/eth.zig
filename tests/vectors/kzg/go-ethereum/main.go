// Emits a known-answer vector for the EIP-4844 (version 0) and EIP-7594
// (version 1) blob transaction network encodings using go-ethereum's own
// types.BlobTxSidecar and crypto/kzg4844 (backed by crate-crypto/go-eth-kzg,
// an implementation independent of c-kzg-4844).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/holiman/uint256"
)

type vector struct {
	Description       string   `json:"description"`
	GoEthereumVersion string   `json:"go_ethereum_version"`
	ChainID           uint64   `json:"chain_id"`
	Nonce             uint64   `json:"nonce"`
	MaxPriorityFee    uint64   `json:"max_priority_fee_per_gas"`
	MaxFee            uint64   `json:"max_fee_per_gas"`
	GasLimit          uint64   `json:"gas_limit"`
	To                string   `json:"to"`
	Value             uint64   `json:"value"`
	Data              string   `json:"data"`
	MaxFeePerBlobGas  uint64   `json:"max_fee_per_blob_gas"`
	PrivateKey        string   `json:"private_key"`
	Sender            string   `json:"sender"`
	BlobRecipes       []string `json:"blob_recipes"`
	BlobSha256        []string `json:"blob_sha256"`
	Commitments       []string `json:"commitments"`
	VersionedHashes   []string `json:"versioned_hashes"`
	BlobProofs        []string `json:"blob_proofs"`
	CellProofsPerBlob int      `json:"cell_proofs_per_blob"`
	CellProofs        []string `json:"cell_proofs"`
	YParity           uint64   `json:"y_parity"`
	R                 string   `json:"r"`
	S                 string   `json:"s"`
	TxHash            string   `json:"tx_hash"`
	SignedTxLen       int      `json:"signed_tx_len"`
	SignedTxKeccak    string   `json:"signed_tx_keccak256"`
	NetworkV0Len      int      `json:"network_v0_len"`
	NetworkV0Keccak   string   `json:"network_v0_keccak256"`
	NetworkV1Len      int      `json:"network_v1_len"`
	NetworkV1Keccak   string   `json:"network_v1_keccak256"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// blobRecipes describes, in words, how each blob is filled. Two *different*
// blobs are used on purpose: with a single blob the blob-major and cell-major
// cell_proofs layouts are indistinguishable, so the vector could not pin the
// one EIP-7594 specifies.
var blobRecipes = []string{
	"for each 32-byte field element fe (0..4095): blob[32*fe+31] = fe % 251; blob[32*fe+30] = (fe/251) % 251; all other bytes zero",
	"for each 32-byte field element fe (0..4095): blob[32*fe+31] = (7*fe + 3) % 251; blob[32*fe+29] = (fe/251) % 251; all other bytes zero",
}

// fillBlob applies the recipe with the given index. Every 32-byte field
// element keeps its top byte zero, so each is a canonical BLS12-381 scalar.
func fillBlob(which int) kzg4844.Blob {
	var blob kzg4844.Blob
	for i := 0; i < len(blob); i += 32 {
		fe := i / 32
		switch which {
		case 0:
			blob[i+31] = byte(fe % 251)
			blob[i+30] = byte((fe / 251) % 251)
		case 1:
			blob[i+31] = byte((7*fe + 3) % 251)
			blob[i+29] = byte((fe / 251) % 251)
		default:
			panic("unknown blob recipe")
		}
	}
	return blob
}

func main() {
	blobs := []kzg4844.Blob{fillBlob(0), fillBlob(1)}
	if blobs[0] == blobs[1] {
		panic("blobs must differ for the ordering check to mean anything")
	}

	var (
		blobSums    []string
		commitments []kzg4844.Commitment
		blobProofs  []kzg4844.Proof
		cellProofs  []kzg4844.Proof
		hashes      []common.Hash
	)
	for i := range blobs {
		sum := sha256.Sum256(blobs[i][:])
		blobSums = append(blobSums, "0x"+hex.EncodeToString(sum[:]))

		commitment, err := kzg4844.BlobToCommitment(&blobs[i])
		must(err)
		commitments = append(commitments, commitment)

		blobProof, err := kzg4844.ComputeBlobProof(&blobs[i], commitment)
		must(err)
		blobProofs = append(blobProofs, blobProof)

		// Blob-major: blob i's 128 proofs are appended as a block, which is
		// what EIP-7594 specifies and what geth's BlobTxSidecar.ToV1 does.
		perBlob, err := kzg4844.ComputeCellProofs(&blobs[i])
		must(err)
		if len(perBlob) != kzg4844.CellProofsPerBlob {
			panic("unexpected cell proof count")
		}
		cellProofs = append(cellProofs, perBlob...)

		hashes = append(hashes, common.Hash(kzg4844.CalcBlobHashV1(sha256.New(), &commitment)))
	}
	// Self-check every cell proof with go-eth-kzg before emitting them.
	must(kzg4844.VerifyCellProofs(blobs, commitments, cellProofs))

	keyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	key, err := crypto.HexToECDSA(keyHex)
	must(err)
	sender := crypto.PubkeyToAddress(key.PublicKey)

	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	mk := func(sc *types.BlobTxSidecar) *types.Transaction {
		inner := &types.BlobTx{
			ChainID:    uint256.NewInt(1),
			Nonce:      7,
			GasTipCap:  uint256.NewInt(1_000_000_000),
			GasFeeCap:  uint256.NewInt(30_000_000_000),
			Gas:        21_000,
			To:         to,
			Value:      uint256.NewInt(0),
			Data:       nil,
			AccessList: nil,
			BlobFeeCap: uint256.NewInt(1_000_000_000),
			BlobHashes: hashes,
			Sidecar:    sc,
		}
		tx, err := types.SignNewTx(key, types.NewCancunSigner(big.NewInt(1)), inner)
		must(err)
		return tx
	}

	v0 := mk(types.NewBlobTxSidecar(types.BlobSidecarVersion0, blobs, commitments, blobProofs))
	v1 := mk(types.NewBlobTxSidecar(types.BlobSidecarVersion1, blobs, commitments, cellProofs))

	signed, err := v0.WithoutBlobTxSidecar().MarshalBinary()
	must(err)
	netV0, err := v0.MarshalBinary()
	must(err)
	netV1, err := v1.MarshalBinary()
	must(err)

	// Round-trip both network encodings through go-ethereum's decoder.
	for _, enc := range [][]byte{netV0, netV1} {
		var back types.Transaction
		must(back.UnmarshalBinary(enc))
		if back.Hash() != v0.Hash() {
			panic("round-trip hash mismatch")
		}
		if back.BlobTxSidecar() == nil {
			panic("round-trip lost sidecar")
		}
	}

	vv, r, s := v0.RawSignatureValues()
	out := vector{
		Description:       "EIP-4844 blob tx with two distinct deterministic blobs: signed tx, v0 network wrapper rlp([tx_payload_body, blobs, commitments, proofs]) and EIP-7594 v1 wrapper rlp([tx_payload_body, 1, blobs, commitments, cell_proofs]). Two blobs so the blob-major cell_proofs layout is pinned. Generated with go-ethereum types.BlobTxSidecar + crypto/kzg4844 (go-eth-kzg backend).",
		GoEthereumVersion: "v1.16.8",
		ChainID:           1,
		Nonce:             7,
		MaxPriorityFee:    1_000_000_000,
		MaxFee:            30_000_000_000,
		GasLimit:          21_000,
		To:                to.Hex(),
		Value:             0,
		Data:              "0x",
		MaxFeePerBlobGas:  1_000_000_000,
		PrivateKey:        "0x" + keyHex,
		Sender:            sender.Hex(),
		BlobRecipes:       blobRecipes,
		BlobSha256:        blobSums,
		CellProofsPerBlob: kzg4844.CellProofsPerBlob,
		YParity:           vv.Uint64(),
		R:                 fmt.Sprintf("0x%064x", r),
		S:                 fmt.Sprintf("0x%064x", s),
		TxHash:            v0.Hash().Hex(),
		SignedTxLen:       len(signed),
		SignedTxKeccak:    crypto.Keccak256Hash(signed).Hex(),
		NetworkV0Len:      len(netV0),
		NetworkV0Keccak:   crypto.Keccak256Hash(netV0).Hex(),
		NetworkV1Len:      len(netV1),
		NetworkV1Keccak:   crypto.Keccak256Hash(netV1).Hex(),
	}
	for i := range commitments {
		out.Commitments = append(out.Commitments, "0x"+hex.EncodeToString(commitments[i][:]))
		out.VersionedHashes = append(out.VersionedHashes, hashes[i].Hex())
		out.BlobProofs = append(out.BlobProofs, "0x"+hex.EncodeToString(blobProofs[i][:]))
	}
	for _, p := range cellProofs {
		out.CellProofs = append(out.CellProofs, "0x"+hex.EncodeToString(p[:]))
	}
	js, err := json.MarshalIndent(out, "", "  ")
	must(err)
	must(os.WriteFile("blobtx_sidecar_vector.json", append(js, '\n'), 0o644))
	must(os.WriteFile("signed_tx.hex", []byte(hex.EncodeToString(signed)+"\n"), 0o644))
	must(os.WriteFile("network_v0.hex", []byte(hex.EncodeToString(netV0)+"\n"), 0o644))
	must(os.WriteFile("network_v1.hex", []byte(hex.EncodeToString(netV1)+"\n"), 0o644))
	fmt.Printf("blobs=%d signed=%d v0=%d v1=%d cell_proofs=%d\n", len(blobs), len(signed), len(netV0), len(netV1), len(cellProofs))
}
