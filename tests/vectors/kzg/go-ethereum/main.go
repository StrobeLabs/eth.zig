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
	BlobRecipe        string   `json:"blob_recipe"`
	BlobSha256        string   `json:"blob_sha256"`
	Commitment        string   `json:"commitment"`
	VersionedHash     string   `json:"versioned_hash"`
	BlobProof         string   `json:"blob_proof"`
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

func main() {
	// Deterministic blob: the same recipe as eth.zig's kzg round-trip test.
	// Every 32-byte field element keeps its top byte zero, so it is canonical.
	var blob kzg4844.Blob
	for i := 0; i < len(blob); i += 32 {
		fe := i / 32
		blob[i+31] = byte(fe % 251)
		blob[i+30] = byte((fe / 251) % 251)
	}
	blobSum := sha256.Sum256(blob[:])

	commitment, err := kzg4844.BlobToCommitment(&blob)
	must(err)
	blobProof, err := kzg4844.ComputeBlobProof(&blob, commitment)
	must(err)
	cellProofs, err := kzg4844.ComputeCellProofs(&blob)
	must(err)
	if len(cellProofs) != kzg4844.CellProofsPerBlob {
		panic("unexpected cell proof count")
	}
	// Self-check the cell proofs with go-eth-kzg before emitting them.
	must(kzg4844.VerifyCellProofs([]kzg4844.Blob{blob}, []kzg4844.Commitment{commitment}, cellProofs))
	vh := kzg4844.CalcBlobHashV1(sha256.New(), &commitment)

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
			BlobHashes: []common.Hash{common.Hash(vh)},
			Sidecar:    sc,
		}
		tx, err := types.SignNewTx(key, types.NewCancunSigner(big.NewInt(1)), inner)
		must(err)
		return tx
	}

	v0 := mk(types.NewBlobTxSidecar(types.BlobSidecarVersion0, []kzg4844.Blob{blob}, []kzg4844.Commitment{commitment}, []kzg4844.Proof{blobProof}))
	v1 := mk(types.NewBlobTxSidecar(types.BlobSidecarVersion1, []kzg4844.Blob{blob}, []kzg4844.Commitment{commitment}, cellProofs))

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
		Description:       "EIP-4844 blob tx with one deterministic blob: signed tx, v0 network wrapper rlp([tx_payload_body, blobs, commitments, proofs]) and EIP-7594 v1 wrapper rlp([tx_payload_body, 1, blobs, commitments, cell_proofs]). Generated with go-ethereum types.BlobTxSidecar + crypto/kzg4844 (go-eth-kzg backend).",
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
		BlobRecipe:        "for each 32-byte field element fe (0..4095): blob[32*fe+31] = fe % 251; blob[32*fe+30] = (fe/251) % 251; all other bytes zero",
		BlobSha256:        "0x" + hex.EncodeToString(blobSum[:]),
		Commitment:        "0x" + hex.EncodeToString(commitment[:]),
		VersionedHash:     common.Hash(vh).Hex(),
		BlobProof:         "0x" + hex.EncodeToString(blobProof[:]),
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
	for _, p := range cellProofs {
		out.CellProofs = append(out.CellProofs, "0x"+hex.EncodeToString(p[:]))
	}
	js, err := json.MarshalIndent(out, "", "  ")
	must(err)
	must(os.WriteFile("blobtx_sidecar_vector.json", append(js, '\n'), 0o644))
	must(os.WriteFile("signed_tx.hex", []byte(hex.EncodeToString(signed)+"\n"), 0o644))
	must(os.WriteFile("network_v0.hex", []byte(hex.EncodeToString(netV0)+"\n"), 0o644))
	must(os.WriteFile("network_v1.hex", []byte(hex.EncodeToString(netV1)+"\n"), 0o644))
	fmt.Printf("signed=%d v0=%d v1=%d commitment=%s\n", len(signed), len(netV0), len(netV1), out.Commitment)
}
