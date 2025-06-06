// pkg/witness/builder.go
package witness

import (
	"context"
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/mpt"
	"github.com/yourorg/bayczk/pkg/slot"
)

func hexToNibbles(h [32]byte) []uints.U8 {
	out := make([]uints.U8, 64)
	for i, b := range h {
		out[2*i] = mpt.ConstU8(b >> 4)   // high nibble
		out[2*i+1] = mpt.ConstU8(b & 0x0f) // low  nibble
	}
	return out
}

func toU8Slice(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b {
		out[i] = mpt.ConstU8(v)
	}
	return out
}

func Build(
	ctx context.Context,
	rpc string,
	block uint64,
	contract common.Address,
	tokenID *big.Int,
	expOwner common.Address,
) (*Bundle, error) {

	cli, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	proof, err := FetchProof(ctx, cli, contract, common.Hash{}, block)
	if err != nil {
		return nil, err
	}
	headerRoot, err := FetchStateRoot(ctx, cli, block)
	if err != nil {
		return nil, err
	}

	var (
		accNodes    [][]uints.U8
		firstAccRaw []byte
	)
	for i, h := range proof.AccountProof {
		raw, _ := hex.DecodeString(h[2:])
		if i == 0 {
			firstAccRaw = raw
		}
		accNodes = append(accNodes, toU8Slice(raw))
	}
	rootByte := crypto.Keccak256(firstAccRaw)[0]

	var storNodes [][]uints.U8
	for _, h := range proof.StorageProof[0].Proof {
		raw, _ := hex.DecodeString(h[2:])
		storNodes = append(storNodes, toU8Slice(raw))
	}

	storLeaf   := storNodes[len(storNodes)-1]
	payload    := storLeaf[1:]
	ownerVal   := append([]uints.U8(nil), payload...)

	accPath  := hexToNibbles(crypto.Keccak256Hash(contract.Bytes()))
	slotKey  := slot.Calc(tokenID, 0)
	storPath := hexToNibbles(slotKey)

	assignment := &circuits.BaycOwnershipCircuit{
		StateRoot: uint64(rootByte),
		TokenID:   tokenID,
		AccountProof: accNodes,
		StorageProof: storNodes,
		AccountPath:  accPath,
		StoragePath:  storPath,
		OwnerBytes:   ownerVal,
	}
	full, _ := frontend.NewWitness(assignment, circuits.Curve().ScalarField())

	blue := &circuits.BaycOwnershipCircuit{
		AccountProof: make([][]uints.U8, len(accNodes)),
		StorageProof: make([][]uints.U8, len(storNodes)),
		AccountPath:  make([]uints.U8, len(accPath)),
		StoragePath:  make([]uints.U8, len(storPath)),
		OwnerBytes:   make([]uints.U8, len(ownerVal)),
	}
	for i, n := range accNodes  { ln := len(n); if ln == 0 { ln = 1 }; blue.AccountProof[i] = make([]uints.U8, ln) }
	for i, n := range storNodes { ln := len(n); if ln == 0 { ln = 1 }; blue.StorageProof[i] = make([]uints.U8, ln) }

	pub := PublicInputs{
		StateRoot: headerRoot,
		TokenID:   tokenID.String(),
		Owner:     expOwner.Hex()[2:],
	}

	return &Bundle{Full: full, Public: pub, Blueprint: blue}, nil
}