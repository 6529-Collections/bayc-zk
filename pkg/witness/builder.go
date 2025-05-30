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
        out[2*i+0] = mpt.ConstU8(b >> 4)     // high nibble
        out[2*i+1] = mpt.ConstU8(b & 0x0f)   // low nibble
    }
    return out
}

func toU8Slice(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b { out[i] = mpt.ConstU8(v) }
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
	if err != nil { return nil, err }
	defer cli.Close()

	/* ─── RPC calls ---------------------------------------------------- */
	proof, err := FetchProof(ctx, cli, contract,
		/*slotKey*/ common.Hash{}, block)
	if err != nil { return nil, err }

	root, err := FetchStateRoot(ctx, cli, block)
	if err != nil { return nil, err }

	/* ─── account‐leaf branch ----------------------------------------- */
	var accNodes [][]uints.U8
	for _, hexStr := range proof.AccountProof {
		bs, _ := hex.DecodeString(hexStr[2:])
		accNodes = append(accNodes, toU8Slice(bs))
	}

	/* ─── storage‐branch ---------------------------------------------- */
	var storNodes [][]uints.U8
	for _, hexStr := range proof.StorageProof[0].Proof {
		bs, _ := hex.DecodeString(hexStr[2:])
		storNodes = append(storNodes, toU8Slice(bs))
	}

	storLeaf := storNodes[len(storNodes)-1]     // []uints.U8
	leafVal  := append([]uints.U8(nil), storLeaf[1:]...)

	accPath  := hexToNibbles(crypto.Keccak256Hash(contract.Bytes()))
	storeKey := slot.Calc(tokenID, 0)          // you already imported pkg/slot
	storPath := hexToNibbles(storeKey)

	assignment := &circuits.BaycOwnershipCircuit{
		// public scalars -------------------------------------------------
		// gnark accepts plain Go numbers / big.Int as frontend.Variable.
		StateRoot: uint64(root[0]),   // we hash-chain with the *first byte*
		TokenID:   tokenID,           // *big.Int is fine

		// private witnesses ---------------------------------------------
		AccountProof: accNodes,
		StorageProof: storNodes,
		AccountPath:  accPath,
		StoragePath:  storPath,
		OwnerBytes:   leafVal,        // 20-byte constant
	}
    full, _ := frontend.NewWitness(assignment,
        circuits.Curve().ScalarField(),
    )

    pub := PublicInputs{
        StateRoot: root,                 // ← use the value we fetched
        TokenID:   tokenID.String(),
        Owner:     expOwner.Hex()[2:],   // strip leading 0x
    }

    return &Bundle{Full: full, Public: pub}, nil
}