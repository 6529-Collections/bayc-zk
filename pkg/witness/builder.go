// pkg/witness/builder.go
package witness

import (
	"context"
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/pkg/mpt"
)

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

	ownerBytes := expOwner.Bytes()               // 20 B
	var leafVal []uints.U8
	for _, b := range ownerBytes { leafVal = append(leafVal, mpt.ConstU8(b)) }

	/* ─── full witness (private+public) -------------------------------- */
    assignment := &circuits.BaycOwnershipCircuit{}          // all-zero circuit
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