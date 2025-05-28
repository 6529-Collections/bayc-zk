package witness

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/yourorg/bayczk/circuits"
	"github.com/consensys/gnark/frontend"
)

// Build downloads proofs via eth_getProof and returns a gnark witness bundle.
// The circuit is still a stub, so we emit an **empty** witness for now.
func Build(
	ctx context.Context,
	rpcURL string,
	blockNum uint64,
	contract common.Address,
	tokenID *big.Int,
	expectedOwner common.Address,
) (*Bundle, error) {

	cli, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	// 1) Header → stateRoot
	header, err := cli.HeaderByNumber(ctx, big.NewInt(int64(blockNum)))
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}

	// 2) slot = keccak256(pad32(tokenID) || pad32(0))
	var idBuf, zero [32]byte
	tokenID.FillBytes(idBuf[:])
	slot := crypto.Keccak256Hash(append(idBuf[:], zero[:]...))

	// 3) Fetch proofs (ignored until circuit is wired)
	var dummyResp interface{}
	if err := cli.Client().CallContext(
		ctx, &dummyResp, "eth_getProof",
		contract, []string{slot.Hex()}, hexutil.Uint64(blockNum),
	); err != nil {
		return nil, err
	}

	// 4) Empty assignment that *does* satisfy frontend.Circuit
	assignment := &circuits.BaycOwnershipCircuit{} // zero-value fields
	full, _ := frontend.NewWitness(assignment, circuits.Curve().ScalarField())

	pub := PublicInputs{
		StateRoot: header.Root,
		TokenID:   tokenID.String(),
		Owner:     expectedOwner.Hex()[2:],
	}
	return &Bundle{Full: full, Public: pub}, nil
}