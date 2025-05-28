package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func Curve() ecc.ID { return ecc.BN254 }

// BaycOwnershipCircuit defines the public inputs and (stubbed) private data.
type BaycOwnershipCircuit struct {
	// Public
	StateRoot frontend.Variable `gnark:",public"`
	TokenID   frontend.Variable `gnark:",public"`
	Owner     frontend.Variable `gnark:",public"`

	// Private (place-holders until the full MPT logic is wired in)
	AccountProof frontend.Variable
	StorageProof frontend.Variable
}

func (c *BaycOwnershipCircuit) Define(api frontend.API) error {
	// 2²⁵⁶ − 1  (fits in a *big.Int)
	maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	api.AssertIsLessOrEqual(c.TokenID, maxUint256)
	return nil
}