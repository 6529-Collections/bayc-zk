package circuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func Curve() ecc.ID { return ecc.BN254 }

type BaycOwnershipCircuit struct {
	StateRoot frontend.Variable `gnark:",public"`
	TokenID   frontend.Variable `gnark:",public"`
	Owner     frontend.Variable `gnark:",public"`

	AccountProof frontend.Variable
	StorageProof frontend.Variable
}

func (c *BaycOwnershipCircuit) Define(api frontend.API) error {
	maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	api.AssertIsLessOrEqual(c.TokenID, maxUint256)
	return nil
}