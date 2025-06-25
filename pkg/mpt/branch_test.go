package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type accHappyCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *accHappyCircuit) Define(api frontend.API) error {
	f := mustLoadFixtures(nil)
	VerifyBranch(api, BranchInput{
		Nodes:   f.nodes,
		Path:    f.path,
		LeafVal: f.payload,
		Root:    c.Root,
	})
	return nil
}

func TestAccountLeafHappy(t *testing.T) {
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}

	for _, c := range curves {
		root := big.NewInt(0)
		root.Mod(root, c.mod)

		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&accHappyCircuit{},
			&accHappyCircuit{Root: root},
			test.WithCurves(c.id),
		)
	}
}
