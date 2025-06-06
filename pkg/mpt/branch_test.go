package mpt

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

/* ---------- tiny wrapper circuit -------------------------------------- */

type accHappyCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *accHappyCircuit) Define(api frontend.API) error {
	fx := mustLoadFixtures(nil)
	VerifyBranch(api, BranchInput{
		Nodes:   fx.nodes,
		Path:    fx.path,
		LeafVal: fx.payload,
		Root:    c.Root,
	})
	return nil
}

func TestAccountLeafHappy(t *testing.T) {

	type tc struct {
		curve ecc.ID
		root  interface{} // witness value for Root
	}
	cases := []tc{
		{ecc.BN254, RootFieldElemBN254},
		{ecc.BLS12_381, RootFieldElemBLS12},
	}

	for _, c := range cases {
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&accHappyCircuit{},              // blueprint
			&accHappyCircuit{Root: c.root},  // witness
			test.WithCurves(c.curve),
		)
	}
}