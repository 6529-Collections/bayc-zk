package mpt

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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

/* ───────────────────────────── test ──────────────────────────── */

func TestAccountLeafHappy(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&accHappyCircuit{},
		&accHappyCircuit{Root: 0xBC},
		test.WithCurves(ecc.BN254, ecc.BLS12_381),
	)
}