package test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/yourorg/bayczk/pkg/mpt"
)

/* helpers ---------------------------------------------------------------- */

func leafBytes(api frontend.API) []uints.U8 {
	return []uints.U8{
		mpt.ConstU8(api, 0x83),      // short-string header
		mpt.ConstU8(api, 0x12),
		mpt.ConstU8(api, 0x34),
		mpt.ConstU8(api, 0x56),
	}
}

func leafValue(api frontend.API) []uints.U8 {
	return []uints.U8{
		mpt.ConstU8(api, 0x12),
		mpt.ConstU8(api, 0x34),
		mpt.ConstU8(api, 0x56),
	}
}

var goodVal = [3]uint8{0x12, 0x34, 0x56}
var badVal  = [3]uint8{0x99, 0x99, 0x99}

/* ----------------------------------------------------------------------- */
/* Generic circuit that takes the expected value as 3 private variables    */
/* ----------------------------------------------------------------------- */

type leafCircuit struct {
	V [3]frontend.Variable
}

func (c *leafCircuit) Define(api frontend.API) error {
	leaf := leafBytes()
	root := mpt.NodeHash(api, leaf)

	leafVal := []uints.U8{
		uints.NewU8(0x12),
		uints.NewU8(0x34),
		uints.NewU8(0x56),
	}
	
	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    []uints.U8{},
		LeafVal: leafVal,
		Root:    root,
	})
	return nil
}

/* --------------------------------------------------------------------- */
/* Tests                                                                 */
/* --------------------------------------------------------------------- */

func TestMPTLeafHappy(t *testing.T) {
	assert := test.NewAssert(t)

	w := leafCircuit{}
	for i, b := range goodVal {
		w.V[i] = b
	}
	assert.ProverSucceeded(&leafCircuit{}, &w)
}

func TestMPTLeafWrongValueFails(t *testing.T) {
	assert := test.NewAssert(t)

	w := leafCircuit{}
	for i, b := range badVal {
		w.V[i] = b
	}
	assert.ProverFailed(&leafCircuit{}, &w)
}