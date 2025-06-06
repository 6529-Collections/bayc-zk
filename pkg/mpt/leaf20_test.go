package mpt

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func leaf20(value [20]byte) []uints.U8 {
	out := make([]uints.U8, 21)
	out[0] = b(0x94)
	for i, v := range value {
		out[i+1] = b(v)
	}
	return out
}

type leaf20Happy struct{}

func (c *leaf20Happy) Define(api frontend.API) error {
	val := [20]byte{1, 2, 3}
	leaf := leaf20(val)
	root := NodeHash(api, leaf)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: leaf[1:],
		Root:    root,
	})
	return nil
}

type leaf20Bad struct{}

func (c *leaf20Bad) Define(api frontend.API) error {
	val := [20]byte{1, 2, 3}
	leaf := leaf20(val)
	root := NodeHash(api, leaf)

	bad := make([]uints.U8, 20)
	copy(bad, leaf[1:])
	bad[0] = b(0xFF)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: bad,
		Root:    root,
	})
	return nil
}

func TestLeaf20Payload(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(new(leaf20Happy), &leaf20Happy{})
	assert.ProverFailed(new(leaf20Bad),   &leaf20Bad{})
}