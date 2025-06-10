package test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/yourorg/bayczk/pkg/mpt"
)

func leafBytes() []uints.U8 {
	return []uints.U8{
		mpt.ConstU8(0x83),
		mpt.ConstU8(0x12),
		mpt.ConstU8(0x34),
		mpt.ConstU8(0x56),
	}
}

func leafValue() []uints.U8 {
	return []uints.U8{
		mpt.ConstU8(0x12),
		mpt.ConstU8(0x34),
		mpt.ConstU8(0x56),
	}
}

type leafHappyCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *leafHappyCircuit) Define(api frontend.API) error {
	leaf := leafBytes()

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: leafValue(),
		Root:    c.Root,
	})
	return nil
}

type leafWrongValueCircuit struct {
	V    [3]uints.U8 `gnark:",private"`
	Root frontend.Variable
}

func (c *leafWrongValueCircuit) Define(api frontend.API) error {
	leaf := leafBytes()

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: c.V[:],
		Root:    c.Root,
	})
	return nil
}

type leafWrongRootCircuit struct {
	V    [3]uints.U8 `gnark:",private"`
	Root frontend.Variable
}

func (c *leafWrongRootCircuit) Define(api frontend.API) error {
	leaf := leafBytes()

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: c.V[:],
		Root:    c.Root,
	})
	return nil
}

func TestMPTLeafHappy(t *testing.T) {
	root := new(big.Int).SetBytes([]byte{0x83, 0x12, 0x34, 0x56})
	assert := test.NewAssert(t)
	assert.ProverSucceeded(new(leafHappyCircuit), &leafHappyCircuit{Root: root})
}

func TestMPTLeafWrongValueFails(t *testing.T) {
	root := new(big.Int).SetBytes([]byte{0x83, 0x12, 0x34, 0x56})
	assert := test.NewAssert(t)

	var w leafWrongValueCircuit
	w.V[0] = mpt.ConstU8(0x99)
	w.V[1] = mpt.ConstU8(0x99)
	w.V[2] = mpt.ConstU8(0x99)

	w.Root = root
	assert.ProverFailed(new(leafWrongValueCircuit), &w)
}

func TestMPTLeafWrongRootFails(t *testing.T) {
	assert := test.NewAssert(t)

	var w leafWrongRootCircuit
	w.V[0] = mpt.ConstU8(0x12)
	w.V[1] = mpt.ConstU8(0x34)
	w.V[2] = mpt.ConstU8(0x56)

	w.Root = new(big.Int).SetBytes([]byte{0xde, 0xad, 0xbe, 0xef})
	assert.ProverFailed(new(leafWrongRootCircuit), &w)
}
