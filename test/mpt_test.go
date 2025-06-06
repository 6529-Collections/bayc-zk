package test

import (
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

type leafHappyCircuit struct{}

func (c *leafHappyCircuit) Define(api frontend.API) error {
	leaf := leafBytes()
	root := mpt.NodeHash(api, leaf)

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: leafValue(),
		Root:    root,
	})
	return nil
}

type leafWrongValueCircuit struct {
	V [3]uints.U8 `gnark:",private"`
}

func (c *leafWrongValueCircuit) Define(api frontend.API) error {
	leaf := leafBytes()
	root := mpt.NodeHash(api, leaf)

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: c.V[:],
		Root:    root,
	})
	return nil
}

type leafWrongRootCircuit struct {
	V [3]uints.U8 `gnark:",private"`
}

func (c *leafWrongRootCircuit) Define(api frontend.API) error {
	leaf := leafBytes()

	bogus := mpt.NodeHash(api, []uints.U8{
		mpt.ConstU8('d'), mpt.ConstU8('e'), mpt.ConstU8('a'), mpt.ConstU8('d'),
		mpt.ConstU8('b'), mpt.ConstU8('e'), mpt.ConstU8('e'), mpt.ConstU8('f'),
	})

	mpt.VerifyBranch(api, mpt.BranchInput{
		Nodes:   [][]uints.U8{leaf},
		Path:    nil,
		LeafVal: c.V[:],
		Root:    bogus,
	})
	return nil
}

func TestMPTLeafHappy(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(new(leafHappyCircuit), &leafHappyCircuit{})
}

func TestMPTLeafWrongValueFails(t *testing.T) {
	assert := test.NewAssert(t)

	var w leafWrongValueCircuit
	w.V[0] = mpt.ConstU8(0x99)
	w.V[1] = mpt.ConstU8(0x99)
	w.V[2] = mpt.ConstU8(0x99)

	assert.ProverFailed(new(leafWrongValueCircuit), &w)
}

func TestMPTLeafWrongRootFails(t *testing.T) {
	assert := test.NewAssert(t)

	var w leafWrongRootCircuit
	w.V[0] = mpt.ConstU8(0x12)
	w.V[1] = mpt.ConstU8(0x34)
	w.V[2] = mpt.ConstU8(0x56)

	assert.ProverFailed(new(leafWrongRootCircuit), &w)
}