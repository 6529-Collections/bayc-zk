package mpt

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type compactCircuit struct {
	// raw bytes (flags+nibbles) passed as *constants* here for brevity
	B0, B1 uints.U8
	Leaf   frontend.Variable `gnark:",public"`
	Nibs   frontend.Variable `gnark:",public"`
}

func (c *compactCircuit) Define(api frontend.API) error {
	var buf = []uints.U8{c.B0, c.B1}
	var out [64]uints.U8
	leaf, cnt := DecodeCompact(api, buf, out[:])
	api.AssertIsEqual(leaf, c.Leaf)
	api.AssertIsEqual(cnt,  c.Nibs)
	return nil
}

func TestCompactOddLeaf(t *testing.T) {
	// 0x31 0x23   => odd *leaf*, nibbles = 0x1 | 0x2 | 0x3
	assert := test.NewAssert(t)
	w := compactCircuit{
		B0:  uints.NewU8(0x31),
		B1:  uints.NewU8(0x23),
		Leaf: 1,         // leaf-flag
		Nibs: 3,         // nibble count
	}
	assert.ProverSucceeded(new(compactCircuit), &w)
}