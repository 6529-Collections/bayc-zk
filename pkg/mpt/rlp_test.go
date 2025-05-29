package mpt

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func b(x byte) uints.U8 { return uints.NewU8(x) }

/* --------------------------------------------------------------------- */
type headerCircuit struct {
	B0, B1, B2 uints.U8
	Off        frontend.Variable `gnark:",public"`
	Len        frontend.Variable `gnark:",public"`
}

func (c *headerCircuit) Define(api frontend.API) error {
	off, ln := decodeRLPHeader(api, []uints.U8{c.B0, c.B1, c.B2})
	api.AssertIsEqual(off, c.Off)
	api.AssertIsEqual(ln,  c.Len)
	return nil
}

/* --------------------------------------------------------------------- */
func TestRLPHeaderVariants(t *testing.T) {
	assert := test.NewAssert(t)

	cases := []struct{ b0, b1, b2, off byte; ln uint16 }{
		{0x83, 0x00, 0x00, 1, 3},       // short string
		{0xc7, 0x00, 0x00, 1, 7},       // short list
		{0xb9, 0x01, 0x23, 3, 0x0123},  // long string  len-of-len=2
		{0xf9, 0x04, 0x56, 3, 0x0456},  // long list    len-of-len=2
	}

	for _, tc := range cases {
		w := headerCircuit{
			B0: b(tc.b0), B1: b(tc.b1), B2: b(tc.b2),
			Off: tc.off, Len: tc.ln,
		}
		assert.ProverSucceeded(new(headerCircuit), &w)
	}
}