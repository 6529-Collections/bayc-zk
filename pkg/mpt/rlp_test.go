package mpt

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func b(x byte) uints.U8 { return uints.NewU8(x) }

type headerCircuit struct {
	B0, B1, B2            uints.U8        // three header bytes (B1/B2 may be 0)
	Off, Len              frontend.Variable `gnark:",public"`
}

func (c *headerCircuit) Define(api frontend.API) error {
	off, ln := decodeRLPHeader(api, []uints.U8{c.B0, c.B1, c.B2})
	api.AssertIsEqual(off, c.Off)
	api.AssertIsEqual(ln,  c.Len)
	return nil
}

/* tests ─────────────────────────────────────────────────────────────*/
func TestRLPHeaderVariants(t *testing.T) {
	assert := test.NewAssert(t)

	b := func(x byte) uints.U8 { return uints.NewU8(x) }

	cases := []struct{ b0, off, ln byte }{
		{0x83, 1, 3}, // short string  (payload len 3)
		{0xc7, 1, 7}, // short list    (payload len 7)
	}

	for _, tc := range cases {
		w := headerCircuit{
			B0:  b(tc.b0),
			Off: tc.off,
			Len: tc.ln,
		}
		assert.ProverSucceeded(new(headerCircuit), &w)
	}
}