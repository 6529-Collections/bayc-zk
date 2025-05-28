package mpt

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

/* helper ────────────────────────────────────────────────────────────*/
func b(x byte) uints.U8 { return uints.NewU8(x) }

/* circuit under test ───────────────────────────────────────────────*/
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

	cases := []struct {
		bytes        [3]byte // header bytes (pad with 0)
		wantOff, wantLen int // expected offset and payload-len
	}{
		{[3]byte{0x83},                1, 3},          // short string
		{[3]byte{0xc7},                1, 7},          // short list
		{[3]byte{0xb9, 0x01, 0x23},    3, 0x0123},     // long  string
		{[3]byte{0xf9, 0x04, 0x56},    3, 0x0456},     // long  list
	}

	for _, tc := range cases {
		w := headerCircuit{
			B0:  b(tc.bytes[0]),
			B1:  b(tc.bytes[1]),
			B2:  b(tc.bytes[2]),
			Off: tc.wantOff,
			Len: tc.wantLen,
		}
		assert.ProverSucceeded(new(headerCircuit), &w)
	}
}