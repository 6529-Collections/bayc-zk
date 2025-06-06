package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// FromLE packs a field-element into little-endian byte form.
func FromLE(api frontend.API, x frontend.Variable, byteLen int) []uints.U8 {
	out := make([]uints.U8, byteLen)

	tmp := x
	for i := 0; i < byteLen; i++ {
		b := api.And(tmp, 0xff)          // lowest 8 bits
		out[i] = uints.U8{Val: b}        // ← build U8 manually
		tmp = api.Div(tmp, 256)          // shift right 8 bits
	}
	return out
}

// convenience for the tests
func BytesToU8s(bs []byte) []uints.U8 {
	u8 := make([]uints.U8, len(bs))
	for i, b := range bs {
		u8[i] = uints.U8{Val: int(b)}    // constant byte → U8
	}
	return u8
}

