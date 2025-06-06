package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func FromLE(api frontend.API, x frontend.Variable, byteLen int) []uints.U8 {
	out := make([]uints.U8, byteLen)

	tmp := x
	for i := 0; i < byteLen; i++ {
		b := api.And(tmp, 0xff)
		out[i] = uints.U8{Val: b}
		tmp = api.Div(tmp, 256)
	}
	return out
}

func BytesToU8s(bs []byte) []uints.U8 {
	u8 := make([]uints.U8, len(bs))
	for i, b := range bs {
		u8[i] = uints.U8{Val: int(b)}
	}
	return u8
}

