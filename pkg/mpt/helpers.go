package mpt

import (
	"github.com/consensys/gnark/std/math/uints"
)


func BytesToU8s(bs []byte) []uints.U8 {
	u8 := make([]uints.U8, len(bs))
	for i, b := range bs {
		u8[i] = uints.U8{Val: int(b)}
	}
	return u8
}

