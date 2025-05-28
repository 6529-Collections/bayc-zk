package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ConstU8 wraps api.Constant so the result is an *unchangeable* byte.
func ConstU8(api frontend.API, b byte) uints.U8 {
	return uints.U8{Val: api.Constant(b)}
}