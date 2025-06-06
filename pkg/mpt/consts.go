
package mpt

import "github.com/consensys/gnark/std/math/uints"

func ConstU8(b byte) uints.U8 {
	return uints.NewU8(b)
}