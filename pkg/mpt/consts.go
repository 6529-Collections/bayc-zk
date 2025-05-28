
package mpt

import "github.com/consensys/gnark/std/math/uints"

// ConstU8 returns an immutable byte that the prover cannot alter.
func ConstU8(b byte) uints.U8 {               // ← no frontend.API here
	return uints.NewU8(b)
}