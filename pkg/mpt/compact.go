
package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func nibble(api frontend.API, bits []frontend.Variable, start int) frontend.Variable {
	val := bits[start]
	val = api.Add(val, api.Mul(bits[start+1], 2))
	val = api.Add(val, api.Mul(bits[start+2], 4))
	val = api.Add(val, api.Mul(bits[start+3], 8))
	return val
}


func DecodeCompact(api frontend.API, in []uints.U8, out []uints.U8) (
	isLeaf frontend.Variable, used frontend.Variable) {

	if len(in) == 0 {
		panic("empty compact path")
	}

	bits := api.ToBinary(in[0].Val, 8)

	hi0, hi1, hi2, hi3 := bits[4], bits[5], bits[6], bits[7]
	loNib               := nibble(api, bits, 0)

	isLeaf = hi1
	isOdd  := hi0
	
	// Use variable-driven equality: compare against frontend.Variable(0) instead of constant 0
	zero := frontend.Variable(0)
	api.AssertIsEqual(hi2, zero)
	api.AssertIsEqual(hi3, zero)

	out[0] = uints.NewU8(0)
	out[0].Val = api.Select(isOdd, loNib, 0)

	for j := 1; j < len(in); j++ {
		b := api.ToBinary(in[j].Val, 8)
		out[2*j-1].Val = nibble(api, b, 4)
		out[2*j  ].Val = nibble(api, b, 0)
	}

	total := api.Add(api.Mul(len(in)-1, 2), isOdd)
	used  = total

	api.AssertIsBoolean(isLeaf)
	return
}