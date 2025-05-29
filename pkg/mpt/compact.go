// pkg/mpt/compact.go  – rewrite
package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

/* -------------------------------------------------------------------------- */
/*  tiny helper: turn 4 selected bits into a 0-15 value                       */
/* -------------------------------------------------------------------------- */
func nibble(api frontend.API, bits []frontend.Variable, start int) frontend.Variable {
	val := bits[start]                                // 2⁰
	val = api.Add(val, api.Mul(bits[start+1], 2))     // 2¹
	val = api.Add(val, api.Mul(bits[start+2], 4))     // 2²
	val = api.Add(val, api.Mul(bits[start+3], 8))     // 2³
	return val
}

/* -------------------------------------------------------------------------- */
/*  DecodeCompact                                                             */
/* -------------------------------------------------------------------------- */

// DecodeCompact parses the hex-prefix path starting at in[0].
//
//   • out must be pre-allocated by the caller.
//   • returns (isLeafFlag , nibbleCount).
func DecodeCompact(api frontend.API, in []uints.U8, out []uints.U8) (
	isLeaf frontend.Variable, used frontend.Variable) {

	if len(in) == 0 {
		panic("empty compact path")
	}

	/* ─── split the first byte  (flags + maybe 1 nibble) ────────────────── */
	bits := api.ToBinary(in[0].Val, 8) // LSB-first, length = 8

	hi0, hi1, hi2, hi3 := bits[4], bits[5], bits[6], bits[7]
	loNib               := nibble(api, bits, 0)       // bits[0..3]

	// flags ---------------------------------------------------------------
	isLeaf = hi1                   // 1 ⇒ leaf   (hi = 2 or 3)
	isOdd  := hi0                  // 1 ⇒ odd #nibbles
	// guarantee hi∈{0,1,2,3}  ⇒  hi2==hi3==0
	api.AssertIsEqual(hi2, 0)
	api.AssertIsEqual(hi3, 0)

	// first nibble (only when odd) ---------------------------------------
	out[0] = uints.NewU8(0)
	out[0].Val = api.Select(isOdd, loNib, 0)

	/* ─── remaining bytes: 2 nibbles each ───────────────────────────────── */
	for j := 1; j < len(in); j++ {
		b := api.ToBinary(in[j].Val, 8)
		out[2*j-1].Val = nibble(api, b, 4) // high nibble
		out[2*j  ].Val = nibble(api, b, 0) // low  nibble
	}

	/* ─── total nibbles used ───────────────────────────────────────────── */
	total := api.Add(api.Mul(len(in)-1, 2), isOdd)
	used  = total

	api.AssertIsBoolean(isLeaf)
	return
}