package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

/* ------------------------------------------------------------------ */
/* tiny helpers (gnark-v0.12 friendly)                                */
/* ------------------------------------------------------------------ */

// x < y   ↦ 1 / 0
func isLess(api frontend.API, x, y frontend.Variable) frontend.Variable {
	// Cmp(x,y) = −1 if x<y.  So    x<y  ≡  Cmp(x,y)+1 == 0
	return api.IsZero(api.Add(api.Cmp(x, y), 1))
}

func c(v int) frontend.Variable { return frontend.Variable(v) } // const → Var

/* ------------------------------------------------------------------ */
/* full RLP header decoder                                            */
/* ------------------------------------------------------------------ */

func decodeRLPHeader(api frontend.API, b []uints.U8) (off, plen frontend.Variable) {
	b0 := b[0].Val

	// -------- selectors ------------------------------------------------ //
	isSingle  := isLess(api, b0, c(0x80))

	isStrSh   := api.And(
		isLess(api, c(0x7f), b0),            //   0x80 ≤ b0
		isLess(api, b0, c(0xb8)),            //         < 0xb8
	)
	isStrLg   := api.And(
		isLess(api, c(0xb7), b0),
		isLess(api, b0, c(0xc0)),
	)
	isListSh  := api.And(
		isLess(api, c(0xbf), b0),
		isLess(api, b0, c(0xf8)),
	)
	// else ⇒ long list

	// -------- case-1 : single byte ------------------------------------- //
	off1, len1 := c(0), c(1)

	// -------- case-2 : short string / list ----------------------------- //
	offShort := c(1)
	lenShort := api.Sub(b0, api.Select(isStrSh, c(0x80), c(0xc0)))

	// -------- case-3 : long string / list ------------------------------ //
	llen    := api.Sub(b0, api.Select(isStrLg, c(0xb7), c(0xf7))) // (#len-bytes)
	offLong := api.Add(c(1), llen)

	// big-endian accumulator of next L bytes
	val := c(0)
    for i := 1; i <= 8; i++ { // RLP spec: L ≤ 8
        // take b[i] only if (i-1) < L  **and** we actually have that byte
        have := frontend.Variable(0)
        if i < len(b) { // safe at Go-level
            have = b[i].Val
        }
		use := isLess(api, c(i-1), llen)          // still inside the length?
		next := api.Add(api.Mul(val, c(256)), have)
		val  = api.Select(use, next, val)
    }
	lenLong := val

	// -------- mux ------------------------------------------------------ //
	off = api.Select(isSingle, off1,
	       api.Select(api.Or(isStrSh, isListSh), offShort, offLong))
	plen = api.Select(isSingle, len1,
	        api.Select(api.Or(isStrSh, isListSh), lenShort, lenLong))
	return
}