package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func isLess(api frontend.API, x, y frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(api.Cmp(x, y), 1))
}

func c(v int) frontend.Variable { return frontend.Variable(v) }

func decodeRLPHeader(api frontend.API, b []uints.U8) (off, plen frontend.Variable) {
	b0 := b[0].Val

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

	off1, len1 := c(0), c(1)

	offShort := c(1)
	lenShort := api.Sub(b0, api.Select(isStrSh, c(0x80), c(0xc0)))

	llen    := api.Sub(b0, api.Select(isStrLg, c(0xb7), c(0xf7)))
	offLong := api.Add(c(1), llen)

	val := c(0)
    for i := 1; i <= 8; i++ {
        have := frontend.Variable(0)
        if i < len(b) {
            have = b[i].Val
        }
		use := isLess(api, c(i-1), llen)
		next := api.Add(api.Mul(val, c(256)), have)
		val  = api.Select(use, next, val)
    }
	lenLong := val

	off = api.Select(isSingle, off1,
	       api.Select(api.Or(isStrSh, isListSh), offShort, offLong))
	plen = api.Select(isSingle, len1,
	        api.Select(api.Or(isStrSh, isListSh), lenShort, lenLong))
	return
}