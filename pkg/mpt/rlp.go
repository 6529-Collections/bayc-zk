package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func isLess(api frontend.API, x, y frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(api.Cmp(x, y), 1))
}

func decodeRLPHeaderShort(api frontend.API, b0 uints.U8) (off, plen frontend.Variable) {
	off = frontend.Variable(1)

	isStr := isLess(api, b0.Val, 0xC0) // 1 for 0x80..0xBF, 0 otherwise
	plen  = api.Sub(b0.Val, api.Select(isStr, 0x80, 0xC0))
	return
}

func decodeRLPHeader(api frontend.API, b []uints.U8) (off, plen frontend.Variable) {
	return decodeRLPHeaderShort(api, b[0])
}