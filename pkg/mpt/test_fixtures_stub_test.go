//go:build !prod
// +build !prod

package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/std/math/uints"
)

/* ------------------ public helper -------------------------------------- */

// RootFieldElemBN254 / RootFieldElemBLS are the values you saw in the
// failing assertions – i.e. the value gnark puts into the wire for
//  Keccak256( {0x00} )[0]  on each curve.
var (
	RootFieldElemBN254 = bigFromDec("18999123868800248288564538536711930955113226631945275278736851282659890443962")
	RootFieldElemBLS12 = bigFromDec("10339734437352608253609609519040515294519402932249706143529600955872926250683")
)

func bigFromDec(s string) *big.Int {
	z, _ := new(big.Int).SetString(s, 10)
	return z
}

/* -------------------- branch fixture (unchanged) ----------------------- */

type branchFixture struct {
	nodes   [][]uints.U8
	path    []uints.U8
	payload []uints.U8
	root    []byte // we don’t actually use this any more
}

func mustLoadFixtures(tb testing.TB) branchFixture {
	if tb != nil {
		tb.Helper()
	}
	d := uints.NewU8(0x00)
	return branchFixture{
		nodes: [][]uints.U8{{d}, {d}},
		path:    []uints.U8{d},
		payload: []uints.U8{d},
	}
}