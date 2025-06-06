//go:build !prod
// +build !prod

package mpt

import (
	"testing"

	"github.com/consensys/gnark/std/math/uints"
)

var dummyRootFirstByte = uint8(0xBC)

type branchFixture struct {
	nodes   [][]uints.U8
	path    []uints.U8
	payload []uints.U8
	root    []byte
}

func mustLoadFixtures(tb testing.TB) branchFixture {
	if tb != nil {
		tb.Helper()
	}
	d := uints.NewU8(0x00)

	return branchFixture{
		nodes: [][]uints.U8{
			{d},
			{d},
		},
		path:    []uints.U8{d},
		payload: []uints.U8{d},
		root:    []byte{dummyRootFirstByte},
	}
}