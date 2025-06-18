package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

// HashNode returns the trie pointer corresponding to the given raw MPT node.
// For nodes shorter than 32 bytes, the RLP bytes are interpreted directly as a
// big-endian integer. Otherwise the Keccak256 hash of the node is used.
func HashNode(api frontend.API, raw []uints.U8) frontend.Variable {
	if len(raw) < 32 {
		acc := frontend.Variable(0)
		for _, b := range raw {
			acc = api.Mul(acc, 256)
			acc = api.Add(acc, b.Val)
		}
		return acc
	}
	k := keccak.New(api)
	k.Write(raw)
	d := k.Sum()

	acc := frontend.Variable(0)
	for _, b := range d {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, b.Val)
	}
	return acc
}
