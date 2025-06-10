package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bs)
	out := k.Sum()

	// pack all 32 digest bytes into a single field element using
	// big-endian order so it matches the header's state root value.
	acc := frontend.Variable(0)
	for _, b := range out {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, b.Val)
	}
	return acc
}

/* -------------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8
	LeafVal []uints.U8
	Root    frontend.Variable
}

func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	api.AssertIsEqual(HashNode(api, in.Nodes[0]), in.Root)

	leaf := in.Nodes[len(in.Nodes)-1]
	if len(in.LeafVal) != 0 {
		goOff := len(leaf) - len(in.LeafVal)

		for i := range in.LeafVal {
			diff := api.Sub(leaf[goOff+i].Val, in.LeafVal[i].Val)

			api.AssertIsEqual(api.Mul(diff, in.Root), 0)
		}
	}

	return NodeHash(api, leaf)
}
