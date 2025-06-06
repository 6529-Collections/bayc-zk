package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
    k := keccak.New(api)
    k.Write(bs)
    return k.Sum()[0].Val
}


/* -------------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8
	LeafVal []uints.U8
	Root    frontend.Variable
}


func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	api.AssertIsEqual(NodeHash(api, in.Nodes[0]), in.Root)

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