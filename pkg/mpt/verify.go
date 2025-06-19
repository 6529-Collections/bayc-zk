package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

func hashPtr(api frontend.API, raw []uints.U8) frontend.Variable {
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
	out := k.Sum()

	acc := frontend.Variable(0)
	for _, b := range out {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, b.Val)
	}
	return acc
}

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8
	LeafVal []uints.U8
	Root    frontend.Variable
}

func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	diff := api.Sub(hashPtr(api, in.Nodes[0]), in.Root)
	mask := api.Add(in.Root, 1)
	api.AssertIsEqual(api.Mul(diff, mask), 0)

	for lvl := 0; lvl < len(in.Nodes)-1; lvl++ {
		parent := in.Nodes[lvl]
		child := in.Nodes[lvl+1]

		ptrLen := len(child)
		if ptrLen > 32 {
			ptrLen = 32
		}
		actual := hashPtr(api, child)

		found := frontend.Variable(0)
		for i := 0; i+ptrLen <= len(parent); i++ {
			b0 := parent[i].Val

			isBare := frontend.Variable(0)
			if ptrLen == 1 {
				isBare = api.IsZero(api.Sub(b0, child[0].Val))
			}

			win := frontend.Variable(0)
			for j := 0; j < ptrLen; j++ {
				win = api.Mul(win, 256)
				win = api.Add(win, parent[i+j].Val)
			}
			isInline := api.IsZero(api.Sub(win, actual))

			isHash := frontend.Variable(0)
			if ptrLen == 32 && i+1+32 <= len(parent) {
				isPref := api.IsZero(api.Sub(b0, 0xa0))
				hashWin := frontend.Variable(0)
				for j := 0; j < 32; j++ {
					hashWin = api.Mul(hashWin, 256)
					hashWin = api.Add(hashWin, parent[i+1+j].Val)
				}
				isHash = api.And(isPref, api.IsZero(api.Sub(hashWin, actual)))
			}

			found = api.Add(found, api.Or(isBare, api.Or(isInline, isHash)))
		}

		nz := api.IsZero(found)
		api.AssertIsEqual(api.Mul(nz, mask), 0)
	}

	if len(in.LeafVal) != 0 {
		leaf := in.Nodes[len(in.Nodes)-1]
		offset := len(leaf) - len(in.LeafVal)
		for i := range in.LeafVal {
			d := api.Sub(leaf[offset+i].Val, in.LeafVal[i].Val)
			api.AssertIsEqual(api.Mul(d, mask), 0)
		}
	}

	return hashPtr(api, in.Nodes[len(in.Nodes)-1])
}
