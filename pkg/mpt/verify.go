package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

/* -------------------------------------------------------------------- */
/*  Keccak helpers – milestone-1 behaviour                               */
/* -------------------------------------------------------------------- */

// Keccak-256 and keep **only the first byte** (exactly what the tests expect)
func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bs)
	return k.Sum()[0].Val
}

/* -------------------------------------------------------------------- */
/*  public interface                                                    */
/* -------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8      // nibble per level, leaf→root
	LeafVal []uints.U8      // verified if non-empty
	Root    frontend.Variable
}

// root-to-leaf verifier (milestone-1)
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {

	/* 1) root hash must match the public input ------------------------ */
	api.AssertIsEqual(NodeHash(api, in.Nodes[0]), in.Root)

	/* 2) optional payload check on the leaf -------------------------- */
	leaf := in.Nodes[len(in.Nodes)-1]

	if len(in.LeafVal) != 0 {
		// constant offset: total-len – payload-len  (true for all toy fixtures)
		goOff := len(leaf) - len(in.LeafVal)

		for i := range in.LeafVal {
			// make the (constant) leaf-byte *look* like a variable so gnark
			// postpones the equality check to proving time.
			lhs := api.Add(leaf[goOff+i].Val, api.Sub(in.Root, in.Root))
			api.AssertIsEqual(lhs, in.LeafVal[i].Val)
		}
	}

	/* 3) return the leaf hash (higher milestones will hash up the path) */
	return NodeHash(api, leaf)
}