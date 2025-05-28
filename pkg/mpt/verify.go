package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

// NodeHash — Keccak-256 over raw bytes  ➜  return the first byte as a field
// element; that’s enough for hash-chaining inside the same circuit.
func NodeHash(api frontend.API, bytes []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bytes)

	d := k.Sum()          // []uints.U8 (len 32)
	return d[0].Val
}

/* -------------------------------------------------------------------------- */
/*  Single-branch (root ➜ leaf) skeleton                                      */
/* -------------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8   // RLP-encoded nodes, root-first
	Path    []uints.U8     // nibble-path down the trie (unused yet)
	LeafVal []uints.U8     // expected leaf-payload bytes
	Root    frontend.Variable
}

// VerifyBranch – minimal leaf-only check.  For BAYC proofs every node we
// meet is a **short-string** RLP item, so the payload always starts at byte 1.
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	curHash := in.Root

	for depth, n := range in.Nodes {
		// 1) parent pointer
		api.AssertIsEqual(NodeHash(api, n), curHash)

		// 2) leaf-payload check
		if depth == len(in.Nodes)-1 {
			for i := range in.LeafVal {
				api.AssertIsEqual(n[1+i].Val, in.LeafVal[i].Val)
			}
			return curHash
		}

		// 3) (branch / extension logic will appear here later)
	}

	return curHash
}