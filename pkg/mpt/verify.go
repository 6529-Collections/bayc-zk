// pkg/mpt/verify.go   – leaf-payload support, no more debug prints
package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/yourorg/bayczk/internal/keccak"
)

/* -------------------------------------------------------------------------- */
/*  helpers                                                                   */
/* -------------------------------------------------------------------------- */

// NodeHash = first byte of Keccak-256(bytes)
func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bs)
	return k.Sum()[0].Val
}

/* -------------------------------------------------------------------------- */
/*  VerifyBranch  – Milestone-1: root → leaf (no extensions/branches yet)     */
/* -------------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8      // root .. leaf (already RLP-encoded bytes)
	Path    []uints.U8        // not used yet
	LeafVal []uints.U8        // expected payload (may be empty = “don’t check”)
	Root    frontend.Variable // public input
}

func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {

	/* ── 1) root node must hash to the public root -------------------- */
	rootNode := in.Nodes[0]                    // very first element
	api.AssertIsEqual(NodeHash(api, rootNode), in.Root)

	/* ── 2) leaf payload check  (optional) ---------------------------- */
	leafNode := in.Nodes[len(in.Nodes)-1]      // very last element

	if len(in.LeafVal) != 0 {
		// leaf must be RLP string with len==20 ⇒ header byte = 0x94
		api.AssertIsEqual(leafNode[0].Val, 0x94)

		payload := leafNode[1:]                // 20 bytes
		for i := range in.LeafVal {
			api.AssertIsEqual(payload[i].Val, in.LeafVal[i].Val)
		}
	}

	/* ── return leaf hash so chained verifiers can use it later ------- */
	return NodeHash(api, leafNode)
}