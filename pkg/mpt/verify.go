// pkg/mpt/verify.go  – TEMPORARY debug version
package mpt

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

// NodeHash = first byte of Keccak-256(bytes)
func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bs)
	return k.Sum()[0].Val
}

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8
	LeafVal []uints.U8
	Root    frontend.Variable
}

// ONLY handles “root → single-leaf” for Milestone-1.
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	fmt.Println("VerifyBranch")
	/* ------------------------------------------------ root pointer check */
	rootNode := in.Nodes[0] // **first** = root
	api.AssertIsEqual(NodeHash(api, rootNode), in.Root)

	/* ------------------------------------------------ leaf-value check   */
	leafNode := in.Nodes[len(in.Nodes)-1] // **last** = leaf
	fmt.Println("len(in.LeafVal)", len(in.LeafVal))
	if len(in.LeafVal) != 0 {
		payload := leafNode[1:] // skip 1-byte 0xa0 header
		for i := range in.LeafVal {

            fmt.Printf("[account] LeafVal=%d bytes\n", len(in.LeafVal))
			// ---------- DEBUG PRINT (remove when green) ----------
			fmt.Printf("compare leaf[%d]  witness=%d  expected=%d\n",
				i, payload[i].Val, in.LeafVal[i].Val)
			// -----------------------------------------------------

			api.AssertIsEqual(payload[i].Val, in.LeafVal[i].Val)
		}
	}

	// For now we simply return the leaf hash (not yet used further).
	return NodeHash(api, leafNode)
}
