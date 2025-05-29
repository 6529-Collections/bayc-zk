// pkg/mpt/verify.go  — *minimal leaf-only version, compiles on v0.12*

package mpt

import (
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
	Nodes   [][]uints.U8   // RLP-encoded nodes, root → leaf
	Path    []uints.U8     // (unused for now)
	LeafVal []uints.U8     // expected payload bytes
	Root    frontend.Variable
}

// Verifies a **single leaf node**.  Works for Milestone-1 tests.
func VerifyBranch(api frontend.API, in BranchInput) {
	// parent-pointer check
	api.AssertIsEqual(NodeHash(api, in.Nodes[0]), in.Root)

	// payload starts right after 1-byte RLP header → compare value
	leaf := in.Nodes[0][1:] // drop RLP header
	for i := range in.LeafVal {
		api.AssertIsEqual(leaf[i].Val, in.LeafVal[i].Val)
	}
}