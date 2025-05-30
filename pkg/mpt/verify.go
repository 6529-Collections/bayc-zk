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
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
    // 1) parent-pointer check
    api.AssertIsEqual(NodeHash(api, in.Nodes[0]), in.Root)

    // 2) (optional) leaf-value check
    if len(in.LeafVal) != 0 {
        leaf := in.Nodes[0][1:]            // after 1-byte RLP header
        for i := range in.LeafVal {
            api.AssertIsEqual(leaf[i].Val, in.LeafVal[i].Val)
        }
    }

    // ────────────────────────────────────────────────────────────────
    //  Milestone-1 stub: we don’t actually parse the account leaf yet,
    //  so just propagate the same hash downward.  Later we’ll replace
    //  this with “extract StorageRoot from the leaf”.
    // ────────────────────────────────────────────────────────────────
    return NodeHash(api, in.Nodes[0])      // equals in.Root today
}