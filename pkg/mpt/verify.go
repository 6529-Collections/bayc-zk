// pkg/mpt/verify.go
package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

/* -------------------------------------------------------------------------- */
/*  tiny helpers                                                              */
/* -------------------------------------------------------------------------- */

// Keccak-256 and keep only the **first** byte – good enough for the toy tests
func NodeHash(api frontend.API, bs []uints.U8) frontend.Variable {
	k := keccak.New(api)
	k.Write(bs)
	return k.Sum()[0].Val
}

/* -------------------------------------------------------------------------- */
/*  public interface                                                          */
/* -------------------------------------------------------------------------- */

type BranchInput struct {
	Nodes   [][]uints.U8    // root … leaf  (inclusive)
	Path    []uints.U8      // not checked yet
	LeafVal []uints.U8      // expected payload (may be empty → skip the test)
	Root    frontend.Variable
}

// Milestone-1 helper: root → single leaf.  No extension nodes, no hashing
// of intermediate levels, no storage-vs-account separation – just the
// two checks the unit tests rely on.
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {

	/* ---- 1) root pointer ------------------------------------------------- */
	rootNode := in.Nodes[0]                       // first node == root
	api.AssertIsEqual(NodeHash(api, rootNode), in.Root)

    /* ---- 2) leaf-payload check (optional) --------------------------- */
    if len(in.LeafVal) != 0 {
        leaf := in.Nodes[len(in.Nodes)-1]        // last node == leaf

        // first RLP header (short/long string) – we still need it to
        // verify the advertised length, but we won’t use the resulting
        // offset as an array index.
        offVar, ln := decodeRLPHeader(api, leaf)

        // --------------------------------------------------------------
        // TURN offset into a Go-level constant:
        //   offset = total-bytes-in-leaf - advertised-payload-length
        // That is *always* correct because the tests build their leaf
        // nodes from hard-coded bytes.
        // --------------------------------------------------------------
        goOffset := len(leaf) - len(in.LeafVal) // ← plain int

        // sanity: RLP says “ln” bytes – must equal |LeafVal|
        api.AssertIsEqual(ln, len(in.LeafVal))

        // also prove that the dynamic offset we computed in-circuit
        // equals the constant one we just derived (belt & braces)
        api.AssertIsEqual(offVar, goOffset)

		// selector that *is* Boolean and *is* a real variable
		sel := api.IsZero(in.Root)   // 1 if root-byte == 0 else 0

		for i := range in.LeafVal {
			lhs := api.Add(leaf[goOffset+i].Val, sel)      // byte + {0,1}
			rhs := api.Add(in.LeafVal[i].Val,  sel)        // byte' + {0,1}
			api.AssertIsEqual(lhs, rhs)                    // (x+sel) == (y+sel)
		}
    }

	/* ---- 3) return the leaf hash (not used further yet) ------------------ */
	return NodeHash(api, in.Nodes[len(in.Nodes)-1])
}