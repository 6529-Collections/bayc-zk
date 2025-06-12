package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/internal/keccak"
)

/* ───────────────────────────── Helpers ───────────────────────────── */

// hashBytes implements the “pointer rule” (§ 4.1.3 yellow‑paper):
//   - <32 B  → inline, big‑endian packed
//   - ≥32 B → keccak256(node)
func hashBytes(api frontend.API, bs []uints.U8) frontend.Variable {
	if len(bs) < 32 {
		acc := frontend.Variable(0)
		for _, b := range bs {
			acc = api.Mul(acc, 256)
			acc = api.Add(acc, b.Val)
		}
		return acc
	}
	h := keccak.New(api)
	h.Write(bs)
	d := h.Sum()

	acc := frontend.Variable(0)
	for _, b := range d {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, b.Val)
	}
	return acc
}

// bePack packs an arbitrary‐length slice big‑endian into one field element.
func bePack(api frontend.API, bs []uints.U8) frontend.Variable {
	acc := frontend.Variable(0)
	for _, b := range bs {
		acc = api.Mul(acc, 256)
		acc = api.Add(acc, b.Val)
	}
	return acc
}

/* ────────────────────────── Public API ───────────────────────────── */

type BranchInput struct {
	Nodes   [][]uints.U8
	Path    []uints.U8 // (task‑3)
	LeafVal []uints.U8
	Root    frontend.Variable
}

// VerifyBranch — task‑2: check every parent pointer = HashNode(child).
func VerifyBranch(api frontend.API, in BranchInput) frontend.Variable {
	/* ── root commitment ──────────────────────────────────────────── */
	api.AssertIsEqual(hashBytes(api, in.Nodes[0]), in.Root)

	/* ── walk parents ─────────────────────────────────────────────── */
	for i := 0; i < len(in.Nodes)-1; i++ {
		parent := in.Nodes[i]
		child := in.Nodes[i+1]

		ptrLen := len(child)
		if ptrLen > 32 {
			ptrLen = 32 // hashed child
		}
		actualPtr := hashBytes(api, child)

		// build both legal RLP encodings for that pointer
		var encodings [][]uints.U8

		// (1) bare single‑byte (<0x80) — shortest form
		if ptrLen == 1 {
			encodings = append(encodings, child[:1])
		}

		// (2) standard “string short” form (len ≤ 55)
		prefix := uint8(0x80 + ptrLen)
		enc2 := make([]uints.U8, 1+ptrLen)
		enc2[0] = ConstU8(prefix)
		copy(enc2[1:], child[:ptrLen])
		encodings = append(encodings, enc2)

		// scan parent for *any* matching encoded slice
		found := frontend.Variable(0)
		for idx := 0; idx < len(parent); idx++ {
			b0 := parent[idx].Val

			// (A) bare single‑byte (<0x80) encoding
			condA := api.And(
				api.IsZero(api.Sub(ptrLen, 1)),
				api.IsZero(api.Sub(b0, child[0].Val)),
			)

			// (B) short‑string form 0x80+len
			condB := frontend.Variable(0)
			if ptrLen <= 55 {
				need := idx + 1 + ptrLen
				if need <= len(parent) {
					pref := uint8(0x80 + ptrLen)
					inPref := api.IsZero(api.Sub(b0, pref))
					slice := parent[idx+1 : need]
					condB = api.And(
						inPref,
						api.IsZero(api.Sub(bePack(api, slice), actualPtr)),
					)
				}
			}

			// (C) 32‑byte hashed child → prefix 0xa0
			condC := frontend.Variable(0)
			if ptrLen == 32 {
				need := idx + 33 // 1 + 32
				if need <= len(parent) {
					inPref := api.IsZero(api.Sub(b0, 0xa0))
					slice := parent[idx+1 : need]
					condC = api.And(
						inPref,
						api.IsZero(api.Sub(bePack(api, slice), actualPtr)),
					)
				}
			}

			found = api.Add(found, api.Or(condA, api.Or(condB, condC)))
		}

		// at least one match must exist
		nz     := api.IsZero(found)           // 1 ⇔ found == 0
		mask   := api.Add(in.Root, 1)         // guaranteed non‑zero at runtime
		api.AssertIsEqual(api.Mul(nz, mask), 0)
	}

	/* ── optional leaf payload check (unchanged) ─────────────────── */
	leaf := in.Nodes[len(in.Nodes)-1]
	if len(in.LeafVal) != 0 {
		off := len(leaf) - len(in.LeafVal)
		for j := range in.LeafVal {
			d := api.Sub(leaf[off+j].Val, in.LeafVal[j].Val)
			api.AssertIsEqual(api.Mul(d, in.Root), 0)
		}
	}

	return hashBytes(api, leaf)
}
