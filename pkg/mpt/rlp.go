package mpt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

/*─────────────────────────────────────────────────────────────────────────────*/
/*  Helpers                                                                    */
/*─────────────────────────────────────────────────────────────────────────────*/

// x < y         (returns a boolean 0 / 1)
func isLess(api frontend.API, x, y frontend.Variable) frontend.Variable {
	// x < y  ⇔  y-x  > 0
	return api.IsZero(api.IsZero(api.Sub(y, x))) // 1 if y-x ≠ 0
}

// x ≤ y         (needed by the generic header parser once we add it)
func isLessOrEqual(api frontend.API, x, y frontend.Variable) frontend.Variable {
	return api.Or(isLess(api, x, y), api.IsZero(api.Sub(x, y)))
}

/*─────────────────────────────────────────────────────────────────────────────*/
/*  Short-header decoder (all we need for now)                                 */
/*─────────────────────────────────────────────────────────────────────────────*/

// For a short *string* or *list* header - the only variant that occurs in the
// BAYC proofs – B₀ satisfies 0x80 ≤ B₀ ≤ 0xf7.
//
//   headerLen  = 1
//   payloadLen = B₀ – 0x80   (for strings)  or  B₀ – 0xc0   (for lists)
//
// Because we won’t distinguish between string/list until Milestone 2, we
// treat them both as “string-like” and subtract 0x80.  That is fine as long as
// we only feed **storage-leaf** and **account-leaf** nodes to the gadget.
func decodeRLPHeaderShort(api frontend.API, b0 uints.U8) (off, plen frontend.Variable) {
	off  = frontend.Variable(1)            // header is exactly one byte
	plen = api.Sub(b0.Val, 0x80)           // payload length
	return
}

/*─────────────────────────────────────────────────────────────────────────────*/
/*  Shim kept for the tests we already wrote                                  */
/*─────────────────────────────────────────────────────────────────────────────*/

// Later we’ll replace this stub with the full implementation that handles
// long strings/lists and selects the correct subtraction constant (0x80 or
// 0xc0).  For now we just call the short variant.
func decodeRLPHeader(api frontend.API, b []uints.U8) (off, plen frontend.Variable) {
	return decodeRLPHeaderShort(api, b[0])
}