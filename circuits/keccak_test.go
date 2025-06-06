package circuits_test

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/yourorg/bayczk/circuits"
	"github.com/yourorg/bayczk/internal/keccak"
)

type keccak64Circuit struct {
	In   [64]uints.U8
	Hash [32]frontend.Variable `gnark:",public"`
}

func (c *keccak64Circuit) Define(api frontend.API) error {
	k := keccak.New(api)
	k.Write(c.In[:])

	out := k.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(out[i].Val, c.Hash[i])
	}
	return nil
}

/* ---------------- test ------------------- */

func TestKeccakGadget64Correct(t *testing.T) {
	assert := test.NewAssert(t)

	var msg [64]byte
	_, _ = rand.Read(msg[:])
	digest := crypto.Keccak256(msg[:])

	var w keccak64Circuit
	for i, b := range msg    { w.In[i]  = uints.NewU8(b) }
	for i, b := range digest { w.Hash[i] = b }

	assert.ProverSucceeded(new(keccak64Circuit), &w, test.WithCurves(circuits.Curve()))
}