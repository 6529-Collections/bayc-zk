package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type extensionTestCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *extensionTestCircuit) Define(api frontend.API) error {
	// Create a simple extension -> leaf structure
	leaf := []uints.U8{b(0xaa)}  // Simple leaf node
	ext := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})  // Extension pointing to leaf
	
	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{ext, leaf},
		Path:    nil,  // No path needed for extension verification
		LeafVal: leaf,
		Root:    c.Root,
	})
	return nil
}

func TestExtensionHandling(t *testing.T) {
	// Create test data
	ext := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
	
	// Calculate root (hash of extension node)
	rootBytes := make([]byte, len(ext))
	for i, u := range ext {
		rootBytes[i] = byte(u.Val.(int))
	}
	rootInt := new(big.Int).SetBytes(rootBytes)
	
	// Test with different curves
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, c := range curves {
		r := new(big.Int).Mod(rootInt, c.mod)
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			new(extensionTestCircuit),
			&extensionTestCircuit{Root: r},
			test.WithCurves(c.id),
		)
	}
}