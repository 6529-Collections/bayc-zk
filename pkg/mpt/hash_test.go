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
	"github.com/ethereum/go-ethereum/crypto"
)

// circuit for short node hashing
type hashShortCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *hashShortCircuit) Define(api frontend.API) error {
	node := []uints.U8{b(0x01), b(0x02)}
	api.AssertIsEqual(HashNode(api, node), c.Root)
	return nil
}

// circuit for long node hashing (33 bytes)
type hashLongCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *hashLongCircuit) Define(api frontend.API) error {
	node := make([]uints.U8, 33)
	for i := range node {
		node[i] = b(byte(i))
	}
	api.AssertIsEqual(HashNode(api, node), c.Root)
	return nil
}

func TestHashNodeVariants(t *testing.T) {
	long := make([]byte, 33)
	for i := range long {
		long[i] = byte(i)
	}

	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}

	for _, c := range curves {
		// short case expected value
		shortVal := new(big.Int).SetBytes([]byte{0x01, 0x02})
		shortVal.Mod(shortVal, c.mod)

		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			new(hashShortCircuit),
			&hashShortCircuit{Root: shortVal},
			test.WithCurves(c.id),
		)

		// long case expected value
		h := crypto.Keccak256(long)
		longVal := new(big.Int).SetBytes(h)
		longVal.Mod(longVal, c.mod)

		assert.ProverSucceeded(
			new(hashLongCircuit),
			&hashLongCircuit{Root: longVal},
			test.WithCurves(c.id),
		)
	}
}
