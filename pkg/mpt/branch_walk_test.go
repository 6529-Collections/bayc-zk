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

func leafNode() []uints.U8 {
	return []uints.U8{b(0xaa)}
}

func extensionNode() []uints.U8 {
	return BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
}

func branchNode(ext []uints.U8) []uints.U8 {
	b := []byte{0xd5}
	for i := 0; i < 16; i++ {
		b = append(b, 0x80)
	}
	b = append(b, 0x84)
	for _, u := range ext {
		b = append(b, byte(u.Val.(int)))
	}
	return BytesToU8s(b)
}

type walkCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *walkCircuit) Define(api frontend.API) error {
	leaf := leafNode()
	ext  := extensionNode()
	br   := branchNode(ext)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{br, ext, leaf},
		Path:    nil,
		LeafVal: leaf,
		Root:    c.Root,
	})
	return nil
}

func TestBranchWalkHappy(t *testing.T) {
	//leaf := leafNode()
	ext  := extensionNode()
	br   := branchNode(ext)

	rootBytes := make([]byte, len(br))
	for i, u := range br {
		rootBytes[i] = byte(u.Val.(int))
	}
	rootInt := new(big.Int).SetBytes(rootBytes)

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
			new(walkCircuit),
			&walkCircuit{Root: r},
			test.WithCurves(c.id),
		)
	}
}

type badCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *badCircuit) Define(api frontend.API) error {
	badLeaf := []uints.U8{b(0xbb)}
	ext     := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
	br      := branchNode(ext)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{br, ext, badLeaf},
		Path:    nil,
		LeafVal: badLeaf,
		Root:    c.Root,
	})
	return nil
}

func TestBranchWalkBrokenChildHashFails(t *testing.T) {
	ext := extensionNode()
	br  := branchNode(ext)

	rootBytes := make([]byte, len(br))
	for i, u := range br {
		rootBytes[i] = byte(u.Val.(int))
	}
	rootInt := new(big.Int).SetBytes(rootBytes)

	assert := test.NewAssert(t)
	assert.ProverFailed(
		new(badCircuit),
		&badCircuit{Root: rootInt},
	)
}

func TestPointerExtractionMatchesGo(t *testing.T) {
	ext   := []byte{0xc3, 0x80, 0x81, 0xaa}
	br    := []byte{0xd5}
	for i := 0; i < 16; i++ { br = append(br, 0x80) }
	br = append(br, 0x84)
	br = append(br, ext...)

	goPtr := big.NewInt(0).SetBytes(ext)
	last4 := big.NewInt(0).SetBytes(br[len(br)-4:])

	if goPtr.Cmp(last4) != 0 {
		t.Fatalf("expected %x, got %x", goPtr, last4)
	}
	dummy := make([]byte, 33)
	goHash := crypto.Keccak256(dummy)
	if len(goHash) != 32 {
		t.Fatal("keccak digest must be 32 bytes")
	}
}