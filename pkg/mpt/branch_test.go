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
	"github.com/yourorg/bayczk/pkg/mpt/testdata"
)

type accHappyCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *accHappyCircuit) Define(api frontend.API) error {
	f := mustLoadFixtures(nil)
	VerifyBranch(api, BranchInput{
		Nodes:   f.nodes,
		Path:    f.path,
		LeafVal: f.payload,
		Root:    c.Root,
	})
	return nil
}

// Happy path test for [branch → extension → leaf] chain
type branchExtensionLeafCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *branchExtensionLeafCircuit) Define(api frontend.API) error {
	// Three-node chain: branch → extension → leaf
	// This creates a minimal test case as required by task specification  
	leaf := testdata.LeafNode()                  // 0xaa
	ext  := testdata.ExtensionNode()             // extension pointing to leaf  
	br   := testdata.BranchNode(ext)             // branch with extension at slot 15
	
	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{br, ext, leaf},
		Path:    []uints.U8{testdata.B(0x0f)},    // nibble 15 where extension is placed
		LeafVal: leaf,
		Root:    c.Root,
	})
	return nil
}

func TestAccountLeafHappy(t *testing.T) {
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}

	for _, c := range curves {
		root := big.NewInt(0)
		root.Mod(root, c.mod)

		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&accHappyCircuit{},
			&accHappyCircuit{Root: root},
			test.WithCurves(c.id),
		)
	}
}

func TestBranchExtensionLeafHappy(t *testing.T) {
	// Use the same pattern as TestBranchWalkHappy
	ext := testdata.ExtensionNode()
	br  := testdata.BranchNode(ext)
	rootInt := testdata.ComputeRootHash(br)

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
			new(branchExtensionLeafCircuit),
			&branchExtensionLeafCircuit{Root: r},
			test.WithCurves(c.id),
		)
	}
}

// Note: Negative test cases (brokenChild, wrongNibble) already exist in comprehensive_test.go
// Note: Test helper functions are now centralized in testdata/helpers.go

// Test storage functionality
type storageOwnershipCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *storageOwnershipCircuit) Define(api frontend.API) error {
	// Test the new storage functionality with mocked data
	ownerAddr := make([]uints.U8, 20)
	for i := 0; i < 20; i++ {
		ownerAddr[i] = testdata.B(byte(0x42 + i)) // Mock address
	}
	
	// Create a mock storage slot with the owner address
	storageSlot := testdata.CreateStorageSlot([]byte{
		0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
		0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	})
	
	// Test the StorageLeafMustEqualOwner function
	StorageLeafMustEqualOwner(api, storageSlot, ownerAddr)
	
	return nil
}

func TestStorageOwnershipValidation(t *testing.T) {
	assert := test.NewAssert(t)
	
	// Test that storage ownership validation works correctly
	assert.ProverSucceeded(
		&storageOwnershipCircuit{},
		&storageOwnershipCircuit{Root: frontend.Variable(1)}, // Dummy root
		test.WithCurves(ecc.BN254, ecc.BLS12_381),
	)
}
