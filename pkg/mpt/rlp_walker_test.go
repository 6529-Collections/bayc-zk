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

// Test circuit that uses the general RLP list walker
type rlpWalkerTestCircuit struct {
	ExpectedStart  frontend.Variable `gnark:",public"`
	ExpectedLength frontend.Variable `gnark:",public"`
}

func (c *rlpWalkerTestCircuit) Define(api frontend.API) error {
	// Test with an extension node: [0xc3, 0x80, 0x81, 0xaa]
	// This is a 2-item RLP list: [0x80, 0xaa] (compact path, child pointer)
	extensionNode := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
	
	// Extract element 1 (the second element, which is the child pointer 0xaa)
	start, length := rlpListWalk(api, extensionNode, 1)
	
	// Verify the results match our expectations
	api.AssertIsEqual(start, c.ExpectedStart)
	api.AssertIsEqual(length, c.ExpectedLength)
	
	return nil
}

func TestRLPWalkerExtensionNode(t *testing.T) {
	// For extension node [0xc3, 0x80, 0x81, 0xaa]:
	// - 0xc3: RLP list header (list with 3 bytes of content)
	// - 0x80: first element (empty string)
	// - 0x81, 0xaa: second element (single byte 0xaa)
	// 
	// Element 1 should start at index 3 and have length 1
	expectedStart := 3   // Index of 0xaa
	expectedLength := 1  // Length of the value 0xaa
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		startMod := new(big.Int).Mod(big.NewInt(int64(expectedStart)), curve.mod)
		lengthMod := new(big.Int).Mod(big.NewInt(int64(expectedLength)), curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&rlpWalkerTestCircuit{},
			&rlpWalkerTestCircuit{
				ExpectedStart:  startMod,
				ExpectedLength: lengthMod,
			},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for branch node RLP walking
type rlpWalkerBranchTestCircuit struct {
	ExpectedStart  frontend.Variable `gnark:",public"`
	ExpectedLength frontend.Variable `gnark:",public"`
	ElementIndex   int               // Not a circuit variable, compile-time constant
}

func (c *rlpWalkerBranchTestCircuit) Define(api frontend.API) error {
	// Create a synthetic branch node for testing
	// Structure: [0xd5] + 15*[0x80] + [0x84] + 4_extension_bytes + [0x80]
	branchNode := make([]uints.U8, 22)
	branchNode[0] = uints.U8{Val: 0xd5} // RLP list header
	
	// 15 empty slots (indices 0-14)
	for i := 1; i <= 15; i++ {
		branchNode[i] = uints.U8{Val: 0x80}
	}
	
	// Extension at index 15: [0x84] + 4 bytes [0xc3, 0x80, 0x81, 0xaa]
	branchNode[16] = uints.U8{Val: 0x84} // RLP header for 4-byte string
	branchNode[17] = uints.U8{Val: 0xc3}
	branchNode[18] = uints.U8{Val: 0x80}
	branchNode[19] = uints.U8{Val: 0x81}
	branchNode[20] = uints.U8{Val: 0xaa}
	
	// Empty slot at index 16
	branchNode[21] = uints.U8{Val: 0x80}
	
	// Extract the specified element
	start, length := rlpListWalk(api, branchNode, c.ElementIndex)
	
	// Verify the results match our expectations
	api.AssertIsEqual(start, c.ExpectedStart)
	api.AssertIsEqual(length, c.ExpectedLength)
	
	return nil
}

func TestRLPWalkerBranchNode(t *testing.T) {
	testCases := []struct {
		name           string
		elementIndex   int
		expectedStart  int
		expectedLength int
	}{
		{
			name:           "Empty slot 0",
			elementIndex:   0,
			expectedStart:  1,  // Position of first 0x80
			expectedLength: 0,  // Empty string has length 0
		},
		{
			name:           "Empty slot 5", 
			elementIndex:   5,
			expectedStart:  6,  // Position of 6th 0x80 
			expectedLength: 0,  // Empty string has length 0
		},
		{
			name:           "Extension at index 15",
			elementIndex:   15,
			expectedStart:  17, // Start of extension data (after 0x84 header)
			expectedLength: 4,  // Length of extension: [0xc3, 0x80, 0x81, 0xaa]
		},
		{
			name:           "Empty slot 16",
			elementIndex:   16,
			expectedStart:  21, // Position of last 0x80
			expectedLength: 0,  // Empty string has length 0
		},
	}
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, curve := range curves {
				startMod := new(big.Int).Mod(big.NewInt(int64(tc.expectedStart)), curve.mod)
				lengthMod := new(big.Int).Mod(big.NewInt(int64(tc.expectedLength)), curve.mod)
				
				// Create circuit with specific element index
				circuit := &rlpWalkerBranchTestCircuit{ElementIndex: tc.elementIndex}
				witness := &rlpWalkerBranchTestCircuit{
					ExpectedStart:  startMod,
					ExpectedLength: lengthMod,
					ElementIndex:   tc.elementIndex,
				}
				
				assert := test.NewAssert(t)
				assert.ProverSucceeded(circuit, witness, test.WithCurves(curve.id))
			}
		})
	}
}

// Test circuit that verifies the RLP walker works with real Ethereum data structures
type rlpWalkerRealDataCircuit struct {
	ExpectedStart  frontend.Variable `gnark:",public"`
	ExpectedLength frontend.Variable `gnark:",public"`
}

func (c *rlpWalkerRealDataCircuit) Define(api frontend.API) error {
	// Create a more realistic branch node structure
	// Real Ethereum branch nodes are much larger, but we'll simulate the key parts
	
	// For now, test with our synthetic structure since real branch nodes 
	// would require much larger circuits
	extensionNode := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
	
	// Test both elements of the extension node
	start0, length0 := rlpListWalk(api, extensionNode, 0) // First element (compact path)
	start1, length1 := rlpListWalk(api, extensionNode, 1) // Second element (child pointer)
	
	// Element 0 should be at index 1 with length 0 (empty string 0x80)
	api.AssertIsEqual(start0, frontend.Variable(1))
	api.AssertIsEqual(length0, frontend.Variable(0))
	
	// Element 1 should be at index 3 with length 1 (single byte 0xaa)
	api.AssertIsEqual(start1, c.ExpectedStart)
	api.AssertIsEqual(length1, c.ExpectedLength)
	
	return nil
}

func TestRLPWalkerRealData(t *testing.T) {
	expectedStart := 3   // Start of 0xaa
	expectedLength := 1  // Length of 0xaa
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		startMod := new(big.Int).Mod(big.NewInt(int64(expectedStart)), curve.mod)
		lengthMod := new(big.Int).Mod(big.NewInt(int64(expectedLength)), curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&rlpWalkerRealDataCircuit{},
			&rlpWalkerRealDataCircuit{
				ExpectedStart:  startMod,
				ExpectedLength: lengthMod,
			},
			test.WithCurves(curve.id),
		)
	}
}