package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Test circuit for single byte pointer decoding
type singleBytePointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *singleBytePointerCircuit) Define(api frontend.API) error {
	// Create a test node containing a single byte element
	// Single byte values (0x00-0x7f) encode themselves directly
	testByte := byte(0x42) // Test with value 0x42
	node := BytesToU8s([]byte{testByte})
	
	// The element starts at position 0 and has length 1 (the byte itself)
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(1)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, node, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestSingleBytePointer(t *testing.T) {
	// Test single byte 0x42
	// For single bytes, HashNode should return the byte value itself (since < 32 bytes)
	testByte := byte(0x42)
	expectedHash := big.NewInt(int64(testByte))
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		hashMod := new(big.Int).Mod(expectedHash, curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&singleBytePointerCircuit{},
			&singleBytePointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for short string pointer decoding
type shortStringPointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *shortStringPointerCircuit) Define(api frontend.API) error {
	// Create a test node with a short string: [0x83, 0x01, 0x02, 0x03]
	// 0x83 = short string header (3 bytes)
	// 0x01, 0x02, 0x03 = payload
	node := BytesToU8s([]byte{0x83, 0x01, 0x02, 0x03})
	
	// The element starts at position 0 and spans the entire node
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(4)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, node, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestShortStringPointer(t *testing.T) {
	// For short string [0x83, 0x01, 0x02, 0x03], the payload is [0x01, 0x02, 0x03]
	// HashNode should return this as a big integer: 0x010203 = 66051
	payload := []byte{0x01, 0x02, 0x03}
	expectedHash := new(big.Int).SetBytes(payload)
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		hashMod := new(big.Int).Mod(expectedHash, curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&shortStringPointerCircuit{},
			&shortStringPointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for empty string pointer decoding (special case)
type emptyStringPointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *emptyStringPointerCircuit) Define(api frontend.API) error {
	// Create a test node with empty string: [0x80]
	// 0x80 = empty string
	node := BytesToU8s([]byte{0x80})
	
	// The element starts at position 0
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(1)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, node, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestEmptyStringPointer(t *testing.T) {
	// For empty string 0x80, the payload is empty
	// HashNode of empty content should return 0
	expectedHash := big.NewInt(0)
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		hashMod := new(big.Int).Mod(expectedHash, curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&emptyStringPointerCircuit{},
			&emptyStringPointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for long string pointer decoding
// NOTE: Long string RLP encoding is complex and depends on the exact format
// For now, we'll skip this test and focus on the more common cases

// Test circuit combining RLP walker with pointer decoding
type combinedWalkerPointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *combinedWalkerPointerCircuit) Define(api frontend.API) error {
	// Create an extension node where element 1 is a short string pointer
	// Extension: [0xc5, 0x80, 0x83, 0x01, 0x02, 0x03]
	// 0xc5 = list with 5 bytes content
	// 0x80 = empty string (element 0, compact path)
	// 0x83, 0x01, 0x02, 0x03 = short string (element 1, child pointer)
	node := BytesToU8s([]byte{0xc5, 0x80, 0x83, 0x01, 0x02, 0x03})
	
	// Use RLP walker to find element 1 (child pointer)
	elementStart, elementLength := rlpListWalk(api, node, 1)
	
	// Use pointer decoder to extract and verify the child hash
	decodePointer(api, node, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestCombinedWalkerPointer(t *testing.T) {
	// Element 1 should be the short string [0x83, 0x01, 0x02, 0x03]
	// Payload is [0x01, 0x02, 0x03] = 0x010203 = 66051
	payload := []byte{0x01, 0x02, 0x03}
	expectedHash := new(big.Int).SetBytes(payload)
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		hashMod := new(big.Int).Mod(expectedHash, curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&combinedWalkerPointerCircuit{},
			&combinedWalkerPointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test the extractPointerPayload helper function
type payloadExtractionCircuit struct {
	ExpectedLength frontend.Variable `gnark:",public"`
	ExpectedByte0  frontend.Variable `gnark:",public"`
	ExpectedByte1  frontend.Variable `gnark:",public"`
	ExpectedByte2  frontend.Variable `gnark:",public"`
}

func (c *payloadExtractionCircuit) Define(api frontend.API) error {
	// Test with short string [0x83, 0x01, 0x02, 0x03]
	node := BytesToU8s([]byte{0x83, 0x01, 0x02, 0x03})
	
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(4)
	
	// Extract payload without verification
	payload, actualLength := extractPointerPayload(api, node, elementStart, elementLength)
	
	// Verify the extracted payload properties
	api.AssertIsEqual(actualLength, c.ExpectedLength)
	api.AssertIsEqual(payload[0].Val, c.ExpectedByte0)
	api.AssertIsEqual(payload[1].Val, c.ExpectedByte1) 
	api.AssertIsEqual(payload[2].Val, c.ExpectedByte2)
	
	return nil
}

func TestPayloadExtraction(t *testing.T) {
	// For short string [0x83, 0x01, 0x02, 0x03]:
	// Expected length: 3
	// Expected bytes: [0x01, 0x02, 0x03]
	expectedLength := 3
	expectedBytes := []byte{0x01, 0x02, 0x03}
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		lengthMod := new(big.Int).Mod(big.NewInt(int64(expectedLength)), curve.mod)
		byte0Mod := new(big.Int).Mod(big.NewInt(int64(expectedBytes[0])), curve.mod)
		byte1Mod := new(big.Int).Mod(big.NewInt(int64(expectedBytes[1])), curve.mod)
		byte2Mod := new(big.Int).Mod(big.NewInt(int64(expectedBytes[2])), curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&payloadExtractionCircuit{},
			&payloadExtractionCircuit{
				ExpectedLength: lengthMod,
				ExpectedByte0:  byte0Mod,
				ExpectedByte1:  byte1Mod,
				ExpectedByte2:  byte2Mod,
			},
			test.WithCurves(curve.id),
		)
	}
}