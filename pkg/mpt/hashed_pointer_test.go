package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

// Test circuit for 32-byte hashed pointer (exactly at the threshold)
type hash32BytePointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *hash32BytePointerCircuit) Define(api frontend.API) error {
	// Create a 32-byte payload that should be Keccak hashed
	// RLP format: 0xa0 (32-byte string) + 32 payload bytes
	payload32 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		payload32[i] = byte(i + 1) // [0x01, 0x02, ..., 0x20]
	}
	
	// RLP encode: 0xa0 + payload
	node := make([]byte, 33)
	node[0] = 0xa0 // Short string with 32 bytes (0x80 + 32 = 0xa0)
	copy(node[1:], payload32)
	
	nodeU8 := BytesToU8s(node)
	
	// Element starts at position 0 and spans the entire node
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(33)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, nodeU8, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestHash32BytePointer(t *testing.T) {
	// Create 32-byte payload
	payload32 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		payload32[i] = byte(i + 1) // [0x01, 0x02, ..., 0x20]
	}
	
	// Compute expected Keccak hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(payload32)
	keccakBytes := hasher.Sum(nil)
	
	// Convert to big-endian integer like HashNode does
	expectedHash := new(big.Int).SetBytes(keccakBytes)
	
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
			&hash32BytePointerCircuit{},
			&hash32BytePointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for 33-byte hashed pointer (above threshold, simpler encoding)
type hash33BytePointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *hash33BytePointerCircuit) Define(api frontend.API) error {
	// Create a 33-byte payload (long string format)
	// RLP format: 0xb8 + 0x21 + 33 payload bytes
	payload33 := make([]byte, 33)
	for i := 0; i < 33; i++ {
		payload33[i] = byte(i + 1) // [0x01, 0x02, ..., 0x21]
	}
	
	// RLP encode as short string: 0x80 + length (since 33 < 56)
	node := make([]byte, 34) // 1 (header) + 33 (payload)
	node[0] = 0x80 + 33 // Short string: 0x80 + length = 0xb1
	copy(node[1:], payload33)
	
	nodeU8 := BytesToU8s(node)
	
	// Element starts at position 0 and spans the entire node
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(34)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, nodeU8, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestHash33BytePointer(t *testing.T) {
	// Create 33-byte payload
	payload33 := make([]byte, 33)
	for i := 0; i < 33; i++ {
		payload33[i] = byte(i + 1) // [0x01, 0x02, ..., 0x21]
	}
	
	// Compute expected Keccak hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(payload33)
	keccakBytes := hasher.Sum(nil)
	
	// Convert to big-endian integer like HashNode does
	expectedHash := new(big.Int).SetBytes(keccakBytes)
	
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
			&hash33BytePointerCircuit{},
			&hash33BytePointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit for 31-byte payload (just below threshold)
type hash31BytePointerCircuit struct {
	ExpectedHash frontend.Variable `gnark:",public"`
}

func (c *hash31BytePointerCircuit) Define(api frontend.API) error {
	// Create a 31-byte payload that should be treated as direct integer
	payload31 := make([]byte, 31)
	for i := 0; i < 31; i++ {
		payload31[i] = byte(i + 1) // [0x01, 0x02, ..., 0x1f]
	}
	
	// RLP encode: 0x80 + 31 = 0x9f (short string with 31 bytes)
	node := make([]byte, 32)
	node[0] = 0x9f
	copy(node[1:], payload31)
	
	nodeU8 := BytesToU8s(node)
	
	// Element starts at position 0 and spans the entire node
	elementStart := frontend.Variable(0)
	elementLength := frontend.Variable(32)
	
	// Decode the pointer and verify it matches expected hash
	decodePointer(api, nodeU8, elementStart, elementLength, c.ExpectedHash)
	
	return nil
}

func TestHash31BytePointer(t *testing.T) {
	// Create 31-byte payload
	payload31 := make([]byte, 31)
	for i := 0; i < 31; i++ {
		payload31[i] = byte(i + 1) // [0x01, 0x02, ..., 0x1f]
	}
	
	// For 31-byte payload, it should be treated as direct big-endian integer (no Keccak)
	expectedHash := new(big.Int).SetBytes(payload31)
	
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
			&hash31BytePointerCircuit{},
			&hash31BytePointerCircuit{ExpectedHash: hashMod},
			test.WithCurves(curve.id),
		)
	}
}

// Test circuit that demonstrates the threshold behavior
type thresholdTestCircuit struct {
	ExpectedHash32 frontend.Variable `gnark:",public"`
	ExpectedHash31 frontend.Variable `gnark:",public"`
}

func (c *thresholdTestCircuit) Define(api frontend.API) error {
	// Create both 31-byte and 32-byte payloads to test threshold
	
	// 31-byte payload (direct integer)
	payload31 := make([]byte, 31)
	for i := 0; i < 31; i++ {
		payload31[i] = byte(i + 1)
	}
	node31 := make([]byte, 32)
	node31[0] = 0x9f // 0x80 + 31
	copy(node31[1:], payload31)
	nodeU8_31 := BytesToU8s(node31)
	
	// 32-byte payload (Keccak hashed)
	payload32 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		payload32[i] = byte(i + 1)
	}
	node32 := make([]byte, 33)
	node32[0] = 0xa0 // 0x80 + 32
	copy(node32[1:], payload32)
	nodeU8_32 := BytesToU8s(node32)
	
	// Test 31-byte (should use direct integer)
	decodePointer(api, nodeU8_31, frontend.Variable(0), frontend.Variable(32), c.ExpectedHash31)
	
	// Test 32-byte (should use Keccak)
	decodePointer(api, nodeU8_32, frontend.Variable(0), frontend.Variable(33), c.ExpectedHash32)
	
	return nil
}

func TestThresholdBehavior(t *testing.T) {
	// 31-byte payload - direct integer
	payload31 := make([]byte, 31)
	for i := 0; i < 31; i++ {
		payload31[i] = byte(i + 1)
	}
	expectedHash31 := new(big.Int).SetBytes(payload31)
	
	// 32-byte payload - Keccak hash
	payload32 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		payload32[i] = byte(i + 1)
	}
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(payload32)
	keccakBytes := hasher.Sum(nil)
	expectedHash32 := new(big.Int).SetBytes(keccakBytes)
	
	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	
	for _, curve := range curves {
		hash31Mod := new(big.Int).Mod(expectedHash31, curve.mod)
		hash32Mod := new(big.Int).Mod(expectedHash32, curve.mod)
		
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			&thresholdTestCircuit{},
			&thresholdTestCircuit{
				ExpectedHash31: hash31Mod,
				ExpectedHash32: hash32Mod,
			},
			test.WithCurves(curve.id),
		)
	}
}