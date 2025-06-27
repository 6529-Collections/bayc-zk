package testdata

import (
	"math/big"
	"github.com/consensys/gnark/std/math/uints"
)

// Test node creation helpers for MPT verification tests.
// These functions create minimal test nodes that work with the VerifyBranch function.

func LeafNode() []uints.U8 {
	return []uints.U8{B(0xaa)}
}

func ExtensionNode() []uints.U8 {
	return BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
}

func BranchNode(ext []uints.U8) []uints.U8 {
	b := []byte{0xd5}
	for i := 0; i < 15; i++ { // Only 15 empty slots (0-14)
		b = append(b, 0x80)
	}
	b = append(b, 0x84) // Extension at index 15
	for _, u := range ext {
		b = append(b, byte(u.Val.(int)))
	}
	b = append(b, 0x80) // Empty slot at index 16
	return BytesToU8s(b)
}

// Helper functions

func B(x byte) uints.U8 {
	return uints.NewU8(x)
}

func BytesToU8s(bs []byte) []uints.U8 {
	u8 := make([]uints.U8, len(bs))
	for i, b := range bs {
		u8[i] = uints.U8{Val: int(b)}
	}
	return u8
}

// ComputeRootHash converts a U8 node to a big.Int for use as circuit root
// This eliminates duplicate root hash calculation logic across tests
func ComputeRootHash(node []uints.U8) *big.Int {
	rootBytes := make([]byte, len(node))
	for i, u := range node {
		rootBytes[i] = byte(u.Val.(int))
	}
	return new(big.Int).SetBytes(rootBytes)
}

// CreateAccountLeaf creates a mock account leaf for testing storage root extraction
// Format: RLP([nonce, balance, storageRoot, codeHash])
func CreateAccountLeaf(nonce, balance uint64, storageRoot, codeHash []byte) []uints.U8 {
	// Simplified account leaf structure for testing
	// In reality this would be proper RLP encoding
	accountData := make([]byte, 0, 128)
	
	// Add RLP header for 4-item list
	accountData = append(accountData, 0xc4) // RLP list header
	
	// Add nonce (simplified as single byte)
	accountData = append(accountData, byte(nonce))
	
	// Add balance (simplified as single byte) 
	accountData = append(accountData, byte(balance))
	
	// Add storage root (32 bytes)
	accountData = append(accountData, storageRoot...)
	
	// Add code hash (32 bytes)
	accountData = append(accountData, codeHash...)
	
	return BytesToU8s(accountData)
}

// CreateStorageSlot creates a mock storage slot with owner address for testing
// BAYC format: 32-byte slot with address right-aligned (bytes [12:32])
func CreateStorageSlot(ownerAddr []byte) []uints.U8 {
	if len(ownerAddr) != 20 {
		panic("ownerAddr must be 20 bytes")
	}
	
	// 32-byte storage slot with address at the end
	slot := make([]byte, 32)
	copy(slot[12:], ownerAddr) // Right-aligned address
	
	return BytesToU8s(slot)
}