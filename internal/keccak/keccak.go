package keccak

// Ethereum-compatible Keccak-256 gadget (gnark v0.12).

import (
	"github.com/consensys/gnark/frontend"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/sha3"
)

// New returns a BinaryHasher that implements legacy-padded Keccak-256.
func New(api frontend.API) stdhash.BinaryHasher {
	h, err := sha3.NewLegacyKeccak256(api) // constructor never fails
	if err != nil {
		panic(err)
	}
	return h
}