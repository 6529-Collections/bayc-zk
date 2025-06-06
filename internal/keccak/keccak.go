package keccak

import (
	"github.com/consensys/gnark/frontend"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/sha3"
)

func New(api frontend.API) stdhash.BinaryHasher {
	h, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		panic(err)
	}
	return h
}