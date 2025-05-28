package slot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

// Calc returns keccak256( pad32(tokenID) ‖ pad32(slotIndex) ).
func Calc(tokenID *big.Int, slotIndex uint64) common.Hash {
	var buf [64]byte

	// first 32 bytes = tokenID
	tokenID.FillBytes(buf[:32])

	// last 32 bytes = slot index (big-endian)
	for i := 0; i < 8; i++ { // write into the LAST 8 bytes of buf[32:64]
		buf[56+i] = byte(slotIndex >> (8 * (7 - i)))
	}

	return crypto.Keccak256Hash(buf[:]) // legacy Keccak-256
}