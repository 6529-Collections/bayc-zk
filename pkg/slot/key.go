package slot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func Calc(tokenID *big.Int, slotIndex uint64) common.Hash {
	var buf [64]byte

	tokenID.FillBytes(buf[:32])

	for i := 0; i < 8; i++ {
		buf[56+i] = byte(slotIndex >> (8 * (7 - i)))
	}

	return crypto.Keccak256Hash(buf[:])
}