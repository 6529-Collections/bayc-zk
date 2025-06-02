package witness

import (
	backendwitness "github.com/consensys/gnark/backend/witness"
	"github.com/yourorg/bayczk/circuits"
)

type PublicInputs struct {
	StateRoot [32]byte `json:"stateRoot"`
	TokenID   string   `json:"tokenId"` // uint256 as decimal string
	Owner     string   `json:"owner"`   // hex without 0x
}

type Bundle struct {
	Full   backendwitness.Witness
	Public PublicInputs
	Blueprint *circuits.BaycOwnershipCircuit
}