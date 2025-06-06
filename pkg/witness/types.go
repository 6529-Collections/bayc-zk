package witness

import (
	backendwitness "github.com/consensys/gnark/backend/witness"
	"github.com/yourorg/bayczk/circuits"
)

type PublicInputs struct {
	StateRoot [32]byte `json:"stateRoot"`
	TokenID   string   `json:"tokenId"`
	Owner     string   `json:"owner"`
}

type Bundle struct {
	Full   backendwitness.Witness
	Public PublicInputs
	Blueprint *circuits.BaycOwnershipCircuit
}