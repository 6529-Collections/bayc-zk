package witness

import backendwitness "github.com/consensys/gnark/backend/witness"

// PublicInputs is what gets written to bayc_public.json
type PublicInputs struct {
	StateRoot [32]byte `json:"stateRoot"`
	TokenID   string   `json:"tokenId"` // uint256 as decimal string
	Owner     string   `json:"owner"`   // hex without 0x
}

// Bundle groups the full gnark witness (for the prover) plus the JSON-friendly
// public inputs.
type Bundle struct {
	Full   backendwitness.Witness
	Public PublicInputs
}