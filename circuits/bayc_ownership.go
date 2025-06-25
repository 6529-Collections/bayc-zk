package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/pkg/mpt"
)

func Curve() ecc.ID { return ecc.BN254 }

type BaycOwnershipCircuit struct {
    StateRoot    frontend.Variable `gnark:",public"`
    TokenID      frontend.Variable `gnark:",public"`

    AccountProof [][]uints.U8      `gnark:",private"`
    StorageProof [][]uints.U8      `gnark:",private"`
    AccountPath  []uints.U8        `gnark:",private"`
    StoragePath  []uints.U8        `gnark:",private"`
    OwnerBytes   []uints.U8        `gnark:",private"`
}

func (c *BaycOwnershipCircuit) Define(api frontend.API) error {

    // ── Account MPT branch verification (stateRoot → account-leaf) ──
    _ = mpt.VerifyBranch(api, mpt.BranchInput{
        Nodes:   c.AccountProof,
        Path:    c.AccountPath,
        LeafVal: nil,          // not checked yet
        Root:    c.StateRoot,  // public
    })

    // ── Storage proof stubbed with empty slice for now ──
    _ = c.StorageProof // Acknowledge but don't use
    _ = c.StoragePath  // Acknowledge but don't use  
    _ = c.OwnerBytes   // Acknowledge but don't use

    return nil
}