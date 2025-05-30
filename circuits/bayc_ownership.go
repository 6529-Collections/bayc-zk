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

    // ---- Account MPT branch (stateRoot → storageRoot) ---------------
    storageRoot := mpt.VerifyBranch(api, mpt.BranchInput{
        Nodes:   c.AccountProof,  // [][]uints.U8
        Path:    c.AccountPath,   // []uints.U8
        LeafVal: nil,             // account leaf has multiple fields; we just take StorageRoot below
        Root:    c.StateRoot,     // public input
    })

    // ---- Storage MPT branch (storageRoot → owner slot) --------------
    mpt.VerifyBranch(api, mpt.BranchInput{
        Nodes:   c.StorageProof,
        Path:    c.StoragePath,
        LeafVal: c.OwnerBytes,    // 20 B constant put in the witness
        Root:    storageRoot,
    })
    return nil
}