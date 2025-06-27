package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/yourorg/bayczk/pkg/mpt"
)

func Curve() ecc.ID { return ecc.BN254 }

type BaycOwnershipCircuit struct {
    StateRoot     frontend.Variable `gnark:",public"`
    TokenID       frontend.Variable `gnark:",public"`
    ExpectedOwner []uints.U8        `gnark:",public"`  // 20-byte owner address

    AccountProof [][]uints.U8      `gnark:",secret"`
    StorageProof [][]uints.U8      `gnark:",secret"`
    AccountPath  []uints.U8        `gnark:",secret"`
    StoragePath  []uints.U8        `gnark:",secret"`
    OwnerBytes   []uints.U8        `gnark:",secret"`
}

func (c *BaycOwnershipCircuit) Define(api frontend.API) error {

    // ── Account MPT branch verification (stateRoot → account-leaf) ──
    _ = mpt.VerifyBranch(api, mpt.BranchInput{
        Nodes:   c.AccountProof,
        Path:    c.AccountPath,
        LeafVal: nil,          // not checked yet
        Root:    c.StateRoot,  // public
    })

    // ── Storage MPT branch verification (storageRoot → storage-leaf) ──
    storageRoot := mpt.AccountLeafStorageRoot(api, c.AccountProof)
    _ = mpt.VerifyBranch(api, mpt.BranchInput{
        Nodes:   c.StorageProof,
        Path:    c.StoragePath,
        LeafVal: c.OwnerBytes,
        Root:    storageRoot,
    })

    // ── Validate that storage slot contains expected owner address ──
    mpt.StorageLeafMustEqualOwner(api, c.OwnerBytes, c.ExpectedOwner)

    return nil
}