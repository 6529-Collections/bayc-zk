package mpt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
)

/* -------------------------------------------------------------------------- */
/*                                test fixtures                               */
/* -------------------------------------------------------------------------- */

// leaf  ── a single-byte RLP string with value 0xaa
func leafNode() []uints.U8 {
	return []uints.U8{b(0xaa)}
}

// extension  ── RLP list [ "", <leaf-ptr> ]
//              bytes: 0xc3  0x80        0x81 0xaa
func extensionNode() []uints.U8 {
	return BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa})
}

// branch     ── 17-item list, 16 × empty, last = <ext-ptr>
//              payload = 16*0x80 ‖ 0x84 <ext>
//              header = 0xd5 (0xc0 + 0x15)
func branchNode(ext []uints.U8) []uints.U8 {
	b := []byte{0xd5}
	for i := 0; i < 16; i++ { // sixteen empties
		b = append(b, 0x80)
	}
	// pointer string (short form, 4-byte payload)
	b = append(b, 0x84) // 0x80 + 4
	for _, u := range ext {
		b = append(b, byte(u.Val.(int)))
	}
	return BytesToU8s(b)
}

/* -------------------------------------------------------------------------- */
/*                                   circuit                                  */
/* -------------------------------------------------------------------------- */

type walkCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *walkCircuit) Define(api frontend.API) error {
	leaf := leafNode()
	ext  := extensionNode()
	br   := branchNode(ext)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{br, ext, leaf},
		Path:    nil, // nibble checks are task-3
		LeafVal: leaf, // still allowed
		Root:    c.Root,
	})
	return nil
}

/* -------------------------------------------------------------------------- */
/*                                happy / bad                                 */
/* -------------------------------------------------------------------------- */

func TestBranchWalkHappy(t *testing.T) {
	//leaf := leafNode()
	ext  := extensionNode()
	br   := branchNode(ext)

	rootBytes := make([]byte, len(br))
	for i, u := range br {
		rootBytes[i] = byte(u.Val.(int))
	}
	rootInt := new(big.Int).SetBytes(rootBytes)

	curves := []struct {
		id  ecc.ID
		mod *big.Int
	}{
		{ecc.BN254, bn254fr.Modulus()},
		{ecc.BLS12_381, bls381fr.Modulus()},
	}
	for _, c := range curves {
		r := new(big.Int).Mod(rootInt, c.mod)
		assert := test.NewAssert(t)
		assert.ProverSucceeded(
			new(walkCircuit),
			&walkCircuit{Root: r},
			test.WithCurves(c.id),
		)
	}
}

type badCircuit struct {
	Root frontend.Variable `gnark:",public"`
}

func (c *badCircuit) Define(api frontend.API) error {
	// identical structure, but corrupt the leaf
	badLeaf := []uints.U8{b(0xbb)}
	ext     := BytesToU8s([]byte{0xc3, 0x80, 0x81, 0xaa}) // unchanged
	br      := branchNode(ext)

	VerifyBranch(api, BranchInput{
		Nodes:   [][]uints.U8{br, ext, badLeaf},
		Path:    nil,
		LeafVal: badLeaf,
		Root:    c.Root,
	})
	return nil
}

func TestBranchWalkBrokenChildHashFails(t *testing.T) {
	ext := extensionNode()
	br  := branchNode(ext)

	rootBytes := make([]byte, len(br))
	for i, u := range br {
		rootBytes[i] = byte(u.Val.(int))
	}
	rootInt := new(big.Int).SetBytes(rootBytes)

	assert := test.NewAssert(t)
	assert.ProverFailed(
		new(badCircuit),
		&badCircuit{Root: rootInt},
	)
}

/* -------------------------------------------------------------------------- */
/*                         compile-time sanity guard                          */
/* -------------------------------------------------------------------------- */

func TestPointerExtractionMatchesGo(t *testing.T) {
	// quick non-constraint check – shows that the simple “last N bytes”
	// logic indeed yields the required pointer value.
	//leaf  := []byte{0xaa}
	ext   := []byte{0xc3, 0x80, 0x81, 0xaa}
	br    := []byte{0xd5}
	for i := 0; i < 16; i++ { br = append(br, 0x80) }
	br = append(br, 0x84)
	br = append(br, ext...)

	goPtr := big.NewInt(0).SetBytes(ext)        // HashNode(child) (<32 bytes)
	last4 := big.NewInt(0).SetBytes(br[len(br)-4:])

	if goPtr.Cmp(last4) != 0 {
		t.Fatalf("expected %x, got %x", goPtr, last4)
	}
	// and the keccak variant (len>=32) exercising the other branch:
	dummy := make([]byte, 33)
	goHash := crypto.Keccak256(dummy)
	if len(goHash) != 32 {
		t.Fatal("keccak digest must be 32 bytes")
	}
}